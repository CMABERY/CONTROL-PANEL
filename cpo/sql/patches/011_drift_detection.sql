-- sql/011_drift_detection.sql
-- P5: Drift Detection Events
--
-- SYSTEM actor emits drift_event artifacts through cpo.commit_action() when
-- conditions indicate governance degradation. Emission is subject to the same
-- gates, fail-closed, and fully audited.
--
-- Signals:
--   1. REPEATED_EXCEPTIONS - same gate bypassed N times in window
--   2. EXPIRED_ASSUMPTION_REFERENCE - decision references expired assumption
--   3. MODE_THRASH - frequent mode transitions
--   4. STATE_STALENESS - state snapshot age exceeds policy window
--
-- Prerequisites:
--   - P2 Step 6 v3 applied
--   - P3 Steps 1-3 applied
--   - P4 applied
--
-- Invariants enforced:
--   - INV-501: Drift events are artifacts, not logs
--   - INV-502: SYSTEM actor is not privileged (gates apply)
--   - INV-503: Deterministic triggering from canonical state
--   - INV-504: No duplicate spam (dedupe by signal/window)
--   - INV-505: Emission is TOCTOU-safe (expected refs required)

-- ============================================================================
-- TYPE: drift_signal (return type for detection functions)
-- ============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'drift_signal') THEN
    CREATE TYPE cpo.drift_signal AS (
      signal_type text,
      severity text,
      window_start_ts timestamptz,
      window_end_ts timestamptz,
      window_seconds int,
      threshold int,
      observed int,
      policy_check_id text,
      evidence_action_log_ids uuid[],
      evidence_decision_ids uuid[],
      evidence_assumption_ids uuid[],
      evidence_state_snapshot_ids uuid[],
      dedupe_key text
    );
  END IF;
END $$;

-- ============================================================================
-- FUNCTION: cpo.detect_repeated_exceptions
-- Detects when same gate is bypassed >= threshold times within window
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.detect_repeated_exceptions(
  p_agent_id text,
  p_now timestamptz,
  p_window_seconds int DEFAULT 3600,
  p_threshold int DEFAULT 3
)
RETURNS SETOF cpo.drift_signal
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_window_start timestamptz := p_now - (p_window_seconds || ' seconds')::interval;
  v_signal cpo.drift_signal;
  v_policy_check record;
BEGIN
  -- Find policy_check_ids with >= threshold PASS_WITH_EXCEPTION outcomes in window
  FOR v_policy_check IN
    SELECT 
      gr->>'policy_check_id' AS policy_check_id,
      COUNT(*) AS bypass_count,
      array_agg((al.content->>'action_log_id')::uuid ORDER BY al.seq) AS action_log_ids
    FROM cpo.cpo_action_logs al,
         jsonb_array_elements(al.content->'gate_results') AS gr
    WHERE al.agent_id = p_agent_id
      AND (al.content->>'ts')::timestamptz >= v_window_start
      AND (al.content->>'ts')::timestamptz <= p_now
      AND gr->>'status' = 'PASS_WITH_EXCEPTION'
    GROUP BY gr->>'policy_check_id'
    HAVING COUNT(*) >= p_threshold
  LOOP
    v_signal.signal_type := 'REPEATED_EXCEPTIONS';
    v_signal.severity := CASE 
      WHEN v_policy_check.bypass_count >= p_threshold * 2 THEN 'ERROR'
      WHEN v_policy_check.bypass_count >= p_threshold THEN 'WARN'
      ELSE 'INFO'
    END;
    v_signal.window_start_ts := v_window_start;
    v_signal.window_end_ts := p_now;
    v_signal.window_seconds := p_window_seconds;
    v_signal.threshold := p_threshold;
    v_signal.observed := v_policy_check.bypass_count;
    v_signal.policy_check_id := v_policy_check.policy_check_id;
    v_signal.evidence_action_log_ids := v_policy_check.action_log_ids;
    v_signal.evidence_decision_ids := NULL;
    v_signal.evidence_assumption_ids := NULL;
    v_signal.evidence_state_snapshot_ids := NULL;
    v_signal.dedupe_key := 'REPEATED_EXCEPTIONS:' || v_policy_check.policy_check_id || ':' || 
                           to_char(p_now AT TIME ZONE 'UTC', 'YYYY-MM-DD-HH24');
    
    RETURN NEXT v_signal;
  END LOOP;
END;
$$;

-- ============================================================================
-- FUNCTION: cpo.detect_expired_assumption_references
-- Detects decisions referencing assumptions that have expired
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.detect_expired_assumption_references(
  p_agent_id text,
  p_now timestamptz
)
RETURNS SETOF cpo.drift_signal
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_signal cpo.drift_signal;
  v_expired record;
BEGIN
  -- Find decisions that reference assumptions where expiry_at <= now
  FOR v_expired IN
    SELECT 
      (a.content->>'assumption_id')::uuid AS assumption_id,
      (a.content->>'expiry_at')::timestamptz AS expiry_at,
      array_agg(DISTINCT (d.content->>'decision_id')::uuid) AS decision_ids
    FROM cpo.cpo_assumptions a
    JOIN cpo.cpo_decisions d ON d.agent_id = a.agent_id
      AND d.content->'referenced_assumptions' ? (a.content->>'assumption_id')
    WHERE a.agent_id = p_agent_id
      AND a.content->>'status' = 'ACTIVE'
      AND (a.content->>'expiry_at')::timestamptz <= p_now
    GROUP BY a.content->>'assumption_id', a.content->>'expiry_at'
  LOOP
    v_signal.signal_type := 'EXPIRED_ASSUMPTION_REFERENCE';
    v_signal.severity := 'WARN';
    v_signal.window_start_ts := NULL;
    v_signal.window_end_ts := p_now;
    v_signal.window_seconds := NULL;
    v_signal.threshold := NULL;
    v_signal.observed := array_length(v_expired.decision_ids, 1);
    v_signal.policy_check_id := NULL;
    v_signal.evidence_action_log_ids := NULL;
    v_signal.evidence_decision_ids := v_expired.decision_ids;
    v_signal.evidence_assumption_ids := ARRAY[v_expired.assumption_id];
    v_signal.evidence_state_snapshot_ids := NULL;
    v_signal.dedupe_key := 'EXPIRED_ASSUMPTION_REFERENCE:' || v_expired.assumption_id::text;
    
    RETURN NEXT v_signal;
  END LOOP;
END;
$$;

-- ============================================================================
-- FUNCTION: cpo.detect_mode_thrash
-- Detects frequent mode transitions within window
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.detect_mode_thrash(
  p_agent_id text,
  p_now timestamptz,
  p_window_seconds int DEFAULT 3600,
  p_threshold int DEFAULT 3
)
RETURNS SETOF cpo.drift_signal
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_window_start timestamptz := p_now - (p_window_seconds || ' seconds')::interval;
  v_signal cpo.drift_signal;
  v_transitions int;
  v_snapshot_ids uuid[];
  v_prev_mode text := NULL;
  v_snapshot record;
BEGIN
  v_transitions := 0;
  v_snapshot_ids := ARRAY[]::uuid[];
  
  -- Count mode transitions in window
  FOR v_snapshot IN
    SELECT 
      (content->>'state_snapshot_id')::uuid AS snapshot_id,
      content->>'mode' AS mode,
      (content->>'ts')::timestamptz AS ts
    FROM cpo.cpo_state_snapshots
    WHERE agent_id = p_agent_id
      AND (content->>'ts')::timestamptz >= v_window_start
      AND (content->>'ts')::timestamptz <= p_now
    ORDER BY seq ASC
  LOOP
    IF v_prev_mode IS NOT NULL AND v_snapshot.mode <> v_prev_mode THEN
      v_transitions := v_transitions + 1;
      v_snapshot_ids := array_append(v_snapshot_ids, v_snapshot.snapshot_id);
    END IF;
    v_prev_mode := v_snapshot.mode;
  END LOOP;
  
  IF v_transitions >= p_threshold THEN
    v_signal.signal_type := 'MODE_THRASH';
    v_signal.severity := CASE 
      WHEN v_transitions >= p_threshold * 2 THEN 'ERROR'
      ELSE 'WARN'
    END;
    v_signal.window_start_ts := v_window_start;
    v_signal.window_end_ts := p_now;
    v_signal.window_seconds := p_window_seconds;
    v_signal.threshold := p_threshold;
    v_signal.observed := v_transitions;
    v_signal.policy_check_id := NULL;
    v_signal.evidence_action_log_ids := NULL;
    v_signal.evidence_decision_ids := NULL;
    v_signal.evidence_assumption_ids := NULL;
    v_signal.evidence_state_snapshot_ids := v_snapshot_ids;
    v_signal.dedupe_key := 'MODE_THRASH:' || to_char(p_now AT TIME ZONE 'UTC', 'YYYY-MM-DD-HH24');
    
    RETURN NEXT v_signal;
  END IF;
END;
$$;

-- ============================================================================
-- FUNCTION: cpo.detect_state_staleness
-- Detects when latest state snapshot exceeds freshness window
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.detect_state_staleness(
  p_agent_id text,
  p_now timestamptz,
  p_max_age_seconds int DEFAULT 86400  -- 24 hours default
)
RETURNS SETOF cpo.drift_signal
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_signal cpo.drift_signal;
  v_latest record;
  v_age_seconds int;
BEGIN
  -- Get latest state snapshot
  SELECT 
    (content->>'state_snapshot_id')::uuid AS snapshot_id,
    (content->>'ts')::timestamptz AS ts
  INTO v_latest
  FROM cpo.cpo_state_snapshots
  WHERE agent_id = p_agent_id
  ORDER BY seq DESC
  LIMIT 1;
  
  IF v_latest IS NULL THEN
    RETURN;
  END IF;
  
  v_age_seconds := EXTRACT(EPOCH FROM (p_now - v_latest.ts))::int;
  
  IF v_age_seconds > p_max_age_seconds THEN
    v_signal.signal_type := 'STATE_STALENESS';
    v_signal.severity := CASE 
      WHEN v_age_seconds > p_max_age_seconds * 2 THEN 'ERROR'
      ELSE 'WARN'
    END;
    v_signal.window_start_ts := v_latest.ts;
    v_signal.window_end_ts := p_now;
    v_signal.window_seconds := p_max_age_seconds;
    v_signal.threshold := p_max_age_seconds;
    v_signal.observed := v_age_seconds;
    v_signal.policy_check_id := NULL;
    v_signal.evidence_action_log_ids := NULL;
    v_signal.evidence_decision_ids := NULL;
    v_signal.evidence_assumption_ids := NULL;
    v_signal.evidence_state_snapshot_ids := ARRAY[v_latest.snapshot_id];
  v_signal.dedupe_key := 'STATE_STALENESS:' || to_char(p_now AT TIME ZONE 'UTC', 'YYYY-MM-DD-HH24');
    
    RETURN NEXT v_signal;
  END IF;
END;
$$;

-- ============================================================================
-- FUNCTION: cpo.detect_drift
-- Aggregates all drift detection signals
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.detect_drift(
  p_agent_id text,
  p_now timestamptz,
  p_window_seconds int DEFAULT 3600,
  p_exception_threshold int DEFAULT 3,
  p_mode_thrash_threshold int DEFAULT 3,
  p_staleness_max_age int DEFAULT 86400
)
RETURNS SETOF cpo.drift_signal
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
BEGIN
  -- Repeated exceptions
  RETURN QUERY SELECT * FROM cpo.detect_repeated_exceptions(
    p_agent_id, p_now, p_window_seconds, p_exception_threshold
  );
  
  -- Expired assumption references
  RETURN QUERY SELECT * FROM cpo.detect_expired_assumption_references(
    p_agent_id, p_now
  );
  
  -- Mode thrash
  RETURN QUERY SELECT * FROM cpo.detect_mode_thrash(
    p_agent_id, p_now, p_window_seconds, p_mode_thrash_threshold
  );
  
  -- State staleness
  RETURN QUERY SELECT * FROM cpo.detect_state_staleness(
    p_agent_id, p_now, p_staleness_max_age
  );
END;
$$;

-- ============================================================================
-- FUNCTION: cpo.emit_drift_events
-- Emits drift events through commit_action (SYSTEM actor, TOCTOU-safe)
-- Returns commit results for each signal
-- ============================================================================

CREATE OR REPLACE FUNCTION cpo.emit_drift_events(
  p_agent_id text,
  p_now timestamptz,
  p_expected_charter_activation_id uuid,
  p_expected_state_snapshot_id uuid,
  p_window_seconds int DEFAULT 3600,
  p_exception_threshold int DEFAULT 3,
  p_mode_thrash_threshold int DEFAULT 3,
  p_staleness_max_age int DEFAULT 86400
)
RETURNS TABLE(
  drift_event_id uuid,
  signal_type text,
  outcome text,
  applied boolean,
  dedupe_skipped boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_signal cpo.drift_signal;
  v_drift_event_id uuid;
  v_action_content jsonb;
  v_artifacts jsonb;
  v_commit_result jsonb;
  v_now_iso text := to_char(p_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  v_existing_count int;
  v_locked boolean := false;
BEGIN
  -- Detect all drift signals
  FOR v_signal IN
    SELECT * FROM cpo.detect_drift(
      p_agent_id, p_now, p_window_seconds,
      p_exception_threshold, p_mode_thrash_threshold, p_staleness_max_age
    )
  LOOP
    -- Serialize dedupe check + emission through the same per-agent commit lock.
    -- This prevents cross-session duplicate drift events when multiple drift scans
    -- run concurrently.
    IF NOT v_locked THEN
      PERFORM pg_advisory_xact_lock(hashtext('cpo:commit:' || p_agent_id));
      v_locked := true;
    END IF;

    -- INV-504: Check for duplicate (same dedupe_key already emitted)
    SELECT COUNT(*) INTO v_existing_count
    FROM cpo.cpo_drift_events de
    WHERE de.agent_id = p_agent_id
      AND de.content->>'dedupe_key' = v_signal.dedupe_key;
    
    IF v_existing_count > 0 THEN
      -- Already emitted, skip
      drift_event_id := NULL;
      signal_type := v_signal.signal_type;
      outcome := 'SKIPPED_DUPLICATE';
      applied := false;
      dedupe_skipped := true;
      RETURN NEXT;
      CONTINUE;
    END IF;
    
    v_drift_event_id := public.gen_random_uuid();
    
    -- Build SYSTEM action content
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id', 'SYSTEM_DRIFT_DETECTOR', 'type', 'SYSTEM'),
      'action', jsonb_build_object(
        'action_type', 'SYSTEM_DRIFT_EVENT',
        'dry_run', false,
        'request_id', 'DRIFT-' || v_drift_event_id::text
      )
    );
    
    -- Build drift_event artifact
    v_artifacts := jsonb_build_object(
      'drift_events', jsonb_build_array(
        jsonb_build_object(
          'protocol_version', 'cpo-contracts@0.1.0',
          'drift_event_id', v_drift_event_id,
          'ts', v_now_iso,
          'signal_type', v_signal.signal_type,
          'severity', v_signal.severity,
          'window', jsonb_build_object(
            'start_ts', CASE WHEN v_signal.window_start_ts IS NOT NULL 
                        THEN to_char(v_signal.window_start_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                        ELSE NULL END,
            'end_ts', to_char(v_signal.window_end_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'window_seconds', v_signal.window_seconds
          ),
          'predicate', jsonb_build_object(
            'threshold', v_signal.threshold,
            'observed', v_signal.observed,
            'policy_check_id', v_signal.policy_check_id
          ),
          'evidence', jsonb_build_object(
            'action_log_ids', COALESCE(to_jsonb(v_signal.evidence_action_log_ids), '[]'::jsonb),
            'decision_ids', COALESCE(to_jsonb(v_signal.evidence_decision_ids), '[]'::jsonb),
            'assumption_ids', COALESCE(to_jsonb(v_signal.evidence_assumption_ids), '[]'::jsonb),
            'state_snapshot_ids', COALESCE(to_jsonb(v_signal.evidence_state_snapshot_ids), '[]'::jsonb)
          ),
          'dedupe_key', v_signal.dedupe_key
        )
      )
    );
    
    -- INV-502 + INV-505: Commit through commit_action (gates apply, TOCTOU checked)
    v_commit_result := cpo.commit_action(
      p_agent_id,
      v_action_content,
      v_artifacts,
      p_expected_charter_activation_id,
      p_expected_state_snapshot_id
    );
    
    drift_event_id := v_drift_event_id;
    signal_type := v_signal.signal_type;
    outcome := v_commit_result->>'outcome';
    applied := (v_commit_result->>'applied')::boolean;
    dedupe_skipped := false;
    RETURN NEXT;
    
    -- If applied, update expected refs for next iteration
    IF applied THEN
      SELECT current_charter_activation_id, current_state_snapshot_id
        INTO p_expected_charter_activation_id, p_expected_state_snapshot_id
        FROM cpo.cpo_agent_heads
       WHERE agent_id = p_agent_id;
    END IF;
  END LOOP;
END;
$$;

-- ============================================================================
-- Harden function exposure
-- ============================================================================

REVOKE ALL ON FUNCTION cpo.detect_repeated_exceptions(text, timestamptz, int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpo.detect_expired_assumption_references(text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpo.detect_mode_thrash(text, timestamptz, int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpo.detect_state_staleness(text, timestamptz, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpo.detect_drift(text, timestamptz, int, int, int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpo.emit_drift_events(text, timestamptz, uuid, uuid, int, int, int, int) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_commit') THEN
    GRANT EXECUTE ON FUNCTION cpo.detect_repeated_exceptions(text, timestamptz, int, int) TO cpo_commit;
    GRANT EXECUTE ON FUNCTION cpo.detect_expired_assumption_references(text, timestamptz) TO cpo_commit;
    GRANT EXECUTE ON FUNCTION cpo.detect_mode_thrash(text, timestamptz, int, int) TO cpo_commit;
    GRANT EXECUTE ON FUNCTION cpo.detect_state_staleness(text, timestamptz, int) TO cpo_commit;
    GRANT EXECUTE ON FUNCTION cpo.detect_drift(text, timestamptz, int, int, int, int) TO cpo_commit;
    GRANT EXECUTE ON FUNCTION cpo.emit_drift_events(text, timestamptz, uuid, uuid, int, int, int, int) TO cpo_commit;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_owner') THEN
    ALTER FUNCTION cpo.detect_repeated_exceptions(text, timestamptz, int, int) OWNER TO cpo_owner;
    ALTER FUNCTION cpo.detect_expired_assumption_references(text, timestamptz) OWNER TO cpo_owner;
    ALTER FUNCTION cpo.detect_mode_thrash(text, timestamptz, int, int) OWNER TO cpo_owner;
    ALTER FUNCTION cpo.detect_state_staleness(text, timestamptz, int) OWNER TO cpo_owner;
    ALTER FUNCTION cpo.detect_drift(text, timestamptz, int, int, int, int) OWNER TO cpo_owner;
    ALTER FUNCTION cpo.emit_drift_events(text, timestamptz, uuid, uuid, int, int, int, int) OWNER TO cpo_owner;
  END IF;
END $$;

COMMENT ON FUNCTION cpo.detect_drift IS
  'P5: Aggregates all drift detection signals for an agent at a given time.';

COMMENT ON FUNCTION cpo.emit_drift_events IS
  'P5: Emits drift_event artifacts through commit_action. SYSTEM actor, TOCTOU-safe (INV-505), dedupe-safe (INV-504).';
