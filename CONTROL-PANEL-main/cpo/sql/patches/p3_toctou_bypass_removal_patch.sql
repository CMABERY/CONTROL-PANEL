-- p3_toctou_bypass_removal_patch.sql
-- P3: Remove semantic TOCTOU bypass branches (P0 violation)
--
-- BLOCKER ADDRESSED:
--   The 009_commit_action_gate_integration.sql contains:
--     IF (NOT v_dry_run) AND (v_action_type NOT LIKE 'BOOTSTRAP_%') AND (v_action_type NOT LIKE 'SYSTEM_%') THEN
--   
--   This violates P0: "no semantic privilege from payload fields"
--   Any client can set action_type='SYSTEM_BYPASS' and skip TOCTOU checks.
--
-- FIX:
--   Replace action_type string matching with actual bootstrap detection:
--     IF (NOT v_dry_run) AND (NOT v_bootstrap) THEN
--
--   - v_bootstrap is TRUE when no heads row exists (legitimate genesis)
--   - dry_run bypass is legitimate (no writes = no TOCTOU concern)
--   - SYSTEM_% bypass is REMOVED (semantic privilege violation)
--   - BOOTSTRAP_% string match is REMOVED (replaced by actual detection)
--
-- This patch upgrades commit_action() to close the P0 violation.

BEGIN;

CREATE OR REPLACE FUNCTION cpo.commit_action(
  p_agent_id                       text,
  p_action_log_content             jsonb,
  p_artifacts                      jsonb DEFAULT '{}'::jsonb,
  p_expected_charter_activation_id uuid DEFAULT NULL,
  p_expected_state_snapshot_id     uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_action_log_id uuid := public.gen_random_uuid();
  v_now           timestamptz := clock_timestamp();

  v_dry_run    boolean := COALESCE((p_action_log_content #>> '{action,dry_run}')::boolean, false);
  v_action_type text   := COALESCE(p_action_log_content #>> '{action,action_type}', '');
  v_request_id  text   := COALESCE(p_action_log_content #>> '{action,request_id}', 'REQ-' || encode(public.gen_random_bytes(8),'hex'));

  v_bootstrap boolean := false;

  v_head record;
  v_seq bigint;

  -- current/evaluated refs
  v_cur_charter_activation_id uuid;
  v_cur_state_snapshot_id uuid;
  v_cur_charter_activation_seq bigint;
  v_cur_state_seq bigint;
  v_cur_charter_version_id uuid;

  -- P3: gate engine results
  v_outcome text := 'FAIL';  -- fail-closed default
  v_applied boolean := false;
  v_gate_result jsonb;
  v_gate_results jsonb := '[]'::jsonb;
  v_errors jsonb := '[]'::jsonb;

  -- charter/state content for gate evaluation
  v_charter_content jsonb;
  v_state_content jsonb;
  v_activation_content jsonb;

  v_content jsonb;
BEGIN
  -- ============================================================
  -- KERNEL GATE 1: agent_id validation (non-exceptionable)
  -- ============================================================
  IF p_agent_id IS NULL OR length(trim(p_agent_id)) = 0 THEN
    RAISE EXCEPTION 'agent_id required' USING ERRCODE='22004';
  END IF;

  -- ============================================================
  -- KERNEL GATE 2: action_log_content validation (non-exceptionable)
  -- ============================================================
  IF jsonb_typeof(p_action_log_content) <> 'object' THEN
    RAISE EXCEPTION 'action_log_content must be a JSON object' USING ERRCODE='22023';
  END IF;

  -- Serialize commits per agent (covers genesis before heads row exists)
  PERFORM pg_advisory_xact_lock(hashtext('cpo:commit:' || p_agent_id));

  -- Lock (or detect) heads row
  SELECT *
    INTO v_head
    FROM cpo.cpo_agent_heads
   WHERE agent_id = p_agent_id
   FOR UPDATE;

  -- v_bootstrap is TRUE when this is the FIRST commit for this agent
  -- (no heads row exists). This is the ONLY legitimate TOCTOU bypass.
  v_bootstrap := NOT FOUND;

  -- Determine next seq defensively (monotonic even if cache missing/corrupt)
  SELECT COALESCE(MAX(seq), 0) INTO v_seq
    FROM cpo.cpo_action_logs
   WHERE agent_id = p_agent_id;

  IF NOT v_bootstrap THEN
    v_seq := GREATEST(v_seq, v_head.last_action_log_seq);
  END IF;

  v_seq := v_seq + 1;

  -- Resolve current/evaluated refs
  IF v_bootstrap THEN
    -- ============================================================
    -- KERNEL GATE 3: Bootstrap artifact requirements (non-exceptionable)
    -- ============================================================
    -- Genesis commit: must supply genesis artifacts
    -- Expected refs MUST be null for bootstrap commits.
    IF (p_expected_charter_activation_id IS NOT NULL) OR (p_expected_state_snapshot_id IS NOT NULL) THEN
      RAISE EXCEPTION 'BOOTSTRAP commits must not include expected refs' USING ERRCODE='22023';
    END IF;

    IF (p_artifacts ? 'charter_activations') IS FALSE OR jsonb_array_length(COALESCE(p_artifacts->'charter_activations','[]'::jsonb)) = 0 THEN
      RAISE EXCEPTION 'BOOTSTRAP requires artifacts.charter_activations[0]' USING ERRCODE='22023';
    END IF;
    IF (p_artifacts ? 'state_snapshots') IS FALSE OR jsonb_array_length(COALESCE(p_artifacts->'state_snapshots','[]'::jsonb)) = 0 THEN
      RAISE EXCEPTION 'BOOTSTRAP requires artifacts.state_snapshots[0]' USING ERRCODE='22023';
    END IF;
    IF (p_artifacts ? 'charters') IS FALSE OR jsonb_array_length(COALESCE(p_artifacts->'charters','[]'::jsonb)) = 0 THEN
      RAISE EXCEPTION 'BOOTSTRAP requires artifacts.charters[0]' USING ERRCODE='22023';
    END IF;

    v_cur_charter_activation_id := (p_artifacts->'charter_activations'->0->>'activation_id')::uuid;
    v_cur_charter_activation_seq := COALESCE((p_artifacts->'charter_activations'->0->>'seq')::bigint, 1);
    v_cur_charter_version_id := (p_artifacts->'charter_activations'->0->>'charter_version_id')::uuid;

    v_cur_state_snapshot_id := (p_artifacts->'state_snapshots'->0->>'state_snapshot_id')::uuid;
    v_cur_state_seq := COALESCE((p_artifacts->'state_snapshots'->0->>'seq')::bigint, 1);

    -- For bootstrap, use the genesis artifacts as evaluation context
    v_charter_content := p_artifacts->'charters'->0;
    v_state_content := p_artifacts->'state_snapshots'->0;
    v_activation_content := p_artifacts->'charter_activations'->0;

  ELSE
    v_cur_charter_activation_id := v_head.current_charter_activation_id;
    v_cur_charter_activation_seq := v_head.current_charter_activation_seq;
    v_cur_charter_version_id := v_head.current_charter_version_id;
    v_cur_state_snapshot_id := v_head.current_state_snapshot_id;
    v_cur_state_seq := v_head.current_state_seq;

    -- ============================================================
    -- KERNEL GATE 4: TOCTOU / Expected refs validation (non-exceptionable)
    -- P3 FIX: Removed ALL semantic bypasses:
    --   - SYSTEM_% bypass: REMOVED
    --   - BOOTSTRAP_% bypass: REMOVED (use v_bootstrap)
    --   - dry_run bypass: REMOVED (action logs are still written)
    -- Only legitimate bypass: v_bootstrap=true (first commit has no previous heads)
    -- ============================================================
    -- Non-bootstrap: expected refs are ALWAYS required (including dry_run)
    IF p_expected_charter_activation_id IS NULL OR p_expected_state_snapshot_id IS NULL THEN
      RAISE EXCEPTION 'expected refs required for non-bootstrap commits' USING ERRCODE='22004';
    END IF;

    IF p_expected_charter_activation_id <> v_cur_charter_activation_id
       OR p_expected_state_snapshot_id <> v_cur_state_snapshot_id THEN
      RAISE EXCEPTION 'STALE_CONTEXT'
        USING ERRCODE='40001',
              HINT='Expected refs do not match current heads; map to HTTP 409 and retry after refresh.';
    END IF;

    -- Fetch current charter/state/activation content for gate evaluation
    SELECT content INTO v_charter_content
      FROM cpo.cpo_charters
     WHERE agent_id = p_agent_id
       AND charter_version_id = v_cur_charter_version_id
     LIMIT 1;

    SELECT content INTO v_state_content
      FROM cpo.cpo_state_snapshots
     WHERE agent_id = p_agent_id
       AND state_snapshot_id = v_cur_state_snapshot_id
     LIMIT 1;

    SELECT content INTO v_activation_content
      FROM cpo.cpo_charter_activations
     WHERE agent_id = p_agent_id
       AND activation_id = v_cur_charter_activation_id
     LIMIT 1;
     
    -- ============================================================
    -- KERNEL GATE 5: Resolved inputs existence (non-exceptionable)
    -- P3 v2.2 FIX: Missing resolved inputs → ERROR, not silent PASS
    -- If charter/state/activation referenced by heads doesn't exist,
    -- the system is in an inconsistent state and cannot evaluate gates.
    -- This must be fail-closed (ERROR), not fail-open (empty → PASS).
    -- ============================================================
    IF v_charter_content IS NULL THEN
      RAISE EXCEPTION 'RESOLVED_INPUT_MISSING: Charter content not found for charter_version_id=%',
        v_cur_charter_version_id
        USING ERRCODE = 'P0001',
              HINT = 'Heads reference a charter that does not exist. System state is inconsistent.';
    END IF;
    
    IF v_state_content IS NULL THEN
      RAISE EXCEPTION 'RESOLVED_INPUT_MISSING: State snapshot content not found for state_snapshot_id=%',
        v_cur_state_snapshot_id
        USING ERRCODE = 'P0001',
              HINT = 'Heads reference a state snapshot that does not exist. System state is inconsistent.';
    END IF;
    
    IF v_activation_content IS NULL THEN
      RAISE EXCEPTION 'RESOLVED_INPUT_MISSING: Charter activation content not found for activation_id=%',
        v_cur_charter_activation_id
        USING ERRCODE = 'P0001',
              HINT = 'Heads reference a charter activation that does not exist. System state is inconsistent.';
    END IF;
  END IF;

  -- ============================================================
  -- P3 GATE ENGINE (charter gates, exception-eligible)
  -- Schema-qualified per INV-202; fail-closed per INV-105
  -- ============================================================
  BEGIN
    -- Build action_log content for evaluation (pre-outcome)
    v_content := jsonb_build_object(
      'protocol_version', 'cpo-contracts@0.1.0',
      'action_log_id', v_action_log_id,
      'seq', v_seq,
      'ts', to_char(v_now AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      'actor', COALESCE(p_action_log_content->'actor', jsonb_build_object('id','SYSTEM','type','SYSTEM')),
      'action', jsonb_set(COALESCE(p_action_log_content->'action','{}'::jsonb), '{request_id}', to_jsonb(v_request_id), true)
    );

    -- Call gate engine (schema-qualified per INV-202)
    v_gate_result := cpo.evaluate_gates(
      p_agent_id,
      v_content,              -- action_log_content
      v_charter_content,      -- charter
      v_state_content,        -- state
      v_activation_content,   -- charter_activation
      v_now                   -- evaluation timestamp
    );

    -- Extract results
    v_outcome := COALESCE(v_gate_result->>'outcome', 'FAIL');
    v_gate_results := COALESCE(v_gate_result->'gate_results', '[]'::jsonb);

    -- Extract any ERROR status gates into errors array
    SELECT COALESCE(jsonb_agg(gr), '[]'::jsonb)
      INTO v_errors
      FROM jsonb_array_elements(v_gate_results) AS gr
     WHERE gr->>'status' = 'ERROR';

  EXCEPTION WHEN OTHERS THEN
    -- Fail-closed: any evaluation error results in FAIL
    v_outcome := 'FAIL';
    v_gate_results := '[]'::jsonb;
    v_errors := jsonb_build_array(
      jsonb_build_object(
        'error_type', 'GATE_EVALUATION_ERROR',
        'sqlstate', SQLSTATE,
        'message', SQLERRM
      )
    );
  END;
  -- ============================================================

  v_applied := (NOT v_dry_run) AND (v_outcome IN ('PASS','PASS_WITH_EXCEPTION'));

  -- Construct canonical action_log content with gate results
  v_content := jsonb_build_object(
    'protocol_version', 'cpo-contracts@0.1.0',
    'action_log_id', v_action_log_id,
    'seq', v_seq,
    'ts', to_char(v_now AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'actor', COALESCE(p_action_log_content->'actor', jsonb_build_object('id','SYSTEM','type','SYSTEM')),
    'action', jsonb_set(COALESCE(p_action_log_content->'action','{}'::jsonb), '{request_id}', to_jsonb(v_request_id), true),
    'expected_refs', jsonb_build_object(
        'expected_charter_activation_id', p_expected_charter_activation_id,
        'expected_state_snapshot_id', p_expected_state_snapshot_id
    ),
    'evaluated_against', jsonb_build_object(
        'charter_activation_id', v_cur_charter_activation_id,
        'charter_activation_seq', v_cur_charter_activation_seq,
        'charter_version_id', v_cur_charter_version_id,
        'state_snapshot_id', v_cur_state_snapshot_id,
        'state_seq', v_cur_state_seq
    ),
    'outcome', v_outcome,
    'applied', v_applied,
    'gate_results', v_gate_results,
    'errors', v_errors
  );

  -- Insert action log spine (append-only) - ALWAYS inserted regardless of outcome
  INSERT INTO cpo.cpo_action_logs(agent_id, content)
  VALUES (p_agent_id, v_content);

  -- Insert artifacts iff applied (PASS/PASS_WITH_EXCEPTION) and not dry-run
  IF v_applied THEN
    IF (p_artifacts ? 'charters') THEN
      INSERT INTO cpo.cpo_charters(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'charters') AS elem;
    END IF;

    IF (p_artifacts ? 'charter_activations') THEN
      INSERT INTO cpo.cpo_charter_activations(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'charter_activations') AS elem;
    END IF;

    IF (p_artifacts ? 'state_snapshots') THEN
      INSERT INTO cpo.cpo_state_snapshots(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'state_snapshots') AS elem;
    END IF;

    IF (p_artifacts ? 'decisions') THEN
      INSERT INTO cpo.cpo_decisions(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'decisions') AS elem;
    END IF;

    IF (p_artifacts ? 'assumptions') THEN
      INSERT INTO cpo.cpo_assumptions(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'assumptions') AS elem;
    END IF;

    IF (p_artifacts ? 'assumption_events') THEN
      INSERT INTO cpo.cpo_assumption_events(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'assumption_events') AS elem;
    END IF;

    IF (p_artifacts ? 'exceptions') THEN
      INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'exceptions') AS elem;
    END IF;

    IF (p_artifacts ? 'exception_events') THEN
      INSERT INTO cpo.cpo_exception_events(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'exception_events') AS elem;
    END IF;

    IF (p_artifacts ? 'drift_events') THEN
      INSERT INTO cpo.cpo_drift_events(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'drift_events') AS elem;
    END IF;

    IF (p_artifacts ? 'drift_resolutions') THEN
      INSERT INTO cpo.cpo_drift_resolutions(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'drift_resolutions') AS elem;
    END IF;

    IF (p_artifacts ? 'changes') THEN
      INSERT INTO cpo.cpo_changes(agent_id, action_log_id, content)
      SELECT p_agent_id, v_action_log_id, elem
      FROM jsonb_array_elements(p_artifacts->'changes') AS elem;
    END IF;

    -- Update heads cache from canonical maxima
    SELECT activation_id, seq, charter_version_id
      INTO v_cur_charter_activation_id, v_cur_charter_activation_seq, v_cur_charter_version_id
      FROM cpo.cpo_charter_activations
     WHERE agent_id = p_agent_id
     ORDER BY seq DESC
     LIMIT 1;

    SELECT state_snapshot_id, seq
      INTO v_cur_state_snapshot_id, v_cur_state_seq
      FROM cpo.cpo_state_snapshots
     WHERE agent_id = p_agent_id
     ORDER BY seq DESC
     LIMIT 1;

    INSERT INTO cpo.cpo_agent_heads(
      agent_id,
      updated_at,
      last_action_log_seq,
      current_charter_activation_id,
      current_charter_activation_seq,
      current_charter_version_id,
      current_state_snapshot_id,
      current_state_seq
    )
    VALUES (
      p_agent_id,
      clock_timestamp(),
      v_seq,
      v_cur_charter_activation_id,
      v_cur_charter_activation_seq,
      v_cur_charter_version_id,
      v_cur_state_snapshot_id,
      v_cur_state_seq
    )
    ON CONFLICT (agent_id) DO UPDATE SET
      updated_at = clock_timestamp(),
      last_action_log_seq = EXCLUDED.last_action_log_seq,
      current_charter_activation_id = EXCLUDED.current_charter_activation_id,
      current_charter_activation_seq = EXCLUDED.current_charter_activation_seq,
      current_charter_version_id = EXCLUDED.current_charter_version_id,
      current_state_snapshot_id = EXCLUDED.current_state_snapshot_id,
      current_state_seq = EXCLUDED.current_state_seq;

  END IF;

  RETURN jsonb_build_object(
    'action_log_id', v_action_log_id,
    'outcome', v_outcome,
    'seq', v_seq,
    'applied', v_applied,
    'gate_results', v_gate_results
  );
END;
$$;

-- Harden function exposure
REVOKE ALL ON FUNCTION cpo.commit_action(text, jsonb, jsonb, uuid, uuid) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_commit') THEN
    GRANT EXECUTE ON FUNCTION cpo.commit_action(text, jsonb, jsonb, uuid, uuid) TO cpo_commit;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_owner') THEN
    ALTER FUNCTION cpo.commit_action(text, jsonb, jsonb, uuid, uuid) OWNER TO cpo_owner;
  END IF;
END $$;

COMMIT;
