-- NOTE (repo packaging): normalized gen_random_bytes() -> public.gen_random_bytes() to align with INV-202 and pinned search_path.
-- P2 Step 6 (v3): commit procedure (SECURITY DEFINER, search_path hardened)
-- Canonical single write path: cpo.commit_action(...)
-- Assumes P2 Steps 1-5 already applied:
--   - cpo schema + append-only primitives
--   - cpo.cpo_action_logs (append-only spine)
--   - canonical artifact tables (append-only) each with (agent_id, action_log_id, content, generated cols)
--   - cpo.cpo_agent_heads cache (mutable)
--   - privilege scaffolding: canonical tables locked down; only cpo_owner owns; cpo_commit gets EXECUTE on this function

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

  -- outcome / gate stub
  v_outcome text := 'PASS';
  v_applied boolean := false;

  v_content jsonb;
BEGIN
  IF p_agent_id IS NULL OR length(trim(p_agent_id)) = 0 THEN
    RAISE EXCEPTION 'agent_id required' USING ERRCODE='22004';
  END IF;

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
    -- Genesis: must supply genesis artifacts (charter, activation, state snapshot) in p_artifacts.
    -- expected refs MUST be null for bootstrap commits.
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
  ELSE
    v_cur_charter_activation_id := v_head.current_charter_activation_id;
    v_cur_charter_activation_seq := v_head.current_charter_activation_seq;
    v_cur_charter_version_id := v_head.current_charter_version_id;
    v_cur_state_snapshot_id := v_head.current_state_snapshot_id;
    v_cur_state_seq := v_head.current_state_seq;

    -- TOCTOU closure for non-bootstrap (no semantic bypasses; dry_run does NOT bypass because action logs are still written)
    IF p_expected_charter_activation_id IS NULL OR p_expected_state_snapshot_id IS NULL THEN
      RAISE EXCEPTION 'expected refs required for non-bootstrap commits' USING ERRCODE='22004';
    END IF;

    IF p_expected_charter_activation_id <> v_cur_charter_activation_id
       OR p_expected_state_snapshot_id <> v_cur_state_snapshot_id THEN
      RAISE EXCEPTION 'STALE_CONTEXT'
        USING ERRCODE='40001',
              HINT='Expected refs do not match current heads; map to HTTP 409 and retry after refresh.';
    END IF;IF p_expected_charter_activation_id <> v_cur_charter_activation_id
         OR p_expected_state_snapshot_id <> v_cur_state_snapshot_id THEN
        RAISE EXCEPTION 'STALE_CONTEXT'
          USING ERRCODE='40001',
                HINT='Expected refs do not match current heads; map to HTTP 409 and retry after refresh.';
      END IF;
    END IF;
  END IF;

  -- P2 gate stub (always PASS) - P3 Step 3 will replace this section with cpo.evaluate_gates(...)
  v_outcome := 'PASS';
  v_applied := (NOT v_dry_run) AND (v_outcome IN ('PASS','PASS_WITH_EXCEPTION'));

  -- Construct canonical action_log content (do not mutate schema by injecting agent_id)
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
    'gate_results', '[]'::jsonb,
    'errors', '[]'::jsonb
  );

  -- Insert action log spine (append-only)
  INSERT INTO cpo.cpo_action_logs(agent_id, content)
  VALUES (p_agent_id, v_content);

  -- Insert artifacts iff applied (PASS/PASS_WITH_EXCEPTION) and not dry-run
  IF v_applied THEN
    -- Each artifact array is optional; insert if present.
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

    -- Update heads cache from the new canonical maxima (authoritative and rebuildable)
    -- Charter activation head
    SELECT activation_id, seq, charter_version_id
      INTO v_cur_charter_activation_id, v_cur_charter_activation_seq, v_cur_charter_version_id
      FROM cpo.cpo_charter_activations
     WHERE agent_id = p_agent_id
     ORDER BY seq DESC
     LIMIT 1;

    -- State head
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
    'applied', v_applied
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
