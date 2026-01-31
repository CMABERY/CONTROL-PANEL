-- P6 v3: Change control as kernel physics
--
-- Goals (locked invariants):
--   INV-601: Charter mutation requires a change package artifact (changes[])
--   INV-602: Approvals are deterministic; expiry enforced (knife-edge: expiry_at <= now is expired)
--   INV-603: Malformed/unknown/partial change package => FAIL (applied=false)
--   INV-604: TOCTOU safety is enforced by commit_action expected refs (no semantic bypass)
--   INV-605: Replay blocked (unique change_id and/or dedupe_key)
--   INV-606: Genesis exemption only for authenticated bootstrap (db role + genesis), never via strings
--
-- This patch is designed to be surgical:
--   - It upgrades change-control helpers and evaluate_change_control_kernel()
--   - It does NOT replace commit_action() wholesale.
--
-- Notes:
--   - action_type is audit telemetry only; it MUST NOT cause PASS/FAIL decisions.
--   - The 6-arg evaluate_change_control_kernel(...) signature is retained as a wrapper
--     to prevent overload residue side-channels.

BEGIN;

-------------------------------------------------------------------------------
-- Helper: Detect whether artifacts propose a charter mutation
-- Fail-closed on malformed shapes: if keys exist but are not arrays, treat as TRUE
-------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.proposes_charter_change(p_artifacts jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_val jsonb;
BEGIN
  v_val := p_artifacts->'charters';
  IF v_val IS NOT NULL THEN
    IF jsonb_typeof(v_val) <> 'array' THEN
      RETURN true; -- malformed attempt => treat as charter-change path
    END IF;
    IF jsonb_array_length(v_val) > 0 THEN
      RETURN true;
    END IF;
  END IF;

  v_val := p_artifacts->'charter_activations';
  IF v_val IS NOT NULL THEN
    IF jsonb_typeof(v_val) <> 'array' THEN
      RETURN true;
    END IF;
    IF jsonb_array_length(v_val) > 0 THEN
      RETURN true;
    END IF;
  END IF;

  RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION cpo.proposes_charter_change(jsonb) FROM PUBLIC;

-------------------------------------------------------------------------------
-- Replay protection: physical uniqueness (preferred)
--
-- If your ledger already contains duplicates, these indexes will fail to build.
-- That is intentional: duplicates violate INV-605 and should be remediated.
-------------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS cpo_changes_unique_change_id
  ON cpo.cpo_changes (agent_id, (content->>'change_id'))
  WHERE NULLIF(content->>'change_id','') IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS cpo_changes_unique_dedupe_key
  ON cpo.cpo_changes (agent_id, (content->>'dedupe_key'))
  WHERE NULLIF(content->>'dedupe_key','') IS NOT NULL;

-------------------------------------------------------------------------------
-- Core: evaluate_change_control_kernel (8-arg)
--
-- IMPORTANT:
--   - No semantic privilege: no BOOTSTRAP_% / SYSTEM_% string matching.
--   - action_type is telemetry only.
--   - Genesis exemption requires BOTH (is_genesis = true) AND (capability = KERNEL_BOOTSTRAP).
--   - Approvals enforce P4-style expiry semantics:
--       * expiry_at IS NULL => invalid (FAIL)
--       * expiry_at <= now  => expired (FAIL)
-------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.evaluate_change_control_kernel(
  p_agent_id text,
  p_action_type text,
  p_artifacts jsonb,
  p_now timestamptz,
  p_current_charter_version_id uuid,
  p_required_approvals integer,
  p_is_genesis boolean,
  p_capability text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_gate_id constant text := 'GATE-CHANGE-CONTROL';

  v_declared_intent_recognized boolean := false;

  -- Proposed mutations
  v_charters jsonb;
  v_activations jsonb;
  v_obj jsonb;

  v_proposed_charter_version_ids uuid[] := ARRAY[]::uuid[];
  v_proposed_activation_ids uuid[] := ARRAY[]::uuid[];
  v_proposed_activation_charter_versions uuid[] := ARRAY[]::uuid[];

  v_tmp_uuid uuid;

  -- Change package selection
  v_changes jsonb;
  v_change jsonb;
  v_candidate jsonb;
  v_candidate_count integer := 0;

  -- Change fields
  v_change_id uuid;
  v_change_id_txt text;
  v_change_type text;
  v_dedupe_key text;

  v_targets jsonb;
  v_target_charter_version_ids uuid[] := ARRAY[]::uuid[];
  v_target_activation_ids uuid[] := ARRAY[]::uuid[];

  -- Approvals
  v_approvals jsonb;
  v_approval jsonb;
  v_approved_by jsonb;
  v_approved_by_id text;
  v_seen_approver_ids text[] := ARRAY[]::text[];
  v_expiry timestamptz;

  v_i integer;

  -- helpers
  v_missing boolean;
BEGIN
  -- Telemetry (NOT enforcement)
  v_declared_intent_recognized := p_action_type = ANY(ARRAY[
    'CHARTER_PROPOSE','CHARTER_CHANGE','CHARTER_ACTIVATE','CHARTER_MUTATE',
    'PROPOSE_CHARTER_CHANGE','SYSTEM_CHARTER_AMEND'
  ]);

  IF NOT cpo.proposes_charter_change(p_artifacts) THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','PASS',
      'reason','NO_CHARTER_CHANGE',
      'declared_intent_recognized', v_declared_intent_recognized
    );
  END IF;

  -- Genesis exemption: authenticated only
  IF p_is_genesis AND p_capability = 'KERNEL_BOOTSTRAP' THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','PASS',
      'reason','GENESIS_BOOTSTRAP_EXEMPT',
      'declared_intent_recognized', v_declared_intent_recognized
    );
  END IF;

  -----------------------------------------------------------------------------
  -- Collect proposed charter mutations
  -----------------------------------------------------------------------------
  v_charters := COALESCE(p_artifacts->'charters', '[]'::jsonb);
  IF jsonb_typeof(v_charters) <> 'array' THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_ARTIFACTS_CHARters');
  END IF;

  FOR v_obj IN SELECT value FROM jsonb_array_elements(v_charters)
  LOOP
    IF jsonb_typeof(v_obj) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_CHARTER_OBJECT');
    END IF;

    v_change_id_txt := NULLIF(v_obj->>'charter_version_id','');
    IF v_change_id_txt IS NULL THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_CHARTER_VERSION_ID');
    END IF;

    BEGIN
      v_tmp_uuid := v_change_id_txt::uuid;
    EXCEPTION
      WHEN others THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INVALID_CHARTER_VERSION_ID');
    END;

    v_proposed_charter_version_ids := array_append(v_proposed_charter_version_ids, v_tmp_uuid);
  END LOOP;

  v_activations := COALESCE(p_artifacts->'charter_activations', '[]'::jsonb);
  IF jsonb_typeof(v_activations) <> 'array' THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_ARTIFACTS_ACTIVATIONS');
  END IF;

  FOR v_obj IN SELECT value FROM jsonb_array_elements(v_activations)
  LOOP
    IF jsonb_typeof(v_obj) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_ACTIVATION_OBJECT');
    END IF;

    -- activation_id MUST be present for deterministic change packages
    v_change_id_txt := NULLIF(v_obj->>'activation_id','');
    IF v_change_id_txt IS NULL THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_ACTIVATION_ID');
    END IF;

    BEGIN
      v_tmp_uuid := v_change_id_txt::uuid;
    EXCEPTION
      WHEN others THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INVALID_ACTIVATION_ID');
    END;

    v_proposed_activation_ids := array_append(v_proposed_activation_ids, v_tmp_uuid);

    -- charter_version_id referenced by activation must exist (in proposed charters or DB)
    v_change_id_txt := NULLIF(v_obj->>'charter_version_id','');
    IF v_change_id_txt IS NULL THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_ACTIVATION_CHARTER_VERSION_ID');
    END IF;

    BEGIN
      v_tmp_uuid := v_change_id_txt::uuid;
    EXCEPTION
      WHEN others THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INVALID_ACTIVATION_CHARTER_VERSION_ID');
    END;

    -- disallow re-activating the already-current charter version
    IF p_current_charter_version_id IS NOT NULL AND v_tmp_uuid = p_current_charter_version_id THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','DUPLICATE_CHARTER_ACTIVATION');
    END IF;

    -- Ensure referenced charter exists either in proposed set or already persisted
    IF NOT (v_tmp_uuid = ANY(v_proposed_charter_version_ids)) THEN
      IF NOT EXISTS (
        SELECT 1 FROM cpo.cpo_charters
         WHERE agent_id = p_agent_id
           AND charter_version_id = v_tmp_uuid
      ) THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','ACTIVATION_REFERENCES_UNKNOWN_CHARTER');
      END IF;
    END IF;

    v_proposed_activation_charter_versions := array_append(v_proposed_activation_charter_versions, v_tmp_uuid);
  END LOOP;

  -----------------------------------------------------------------------------
  -- Require a change package
  -----------------------------------------------------------------------------
  v_changes := p_artifacts->'changes';
  IF v_changes IS NULL THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','FAIL',
      'reason','CHANGE_PACKAGE_REQUIRED',
      'violated_invariant','INV-601'
    );
  END IF;

  IF jsonb_typeof(v_changes) <> 'array' OR jsonb_array_length(v_changes) = 0 THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','FAIL',
      'reason','CHANGE_PACKAGE_REQUIRED',
      'violated_invariant','INV-601'
    );
  END IF;

  -----------------------------------------------------------------------------
  -- Select a single matching change package that covers all proposed mutations
  -----------------------------------------------------------------------------
  FOR v_change IN SELECT value FROM jsonb_array_elements(v_changes)
  LOOP
    IF jsonb_typeof(v_change) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_CHANGE_OBJECT', 'violated_invariant','INV-603');
    END IF;

    v_targets := v_change->'targets';
    IF v_targets IS NULL OR jsonb_typeof(v_targets) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_CHANGE_TARGETS', 'violated_invariant','INV-603');
    END IF;

    -- Parse target charter_version_ids
    v_target_charter_version_ids := ARRAY[]::uuid[];
    IF v_targets ? 'charter_version_ids' THEN
      IF jsonb_typeof(v_targets->'charter_version_ids') <> 'array' THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_VERSION_IDS', 'violated_invariant','INV-603');
      END IF;

      FOR v_obj IN SELECT value FROM jsonb_array_elements(v_targets->'charter_version_ids')
      LOOP
        v_change_id_txt := NULLIF(trim(both '"' from v_obj::text), '');
        IF v_change_id_txt IS NULL THEN
          RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_VERSION_IDS', 'violated_invariant','INV-603');
        END IF;
        BEGIN
          v_tmp_uuid := v_change_id_txt::uuid;
        EXCEPTION
          WHEN others THEN
            RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_VERSION_IDS', 'violated_invariant','INV-603');
        END;
        v_target_charter_version_ids := array_append(v_target_charter_version_ids, v_tmp_uuid);
      END LOOP;
    END IF;

    -- Parse target charter_activation_ids
    v_target_activation_ids := ARRAY[]::uuid[];
    IF v_targets ? 'charter_activation_ids' THEN
      IF jsonb_typeof(v_targets->'charter_activation_ids') <> 'array' THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_ACTIVATION_IDS', 'violated_invariant','INV-603');
      END IF;

      FOR v_obj IN SELECT value FROM jsonb_array_elements(v_targets->'charter_activation_ids')
      LOOP
        v_change_id_txt := NULLIF(trim(both '"' from v_obj::text), '');
        IF v_change_id_txt IS NULL THEN
          RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_ACTIVATION_IDS', 'violated_invariant','INV-603');
        END IF;
        BEGIN
          v_tmp_uuid := v_change_id_txt::uuid;
        EXCEPTION
          WHEN others THEN
            RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_TARGET_CHARTER_ACTIVATION_IDS', 'violated_invariant','INV-603');
        END;
        v_target_activation_ids := array_append(v_target_activation_ids, v_tmp_uuid);
      END LOOP;
    END IF;

    -- Coverage check
    v_missing := false;

    IF array_length(v_proposed_charter_version_ids,1) IS NOT NULL THEN
      FOR v_i IN 1..array_length(v_proposed_charter_version_ids,1)
      LOOP
        IF NOT (v_proposed_charter_version_ids[v_i] = ANY(v_target_charter_version_ids)) THEN
          v_missing := true;
        END IF;
      END LOOP;
    END IF;

    IF array_length(v_proposed_activation_ids,1) IS NOT NULL THEN
      FOR v_i IN 1..array_length(v_proposed_activation_ids,1)
      LOOP
        IF NOT (v_proposed_activation_ids[v_i] = ANY(v_target_activation_ids)) THEN
          v_missing := true;
        END IF;
      END LOOP;
    END IF;

    IF NOT v_missing THEN
      v_candidate := v_change;
      v_candidate_count := v_candidate_count + 1;
    END IF;
  END LOOP;

  IF v_candidate_count = 0 THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','FAIL',
      'reason','NO_VALID_CHANGE_PACKAGE_COVERS_TARGETS',
      'violated_invariant','INV-603'
    );
  END IF;

  IF v_candidate_count > 1 THEN
    RETURN jsonb_build_object(
      'policy_check_id', v_gate_id,
      'status','FAIL',
      'reason','AMBIGUOUS_CHANGE_PACKAGE',
      'violated_invariant','INV-405'
    );
  END IF;

  v_change := v_candidate;

  -----------------------------------------------------------------------------
  -- Validate selected change package
  -----------------------------------------------------------------------------
  v_change_id_txt := NULLIF(v_change->>'change_id','');
  IF v_change_id_txt IS NULL THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_CHANGE_ID', 'violated_invariant','INV-603');
  END IF;

  BEGIN
    v_change_id := v_change_id_txt::uuid;
  EXCEPTION
    WHEN others THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INVALID_CHANGE_ID', 'violated_invariant','INV-603');
  END;

  v_change_type := NULLIF(v_change->>'change_type','');
  IF v_change_type IS NULL OR v_change_type NOT IN ('CHARTER_AMENDMENT','CHARTER_ACTIVATION') THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','UNKNOWN_CHANGE_TYPE', 'violated_invariant','INV-603');
  END IF;

  v_dedupe_key := NULLIF(v_change->>'dedupe_key','');

  -- Replay checks (fail closed)
  IF EXISTS (
    SELECT 1 FROM cpo.cpo_changes
     WHERE agent_id = p_agent_id
       AND (content->>'change_id') = v_change_id::text
  ) THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','REPLAY_CHANGE_ID', 'violated_invariant','INV-605');
  END IF;

  IF v_dedupe_key IS NOT NULL AND EXISTS (
    SELECT 1 FROM cpo.cpo_changes
     WHERE agent_id = p_agent_id
       AND (content->>'dedupe_key') = v_dedupe_key
  ) THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','REPLAY_DEDUPE_KEY', 'violated_invariant','INV-605');
  END IF;

  -- Approvals validation
  v_approvals := v_change->'approvals';
  IF v_approvals IS NULL OR jsonb_typeof(v_approvals) <> 'array' THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_APPROVALS', 'violated_invariant','INV-603');
  END IF;

  IF jsonb_array_length(v_approvals) < GREATEST(p_required_approvals, 1) THEN
    RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INSUFFICIENT_APPROVALS', 'violated_invariant','INV-602');
  END IF;

  v_seen_approver_ids := ARRAY[]::text[];

  FOR v_approval IN SELECT value FROM jsonb_array_elements(v_approvals)
  LOOP
    IF jsonb_typeof(v_approval) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MALFORMED_APPROVAL', 'violated_invariant','INV-603');
    END IF;

    v_approved_by := v_approval->'approved_by';
    IF v_approved_by IS NULL OR jsonb_typeof(v_approved_by) <> 'object' THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_APPROVED_BY', 'violated_invariant','INV-603');
    END IF;

    v_approved_by_id := NULLIF(v_approved_by->>'id','');
    IF v_approved_by_id IS NULL THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_APPROVER_ID', 'violated_invariant','INV-602');
    END IF;

    -- Deterministic approvals: no duplicates
    IF v_approved_by_id = ANY(v_seen_approver_ids) THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','DUPLICATE_APPROVER', 'violated_invariant','INV-602');
    END IF;
    v_seen_approver_ids := array_append(v_seen_approver_ids, v_approved_by_id);

    -- Expiry required and enforced (P4 semantics)
    BEGIN
      v_expiry := NULLIF(v_approval->>'expiry_at','')::timestamptz;
    EXCEPTION
      WHEN others THEN
        RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','INVALID_APPROVAL_EXPIRY', 'violated_invariant','INV-602');
    END;

    IF v_expiry IS NULL THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','MISSING_APPROVAL_EXPIRY', 'violated_invariant','INV-602');
    END IF;

    IF v_expiry <= p_now THEN
      RETURN jsonb_build_object('policy_check_id', v_gate_id, 'status','FAIL', 'reason','EXPIRED_APPROVAL', 'violated_invariant','INV-602');
    END IF;
  END LOOP;

  -- PASS
  RETURN jsonb_build_object(
    'policy_check_id', v_gate_id,
    'status','PASS',
    'reason','CHANGE_PACKAGE_VALID',
    'change_id', v_change_id::text,
    'dedupe_key', v_dedupe_key,
    'declared_intent_recognized', v_declared_intent_recognized
  );
END;
$$;

REVOKE ALL ON FUNCTION cpo.evaluate_change_control_kernel(text,text,jsonb,timestamptz,uuid,integer,boolean,text) FROM PUBLIC;

-------------------------------------------------------------------------------
-- Wrapper: legacy 6-arg signature (prevents overload residue side-channels)
--
-- Derives authenticated context internally from DB state and DB roles.
-------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.evaluate_change_control_kernel(
  p_agent_id text,
  p_action_type text,
  p_artifacts jsonb,
  p_now timestamptz,
  p_current_charter_version_id uuid,
  p_required_approvals integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_is_genesis boolean;
  v_capability text;
BEGIN
  v_is_genesis := NOT EXISTS (
    SELECT 1 FROM cpo.cpo_agent_heads WHERE agent_id = p_agent_id
  );

  v_capability := CASE
    WHEN pg_has_role(session_user, 'cpo_bootstrap', 'MEMBER') THEN 'KERNEL_BOOTSTRAP'
    ELSE 'NORMAL'
  END;

  RETURN cpo.evaluate_change_control_kernel(
    p_agent_id,
    p_action_type,
    p_artifacts,
    p_now,
    p_current_charter_version_id,
    p_required_approvals,
    v_is_genesis,
    v_capability
  );
END;
$$;

REVOKE ALL ON FUNCTION cpo.evaluate_change_control_kernel(text,text,jsonb,timestamptz,uuid,integer) FROM PUBLIC;

COMMIT;
