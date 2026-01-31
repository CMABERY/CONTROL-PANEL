-- P6 v3 Proof Suite — Change control as kernel physics
--
-- All proofs are hard-fail. No SKIP branches.
-- These tests are designed to run against a P0–P5 hardened system.
--
-- Preconditions:
--   - Schema cpo exists
--   - Table cpo.cpo_changes exists with (agent_id, action_log_id, content) at minimum
--   - Function cpo.evaluate_change_control_kernel(...) exists (from p6_change_control_kernel_patch.sql)
--
-- Notes:
--   - Proofs call evaluate_change_control_kernel directly (behavioral) to avoid coupling to commit_action return shapes.
--   - Wiring into the write aperture is covered by p6_ci_guard_change_control.sql.

BEGIN;

DO $$
DECLARE
  v_agent text := 'P6_PROOF_' || floor(random()*1000000)::text;
  v_now timestamptz := clock_timestamp();

  v_current_charter_version_id uuid := gen_random_uuid();

  v_new_charter_version_id uuid := gen_random_uuid();
  v_new_activation_id uuid := gen_random_uuid();

  v_change_id uuid := gen_random_uuid();
  v_dedupe_key text := 'P6_DEDUPE_' || floor(random()*1000000)::text;

  v_res jsonb;

  v_artifacts_ok jsonb;
  v_artifacts_missing_changes jsonb;
  v_artifacts_bad_approvals jsonb;
  v_artifacts_expired_approval jsonb;
  v_artifacts_missing_expiry jsonb;
  v_artifacts_unknown_change_type jsonb;
  v_artifacts_missing_targets jsonb;
  v_artifacts_duplicate_activation jsonb;

  v_action_log_id uuid := gen_random_uuid();

  v_tbl regclass;
BEGIN
  -----------------------------------------------------------------------------
  -- Baseline assumptions: required table exists
  -----------------------------------------------------------------------------
  v_tbl := to_regclass('cpo.cpo_changes');
  IF v_tbl IS NULL THEN
    RAISE EXCEPTION 'P6 PROOFS REQUIRE TABLE cpo.cpo_changes (not found)';
  END IF;

  -----------------------------------------------------------------------------
  -- Build canonical "OK" artifact envelope for a charter mutation
  -----------------------------------------------------------------------------
  v_artifacts_ok := jsonb_build_object(
    'charters', jsonb_build_array(
      jsonb_build_object(
        'charter_version_id', v_new_charter_version_id,
        'policy_checks', '{}'::jsonb
      )
    ),
    'charter_activations', jsonb_build_array(
      jsonb_build_object(
        'activation_id', v_new_activation_id,
        'charter_version_id', v_new_charter_version_id
      )
    ),
    'changes', jsonb_build_array(
      jsonb_build_object(
        'change_id', v_change_id,
        'change_type', 'CHARTER_AMENDMENT',
        'dedupe_key', v_dedupe_key,
        'targets', jsonb_build_object(
          'charter_version_ids', jsonb_build_array(v_new_charter_version_id),
          'charter_activation_ids', jsonb_build_array(v_new_activation_id)
        ),
        'approvals', jsonb_build_array(
          jsonb_build_object(
            'approved_by', jsonb_build_object('id','APPROVER_1','type','HUMAN'),
            'approved_at', (v_now - interval '1 minute')::text,
            'expiry_at', (v_now + interval '1 hour')::text
          )
        )
      )
    )
  );

  -----------------------------------------------------------------------------
  -- PROOF 1 (INV-601/602/603): OK package PASS; action_type is audit-only
  -----------------------------------------------------------------------------
  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'WEIRD_STRING_DO_NOT_ENFORCE',
    v_artifacts_ok,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'PASS' THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected PASS, got % (res=%)', v_res->>'status', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 2 (INV-601): Missing changes[] => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_missing_changes := v_artifacts_ok - 'changes';

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_missing_changes,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'CHANGE_PACKAGE_REQUIRED' THEN
    RAISE EXCEPTION 'PROOF 2 FAIL: expected FAIL/CHANGE_PACKAGE_REQUIRED, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 3 (INV-602/603): Missing approvals => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_bad_approvals := jsonb_set(
    v_artifacts_ok,
    '{changes,0,approvals}',
    '[]'::jsonb,
    true
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_bad_approvals,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: expected FAIL, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 4 (INV-602): Knife-edge expiry_at <= now is expired => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_expired_approval := jsonb_set(
    v_artifacts_ok,
    '{changes,0,approvals,0,expiry_at}',
    to_jsonb(v_now::text),
    true
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_expired_approval,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'APPROVAL_EXPIRED' THEN
    RAISE EXCEPTION 'PROOF 4 FAIL: expected FAIL/APPROVAL_EXPIRED, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 5 (INV-602): Missing expiry_at is invalid (fail-closed) => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_missing_expiry := (jsonb_set(
    v_artifacts_ok,
    '{changes,0,approvals,0}',
    (v_artifacts_ok#>'{changes,0,approvals,0}') - 'expiry_at',
    true
  ));

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_missing_expiry,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'APPROVAL_EXPIRY_REQUIRED' THEN
    RAISE EXCEPTION 'PROOF 5 FAIL: expected FAIL/APPROVAL_EXPIRY_REQUIRED, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 6 (INV-603): Unknown change_type => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_unknown_change_type := jsonb_set(
    v_artifacts_ok,
    '{changes,0,change_type}',
    '"ALIEN_TECH"'::jsonb,
    true
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_unknown_change_type,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'UNKNOWN_CHANGE_TYPE' THEN
    RAISE EXCEPTION 'PROOF 6 FAIL: expected FAIL/UNKNOWN_CHANGE_TYPE, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 7 (INV-603): Missing targets coverage => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_missing_targets := jsonb_set(
    v_artifacts_ok,
    '{changes,0,targets,charter_activation_ids}',
    '[]'::jsonb,
    true
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_missing_targets,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' THEN
    RAISE EXCEPTION 'PROOF 7 FAIL: expected FAIL, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 8 (INV-605): Duplicate activation of current charter version => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_duplicate_activation := jsonb_build_object(
    'charter_activations', jsonb_build_array(
      jsonb_build_object(
        'activation_id', gen_random_uuid(),
        'charter_version_id', v_current_charter_version_id
      )
    ),
    'changes', (v_artifacts_ok->'changes')
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_ACTIVATE',
    v_artifacts_duplicate_activation,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'DUPLICATE_CHARTER_ACTIVATION' THEN
    RAISE EXCEPTION 'PROOF 8 FAIL: expected FAIL/DUPLICATE_CHARTER_ACTIVATION, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 9 (INV-605): Replay change_id => FAIL
  -----------------------------------------------------------------------------
  INSERT INTO cpo.cpo_changes(agent_id, action_log_id, content)
  VALUES (
    v_agent,
    v_action_log_id,
    jsonb_build_object(
      'change_id', v_change_id,
      'dedupe_key', v_dedupe_key,
      'change_type', 'CHARTER_AMENDMENT'
    )
  );

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_ok,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'REPLAY_CHANGE_ID' THEN
    RAISE EXCEPTION 'PROOF 9 FAIL: expected FAIL/REPLAY_CHANGE_ID, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 10 (INV-605): Replay dedupe_key with new change_id => FAIL
  -----------------------------------------------------------------------------
  v_artifacts_ok := jsonb_set(v_artifacts_ok, '{changes,0,change_id}', to_jsonb(gen_random_uuid()), true);

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'CHARTER_PROPOSE',
    v_artifacts_ok,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'REPLAY_DEDUPE_KEY' THEN
    RAISE EXCEPTION 'PROOF 10 FAIL: expected FAIL/REPLAY_DEDUPE_KEY, got res=%', v_res;
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 11 (INV-606): Genesis bootstrap exemption is authenticated (db_role + genesis)
  --   - Genesis + KERNEL_BOOTSTRAP => PASS even without changes[]
  --   - Non-genesis + action_type BOOTSTRAP_* => still FAIL without changes[]
  -----------------------------------------------------------------------------

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'BOOTSTRAP_EXPLOIT',
    v_artifacts_missing_changes,
    v_now,
    v_current_charter_version_id,
    1,
    true,
    'KERNEL_BOOTSTRAP'
  );

  IF v_res->>'status' != 'PASS' OR v_res->>'reason' != 'GENESIS_BOOTSTRAP_EXEMPT' THEN
    RAISE EXCEPTION 'PROOF 11a FAIL: expected PASS/GENESIS_BOOTSTRAP_EXEMPT, got res=%', v_res;
  END IF;

  v_res := cpo.evaluate_change_control_kernel(
    v_agent,
    'BOOTSTRAP_EXPLOIT',
    v_artifacts_missing_changes,
    v_now,
    v_current_charter_version_id,
    1,
    false,
    'NORMAL'
  );

  IF v_res->>'status' != 'FAIL' OR v_res->>'reason' != 'CHANGE_PACKAGE_REQUIRED' THEN
    RAISE EXCEPTION 'PROOF 11b FAIL: expected FAIL/CHANGE_PACKAGE_REQUIRED, got res=%', v_res;
  END IF;

  RAISE NOTICE 'P6 PROOFS PASSED (v3): Change control invariants enforced';
END $$;

ROLLBACK;
