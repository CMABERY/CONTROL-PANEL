-- p4_exception_expiry_proofs_v3.sql
--
-- P4 Proof Suite (hard-assert only)
--
-- Preconditions:
--   * cpo.cpo_exceptions table exists
--   * cpo.evaluate_gates exists (from 008_gate_engine.sql)
--   * cpo.eval_rule exists (from 007_policy_dsl.sql)
--   * p4_exception_expiry_enforcement_v3.sql applied
--
-- Proof coverage:
--   INV-401 Exceptions apply only to FAIL (ERROR ignores exceptions)
--   INV-402 expiry_at <= now => expired (inclusive)
--   INV-403 expiry_at IS NULL => invalid (fail-closed)
--   INV-404 PASS_WITH_EXCEPTION records exception_id + policy_check_id
--   INV-405 Deterministic selection / ambiguity fail-closed
--
BEGIN;

DO $$
DECLARE
  v_agent_id text := 'P4_TEST_' || floor(random()*1000000)::text;
  v_action_log_id uuid;
  v_now timestamptz := clock_timestamp();
  v_now_iso text;
  v_past_iso text;
  v_future_iso text;

  v_policy_check_id text := 'GATE-ACTION-TYPE-CONTROL';

  v_exception_id_valid uuid := gen_random_uuid();
  v_exception_id_expired uuid := gen_random_uuid();
  v_exception_id_edge uuid := gen_random_uuid();
  v_exception_id_missing_expiry uuid := gen_random_uuid();
  v_exception_id_revoked uuid := gen_random_uuid();
  v_exception_id_ambig_1 uuid := gen_random_uuid();
  v_exception_id_ambig_2 uuid := gen_random_uuid();

  v_charter jsonb;
  v_action_log_content jsonb;
  v_res jsonb;

  v_gate jsonb;
  v_gate_status text;
  v_gate_exception_id text;
  v_gate_policy_check_id text;

  v_found jsonb;
  v_ok boolean;
BEGIN
  v_now_iso := to_char(v_now, 'YYYY-MM-DD"T"HH24:MI:SSOF');
  v_past_iso := to_char(v_now - interval '1 hour', 'YYYY-MM-DD"T"HH24:MI:SSOF');
  v_future_iso := to_char(v_now + interval '1 hour', 'YYYY-MM-DD"T"HH24:MI:SSOF');

  -----------------------------------------------------------------------------
  -- Setup: Charter gate that fails unless action_type == 'ALLOWED_ACTION'
  -----------------------------------------------------------------------------
  v_charter := jsonb_build_object(
    'policy_checks', jsonb_build_object(
      v_policy_check_id,
      jsonb_build_object(
        'fail_message', 'P4 canary: deny unless exception applies',
        'rule', jsonb_build_object(
          'op', 'EQ',
          'arg1', jsonb_build_object('pointer','/action/action_type'),
          'arg2', 'ALLOWED_ACTION'
        )
      )
    )
  );

  -----------------------------------------------------------------------------
  -- Seed exceptions
  -----------------------------------------------------------------------------
  v_action_log_id := gen_random_uuid();

  -- Valid exception for DENIED_ACTION
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_valid,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -- Expired exception (expiry in the past)
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_expired,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_past_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -- Knife-edge expired exception (expiry == now) (inclusive)
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_edge,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_now_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -- Missing expiry_at (must be invalid, fail-closed)
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_missing_expiry,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -- Revoked exception: older ACTIVE row + later REVOKED row (same exception_id)
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_revoked,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -- Later row: REVOKED (must win over older ACTIVE)
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_revoked,
      'policy_check_id', v_policy_check_id,
      'status', 'REVOKED',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  -----------------------------------------------------------------------------
  -- PROOF 1: is_exception_valid recognizes only the valid one
  -----------------------------------------------------------------------------
  v_ok := cpo.is_exception_valid(v_agent_id, v_exception_id_valid, 'DENIED_ACTION', v_now);
  IF NOT v_ok THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected valid exception to be valid';
  END IF;

  v_ok := cpo.is_exception_valid(v_agent_id, v_exception_id_expired, 'DENIED_ACTION', v_now);
  IF v_ok THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected expired exception to be invalid';
  END IF;

  v_ok := cpo.is_exception_valid(v_agent_id, v_exception_id_edge, 'DENIED_ACTION', v_now);
  IF v_ok THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected knife-edge exception to be invalid (expiry_at <= now)';
  END IF;

  v_ok := cpo.is_exception_valid(v_agent_id, v_exception_id_missing_expiry, 'DENIED_ACTION', v_now);
  IF v_ok THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected missing-expiry exception to be invalid';
  END IF;

  v_ok := cpo.is_exception_valid(v_agent_id, v_exception_id_revoked, 'DENIED_ACTION', v_now);
  IF v_ok THEN
    RAISE EXCEPTION 'PROOF 1 FAIL: expected revoked exception to be invalid (latest row wins)';
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 2: find_valid_exception returns the expected exception_id (and only one)
  -----------------------------------------------------------------------------
  v_found := cpo.find_valid_exception(v_agent_id, v_policy_check_id, 'DENIED_ACTION', v_now);

  IF v_found IS NULL THEN
    RAISE EXCEPTION 'PROOF 2 FAIL: expected to find a valid exception';
  END IF;

  IF (v_found->>'exception_id')::uuid != v_exception_id_valid THEN
    RAISE EXCEPTION 'PROOF 2 FAIL: expected exception_id %, got %', v_exception_id_valid, v_found->>'exception_id';
  END IF;

  IF v_found->>'policy_check_id' != v_policy_check_id THEN
    RAISE EXCEPTION 'PROOF 2 FAIL: expected policy_check_id %, got %', v_policy_check_id, v_found->>'policy_check_id';
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 3: PASS_WITH_EXCEPTION records policy_check_id + exception_id (INV-404)
  -----------------------------------------------------------------------------
  v_action_log_content := jsonb_build_object(
    'action', jsonb_build_object('action_type','DENIED_ACTION')
  );

  v_res := cpo.evaluate_gates(
    v_agent_id,
    v_charter,
    v_action_log_content,
    '{}'::jsonb,
    v_now
  );

  IF v_res->>'outcome' != 'PASS_WITH_EXCEPTION' THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: expected PASS_WITH_EXCEPTION, got %', v_res->>'outcome';
  END IF;

  -- locate the gate result
  SELECT gr
    INTO v_gate
    FROM jsonb_array_elements(v_res->'gate_results') gr
   WHERE gr->>'policy_check_id' = v_policy_check_id;

  IF v_gate IS NULL THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: gate_results missing %', v_policy_check_id;
  END IF;

  v_gate_status := v_gate->>'status';
  IF v_gate_status != 'PASS_WITH_EXCEPTION' THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: expected gate status PASS_WITH_EXCEPTION, got %', v_gate_status;
  END IF;

  v_gate_exception_id := v_gate->>'exception_id';
  IF v_gate_exception_id IS NULL THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: PASS_WITH_EXCEPTION must record exception_id';
  END IF;
  IF v_gate_exception_id::uuid != v_exception_id_valid THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: expected exception_id %, got %', v_exception_id_valid, v_gate_exception_id;
  END IF;

  v_gate_policy_check_id := v_gate->>'policy_check_id';
  IF v_gate_policy_check_id IS DISTINCT FROM v_policy_check_id THEN
    RAISE EXCEPTION 'PROOF 3 FAIL: policy_check_id mismatch';
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 4: ERROR ignores exceptions (INV-401)
  -- Gate uses an unknown operator which must ERROR; exception must not apply.
  -----------------------------------------------------------------------------
  v_charter := jsonb_build_object(
    'policy_checks', jsonb_build_object(
      'GATE-WILL-ERROR',
      jsonb_build_object(
        'fail_message', 'P4 error canary',
        'rule', jsonb_build_object(
          'op', 'NO_SUCH_OPERATOR',
          'arg1', jsonb_build_object('pointer','/action/action_type'),
          'arg2', 'anything'
        )
      )
    )
  );

  -- Insert a valid exception for the ERROR gate anyway; it must have no effect.
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', gen_random_uuid(),
      'policy_check_id', 'GATE-WILL-ERROR',
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  v_action_log_content := jsonb_build_object(
    'action', jsonb_build_object('action_type','DENIED_ACTION')
  );

  v_res := cpo.evaluate_gates(
    v_agent_id,
    v_charter,
    v_action_log_content,
    '{}'::jsonb,
    v_now
  );

  IF v_res->>'outcome' != 'FAIL' THEN
    RAISE EXCEPTION 'PROOF 4 FAIL: expected outcome FAIL (ERROR blocks write), got %', v_res->>'outcome';
  END IF;

  SELECT gr
    INTO v_gate
    FROM jsonb_array_elements(v_res->'gate_results') gr
   WHERE gr->>'policy_check_id' = 'GATE-WILL-ERROR';

  IF v_gate IS NULL THEN
    RAISE EXCEPTION 'PROOF 4 FAIL: gate_results missing GATE-WILL-ERROR';
  END IF;

  IF v_gate->>'status' != 'ERROR' THEN
    RAISE EXCEPTION 'PROOF 4 FAIL: expected gate status ERROR, got %', v_gate->>'status';
  END IF;

  IF v_gate ? 'exception_id' THEN
    RAISE EXCEPTION 'PROOF 4 FAIL: ERROR must not record exception_id (exceptions not consulted)';
  END IF;

  -----------------------------------------------------------------------------
  -- PROOF 5: Multiple valid exceptions for the same gate+action_type is ambiguous
  -- and must hard-fail (INV-405, fail-closed).
  -----------------------------------------------------------------------------
  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_ambig_1,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  v_action_log_id := gen_random_uuid();
  INSERT INTO cpo.cpo_exceptions(agent_id, action_log_id, content)
  VALUES (
    v_agent_id,
    v_action_log_id,
    jsonb_build_object(
      'exception_id', v_exception_id_ambig_2,
      'policy_check_id', v_policy_check_id,
      'status', 'ACTIVE',
      'created_at', v_now_iso,
      'expiry_at', v_future_iso,
      'scope', jsonb_build_object('action_types', jsonb_build_array('DENIED_ACTION'))
    )
  );

  DECLARE
    v_sqlstate text;
    v_msg text;
  BEGIN
    PERFORM cpo.find_valid_exception(v_agent_id, v_policy_check_id, 'DENIED_ACTION', v_now);
    RAISE EXCEPTION 'PROOF 5 FAIL: ambiguous exception match should raise';
  EXCEPTION
    WHEN OTHERS THEN
      GET STACKED DIAGNOSTICS
        v_sqlstate = RETURNED_SQLSTATE,
        v_msg = MESSAGE_TEXT;
      IF v_sqlstate <> 'P0001' OR v_msg NOT LIKE 'AMBIGUOUS_EXCEPTION_MATCH:%' THEN
        RAISE EXCEPTION 'PROOF 5 FAIL: expected P0001 AMBIGUOUS_EXCEPTION_MATCH, got %: %', v_sqlstate, v_msg;
      END IF;
  END;

  RAISE NOTICE 'P4 PROOFS PASSED';

END $$;

ROLLBACK;
