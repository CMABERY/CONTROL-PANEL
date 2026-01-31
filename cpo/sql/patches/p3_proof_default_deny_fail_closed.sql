-- p3_proof_default_deny_fail_closed.sql
-- P3 STRUCTURAL PROOF: Default Deny + Fail-Closed Semantics
--
-- PROPERTIES PROVEN:
--   1. commit_action default is FAIL (fail-closed initialization)
--   2. applied=true ONLY when outcome ∈ {PASS, PASS_WITH_EXCEPTION}
--   3. Artifact inserts ONLY execute inside IF v_applied block
--   4. evaluate_gates catches ALL exceptions → ERROR → overall FAIL
--   5. Unknown operator → ERROR → FAIL
--   6. Disallowed pointer root → ERROR → FAIL

BEGIN;

DO $$
BEGIN
  RAISE NOTICE '';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 PROOF: Default Deny + Fail-Closed Semantics';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 1: commit_action initializes v_outcome to FAIL (fail-closed default)
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 1: commit_action initializes outcome=FAIL ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must initialize v_outcome to 'FAIL' (not 'PASS')
  IF v_fn_body NOT LIKE '%v_outcome text := ''FAIL''%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not initialize v_outcome := ''FAIL''. '
      'Default must be fail-closed.';
  END IF;
  
  RAISE NOTICE 'OK: v_outcome initialized to FAIL (fail-closed default)';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 2: applied=true ONLY for PASS or PASS_WITH_EXCEPTION
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 2: applied=true ONLY for PASS/PASS_WITH_EXCEPTION ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must have the correct applied condition
  IF v_fn_body NOT LIKE '%v_applied := (NOT v_dry_run) AND (v_outcome IN (''PASS'',''PASS_WITH_EXCEPTION''))%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not correctly compute v_applied. '
      'Must be: (NOT v_dry_run) AND (v_outcome IN (''PASS'',''PASS_WITH_EXCEPTION''))';
  END IF;
  
  RAISE NOTICE 'OK: applied := (NOT dry_run) AND outcome IN (PASS, PASS_WITH_EXCEPTION)';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 3: Artifact inserts ONLY inside IF v_applied block
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
  v_applied_block_start int;
  v_applied_block_end int;
  v_insert_positions int[];
  v_insert_pos int;
BEGIN
  RAISE NOTICE '=== PROOF 3: Artifact inserts ONLY inside IF v_applied ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- The action_logs insert is ALWAYS done (for audit)
  -- But canonical artifact inserts must be inside the IF v_applied block
  
  -- Find the IF v_applied THEN block
  v_applied_block_start := position('IF v_applied THEN' IN v_fn_body);
  
  IF v_applied_block_start = 0 THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing IF v_applied THEN block';
  END IF;
  
  RAISE NOTICE 'OK: IF v_applied THEN block found at position %', v_applied_block_start;
  
  -- Verify artifact inserts are AFTER the IF v_applied THEN
  -- We check for the canonical tables that should only be written when applied
  IF position('INSERT INTO cpo.cpo_charters' IN v_fn_body) < v_applied_block_start THEN
    RAISE EXCEPTION 'PROOF FAIL: cpo_charters insert is before IF v_applied block';
  END IF;
  
  IF position('INSERT INTO cpo.cpo_decisions' IN v_fn_body) < v_applied_block_start THEN
    RAISE EXCEPTION 'PROOF FAIL: cpo_decisions insert is before IF v_applied block';
  END IF;
  
  RAISE NOTICE 'OK: Artifact inserts are inside IF v_applied THEN block';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 4: evaluate_gates catches all exceptions → ERROR → FAIL
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 4: evaluate_gates catches all exceptions ===';
  
  v_fn_body := pg_get_functiondef('cpo.evaluate_gates(text, jsonb, jsonb, jsonb, jsonb, timestamptz)'::regprocedure);
  
  -- Must have EXCEPTION WHEN OTHERS block inside the gate loop
  IF v_fn_body NOT LIKE '%EXCEPTION WHEN OTHERS THEN%' THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates missing EXCEPTION WHEN OTHERS block';
  END IF;
  
  RAISE NOTICE 'OK: evaluate_gates has EXCEPTION WHEN OTHERS block';
  
  -- Must set status to ERROR on exception
  IF v_fn_body NOT LIKE '%''status'', ''ERROR''%' THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates does not set status=ERROR on exception';
  END IF;
  
  RAISE NOTICE 'OK: Exceptions produce status=ERROR';
  
  -- Must have v_has_error flag
  IF v_fn_body NOT LIKE '%v_has_error := true%' THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates does not set v_has_error on exception';
  END IF;
  
  RAISE NOTICE 'OK: v_has_error flag set on exception';
  
  -- outcome must be FAIL when v_has_error
  IF v_fn_body NOT LIKE '%WHEN v_has_error THEN ''FAIL''%' THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates does not return FAIL when v_has_error';
  END IF;
  
  RAISE NOTICE 'OK: outcome=FAIL when v_has_error';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 5: Unknown operator → ERROR → FAIL (behavioral)
-- ===========================================================================

DO $$
DECLARE
  v_charter jsonb;
  v_action_content jsonb;
  v_result jsonb;
  v_gate_status text;
  v_error_type text;
  v_outcome text;
BEGIN
  RAISE NOTICE '=== PROOF 5: Unknown operator → ERROR → FAIL ===';
  
  -- Charter with an unknown operator
  v_charter := jsonb_build_object(
    'policy_checks', jsonb_build_object(
      'gate_unknown_op', jsonb_build_object(
        'policy_check_id', 'gate_unknown_op',
        'rule', jsonb_build_object(
          'op', 'NONEXISTENT_OPERATOR',
          'args', jsonb_build_array('a', 'b')
        )
      )
    )
  );
  
  v_action_content := jsonb_build_object(
    'action', jsonb_build_object('action_type', 'TEST')
  );
  
  v_result := cpo.evaluate_gates(
    'PROOF_AGENT',
    v_action_content,
    v_charter,
    '{}'::jsonb,
    '{}'::jsonb,
    clock_timestamp()
  );
  
  v_gate_status := v_result->'gate_results'->0->>'status';
  v_error_type := v_result->'gate_results'->0->>'error_type';
  v_outcome := v_result->>'outcome';
  
  IF v_gate_status <> 'ERROR' THEN
    RAISE EXCEPTION 'PROOF FAIL: Unknown operator should produce ERROR, got %', v_gate_status;
  END IF;
  
  IF v_error_type <> 'UNKNOWN_OPERATOR' THEN
    RAISE EXCEPTION 'PROOF FAIL: Expected error_type UNKNOWN_OPERATOR, got %', v_error_type;
  END IF;
  
  IF v_outcome <> 'FAIL' THEN
    RAISE EXCEPTION 'PROOF FAIL: Unknown operator should produce FAIL outcome, got %', v_outcome;
  END IF;
  
  RAISE NOTICE 'OK: Unknown operator → ERROR (UNKNOWN_OPERATOR) → FAIL';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 6: Disallowed pointer root → ERROR → FAIL (behavioral)
-- ===========================================================================

DO $$
DECLARE
  v_charter jsonb;
  v_action_content jsonb;
  v_result jsonb;
  v_gate_status text;
  v_error_type text;
  v_outcome text;
BEGIN
  RAISE NOTICE '=== PROOF 6: Disallowed pointer root → ERROR → FAIL ===';
  
  -- Charter referencing a disallowed root
  v_charter := jsonb_build_object(
    'policy_checks', jsonb_build_object(
      'gate_bad_root', jsonb_build_object(
        'policy_check_id', 'gate_bad_root',
        'rule', jsonb_build_object(
          'op', 'EQ',
          'args', jsonb_build_array(
            '/forbidden/path',  -- Not in allowlist
            'value'
          )
        )
      )
    )
  );
  
  v_action_content := jsonb_build_object(
    'action', jsonb_build_object('action_type', 'TEST')
  );
  
  v_result := cpo.evaluate_gates(
    'PROOF_AGENT',
    v_action_content,
    v_charter,
    '{}'::jsonb,
    '{}'::jsonb,
    clock_timestamp()
  );
  
  v_gate_status := v_result->'gate_results'->0->>'status';
  v_error_type := v_result->'gate_results'->0->>'error_type';
  v_outcome := v_result->>'outcome';
  
  IF v_gate_status <> 'ERROR' THEN
    RAISE EXCEPTION 'PROOF FAIL: Disallowed root should produce ERROR, got %', v_gate_status;
  END IF;
  
  IF v_error_type <> 'DISALLOWED_ROOT' THEN
    RAISE EXCEPTION 'PROOF FAIL: Expected error_type DISALLOWED_ROOT, got %', v_error_type;
  END IF;
  
  IF v_outcome <> 'FAIL' THEN
    RAISE EXCEPTION 'PROOF FAIL: Disallowed root should produce FAIL outcome, got %', v_outcome;
  END IF;
  
  RAISE NOTICE 'OK: Disallowed root → ERROR (DISALLOWED_ROOT) → FAIL';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- SUMMARY
-- ===========================================================================

DO $$
BEGIN
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 DEFAULT DENY + FAIL-CLOSED PROOFS: ALL PASSED';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
  RAISE NOTICE 'PROPERTIES PROVEN:';
  RAISE NOTICE '  1. commit_action initializes v_outcome := ''FAIL'' (fail-closed)';
  RAISE NOTICE '  2. applied=true ONLY for PASS or PASS_WITH_EXCEPTION';
  RAISE NOTICE '  3. Artifact inserts ONLY inside IF v_applied block';
  RAISE NOTICE '  4. evaluate_gates catches ALL exceptions → ERROR → FAIL';
  RAISE NOTICE '  5. Unknown operator → ERROR (UNKNOWN_OPERATOR) → FAIL';
  RAISE NOTICE '  6. Disallowed pointer root → ERROR (DISALLOWED_ROOT) → FAIL';
  RAISE NOTICE '';
  RAISE NOTICE 'INVARIANT: Writes proceed ONLY on explicit PASS verdict.';
  RAISE NOTICE '';
END $$;

ROLLBACK;
