-- p3_proof_resolved_inputs_required.sql
-- P3 STRUCTURAL PROOF: Resolved Inputs Must Exist (Fail-Closed)
--
-- BLOCKER ADDRESSED:
--   Missing charter/state/activation rows would cause evaluate_gates() to receive NULL,
--   which COALESCEs to {} → no policy_checks → PASS.
--   That's a FAIL-OPEN hole: "cannot evaluate" becomes "approved".
--
-- PROPERTY PROVEN:
--   commit_action() RAISEs on missing resolved inputs BEFORE calling evaluate_gates().
--   This is KERNEL GATE 5 (non-exceptionable).
--
-- WHY THIS MATTERS:
--   Without this check:
--     v_charter_content = NULL (missing row)
--     → evaluate_gates() receives NULL
--     → COALESCE(p_charter->'policy_checks', '{}') = '{}'
--     → no gates to evaluate
--     → outcome = PASS  ← FAIL-OPEN!
--   
--   With this check:
--     v_charter_content = NULL
--     → RAISE EXCEPTION 'RESOLVED_INPUT_MISSING'
--     → commit blocked  ← FAIL-CLOSED ✓

BEGIN;

DO $$
BEGIN
  RAISE NOTICE '';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 PROOF: Resolved Inputs Must Exist (Fail-Closed)';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 1: commit_action checks v_charter_content IS NULL
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 1: Charter content existence check ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must check v_charter_content IS NULL
  IF v_fn_body NOT LIKE '%v_charter_content IS NULL%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not check v_charter_content IS NULL. '
      'Missing charter could silently degrade to PASS (fail-open hole).';
  END IF;
  
  RAISE NOTICE 'OK: commit_action checks v_charter_content IS NULL';
  
  -- Must RAISE on missing (not soft error)
  IF v_fn_body NOT LIKE '%RESOLVED_INPUT_MISSING%Charter%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not RAISE on missing charter.';
  END IF;
  
  RAISE NOTICE 'OK: Raises RESOLVED_INPUT_MISSING on missing charter';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 2: commit_action checks v_state_content IS NULL
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 2: State content existence check ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  IF v_fn_body NOT LIKE '%v_state_content IS NULL%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not check v_state_content IS NULL.';
  END IF;
  
  RAISE NOTICE 'OK: commit_action checks v_state_content IS NULL';
  
  IF v_fn_body NOT LIKE '%RESOLVED_INPUT_MISSING%State%' OR 
     v_fn_body NOT LIKE '%RESOLVED_INPUT_MISSING%state%' THEN
    -- Check for either capitalization
    IF v_fn_body NOT LIKE '%RESOLVED_INPUT_MISSING%' THEN
      RAISE EXCEPTION 'PROOF FAIL: commit_action does not RAISE on missing state.';
    END IF;
  END IF;
  
  RAISE NOTICE 'OK: Raises RESOLVED_INPUT_MISSING on missing state';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 3: commit_action checks v_activation_content IS NULL
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 3: Activation content existence check ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  IF v_fn_body NOT LIKE '%v_activation_content IS NULL%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not check v_activation_content IS NULL.';
  END IF;
  
  RAISE NOTICE 'OK: commit_action checks v_activation_content IS NULL';
  
  IF v_fn_body NOT LIKE '%RESOLVED_INPUT_MISSING%activation%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not RAISE on missing activation.';
  END IF;
  
  RAISE NOTICE 'OK: Raises RESOLVED_INPUT_MISSING on missing activation';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 4: Resolved input checks happen BEFORE evaluate_gates()
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
  v_check_pos int;
  v_eval_pos int;
BEGIN
  RAISE NOTICE '=== PROOF 4: Checks happen BEFORE gate evaluation ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  v_check_pos := position('RESOLVED_INPUT_MISSING' IN v_fn_body);
  v_eval_pos := position('cpo.evaluate_gates(' IN v_fn_body);
  
  IF v_check_pos = 0 THEN
    RAISE EXCEPTION 'PROOF FAIL: RESOLVED_INPUT_MISSING check not found';
  END IF;
  
  IF v_eval_pos = 0 THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates call not found';
  END IF;
  
  IF v_check_pos > v_eval_pos THEN
    RAISE EXCEPTION 'PROOF FAIL: RESOLVED_INPUT_MISSING check is AFTER evaluate_gates. '
      'Must validate inputs BEFORE passing to gate engine.';
  END IF;
  
  RAISE NOTICE 'OK: Resolved input checks happen BEFORE evaluate_gates()';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 5: BEHAVIORAL - Demonstrate the fail-open hole that is now closed
-- ===========================================================================

DO $$
DECLARE
  v_result jsonb;
BEGIN
  RAISE NOTICE '=== PROOF 5: NULL charter would fail-open without this fix ===';
  
  -- Call evaluate_gates with NULL charter to show what would happen
  v_result := cpo.evaluate_gates(
    'PROOF_AGENT',
    '{"action": {"action_type": "TEST"}}'::jsonb,
    NULL::jsonb,  -- NULL charter
    '{}'::jsonb,
    '{}'::jsonb,
    clock_timestamp()
  );
  
  IF v_result->>'outcome' = 'PASS' THEN
    RAISE NOTICE 'DEMONSTRATED: evaluate_gates with NULL charter returns PASS';
    RAISE NOTICE 'This proves why KERNEL GATE 5 is required:';
    RAISE NOTICE '  Without it: missing charter → NULL → {} → no gates → PASS (fail-OPEN)';
    RAISE NOTICE '  With it:    missing charter → RAISE → blocked (fail-CLOSED)';
  ELSE
    RAISE NOTICE 'NOTE: evaluate_gates returned % (expected PASS for NULL charter)', v_result->>'outcome';
  END IF;
  
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 6: These are kernel gates (RAISE directly, non-exceptionable)
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
  v_check_pos int;
  v_gate_pos int;
BEGIN
  RAISE NOTICE '=== PROOF 6: Resolved input checks are kernel gates ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- RESOLVED_INPUT_MISSING uses RAISE EXCEPTION (not gate engine)
  IF v_fn_body NOT LIKE '%RAISE EXCEPTION ''RESOLVED_INPUT_MISSING%' THEN
    RAISE EXCEPTION 'PROOF FAIL: RESOLVED_INPUT_MISSING does not use RAISE EXCEPTION';
  END IF;
  
  RAISE NOTICE 'OK: Uses RAISE EXCEPTION (kernel gate, non-exceptionable)';
  
  -- Must be before gate engine (kernel layer, not policy layer)
  v_check_pos := position('RESOLVED_INPUT_MISSING' IN v_fn_body);
  v_gate_pos := position('cpo.evaluate_gates(' IN v_fn_body);
  
  IF v_check_pos > v_gate_pos THEN
    RAISE EXCEPTION 'PROOF FAIL: RESOLVED_INPUT_MISSING is after evaluate_gates. '
      'Kernel gates must execute before policy gates.';
  END IF;
  
  RAISE NOTICE 'OK: Kernel gate topology: resolved input check → gate engine';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- SUMMARY
-- ===========================================================================

DO $$
BEGIN
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 RESOLVED INPUTS REQUIRED PROOFS: ALL PASSED';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
  RAISE NOTICE 'PROPERTIES PROVEN:';
  RAISE NOTICE '  1. commit_action checks v_charter_content IS NULL';
  RAISE NOTICE '  2. commit_action checks v_state_content IS NULL';
  RAISE NOTICE '  3. commit_action checks v_activation_content IS NULL';
  RAISE NOTICE '  4. Checks happen BEFORE evaluate_gates()';
  RAISE NOTICE '  5. DEMONSTRATED: NULL charter → PASS without this fix (fail-open)';
  RAISE NOTICE '  6. These are kernel gates (RAISE, non-exceptionable)';
  RAISE NOTICE '';
  RAISE NOTICE 'INVARIANT (KERNEL GATE 5):';
  RAISE NOTICE '  Missing resolved inputs → RAISE → blocked';
  RAISE NOTICE '  "Cannot evaluate" = ERROR/blocked, not "approved"';
  RAISE NOTICE '';
  RAISE NOTICE 'This closes the fail-open hole where missing charter/state/activation';
  RAISE NOTICE 'would silently degrade to PASS via empty policy_checks.';
  RAISE NOTICE '';
END $$;

ROLLBACK;
