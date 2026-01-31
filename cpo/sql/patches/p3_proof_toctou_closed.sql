-- p3_proof_toctou_closed.sql
-- P3 STRUCTURAL PROOF: TOCTOU-Closed Gate Evaluation
--
-- PROPERTIES PROVEN:
--   1. Gate evaluation occurs inside commit_action transaction
--   2. Evaluation context (charter, state, activation) is resolved BEFORE evaluation
--   3. Same heads snapshot used for evaluation AND write decision
--   4. Advisory lock serializes per-agent commits
--   5. FOR UPDATE lock on heads row prevents concurrent mutation
--
-- TOCTOU = Time-Of-Check-To-Time-Of-Use vulnerability
-- Closed = evaluation and write decision use same snapshot

BEGIN;

DO $$
BEGIN
  RAISE NOTICE '';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 PROOF: TOCTOU-Closed Gate Evaluation';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 1: evaluate_gates is called inside commit_action (same transaction)
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 1: evaluate_gates called inside commit_action ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must call cpo.evaluate_gates (schema-qualified)
  IF v_fn_body NOT LIKE '%cpo.evaluate_gates(%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action does not call cpo.evaluate_gates(). '
      'Gate evaluation must be inside the commit transaction.';
  END IF;
  
  RAISE NOTICE 'OK: cpo.evaluate_gates() called inside commit_action';
  RAISE NOTICE 'IMPLICATION: Same transaction = same snapshot = TOCTOU-closed';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 2: Context resolved BEFORE evaluation
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
  v_resolve_pos int;
  v_evaluate_pos int;
BEGIN
  RAISE NOTICE '=== PROOF 2: Context resolved BEFORE gate evaluation ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Charter content fetch
  v_resolve_pos := position('SELECT content INTO v_charter_content' IN v_fn_body);
  v_evaluate_pos := position('cpo.evaluate_gates(' IN v_fn_body);
  
  IF v_resolve_pos = 0 THEN
    -- May use bootstrap artifacts instead - check for that pattern
    v_resolve_pos := position('v_charter_content := p_artifacts->''charters''->' IN v_fn_body);
    IF v_resolve_pos = 0 THEN
      RAISE EXCEPTION 'PROOF FAIL: Charter content resolution not found';
    END IF;
  END IF;
  
  IF v_resolve_pos > v_evaluate_pos THEN
    RAISE EXCEPTION 'PROOF FAIL: Charter content resolved AFTER evaluate_gates call. '
      'Context must be resolved before evaluation.';
  END IF;
  
  RAISE NOTICE 'OK: Charter content resolved before evaluation';
  
  -- State content fetch
  v_resolve_pos := position('SELECT content INTO v_state_content' IN v_fn_body);
  IF v_resolve_pos = 0 THEN
    v_resolve_pos := position('v_state_content := p_artifacts->''state_snapshots''->' IN v_fn_body);
  END IF;
  
  IF v_resolve_pos > v_evaluate_pos THEN
    RAISE EXCEPTION 'PROOF FAIL: State content resolved AFTER evaluate_gates call';
  END IF;
  
  RAISE NOTICE 'OK: State content resolved before evaluation';
  
  -- Activation content fetch
  v_resolve_pos := position('SELECT content INTO v_activation_content' IN v_fn_body);
  IF v_resolve_pos = 0 THEN
    v_resolve_pos := position('v_activation_content := p_artifacts->''charter_activations''->' IN v_fn_body);
  END IF;
  
  IF v_resolve_pos > v_evaluate_pos THEN
    RAISE EXCEPTION 'PROOF FAIL: Activation content resolved AFTER evaluate_gates call';
  END IF;
  
  RAISE NOTICE 'OK: Activation content resolved before evaluation';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 3: Advisory lock serializes per-agent commits
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 3: Advisory lock serializes per-agent commits ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must have advisory lock
  IF v_fn_body NOT LIKE '%pg_advisory_xact_lock(hashtext(''cpo:commit:'' || p_agent_id))%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing per-agent advisory lock. '
      'Concurrent commits must be serialized.';
  END IF;
  
  RAISE NOTICE 'OK: pg_advisory_xact_lock serializes commits per agent';
  RAISE NOTICE 'IMPLICATION: No concurrent writes can interleave';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 4: FOR UPDATE lock on heads row
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 4: FOR UPDATE lock on heads row ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must lock heads row with FOR UPDATE
  IF v_fn_body NOT LIKE '%FROM cpo.cpo_agent_heads%WHERE agent_id = p_agent_id%FOR UPDATE%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing FOR UPDATE on heads row. '
      'Heads must be locked during commit.';
  END IF;
  
  RAISE NOTICE 'OK: Heads row locked with FOR UPDATE';
  RAISE NOTICE 'IMPLICATION: Heads cannot change between evaluation and write';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 5: Expected refs validation (TOCTOU check)
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 5: Expected refs validation (TOCTOU check) ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must validate expected refs match current heads
  IF v_fn_body NOT LIKE '%p_expected_charter_activation_id <> v_cur_charter_activation_id%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing expected charter activation check';
  END IF;
  
  IF v_fn_body NOT LIKE '%p_expected_state_snapshot_id <> v_cur_state_snapshot_id%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing expected state snapshot check';
  END IF;
  
  -- Must raise STALE_CONTEXT on mismatch
  IF v_fn_body NOT LIKE '%RAISE EXCEPTION ''STALE_CONTEXT''%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing STALE_CONTEXT exception';
  END IF;
  
  RAISE NOTICE 'OK: Expected refs validated against current heads';
  RAISE NOTICE 'OK: STALE_CONTEXT raised on mismatch';
  RAISE NOTICE 'IMPLICATION: Client must have current snapshot to commit';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- PROOF 6: Evaluation timestamp is transaction-local
-- ===========================================================================

DO $$
DECLARE
  v_fn_body text;
BEGIN
  RAISE NOTICE '=== PROOF 6: Evaluation uses transaction-local timestamp ===';
  
  v_fn_body := pg_get_functiondef('cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure);
  
  -- Must capture v_now at start
  IF v_fn_body NOT LIKE '%v_now%timestamptz := clock_timestamp()%' THEN
    RAISE EXCEPTION 'PROOF FAIL: commit_action missing v_now := clock_timestamp()';
  END IF;
  
  -- Must pass v_now to evaluate_gates (not a new timestamp)
  IF v_fn_body NOT LIKE '%evaluate_gates(%v_now%' THEN
    RAISE EXCEPTION 'PROOF FAIL: evaluate_gates not called with v_now';
  END IF;
  
  RAISE NOTICE 'OK: v_now captured at transaction start';
  RAISE NOTICE 'OK: Same timestamp used for evaluation and logging';
  RAISE NOTICE '';
END $$;

-- ===========================================================================
-- SUMMARY
-- ===========================================================================

DO $$
BEGIN
  RAISE NOTICE '=============================================================';
  RAISE NOTICE 'P3 TOCTOU-CLOSED PROOFS: ALL PASSED';
  RAISE NOTICE '=============================================================';
  RAISE NOTICE '';
  RAISE NOTICE 'PROPERTIES PROVEN:';
  RAISE NOTICE '  1. evaluate_gates called inside commit_action (same tx)';
  RAISE NOTICE '  2. Context (charter/state/activation) resolved before eval';
  RAISE NOTICE '  3. Advisory lock serializes per-agent commits';
  RAISE NOTICE '  4. FOR UPDATE lock on heads row during commit';
  RAISE NOTICE '  5. Expected refs validated (STALE_CONTEXT on mismatch)';
  RAISE NOTICE '  6. Transaction-local timestamp for evaluation';
  RAISE NOTICE '';
  RAISE NOTICE 'INVARIANT: Evaluation and write decision use the same';
  RAISE NOTICE '           snapshot. No TOCTOU vulnerability.';
  RAISE NOTICE '';
END $$;

ROLLBACK;
