-- P6 CI Guard — change-control semantic integrity
--
-- Hard-fails if:
--   - Additional overloads exist (side-channel risk)
--   - action_type-based bypass patterns appear (SYSTEM_/BOOTSTRAP_)
--   - Genesis exemption is derived from strings rather than (is_genesis + capability)
--   - Approval expiry isn't enforced with knife-edge semantics (expiry_at <= now is expired)
--   - P6 isn't wired into the write aperture (commit_action -> ... -> change control)

DO $$
DECLARE
  v_schema_oid oid;
  v_cnt int;
  v_sig text;
  v_core regprocedure;
  v_wrapper regprocedure;
  v_coredef text;
  v_wrapdef text;

  v_commit regprocedure;
  v_commitdef text;

  v_prelude regprocedure;
  v_preludedef text;

  v_has_direct bool;
  v_has_prelude bool;
BEGIN
  -- Ensure we are checking the intended schema.
  SELECT n.oid INTO v_schema_oid FROM pg_namespace n WHERE n.nspname = 'cpo';
  IF v_schema_oid IS NULL THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: schema cpo not found';
  END IF;

  -- Overload count guard (side-channels)
  SELECT count(*) INTO v_cnt
    FROM pg_proc p
   WHERE p.proname = 'evaluate_change_control_kernel'
     AND p.pronamespace = v_schema_oid;

  IF v_cnt != 2 THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: expected exactly 2 overloads of cpo.evaluate_change_control_kernel (core + wrapper), found %', v_cnt;
  END IF;

  -- Resolve exact signatures (hard-fail if missing)
  v_core := 'cpo.evaluate_change_control_kernel(text,text,jsonb,timestamptz,uuid,integer,boolean,text)'::regprocedure;
  v_wrapper := 'cpo.evaluate_change_control_kernel(text,text,jsonb,timestamptz,uuid,integer)'::regprocedure;

  SELECT pg_get_functiondef(v_core) INTO v_coredef;
  SELECT pg_get_functiondef(v_wrapper) INTO v_wrapdef;

  IF v_coredef IS NULL OR length(v_coredef) = 0 THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: could not load core function definition';
  END IF;
  IF v_wrapdef IS NULL OR length(v_wrapdef) = 0 THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: could not load wrapper function definition';
  END IF;

  -- Ban semantic bypass patterns (action_type prefixes)
  IF v_coredef ~* 'LIKE\s+''SYSTEM_%''' OR v_coredef ~* 'LIKE\s+''BOOTSTRAP_%''' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: semantic bypass pattern LIKE SYSTEM_/BOOTSTRAP_ detected in core';
  END IF;
  IF v_coredef ~* 'starts_with\s*\(' OR v_coredef ~* '\bleft\s*\(' OR v_coredef ~* '\~\s*''\^SYSTEM''' OR v_coredef ~* '\~\s*''\^BOOTSTRAP''' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: semantic bypass prefix-matching detected in core';
  END IF;

  -- Require authenticated genesis exemption (not strings)
  IF v_coredef !~ 'p_is_genesis' OR v_coredef !~ 'p_capability' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: core does not reference p_is_genesis and p_capability';
  END IF;
  IF v_coredef !~ 'GENESIS_BOOTSTRAP_EXEMPT' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: core missing explicit GENESIS_BOOTSTRAP_EXEMPT path';
  END IF;

  -- Approval expiry knife-edge semantics
  IF v_coredef !~ 'v_expiry\s*<=\s*p_now' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: core missing knife-edge expiry check (expiry_at <= now is expired)';
  END IF;
  IF v_coredef !~ 'APPROVAL_EXPIRY_REQUIRED' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: core missing fail-closed expiry-at-required behavior';
  END IF;

  -- Wrapper must derive capability from db role, not strings
  IF v_wrapdef !~ 'pg_has_role\(session_user,\s*''cpo_bootstrap''' THEN
    RAISE EXCEPTION 'P6 CI GUARD FAIL: wrapper does not derive capability from cpo_bootstrap role';
  END IF;

  -- Write-aperture wiring guard
  -- We accept either:
  --   commit_action -> evaluate_change_control_kernel (direct)
  -- or
  --   commit_action -> evaluate_kernel_mandatory_gates -> evaluate_change_control_kernel

  v_commit := 'cpo.commit_action(text, jsonb, jsonb, uuid, uuid)'::regprocedure;
  SELECT pg_get_functiondef(v_commit) INTO v_commitdef;

  v_has_direct := (v_commitdef ~ 'evaluate_change_control_kernel');
  v_has_prelude := (v_commitdef ~ 'evaluate_kernel_mandatory_gates');

  IF v_has_direct THEN
    RAISE NOTICE 'OK: commit_action references evaluate_change_control_kernel directly';
  ELSIF v_has_prelude THEN
    BEGIN
      v_prelude := 'cpo.evaluate_kernel_mandatory_gates(jsonb, jsonb, text, timestamptz, uuid, uuid, boolean, text)'::regprocedure;
      SELECT pg_get_functiondef(v_prelude) INTO v_preludedef;
    EXCEPTION WHEN undefined_function THEN
      -- Try a looser search: find any evaluate_kernel_mandatory_gates overload and inspect it.
      SELECT 'cpo.evaluate_kernel_mandatory_gates'::regproc::oid::regprocedure INTO v_prelude;
      SELECT pg_get_functiondef(v_prelude) INTO v_preludedef;
    END;

    IF v_preludedef IS NULL OR length(v_preludedef)=0 THEN
      RAISE EXCEPTION 'P6 CI GUARD FAIL: commit_action calls evaluate_kernel_mandatory_gates, but prelude function definition could not be loaded';
    END IF;

    IF v_preludedef !~ 'evaluate_change_control_kernel' THEN
      RAISE EXCEPTION 'P6 CI GUARD FAIL: prelude does not reference evaluate_change_control_kernel';
    END IF;

    RAISE NOTICE 'OK: commit_action -> prelude -> evaluate_change_control_kernel chain detected';
  ELSE
    RAISE EXCEPTION 'P6 CI GUARD FAIL: no wiring detected from commit_action to change control (direct or via prelude)';
  END IF;

  RAISE NOTICE 'P6 CI GUARD PASS: change-control wiring + semantic constraints verified.';
END;
$$;
