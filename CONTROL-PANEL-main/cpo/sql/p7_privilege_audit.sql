-- P7 Privilege Audit (hard-fail)
-- Fails if privilege drift would permit bypass of kernel physics.
--
-- Checks:
--   1) PUBLIC has EXECUTE on any cpo function => FAIL
--   2) PUBLIC has DML on any cpo table => FAIL
--   3) SECURITY DEFINER functions in cpo must lock search_path => FAIL
--
-- Notes:
--   - This is intentionally strict. If you truly want a PUBLIC function, it should live
--     outside the cpo schema or be explicitly exempted (add an allowlist below).

DO $$
DECLARE
  v_cnt int;
  v_bad text;
BEGIN
  -- 1) PUBLIC EXECUTE
  SELECT count(*) INTO v_cnt
  FROM information_schema.role_routine_grants g
  WHERE g.routine_schema = 'cpo'
    AND g.grantee = 'PUBLIC'
    AND g.privilege_type = 'EXECUTE';

  IF v_cnt > 0 THEN
    RAISE EXCEPTION 'P7 PRIVILEGE AUDIT FAIL: PUBLIC has EXECUTE on % cpo routines', v_cnt;
  END IF;

  -- 2) PUBLIC DML
  SELECT count(*) INTO v_cnt
  FROM information_schema.role_table_grants g
  WHERE g.table_schema = 'cpo'
    AND g.grantee = 'PUBLIC'
    AND g.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE');

  IF v_cnt > 0 THEN
    RAISE EXCEPTION 'P7 PRIVILEGE AUDIT FAIL: PUBLIC has DML on % cpo tables', v_cnt;
  END IF;

  -- 3) SECURITY DEFINER search_path lock
  -- Allowlist (if you need exemptions): add signatures here.
  -- Example: ('cpo.some_helper(text)') etc.
  WITH definer AS (
    SELECT
      p.oid,
      n.nspname AS schema_name,
      p.proname AS function_name,
      pg_get_function_identity_arguments(p.oid) AS identity_args,
      pg_get_functiondef(p.oid) AS defn
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'cpo'
      AND p.prosecdef = true
  ),
  offenders AS (
    SELECT schema_name || '.' || function_name || '(' || identity_args || ')' AS sig
    FROM definer
    WHERE defn !~* 'SET[[:space:]]+search_path'
  )
  SELECT string_agg(sig, E'\n') INTO v_bad
  FROM offenders;

  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION 'P7 PRIVILEGE AUDIT FAIL: SECURITY DEFINER functions missing SET search_path: %', E'\n' || v_bad;
  END IF;

END $$;
