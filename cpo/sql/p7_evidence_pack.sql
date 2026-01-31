-- P7 Evidence Pack SQL
-- Emits a single JSON object (one row) with schema/function fingerprints and metadata.
--
-- Required extensions:
--   - pgcrypto recommended (for sha256 via public.digest)
--
-- Inputs via psql -v:
--   :p7_run_id      string
--   :p7_commit_sha  string (optional)

\pset format unaligned
\pset tuples_only on

WITH
meta AS (
  SELECT
    COALESCE(:p7_run_id, '')::text AS run_id,
    NULLIF(COALESCE(:p7_commit_sha, ''), '')::text AS commit_sha,
    current_database() AS dbname,
    now() AT TIME ZONE 'UTC' AS generated_at_utc,
    current_setting('server_version') AS server_version
),
cpo_funcs AS (
  SELECT
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_function_identity_arguments(p.oid) AS identity_args,
    pg_get_functiondef(p.oid) AS definition
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'cpo'
),
func_hashes AS (
  SELECT
    schema_name,
    function_name,
    identity_args,
    encode(public.digest(convert_to(definition, 'utf8'), 'sha256'), 'hex') AS sha256
  FROM cpo_funcs
),
schema_fingerprint AS (
  SELECT encode(public.digest(convert_to(string_agg(sha256, '' ORDER BY schema_name, function_name, identity_args), 'utf8'), 'sha256'), 'hex') AS cpo_functions_sha256
  FROM func_hashes
),
public_exec AS (
  SELECT count(*) AS public_execute_count
  FROM information_schema.role_routine_grants g
  WHERE g.routine_schema = 'cpo'
    AND g.grantee = 'PUBLIC'
    AND g.privilege_type = 'EXECUTE'
),
public_dml AS (
  SELECT count(*) AS public_dml_count
  FROM information_schema.role_table_grants g
  WHERE g.table_schema = 'cpo'
    AND g.grantee = 'PUBLIC'
    AND g.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')
)
SELECT jsonb_pretty(
  jsonb_build_object(
    'run_id', (SELECT run_id FROM meta),
    'commit_sha', (SELECT commit_sha FROM meta),
    'generated_at_utc', (SELECT generated_at_utc FROM meta),
    'dbname', (SELECT dbname FROM meta),
    'server_version', (SELECT server_version FROM meta),
    'fingerprints', jsonb_build_object(
      'cpo_functions_sha256', (SELECT cpo_functions_sha256 FROM schema_fingerprint)
    ),
    'security', jsonb_build_object(
      'public_execute_count', (SELECT public_execute_count FROM public_exec),
      'public_dml_count', (SELECT public_dml_count FROM public_dml)
    ),
    'cpo_functions', (
      SELECT jsonb_agg(
        jsonb_build_object(
          'signature', schema_name || '.' || function_name || '(' || identity_args || ')',
          'sha256', sha256
        )
        ORDER BY schema_name, function_name, identity_args
      )
      FROM func_hashes
    )
  )
);
