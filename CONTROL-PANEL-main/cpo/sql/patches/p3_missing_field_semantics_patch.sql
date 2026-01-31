-- p3_missing_field_semantics_patch.sql
-- P3: Strict missing-field semantics for gate evaluation
--
-- LOCKED SEMANTIC:
--   Any rule that references a pointer path implicitly requires it.
--   If that pointer resolves to missing or NULL (including JSON `null`),
--   the gate returns ERROR (not FAIL).
--
-- Semantic distinction:
--   FAIL  = "policy evaluated; answer is no"
--   ERROR = "policy could not evaluate" (misconfigured/unexpected state)
--
-- This patch:
--   1. Adds cpo.jsonptr_get_required() - raises on NULL/missing with specific SQLSTATE
--   2. Updates cpo._resolve_arg() to use required resolver for pointer operands
--
-- Apply order:
--   AFTER sql/007_policy_dsl.sql
--   BEFORE sql/008_gate_engine.sql (or as a patch to existing)

BEGIN;

-- ----------------------------------------------------------------------------
-- Required pointer resolver: raises on NULL/missing
-- SQLSTATE 'CPO01' allows gate engine to classify without string parsing
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.jsonptr_get_required(p_doc jsonb, p_ptr text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_result jsonb;
BEGIN
  -- Call existing resolver (handles root allowlist, path traversal)
  v_result := cpo.jsonptr_get(p_doc, p_ptr);
  
  -- Fail-closed: NULL result (missing path) or JSON null literal
  IF v_result IS NULL THEN
    RAISE EXCEPTION 'MISSING_POINTER'
      USING ERRCODE = 'CPO01',
            DETAIL = p_ptr,
            HINT = 'Pointer path resolved to NULL (missing or undefined)';
  END IF;
  
  -- Also fail on JSON null literal (explicit null in document)
  IF jsonb_typeof(v_result) = 'null' THEN
    RAISE EXCEPTION 'MISSING_POINTER'
      USING ERRCODE = 'CPO01',
            DETAIL = p_ptr,
            HINT = 'Pointer path resolved to JSON null literal';
  END IF;
  
  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION cpo.jsonptr_get_required IS
  'P3: Required pointer resolver. Raises SQLSTATE CPO01 on NULL/missing. '
  'Used by _resolve_arg for strict missing-field semantics.';

-- ----------------------------------------------------------------------------
-- Upgraded _resolve_arg: uses required resolver for pointer operands
-- This makes ALL pointer references implicitly required
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo._resolve_arg(p_ctx jsonb, p_arg jsonb)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_txt text;
BEGIN
  IF p_arg IS NULL THEN
    RETURN NULL;
  END IF;

  IF jsonb_typeof(p_arg) = 'string' THEN
    v_txt := p_arg::text;
    -- jsonb string renders with quotes; strip them
    v_txt := trim(both '"' from v_txt);

    IF left(v_txt, 1) = '/' THEN
      -- P3: Use REQUIRED resolver (raises on NULL/missing)
      RETURN cpo.jsonptr_get_required(p_ctx, v_txt);
    END IF;
  END IF;

  RETURN p_arg;
END;
$$;

COMMENT ON FUNCTION cpo._resolve_arg IS
  'P3: Argument resolver. Pointer references (strings starting with /) '
  'are implicitly required and raise SQLSTATE CPO01 if NULL/missing.';

-- ----------------------------------------------------------------------------
-- Harden exposure
-- ----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION cpo.jsonptr_get_required(jsonb, text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_commit') THEN
    GRANT EXECUTE ON FUNCTION cpo.jsonptr_get_required(jsonb, text) TO cpo_commit;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_owner') THEN
    ALTER FUNCTION cpo.jsonptr_get_required(jsonb, text) OWNER TO cpo_owner;
  END IF;
END $$;

COMMIT;
