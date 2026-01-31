-- p4_exception_expiry_enforcement_v3.sql
--
-- P4: Exceptions are time-bounded authority, not escape hatches.
--
-- Locked invariants enforced by these functions:
--   INV-402  expiry_at <= now  => expired (inclusive knife-edge)
--   INV-403  expiry_at IS NULL => invalid (fail-closed)
--   INV-405  deterministic exception selection
--
-- Context / topology notes:
--   * INV-401 (exceptions apply only to FAIL) is enforced by the gate engine:
--     it consults exceptions only after a gate evaluates to FAIL.
--   * INV-406 (kernel gates cannot be exceptioned) is enforced by P0.5 topology:
--     kernel-mandatory gates run in the prelude and never consult exception logic.
--
-- This patch focuses on *exception validity* and *exception selection*.

BEGIN;

-- Helper: scope match is strict and fail-closed.
--   * scope.all == true => applies to all action types
--   * otherwise scope.action_types must be an array and contain p_action_type
--   * any other shape => no match
CREATE OR REPLACE FUNCTION cpo._exception_scope_allows_action_type(
  p_scope jsonb,
  p_action_type text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE
    WHEN p_scope IS NULL THEN false
    WHEN p_scope->>'all' = 'true' THEN true
    WHEN (p_scope ? 'action_types')
         AND jsonb_typeof(p_scope->'action_types') = 'array'
      THEN EXISTS (
        SELECT 1
          FROM jsonb_array_elements_text(p_scope->'action_types') t(v)
         WHERE t.v = p_action_type
      )
    ELSE false
  END;
$$;

REVOKE ALL ON FUNCTION cpo._exception_scope_allows_action_type(jsonb, text) FROM PUBLIC;


-- cpo.is_exception_valid
-- Returns TRUE iff the *latest* exception event for exception_id is ACTIVE,
-- unexpired, and in-scope.
--
-- IMPORTANT: We evaluate validity against the latest row (by table id) for a
-- logical exception_id, to avoid "zombie" application of older ACTIVE rows
-- after a later REVOKED/SUPERSEDED row exists.
CREATE OR REPLACE FUNCTION cpo.is_exception_valid(
  p_agent_id text,
  p_exception_id uuid,
  p_action_type text,
  p_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_exc jsonb;
  v_expiry timestamptz;
BEGIN
  -- Fetch the latest event for this logical exception_id
  SELECT e.content
    INTO v_exc
    FROM cpo.cpo_exceptions e
   WHERE e.agent_id = p_agent_id
     AND e.content->>'exception_id' = p_exception_id::text
   ORDER BY e.id DESC
   LIMIT 1;

  IF v_exc IS NULL THEN
    RETURN false;
  END IF;

  -- Status must be ACTIVE
  IF COALESCE(v_exc->>'status', '') <> 'ACTIVE' THEN
    RETURN false;
  END IF;

  -- expiry_at is REQUIRED (INV-403). Missing/blank/invalid => invalid.
  BEGIN
    v_expiry := NULLIF(v_exc->>'expiry_at', '')::timestamptz;
  EXCEPTION
    WHEN invalid_text_representation OR datetime_field_overflow THEN
      RETURN false;
  END;

  IF v_expiry IS NULL THEN
    RETURN false;
  END IF;

  -- Inclusive expiry rule (INV-402): expiry_at <= now is expired.
  IF v_expiry <= p_now THEN
    RETURN false;
  END IF;

  -- Scope must match.
  IF NOT cpo._exception_scope_allows_action_type(v_exc->'scope', p_action_type) THEN
    RETURN false;
  END IF;

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION cpo.is_exception_valid(text, uuid, text, timestamptz) FROM PUBLIC;


-- cpo.find_valid_exception
-- Returns a jsonb envelope describing the chosen valid exception, or NULL.
--
-- Determinism (INV-405):
--   * collapse ledger rows to "latest event per exception_id" (by id DESC)
--   * scan candidates newest-first (by latest row id DESC)
--   * pick the first valid match
--   * if multiple valid matches exist for the same policy_check_id + action_type,
--     FAIL-CLOSED (raise) to prevent ambiguous authority.
CREATE OR REPLACE FUNCTION cpo.find_valid_exception(
  p_agent_id text,
  p_policy_check_id text,
  p_action_type text,
  p_now timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_row record;
  v_exc jsonb;
  v_expiry timestamptz;
  v_match jsonb;
  v_match_row_id bigint;
  v_match_count int := 0;
BEGIN
  -- Latest state per exception_id, filtered to this agent + policy_check_id.
  FOR v_row IN
    WITH latest AS (
      SELECT DISTINCT ON (e.content->>'exception_id')
             e.id AS row_id,
             e.content AS content
        FROM cpo.cpo_exceptions e
       WHERE e.agent_id = p_agent_id
         AND e.content->>'policy_check_id' = p_policy_check_id
         AND e.content ? 'exception_id'
       ORDER BY e.content->>'exception_id', e.id DESC
    )
    SELECT row_id, content
      FROM latest
     ORDER BY row_id DESC
  LOOP
    v_exc := v_row.content;

    -- Status must be ACTIVE
    IF COALESCE(v_exc->>'status', '') <> 'ACTIVE' THEN
      CONTINUE;
    END IF;

    -- expiry_at is REQUIRED (INV-403). Missing/blank/invalid => invalid.
    BEGIN
      v_expiry := NULLIF(v_exc->>'expiry_at', '')::timestamptz;
    EXCEPTION
      WHEN invalid_text_representation OR datetime_field_overflow THEN
        CONTINUE;
    END;

    IF v_expiry IS NULL THEN
      CONTINUE;
    END IF;

    -- Inclusive expiry rule (INV-402): expiry_at <= now is expired.
    IF v_expiry <= p_now THEN
      CONTINUE;
    END IF;

    -- Scope must match.
    IF NOT cpo._exception_scope_allows_action_type(v_exc->'scope', p_action_type) THEN
      CONTINUE;
    END IF;

    -- Valid match.
    v_match_count := v_match_count + 1;

    IF v_match_count = 1 THEN
      v_match_row_id := v_row.row_id;
      v_match := jsonb_build_object(
        'exception_id', (v_exc->>'exception_id')::uuid,
        'policy_check_id', p_policy_check_id,
        'expiry_at', v_expiry,
        'scope', v_exc->'scope'
      );
    ELSE
      -- Multiple valid matches => ambiguous authority.
      RAISE EXCEPTION
        'AMBIGUOUS_EXCEPTION_MATCH: multiple valid exceptions for agent_id=% policy_check_id=% action_type=% (first_row_id=% additional_row_id=%)',
        p_agent_id, p_policy_check_id, p_action_type, v_match_row_id, v_row.row_id
        USING ERRCODE = 'P0001';
    END IF;
  END LOOP;

  RETURN v_match;
END;
$$;

REVOKE ALL ON FUNCTION cpo.find_valid_exception(text, text, text, timestamptz) FROM PUBLIC;

COMMIT;
