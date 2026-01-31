-- p3_gate_engine_missing_field_patch.sql
-- P3: Gate engine upgrade for strict missing-field error classification
--
-- This patch upgrades cpo.evaluate_gates() to:
--   1. Classify SQLSTATE 'CPO01' (MISSING_POINTER) as error_type = 'MISSING_FIELD'
--   2. Extract the missing pointer path from PG_EXCEPTION_DETAIL
--   3. Ensure ERROR gates are NEVER exception-eligible
--
-- Prerequisites:
--   - sql/008_gate_engine.sql applied
--   - p3_missing_field_semantics_patch.sql applied
--
-- Behavior:
--   - FAIL = "evaluated, policy said no" → exceptions consulted
--   - ERROR = "could not evaluate" → exceptions NOT consulted, blocks write

BEGIN;

CREATE OR REPLACE FUNCTION cpo.evaluate_gates(
  p_agent_id text,
  p_action_log_content jsonb,
  p_charter jsonb,
  p_state jsonb,
  p_charter_activation jsonb,
  p_now timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_policy_checks jsonb := COALESCE(p_charter->'policy_checks', '{}'::jsonb);
  v_gate_results jsonb := '[]'::jsonb;
  v_keys text[];
  v_key text;
  v_check jsonb;
  v_rule jsonb;
  v_ok boolean;
  v_ctx jsonb;
  v_action_type text := COALESCE(p_action_log_content->'action'->>'action_type', '');
  v_exception jsonb;
  v_status text;
  v_has_fail boolean := false;
  v_has_error boolean := false;
  v_has_exception boolean := false;
  
  -- P3: Error classification variables
  v_sqlstate text;
  v_sqlerrm text;
  v_detail text;
  v_error_type text;
  v_gate_entry jsonb;
BEGIN
  -- Build canonical evaluation context
  v_ctx := jsonb_build_object(
    'action', COALESCE(p_action_log_content->'action', '{}'::jsonb),
    'actor', COALESCE(p_action_log_content->'actor', '{}'::jsonb),
    'resolved', jsonb_build_object(
      'charter', COALESCE(p_charter, '{}'::jsonb),
      'state', COALESCE(p_state, '{}'::jsonb),
      'charter_activation', COALESCE(p_charter_activation, '{}'::jsonb)
    ),
    'resources', '{}'::jsonb,
    'now', to_char(p_now AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')
  );

  -- Deterministic key order
  SELECT array_agg(k ORDER BY k)
    INTO v_keys
    FROM jsonb_object_keys(v_policy_checks) AS k;

  IF v_keys IS NULL THEN
    v_keys := ARRAY[]::text[];
  END IF;

  FOREACH v_key IN ARRAY v_keys LOOP
    v_check := v_policy_checks->v_key;
    v_rule := COALESCE(v_check->'rule', jsonb_build_object('op','TRUE'));

    BEGIN
      v_ok := cpo.eval_rule(v_ctx, v_rule);

      IF v_ok THEN
        v_status := 'PASS';
        v_gate_entry := jsonb_strip_nulls(jsonb_build_object(
          'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
          'status', v_status,
          'fail_message', v_check->>'fail_message'
        ));
      ELSE
        -- FAIL path: exceptions ARE consulted
        v_exception := cpo.find_valid_exception(
          p_agent_id, 
          COALESCE(v_check->>'policy_check_id', v_key), 
          v_action_type, 
          p_now
        );
        
        IF v_exception IS NOT NULL THEN
          v_status := 'PASS_WITH_EXCEPTION';
          v_has_exception := true;
          v_gate_entry := jsonb_strip_nulls(jsonb_build_object(
            'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
            'status', v_status,
            'fail_message', v_check->>'fail_message',
            'exception_id', v_exception->>'exception_id'
          ));
        ELSE
          v_status := 'FAIL';
          v_has_fail := true;
          v_gate_entry := jsonb_strip_nulls(jsonb_build_object(
            'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
            'status', v_status,
            'fail_message', v_check->>'fail_message'
          ));
        END IF;
      END IF;

      v_gate_results := v_gate_results || jsonb_build_array(v_gate_entry);

    EXCEPTION WHEN OTHERS THEN
      -- ERROR path: exceptions are NOT consulted (gate could not evaluate)
      v_has_error := true;
      
      -- Capture exception details
      GET STACKED DIAGNOSTICS 
        v_sqlstate = RETURNED_SQLSTATE,
        v_sqlerrm = MESSAGE_TEXT,
        v_detail = PG_EXCEPTION_DETAIL;
      
      -- P3: Classify error type based on SQLSTATE
      IF v_sqlstate = 'CPO01' THEN
        -- MISSING_POINTER from jsonptr_get_required
        v_error_type := 'MISSING_FIELD';
        v_gate_entry := jsonb_build_object(
          'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
          'status', 'ERROR',
          'error_type', v_error_type,
          'error_code', 'MISSING_FIELD',
          'missing_pointer', v_detail,  -- The pointer path
          'sqlstate', v_sqlstate,
          'message', v_sqlerrm
        );
      ELSIF v_sqlerrm LIKE 'Unknown operator%' THEN
        -- Unknown operator from eval_rule
        v_error_type := 'UNKNOWN_OPERATOR';
        v_gate_entry := jsonb_build_object(
          'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
          'status', 'ERROR',
          'error_type', v_error_type,
          'error_code', 'UNKNOWN_OPERATOR',
          'sqlstate', v_sqlstate,
          'message', v_sqlerrm
        );
      ELSIF v_sqlerrm LIKE 'Pointer root not allowed%' THEN
        -- Disallowed pointer root from jsonptr_get
        v_error_type := 'DISALLOWED_ROOT';
        v_gate_entry := jsonb_build_object(
          'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
          'status', 'ERROR',
          'error_type', v_error_type,
          'error_code', 'DISALLOWED_ROOT',
          'sqlstate', v_sqlstate,
          'message', v_sqlerrm
        );
      ELSE
        -- Generic rule evaluation error
        v_error_type := 'RULE_EVAL_ERROR';
        v_gate_entry := jsonb_build_object(
          'policy_check_id', COALESCE(v_check->>'policy_check_id', v_key),
          'status', 'ERROR',
          'error_type', v_error_type,
          'sqlstate', v_sqlstate,
          'message', v_sqlerrm
        );
      END IF;
      
      v_gate_results := v_gate_results || jsonb_build_array(v_gate_entry);
    END;
  END LOOP;

  RETURN jsonb_build_object(
    'outcome',
      CASE
        WHEN v_has_error THEN 'FAIL'      -- ERROR → FAIL (fail-closed)
        WHEN v_has_fail THEN 'FAIL'
        WHEN v_has_exception THEN 'PASS_WITH_EXCEPTION'
        ELSE 'PASS'
      END,
    'gate_results', v_gate_results
  );
END;
$$;

COMMENT ON FUNCTION cpo.evaluate_gates IS
  'P3: Gate engine with strict missing-field semantics. '
  'SQLSTATE CPO01 (MISSING_POINTER) → ERROR with error_type=MISSING_FIELD. '
  'ERROR gates block writes and are never exception-eligible.';

-- Harden exposure (same as baseline)
REVOKE ALL ON FUNCTION cpo.evaluate_gates(text, jsonb, jsonb, jsonb, jsonb, timestamptz) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_commit') THEN
    GRANT EXECUTE ON FUNCTION cpo.evaluate_gates(text, jsonb, jsonb, jsonb, jsonb, timestamptz) TO cpo_commit;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpo_owner') THEN
    ALTER FUNCTION cpo.evaluate_gates(text, jsonb, jsonb, jsonb, jsonb, timestamptz) OWNER TO cpo_owner;
  END IF;
END $$;

COMMIT;
