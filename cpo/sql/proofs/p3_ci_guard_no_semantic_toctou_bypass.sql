-- p3_ci_guard_no_semantic_toctou_bypass.sql
--
-- CI Guard: commit_action() MUST NOT derive enforcement from semantic fields.
-- Hard-fails if any prohibited patterns are detected in ANY cpo.commit_action overload.
--
-- Targets the canonical write aperture signature explicitly:
--   cpo.commit_action(text, jsonb, jsonb, uuid, uuid)
--
-- Also scans all other overloads (if any) to prevent side-channel wrappers.
--
-- Prohibited:
--   - action_type prefix privilege (SYSTEM_%, BOOTSTRAP_%), via LIKE/starts_with/left/regex
--   - dry_run-gated expected-refs enforcement (since dry_run still writes action logs)
--
-- Optional guard:
--   - If commit_action fetches resolved charter/state/activation content AND calls evaluate_gates(),
--     it MUST include KERNEL GATE 5 checks that hard-RAISE on missing resolved inputs.
--
-- This file is read-only; it makes no writes.

BEGIN;

DO $$
DECLARE
  v_canonical_sig constant text := 'cpo.commit_action(text, jsonb, jsonb, uuid, uuid)';
  v_canonical_oid oid;

  v_sigs text[];
  v_sig text;
  v_proc_oid oid;

  v_def text;
  v_norm text;

  v_search_start int;
  v_pos int;
  v_window text;

  v_found boolean;

  -- helper flags for optional KERNEL GATE 5 check
  v_has_resolved_fetch boolean;
  v_has_gate_call boolean;
  v_has_gate5_charter boolean;
  v_has_gate5_state boolean;
  v_has_gate5_activation boolean;
BEGIN
  ---------------------------------------------------------------------------
  -- PRELUDE: ensure canonical signature exists (exact regprocedure)
  ---------------------------------------------------------------------------
  BEGIN
    v_canonical_oid := v_canonical_sig::regprocedure::oid;
  EXCEPTION
    WHEN undefined_function THEN
      RAISE EXCEPTION 'CI GUARD FAIL: canonical write aperture missing: %', v_canonical_sig;
  END;

  ---------------------------------------------------------------------------
  -- Enumerate ALL overloads of cpo.commit_action (side-channel scan)
  ---------------------------------------------------------------------------
  SELECT array_agg((p.oid::regprocedure)::text ORDER BY (p.oid::regprocedure)::text)
    INTO v_sigs
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'cpo'
     AND p.proname = 'commit_action';

  IF v_sigs IS NULL OR array_length(v_sigs, 1) = 0 THEN
    RAISE EXCEPTION 'CI GUARD FAIL: no cpo.commit_action functions found';
  END IF;

  ---------------------------------------------------------------------------
  -- Scan each overload for prohibited patterns
  ---------------------------------------------------------------------------
  FOREACH v_sig IN ARRAY v_sigs LOOP
    v_proc_oid := v_sig::regprocedure::oid;
    SELECT pg_get_functiondef(v_proc_oid) INTO v_def;

    -- normalize: lower-case + collapse whitespace/newlines for reliable matching
    v_norm := lower(regexp_replace(regexp_replace(v_def, E'[\\n\\r\\t]+', ' ', 'g'), ' +', ' ', 'g'));

    -------------------------------------------------------------------------
    -- PROHIBITED: action_type prefix privilege (SYSTEM / BOOTSTRAP)
    -------------------------------------------------------------------------
    IF v_norm LIKE '%like ''system\_%''%' ESCAPE '\' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (LIKE system_%%) in %', v_sig;
    END IF;

    IF v_norm LIKE '%like ''bootstrap\_%''%' ESCAPE '\' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (LIKE bootstrap_%%) in %', v_sig;
    END IF;

    -- starts_with(action_type, 'SYSTEM') / starts_with(..., 'BOOTSTRAP')
    IF v_norm ~ 'starts_with\\s*\\(\\s*[^,]*action_type[^,]*,\\s*''system' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (starts_with ... system) in %', v_sig;
    END IF;

    IF v_norm ~ 'starts_with\\s*\\(\\s*[^,]*action_type[^,]*,\\s*''bootstrap' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (starts_with ... bootstrap) in %', v_sig;
    END IF;

    -- left(action_type, N) = 'SYSTEM' / 'BOOTSTRAP'
    IF v_norm ~ 'left\\s*\\(\\s*[^,]*action_type[^,]*,\\s*\\d+\\s*\\)\\s*=\\s*''system' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (left ... = system) in %', v_sig;
    END IF;

    IF v_norm ~ 'left\\s*\\(\\s*[^,]*action_type[^,]*,\\s*\\d+\\s*\\)\\s*=\\s*''bootstrap' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (left ... = bootstrap) in %', v_sig;
    END IF;

    -- regex prefix checks: action_type ~ '^SYSTEM' / '^BOOTSTRAP'
    IF v_norm ~ 'action_type\\s*~\\s*''\\^system' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (regex ^system) in %', v_sig;
    END IF;

    IF v_norm ~ 'action_type\\s*~\\s*''\\^bootstrap' THEN
      RAISE EXCEPTION 'CI GUARD FAIL: semantic bypass detected (regex ^bootstrap) in %', v_sig;
    END IF;

    -------------------------------------------------------------------------
    -- PROHIBITED: dry_run-gated expected-refs enforcement
    -- If an IF NOT v_dry_run block exists, ensure it does NOT contain expected-refs logic.
    -------------------------------------------------------------------------
    v_search_start := 1;
    LOOP
      v_pos := strpos(substr(v_norm, v_search_start), 'if not v_dry_run');
      EXIT WHEN v_pos = 0;

      v_pos := v_pos + v_search_start - 1;
      v_window := substr(v_norm, v_pos, 1600);

      IF v_window LIKE '%p_expected_charter_activation_id%'
         OR v_window LIKE '%p_expected_state_snapshot_id%'
         OR v_window LIKE '%stale_context%'
         OR v_window LIKE '%40001%'
      THEN
        RAISE EXCEPTION 'CI GUARD FAIL: dry_run appears to gate expected-refs enforcement in %', v_sig;
      END IF;

      v_search_start := v_pos + 1;
    END LOOP;

    -------------------------------------------------------------------------
    -- OPTIONAL: If this overload is the integrated write aperture (fetches resolved inputs
    -- and calls evaluate_gates), then it MUST include KERNEL GATE 5 checks.
    -------------------------------------------------------------------------
    v_has_resolved_fetch :=
      (v_norm LIKE '%from cpo.cpo_charters%' AND v_norm LIKE '%select content into v_charter_content%')
      OR (v_norm LIKE '%from cpo.cpo_state_snapshots%' AND v_norm LIKE '%select content into v_state_content%')
      OR (v_norm LIKE '%from cpo.cpo_charter_activations%' AND v_norm LIKE '%select content into v_activation_content%');

    v_has_gate_call := (v_norm LIKE '%cpo.evaluate_gates%' OR v_norm LIKE '%evaluate_gates%');

    IF v_has_resolved_fetch AND v_has_gate_call THEN
      v_has_gate5_charter := (v_norm LIKE '%v_charter_content is null%' AND v_norm LIKE '%resolved_input_missing%');
      v_has_gate5_state := (v_norm LIKE '%v_state_content is null%' AND v_norm LIKE '%resolved_input_missing%');
      v_has_gate5_activation := (v_norm LIKE '%v_activation_content is null%' AND v_norm LIKE '%resolved_input_missing%');

      IF NOT v_has_gate5_charter THEN
        RAISE EXCEPTION 'CI GUARD FAIL: missing KERNEL GATE 5 charter check in %', v_sig;
      END IF;

      IF NOT v_has_gate5_state THEN
        RAISE EXCEPTION 'CI GUARD FAIL: missing KERNEL GATE 5 state check in %', v_sig;
      END IF;

      IF NOT v_has_gate5_activation THEN
        RAISE EXCEPTION 'CI GUARD FAIL: missing KERNEL GATE 5 activation check in %', v_sig;
      END IF;
    END IF;

  END LOOP;

  ---------------------------------------------------------------------------
  -- Final: ensure canonical signature is among overloads (sanity)
  ---------------------------------------------------------------------------
  v_found := false;
  FOREACH v_sig IN ARRAY v_sigs LOOP
    IF v_sig = v_canonical_sig THEN
      v_found := true;
    END IF;
  END LOOP;

  IF NOT v_found THEN
    RAISE EXCEPTION 'CI GUARD FAIL: canonical signature not present in overload list (unexpected): %', v_canonical_sig;
  END IF;

  RAISE NOTICE 'OK: CI guard passed for % (and scanned % overload(s))',
    v_canonical_sig, array_length(v_sigs, 1);

END $$;

ROLLBACK;
