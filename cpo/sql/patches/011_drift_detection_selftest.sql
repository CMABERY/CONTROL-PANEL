-- sql/011_drift_detection_selftest.sql
-- P5 Self-Test v3: Drift Detection Events
--
-- PROVES (deterministically, with hard assertions):
--   1. REPEATED_EXCEPTIONS: N bypasses in window → drift_event
--   2. INV-504 dedupe: same signal re-emitted → skipped
--   3. Below threshold: N-1 bypasses → no drift_event
--   4. Fail-closed: SYSTEM_DRIFT_EVENT blocked by gate → no artifacts
--   5. EXPIRED_ASSUMPTION_REFERENCE: expired assumption referenced → drift_event
--   6. MODE_THRASH: frequent transitions → drift_event
--   7. STATE_STALENESS: old snapshot → drift_event
--
-- ALL P5 DRIFT SIGNALS ARE PROVEN BY THIS SUITE.
--
-- REQUIRES:
--   - P2 Step 6 v3 applied
--   - P3 Steps 1-3 applied (gate engine integrated)
--   - P4 applied (exception expiry)
--   - P5 applied (drift detection)
--
-- Runs inside BEGIN ... ROLLBACK (no canonical debris)

BEGIN;

DO $$
DECLARE
  v_agent text := 'AGENT_P5_DRIFT_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
  v_charter_version_id uuid := public.gen_random_uuid();
  v_activation_id uuid := public.gen_random_uuid();
  v_state0_id uuid := public.gen_random_uuid();
  
  v_exception_id uuid := public.gen_random_uuid();

  v_now timestamptz := clock_timestamp();
  v_now_iso text := to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  v_future_iso text := to_char((v_now + interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  v_past_iso text := to_char((v_now - interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');

  v_action_content jsonb;
  v_artifacts jsonb;
  v_res jsonb;

  v_expected_activation uuid;
  v_expected_state uuid;

  v_drift_results record;
  v_drift_event_count int;
  v_drift_event_row record;
  v_i int;
BEGIN
  -- ================================================================
  -- SETUP: Bootstrap agent with charter that allows SYSTEM_DRIFT_EVENT
  -- but blocks RESTRICTED_ACTION (needs exception to pass)
  -- ================================================================
  RAISE NOTICE 'SETUP: Bootstrap agent with drift-permissive charter...';

  v_action_content := jsonb_build_object(
    'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
    'action', jsonb_build_object(
      'action_type','BOOTSTRAP_CHARTER',
      'dry_run',false,
      'request_id','REQ-P5-BOOTSTRAP'
    )
  );

  v_artifacts := jsonb_build_object(
    'charters', jsonb_build_array(
      jsonb_build_object(
        'protocol_version','cpo-contracts@0.1.0',
        'charter_version_id', v_charter_version_id,
        'semver','1.0.0',
        'created_at', v_now_iso,
        'content', jsonb_build_object('note','P5 drift detection selftest charter'),
        'policy_checks', jsonb_build_object(
          'GATE-MODE', jsonb_build_object(
            'policy_check_id', 'GATE-MODE',
            'rule', jsonb_build_object(
              'op', 'OR',
              'args', jsonb_build_array(
                jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'SYSTEM')),
                jsonb_build_object('op', 'IN', 'args', jsonb_build_array(
                  '/action/action_type',
                  jsonb_build_array('CREATE_DECISION', 'CREATE_ASSUMPTION', 'MODE_CHANGE')
                ))
              )
            ),
            'fail_message', 'Action type not in allowlist'
          )
        )
      )
    ),
    'charter_activations', jsonb_build_array(
      jsonb_build_object(
        'protocol_version','cpo-contracts@0.1.0',
        'activation_id', v_activation_id,
        'seq', 1,
        'charter_version_id', v_charter_version_id,
        'activated_at', v_now_iso,
        'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
        'mode','NORMAL'
      )
    ),
    'state_snapshots', jsonb_build_array(
      jsonb_build_object(
        'protocol_version','cpo-contracts@0.1.0',
        'state_snapshot_id', v_state0_id,
        'seq', 1,
        'ts', v_now_iso,
        'mode','NORMAL',
        'mode_entered_at', v_now_iso,
        'charter_activation_id', v_activation_id,
        'state', jsonb_build_object('objective','P5 drift test')
      )
    )
  );

  v_res := cpo.commit_action(v_agent, v_action_content, v_artifacts, NULL, NULL);

  IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
    RAISE EXCEPTION 'SETUP FAIL: Bootstrap expected PASS, got %. gate_results: %', 
      v_res->>'outcome', v_res->'gate_results';
  END IF;

  RAISE NOTICE 'OK: Bootstrap succeeded';

  SELECT current_charter_activation_id, current_state_snapshot_id 
    INTO v_expected_activation, v_expected_state
    FROM cpo.cpo_agent_heads WHERE agent_id = v_agent;

  -- ================================================================
  -- SETUP: Create exception for RESTRICTED_ACTION on GATE-MODE
  -- ================================================================
  RAISE NOTICE 'SETUP: Creating exception for RESTRICTED_ACTION...';

  v_action_content := jsonb_build_object(
    'actor', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
    'action', jsonb_build_object(
      'action_type','SYSTEM_CREATE_EXCEPTION',
      'dry_run',false,
      'request_id','REQ-P5-EXC'
    )
  );

  v_artifacts := jsonb_build_object(
    'exceptions', jsonb_build_array(
      jsonb_build_object(
        'protocol_version','cpo-contracts@0.1.0',
        'exception_id', v_exception_id,
        'policy_check_id', 'GATE-MODE',
        'status', 'ACTIVE',
        'created_at', v_now_iso,
        'expiry_at', v_future_iso,
        'created_by', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
        'justification', 'P5 test: enable repeated exception bypasses',
        'scope', jsonb_build_object(
          'action_types', jsonb_build_array('RESTRICTED_ACTION')
        )
      )
    )
  );

  v_res := cpo.commit_action(v_agent, v_action_content, v_artifacts, v_expected_activation, v_expected_state);
  IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
    RAISE EXCEPTION 'SETUP FAIL: Could not create exception';
  END IF;

  SELECT current_charter_activation_id, current_state_snapshot_id 
    INTO v_expected_activation, v_expected_state
    FROM cpo.cpo_agent_heads WHERE agent_id = v_agent;

  RAISE NOTICE 'OK: Exception created';

  -- ================================================================
  -- TEST 1: REPEATED_EXCEPTIONS - N bypasses triggers drift_event
  -- Threshold is 3; we'll do 3 bypasses
  -- ================================================================
  RAISE NOTICE 'TEST 1: REPEATED_EXCEPTIONS - 3 bypasses triggers drift_event...';

  FOR v_i IN 1..3 LOOP
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','HUMAN_001','type','HUMAN'),
      'action', jsonb_build_object(
        'action_type','RESTRICTED_ACTION',
        'dry_run',false,
        'request_id','REQ-P5-BYPASS-' || v_i
      )
    );

    v_res := cpo.commit_action(v_agent, v_action_content, '{}'::jsonb, v_expected_activation, v_expected_state);

    IF v_res->>'outcome' <> 'PASS_WITH_EXCEPTION' THEN
      RAISE EXCEPTION 'TEST 1 SETUP FAIL: Bypass % expected PASS_WITH_EXCEPTION, got %',
        v_i, v_res->>'outcome';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation, v_expected_state
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent;
  END LOOP;

  RAISE NOTICE 'OK: 3 bypasses committed with PASS_WITH_EXCEPTION';

  -- Emit drift events
  SELECT COUNT(*) INTO v_drift_event_count FROM cpo.cpo_drift_events WHERE agent_id = v_agent;

  FOR v_drift_results IN
    SELECT * FROM cpo.emit_drift_events(
      v_agent, v_now, v_expected_activation, v_expected_state,
      3600, 3, 3, 86400  -- window, exception threshold, mode thrash threshold, staleness
    )
  LOOP
    IF v_drift_results.signal_type = 'REPEATED_EXCEPTIONS' THEN
      IF v_drift_results.outcome NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
        RAISE EXCEPTION 'TEST 1 FAIL: REPEATED_EXCEPTIONS emission outcome %, expected PASS',
          v_drift_results.outcome;
      END IF;
      IF v_drift_results.applied <> true THEN
        RAISE EXCEPTION 'TEST 1 FAIL: REPEATED_EXCEPTIONS emission applied=false';
      END IF;
      RAISE NOTICE 'OK: REPEATED_EXCEPTIONS drift_event emitted (id: %)', v_drift_results.drift_event_id;
    END IF;
  END LOOP;

  -- Verify drift_event artifact was inserted
  IF (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent) <= v_drift_event_count THEN
    RAISE EXCEPTION 'TEST 1 FAIL: No drift_event artifact inserted';
  END IF;

  -- Verify drift_event content
  SELECT * INTO v_drift_event_row
    FROM cpo.cpo_drift_events
   WHERE agent_id = v_agent
     AND content->>'signal_type' = 'REPEATED_EXCEPTIONS'
   ORDER BY action_log_id DESC
   LIMIT 1;

  IF v_drift_event_row IS NULL THEN
    RAISE EXCEPTION 'TEST 1 FAIL: REPEATED_EXCEPTIONS drift_event not found in artifacts';
  END IF;

  IF (v_drift_event_row.content->'predicate'->>'observed')::int < 3 THEN
    RAISE EXCEPTION 'TEST 1 FAIL: observed count should be >= 3, got %',
      v_drift_event_row.content->'predicate'->>'observed';
  END IF;

  IF v_drift_event_row.content->'predicate'->>'policy_check_id' <> 'GATE-MODE' THEN
    RAISE EXCEPTION 'TEST 1 FAIL: policy_check_id should be GATE-MODE';
  END IF;

  RAISE NOTICE 'OK: TEST 1 - REPEATED_EXCEPTIONS triggers drift_event with correct predicate';

  SELECT current_charter_activation_id, current_state_snapshot_id 
    INTO v_expected_activation, v_expected_state
    FROM cpo.cpo_agent_heads WHERE agent_id = v_agent;

  -- ================================================================
  -- TEST 2: INV-504 dedupe - same signal re-emitted is skipped
  -- ================================================================
  RAISE NOTICE 'TEST 2: INV-504 dedupe - same signal re-emitted is skipped...';

  v_drift_event_count := (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent);

  FOR v_drift_results IN
    SELECT * FROM cpo.emit_drift_events(
      v_agent, v_now, v_expected_activation, v_expected_state,
      3600, 3, 3, 86400
    )
  LOOP
    IF v_drift_results.signal_type = 'REPEATED_EXCEPTIONS' THEN
      IF v_drift_results.dedupe_skipped <> true THEN
        RAISE EXCEPTION 'TEST 2 FAIL: REPEATED_EXCEPTIONS should be dedupe_skipped=true on re-emission';
      END IF;
      RAISE NOTICE 'OK: REPEATED_EXCEPTIONS correctly skipped (dedupe)';
    END IF;
  END LOOP;

  IF (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent) > v_drift_event_count THEN
    RAISE EXCEPTION 'TEST 2 FAIL: Duplicate drift_event was inserted despite dedupe';
  END IF;

  RAISE NOTICE 'OK: TEST 2 - INV-504 dedupe prevents duplicate drift_event';

  -- ================================================================
  -- TEST 3: Below threshold does NOT emit
  -- Create new agent with only 2 bypasses (threshold is 3)
  -- ================================================================
  RAISE NOTICE 'TEST 3: Below threshold (2 bypasses) does NOT emit...';

  DECLARE
    v_agent2 text := 'AGENT_P5_BELOW_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
    v_charter2_id uuid := public.gen_random_uuid();
    v_activation2_id uuid := public.gen_random_uuid();
    v_state2_id uuid := public.gen_random_uuid();
    v_exception2_id uuid := public.gen_random_uuid();
    v_expected_activation2 uuid;
    v_expected_state2 uuid;
    v_drift_count_before int;
  BEGIN
    -- Bootstrap agent2 (copy charter structure)
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
      'action', jsonb_build_object('action_type','BOOTSTRAP_CHARTER','dry_run',false,'request_id','REQ-P5-AGENT2-BOOT')
    );

    v_artifacts := jsonb_build_object(
      'charters', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'charter_version_id', v_charter2_id,
          'semver','1.0.0',
          'created_at', v_now_iso,
          'content', jsonb_build_object('note','P5 agent2 below threshold'),
          'policy_checks', jsonb_build_object(
            'GATE-MODE', jsonb_build_object(
              'policy_check_id', 'GATE-MODE',
              'rule', jsonb_build_object(
                'op', 'OR',
                'args', jsonb_build_array(
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'SYSTEM'))
                )
              ),
              'fail_message', 'Only BOOTSTRAP/SYSTEM allowed'
            )
          )
        )
      ),
      'charter_activations', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'activation_id', v_activation2_id,
          'seq', 1,
          'charter_version_id', v_charter2_id,
          'activated_at', v_now_iso,
          'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
          'mode','NORMAL'
        )
      ),
      'state_snapshots', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'state_snapshot_id', v_state2_id,
          'seq', 1,
          'ts', v_now_iso,
          'mode','NORMAL',
          'mode_entered_at', v_now_iso,
          'charter_activation_id', v_activation2_id,
          'state', jsonb_build_object('objective','P5 below threshold test')
        )
      )
    );

    v_res := cpo.commit_action(v_agent2, v_action_content, v_artifacts, NULL, NULL);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 3 SETUP FAIL: Could not bootstrap agent2';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation2, v_expected_state2
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent2;

    -- Create exception for agent2
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
      'action', jsonb_build_object('action_type','SYSTEM_CREATE_EXCEPTION','dry_run',false,'request_id','REQ-P5-AGENT2-EXC')
    );

    v_artifacts := jsonb_build_object(
      'exceptions', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'exception_id', v_exception2_id,
          'policy_check_id', 'GATE-MODE',
          'status', 'ACTIVE',
          'created_at', v_now_iso,
          'expiry_at', v_future_iso,
          'created_by', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
          'justification', 'P5 test: agent2 exception',
          'scope', jsonb_build_object('action_types', jsonb_build_array('RESTRICTED_ACTION'))
        )
      )
    );

    v_res := cpo.commit_action(v_agent2, v_action_content, v_artifacts, v_expected_activation2, v_expected_state2);

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation2, v_expected_state2
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent2;

    -- Do only 2 bypasses (below threshold of 3)
    FOR v_i IN 1..2 LOOP
      v_action_content := jsonb_build_object(
        'actor', jsonb_build_object('id','HUMAN_001','type','HUMAN'),
        'action', jsonb_build_object('action_type','RESTRICTED_ACTION','dry_run',false,'request_id','REQ-P5-AGENT2-BYPASS-' || v_i)
      );

      v_res := cpo.commit_action(v_agent2, v_action_content, '{}'::jsonb, v_expected_activation2, v_expected_state2);

      SELECT current_charter_activation_id, current_state_snapshot_id 
        INTO v_expected_activation2, v_expected_state2
        FROM cpo.cpo_agent_heads WHERE agent_id = v_agent2;
    END LOOP;

    v_drift_count_before := (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent2);

    -- Emit drift - should NOT produce REPEATED_EXCEPTIONS
    FOR v_drift_results IN
      SELECT * FROM cpo.emit_drift_events(
        v_agent2, v_now, v_expected_activation2, v_expected_state2,
        3600, 3, 3, 86400
      )
    LOOP
      IF v_drift_results.signal_type = 'REPEATED_EXCEPTIONS' THEN
        RAISE EXCEPTION 'TEST 3 FAIL: REPEATED_EXCEPTIONS emitted with only 2 bypasses (threshold is 3)';
      END IF;
    END LOOP;

    IF (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent2 AND content->>'signal_type' = 'REPEATED_EXCEPTIONS') > 0 THEN
      RAISE EXCEPTION 'TEST 3 FAIL: REPEATED_EXCEPTIONS artifact exists for below-threshold agent';
    END IF;

    RAISE NOTICE 'OK: TEST 3 - Below threshold (2 bypasses) does NOT emit REPEATED_EXCEPTIONS';
  END;

  -- ================================================================
  -- TEST 4: Fail-closed - SYSTEM_DRIFT_EVENT blocked by gate
  -- Create agent with charter that disallows SYSTEM_DRIFT_EVENT
  -- ================================================================
  RAISE NOTICE 'TEST 4: Fail-closed - SYSTEM_DRIFT_EVENT blocked by gate...';

  DECLARE
    v_agent3 text := 'AGENT_P5_BLOCKED_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
    v_charter3_id uuid := public.gen_random_uuid();
    v_activation3_id uuid := public.gen_random_uuid();
    v_state3_id uuid := public.gen_random_uuid();
    v_exception3_id uuid := public.gen_random_uuid();
    v_expected_activation3 uuid;
    v_expected_state3 uuid;
    v_emission_blocked boolean := false;
  BEGIN
    -- Bootstrap agent3 with restrictive charter (no SYSTEM_DRIFT_EVENT)
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
      'action', jsonb_build_object('action_type','BOOTSTRAP_CHARTER','dry_run',false,'request_id','REQ-P5-AGENT3-BOOT')
    );

    v_artifacts := jsonb_build_object(
      'charters', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'charter_version_id', v_charter3_id,
          'semver','1.0.0',
          'created_at', v_now_iso,
          'content', jsonb_build_object('note','P5 agent3 - blocks SYSTEM_DRIFT_EVENT'),
          'policy_checks', jsonb_build_object(
            'GATE-MODE', jsonb_build_object(
              'policy_check_id', 'GATE-MODE',
              'rule', jsonb_build_object(
                'op', 'OR',
                'args', jsonb_build_array(
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                  jsonb_build_object('op', 'EQ', 'args', jsonb_build_array('/action/action_type', 'SYSTEM_CREATE_EXCEPTION'))
                  -- NOTE: SYSTEM_DRIFT_EVENT is NOT allowed
                )
              ),
              'fail_message', 'SYSTEM_DRIFT_EVENT not allowed'
            )
          )
        )
      ),
      'charter_activations', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'activation_id', v_activation3_id,
          'seq', 1,
          'charter_version_id', v_charter3_id,
          'activated_at', v_now_iso,
          'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
          'mode','NORMAL'
        )
      ),
      'state_snapshots', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'state_snapshot_id', v_state3_id,
          'seq', 1,
          'ts', v_now_iso,
          'mode','NORMAL',
          'mode_entered_at', v_now_iso,
          'charter_activation_id', v_activation3_id,
          'state', jsonb_build_object('objective','P5 blocked drift test')
        )
      )
    );

    v_res := cpo.commit_action(v_agent3, v_action_content, v_artifacts, NULL, NULL);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 4 SETUP FAIL: Could not bootstrap agent3';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation3, v_expected_state3
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent3;

    -- Create exception that allows RESTRICTED_ACTION
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
      'action', jsonb_build_object('action_type','SYSTEM_CREATE_EXCEPTION','dry_run',false,'request_id','REQ-P5-AGENT3-EXC')
    );

    v_artifacts := jsonb_build_object(
      'exceptions', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'exception_id', v_exception3_id,
          'policy_check_id', 'GATE-MODE',
          'status', 'ACTIVE',
          'created_at', v_now_iso,
          'expiry_at', v_future_iso,
          'created_by', jsonb_build_object('id','SYSTEM_EXCEPTION','type','SYSTEM'),
          'justification', 'P5 test: agent3 exception for RESTRICTED_ACTION',
          'scope', jsonb_build_object('action_types', jsonb_build_array('RESTRICTED_ACTION'))
        )
      )
    );

    v_res := cpo.commit_action(v_agent3, v_action_content, v_artifacts, v_expected_activation3, v_expected_state3);

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation3, v_expected_state3
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent3;

    -- Do 3 bypasses to trigger repeated exceptions
    FOR v_i IN 1..3 LOOP
      v_action_content := jsonb_build_object(
        'actor', jsonb_build_object('id','HUMAN_001','type','HUMAN'),
        'action', jsonb_build_object('action_type','RESTRICTED_ACTION','dry_run',false,'request_id','REQ-P5-AGENT3-BYPASS-' || v_i)
      );

      v_res := cpo.commit_action(v_agent3, v_action_content, '{}'::jsonb, v_expected_activation3, v_expected_state3);

      SELECT current_charter_activation_id, current_state_snapshot_id 
        INTO v_expected_activation3, v_expected_state3
        FROM cpo.cpo_agent_heads WHERE agent_id = v_agent3;
    END LOOP;

    -- Try to emit drift - should FAIL because SYSTEM_DRIFT_EVENT is blocked
    FOR v_drift_results IN
      SELECT * FROM cpo.emit_drift_events(
        v_agent3, v_now, v_expected_activation3, v_expected_state3,
        3600, 3, 3, 86400
      )
    LOOP
      IF v_drift_results.signal_type = 'REPEATED_EXCEPTIONS' THEN
        IF v_drift_results.outcome = 'FAIL' AND v_drift_results.applied = false THEN
          v_emission_blocked := true;
          RAISE NOTICE 'OK: SYSTEM_DRIFT_EVENT blocked by gate (outcome=FAIL, applied=false)';
        ELSIF v_drift_results.outcome IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
          RAISE EXCEPTION 'TEST 4 FAIL: SYSTEM_DRIFT_EVENT should be blocked by gate, got outcome=%',
            v_drift_results.outcome;
        END IF;
      END IF;
    END LOOP;

    IF NOT v_emission_blocked THEN
      RAISE EXCEPTION 'TEST 4 FAIL: No blocked emission detected for REPEATED_EXCEPTIONS signal';
    END IF;

    -- Verify no drift_event artifact was inserted
    IF (SELECT COUNT(*) FROM cpo.cpo_drift_events WHERE agent_id = v_agent3) > 0 THEN
      RAISE EXCEPTION 'TEST 4 FAIL: drift_event artifact inserted despite FAIL outcome';
    END IF;

    RAISE NOTICE 'OK: TEST 4 - Fail-closed: SYSTEM_DRIFT_EVENT blocked → no drift artifacts (INV-502)';
  END;

  -- ================================================================
  -- TEST 5: EXPIRED_ASSUMPTION_REFERENCE emits drift_event
  -- Create an expired assumption, then a decision referencing it
  -- ================================================================
  RAISE NOTICE 'TEST 5: EXPIRED_ASSUMPTION_REFERENCE emits drift_event...';

  DECLARE
    v_agent5 text := 'AGENT_P5_EXPIRED_ASM_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
    v_charter5_id uuid := public.gen_random_uuid();
    v_activation5_id uuid := public.gen_random_uuid();
    v_state5_id uuid := public.gen_random_uuid();
    v_assumption5_id uuid := public.gen_random_uuid();
    v_decision5_id uuid := public.gen_random_uuid();
    v_expected_activation5 uuid;
    v_expected_state5 uuid;
    v_drift_event_found boolean := false;
    v_past_expiry_iso text := to_char((v_now - interval '1 second') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  BEGIN
    -- Bootstrap agent5 with permissive charter
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
      'action', jsonb_build_object('action_type','BOOTSTRAP_CHARTER','dry_run',false,'request_id','REQ-P5-AGENT5-BOOT')
    );

    v_artifacts := jsonb_build_object(
      'charters', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'charter_version_id', v_charter5_id,
          'semver','1.0.0',
          'created_at', v_now_iso,
          'content', jsonb_build_object('note','P5 agent5 - expired assumption test'),
          'policy_checks', jsonb_build_object(
            'GATE-MODE', jsonb_build_object(
              'policy_check_id', 'GATE-MODE',
              'rule', jsonb_build_object(
                'op', 'OR',
                'args', jsonb_build_array(
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'SYSTEM')),
                  jsonb_build_object('op', 'IN', 'args', jsonb_build_array('/action/action_type', jsonb_build_array('CREATE_DECISION', 'CREATE_ASSUMPTION')))
                )
              ),
              'fail_message', 'Action type not allowed'
            )
          )
        )
      ),
      'charter_activations', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'activation_id', v_activation5_id,
          'seq', 1,
          'charter_version_id', v_charter5_id,
          'activated_at', v_now_iso,
          'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
          'mode','NORMAL'
        )
      ),
      'state_snapshots', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'state_snapshot_id', v_state5_id,
          'seq', 1,
          'ts', v_now_iso,
          'mode','NORMAL',
          'mode_entered_at', v_now_iso,
          'charter_activation_id', v_activation5_id,
          'state', jsonb_build_object('objective','P5 expired assumption test')
        )
      )
    );

    v_res := cpo.commit_action(v_agent5, v_action_content, v_artifacts, NULL, NULL);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 5 SETUP FAIL: Could not bootstrap agent5';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation5, v_expected_state5
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent5;

    -- Create an EXPIRED assumption (expiry_at in the past)
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_ASSUMPTION','type','SYSTEM'),
      'action', jsonb_build_object('action_type','SYSTEM_CREATE_ASSUMPTION','dry_run',false,'request_id','REQ-P5-AGENT5-ASM')
    );

    v_artifacts := jsonb_build_object(
      'assumptions', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'assumption_id', v_assumption5_id,
          'created_at', v_past_iso,
          'expiry_at', v_past_expiry_iso,  -- EXPIRED (1 second ago)
          'status', 'ACTIVE',
          'summary', 'P5 test: expired assumption',
          'created_by', jsonb_build_object('id','SYSTEM_ASSUMPTION','type','SYSTEM')
        )
      )
    );

    v_res := cpo.commit_action(v_agent5, v_action_content, v_artifacts, v_expected_activation5, v_expected_state5);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 5 SETUP FAIL: Could not create assumption';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation5, v_expected_state5
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent5;

    -- Create a decision that REFERENCES the expired assumption
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','HUMAN_001','type','HUMAN'),
      'action', jsonb_build_object('action_type','CREATE_DECISION','dry_run',false,'request_id','REQ-P5-AGENT5-DEC')
    );

    v_artifacts := jsonb_build_object(
      'decisions', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'decision_id', v_decision5_id,
          'seq', 1,
          'ts', v_now_iso,
          'decision_type','TEST_DECISION',
          'summary', 'Decision referencing expired assumption',
          'referenced_assumptions', jsonb_build_array(v_assumption5_id::text)
        )
      )
    );

    v_res := cpo.commit_action(v_agent5, v_action_content, v_artifacts, v_expected_activation5, v_expected_state5);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 5 SETUP FAIL: Could not create decision';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation5, v_expected_state5
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent5;

    -- Emit drift events
    FOR v_drift_results IN
      SELECT * FROM cpo.emit_drift_events(
        v_agent5, v_now, v_expected_activation5, v_expected_state5,
        3600, 3, 3, 86400
      )
    LOOP
      IF v_drift_results.signal_type = 'EXPIRED_ASSUMPTION_REFERENCE' THEN
        IF v_drift_results.outcome NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
          RAISE EXCEPTION 'TEST 5 FAIL: EXPIRED_ASSUMPTION_REFERENCE emission outcome %, expected PASS',
            v_drift_results.outcome;
        END IF;
        IF v_drift_results.applied <> true THEN
          RAISE EXCEPTION 'TEST 5 FAIL: EXPIRED_ASSUMPTION_REFERENCE emission applied=false';
        END IF;
        v_drift_event_found := true;
        RAISE NOTICE 'OK: EXPIRED_ASSUMPTION_REFERENCE drift_event emitted (id: %)', v_drift_results.drift_event_id;
      END IF;
    END LOOP;

    IF NOT v_drift_event_found THEN
      RAISE EXCEPTION 'TEST 5 FAIL: EXPIRED_ASSUMPTION_REFERENCE signal not emitted';
    END IF;

    -- Verify drift_event artifact content
    SELECT * INTO v_drift_event_row
      FROM cpo.cpo_drift_events
     WHERE agent_id = v_agent5
       AND content->>'signal_type' = 'EXPIRED_ASSUMPTION_REFERENCE'
     ORDER BY action_log_id DESC
     LIMIT 1;

    IF v_drift_event_row IS NULL THEN
      RAISE EXCEPTION 'TEST 5 FAIL: EXPIRED_ASSUMPTION_REFERENCE drift_event artifact not found';
    END IF;

    IF NOT (v_drift_event_row.content->'evidence'->'assumption_ids')::jsonb ? v_assumption5_id::text THEN
      RAISE EXCEPTION 'TEST 5 FAIL: evidence.assumption_ids should contain %', v_assumption5_id;
    END IF;

    RAISE NOTICE 'OK: TEST 5 - EXPIRED_ASSUMPTION_REFERENCE triggers drift_event with correct evidence';
  END;

  -- ================================================================
  -- TEST 6: MODE_THRASH emits drift_event
  -- Create multiple state snapshots with alternating modes
  -- ================================================================
  RAISE NOTICE 'TEST 6: MODE_THRASH emits drift_event...';

  DECLARE
    v_agent6 text := 'AGENT_P5_MODE_THRASH_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
    v_charter6_id uuid := public.gen_random_uuid();
    v_activation6_id uuid := public.gen_random_uuid();
    v_state6_ids uuid[] := ARRAY[public.gen_random_uuid(), public.gen_random_uuid(), public.gen_random_uuid(), public.gen_random_uuid()];
    v_expected_activation6 uuid;
    v_expected_state6 uuid;
    v_drift_event_found boolean := false;
    v_modes text[] := ARRAY['NORMAL', 'REFLECT', 'NORMAL', 'REFLECT'];
  BEGIN
    -- Bootstrap agent6 with all 4 state snapshots showing mode transitions
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
      'action', jsonb_build_object('action_type','BOOTSTRAP_CHARTER','dry_run',false,'request_id','REQ-P5-AGENT6-BOOT')
    );

    v_artifacts := jsonb_build_object(
      'charters', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'charter_version_id', v_charter6_id,
          'semver','1.0.0',
          'created_at', v_now_iso,
          'content', jsonb_build_object('note','P5 agent6 - mode thrash test'),
          'policy_checks', jsonb_build_object(
            'GATE-MODE', jsonb_build_object(
              'policy_check_id', 'GATE-MODE',
              'rule', jsonb_build_object(
                'op', 'OR',
                'args', jsonb_build_array(
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'SYSTEM')),
                  jsonb_build_object('op', 'EQ', 'args', jsonb_build_array('/action/action_type', 'MODE_CHANGE'))
                )
              ),
              'fail_message', 'Action type not allowed'
            )
          )
        )
      ),
      'charter_activations', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'activation_id', v_activation6_id,
          'seq', 1,
          'charter_version_id', v_charter6_id,
          'activated_at', v_now_iso,
          'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
          'mode','NORMAL'
        )
      ),
      'state_snapshots', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'state_snapshot_id', v_state6_ids[1],
          'seq', 1,
          'ts', v_now_iso,
          'mode', v_modes[1],
          'mode_entered_at', v_now_iso,
          'charter_activation_id', v_activation6_id,
          'state', jsonb_build_object('objective','P5 mode thrash test')
        )
      )
    );

    v_res := cpo.commit_action(v_agent6, v_action_content, v_artifacts, NULL, NULL);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 6 SETUP FAIL: Could not bootstrap agent6';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation6, v_expected_state6
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent6;

    -- Commit 3 more state snapshots with alternating modes (REFLECT, NORMAL, REFLECT)
    FOR v_i IN 2..4 LOOP
      v_action_content := jsonb_build_object(
        'actor', jsonb_build_object('id','SYSTEM_MODE','type','SYSTEM'),
        'action', jsonb_build_object('action_type','SYSTEM_MODE_CHANGE','dry_run',false,'request_id','REQ-P5-AGENT6-MODE-' || v_i)
      );

      v_artifacts := jsonb_build_object(
        'state_snapshots', jsonb_build_array(
          jsonb_build_object(
            'protocol_version','cpo-contracts@0.1.0',
            'state_snapshot_id', v_state6_ids[v_i],
            'seq', v_i,
            'ts', v_now_iso,
            'mode', v_modes[v_i],
            'mode_entered_at', v_now_iso,
            'charter_activation_id', v_activation6_id,
            'state', jsonb_build_object('objective','P5 mode thrash test', 'transition', v_i)
          )
        )
      );

      v_res := cpo.commit_action(v_agent6, v_action_content, v_artifacts, v_expected_activation6, v_expected_state6);
      IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
        RAISE EXCEPTION 'TEST 6 SETUP FAIL: Could not commit mode change %', v_i;
      END IF;

      SELECT current_charter_activation_id, current_state_snapshot_id 
        INTO v_expected_activation6, v_expected_state6
        FROM cpo.cpo_agent_heads WHERE agent_id = v_agent6;
    END LOOP;

    RAISE NOTICE 'OK: 4 state snapshots with 3 mode transitions committed';

    -- Emit drift events
    FOR v_drift_results IN
      SELECT * FROM cpo.emit_drift_events(
        v_agent6, v_now, v_expected_activation6, v_expected_state6,
        3600, 3, 3, 86400  -- mode_thrash_threshold = 3
      )
    LOOP
      IF v_drift_results.signal_type = 'MODE_THRASH' THEN
        IF v_drift_results.outcome NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
          RAISE EXCEPTION 'TEST 6 FAIL: MODE_THRASH emission outcome %, expected PASS',
            v_drift_results.outcome;
        END IF;
        IF v_drift_results.applied <> true THEN
          RAISE EXCEPTION 'TEST 6 FAIL: MODE_THRASH emission applied=false';
        END IF;
        v_drift_event_found := true;
        RAISE NOTICE 'OK: MODE_THRASH drift_event emitted (id: %)', v_drift_results.drift_event_id;
      END IF;
    END LOOP;

    IF NOT v_drift_event_found THEN
      RAISE EXCEPTION 'TEST 6 FAIL: MODE_THRASH signal not emitted despite 3 transitions';
    END IF;

    -- Verify drift_event artifact content
    SELECT * INTO v_drift_event_row
      FROM cpo.cpo_drift_events
     WHERE agent_id = v_agent6
       AND content->>'signal_type' = 'MODE_THRASH'
     ORDER BY action_log_id DESC
     LIMIT 1;

    IF v_drift_event_row IS NULL THEN
      RAISE EXCEPTION 'TEST 6 FAIL: MODE_THRASH drift_event artifact not found';
    END IF;

    IF (v_drift_event_row.content->'predicate'->>'observed')::int < 3 THEN
      RAISE EXCEPTION 'TEST 6 FAIL: predicate.observed should be >= 3, got %',
        v_drift_event_row.content->'predicate'->>'observed';
    END IF;

    RAISE NOTICE 'OK: TEST 6 - MODE_THRASH triggers drift_event with observed >= 3';
  END;

  -- ================================================================
  -- TEST 7: STATE_STALENESS emits drift_event
  -- Create a state snapshot with ts older than max_age
  -- ================================================================
  RAISE NOTICE 'TEST 7: STATE_STALENESS emits drift_event...';

  DECLARE
    v_agent7 text := 'AGENT_P5_STALENESS_' || to_char(clock_timestamp(),'YYYYMMDDHH24MISS') || '_' || floor(random()*1000000)::bigint::text;
    v_charter7_id uuid := public.gen_random_uuid();
    v_activation7_id uuid := public.gen_random_uuid();
    v_state7_id uuid := public.gen_random_uuid();
    v_expected_activation7 uuid;
    v_expected_state7 uuid;
    v_drift_event_found boolean := false;
    v_stale_ts_iso text := to_char((v_now - interval '2 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
    v_staleness_max_age int := 86400;  -- 1 day in seconds
  BEGIN
    -- Bootstrap agent7 with a STALE state snapshot (ts = now - 2 days)
    v_action_content := jsonb_build_object(
      'actor', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
      'action', jsonb_build_object('action_type','BOOTSTRAP_CHARTER','dry_run',false,'request_id','REQ-P5-AGENT7-BOOT')
    );

    v_artifacts := jsonb_build_object(
      'charters', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'charter_version_id', v_charter7_id,
          'semver','1.0.0',
          'created_at', v_stale_ts_iso,
          'content', jsonb_build_object('note','P5 agent7 - staleness test'),
          'policy_checks', jsonb_build_object(
            'GATE-MODE', jsonb_build_object(
              'policy_check_id', 'GATE-MODE',
              'rule', jsonb_build_object(
                'op', 'OR',
                'args', jsonb_build_array(
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'BOOTSTRAP')),
                  jsonb_build_object('op', 'STARTS_WITH', 'args', jsonb_build_array('/action/action_type', 'SYSTEM'))
                )
              ),
              'fail_message', 'Action type not allowed'
            )
          )
        )
      ),
      'charter_activations', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'activation_id', v_activation7_id,
          'seq', 1,
          'charter_version_id', v_charter7_id,
          'activated_at', v_stale_ts_iso,
          'activated_by', jsonb_build_object('id','SYSTEM_BOOTSTRAP','type','SYSTEM'),
          'mode','NORMAL'
        )
      ),
      'state_snapshots', jsonb_build_array(
        jsonb_build_object(
          'protocol_version','cpo-contracts@0.1.0',
          'state_snapshot_id', v_state7_id,
          'seq', 1,
          'ts', v_stale_ts_iso,  -- 2 days ago (STALE)
          'mode','NORMAL',
          'mode_entered_at', v_stale_ts_iso,
          'charter_activation_id', v_activation7_id,
          'state', jsonb_build_object('objective','P5 staleness test')
        )
      )
    );

    v_res := cpo.commit_action(v_agent7, v_action_content, v_artifacts, NULL, NULL);
    IF v_res->>'outcome' NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
      RAISE EXCEPTION 'TEST 7 SETUP FAIL: Could not bootstrap agent7';
    END IF;

    SELECT current_charter_activation_id, current_state_snapshot_id 
      INTO v_expected_activation7, v_expected_state7
      FROM cpo.cpo_agent_heads WHERE agent_id = v_agent7;

    RAISE NOTICE 'OK: Agent7 bootstrapped with stale state snapshot (ts = now - 2 days)';

    -- Emit drift events with staleness check (max_age = 1 day)
    FOR v_drift_results IN
      SELECT * FROM cpo.emit_drift_events(
        v_agent7, v_now, v_expected_activation7, v_expected_state7,
        3600, 3, 3, v_staleness_max_age
      )
    LOOP
      IF v_drift_results.signal_type = 'STATE_STALENESS' THEN
        IF v_drift_results.outcome NOT IN ('PASS', 'PASS_WITH_EXCEPTION') THEN
          RAISE EXCEPTION 'TEST 7 FAIL: STATE_STALENESS emission outcome %, expected PASS',
            v_drift_results.outcome;
        END IF;
        IF v_drift_results.applied <> true THEN
          RAISE EXCEPTION 'TEST 7 FAIL: STATE_STALENESS emission applied=false';
        END IF;
        v_drift_event_found := true;
        RAISE NOTICE 'OK: STATE_STALENESS drift_event emitted (id: %)', v_drift_results.drift_event_id;
      END IF;
    END LOOP;

    IF NOT v_drift_event_found THEN
      RAISE EXCEPTION 'TEST 7 FAIL: STATE_STALENESS signal not emitted despite stale snapshot';
    END IF;

    -- Verify drift_event artifact content
    SELECT * INTO v_drift_event_row
      FROM cpo.cpo_drift_events
     WHERE agent_id = v_agent7
       AND content->>'signal_type' = 'STATE_STALENESS'
     ORDER BY action_log_id DESC
     LIMIT 1;

    IF v_drift_event_row IS NULL THEN
      RAISE EXCEPTION 'TEST 7 FAIL: STATE_STALENESS drift_event artifact not found';
    END IF;

    -- observed should be > max_age (172800 seconds = 2 days > 86400 = 1 day)
    IF (v_drift_event_row.content->'predicate'->>'observed')::int <= v_staleness_max_age THEN
      RAISE EXCEPTION 'TEST 7 FAIL: predicate.observed should be > %, got %',
        v_staleness_max_age, v_drift_event_row.content->'predicate'->>'observed';
    END IF;

    RAISE NOTICE 'OK: TEST 7 - STATE_STALENESS triggers drift_event with observed > max_age';
  END;

  -- ================================================================
  -- Summary
  -- ================================================================
  RAISE NOTICE '==========================================';
  RAISE NOTICE 'OK: P5 Drift Detection self-test v2 PASSED';
  RAISE NOTICE '  - TEST 1: REPEATED_EXCEPTIONS triggers drift_event';
  RAISE NOTICE '  - TEST 2: INV-504 dedupe prevents duplicate emission';
  RAISE NOTICE '  - TEST 3: Below threshold does NOT emit';
  RAISE NOTICE '  - TEST 4: INV-502 SYSTEM actor blocked by gates';
  RAISE NOTICE '  - TEST 5: EXPIRED_ASSUMPTION_REFERENCE triggers drift_event';
  RAISE NOTICE '  - TEST 6: MODE_THRASH triggers drift_event';
  RAISE NOTICE '  - TEST 7: STATE_STALENESS triggers drift_event';
  RAISE NOTICE '  - ALL P5 SIGNALS PROVEN';
  RAISE NOTICE '==========================================';
END $$;

ROLLBACK;
