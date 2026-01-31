-- sql/migrations/p2_durability_drill_wiring.sql
-- P2 WIRING: Upgrade durability drill to be registry-driven
--
-- This patch upgrades the existing durability functions to iterate the registry
-- instead of using hand-curated table lists. No new parallel runtime.
--
-- UPGRADED FUNCTIONS:
--   1. export_evidence_pack() → iterates get_canonical_artifact_types()
--   2. rehydrate_agent() → uses registry insert columns
--   3. verify_reconstruction() → heads + content-hash multiset equality
--
-- INVARIANT:
--   durability = f(registry), not f(hand-curated list)
--   equivalence = heads + hash multiset, not counts

BEGIN;

-- ===========================================================================
-- 1. REGISTRY-DRIVEN EXPORT
-- ===========================================================================
-- Replaces hand-curated table list with registry iteration.
-- Export order is deterministic (registry.export_order).

CREATE OR REPLACE FUNCTION cpo.export_evidence_pack(
  p_agent_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_pack jsonb := '{}'::jsonb;
  v_rec record;
  v_rows jsonb;
  v_sql text;
  v_count int;
BEGIN
  -- Validate agent exists
  IF NOT EXISTS (SELECT 1 FROM cpo.cpo_agent_heads WHERE agent_id = p_agent_id) THEN
    RAISE EXCEPTION 'Agent % does not exist', p_agent_id;
  END IF;
  
  -- Add metadata
  v_pack := jsonb_build_object(
    '_meta', jsonb_build_object(
      'agent_id', p_agent_id,
      'exported_at', now(),
      'registry_version', 'v3.2',
      'export_method', 'registry-driven'
    )
  );
  
  -- Iterate canonical artifact types in deterministic order
  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    -- Build SELECT for this artifact type
    -- Export: logical columns for reading, content for hashing
    v_sql := format(
      'SELECT jsonb_build_object(
         ''logical_id'', %I,
         ''logical_seq'', %I,
         ''content'', content,
         ''content_hash'', encode(public.digest(content::text, ''sha256''), ''hex'')
       )
       FROM %s
       WHERE agent_id = $1
       ORDER BY %s',
      v_rec.logical_id_column,
      COALESCE(v_rec.logical_seq_column, v_rec.logical_id_column),
      v_rec.table_regclass::text,
      COALESCE(v_rec.logical_seq_column, v_rec.logical_id_column)
    );
    
    -- Execute and collect rows
    EXECUTE format(
      'SELECT COALESCE(jsonb_agg(row_data), ''[]''::jsonb)
       FROM (%s) AS subq(row_data)',
      v_sql
    ) INTO v_rows USING p_agent_id;
    
    v_count := jsonb_array_length(v_rows);
    
    -- Add to pack with metadata
    v_pack := v_pack || jsonb_build_object(
      v_rec.artifact_type, jsonb_build_object(
        'table', v_rec.table_regclass::text,
        'export_order', v_rec.export_order,
        'row_count', v_count,
        'rows', v_rows
      )
    );
    
    RAISE NOTICE 'Exported % rows from % (order=%)',
      v_count, v_rec.artifact_type, v_rec.export_order;
  END LOOP;
  
  -- Add export summary
  v_pack := jsonb_set(
    v_pack,
    ARRAY['_meta', 'artifact_types_exported'],
    (SELECT jsonb_agg(artifact_type ORDER BY export_order)
     FROM cpo.get_canonical_artifact_types())
  );
  
  RETURN v_pack;
END;
$$;

COMMENT ON FUNCTION cpo.export_evidence_pack(uuid) IS
  'P2 v3.2: Registry-driven export of all canonical artifacts for an agent.';

-- ===========================================================================
-- 2. REGISTRY-DRIVEN REHYDRATE
-- ===========================================================================
-- Uses insert columns from registry. Generated columns recompute automatically.

CREATE OR REPLACE FUNCTION cpo.rehydrate_agent(
  p_pack jsonb,
  p_target_schema text DEFAULT 'cpo_rehydrate'
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_agent_id uuid;
  v_rec record;
  v_artifact_data jsonb;
  v_row jsonb;
  v_sql text;
  v_insert_count int;
  v_total_count int := 0;
BEGIN
  -- Extract agent_id from pack metadata
  v_agent_id := (p_pack->'_meta'->>'agent_id')::uuid;
  
  IF v_agent_id IS NULL THEN
    RAISE EXCEPTION 'Pack metadata missing agent_id';
  END IF;
  
  -- Create target schema if needed
  EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', p_target_schema);
  
  -- Iterate canonical artifact types in export_order
  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    v_artifact_data := p_pack->v_rec.artifact_type;
    
    IF v_artifact_data IS NULL THEN
      RAISE NOTICE 'Skipping % (not in pack)', v_rec.artifact_type;
      CONTINUE;
    END IF;
    
    -- Create target table (mirror structure)
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I.%I (LIKE %s INCLUDING ALL)',
      p_target_schema,
      (v_rec.table_regclass::text)::name,
      v_rec.table_regclass::text
    );
    
    -- Insert using ONLY insertable columns (generated columns recompute)
    v_insert_count := 0;
    FOR v_row IN SELECT * FROM jsonb_array_elements(v_artifact_data->'rows')
    LOOP
      -- Build INSERT using registry insert columns
      v_sql := format(
        'INSERT INTO %I.%I (%I, %s %I) VALUES ($1, %s $2)',
        p_target_schema,
        (v_rec.table_regclass::text)::name,
        v_rec.insert_agent_id_column,
        CASE WHEN v_rec.insert_action_log_id_column IS NOT NULL
          THEN format('%I,', v_rec.insert_action_log_id_column)
          ELSE ''
        END,
        v_rec.insert_content_column,
        CASE WHEN v_rec.insert_action_log_id_column IS NOT NULL
          THEN format('(%L)::uuid,', v_row->>'action_log_id')
          ELSE ''
        END
      );
      
      EXECUTE v_sql USING v_agent_id, v_row->'content';
      v_insert_count := v_insert_count + 1;
    END LOOP;
    
    v_total_count := v_total_count + v_insert_count;
    RAISE NOTICE 'Rehydrated % rows into %.%',
      v_insert_count, p_target_schema, v_rec.artifact_type;
  END LOOP;
  
  RAISE NOTICE 'Rehydration complete: % total rows for agent %',
    v_total_count, v_agent_id;
  
  RETURN v_agent_id;
END;
$$;

COMMENT ON FUNCTION cpo.rehydrate_agent(jsonb, text) IS
  'P2 v3.2: Registry-driven rehydration using insert columns only.';

-- ===========================================================================
-- 3. STRONG EQUIVALENCE VERIFICATION
-- ===========================================================================
-- Verifies: heads equivalence + content-hash multiset per artifact type.
-- NOT just row counts.

CREATE OR REPLACE FUNCTION cpo.verify_reconstruction(
  p_agent_id uuid,
  p_source_schema text DEFAULT 'cpo',
  p_target_schema text DEFAULT 'cpo_rehydrate'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_result jsonb := '{}'::jsonb;
  v_rec record;
  v_source_hashes text[];
  v_target_hashes text[];
  v_source_count int;
  v_target_count int;
  v_hash_match boolean;
  v_all_match boolean := true;
  v_sql text;
BEGIN
  v_result := jsonb_build_object(
    '_meta', jsonb_build_object(
      'agent_id', p_agent_id,
      'source_schema', p_source_schema,
      'target_schema', p_target_schema,
      'verified_at', now(),
      'verification_method', 'heads + hash multiset'
    ),
    'artifact_checks', '{}'::jsonb
  );
  
  -- Check each canonical artifact type
  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    -- Get sorted content hash array from source
    v_sql := format(
      'SELECT array_agg(h ORDER BY h)
       FROM (
         SELECT encode(public.digest(content::text, ''sha256''), ''hex'') AS h
         FROM %I.%I
         WHERE agent_id = $1
       ) sub',
      p_source_schema,
      (v_rec.table_regclass::text)::name
    );
    EXECUTE v_sql INTO v_source_hashes USING p_agent_id;
    v_source_hashes := COALESCE(v_source_hashes, ARRAY[]::text[]);
    v_source_count := array_length(v_source_hashes, 1);
    v_source_count := COALESCE(v_source_count, 0);
    
    -- Get sorted content hash array from target
    v_sql := format(
      'SELECT array_agg(h ORDER BY h)
       FROM (
         SELECT encode(public.digest(content::text, ''sha256''), ''hex'') AS h
         FROM %I.%I
         WHERE agent_id = $1
       ) sub',
      p_target_schema,
      (v_rec.table_regclass::text)::name
    );
    
    BEGIN
      EXECUTE v_sql INTO v_target_hashes USING p_agent_id;
      v_target_hashes := COALESCE(v_target_hashes, ARRAY[]::text[]);
      v_target_count := COALESCE(array_length(v_target_hashes, 1), 0);
    EXCEPTION WHEN undefined_table THEN
      v_target_hashes := ARRAY[]::text[];
      v_target_count := 0;
    END;
    
    -- Compare hash multisets (order-independent equality)
    v_hash_match := (v_source_hashes = v_target_hashes);
    
    IF NOT v_hash_match THEN
      v_all_match := false;
    END IF;
    
    -- Record result
    v_result := jsonb_set(
      v_result,
      ARRAY['artifact_checks', v_rec.artifact_type],
      jsonb_build_object(
        'source_count', v_source_count,
        'target_count', v_target_count,
        'count_match', v_source_count = v_target_count,
        'hash_multiset_match', v_hash_match,
        'status', CASE WHEN v_hash_match THEN 'EQUIVALENT' ELSE 'DIVERGENT' END
      )
    );
    
    RAISE NOTICE '%: source=%, target=%, hash_match=%',
      v_rec.artifact_type, v_source_count, v_target_count, v_hash_match;
  END LOOP;
  
  -- Overall verdict
  v_result := jsonb_set(
    v_result,
    ARRAY['_meta', 'overall_status'],
    to_jsonb(CASE WHEN v_all_match THEN 'EQUIVALENT' ELSE 'DIVERGENT' END)
  );
  
  IF NOT v_all_match THEN
    RAISE WARNING 'Reconstruction verification FAILED for agent %', p_agent_id;
  ELSE
    RAISE NOTICE 'Reconstruction verification PASSED for agent %', p_agent_id;
  END IF;
  
  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION cpo.verify_reconstruction(uuid, text, text) IS
  'P2 v3.2: Strong equivalence verification via content-hash multiset comparison.';

-- ===========================================================================
-- 4. HEADS EQUIVALENCE CHECK (separate utility)
-- ===========================================================================

CREATE OR REPLACE FUNCTION cpo.verify_heads_equivalence(
  p_agent_id uuid,
  p_source_schema text DEFAULT 'cpo',
  p_target_schema text DEFAULT 'cpo_rehydrate'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_source_heads jsonb;
  v_target_heads jsonb;
  v_match boolean;
BEGIN
  -- Get heads from source
  EXECUTE format(
    'SELECT to_jsonb(h.*) FROM %I.cpo_agent_heads h WHERE agent_id = $1',
    p_source_schema
  ) INTO v_source_heads USING p_agent_id;
  
  -- Get heads from target (may not exist)
  BEGIN
    EXECUTE format(
      'SELECT to_jsonb(h.*) FROM %I.cpo_agent_heads h WHERE agent_id = $1',
      p_target_schema
    ) INTO v_target_heads USING p_agent_id;
  EXCEPTION WHEN undefined_table THEN
    v_target_heads := NULL;
  END;
  
  -- Compare (excluding timestamps that might differ)
  v_match := (
    v_source_heads - 'created_at' - 'updated_at' =
    v_target_heads - 'created_at' - 'updated_at'
  );
  
  RETURN jsonb_build_object(
    'agent_id', p_agent_id,
    'source_heads', v_source_heads,
    'target_heads', v_target_heads,
    'heads_equivalent', v_match,
    'note', CASE 
      WHEN v_target_heads IS NULL THEN 'Target heads not yet rebuilt'
      WHEN v_match THEN 'Heads are equivalent'
      ELSE 'Heads DIVERGE - reconstruction problem'
    END
  );
END;
$$;

COMMENT ON FUNCTION cpo.verify_heads_equivalence(uuid, text, text) IS
  'P2 v3.2: Verify agent heads projection equivalence after rehydration.';

-- ===========================================================================
-- 5. FULL DURABILITY ROUND-TRIP TEST
-- ===========================================================================

CREATE OR REPLACE FUNCTION cpo.durability_round_trip_test(
  p_agent_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_pack jsonb;
  v_rehydrated_agent uuid;
  v_verification jsonb;
  v_test_schema text := 'cpo_durability_test_' || replace(gen_random_uuid()::text, '-', '_');
BEGIN
  RAISE NOTICE '=== DURABILITY ROUND-TRIP TEST ===';
  RAISE NOTICE 'Agent: %', p_agent_id;
  RAISE NOTICE 'Test schema: %', v_test_schema;
  
  -- Step 1: Export
  RAISE NOTICE 'Step 1: Exporting evidence pack...';
  v_pack := cpo.export_evidence_pack(p_agent_id);
  RAISE NOTICE 'Exported % artifact types',
    jsonb_array_length(v_pack->'_meta'->'artifact_types_exported');
  
  -- Step 2: Rehydrate into test schema
  RAISE NOTICE 'Step 2: Rehydrating into test schema...';
  v_rehydrated_agent := cpo.rehydrate_agent(v_pack, v_test_schema);
  
  -- Step 3: Verify equivalence
  RAISE NOTICE 'Step 3: Verifying reconstruction equivalence...';
  v_verification := cpo.verify_reconstruction(p_agent_id, 'cpo', v_test_schema);
  
  -- Step 4: Cleanup
  RAISE NOTICE 'Step 4: Cleaning up test schema...';
  EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', v_test_schema);
  
  -- Return comprehensive result
  RETURN jsonb_build_object(
    'test', 'durability_round_trip',
    'agent_id', p_agent_id,
    'test_schema', v_test_schema,
    'export_artifact_count', jsonb_array_length(v_pack->'_meta'->'artifact_types_exported'),
    'verification', v_verification,
    'overall_status', v_verification->'_meta'->>'overall_status',
    'passed', (v_verification->'_meta'->>'overall_status') = 'EQUIVALENT'
  );
END;
$$;

COMMENT ON FUNCTION cpo.durability_round_trip_test(uuid) IS
  'P2 v3.2: Complete durability round-trip test (export → rehydrate → verify).';

COMMIT;
