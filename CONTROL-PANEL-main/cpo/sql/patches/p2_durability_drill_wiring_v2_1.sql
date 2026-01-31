-- p2_durability_drill_wiring_v2_1.sql
-- Surgical corrections to p2_durability_drill_wiring_v2.sql:
--   1) Treat agent_id as TEXT (no UUID coercion).
--   2) Export includes action_log_id for tables that require it.
--   3) Rehydrate derives action_log_id from the pack row wrapper, not content JSON.
--   4) Heads rebuild targets the actual cpo.cpo_agent_heads schema (v2.2).
--   5) Equivalence hashes include action_log_id + content for tables with action_log_id.
--
-- This file *upgrades existing durability signatures in place*:
--   cpo.export_evidence_pack(text) RETURNS jsonb
--   cpo.rehydrate_agent(jsonb) RETURNS jsonb
--   cpo.verify_reconstruction(text, jsonb) RETURNS jsonb

BEGIN;

-- ----------------------------------------------------------------------------
-- Helper: Build a registry-driven export section for a single canonical table.
-- Rows are exported as objects with:
--   logical_id, logical_seq, action_log_id (nullable), content, row_hash
--
-- row_hash definition:
--   - If the table has an action_log_id insert column: SHA256(action_log_id || '|' || content)
--   - Otherwise (e.g., action logs): SHA256(content)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.durability_build_pack_for_table(
  p_agent_id text,
  p_table_regclass regclass
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_rec record;
  v_sql text;
  v_rows jsonb;
  v_seq_expr text;
  v_order_expr text;
  v_action_log_expr text;
  v_hash_expr text;
BEGIN
  SELECT
    artifact_type,
    table_regclass,
    table_kind,
    logical_id_column,
    logical_seq_column,
    insert_agent_id_column,
    insert_action_log_id_column,
    insert_content_column,
    is_canonical,
    is_exported,
    export_order,
    description
  INTO v_rec
  FROM cpo.cpo_artifact_table_registry
  WHERE table_regclass = p_table_regclass
    AND table_kind = 'canonical'
    AND is_exported = true;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'No exported canonical registry row for table %', p_table_regclass;
  END IF;

  -- Sequence expression (stable ordering): use logical_seq if present else logical_id.
  v_seq_expr := CASE
    WHEN v_rec.logical_seq_column IS NOT NULL THEN format('%I', v_rec.logical_seq_column)
    ELSE format('%I', v_rec.logical_id_column)
  END;

  v_order_expr := v_seq_expr;

  -- action_log_id field in the exported row wrapper
  v_action_log_expr := CASE
    WHEN v_rec.insert_action_log_id_column IS NOT NULL THEN format('%I', v_rec.insert_action_log_id_column)
    ELSE 'NULL'
  END;

  -- Row hash (action_log_id + content) when action_log_id exists; else content only.
  v_hash_expr := CASE
    WHEN v_rec.insert_action_log_id_column IS NOT NULL THEN
      format('(%I)::text || ''|'' || (%I)::text', v_rec.insert_action_log_id_column, v_rec.insert_content_column)
    ELSE
      format('(%I)::text', v_rec.insert_content_column)
  END;

  v_sql := format(
    'SELECT COALESCE(jsonb_agg(
        jsonb_build_object(
          ''logical_id'', %1$I,
          ''logical_seq'', %2$s,
          ''action_log_id'', %3$s,
          ''content'', %4$I,
          ''row_hash'', encode(public.digest(%5$s, ''sha256''), ''hex'')
        )
        ORDER BY %6$s, %1$I
      ), ''[]''::jsonb)
     FROM %7$s
     WHERE %8$I = $1',
    v_rec.logical_id_column,
    v_seq_expr,
    v_action_log_expr,
    v_rec.insert_content_column,
    v_hash_expr,
    v_order_expr,
    v_rec.table_regclass,
    v_rec.insert_agent_id_column
  );

  EXECUTE v_sql INTO v_rows USING p_agent_id;

  RETURN jsonb_build_object(
    'table', v_rec.table_regclass::text,
    'export_order', v_rec.export_order,
    'row_count', jsonb_array_length(v_rows),
    'rows', v_rows
  );
END;
$$;

REVOKE ALL ON FUNCTION cpo.durability_build_pack_for_table(text, regclass) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Upgrade: export_evidence_pack(text)
-- Registry-driven export. Pack format is self-describing and carries source heads.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.export_evidence_pack(
  p_agent_id text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_rec record;
  v_pack jsonb := '{}'::jsonb;
  v_pack_meta jsonb;
  v_source_heads jsonb;
BEGIN
  -- Require existing agent heads (projection). This anchors durability to real state.
  SELECT to_jsonb(h.*)
    INTO v_source_heads
    FROM cpo.cpo_agent_heads h
   WHERE h.agent_id = p_agent_id;

  IF v_source_heads IS NULL THEN
    RAISE EXCEPTION 'Agent % not found (no heads row)', p_agent_id;
  END IF;

  v_pack_meta := jsonb_build_object(
    'agent_id', p_agent_id,
    'exported_at', to_char(clock_timestamp(), 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'source_heads', v_source_heads,
    'artifact_types_exported', (
      SELECT jsonb_agg(artifact_type ORDER BY export_order)
      FROM cpo.get_canonical_artifact_types()
    )
  );

  v_pack := v_pack || jsonb_build_object('_meta', v_pack_meta);

  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    v_pack := v_pack || jsonb_build_object(
      v_rec.artifact_type,
      cpo.durability_build_pack_for_table(p_agent_id, v_rec.table_regclass)
    );
  END LOOP;

  RETURN v_pack;
END;
$$;

REVOKE ALL ON FUNCTION cpo.export_evidence_pack(text) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Helper: Insert exported rows for a single registry table.
-- Derives action_log_id from the *row wrapper* (v_row->>'action_log_id'), not content.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.durability_insert_rows_for_table(
  p_agent_id text,
  p_table_regclass regclass,
  p_rows jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_rec record;
  v_row jsonb;
  v_content jsonb;
  v_action_log_id uuid;
  v_sql text;
BEGIN
  SELECT
    table_regclass,
    logical_id_column,
    logical_seq_column,
    insert_agent_id_column,
    insert_action_log_id_column,
    insert_content_column
  INTO v_rec
  FROM cpo.cpo_artifact_table_registry
  WHERE table_regclass = p_table_regclass
    AND table_kind = 'canonical'
    AND is_exported = true;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'No exported canonical registry row for table %', p_table_regclass;
  END IF;

  IF p_rows IS NULL OR jsonb_typeof(p_rows) <> 'array' THEN
    RAISE EXCEPTION 'Rows payload must be an array for table %', p_table_regclass;
  END IF;

  FOR v_row IN SELECT * FROM jsonb_array_elements(p_rows)
  LOOP
    v_content := v_row->'content';
    IF v_content IS NULL THEN
      RAISE EXCEPTION 'Export row missing content for table %', p_table_regclass;
    END IF;

    v_action_log_id := NULL;
    IF v_rec.insert_action_log_id_column IS NOT NULL THEN
      -- action_log_id is exported in the row wrapper.
      IF v_row->>'action_log_id' IS NULL THEN
        RAISE EXCEPTION 'Export row missing action_log_id for table %', p_table_regclass;
      END IF;
      v_action_log_id := (v_row->>'action_log_id')::uuid;

      v_sql := format(
        'INSERT INTO %s(%I, %I, %I) VALUES ($1, $2, $3)',
        v_rec.table_regclass,
        v_rec.insert_agent_id_column,
        v_rec.insert_action_log_id_column,
        v_rec.insert_content_column
      );

      EXECUTE v_sql USING p_agent_id, v_action_log_id, v_content;
    ELSE
      v_sql := format(
        'INSERT INTO %s(%I, %I) VALUES ($1, $2)',
        v_rec.table_regclass,
        v_rec.insert_agent_id_column,
        v_rec.insert_content_column
      );

      EXECUTE v_sql USING p_agent_id, v_content;
    END IF;
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION cpo.durability_insert_rows_for_table(text, regclass, jsonb) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Helper: Rebuild heads projection from canonical maxima (same physics as commit_action).
-- Targets the actual cpo.cpo_agent_heads schema (v2.2).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.rebuild_agent_heads(
  p_agent_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_last_action_log_seq bigint;
  v_cur_charter_activation_id uuid;
  v_cur_charter_activation_seq bigint;
  v_cur_charter_version_id uuid;
  v_cur_state_snapshot_id uuid;
  v_cur_state_seq bigint;
BEGIN
  -- Charter activation head
  SELECT activation_id, seq, charter_version_id
    INTO v_cur_charter_activation_id, v_cur_charter_activation_seq, v_cur_charter_version_id
    FROM cpo.cpo_charter_activations
   WHERE agent_id = p_agent_id
   ORDER BY seq DESC
   LIMIT 1;

  -- State head
  SELECT state_snapshot_id, seq
    INTO v_cur_state_snapshot_id, v_cur_state_seq
    FROM cpo.cpo_state_snapshots
   WHERE agent_id = p_agent_id
   ORDER BY seq DESC
   LIMIT 1;

  -- Last action log seq
  SELECT COALESCE(MAX(seq), 0)
    INTO v_last_action_log_seq
    FROM cpo.cpo_action_logs
   WHERE agent_id = p_agent_id;

  INSERT INTO cpo.cpo_agent_heads(
    agent_id,
    updated_at,
    last_action_log_seq,
    current_charter_activation_id,
    current_charter_activation_seq,
    current_charter_version_id,
    current_state_snapshot_id,
    current_state_seq
  )
  VALUES (
    p_agent_id,
    clock_timestamp(),
    v_last_action_log_seq,
    v_cur_charter_activation_id,
    v_cur_charter_activation_seq,
    v_cur_charter_version_id,
    v_cur_state_snapshot_id,
    v_cur_state_seq
  )
  ON CONFLICT (agent_id) DO UPDATE SET
    updated_at = clock_timestamp(),
    last_action_log_seq = EXCLUDED.last_action_log_seq,
    current_charter_activation_id = EXCLUDED.current_charter_activation_id,
    current_charter_activation_seq = EXCLUDED.current_charter_activation_seq,
    current_charter_version_id = EXCLUDED.current_charter_version_id,
    current_state_snapshot_id = EXCLUDED.current_state_snapshot_id,
    current_state_seq = EXCLUDED.current_state_seq;
END;
$$;

REVOKE ALL ON FUNCTION cpo.rebuild_agent_heads(text) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Upgrade: rehydrate_agent(jsonb)
-- Imports from a pack produced by export_evidence_pack(text).
-- Rebuilds heads projection from canonical maxima.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.rehydrate_agent(
  p_pack jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_agent_id text;
  v_rec record;
  v_rows jsonb;
  v_heads jsonb;
BEGIN
  v_agent_id := p_pack->'_meta'->>'agent_id';
  IF v_agent_id IS NULL THEN
    RAISE EXCEPTION 'Pack missing _meta.agent_id';
  END IF;

  IF EXISTS (SELECT 1 FROM cpo.cpo_agent_heads WHERE agent_id = v_agent_id) THEN
    RAISE EXCEPTION 'Agent % already exists. Purge first.', v_agent_id;
  END IF;

  -- Insert canonical tables in export_order.
  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    v_rows := p_pack->v_rec.artifact_type->'rows';
    IF v_rows IS NULL THEN
      -- Export must be structurally complete: every artifact_type key present.
      RAISE EXCEPTION 'Pack missing artifact_type section: %', v_rec.artifact_type;
    END IF;

    PERFORM cpo.durability_insert_rows_for_table(
      v_agent_id,
      v_rec.table_regclass,
      v_rows
    );
  END LOOP;

  -- Rebuild heads projection from canonical maxima.
  PERFORM cpo.rebuild_agent_heads(v_agent_id);

  SELECT to_jsonb(h.*) INTO v_heads
    FROM cpo.cpo_agent_heads h
   WHERE h.agent_id = v_agent_id;

  RETURN jsonb_build_object(
    'rehydrated', true,
    'agent_id', v_agent_id,
    'computed_heads', v_heads
  );
END;
$$;

REVOKE ALL ON FUNCTION cpo.rehydrate_agent(jsonb) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Upgrade: verify_reconstruction(text, jsonb)
-- Verifies:
--   1) Heads equivalence (projection)
--   2) Canonical equivalence via row_hash multiset per artifact type
--
-- Note: row_hash includes action_log_id for tables that have an action_log_id column.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.verify_reconstruction(
  p_agent_id text,
  p_expected_pack jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_expected_heads jsonb;
  v_actual_heads jsonb;
  v_rec record;
  v_expected_hashes text[];
  v_actual_hashes text[];
  v_sql text;
BEGIN
  -- Heads must exist
  SELECT to_jsonb(h.*) INTO v_actual_heads
    FROM cpo.cpo_agent_heads h
   WHERE h.agent_id = p_agent_id;

  IF v_actual_heads IS NULL THEN
    RAISE EXCEPTION 'VERIFICATION FAIL: Agent heads not found for %', p_agent_id;
  END IF;

  v_expected_heads := p_expected_pack->'_meta'->'source_heads';
  IF v_expected_heads IS NULL THEN
    RAISE EXCEPTION 'VERIFICATION FAIL: Pack missing _meta.source_heads';
  END IF;

  -- Compare heads excluding updated_at
  IF (v_expected_heads - 'updated_at') <> (v_actual_heads - 'updated_at') THEN
    RAISE EXCEPTION 'VERIFICATION FAIL: Heads mismatch. expected=% actual=%',
      (v_expected_heads - 'updated_at'), (v_actual_heads - 'updated_at');
  END IF;

  -- Compare canonical rows by row_hash multiset per artifact type.
  FOR v_rec IN
    SELECT * FROM cpo.get_canonical_artifact_types()
  LOOP
    v_expected_hashes := ARRAY(
      SELECT h->>'row_hash'
      FROM jsonb_array_elements(p_expected_pack->v_rec.artifact_type->'rows') AS h
      ORDER BY h->>'row_hash'
    );

    -- Actual row_hash computation (must match export definition)
    IF v_rec.insert_action_log_id_column IS NOT NULL THEN
      v_sql := format(
        'SELECT COALESCE(array_agg(h ORDER BY h), ARRAY[]::text[])
         FROM (
           SELECT encode(public.digest((%I)::text || ''|'' || (%I)::text, ''sha256''), ''hex'') AS h
           FROM %s
           WHERE %I = $1
         ) t',
        v_rec.insert_action_log_id_column,
        v_rec.insert_content_column,
        v_rec.table_regclass,
        v_rec.insert_agent_id_column
      );
    ELSE
      v_sql := format(
        'SELECT COALESCE(array_agg(h ORDER BY h), ARRAY[]::text[])
         FROM (
           SELECT encode(public.digest((%I)::text, ''sha256''), ''hex'') AS h
           FROM %s
           WHERE %I = $1
         ) t',
        v_rec.insert_content_column,
        v_rec.table_regclass,
        v_rec.insert_agent_id_column
      );
    END IF;

    EXECUTE v_sql INTO v_actual_hashes USING p_agent_id;

    IF v_expected_hashes IS DISTINCT FROM v_actual_hashes THEN
      RAISE EXCEPTION 'VERIFICATION FAIL: Canonical mismatch for %: expected=% actual=%',
        v_rec.artifact_type, array_length(v_expected_hashes,1), array_length(v_actual_hashes,1);
    END IF;
  END LOOP;

  RETURN jsonb_build_object('verified', true, 'agent_id', p_agent_id);
END;
$$;

REVOKE ALL ON FUNCTION cpo.verify_reconstruction(text, jsonb) FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Optional: full round-trip test helper (not part of the kernel write aperture).
-- Keeps text signature to align with agent_id contract.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cpo.durability_round_trip_test(
  p_agent_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
DECLARE
  v_pack jsonb;
  v_result jsonb;
BEGIN
  v_pack := cpo.export_evidence_pack(p_agent_id);

  -- Destroy
  PERFORM cpo.purge_agent(p_agent_id);

  -- Rehydrate
  PERFORM cpo.rehydrate_agent(v_pack);

  -- Verify
  v_result := cpo.verify_reconstruction(p_agent_id, v_pack);

  RETURN jsonb_build_object('round_trip', true, 'result', v_result);
END;
$$;

REVOKE ALL ON FUNCTION cpo.durability_round_trip_test(text) FROM PUBLIC;

COMMIT;
