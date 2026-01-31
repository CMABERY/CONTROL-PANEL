-- sql/migrations/p2_artifact_table_registry_v3.sql
-- P2 v3.2: Artifact Table Registry (TRUTHFUL)
--
-- AUDIT CORRECTIONS (v3.2):
--   1. Column names match ACTUAL 000_bootstrap.sql (action_log_id, charter_version_id, etc.)
--   2. Removed non-existent columns (content_hash, snapshot_hash, version, snapshot)
--   3. Added projections (cpo_agent_heads) as is_canonical=false, is_exported=false
--   4. Hash computed at export time, not stored column
--   5. Explicit column lists in all INSERT statements
--   6. logical_id_column = 'id' for tables without generated UUIDs:
--      - cpo_assumption_events, cpo_exception_events, cpo_drift_resolutions, cpo_changes
--
-- INVARIANT:
--   privileged_behavior = f(db_role), not f(strings)
--   durability = f(registry), anchored to write aperture
--   registry is TRUTHFUL (all declared columns exist)

BEGIN;

-- ===========================================================================
-- ARTIFACT TABLE REGISTRY v3
-- ===========================================================================

CREATE TABLE IF NOT EXISTS cpo.cpo_artifact_table_registry (
  artifact_type text PRIMARY KEY,
  table_regclass regclass NOT NULL,
  
  -- Table classification (canonical vs projection)
  table_kind text NOT NULL DEFAULT 'canonical'
    CHECK (table_kind IN ('canonical', 'projection')),
  
  -- Logical identity columns (for export - may be GENERATED)
  logical_id_column text NOT NULL,
  logical_seq_column text,
  
  -- Insert columns (for rehydrate - actually insertable)
  insert_agent_id_column text NOT NULL DEFAULT 'agent_id',
  insert_action_log_id_column text,
  insert_content_column text NOT NULL DEFAULT 'content',
  
  -- Export semantics
  is_canonical boolean NOT NULL DEFAULT true,
  is_exported boolean NOT NULL DEFAULT true,
  export_order int,
  
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  
  CONSTRAINT export_order_unique UNIQUE (export_order),
  CONSTRAINT export_order_positive CHECK (export_order IS NULL OR export_order > 0),
  CONSTRAINT canonical_consistency CHECK (
    (table_kind = 'canonical' AND is_canonical = true) OR
    (table_kind = 'projection' AND is_canonical = false)
  ),
  CONSTRAINT exported_requires_order CHECK (
    (is_exported = true AND export_order IS NOT NULL) OR
    (is_exported = false)
  )
);

-- ===========================================================================
-- IMMUTABILITY GUARD (P1 pattern)
-- ===========================================================================

CREATE OR REPLACE FUNCTION cpo.artifact_registry_immutability_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cpo, pg_catalog
AS $$
BEGIN
  IF current_setting('cpo.migration_in_progress', true) = 'true'
     AND pg_has_role(session_user, 'cpo_migration', 'MEMBER') THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  
  RAISE EXCEPTION 'Artifact registry is immutable at runtime. '
    'Requires: SET cpo.migration_in_progress=true AND cpo_migration role. Table: %',
    TG_TABLE_NAME USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS trg_artifact_registry_immutable ON cpo.cpo_artifact_table_registry;
CREATE TRIGGER trg_artifact_registry_immutable
  BEFORE INSERT OR UPDATE OR DELETE ON cpo.cpo_artifact_table_registry
  FOR EACH ROW EXECUTE FUNCTION cpo.artifact_registry_immutability_guard();

-- ===========================================================================
-- SEED DATA v3: ACTUAL column names from 000_bootstrap.sql
-- ===========================================================================
-- CRITICAL: These MUST match your actual schema. Adjust as needed.

DO $$
BEGIN
  IF pg_has_role(session_user, 'cpo_migration', 'MEMBER') THEN
    SET LOCAL cpo.migration_in_progress = 'true';
    DELETE FROM cpo.cpo_artifact_table_registry;
    
    -- =========================================================================
    -- CANONICAL ARTIFACTS (append-only, exportable)
    -- =========================================================================
    
    -- Action log - GENERATED: action_log_id, seq
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'action_log', 'cpo.cpo_action_logs'::regclass, 'canonical',
      'action_log_id', 'seq',
      'agent_id', NULL, 'content',
      true, true, 10, 'Append-only action log. GENERATED: action_log_id, seq.'
    );
    
    -- Charters - GENERATED: charter_version_id
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'charter', 'cpo.cpo_charters'::regclass, 'canonical',
      'charter_version_id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 20, 'Charter definitions. GENERATED: charter_version_id.'
    );
    
    -- Charter activations - GENERATED: activation_id, seq
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'charter_activation', 'cpo.cpo_charter_activations'::regclass, 'canonical',
      'activation_id', 'seq',
      'agent_id', 'action_log_id', 'content',
      true, true, 21, 'Charter activation records. GENERATED: activation_id, seq.'
    );
    
    -- State snapshots - GENERATED: state_snapshot_id, seq
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'state_snapshot', 'cpo.cpo_state_snapshots'::regclass, 'canonical',
      'state_snapshot_id', 'seq',
      'agent_id', 'action_log_id', 'content',
      true, true, 30, 'State snapshots. GENERATED: state_snapshot_id, seq.'
    );
    
    -- Decisions - GENERATED: decision_id
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'decision', 'cpo.cpo_decisions'::regclass, 'canonical',
      'decision_id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 40, 'Decision records. GENERATED: decision_id.'
    );
    
    -- Assumptions - GENERATED: assumption_id
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'assumption', 'cpo.cpo_assumptions'::regclass, 'canonical',
      'assumption_id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 50, 'Assumption records. GENERATED: assumption_id.'
    );
    
    -- Assumption events (uses bigserial 'id', not generated UUID)
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'assumption_event', 'cpo.cpo_assumption_events'::regclass, 'canonical',
      'id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 51, 'Assumption lifecycle events. Uses bigserial id.'
    );
    
    -- Exceptions - GENERATED: exception_id
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'exception', 'cpo.cpo_exceptions'::regclass, 'canonical',
      'exception_id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 60, 'Exception grants. GENERATED: exception_id.'
    );
    
    -- Exception events (uses bigserial 'id', not generated UUID)
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'exception_event', 'cpo.cpo_exception_events'::regclass, 'canonical',
      'id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 61, 'Exception lifecycle events. Uses bigserial id.'
    );
    
    -- Drift events - GENERATED: drift_event_id
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'drift_event', 'cpo.cpo_drift_events'::regclass, 'canonical',
      'drift_event_id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 70, 'Drift detection events. GENERATED: drift_event_id.'
    );
    
    -- Drift resolutions (uses bigserial 'id', not generated UUID)
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'drift_resolution', 'cpo.cpo_drift_resolutions'::regclass, 'canonical',
      'id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 71, 'Drift resolution records. Uses bigserial id.'
    );
    
    -- Changes (uses bigserial 'id'; change_id lives inside content jsonb)
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'change', 'cpo.cpo_changes'::regclass, 'canonical',
      'id', NULL,
      'agent_id', 'action_log_id', 'content',
      true, true, 80, 'Change control records. Uses bigserial id; change_id in content.'
    );
    
    -- =========================================================================
    -- PROJECTIONS (rebuildable, NOT exported)
    -- =========================================================================
    
    -- Agent heads (derived from canonical artifacts)
    INSERT INTO cpo.cpo_artifact_table_registry (
      artifact_type, table_regclass, table_kind,
      logical_id_column, logical_seq_column,
      insert_agent_id_column, insert_action_log_id_column, insert_content_column,
      is_canonical, is_exported, export_order, description
    ) VALUES (
      'agent_heads', 'cpo.cpo_agent_heads'::regclass, 'projection',
      'agent_id', NULL,
      'agent_id', NULL, 'agent_id',
      false, false, NULL, 'Derived projection. Rebuildable from canonical.'
    );
    
    RAISE NOTICE 'P2 v3: Seeded % canonical + % projection tables',
      (SELECT COUNT(*) FROM cpo.cpo_artifact_table_registry WHERE table_kind = 'canonical'),
      (SELECT COUNT(*) FROM cpo.cpo_artifact_table_registry WHERE table_kind = 'projection');
      
  ELSE
    RAISE EXCEPTION 'P2 v3: session_user "%" lacks cpo_migration role', session_user;
  END IF;
END $$;

-- ===========================================================================
-- HELPER FUNCTIONS
-- ===========================================================================

CREATE OR REPLACE FUNCTION cpo.get_canonical_artifact_types()
RETURNS TABLE (
  artifact_type text, table_regclass regclass,
  logical_id_column text, logical_seq_column text,
  insert_agent_id_column text, insert_action_log_id_column text,
  insert_content_column text, export_order int
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = cpo, pg_catalog
AS $$
  SELECT r.artifact_type, r.table_regclass,
         r.logical_id_column, r.logical_seq_column,
         r.insert_agent_id_column, r.insert_action_log_id_column,
         r.insert_content_column, r.export_order
  FROM cpo.cpo_artifact_table_registry r
  WHERE r.table_kind = 'canonical' AND r.is_exported = true
  ORDER BY r.export_order ASC;
$$;

REVOKE ALL ON FUNCTION cpo.get_canonical_artifact_types() FROM PUBLIC;

CREATE OR REPLACE FUNCTION cpo.get_all_write_aperture_targets()
RETURNS TABLE (
  artifact_type text, table_regclass regclass,
  table_kind text, is_canonical boolean, is_exported boolean
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = cpo, pg_catalog
AS $$
  SELECT r.artifact_type, r.table_regclass, r.table_kind, r.is_canonical, r.is_exported
  FROM cpo.cpo_artifact_table_registry r
  ORDER BY COALESCE(r.export_order, 999), r.artifact_type;
$$;

REVOKE ALL ON FUNCTION cpo.get_all_write_aperture_targets() FROM PUBLIC;

COMMIT;
