-- Immutable accepted custom-model V2 intent and original dataset snapshots.
-- Applied only inside the original native migration transaction. No legacy backfill.

DO $custom_model_v2_owner$
DECLARE
    v_original_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
BEGIN
    SELECT c.relowner INTO v_original_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'model_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER;
    IF v_original_owner IS NULL OR v_current_role IS NULL OR
       v_current_role IS DISTINCT FROM v_original_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
END;
$custom_model_v2_owner$;

CREATE TABLE openbot_internal.run_model_selection_v2_snapshots (
    run_id text COLLATE pg_catalog."C" NOT NULL,
    deployment_id text COLLATE pg_catalog."C" NOT NULL,
    tenant_id text COLLATE pg_catalog."C" NOT NULL,
    owner_user_id text COLLATE pg_catalog."C" NOT NULL,
    auth_generation bigint NOT NULL,
    connection_id uuid NOT NULL,
    connection_revision bigint NOT NULL,
    secret_id uuid NOT NULL,
    protocol text COLLATE pg_catalog."C" NOT NULL,
    endpoint text COLLATE pg_catalog."C" NOT NULL,
    model text COLLATE pg_catalog."C" NOT NULL,
    created_at timestamp with time zone NOT NULL,
    snapshot_schema smallint NOT NULL,
    source text COLLATE pg_catalog."C" NOT NULL,
    model_id text COLLATE pg_catalog."C" NOT NULL,
    catalog_revision bigint NOT NULL,
    dataset_id text COLLATE pg_catalog."C" NOT NULL,
    dataset_binding_schema smallint NOT NULL,
    dataset_initial_origin text COLLATE pg_catalog."C" NOT NULL,
    dataset_binding_created_at timestamp with time zone NOT NULL,
    credential_policy text COLLATE pg_catalog."C" NOT NULL,
    CONSTRAINT run_model_selection_v2_snapshots_pkey PRIMARY KEY (run_id),
    CONSTRAINT run_model_selection_v2_snapshots_run_fkey
        FOREIGN KEY (run_id) REFERENCES public.runs (run_id)
        MATCH SIMPLE ON UPDATE RESTRICT ON DELETE CASCADE
        NOT DEFERRABLE INITIALLY IMMEDIATE,
    CONSTRAINT run_model_selection_v2_snapshots_scope_check
        CHECK (pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512
               AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
               AND pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512
               AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
               AND pg_catalog.octet_length(owner_user_id) BETWEEN 1 AND 512
               AND owner_user_id !~ U&'[\0001-\001F\007F-\009F]'),
    CONSTRAINT run_model_selection_v2_snapshots_auth_generation_nonnegative
        CHECK (auth_generation >= 0),
    CONSTRAINT run_model_selection_v2_snapshots_connection_revision_positive
        CHECK (connection_revision > 0),
    CONSTRAINT run_model_selection_v2_snapshots_protocol_check
        CHECK (protocol IN ('openai_chat_completions', 'openai_responses', 'anthropic_messages')),
    CONSTRAINT run_model_selection_v2_snapshots_endpoint_check
        CHECK (pg_catalog.octet_length(endpoint) BETWEEN 1 AND 2048),
    CONSTRAINT run_model_selection_v2_snapshots_model_check
        CHECK (pg_catalog.octet_length(model) BETWEEN 1 AND 512),
    CONSTRAINT run_model_selection_v2_snapshots_snapshot_schema_check
        CHECK (snapshot_schema = 2),
    CONSTRAINT run_model_selection_v2_snapshots_source_check
        CHECK (source = 'custom'),
    CONSTRAINT run_model_selection_v2_snapshots_model_id_shape
        CHECK (pg_catalog.octet_length(model_id) = 43
               AND model_id = ('custom:'::text || connection_id::text)),
    CONSTRAINT run_model_selection_v2_snapshots_catalog_revision_positive
        CHECK (catalog_revision > 0),
    CONSTRAINT run_model_selection_v2_snapshots_dataset_id_check
        CHECK (pg_catalog.octet_length(dataset_id) BETWEEN 1 AND 512
               AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'),
    CONSTRAINT run_model_selection_v2_snapshots_dataset_binding_schema_check
        CHECK (dataset_binding_schema = 1),
    CONSTRAINT run_model_selection_v2_snapshots_dataset_initial_origin_check
        CHECK (dataset_initial_origin IN ('desktop_canary', 'server_first_adoption')),
    CONSTRAINT run_model_selection_v2_snapshots_credential_policy_check
        CHECK (credential_policy = 'custom_fixed_secret_revision_v1')
);

DO $custom_model_v2_postconditions$
DECLARE
    v_original_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
    v_snapshot_oid pg_catalog.oid;
    v_snapshot_owner pg_catalog.oid;
BEGIN
    SELECT c.relowner INTO v_original_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'model_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER;
    SELECT c.oid, c.relowner INTO v_snapshot_oid, v_snapshot_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'openbot_internal' AND c.relname = 'run_model_selection_v2_snapshots'
      AND c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relispartition
      AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity;
    IF v_original_owner IS NULL OR v_current_role IS NULL OR v_snapshot_oid IS NULL OR
       v_current_role IS DISTINCT FROM v_original_owner OR
       v_snapshot_owner IS DISTINCT FROM v_original_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = v_snapshot_oid AND a.attnum > 0
          AND (a.attisdropped OR a.attacl IS NOT NULL)
    ) OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a
          WHERE a.attrelid = v_snapshot_oid AND a.attnum > 0) <> 21 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = v_snapshot_oid) OR
       EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class = v_snapshot_oid) OR
       EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
               WHERE tgrelid = v_snapshot_oid AND NOT tgisinternal) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index
        WHERE indrelid = v_snapshot_oid) <> 1 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid = idx.relam
        WHERE i.indrelid = v_snapshot_oid AND (
            idx.relowner IS DISTINCT FROM v_original_owner OR idx.relacl IS NOT NULL OR
            idx.relname <> 'run_model_selection_v2_snapshots_pkey' OR am.amname <> 'btree' OR
            NOT i.indisprimary OR NOT i.indisunique OR NOT i.indisvalid OR
            NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate OR
            i.indnullsnotdistinct OR i.indnkeyatts <> 1 OR i.indnatts <> 1 OR
            i.indkey::text <> '1' OR i.indpred IS NOT NULL OR i.indexprs IS NOT NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
    -- NULL and explicit builtin owner-only ACLs are the sole allowed states.
    -- EXCEPT ALL retains duplicate entries, grant options and PG17 MAINTAIN.
    -- Inherited additional default grants fail this migration; never REVOKE/repair them.
    IF EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_snapshot_oid)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_original_owner)) a)
    ) OR EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_original_owner)) a)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_snapshot_oid)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_v2_schema_invalid';
    END IF;
END;
$custom_model_v2_postconditions$;
