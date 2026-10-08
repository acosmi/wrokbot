-- Persistent custom model catalogs for existing model connections.
-- Uses the original Read Committed native migration transaction.
-- The first explicit connection-table lock precedes DDL and backfill.

DO $custom_model_catalog_owner$
DECLARE
    v_old_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
BEGIN
    SELECT c.relowner INTO v_old_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'model_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r
    WHERE r.rolname = CURRENT_USER;
    IF v_old_owner IS NULL OR v_current_role IS NULL OR
       v_current_role IS DISTINCT FROM v_old_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
END;
$custom_model_catalog_owner$;

LOCK TABLE public.model_connections IN EXCLUSIVE MODE;

CREATE TABLE public.custom_model_catalogs (
    connection_id uuid NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL,
    model_id text COLLATE pg_catalog."C" NOT NULL,
    catalog_revision bigint NOT NULL,
    protocol text NOT NULL,
    endpoint text NOT NULL,
    model text NOT NULL,
    enabled boolean NOT NULL,
    retired boolean NOT NULL,
    CONSTRAINT custom_model_catalogs_pkey PRIMARY KEY (connection_id),
    CONSTRAINT custom_model_catalogs_model_id_key UNIQUE (model_id),
    CONSTRAINT custom_model_catalogs_model_id_shape
        CHECK (pg_catalog.octet_length(model_id) = 43
               AND model_id = ('custom:'::text || connection_id::text)),
    CONSTRAINT custom_model_catalogs_catalog_revision_positive
        CHECK (catalog_revision > 0),
    CONSTRAINT custom_model_catalogs_protocol_check
        CHECK (protocol IN ('openai_chat_completions', 'openai_responses', 'anthropic_messages')),
    CONSTRAINT custom_model_catalogs_endpoint_check
        CHECK (pg_catalog.octet_length(endpoint) BETWEEN 1 AND 2048),
    CONSTRAINT custom_model_catalogs_model_check
        CHECK (pg_catalog.octet_length(model) BETWEEN 1 AND 512),
    CONSTRAINT custom_model_catalogs_connection_scope_fkey
        FOREIGN KEY (connection_id, deployment_id, tenant_id, owner_user_id)
        REFERENCES public.model_connections (id, deployment_id, tenant_id, owner_user_id)
        MATCH SIMPLE ON UPDATE RESTRICT ON DELETE CASCADE
        NOT DEFERRABLE INITIALLY IMMEDIATE
);

-- All original rows, including disabled and softdeleted, start catalog revision 1.
-- Their existing connection revision, names, secret pointers and times are untouched.
INSERT INTO public.custom_model_catalogs (
    connection_id, deployment_id, tenant_id, owner_user_id,
    model_id, catalog_revision, protocol, endpoint, model, enabled, retired
)
SELECT c.id, c.deployment_id, c.tenant_id, c.owner_user_id,
       'custom:'::text || c.id::text, 1,
       c.protocol, c.endpoint, c.model, c.enabled, c.deleted_at IS NOT NULL
FROM public.model_connections c;

CREATE FUNCTION openbot_internal.sync_custom_model_catalog()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE CALLED ON NULL INPUT SECURITY INVOKER PARALLEL UNSAFE
SET search_path = pg_catalog
AS $custom_model_catalog_sync$
DECLARE
    v_catalog public.custom_model_catalogs%ROWTYPE;
    v_revision bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.custom_model_catalogs (
            connection_id, deployment_id, tenant_id, owner_user_id,
            model_id, catalog_revision, protocol, endpoint, model, enabled, retired
        ) VALUES (
            NEW.id, NEW.deployment_id, NEW.tenant_id, NEW.owner_user_id,
            'custom:'::text || NEW.id::text, 1,
            NEW.protocol, NEW.endpoint, NEW.model, NEW.enabled, NEW.deleted_at IS NOT NULL
        );
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    SELECT c.* INTO v_catalog
    FROM public.custom_model_catalogs c
    WHERE c.connection_id = OLD.id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF v_catalog.catalog_revision <= 0 OR
       ROW(v_catalog.connection_id, v_catalog.deployment_id, v_catalog.tenant_id,
           v_catalog.owner_user_id, v_catalog.model_id, v_catalog.protocol,
           v_catalog.endpoint, v_catalog.model, v_catalog.enabled, v_catalog.retired)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.deployment_id, OLD.tenant_id, OLD.owner_user_id,
           'custom:'::text || OLD.id::text, OLD.protocol, OLD.endpoint, OLD.model,
           OLD.enabled, OLD.deleted_at IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF ROW(NEW.id, NEW.deployment_id, NEW.tenant_id, NEW.owner_user_id)
       IS DISTINCT FROM ROW(OLD.id, OLD.deployment_id, OLD.tenant_id, OLD.owner_user_id) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF ROW(NEW.protocol, NEW.endpoint, NEW.model, NEW.enabled, NEW.deleted_at IS NOT NULL)
       IS NOT DISTINCT FROM
       ROW(OLD.protocol, OLD.endpoint, OLD.model, OLD.enabled, OLD.deleted_at IS NOT NULL) THEN
        RETURN NEW;
    END IF;
    IF v_catalog.catalog_revision = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    v_revision := v_catalog.catalog_revision + 1;
    UPDATE public.custom_model_catalogs
    SET catalog_revision = v_revision, protocol = NEW.protocol, endpoint = NEW.endpoint,
        model = NEW.model, enabled = NEW.enabled, retired = NEW.deleted_at IS NOT NULL
    WHERE connection_id = OLD.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    RETURN NEW;
END;
$custom_model_catalog_sync$;

CREATE TRIGGER model_connections_custom_catalog_sync
AFTER INSERT OR UPDATE ON public.model_connections
FOR EACH ROW EXECUTE FUNCTION openbot_internal.sync_custom_model_catalog();

-- Only new objects are affected. Additional custom default grants to another role
-- cause the exact ACL assertion to fail; no dynamic ACL cleanup is permitted.
REVOKE ALL ON FUNCTION openbot_internal.sync_custom_model_catalog() FROM PUBLIC;

DO $custom_model_catalog_postconditions$
DECLARE
    v_old_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
    v_catalog_oid pg_catalog.oid;
    v_catalog_owner pg_catalog.oid;
    v_function_oid pg_catalog.oid;
    v_function_owner pg_catalog.oid;
BEGIN
    -- The expected owner still comes from the original 0030 relation, never a
    -- newly created object's ACL/owner and never a caller-supplied role/OID.
    SELECT c.relowner INTO v_old_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'model_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r
    WHERE r.rolname = CURRENT_USER;
    SELECT c.oid, c.relowner INTO v_catalog_oid, v_catalog_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'custom_model_catalogs' AND c.relkind = 'r';
    SELECT p.oid, p.proowner INTO v_function_oid, v_function_owner
    FROM pg_catalog.pg_proc p
    WHERE p.oid = pg_catalog.to_regprocedure('openbot_internal.sync_custom_model_catalog()');
    IF v_old_owner IS NULL OR v_current_role IS NULL OR v_catalog_oid IS NULL OR
       v_function_oid IS NULL OR v_current_role IS DISTINCT FROM v_old_owner OR
       v_catalog_owner IS DISTINCT FROM v_old_owner OR
       v_function_owner IS DISTINCT FROM v_old_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index i
        WHERE i.indrelid = v_catalog_oid) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
        WHERE i.indrelid = v_catalog_oid AND (
            idx.relowner IS DISTINCT FROM v_old_owner OR
            idx.relname NOT IN ('custom_model_catalogs_pkey', 'custom_model_catalogs_model_id_key')
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = v_catalog_oid AND a.attnum > 0 AND NOT a.attisdropped
          AND a.attacl IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    -- Full ACL multiset, including duplicate entries and grant options. PG17's
    -- own TABLE default includes MAINTAIN; no hand-written old seven-item list.
    IF EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_catalog_oid)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_old_owner)) a)
    ) OR EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_old_owner)) a)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_catalog_oid)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    -- FUNCTION expected ACL is exactly (original O, original O, EXECUTE, false).
    -- NULL actual ACL expands to the default PUBLIC grant and therefore fails.
    IF EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_proc p
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(p.proacl, pg_catalog.acldefault('f'::pg_catalog."char", p.proowner))) a
         WHERE p.oid = v_function_oid)
        EXCEPT ALL
        (SELECT v_old_owner, v_old_owner, 'EXECUTE'::text, false)
    ) OR EXISTS (
        (SELECT v_old_owner, v_old_owner, 'EXECUTE'::text, false)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_proc p
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(p.proacl, pg_catalog.acldefault('f'::pg_catalog."char", p.proowner))) a
         WHERE p.oid = v_function_oid)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    -- This check applies to this one new DDL/backfill, not native AlreadyApplied.
    -- The separate replay verifier requires positive revisions, never resetting 1.
    IF EXISTS (
        SELECT 1
        FROM public.model_connections m
        LEFT JOIN public.custom_model_catalogs c ON c.connection_id = m.id
        WHERE c.connection_id IS NULL OR
          ROW(c.connection_id, c.deployment_id, c.tenant_id, c.owner_user_id,
              c.model_id, c.catalog_revision, c.protocol, c.endpoint, c.model,
              c.enabled, c.retired)
          IS DISTINCT FROM
          ROW(m.id, m.deployment_id, m.tenant_id, m.owner_user_id,
              'custom:'::text || m.id::text, 1::bigint, m.protocol, m.endpoint,
              m.model, m.enabled, m.deleted_at IS NOT NULL)
    ) OR EXISTS (
        SELECT 1
        FROM public.custom_model_catalogs c
        LEFT JOIN public.model_connections m ON m.id = c.connection_id
        WHERE m.id IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
END;
$custom_model_catalog_postconditions$;
