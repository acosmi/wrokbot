-- Immutable trusted dataset identity for the artifact namespace.
-- This internal registry adds no artifact metadata, quota, receipt or public route.
CREATE TABLE openbot_internal.artifact_dataset_bindings (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    binding_schema smallint NOT NULL,
    initial_origin text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT artifact_dataset_bindings_pkey PRIMARY KEY (deployment_id, tenant_id),
    CONSTRAINT artifact_dataset_bindings_deployment_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512
        AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT artifact_dataset_bindings_tenant_shape CHECK (
        octet_length(tenant_id) BETWEEN 1 AND 512
        AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT artifact_dataset_bindings_dataset_shape CHECK (
        octet_length(dataset_id) BETWEEN 1 AND 512
        AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT artifact_dataset_bindings_schema_known CHECK (binding_schema = 1),
    CONSTRAINT artifact_dataset_bindings_origin_known CHECK (
        initial_origin IN ('desktop_canary', 'server_first_adoption')
    )
);

CREATE TRIGGER artifact_dataset_bindings_append_only
    BEFORE DELETE OR UPDATE ON openbot_internal.artifact_dataset_bindings
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_dataset_bindings_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_dataset_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();
