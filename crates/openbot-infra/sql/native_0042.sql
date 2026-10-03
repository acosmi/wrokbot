-- Real artifact registration, durable admission, lifetime slots and once-only charges.
-- Business source identities deliberately have no user/thread/run/message FK.
-- All six tables are internal; public schema remains exactly0040.

CREATE TABLE openbot_internal.artifact_store_bindings (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    store_id text COLLATE "C" NOT NULL,
    root_device text COLLATE "C" NOT NULL,
    root_inode text COLLATE "C" NOT NULL,
    root_uid text COLLATE "C" NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT artifact_store_bindings_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id),
    CONSTRAINT artifact_store_bindings_exact_key UNIQUE (deployment_id,tenant_id,dataset_id,store_id),
    CONSTRAINT artifact_store_bindings_id_shape CHECK (store_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT artifact_store_bindings_physical_shape CHECK (
        root_device ~ '^(0|[1-9][0-9]{0,19})$' AND root_device::numeric <= 18446744073709551615
        AND root_inode ~ '^(0|[1-9][0-9]{0,19})$' AND root_inode::numeric <= 18446744073709551615
        AND root_uid ~ '^(0|[1-9][0-9]{0,19})$' AND root_uid::numeric <= 18446744073709551615
    ),
    CONSTRAINT artifact_store_bindings_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TABLE openbot_internal.artifact_workspace_quotas (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    workspace_kind text COLLATE "C" NOT NULL,
    workspace_id text COLLATE "C" NOT NULL,
    charged_bytes bigint DEFAULT 0 NOT NULL,
    CONSTRAINT artifact_workspace_quotas_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id,workspace_kind,workspace_id),
    CONSTRAINT artifact_workspace_quotas_kind CHECK (workspace_kind IN ('channel','thread')),
    CONSTRAINT artifact_workspace_quotas_bytes CHECK (charged_bytes BETWEEN 0 AND 17179869184),
    CONSTRAINT artifact_workspace_quotas_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(workspace_id) BETWEEN 1 AND 512 AND workspace_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TABLE openbot_internal.artifact_run_quotas (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    source_run_id text COLLATE "C" NOT NULL,
    identity_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT artifact_run_quotas_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id,source_run_id),
    CONSTRAINT artifact_run_quotas_count CHECK (identity_count BETWEEN 0 AND 32),
    CONSTRAINT artifact_run_quotas_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_run_id) BETWEEN 1 AND 512 AND source_run_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TABLE openbot_internal.artifact_save_operations (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    artifact_id text COLLATE "C" NOT NULL,
    owner_actor_id text COLLATE "C" NOT NULL,
    source_thread_id text COLLATE "C" NOT NULL,
    source_run_id text COLLATE "C" NOT NULL,
    source_message_id text COLLATE "C" NOT NULL,
    source_call_seq bigint,
    source_attempt_seq bigint,
    state text NOT NULL,
    store_id text COLLATE "C",
    workspace_kind text COLLATE "C",
    workspace_id text COLLATE "C",
    expected_sha256 text,
    expected_bytes bigint,
    charged_bytes bigint,
    actual_absent boolean,
    actual_byte_length bigint,
    actual_sha256 text,
    actual_location text,
    observation_phase text,
    created_at timestamptz,
    CONSTRAINT artifact_save_operations_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id,operation_id),
    CONSTRAINT artifact_save_operations_locator UNIQUE (deployment_id,tenant_id,dataset_id,request_id),
    CONSTRAINT artifact_save_operations_artifact UNIQUE (deployment_id,tenant_id,dataset_id,artifact_id),
    CONSTRAINT artifact_save_operations_id_shape CHECK (request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND artifact_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT artifact_save_operations_state CHECK (state IN ('admitted','io_started','available','failed_partial','unresolved','deleted','expired')),
    CONSTRAINT artifact_save_operations_sequences CHECK ((source_call_seq IS NULL AND source_attempt_seq IS NULL) OR (source_call_seq IS NOT NULL AND source_attempt_seq IS NOT NULL AND source_call_seq >= 0 AND source_attempt_seq >= 0)),
    CONSTRAINT artifact_save_operations_payload CHECK (
        (state IN ('deleted','expired') AND store_id IS NULL AND workspace_kind IS NULL AND workspace_id IS NULL
         AND expected_sha256 IS NULL AND expected_bytes IS NULL AND charged_bytes IS NULL AND created_at IS NULL
         AND actual_absent IS NULL AND actual_byte_length IS NULL AND actual_sha256 IS NULL
         AND actual_location IS NULL AND observation_phase IS NULL)
        OR (state NOT IN ('deleted','expired') AND store_id IS NOT NULL AND store_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
         AND workspace_kind IS NOT NULL AND workspace_kind IN ('channel','thread') AND workspace_id IS NOT NULL
         AND octet_length(workspace_id) BETWEEN 1 AND 512 AND workspace_id !~ U&'[\0001-\001F\007F-\009F]'
         AND expected_sha256 IS NOT NULL AND expected_sha256 ~ '^[0-9a-f]{64}$'
         AND expected_bytes IS NOT NULL AND expected_bytes BETWEEN 1 AND 67108864 AND charged_bytes IS NOT NULL AND charged_bytes BETWEEN 0 AND 67108864 AND created_at IS NOT NULL)
    ),
    CONSTRAINT artifact_save_operations_observation CHECK (
        (actual_absent IS NULL AND actual_byte_length IS NULL AND actual_sha256 IS NULL AND actual_location IS NULL)
        OR (actual_absent IS TRUE AND actual_byte_length IS NULL AND actual_sha256 IS NULL AND actual_location IS NULL)
        OR (actual_absent IS FALSE AND actual_byte_length IS NOT NULL AND actual_byte_length BETWEEN 0 AND 67108864
            AND actual_sha256 IS NOT NULL AND actual_sha256 ~ '^[0-9a-f]{64}$'
            AND actual_location IS NOT NULL AND actual_location IN ('staging','object'))
    ),
    CONSTRAINT artifact_save_operations_phase CHECK (observation_phase IS NULL OR observation_phase IN ('before_write','staging','installing','installed')),
    CONSTRAINT artifact_save_operations_store_fkey FOREIGN KEY (deployment_id,tenant_id,dataset_id,store_id)
        REFERENCES openbot_internal.artifact_store_bindings(deployment_id,tenant_id,dataset_id,store_id),
    CONSTRAINT artifact_save_operations_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(owner_actor_id) BETWEEN 1 AND 512 AND owner_actor_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_thread_id) BETWEEN 1 AND 512 AND source_thread_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_run_id) BETWEEN 1 AND 512 AND source_run_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_message_id) BETWEEN 1 AND 512 AND source_message_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TABLE openbot_internal.artifact_records (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    artifact_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    owner_actor_id text COLLATE "C" NOT NULL,
    source_thread_id text COLLATE "C" NOT NULL,
    source_run_id text COLLATE "C" NOT NULL,
    source_message_id text COLLATE "C" NOT NULL,
    source_call_seq bigint,
    source_attempt_seq bigint,
    status text NOT NULL,
    workspace_kind text COLLATE "C",
    workspace_id text COLLATE "C",
    media_type text,
    byte_length bigint,
    sha256 text,
    retention_class text,
    saved_by text COLLATE "C",
    saved_at timestamptz,
    CONSTRAINT artifact_records_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id,artifact_id),
    CONSTRAINT artifact_records_operation UNIQUE (deployment_id,tenant_id,dataset_id,operation_id),
    CONSTRAINT artifact_records_receipt_pair UNIQUE (deployment_id,tenant_id,dataset_id,operation_id,artifact_id),
    CONSTRAINT artifact_records_id_shape CHECK (artifact_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT artifact_records_status CHECK (status IN ('available','failed_partial','deleted','expired')),
    CONSTRAINT artifact_records_sequences CHECK ((source_call_seq IS NULL AND source_attempt_seq IS NULL) OR (source_call_seq IS NOT NULL AND source_attempt_seq IS NOT NULL AND source_call_seq >= 0 AND source_attempt_seq >= 0)),
    CONSTRAINT artifact_records_payload CHECK (
        (status IN ('deleted','expired') AND workspace_kind IS NULL AND workspace_id IS NULL AND media_type IS NULL
         AND byte_length IS NULL AND sha256 IS NULL AND retention_class IS NULL AND saved_by IS NULL AND saved_at IS NULL)
        OR (status IN ('available','failed_partial') AND workspace_kind IS NOT NULL AND workspace_kind IN ('channel','thread') AND workspace_id IS NOT NULL
         AND octet_length(workspace_id) BETWEEN 1 AND 512 AND workspace_id !~ U&'[\0001-\001F\007F-\009F]'
         AND media_type IS NOT NULL AND media_type='text/plain; charset=utf-8' AND byte_length IS NOT NULL AND byte_length BETWEEN 0 AND 67108864
         AND sha256 IS NOT NULL AND sha256 ~ '^[0-9a-f]{64}$'
         AND retention_class IS NOT NULL AND retention_class='explicit_saved' AND saved_by IS NOT NULL AND saved_by=owner_actor_id AND saved_at IS NOT NULL)
    ),
    CONSTRAINT artifact_records_operation_fkey FOREIGN KEY (deployment_id,tenant_id,dataset_id,operation_id)
        REFERENCES openbot_internal.artifact_save_operations(deployment_id,tenant_id,dataset_id,operation_id),
    CONSTRAINT artifact_records_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(owner_actor_id) BETWEEN 1 AND 512 AND owner_actor_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_thread_id) BETWEEN 1 AND 512 AND source_thread_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_run_id) BETWEEN 1 AND 512 AND source_run_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_message_id) BETWEEN 1 AND 512 AND source_message_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TABLE openbot_internal.artifact_saved_receipts (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    artifact_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    owner_actor_id text COLLATE "C" NOT NULL,
    source_thread_id text COLLATE "C" NOT NULL,
    source_run_id text COLLATE "C" NOT NULL,
    source_message_id text COLLATE "C" NOT NULL,
    source_call_seq bigint,
    source_attempt_seq bigint,
    CONSTRAINT artifact_saved_receipts_pkey PRIMARY KEY (deployment_id,tenant_id,dataset_id,operation_id),
    CONSTRAINT artifact_saved_receipts_artifact UNIQUE (deployment_id,tenant_id,dataset_id,artifact_id),
    CONSTRAINT artifact_saved_receipts_id_shape CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND artifact_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT artifact_saved_receipts_sequences CHECK ((source_call_seq IS NULL AND source_attempt_seq IS NULL) OR (source_call_seq IS NOT NULL AND source_attempt_seq IS NOT NULL AND source_call_seq >= 0 AND source_attempt_seq >= 0)),
    CONSTRAINT artifact_saved_receipts_operation_fkey FOREIGN KEY (deployment_id,tenant_id,dataset_id,operation_id)
        REFERENCES openbot_internal.artifact_save_operations(deployment_id,tenant_id,dataset_id,operation_id),
    CONSTRAINT artifact_saved_receipts_artifact_fkey FOREIGN KEY (deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
        REFERENCES openbot_internal.artifact_records(deployment_id,tenant_id,dataset_id,operation_id,artifact_id),
    CONSTRAINT artifact_saved_receipts_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(owner_actor_id) BETWEEN 1 AND 512 AND owner_actor_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_thread_id) BETWEEN 1 AND 512 AND source_thread_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_run_id) BETWEEN 1 AND 512 AND source_run_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(source_message_id) BETWEEN 1 AND 512 AND source_message_id !~ U&'[\0001-\001F\007F-\009F]'
    )
);

CREATE TRIGGER artifact_store_bindings_append_only
    BEFORE DELETE OR UPDATE ON openbot_internal.artifact_store_bindings
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_saved_receipts_append_only
    BEFORE DELETE OR UPDATE ON openbot_internal.artifact_saved_receipts
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_store_bindings_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_store_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_workspace_quotas_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_workspace_quotas
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_run_quotas_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_run_quotas
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_save_operations_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_save_operations
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_records_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_records
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_saved_receipts_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_saved_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE INDEX artifact_records_source_idx ON openbot_internal.artifact_records
    USING btree(deployment_id,tenant_id,dataset_id,source_run_id,artifact_id);

-- Durable identities survive source deletion and cannot be rebound or reopened for another IO.
CREATE FUNCTION openbot_internal.prevent_artifact_operation_misuse()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'artifact operation identity cannot be deleted' USING ERRCODE='55000';
    END IF;
    IF ROW(NEW.deployment_id,NEW.tenant_id,NEW.dataset_id,NEW.request_id,NEW.operation_id,NEW.artifact_id,
           NEW.owner_actor_id,NEW.source_thread_id,NEW.source_run_id,NEW.source_message_id,NEW.source_call_seq,NEW.source_attempt_seq)
       IS DISTINCT FROM
       ROW(OLD.deployment_id,OLD.tenant_id,OLD.dataset_id,OLD.request_id,OLD.operation_id,OLD.artifact_id,
           OLD.owner_actor_id,OLD.source_thread_id,OLD.source_run_id,OLD.source_message_id,OLD.source_call_seq,OLD.source_attempt_seq) THEN
        RAISE EXCEPTION 'artifact operation identity cannot be rebound' USING ERRCODE='55000';
    END IF;
    IF OLD.state IN ('deleted','expired') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'artifact operation tombstone is final' USING ERRCODE='55000';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
        (OLD.state='admitted' AND NEW.state IN ('io_started','unresolved'))
        OR (OLD.state='io_started' AND NEW.state IN ('available','failed_partial','unresolved'))
        OR (OLD.state='unresolved' AND NEW.state IN ('failed_partial','deleted','expired'))
        OR (OLD.state IN ('available','failed_partial') AND NEW.state IN ('deleted','expired'))
    ) THEN
        RAISE EXCEPTION 'artifact operation cannot reopen IO' USING ERRCODE='55000';
    END IF;
    IF NEW.state NOT IN ('deleted','expired') AND
       ROW(NEW.store_id,NEW.workspace_kind,NEW.workspace_id,NEW.expected_sha256,NEW.expected_bytes,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.store_id,OLD.workspace_kind,OLD.workspace_id,OLD.expected_sha256,OLD.expected_bytes,OLD.created_at) THEN
        RAISE EXCEPTION 'artifact operation intent cannot change' USING ERRCODE='55000';
    END IF;
    IF OLD.state IN ('available','failed_partial') AND NEW.state=OLD.state AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'artifact settled operation cannot change' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_save_operations_identity_guard
    BEFORE DELETE OR UPDATE ON openbot_internal.artifact_save_operations
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_artifact_operation_misuse();

CREATE FUNCTION openbot_internal.prevent_artifact_record_misuse()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'artifact identity cannot be deleted' USING ERRCODE='55000';
    END IF;
    IF ROW(NEW.deployment_id,NEW.tenant_id,NEW.dataset_id,NEW.artifact_id,NEW.operation_id,NEW.request_id,
           NEW.owner_actor_id,NEW.source_thread_id,NEW.source_run_id,NEW.source_message_id,NEW.source_call_seq,NEW.source_attempt_seq)
       IS DISTINCT FROM
       ROW(OLD.deployment_id,OLD.tenant_id,OLD.dataset_id,OLD.artifact_id,OLD.operation_id,OLD.request_id,
           OLD.owner_actor_id,OLD.source_thread_id,OLD.source_run_id,OLD.source_message_id,OLD.source_call_seq,OLD.source_attempt_seq) THEN
        RAISE EXCEPTION 'artifact identity cannot be rebound' USING ERRCODE='55000';
    END IF;
    IF NEW.status=OLD.status AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'artifact record cannot be overwritten' USING ERRCODE='55000';
    END IF;
    IF NEW.status<>OLD.status AND NOT
       (OLD.status IN ('available','failed_partial') AND NEW.status IN ('deleted','expired')) THEN
        RAISE EXCEPTION 'artifact record tombstone cannot reopen' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_records_identity_guard
    BEFORE DELETE OR UPDATE ON openbot_internal.artifact_records
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_artifact_record_misuse();

-- Deleting a counter cannot make preserved lifetime identities or bytes disappear.
CREATE TRIGGER artifact_workspace_quotas_no_delete
    BEFORE DELETE ON openbot_internal.artifact_workspace_quotas
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER artifact_run_quotas_no_delete
    BEFORE DELETE ON openbot_internal.artifact_run_quotas
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();
