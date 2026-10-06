-- Durable cleanup intent for an already materialized original artifact record only.
-- Neither phase proves physical absence, directory sync, reader drain or a byte refund.
DO $$
BEGIN
    IF pg_catalog.current_setting('server_encoding') <> 'UTF8'
       OR pg_catalog.current_setting('block_size')::integer <> 8192
       OR pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 170000 AND 179999 THEN
        RAISE EXCEPTION 'artifact cleanup storage prerequisites are unavailable'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE TABLE openbot_internal.artifact_cleanup_fences (
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    dataset_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    artifact_id text COLLATE "C" NOT NULL,
    terminal_status text NOT NULL,
    phase text NOT NULL,
    CONSTRAINT artifact_cleanup_fences_pkey PRIMARY KEY
        (deployment_id, tenant_id, dataset_id, artifact_id),
    CONSTRAINT artifact_cleanup_fences_record_pair_fkey FOREIGN KEY
        (deployment_id, tenant_id, dataset_id, operation_id, artifact_id)
        REFERENCES openbot_internal.artifact_records
            (deployment_id, tenant_id, dataset_id, operation_id, artifact_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE INITIALLY IMMEDIATE,
    CONSTRAINT artifact_cleanup_fences_identity_shape CHECK (
        pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512
        AND (deployment_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512
        AND (tenant_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND pg_catalog.octet_length(dataset_id) BETWEEN 1 AND 512
        AND (dataset_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT artifact_cleanup_fences_id_shape CHECK (
        pg_catalog.octet_length(operation_id) = 36
        AND pg_catalog.octet_length(artifact_id) = 36
        AND (operation_id COLLATE "C") ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND (artifact_id COLLATE "C") ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT artifact_cleanup_fences_terminal_status CHECK
        (terminal_status IN ('deleted', 'expired')),
    CONSTRAINT artifact_cleanup_fences_phase CHECK
        (phase IN ('armed', 'completed'))
);

-- This is a structural guard, not a producer for deletion or current authorization.
CREATE FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'artifact cleanup fences cannot be removed'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase IS DISTINCT FROM 'armed' THEN
            RAISE EXCEPTION 'artifact cleanup fences must begin armed'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'artifact cleanup fence operation is unsupported'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(NEW.deployment_id, NEW.tenant_id, NEW.dataset_id, NEW.operation_id,
           NEW.artifact_id, NEW.terminal_status)
       IS DISTINCT FROM
       ROW(OLD.deployment_id, OLD.tenant_id, OLD.dataset_id, OLD.operation_id,
           OLD.artifact_id, OLD.terminal_status) THEN
        RAISE EXCEPTION 'artifact cleanup fence identity and intent are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF OLD.phase IS DISTINCT FROM 'armed' OR NEW.phase IS DISTINCT FROM 'completed' THEN
        RAISE EXCEPTION 'artifact cleanup fence phase cannot reopen'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM openbot_internal.artifact_records AS record
        JOIN openbot_internal.artifact_save_operations AS operation
          ON operation.deployment_id = record.deployment_id
         AND operation.tenant_id = record.tenant_id
         AND operation.dataset_id = record.dataset_id
         AND operation.operation_id = record.operation_id
         AND operation.artifact_id = record.artifact_id
        WHERE record.deployment_id = NEW.deployment_id
          AND record.tenant_id = NEW.tenant_id
          AND record.dataset_id = NEW.dataset_id
          AND record.operation_id = NEW.operation_id
          AND record.artifact_id = NEW.artifact_id
          AND record.status = NEW.terminal_status
          AND operation.state = NEW.terminal_status
          AND operation.request_id IS NOT DISTINCT FROM record.request_id
          AND operation.owner_actor_id IS NOT DISTINCT FROM record.owner_actor_id
          AND operation.source_thread_id IS NOT DISTINCT FROM record.source_thread_id
          AND operation.source_run_id IS NOT DISTINCT FROM record.source_run_id
          AND operation.source_message_id IS NOT DISTINCT FROM record.source_message_id
          AND operation.source_call_seq IS NOT DISTINCT FROM record.source_call_seq
          AND operation.source_attempt_seq IS NOT DISTINCT FROM record.source_attempt_seq
    ) THEN
        RAISE EXCEPTION 'artifact cleanup completion requires the exact original terminal pair'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_cleanup_fences_identity_guard
    BEFORE INSERT OR UPDATE OR DELETE ON openbot_internal.artifact_cleanup_fences
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation();

CREATE TRIGGER artifact_cleanup_fences_no_truncate
    BEFORE TRUNCATE ON openbot_internal.artifact_cleanup_fences
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_artifact_cleanup_fence_mutation();
