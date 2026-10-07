-- Additive repair of cleanup completion; earlier native SQL and guards remain immutable.
-- No receipt is manufactured: partially materialized artifacts may have no saved receipt.
CREATE FUNCTION openbot_internal.prevent_artifact_cleanup_saved_receipt_mismatch()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.phase = 'armed' AND NEW.phase = 'completed' AND EXISTS (
        SELECT 1
        FROM openbot_internal.artifact_saved_receipts AS receipt
        JOIN openbot_internal.artifact_records AS record
          ON record.deployment_id = receipt.deployment_id
         AND record.tenant_id = receipt.tenant_id
         AND record.dataset_id = receipt.dataset_id
         AND record.operation_id = receipt.operation_id
         AND record.artifact_id = receipt.artifact_id
        JOIN openbot_internal.artifact_save_operations AS operation
          ON operation.deployment_id = record.deployment_id
         AND operation.tenant_id = record.tenant_id
         AND operation.dataset_id = record.dataset_id
         AND operation.operation_id = record.operation_id
         AND operation.artifact_id = record.artifact_id
        WHERE receipt.deployment_id = NEW.deployment_id
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.dataset_id = NEW.dataset_id
          AND receipt.operation_id = NEW.operation_id
          AND receipt.artifact_id = NEW.artifact_id
          AND (
            ROW(receipt.request_id, receipt.owner_actor_id, receipt.source_thread_id,
                receipt.source_run_id, receipt.source_message_id,
                receipt.source_call_seq, receipt.source_attempt_seq)
            IS DISTINCT FROM
            ROW(record.request_id, record.owner_actor_id, record.source_thread_id,
                record.source_run_id, record.source_message_id,
                record.source_call_seq, record.source_attempt_seq)
            OR
            ROW(receipt.request_id, receipt.owner_actor_id, receipt.source_thread_id,
                receipt.source_run_id, receipt.source_message_id,
                receipt.source_call_seq, receipt.source_attempt_seq)
            IS DISTINCT FROM
            ROW(operation.request_id, operation.owner_actor_id, operation.source_thread_id,
                operation.source_run_id, operation.source_message_id,
                operation.source_call_seq, operation.source_attempt_seq)
          )
    ) THEN
        RAISE EXCEPTION 'artifact cleanup completion requires the original saved receipt'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_cleanup_fences_saved_receipt_guard
    BEFORE UPDATE ON openbot_internal.artifact_cleanup_fences
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_artifact_cleanup_saved_receipt_mismatch();
