-- R401/R402: immutable, content-free evidence of one real remember business commit.
-- No business foreign keys: existing deletion behavior must not erase or be blocked by evidence.
CREATE TABLE public.remember_effect_receipts (
    receipt_id text PRIMARY KEY CHECK (receipt_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    thread_id text NOT NULL,
    run_id text NOT NULL,
    actor_id text NOT NULL,
    bot_id text NOT NULL,
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    tool_call_id text NOT NULL,
    call_seq bigint NOT NULL CHECK (call_seq >= 0),
    attempt_id text NOT NULL UNIQUE,
    attempt_seq bigint NOT NULL CHECK (attempt_seq >= 0),
    decision_id text NOT NULL,
    capability_id text NOT NULL,
    args_hash text NOT NULL CHECK (args_hash ~ '^[0-9a-f]{64}$'),
    schema_hash text NOT NULL CHECK (schema_hash ~ '^[0-9a-f]{64}$'),
    catalog_generation bigint NOT NULL CHECK (catalog_generation >= 0),
    target_kind text NOT NULL CHECK (target_kind IN ('memory_user','memory_bot','memory_thread')),
    target_id text NOT NULL,
    memory_id text NOT NULL CHECK (memory_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    memory_event_seq bigint NOT NULL CHECK (memory_event_seq = 0),
    audit_event_id text NOT NULL CHECK (audit_event_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    recorded_at timestamptz NOT NULL,
    UNIQUE (run_id,call_seq,attempt_seq),
    CONSTRAINT remember_effect_receipts_identity_bounds CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(thread_id) BETWEEN 1 AND 512 AND thread_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(run_id) BETWEEN 1 AND 512 AND run_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(actor_id) BETWEEN 1 AND 512 AND actor_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(bot_id) BETWEEN 1 AND 512 AND bot_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tool_call_id) BETWEEN 1 AND 512 AND tool_call_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(attempt_id) BETWEEN 1 AND 512 AND attempt_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(decision_id) BETWEEN 1 AND 512 AND decision_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(capability_id) BETWEEN 1 AND 512 AND capability_id !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(target_id) BETWEEN 1 AND 512 AND target_id !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT remember_effect_receipts_target_binding CHECK (
        (target_kind='memory_user' AND target_id=actor_id)
        OR (target_kind='memory_bot' AND target_id=bot_id)
        OR (target_kind='memory_thread' AND target_id=thread_id)
    )
);
CREATE TRIGGER remember_effect_receipts_append_only
    BEFORE DELETE OR UPDATE ON public.remember_effect_receipts
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();
CREATE TRIGGER remember_effect_receipts_no_truncate
    BEFORE TRUNCATE ON public.remember_effect_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();
