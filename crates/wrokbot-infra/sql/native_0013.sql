-- OpenBot native schema 0013：audit hash chain / checkpoint / durable tool decision。
--
-- 只允许 expand（v3 §14.3）：追加 nullable 列、新表、索引与非破坏性 CHECK/FK；
-- 本文件不得出现 DROP / RENAME / ALTER COLUMN / SET NOT NULL / downgrade。
-- 幂等性由 openbot_internal.schema_migrations 账本承担，本文件本身刻意不用 IF NOT EXISTS：
-- 「对象存在但账本没有」是需要调查的漂移，不能静默当成已经施加。

ALTER TABLE public.audit_events
    ADD COLUMN prev_hash text;

ALTER TABLE public.audit_events
    ADD COLUMN row_hash text;

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_prev_hash_lower_hex
    CHECK (prev_hash IS NULL OR prev_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_row_hash_lower_hex
    CHECK (row_hash IS NULL OR row_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_hash_pair_shape
    CHECK (row_hash IS NOT NULL OR prev_hash IS NULL);

CREATE TABLE public.audit_checkpoints (
    sequence bigint NOT NULL,
    checkpoint_kind text NOT NULL,
    first_event_id text NOT NULL,
    first_row_hash text NOT NULL,
    last_event_id text NOT NULL,
    last_row_hash text NOT NULL,
    event_count bigint NOT NULL,
    unlinked_rows_before bigint,
    retention_days integer,
    signature text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT audit_checkpoints_pkey PRIMARY KEY (sequence),
    CONSTRAINT audit_checkpoints_sequence_nonnegative CHECK (sequence >= 0),
    CONSTRAINT audit_checkpoints_first_hash_lower_hex
        CHECK (first_row_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_checkpoints_last_hash_lower_hex
        CHECK (last_row_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_checkpoints_signature_lower_hex
        CHECK (signature ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_checkpoints_event_count_positive CHECK (event_count > 0),
    CONSTRAINT audit_checkpoints_unlinked_rows_nonnegative
        CHECK (unlinked_rows_before IS NULL OR unlinked_rows_before >= 0),
    CONSTRAINT audit_checkpoints_retention_days_positive
        CHECK (retention_days IS NULL OR retention_days >= 1),
    CONSTRAINT audit_checkpoints_kind_shape CHECK (
        (
            checkpoint_kind = 'genesis'
            AND first_event_id = last_event_id
            AND first_row_hash = last_row_hash
            AND event_count = 1
            AND unlinked_rows_before IS NOT NULL
            AND retention_days IS NULL
        )
        OR (
            checkpoint_kind = 'periodic'
            AND unlinked_rows_before IS NULL
            AND retention_days IS NULL
        )
        OR (
            checkpoint_kind = 'closure'
            AND unlinked_rows_before IS NULL
            AND retention_days IS NOT NULL
        )
    )
);

CREATE INDEX audit_checkpoints_created_at_idx
    ON public.audit_checkpoints USING btree (created_at, sequence);

CREATE FUNCTION openbot_internal.prevent_append_only_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'append-only relation refuses mutation';
END;
$$;

CREATE TRIGGER audit_checkpoints_append_only
    BEFORE DELETE OR UPDATE ON public.audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TRIGGER audit_checkpoints_no_truncate
    BEFORE TRUNCATE ON public.audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_append_only_mutation();

CREATE TABLE public.tool_calls (
    tool_call_id text NOT NULL,
    run_id text NOT NULL,
    call_seq bigint NOT NULL,
    decision_id text NOT NULL,
    actor_id text NOT NULL,
    bot_id text NOT NULL,
    tool_name text NOT NULL,
    schema_hash text NOT NULL,
    catalog_generation bigint NOT NULL,
    args_hash text NOT NULL,
    target_kind text NOT NULL,
    target_id text NOT NULL,
    effect text NOT NULL,
    effect_downgraded boolean NOT NULL,
    idempotency text NOT NULL,
    idempotency_key text,
    approval_class text NOT NULL,
    policy_version text NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tool_calls_pkey PRIMARY KEY (tool_call_id),
    CONSTRAINT tool_calls_run_call_seq_key UNIQUE (run_id, call_seq),
    CONSTRAINT tool_calls_decision_id_key UNIQUE (decision_id),
    CONSTRAINT tool_calls_call_seq_nonnegative CHECK (call_seq >= 0),
    CONSTRAINT tool_calls_catalog_generation_nonnegative CHECK (catalog_generation >= 0),
    CONSTRAINT tool_calls_schema_hash_lower_hex
        CHECK (schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT tool_calls_args_hash_lower_hex
        CHECK (args_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT tool_calls_effect_known
        CHECK (effect IN ('read', 'write', 'execute', 'network', 'credential')),
    CONSTRAINT tool_calls_idempotency_known
        CHECK (idempotency IN ('idempotent', 'keyed', 'non_idempotent')),
    CONSTRAINT tool_calls_idempotency_key_nonempty
        CHECK (idempotency_key IS NULL OR idempotency_key <> ''),
    CONSTRAINT tool_calls_approval_class_known
        CHECK (approval_class IN ('not_required', 'once_per_run', 'every_call'))
);

CREATE TABLE public.tool_attempts (
    tool_call_id text NOT NULL,
    attempt_seq bigint NOT NULL,
    attempt_id text NOT NULL,
    capability_id text,
    status text NOT NULL,
    commit_state text,
    output_bytes bigint,
    duration_ms bigint,
    error_code text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tool_attempts_pkey PRIMARY KEY (tool_call_id, attempt_seq),
    CONSTRAINT tool_attempts_attempt_id_key UNIQUE (attempt_id),
    CONSTRAINT tool_attempts_capability_id_key UNIQUE (capability_id),
    CONSTRAINT tool_attempts_tool_call_id_fkey
        FOREIGN KEY (tool_call_id) REFERENCES public.tool_calls(tool_call_id) ON DELETE CASCADE,
    CONSTRAINT tool_attempts_attempt_seq_nonnegative CHECK (attempt_seq >= 0),
    CONSTRAINT tool_attempts_status_known CHECK (
        status IN (
            'decision_recorded',
            'executing',
            'completed',
            'reconciliation_required',
            'aborted'
        )
    ),
    CONSTRAINT tool_attempts_commit_state_known
        CHECK (commit_state IS NULL OR commit_state IN ('committed', 'not_committed', 'unknown')),
    CONSTRAINT tool_attempts_output_bytes_u32
        CHECK (output_bytes IS NULL OR output_bytes BETWEEN 0 AND 4294967295),
    CONSTRAINT tool_attempts_duration_nonnegative
        CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT tool_attempts_time_order
        CHECK (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at)),
    CONSTRAINT tool_attempts_reconciliation_is_unknown CHECK (
        status <> 'reconciliation_required' OR commit_state = 'unknown'
    )
);

CREATE INDEX tool_attempts_status_idx
    ON public.tool_attempts USING btree (status, created_at);
