-- OpenBot native schema 0016：native thread / run / realtime / memory base。
--
-- 只允许 expand（v3 §14.3）：十张新表、索引与 tool_calls→runs 的 NOT VALID FK。
-- 历史 tool_calls 可能早于 native runs，故外键先只约束新写；导入/backfill 完成后另批 VALIDATE。

CREATE TABLE public.threads (
    thread_id text NOT NULL,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    created_by text NOT NULL,
    anchor_kind text NOT NULL,
    anchor_id text NOT NULL,
    title text,
    status text DEFAULT 'active' NOT NULL,
    next_message_seq bigint DEFAULT 0 NOT NULL,
    next_event_seq bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT threads_pkey PRIMARY KEY (thread_id),
    CONSTRAINT threads_identity_nonempty CHECK (
        tenant_id <> '' AND deployment_id <> '' AND created_by <> '' AND anchor_id <> ''
    ),
    CONSTRAINT threads_anchor_kind_known CHECK (anchor_kind IN ('channel', 'direct_bot')),
    CONSTRAINT threads_status_known CHECK (status IN ('active', 'archived', 'deleted')),
    CONSTRAINT threads_next_message_seq_nonnegative CHECK (next_message_seq >= 0),
    CONSTRAINT threads_next_event_seq_nonnegative CHECK (next_event_seq >= 0),
    CONSTRAINT threads_deleted_shape CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    CONSTRAINT threads_time_order CHECK (
        updated_at >= created_at AND (deleted_at IS NULL OR deleted_at >= created_at)
    )
);

CREATE INDEX threads_tenant_created_idx
    ON public.threads USING btree (tenant_id, created_at DESC, thread_id);

CREATE INDEX threads_anchor_idx
    ON public.threads USING btree (tenant_id, anchor_kind, anchor_id, created_at DESC);

CREATE TABLE public.thread_memberships (
    thread_id text NOT NULL,
    user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT thread_memberships_pkey PRIMARY KEY (thread_id, user_id),
    CONSTRAINT thread_memberships_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT thread_memberships_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

CREATE INDEX thread_memberships_user_id_idx
    ON public.thread_memberships USING btree (user_id, thread_id);

CREATE TABLE public.messages (
    message_id text NOT NULL,
    thread_id text NOT NULL,
    seq bigint NOT NULL,
    role text NOT NULL,
    content jsonb NOT NULL,
    search_text text NOT NULL,
    run_id text,
    actor_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT messages_pkey PRIMARY KEY (message_id),
    CONSTRAINT messages_thread_seq_key UNIQUE (thread_id, seq),
    CONSTRAINT messages_thread_message_key UNIQUE (thread_id, message_id),
    CONSTRAINT messages_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT messages_seq_nonnegative CHECK (seq >= 0),
    CONSTRAINT messages_role_known
        CHECK (role IN ('user', 'assistant', 'system', 'tool', 'summary')),
    CONSTRAINT messages_content_not_json_null CHECK (content <> 'null'::jsonb)
);

CREATE INDEX messages_search_idx
    ON public.messages USING gin (to_tsvector('simple', search_text));

CREATE TABLE public.runs (
    run_id text NOT NULL,
    thread_id text NOT NULL,
    bot_id text NOT NULL,
    actor_id text NOT NULL,
    foreground boolean NOT NULL,
    status text DEFAULT 'queued' NOT NULL,
    fencing_token bigint NOT NULL,
    next_event_seq bigint DEFAULT 0 NOT NULL,
    terminal_event_seq bigint,
    error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    CONSTRAINT runs_pkey PRIMARY KEY (run_id),
    CONSTRAINT runs_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT runs_identity_nonempty CHECK (bot_id <> '' AND actor_id <> ''),
    CONSTRAINT runs_status_known CHECK (
        status IN (
            'queued', 'running', 'completed', 'failed', 'cancelled',
            'reconciliation_required'
        )
    ),
    CONSTRAINT runs_fencing_token_nonnegative CHECK (fencing_token >= 0),
    CONSTRAINT runs_next_event_seq_nonnegative CHECK (next_event_seq >= 0),
    CONSTRAINT runs_terminal_event_seq_nonnegative
        CHECK (terminal_event_seq IS NULL OR terminal_event_seq >= 0),
    CONSTRAINT runs_terminal_shape CHECK (
        (
            status IN ('queued', 'running')
            AND terminal_event_seq IS NULL
            AND finished_at IS NULL
        )
        OR (
            status IN ('completed', 'failed', 'cancelled', 'reconciliation_required')
            AND terminal_event_seq IS NOT NULL
            AND finished_at IS NOT NULL
        )
    ),
    CONSTRAINT runs_started_shape CHECK (
        (status = 'queued' AND started_at IS NULL)
        OR status = 'cancelled'
        OR (
            status IN ('running', 'completed', 'failed', 'reconciliation_required')
            AND started_at IS NOT NULL
        )
    ),
    CONSTRAINT runs_error_shape CHECK (
        status NOT IN ('failed', 'reconciliation_required') OR error_code IS NOT NULL
    ),
    CONSTRAINT runs_time_order CHECK (
        (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR finished_at >= created_at)
        AND (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
    )
);

CREATE UNIQUE INDEX runs_one_foreground_active_per_thread
    ON public.runs USING btree (thread_id)
    WHERE foreground AND status IN ('queued', 'running', 'reconciliation_required');

CREATE INDEX runs_thread_created_idx
    ON public.runs USING btree (thread_id, created_at DESC, run_id);

CREATE TABLE public.run_events (
    run_id text NOT NULL,
    seq bigint NOT NULL,
    thread_id text NOT NULL,
    event_seq bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    terminal boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT run_events_pkey PRIMARY KEY (run_id, seq),
    CONSTRAINT run_events_thread_event_seq_key UNIQUE (thread_id, event_seq),
    CONSTRAINT run_events_run_id_fkey
        FOREIGN KEY (run_id) REFERENCES public.runs(run_id) ON DELETE CASCADE,
    CONSTRAINT run_events_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT run_events_seq_nonnegative CHECK (seq >= 0),
    CONSTRAINT run_events_event_seq_nonnegative CHECK (event_seq >= 0),
    CONSTRAINT run_events_type_known CHECK (
        event_type IN (
            'started', 'semantic_chunk', 'checkpoint', 'completed', 'failed', 'cancelled',
            'reconciliation_required'
        )
    ),
    CONSTRAINT run_events_terminal_shape CHECK (
        terminal = (event_type IN ('completed', 'failed', 'cancelled', 'reconciliation_required'))
    ),
    CONSTRAINT run_events_payload_not_json_null CHECK (payload <> 'null'::jsonb)
);

CREATE UNIQUE INDEX run_events_one_terminal_per_run
    ON public.run_events USING btree (run_id)
    WHERE terminal;

CREATE TABLE public.thread_leases (
    thread_id text NOT NULL,
    owner_id text NOT NULL,
    fencing_token bigint NOT NULL,
    acquired_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT thread_leases_pkey PRIMARY KEY (thread_id),
    CONSTRAINT thread_leases_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT thread_leases_owner_nonempty CHECK (owner_id <> ''),
    CONSTRAINT thread_leases_fencing_nonnegative CHECK (fencing_token >= 0),
    CONSTRAINT thread_leases_expiry_after_acquire CHECK (expires_at > acquired_at),
    CONSTRAINT thread_leases_updated_after_acquire CHECK (updated_at >= acquired_at)
);

CREATE INDEX thread_leases_expiry_idx
    ON public.thread_leases USING btree (expires_at, thread_id);

CREATE TABLE public.outbox (
    outbox_id text NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    seq bigint NOT NULL,
    destination text NOT NULL,
    delivery_class text NOT NULL,
    payload jsonb NOT NULL,
    status text DEFAULT 'pending' NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_by text,
    claim_expires_at timestamp with time zone,
    delivered_at timestamp with time zone,
    last_error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT outbox_pkey PRIMARY KEY (outbox_id),
    CONSTRAINT outbox_delivery_key UNIQUE (aggregate_id, seq, destination),
    CONSTRAINT outbox_identity_nonempty CHECK (
        aggregate_kind <> '' AND aggregate_id <> '' AND destination <> ''
    ),
    CONSTRAINT outbox_seq_nonnegative CHECK (seq >= 0),
    CONSTRAINT outbox_delivery_class_replay_safe
        CHECK (delivery_class IN ('internal', 'idempotent_external')),
    CONSTRAINT outbox_status_known
        CHECK (status IN ('pending', 'delivering', 'delivered', 'dead_letter')),
    CONSTRAINT outbox_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT outbox_claim_shape CHECK (
        (status = 'delivering' AND claimed_by IS NOT NULL AND claim_expires_at IS NOT NULL)
        OR (status <> 'delivering' AND claimed_by IS NULL AND claim_expires_at IS NULL)
    ),
    CONSTRAINT outbox_delivered_shape CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CONSTRAINT outbox_time_order CHECK (
        updated_at >= created_at
        AND available_at >= created_at
        AND (claim_expires_at IS NULL OR claim_expires_at > updated_at)
        AND (delivered_at IS NULL OR delivered_at >= created_at)
    )
);

CREATE INDEX outbox_ready_idx
    ON public.outbox USING btree (status, available_at, outbox_id);

CREATE INDEX outbox_claim_expiry_idx
    ON public.outbox USING btree (claim_expires_at, outbox_id)
    WHERE status = 'delivering';

CREATE TABLE public.memories (
    memory_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL,
    scope_kind text NOT NULL,
    scope_id text,
    memory_kind text NOT NULL,
    content text,
    tags text[] DEFAULT '{}' NOT NULL,
    sensitivity text NOT NULL,
    source_thread_id text,
    source_message_id text,
    origin text NOT NULL,
    created_by text NOT NULL,
    supersedes_id text,
    status text DEFAULT 'active' NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT memories_pkey PRIMARY KEY (memory_id),
    CONSTRAINT memories_owner_user_id_fkey
        FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT memories_source_message_fkey
        FOREIGN KEY (source_thread_id, source_message_id)
        REFERENCES public.messages(thread_id, message_id) ON DELETE RESTRICT,
    CONSTRAINT memories_supersedes_id_fkey
        FOREIGN KEY (supersedes_id) REFERENCES public.memories(memory_id) ON DELETE SET NULL,
    CONSTRAINT memories_identity_nonempty CHECK (
        tenant_id <> '' AND owner_user_id <> '' AND created_by <> ''
    ),
    CONSTRAINT memories_scope_shape CHECK (
        (scope_kind = 'user' AND scope_id IS NULL)
        OR (scope_kind IN ('bot', 'thread') AND scope_id IS NOT NULL AND scope_id <> '')
    ),
    CONSTRAINT memories_kind_known CHECK (memory_kind IN ('preference', 'fact')),
    CONSTRAINT memories_sensitivity_known CHECK (sensitivity IN ('normal', 'sensitive')),
    CONSTRAINT memories_origin_known
        CHECK (origin IN ('user_action', 'remember_tool', 'verified_import')),
    CONSTRAINT memories_status_known
        CHECK (status IN ('active', 'superseded', 'forbidden', 'deleted')),
    CONSTRAINT memories_content_shape CHECK (
        (status IN ('active', 'superseded') AND content IS NOT NULL AND content <> '')
        OR (status IN ('forbidden', 'deleted') AND content IS NULL)
    ),
    CONSTRAINT memories_source_pair CHECK (
        (source_thread_id IS NULL) = (source_message_id IS NULL)
    ),
    CONSTRAINT memories_fact_source_required CHECK (
        memory_kind <> 'fact' OR source_message_id IS NOT NULL
    ),
    CONSTRAINT memories_import_source_required CHECK (
        origin <> 'verified_import' OR source_message_id IS NOT NULL
    ),
    CONSTRAINT memories_tags_no_null CHECK (array_position(tags, NULL) IS NULL),
    CONSTRAINT memories_expiry_after_create CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT memories_updated_after_create CHECK (updated_at >= created_at),
    CONSTRAINT memories_no_self_supersede CHECK (supersedes_id IS NULL OR supersedes_id <> memory_id)
);

CREATE INDEX memories_recall_idx
    ON public.memories USING btree (
        tenant_id, owner_user_id, scope_kind, scope_id, created_at DESC, memory_id
    )
    WHERE status = 'active';

CREATE INDEX memories_tags_idx ON public.memories USING gin (tags);

CREATE INDEX memories_search_idx
    ON public.memories USING gin (to_tsvector('simple', COALESCE(content, '')));

CREATE TABLE public.memory_events (
    memory_id text NOT NULL,
    seq bigint NOT NULL,
    event_type text NOT NULL,
    actor_id text NOT NULL,
    metadata jsonb DEFAULT '{}' NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT memory_events_pkey PRIMARY KEY (memory_id, seq),
    CONSTRAINT memory_events_memory_id_fkey
        FOREIGN KEY (memory_id) REFERENCES public.memories(memory_id) ON DELETE CASCADE,
    CONSTRAINT memory_events_seq_nonnegative CHECK (seq >= 0),
    CONSTRAINT memory_events_actor_nonempty CHECK (actor_id <> ''),
    CONSTRAINT memory_events_type_known
        CHECK (event_type IN ('create', 'supersede', 'correct', 'forbid', 'delete')),
    CONSTRAINT memory_events_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE public.intelligence_import_cursors (
    bundle_id text NOT NULL,
    aggregate_kind text NOT NULL,
    deployment_id text NOT NULL,
    cursor text NOT NULL,
    last_hash text NOT NULL,
    imported_count bigint NOT NULL,
    status text NOT NULL,
    provenance jsonb DEFAULT '{}' NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT intelligence_import_cursors_pkey PRIMARY KEY (bundle_id, aggregate_kind),
    CONSTRAINT intelligence_import_cursors_identity_nonempty CHECK (
        bundle_id <> '' AND deployment_id <> '' AND cursor <> ''
    ),
    CONSTRAINT intelligence_import_cursors_kind_known
        CHECK (aggregate_kind IN ('thread', 'message', 'run_event', 'memory')),
    CONSTRAINT intelligence_import_cursors_hash_lower_hex
        CHECK (last_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT intelligence_import_cursors_count_nonnegative CHECK (imported_count >= 0),
    CONSTRAINT intelligence_import_cursors_status_known
        CHECK (status IN ('running', 'completed', 'failed')),
    CONSTRAINT intelligence_import_cursors_provenance_object
        CHECK (jsonb_typeof(provenance) = 'object')
);

ALTER TABLE ONLY public.tool_calls
    ADD CONSTRAINT tool_calls_run_id_fkey
    FOREIGN KEY (run_id) REFERENCES public.runs(run_id) ON DELETE RESTRICT NOT VALID;
