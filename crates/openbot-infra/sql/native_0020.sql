-- Native 0020: durable human tool approval requests and decisions.
-- Expand-only: one new table and indexes; no existing object is rewritten.

CREATE TABLE public.tool_approvals (
    approval_id text NOT NULL,
    tool_call_id text NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    thread_id text NOT NULL,
    run_id text NOT NULL,
    actor_id text NOT NULL,
    bot_id text NOT NULL,
    auth_generation bigint NOT NULL,
    tool_name text NOT NULL,
    args_hash text NOT NULL,
    target_kind text NOT NULL,
    target_id text NOT NULL,
    effect text NOT NULL,
    approval_class text NOT NULL,
    computer_generation bigint NOT NULL,
    catalog_generation bigint NOT NULL,
    document_generation bigint,
    policy_version text NOT NULL,
    arguments_summary jsonb,
    change_summary jsonb,
    state text DEFAULT 'pending' NOT NULL,
    requested_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    decided_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tool_approvals_pkey PRIMARY KEY (approval_id),
    CONSTRAINT tool_approvals_tool_call_key UNIQUE (tool_call_id),
    CONSTRAINT tool_approvals_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT tool_approvals_run_id_fkey
        FOREIGN KEY (run_id) REFERENCES public.runs(run_id) ON DELETE CASCADE,
    CONSTRAINT tool_approvals_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT tool_approvals_bot_id_fkey
        FOREIGN KEY (bot_id) REFERENCES public.agents(id) ON DELETE CASCADE,
    CONSTRAINT tool_approvals_decided_by_fkey
        FOREIGN KEY (decided_by) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT tool_approvals_identity_nonempty CHECK (
        approval_id <> '' AND tool_call_id <> '' AND deployment_id <> '' AND tenant_id <> ''
        AND tool_name <> '' AND target_kind <> '' AND target_id <> ''
    ),
    CONSTRAINT tool_approvals_generation_nonnegative CHECK (
        auth_generation >= 0 AND computer_generation >= 0 AND catalog_generation >= 0
        AND (document_generation IS NULL OR document_generation >= 0)
    ),
    CONSTRAINT tool_approvals_args_hash_lower_hex
        CHECK (args_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT tool_approvals_policy_version_lower_hex
        CHECK (policy_version ~ '^[0-9a-f]{64}$'),
    CONSTRAINT tool_approvals_effect_known
        CHECK (effect IN ('write','execute','network','credential')),
    CONSTRAINT tool_approvals_class_known
        CHECK (approval_class IN ('once_per_run','every_call')),
    CONSTRAINT tool_approvals_state_known
        CHECK (state IN ('pending','granted','denied','expired','cancelled')),
    CONSTRAINT tool_approvals_expiry_after_request CHECK (expires_at > requested_at),
    CONSTRAINT tool_approvals_decision_shape CHECK (
        (
            state = 'pending' AND decided_at IS NULL AND decided_by IS NULL
            AND arguments_summary IS NOT NULL
        )
        OR (
            state IN ('granted','denied') AND decided_at IS NOT NULL
            AND decided_by = actor_id AND arguments_summary IS NULL AND change_summary IS NULL
        )
        OR (
            state IN ('expired','cancelled') AND decided_at IS NOT NULL AND decided_by IS NULL
            AND arguments_summary IS NULL AND change_summary IS NULL
        )
    ),
    CONSTRAINT tool_approvals_time_order CHECK (
        updated_at >= created_at AND requested_at >= created_at
        AND (decided_at IS NULL OR decided_at >= requested_at)
    )
);

CREATE INDEX tool_approvals_actor_pending_idx
    ON public.tool_approvals USING btree (actor_id, requested_at, approval_id)
    WHERE state = 'pending';

CREATE INDEX tool_approvals_run_binding_idx
    ON public.tool_approvals USING btree (
        run_id, actor_id, bot_id, tool_name, args_hash, target_kind, target_id, requested_at DESC
    );

ALTER TABLE public.tool_calls
    ADD COLUMN approval_id text;

CREATE INDEX tool_calls_approval_id_idx
    ON public.tool_calls USING btree (approval_id)
    WHERE approval_id IS NOT NULL;
