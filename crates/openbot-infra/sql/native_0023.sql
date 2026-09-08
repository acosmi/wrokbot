-- Native 0023: durable human answers for compiled decision components.
-- Expand-only: this is deliberately separate from acting tool_approvals.

CREATE TABLE public.component_human_decisions (
    decision_id text NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    thread_id text NOT NULL,
    run_id text NOT NULL,
    actor_id text NOT NULL,
    bot_id text NOT NULL,
    auth_generation bigint NOT NULL,
    provider_call_id text NOT NULL,
    component_name text NOT NULL,
    arguments jsonb NOT NULL,
    arguments_hash text NOT NULL,
    state text DEFAULT 'pending' NOT NULL,
    answer jsonb,
    requested_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT component_human_decisions_pkey PRIMARY KEY (decision_id),
    CONSTRAINT component_human_decisions_run_call_key UNIQUE (run_id, provider_call_id),
    CONSTRAINT component_human_decisions_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_run_id_fkey
        FOREIGN KEY (run_id) REFERENCES public.runs(run_id) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_bot_id_fkey
        FOREIGN KEY (bot_id) REFERENCES public.agents(id) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_component_name_fkey
        FOREIGN KEY (component_name) REFERENCES public.components(name) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_resolved_by_fkey
        FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT component_human_decisions_identity_nonempty CHECK (
        decision_id <> '' AND deployment_id <> '' AND tenant_id <> '' AND thread_id <> ''
        AND run_id <> '' AND actor_id <> '' AND bot_id <> '' AND provider_call_id <> ''
    ),
    CONSTRAINT component_human_decisions_auth_generation_nonnegative
        CHECK (auth_generation >= 0),
    CONSTRAINT component_human_decisions_component_known
        CHECK (component_name IN ('askApproval','askChoice')),
    CONSTRAINT component_human_decisions_arguments_object
        CHECK (jsonb_typeof(arguments) = 'object'),
    CONSTRAINT component_human_decisions_arguments_hash_lower_hex
        CHECK (arguments_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT component_human_decisions_state_known
        CHECK (state IN ('pending','answered','cancelled','expired')),
    CONSTRAINT component_human_decisions_answer_shape CHECK (
        answer IS NULL OR (
            jsonb_typeof(answer) = 'object' AND (
                (
                    component_name = 'askApproval'
                    AND answer ? 'decision'
                    AND answer->>'decision' IN ('approved','declined')
                    AND (answer - ARRAY['decision','note']::text[]) = '{}'::jsonb
                    AND (
                        NOT answer ? 'note'
                        OR (jsonb_typeof(answer->'note') = 'string' AND answer->>'note' <> '')
                    )
                ) OR (
                    component_name = 'askChoice'
                    AND answer ?& ARRAY['choice','label']::text[]
                    AND jsonb_typeof(answer->'choice') = 'string'
                    AND answer->>'choice' <> ''
                    AND jsonb_typeof(answer->'label') = 'string'
                    AND answer->>'label' <> ''
                    AND (answer - ARRAY['choice','label']::text[]) = '{}'::jsonb
                )
            )
        )
    ),
    CONSTRAINT component_human_decisions_resolution_shape CHECK (
        (
            state = 'pending' AND answer IS NULL AND resolved_at IS NULL AND resolved_by IS NULL
        ) OR (
            state = 'answered' AND answer IS NOT NULL AND resolved_at IS NOT NULL
            AND resolved_by = actor_id
        ) OR (
            state IN ('cancelled','expired') AND answer IS NULL AND resolved_at IS NOT NULL
            AND resolved_by IS NULL
        )
    ),
    CONSTRAINT component_human_decisions_expiry_after_request
        CHECK (expires_at > requested_at),
    CONSTRAINT component_human_decisions_time_order CHECK (
        updated_at >= created_at AND requested_at >= created_at
        AND (resolved_at IS NULL OR resolved_at >= requested_at)
    )
);

CREATE INDEX component_human_decisions_actor_pending_idx
    ON public.component_human_decisions USING btree (actor_id, requested_at, decision_id)
    WHERE state = 'pending';

CREATE INDEX component_human_decisions_run_state_idx
    ON public.component_human_decisions USING btree (run_id, state, requested_at, decision_id);
