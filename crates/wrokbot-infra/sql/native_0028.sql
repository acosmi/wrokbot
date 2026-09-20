-- Native 0028: durable actor-scoped AG-UI interrupt/resume state.
-- Expand-only: remote descriptors are presentation data, never grants or tool outcomes.

CREATE TABLE public.remote_agent_interrupts (
    request_id text NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    thread_id text NOT NULL,
    run_id text NOT NULL,
    actor_id text NOT NULL,
    bot_id text NOT NULL,
    auth_generation bigint NOT NULL,
    protocol_run_id text NOT NULL,
    interrupt_id text NOT NULL,
    position smallint NOT NULL,
    descriptor jsonb,
    state text DEFAULT 'pending' NOT NULL,
    response_status text,
    response_payload jsonb,
    resume_protocol_run_id text,
    requested_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT remote_agent_interrupts_pkey PRIMARY KEY (request_id),
    CONSTRAINT remote_agent_interrupts_remote_key
        UNIQUE (run_id, protocol_run_id, interrupt_id),
    CONSTRAINT remote_agent_interrupts_position_key
        UNIQUE (run_id, protocol_run_id, position),
    CONSTRAINT remote_agent_interrupts_thread_id_fkey
        FOREIGN KEY (thread_id) REFERENCES public.threads(thread_id) ON DELETE CASCADE,
    CONSTRAINT remote_agent_interrupts_run_id_fkey
        FOREIGN KEY (run_id) REFERENCES public.runs(run_id) ON DELETE CASCADE,
    CONSTRAINT remote_agent_interrupts_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT remote_agent_interrupts_bot_id_fkey
        FOREIGN KEY (bot_id) REFERENCES public.agents(id) ON DELETE CASCADE,
    CONSTRAINT remote_agent_interrupts_resolved_by_fkey
        FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT remote_agent_interrupts_identity_shape CHECK (
        request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND deployment_id <> '' AND tenant_id <> '' AND thread_id <> '' AND run_id <> ''
        AND actor_id <> '' AND bot_id <> ''
        AND protocol_run_id <> '' AND octet_length(protocol_run_id) <= 1024
        AND interrupt_id <> '' AND octet_length(interrupt_id) <= 256
        AND position >= 0 AND position < 256 AND auth_generation >= 0
    ),
    CONSTRAINT remote_agent_interrupts_descriptor_shape CHECK (
        descriptor IS NULL OR (
            jsonb_typeof(descriptor) = 'object'
            AND descriptor ?& ARRAY['id','reason']::text[]
            AND descriptor->>'id' = interrupt_id
            AND jsonb_typeof(descriptor->'id') = 'string'
            AND jsonb_typeof(descriptor->'reason') = 'string'
            AND (descriptor - ARRAY[
                'id','reason','message','toolCallId','responseSchema','expiresAt','metadata'
            ]::text[]) = '{}'::jsonb
            AND (NOT descriptor ? 'message' OR jsonb_typeof(descriptor->'message') = 'string')
            AND (NOT descriptor ? 'toolCallId' OR jsonb_typeof(descriptor->'toolCallId') = 'string')
            AND (NOT descriptor ? 'responseSchema' OR jsonb_typeof(descriptor->'responseSchema') = 'object')
            AND (NOT descriptor ? 'expiresAt' OR jsonb_typeof(descriptor->'expiresAt') = 'string')
            AND (NOT descriptor ? 'metadata' OR jsonb_typeof(descriptor->'metadata') = 'object')
        )
    ),
    CONSTRAINT remote_agent_interrupts_state_known
        CHECK (state IN ('pending','resolved','cancelled','expired','retired')),
    CONSTRAINT remote_agent_interrupts_response_status_known
        CHECK (response_status IS NULL OR response_status IN ('resolved','cancelled')),
    CONSTRAINT remote_agent_interrupts_state_shape CHECK (
        (state = 'pending' AND descriptor IS NOT NULL AND response_status IS NULL
            AND response_payload IS NULL AND resolved_at IS NULL AND resolved_by IS NULL
            AND resume_protocol_run_id IS NULL)
        OR (state = 'resolved' AND descriptor IS NOT NULL AND response_status = 'resolved'
            AND resolved_at IS NOT NULL AND resolved_by = actor_id)
        OR (state = 'cancelled' AND descriptor IS NOT NULL AND response_status = 'cancelled'
            AND response_payload IS NULL AND resolved_at IS NOT NULL AND resolved_by = actor_id)
        OR (state = 'expired' AND descriptor IS NOT NULL AND response_status = 'cancelled'
            AND response_payload IS NULL AND resolved_at IS NOT NULL AND resolved_by IS NULL)
        OR (state = 'retired' AND descriptor IS NULL AND response_payload IS NULL
            AND resolved_at IS NOT NULL AND resolved_by IS NULL)
    ),
    CONSTRAINT remote_agent_interrupts_resume_shape CHECK (
        resume_protocol_run_id IS NULL OR (
            resume_protocol_run_id <> ''
            AND octet_length(resume_protocol_run_id) <= 1024
            AND resume_protocol_run_id <> protocol_run_id
            AND state IN ('resolved','cancelled','expired')
        )
    ),
    CONSTRAINT remote_agent_interrupts_time_shape CHECK (
        expires_at > requested_at AND updated_at >= created_at
        AND requested_at >= created_at
        AND (resolved_at IS NULL OR resolved_at >= requested_at)
    )
);

CREATE INDEX remote_agent_interrupts_actor_pending_idx
    ON public.remote_agent_interrupts USING btree
       (actor_id, requested_at, request_id)
    WHERE state = 'pending';

CREATE INDEX remote_agent_interrupts_run_batch_idx
    ON public.remote_agent_interrupts USING btree
       (run_id, protocol_run_id, position);
