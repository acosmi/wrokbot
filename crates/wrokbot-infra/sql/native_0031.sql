-- Immutable custom selection facts; source-object deletion must not erase routing intent.
CREATE TABLE public.run_model_selections (
    run_id text PRIMARY KEY REFERENCES public.runs(run_id) ON DELETE CASCADE,
    deployment_id text NOT NULL CHECK (deployment_id <> ''),
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    owner_user_id text NOT NULL CHECK (owner_user_id <> ''),
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    connection_id uuid NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    secret_id uuid NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('openai_chat_completions','openai_responses','anthropic_messages')),
    endpoint text NOT NULL CHECK (octet_length(endpoint) BETWEEN 1 AND 2048),
    model text NOT NULL CHECK (octet_length(model) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL
);
