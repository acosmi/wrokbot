-- Personal custom-model authority is separate from deployment-admin credentials.
CREATE TABLE public.model_connections (
    id uuid PRIMARY KEY,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 100),
    protocol text NOT NULL CHECK (protocol IN ('openai_chat_completions','openai_responses','anthropic_messages')),
    endpoint text NOT NULL CHECK (octet_length(endpoint) BETWEEN 1 AND 2048),
    model text NOT NULL CHECK (octet_length(model) BETWEEN 1 AND 512),
    enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    current_secret_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    UNIQUE(id,deployment_id,tenant_id,owner_user_id)
);
CREATE INDEX model_connections_owner_active ON public.model_connections(deployment_id,tenant_id,owner_user_id,id) WHERE deleted_at IS NULL;

CREATE TABLE public.model_connection_secrets (
    id uuid PRIMARY KEY,
    connection_id uuid NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL,
    encrypted_value text NOT NULL,
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    UNIQUE(id,connection_id,deployment_id,tenant_id,owner_user_id),
    FOREIGN KEY(connection_id,deployment_id,tenant_id,owner_user_id)
      REFERENCES public.model_connections(id,deployment_id,tenant_id,owner_user_id)
      ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE public.model_connections ADD CONSTRAINT model_connections_current_secret_scope
    FOREIGN KEY(current_secret_id,id,deployment_id,tenant_id,owner_user_id)
    REFERENCES public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id)
    DEFERRABLE INITIALLY DEFERRED;
