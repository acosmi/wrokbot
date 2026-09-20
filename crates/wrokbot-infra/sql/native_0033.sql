CREATE TABLE public.sdk_gateway_connections (
    id uuid PRIMARY KEY,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 100),
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 256),
    account_id text NOT NULL CHECK (octet_length(account_id) BETWEEN 1 AND 256),
    organization_id text CHECK (organization_id IS NULL OR octet_length(organization_id) BETWEEN 1 AND 256),
    auth_contract_version smallint NOT NULL CHECK (auth_contract_version = 2),
    error_contract_version smallint NOT NULL CHECK (error_contract_version = 1),
    enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    credential_generation bigint NOT NULL CHECK (credential_generation > 0),
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    state text NOT NULL CHECK (state IN ('ready','missing','rotation_pending','auth_required')),
    current_secret_id uuid,
    pending_operation_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    UNIQUE(id,deployment_id,tenant_id,owner_user_id),
    CONSTRAINT sdk_gateway_connections_state_shape CHECK (
        (state = 'ready' AND current_secret_id IS NOT NULL AND pending_operation_id IS NULL)
        OR (state = 'rotation_pending' AND current_secret_id IS NOT NULL AND pending_operation_id IS NOT NULL)
        OR (state IN ('missing','auth_required') AND current_secret_id IS NULL AND pending_operation_id IS NULL)
    )
);
CREATE INDEX sdk_gateway_connections_owner_active
    ON public.sdk_gateway_connections(deployment_id,tenant_id,owner_user_id,id)
    WHERE deleted_at IS NULL;

CREATE TABLE public.sdk_gateway_secrets (
    id uuid PRIMARY KEY,
    connection_id uuid NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL,
    credential_generation bigint NOT NULL CHECK (credential_generation > 0),
    encrypted_value text NOT NULL CHECK (octet_length(encrypted_value) BETWEEN 1 AND 524288),
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    UNIQUE(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation),
    FOREIGN KEY(connection_id,deployment_id,tenant_id,owner_user_id)
      REFERENCES public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id)
      ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.sdk_gateway_operations (
    id uuid PRIMARY KEY,
    connection_id uuid NOT NULL,
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_user_id text NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    from_generation bigint NOT NULL CHECK (from_generation > 0),
    to_generation bigint NOT NULL CHECK (to_generation > from_generation AND to_generation - from_generation = 1),
    state text NOT NULL CHECK (state IN ('pending','staged','committed','auth_required','cleared')),
    candidate_secret_id uuid,
    token_admitted_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE(id,connection_id,deployment_id,tenant_id,owner_user_id),
    FOREIGN KEY(connection_id,deployment_id,tenant_id,owner_user_id)
      REFERENCES public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id)
      ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(candidate_secret_id,connection_id,deployment_id,tenant_id,owner_user_id,to_generation)
      REFERENCES public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT sdk_gateway_operations_state_shape CHECK (
        (state = 'pending' AND candidate_secret_id IS NULL AND completed_at IS NULL)
        OR (state = 'staged' AND candidate_secret_id IS NOT NULL AND token_admitted_at IS NOT NULL AND completed_at IS NULL)
        OR (state = 'committed' AND candidate_secret_id IS NOT NULL AND token_admitted_at IS NOT NULL AND completed_at IS NOT NULL)
        OR (state IN ('auth_required','cleared') AND completed_at IS NOT NULL)
    )
);

ALTER TABLE public.sdk_gateway_connections
    ADD CONSTRAINT sdk_gateway_connections_current_secret_scope
    FOREIGN KEY(current_secret_id,id,deployment_id,tenant_id,owner_user_id,credential_generation)
    REFERENCES public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.sdk_gateway_connections
    ADD CONSTRAINT sdk_gateway_connections_pending_operation_scope
    FOREIGN KEY(pending_operation_id,id,deployment_id,tenant_id,owner_user_id)
    REFERENCES public.sdk_gateway_operations(id,connection_id,deployment_id,tenant_id,owner_user_id)
    DEFERRABLE INITIALLY DEFERRED;
