-- R395: one durable refresh-token send per operation; tombstones survive reconnect/removal.
-- No credential, user or server cascade can erase an unresolved upstream consumption fact.
CREATE TABLE public.oauth_refresh_operations (
    operation_id uuid PRIMARY KEY,
    credential_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    actor_id text NOT NULL CHECK (actor_id <> ''),
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    server_id text NOT NULL CHECK (server_id <> ''),
    client_credential_id uuid NOT NULL,
    server_generation bigint NOT NULL CHECK (server_generation >= 0),
    server_updated_at timestamptz NOT NULL,
    client_updated_at timestamptz NOT NULL,
    resource text NOT NULL CHECK (octet_length(resource) BETWEEN 1 AND 8192),
    transport text NOT NULL CHECK (transport IN ('mcp','google_drive_rest')),
    egress_allow_cidrs text[] NOT NULL,
    granted_scope text NOT NULL CHECK (octet_length(granted_scope) <= 16384),
    state text NOT NULL CHECK (state IN ('pending','committed','unknown','auth_required')),
    admitted_at timestamptz,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (credential_id,generation),
    CONSTRAINT oauth_refresh_operations_state_shape CHECK (
        (state = 'pending' AND completed_at IS NULL)
        OR (state IN ('committed','unknown','auth_required') AND admitted_at IS NOT NULL
            AND completed_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX oauth_refresh_operations_unresolved
    ON public.oauth_refresh_operations(credential_id) WHERE state <> 'committed';
