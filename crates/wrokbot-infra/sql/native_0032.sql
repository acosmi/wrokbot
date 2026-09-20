CREATE TABLE openbot_internal.desktop_vault_canaries (
    dataset_id text NOT NULL CHECK (dataset_id ~ '^[0-9a-f]{32}$'),
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 256),
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 256),
    key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{32}$'),
    key_version integer NOT NULL CHECK (key_version > 0),
    canary_schema smallint NOT NULL CHECK (canary_schema = 1),
    encrypted_canary text NOT NULL CHECK (octet_length(encrypted_canary) BETWEEN 1 AND 4096),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dataset_id, key_version),
    UNIQUE (deployment_id, tenant_id, key_version),
    UNIQUE (dataset_id, key_id)
);
