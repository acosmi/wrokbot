-- Native 0017: MCP catalog generation, stale-grant state, and cross-replica tool-call sequence.
-- Expand-only: legacy NULL rows remain readable until the first authoritative refresh.

ALTER TABLE public.runs
    ADD COLUMN next_tool_call_seq bigint;

ALTER TABLE public.runs
    ADD CONSTRAINT runs_next_tool_call_seq_nonnegative
    CHECK (next_tool_call_seq IS NULL OR next_tool_call_seq >= 0);

ALTER TABLE public.mcp_servers
    ADD COLUMN catalog_generation bigint,
    ADD COLUMN catalog_hash text,
    ADD COLUMN catalog_transport_fingerprint text;

ALTER TABLE public.mcp_servers
    ADD CONSTRAINT mcp_servers_catalog_generation_nonnegative
    CHECK (catalog_generation IS NULL OR catalog_generation >= 0),
    ADD CONSTRAINT mcp_servers_catalog_hash_lower_hex
    CHECK (catalog_hash IS NULL OR catalog_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT mcp_servers_transport_fingerprint_lower_hex
    CHECK (catalog_transport_fingerprint IS NULL OR catalog_transport_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT mcp_servers_catalog_pair
    CHECK (
        (catalog_generation IS NULL AND catalog_hash IS NULL
         AND catalog_transport_fingerprint IS NULL)
        OR
        (catalog_generation IS NOT NULL AND catalog_hash IS NOT NULL
         AND catalog_transport_fingerprint IS NOT NULL)
    );

ALTER TABLE public.mcp_tools
    ADD COLUMN schema_hash text,
    ADD COLUMN effect text,
    ADD COLUMN catalog_generation bigint,
    ADD COLUMN first_seen_at timestamp with time zone,
    ADD COLUMN last_seen_at timestamp with time zone,
    ADD COLUMN available boolean;

ALTER TABLE public.mcp_tools
    ADD CONSTRAINT mcp_tools_schema_hash_lower_hex
    CHECK (schema_hash IS NULL OR schema_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT mcp_tools_effect_domain
    CHECK (effect IS NULL OR effect IN ('read','write','execute','network','credential')),
    ADD CONSTRAINT mcp_tools_catalog_generation_nonnegative
    CHECK (catalog_generation IS NULL OR catalog_generation >= 0),
    ADD CONSTRAINT mcp_tools_seen_order
    CHECK (first_seen_at IS NULL OR last_seen_at IS NULL OR first_seen_at <= last_seen_at),
    ADD CONSTRAINT mcp_tools_catalog_projection_complete
    CHECK (
        (schema_hash IS NULL AND effect IS NULL AND catalog_generation IS NULL
         AND first_seen_at IS NULL AND last_seen_at IS NULL AND available IS NULL)
        OR
        (schema_hash IS NOT NULL AND effect IS NOT NULL AND catalog_generation IS NOT NULL
         AND first_seen_at IS NOT NULL AND last_seen_at IS NOT NULL AND available IS NOT NULL)
    );

ALTER TABLE public.plugin_grants
    ADD COLUMN state text,
    ADD COLUMN catalog_generation bigint,
    ADD COLUMN schema_hash text,
    ADD COLUMN effect text,
    ADD COLUMN transport_fingerprint text;

ALTER TABLE public.plugin_grants
    ADD CONSTRAINT plugin_grants_state_domain
    CHECK (state IS NULL OR state IN ('active','suspended_missing')),
    ADD CONSTRAINT plugin_grants_catalog_generation_nonnegative
    CHECK (catalog_generation IS NULL OR catalog_generation >= 0),
    ADD CONSTRAINT plugin_grants_schema_hash_lower_hex
    CHECK (schema_hash IS NULL OR schema_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT plugin_grants_effect_domain
    CHECK (effect IS NULL OR effect IN ('read','write','execute','network','credential')),
    ADD CONSTRAINT plugin_grants_transport_fingerprint_lower_hex
    CHECK (transport_fingerprint IS NULL OR transport_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT plugin_grants_catalog_projection_complete
    CHECK (
        (state IS NULL AND catalog_generation IS NULL AND schema_hash IS NULL AND effect IS NULL
         AND transport_fingerprint IS NULL)
        OR
        (state IS NOT NULL AND catalog_generation IS NOT NULL AND schema_hash IS NOT NULL
         AND effect IS NOT NULL AND transport_fingerprint IS NOT NULL)
    );
