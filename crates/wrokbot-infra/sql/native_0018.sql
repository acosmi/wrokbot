-- Native 0018: credential generation is part of MCP server/grant identity.
-- Expand-only: legacy NULL means generation zero until the first credential/grant write.

ALTER TABLE public.mcp_servers
    ADD COLUMN credential_generation bigint;

ALTER TABLE public.mcp_servers
    ADD CONSTRAINT mcp_servers_credential_generation_nonnegative
    CHECK (credential_generation IS NULL OR credential_generation >= 0);

ALTER TABLE public.plugin_grants
    ADD COLUMN credential_generation bigint;

ALTER TABLE public.plugin_grants
    ADD CONSTRAINT plugin_grants_credential_generation_nonnegative
    CHECK (credential_generation IS NULL OR credential_generation >= 0);
