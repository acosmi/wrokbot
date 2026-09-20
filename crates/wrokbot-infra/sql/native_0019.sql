-- Native 0019: explicit vendor transport identity.
-- Expand-only: legacy NULL is interpreted as MCP by the Rust reader.

ALTER TABLE public.mcp_servers
    ADD COLUMN transport text;

ALTER TABLE public.mcp_servers
    ADD CONSTRAINT mcp_servers_transport_domain
    CHECK (transport IS NULL OR transport IN ('mcp','google_drive_rest'));
