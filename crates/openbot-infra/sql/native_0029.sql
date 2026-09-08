-- Native 0029: explicit per-server private-egress authority for custom MCP servers.
-- Expand-only: NULL is the legacy/public-only policy. Only custom provenance may carry overrides.

ALTER TABLE public.mcp_servers
    ADD COLUMN egress_allow_cidrs text[];

ALTER TABLE public.mcp_servers
    ADD CONSTRAINT mcp_servers_egress_allow_cidrs_shape
    CHECK (
        egress_allow_cidrs IS NULL OR (
            provenance = 'custom'
            AND cardinality(egress_allow_cidrs) <= 32
            AND array_position(egress_allow_cidrs, NULL) IS NULL
            AND octet_length(array_to_string(egress_allow_cidrs, ',')) <= 2048
        )
    );
