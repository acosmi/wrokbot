//! MCP / grants / skills 表的类型化 PostgreSQL repositories。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `mcp_servers` repository。
    McpServerRepo,
    table = mcp_servers,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

define_table_repo!(
    /// `mcp_tools` repository。
    McpToolRepo,
    table = mcp_tools,
    order_by = "\"server_id\", \"name\"",
    find = find_by_key(server_id: &str, name: &str) where "\"server_id\" = $1 AND \"name\" = $2"
);

define_table_repo!(
    /// `mcp_user_credentials` repository。
    McpUserCredentialRepo,
    table = mcp_user_credentials,
    order_by = "\"server_id\", \"user_id\"",
    find = find_by_key(server_id: &str, user_id: &str) where "\"server_id\" = $1 AND \"user_id\" = $2"
);

define_table_repo!(
    /// `plugin_grants` repository。
    PluginGrantRepo,
    table = plugin_grants,
    order_by = "\"kind\", \"ref\", \"agent_id\"",
    find = find_by_key(kind: &str, r#ref: &str, agent_id: &str) where "\"kind\" = $1 AND \"ref\" = $2 AND \"agent_id\" = $3"
);

define_table_repo!(
    /// `skills` repository。
    SkillRepo,
    table = skills,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);
