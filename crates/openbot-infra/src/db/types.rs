//! 上游 0012 终态里的 4 个 PostgreSQL enum 类型在 Rust 侧的封闭映射。
//!
//! `0000_schema.sql` 一共建过 7 个 enum，但 `0010` 删掉 `acl_effect`、`0011` 删掉
//! `connector_type` 与 `sync_status`，所以 0012 终态的 `pg_type` 里只剩这 4 个
//! （真源 `fixtures/db/schema-0012.json` 的 `enums` 数组）。三个已删除的 enum 刻意**不**在这里
//! 出现，也不重建 —— 迁移边界检查会把「库里还有它们」判成没迁到 0012（见
//! [`crate::db::compat::RETIRED_ENUMS`]）。
//!
//! 每个 enum 都是**封闭**的：`FromSql` 遇到未知标签会报错而不是落到某个兜底变体。
//! `user_roles.role` 尤其如此 —— repository contract §5 不变量 3「deny 优先；空 / 坏 / 未知 policy
//! fail-closed」，把未知角色悄悄当成 `User` 或 `Admin` 都是错的答案。

use postgres_types::{FromSql, ToSql};

/// 一次性把 Rust 变体、PostgreSQL 类型名、PostgreSQL 标签写在同一处。
///
/// 展开出 `#[postgres(name = ...)]` 绑定**与** `PG_TYPE_NAME` / `PG_LABELS` 两个常量，
/// 所以「绑定的标签」与「台账里声称的标签」在构造上不可能漂开；
/// [`crate::db::compat`] 拿后者与真库的 `pg_enum` 逐值比对。
macro_rules! define_pg_enum {
    (
        $(#[$meta:meta])*
        $name:ident = $pg_type:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $label:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToSql, FromSql)]
        #[postgres(name = $pg_type)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                #[postgres(name = $label)]
                $variant,
            )+
        }

        impl $name {
            /// PostgreSQL 侧的类型名。
            pub const PG_TYPE_NAME: &'static str = $pg_type;

            /// PostgreSQL 侧的标签全集，顺序同 `pg_enum.enumsortorder`。
            pub const PG_LABELS: &'static [&'static str] = &[$($label),+];
        }
    };
}

define_pg_enum! {
    /// `public.agent_type` —— `agents.type`。
    AgentType = "agent_type" {
        /// 随包内置的 agent。
        BuiltIn = "built_in",
        /// 用户接入的远程 AG-UI agent。
        RemoteAgUi = "remote_ag_ui",
    }
}

define_pg_enum! {
    /// `public.agent_visibility` —— `agent_profiles.visibility`。
    AgentVisibility = "agent_visibility" {
        /// 对部署内所有人可见。
        Public = "public",
        /// 只对 `agent_profiles.owner_user_id` 可见。
        Private = "private",
    }
}

define_pg_enum! {
    /// `public.credential_kind` —— `credentials.kind`。
    ///
    /// `Connector` 保留：`0011` 删的是那四张 connector 表，不是这个标签（该 migration 的注释
    /// 逐字写着「`credential_kind` keeps its `connector` value」）。
    CredentialKind = "credential_kind" {
        /// 模型厂商凭据。
        Model = "model",
        /// 旧 connector 子系统的凭据。
        Connector = "connector",
        /// 远程 agent 的凭据。
        Agent = "agent",
        /// MCP server 的凭据。
        Mcp = "mcp",
        /// MCP OAuth client 凭据。
        McpOauthClient = "mcp_oauth_client",
        /// MCP 的用户级 token。
        McpUserToken = "mcp_user_token",
    }
}

define_pg_enum! {
    /// `public.role` —— `user_roles.role`。
    ///
    /// 封闭且 default-deny：`user_roles` 里**没有**行等于「不是 admin」，
    /// 而不是「未知角色，先放行」（`parity/tables.yaml::tbl-user-roles` 的 notes 逐字要求）。
    Role = "role" {
        /// 管理员。
        Admin = "admin",
        /// 普通用户。
        User = "user",
    }
}

/// 一个 PostgreSQL enum 类型的期望形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumSpec {
    /// PostgreSQL 类型名。
    pub name: &'static str,
    /// 标签全集，顺序同 `pg_enum.enumsortorder`。
    pub labels: &'static [&'static str],
}

impl EnumSpec {
    const fn new(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self { name, labels }
    }
}

/// 0012 终态应当存在的 4 个 enum，按类型名升序（与 `schema_facts.sql` 的排序一致）。
pub const EXPECTED_ENUMS: &[EnumSpec] = &[
    EnumSpec::new(AgentType::PG_TYPE_NAME, AgentType::PG_LABELS),
    EnumSpec::new(AgentVisibility::PG_TYPE_NAME, AgentVisibility::PG_LABELS),
    EnumSpec::new(CredentialKind::PG_TYPE_NAME, CredentialKind::PG_LABELS),
    EnumSpec::new(Role::PG_TYPE_NAME, Role::PG_LABELS),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_enums_are_the_four_survivors_in_sorted_order() {
        let names: Vec<&str> = EXPECTED_ENUMS.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            vec!["agent_type", "agent_visibility", "credential_kind", "role"],
        );
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "EXPECTED_ENUMS 必须按类型名升序");
    }

    #[test]
    fn enum_labels_match_the_reference_schema() {
        assert_eq!(AgentType::PG_LABELS, &["built_in", "remote_ag_ui"]);
        assert_eq!(AgentVisibility::PG_LABELS, &["public", "private"]);
        assert_eq!(
            CredentialKind::PG_LABELS,
            &[
                "model",
                "connector",
                "agent",
                "mcp",
                "mcp_oauth_client",
                "mcp_user_token",
            ],
        );
        assert_eq!(Role::PG_LABELS, &["admin", "user"]);
    }

    /// 上面三个 enum 的标签数合计 = 参照库 `pg_enum` 的行数（2 + 2 + 6 + 2 = 12）。
    #[test]
    fn total_enum_label_count_matches_the_reference_schema() {
        let total: usize = EXPECTED_ENUMS.iter().map(|e| e.labels.len()).sum();
        assert_eq!(total, 12);
    }
}
