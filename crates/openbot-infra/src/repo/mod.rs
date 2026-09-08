//! repository —— `openbot-application` 里各 port 的 PostgreSQL 实现。
//!
//! 依赖方向是 `openbot-infra -> openbot-application`：port 由 application 定义，
//! 适配器在这里实现。application 只依赖 contracts，所以整条链无环。
//!
//! 每个 repo 的落点由 `parity/tables.yaml` 对应表条目 notes 里的 `repo=` 钉死，
//! 不由本模块自行命名。
//!
//! 本层只做「SQL ↔ 类型化行」的翻译：可见性、定序、游标判据落在 SQL 里，
//! 业务规则与编排在 application。**不接受来自 transport 的任意 query**（v3 §5.2）。

#[cfg(any(feature = "server-runtime", feature = "desktop-local-vault"))]
#[cfg_attr(
    not(feature = "server-runtime"),
    allow(dead_code, unused_imports, unused_macros)
)]
pub(crate) mod common;

#[cfg(feature = "server-runtime")]
pub mod agents;
pub mod audit;
#[cfg(feature = "server-runtime")]
pub mod channels;
#[cfg(feature = "server-runtime")]
pub mod components;
#[cfg(feature = "server-runtime")]
pub mod computer;
#[cfg(feature = "server-runtime")]
pub mod import;
#[cfg(feature = "server-runtime")]
pub mod memory;
#[cfg(feature = "server-runtime")]
pub mod outbox;
#[cfg(feature = "server-runtime")]
pub mod people;
pub mod people_admin;
#[cfg(feature = "server-runtime")]
pub mod plugins;
#[cfg(feature = "server-runtime")]
pub mod run;
#[cfg(feature = "server-runtime")]
pub mod tenant;
#[cfg(feature = "server-runtime")]
pub mod thread;
#[cfg(feature = "server-runtime")]
pub mod tools;

#[cfg(feature = "server-runtime")]
pub use agents::PostgresAgentDirectory;
#[cfg(feature = "server-runtime")]
pub use channels::ChannelRepo;

/// 当前已有物理表的具名 repository 台账。
///
/// 28 个上游表各一个（`ChannelRepo` 已含 channels），0013 再加 tool_calls/tool_attempts；
/// `audit_checkpoints` 与 audit_events 共用 `AuditEventRepo`。0016 与十张物理表同批补齐
/// thread/message/run/outbox/memory/import 十个 repository，40 个规划落点现均指向真实类型。
#[cfg(feature = "server-runtime")]
pub const IMPLEMENTED_REPOSITORIES: &[&str] = &[
    "openbot-infra::repo::agents::AgentPreferenceRepo",
    "openbot-infra::repo::agents::AgentProfileRepo",
    "openbot-infra::repo::agents::AgentRepo",
    "openbot-infra::repo::audit::AuditEventRepo",
    "openbot-infra::repo::channels::ChannelAgentRepo",
    "openbot-infra::repo::channels::ChannelMembershipRepo",
    "openbot-infra::repo::channels::ChannelRepo",
    "openbot-infra::repo::channels::LegacyIntelligenceMappingRepo",
    "openbot-infra::repo::components::ComponentExclusionRepo",
    "openbot-infra::repo::components::ComponentFunctionRepo",
    "openbot-infra::repo::components::ComponentRepo",
    "openbot-infra::repo::components::SandboxedComponentRepo",
    "openbot-infra::repo::computer::ActionPolicyRepo",
    "openbot-infra::repo::computer::SnapshotRepo",
    "openbot-infra::repo::import::ImportCursorRepo",
    "openbot-infra::repo::memory::MemoryEventRepo",
    "openbot-infra::repo::memory::MemoryRepo",
    "openbot-infra::repo::outbox::OutboxRepo",
    "openbot-infra::repo::people::AccountRepo",
    "openbot-infra::repo::people::IdentityProviderRepo",
    "openbot-infra::repo::people::RevokedAccessRepo",
    "openbot-infra::repo::people::RoleRepo",
    "openbot-infra::repo::people::SessionRepo",
    "openbot-infra::repo::people::UserRepo",
    "openbot-infra::repo::people::VerificationRepo",
    "openbot-infra::repo::plugins::McpServerRepo",
    "openbot-infra::repo::plugins::McpToolRepo",
    "openbot-infra::repo::plugins::McpUserCredentialRepo",
    "openbot-infra::repo::plugins::PluginGrantRepo",
    "openbot-infra::repo::plugins::SkillRepo",
    "openbot-infra::repo::run::RunEventRepo",
    "openbot-infra::repo::run::RunRepo",
    "openbot-infra::repo::tenant::DeploymentPackageRepo",
    "openbot-infra::repo::thread::MessageRepo",
    "openbot-infra::repo::thread::ThreadLeaseRepo",
    "openbot-infra::repo::thread::ThreadMembershipRepo",
    "openbot-infra::repo::thread::ThreadRepo",
    "openbot-infra::repo::tools::ToolAttemptRepo",
    "openbot-infra::repo::tools::ToolCallRepo",
    "openbot-infra::vault::CredentialRepo",
];

#[cfg(all(test, feature = "server-runtime"))]
mod tests {
    use super::*;

    #[test]
    fn implemented_repository_ledger_has_forty_unique_sorted_names() {
        assert_eq!(IMPLEMENTED_REPOSITORIES.len(), 40);
        let mut sorted = IMPLEMENTED_REPOSITORIES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(IMPLEMENTED_REPOSITORIES, sorted);

        let mut actual = [
            core::any::type_name::<agents::AgentPreferenceRepo>(),
            core::any::type_name::<agents::AgentProfileRepo>(),
            core::any::type_name::<agents::AgentRepo>(),
            core::any::type_name::<audit::AuditEventRepo>(),
            core::any::type_name::<channels::ChannelAgentRepo>(),
            core::any::type_name::<channels::ChannelMembershipRepo>(),
            core::any::type_name::<channels::ChannelRepo>(),
            core::any::type_name::<channels::LegacyIntelligenceMappingRepo>(),
            core::any::type_name::<components::ComponentExclusionRepo>(),
            core::any::type_name::<components::ComponentFunctionRepo>(),
            core::any::type_name::<components::ComponentRepo>(),
            core::any::type_name::<components::SandboxedComponentRepo>(),
            core::any::type_name::<computer::ActionPolicyRepo>(),
            core::any::type_name::<computer::SnapshotRepo>(),
            core::any::type_name::<import::ImportCursorRepo>(),
            core::any::type_name::<memory::MemoryEventRepo>(),
            core::any::type_name::<memory::MemoryRepo>(),
            core::any::type_name::<outbox::OutboxRepo>(),
            core::any::type_name::<people::AccountRepo>(),
            core::any::type_name::<people::IdentityProviderRepo>(),
            core::any::type_name::<people::RevokedAccessRepo>(),
            core::any::type_name::<people::RoleRepo>(),
            core::any::type_name::<people::SessionRepo>(),
            core::any::type_name::<people::UserRepo>(),
            core::any::type_name::<people::VerificationRepo>(),
            core::any::type_name::<plugins::McpServerRepo>(),
            core::any::type_name::<plugins::McpToolRepo>(),
            core::any::type_name::<plugins::McpUserCredentialRepo>(),
            core::any::type_name::<plugins::PluginGrantRepo>(),
            core::any::type_name::<plugins::SkillRepo>(),
            core::any::type_name::<run::RunEventRepo>(),
            core::any::type_name::<run::RunRepo>(),
            core::any::type_name::<tenant::DeploymentPackageRepo>(),
            core::any::type_name::<thread::MessageRepo>(),
            core::any::type_name::<thread::ThreadLeaseRepo>(),
            core::any::type_name::<thread::ThreadMembershipRepo>(),
            core::any::type_name::<thread::ThreadRepo>(),
            core::any::type_name::<tools::ToolAttemptRepo>(),
            core::any::type_name::<tools::ToolCallRepo>(),
            core::any::type_name::<crate::vault::CredentialRepo>(),
        ]
        .map(|name| name.replace("openbot_infra", "openbot-infra"));
        actual.sort_unstable();
        assert_eq!(
            IMPLEMENTED_REPOSITORIES,
            actual.each_ref().map(String::as_str),
            "字符串台账必须逐项指向真实类型",
        );
    }
}
