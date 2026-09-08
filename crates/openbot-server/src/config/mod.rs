//! 启动配置 —— 环境变量的三档处置（v3 §15.4）与 Server 侧的那份配置本体。
//!
//! # 三档是什么
//!
//! v3 §15.4 把上游每一个环境变量判进三档，本模块是它的执行面：
//!
//! | 档 | 机制 | 落点 |
//! | --- | --- | --- |
//! | preserve | 照常读那个名字 | [`ServerConfig`]、`openbot_infra::auth::config::AuthConfig`、`openbot_infra::db` |
//! | remove | **全环境扫描**，出现即拒绝启动 | [`migration::RETIRED_ENV_VARS`] |
//! | rename | 同上，附带说出新名字 | [`migration::RENAMED_ENV_VARS`] |
//!
//! 后两档需要独立机制，preserve 不需要 —— 因为退役变量在 Rust 版里**没有对应字段**，
//! 判据只能挂在"这个名字在不在环境里"上，挂不到任何消费者身上。详见
//! [`migration`] 模块文档里那段 `AGENT_TOOL_TOKEN` 的论证。
//!
//! # 一条贯穿本模块的硬约束：解析器不读进程环境
//!
//! 所有 `from_env_map` 都接受一张 [`env::EnvMap`]。理由不是风格：一个读
//! `std::env::var` 的解析器，它的测试就是**对不受控的全机状态下断言** —— 同一条用例
//! 换台机器、或与另一条用例并发跑，答案会翻。
//!
//! 唯一允许触碰进程环境的是 [`env::env_map_from_process`]，它由二进制入口调用一次，
//! **不被任何测试调用**。这条不靠自觉：本模块的
//! `parsers_never_touch_the_process_environment` 用源码级判据钉住它。
//!
//! # 错误一次列全
//!
//! [`error::ConfigError`] 带的是一个问题**清单**而不是一个问题。上游
//! `server/src/config.ts` 是抛第一个就停，这里刻意不照搬 —— 理由（运维在容器里
//! 改一行重启一次的现实成本）写在 [`error`] 模块文档里。
//!
//! # 谁不在这里
//!
//! - `DATABASE_URL` → `openbot-infra::db`（台账 `database-url` 的 `target` 就是那里）。
//! - 认证面全部 → `openbot_infra::auth::config`：session secret、`KEY_ENCRYPTION_KEY`、
//!   三家 OAuth、`INITIAL_ADMIN_EMAILS`、`TRUSTED_ORIGINS`、`OPENBOT_SINGLE_USER`。
//! - `openbot-computer` / `openbot-agent` 归属的那一大批 → G4/G5。本模块只收 Server
//!   作为**调用方**要用的那六个 computer 端点变量。
//!
//! 注意最后一条的边界：[`migration::RETIRED_ENV_VARS`] 与 [`migration::RENAMED_ENV_VARS`]
//! 是**全环境**扫描，覆盖 §15.4 表里所有 remove / rename 项，包括归属 computer 的那三个
//! scope 化变量 —— 它们的**配置结构体**不在这里，但"出现即报错"的判定必须在这里，
//! 因为那是启动期唯一一次看得见整张环境表的地方。

pub mod address;
pub mod agent;
pub mod env;
pub mod error;
pub mod launch;
pub mod migration;
pub mod policy;
pub mod preflight;
pub mod secret;
pub mod server;
pub mod transport;

pub use address::{AddressParseError, DeploymentAddress, Scheme, is_loopback_host};
pub use agent::{
    AgentBudgets, ManagedProviderConfig, ManagedProviderKind, PackageOpenAiProviderConfig,
    parse_agent_config,
};
pub use env::{EnvMap, env_map_from_process};
pub use error::{ConfigError, ConfigProblem, Expectation};
pub use migration::{
    RENAMED_ENV_VAR_CODE, RENAMED_ENV_VARS, RENAMED_SINGLE_USER_FLAG_CODE, RETIRED_ENV_VARS,
    RenamedEnvVar, Replacement, RetiredEnvVar, RetirementReason, check_migrated_env_vars,
};
pub use policy::parse_action_policy;
pub use preflight::{
    AuditRetentionPreflightCode, AuditRetentionPreflightFinding, AuditRetentionPreflightReport,
    preflight_audit_retention,
};
pub use secret::Secret;
pub use server::{
    AuditRetention, ComputerConfig, ComputerProvider, DEFAULT_PORT, DEFAULT_TENANT_PACKAGE_DIR,
    DeploymentEnvironment, ServerConfig,
};
pub use transport::PublicTransport;

#[cfg(test)]
mod tests {
    /// 解析器一个都不许碰进程环境。
    ///
    /// # 判据为什么是源码级的
    ///
    /// 这条约束的违反形态是"某人图省事，在某个 `parse_*` 里直接读了一下"，
    /// 而它的后果要到**别人的测试在别人的机器上莫名其妙翻掉**时才显形。行为级的测试
    /// 抓不到它（一个读了进程环境、但那台机器恰好没设那个变量的解析器，行为完全正常）。
    ///
    /// 所以判据落在源码上：除 `env.rs` 外，本模块的每个文件都不许出现 `std::env`。
    ///
    /// # `mod.rs` 自己为什么不在被查名单里
    ///
    /// 它就是这条测试的所在地，源码里必然带着要找的那个串。needle 用 `concat!` 拼出来
    /// 正是为了让**被查的**文件不会因为写了这条断言而自己判红。
    #[test]
    fn parsers_never_touch_the_process_environment() {
        // 拼出来而不是写成字面量：写成字面量的话，任何一个含有这条断言的文件都会
        // 因为断言本身而被自己判红。
        let needle = concat!("std::", "env");

        let parsers: [(&str, &str); 9] = [
            ("address.rs", include_str!("address.rs")),
            ("agent.rs", include_str!("agent.rs")),
            ("error.rs", include_str!("error.rs")),
            ("migration.rs", include_str!("migration.rs")),
            ("policy.rs", include_str!("policy.rs")),
            ("preflight.rs", include_str!("preflight.rs")),
            ("secret.rs", include_str!("secret.rs")),
            ("server.rs", include_str!("server.rs")),
            ("transport.rs", include_str!("transport.rs")),
        ];
        for (file, source) in parsers {
            assert!(
                !source.contains(needle),
                "{file} 直接读了进程环境 —— 解析器只许接受 EnvMap"
            );
        }

        // 正向对照：同一条判据在**唯一允许**的那个文件上确实为真。
        // 没有它，`include_str!` 路径写错或 needle 拼错时上面全部恒过。
        assert!(include_str!("env.rs").contains(needle));
    }
}
