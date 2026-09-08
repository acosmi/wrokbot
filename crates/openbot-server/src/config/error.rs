//! 启动配置的失败 —— **一次列全**，不是报一个停一个。
//!
//! # 为什么聚合不是体验优化
//!
//! 运维改配置的循环是"改一行 → 重建/重启容器 → 看日志"。这个循环在 Kubernetes 上是分钟级，
//! 在有人盯着的发布窗口里是全部的时间。一个"抛第一个错就停"的解析器，把一份有四处毛病的
//! `.env` 变成四轮这样的循环 —— 而这四处毛病本来在同一秒里全都可知。
//!
//! 上游 `server/src/config.ts` 用 `throw` 逐个抛（`required` / `keyEncryptionKey` /
//! `oauthClient` / `authConfig` 各自 throw），所以它就是上面那个形态。这里刻意不照搬：
//! 聚合是本轮的**改进**，不是 parity 项。
//!
//! # 为什么错误里只有变量名，没有变量值
//!
//! 与 `openbot_application::ports::PortError` 同一条决定：错误会进日志，而环境变量的值
//! 里有 `COMPUTER_TOKEN`、`OPENBOT_SESSION_SECRET`、`KEY_ENCRYPTION_KEY`
//! （v3 §6.4 末段点名"永不进入普通日志"的那一串）。所以 [`ConfigProblem`] 的每个字段
//! 都是 `&'static str` 或封闭枚举 —— **类型上就装不进一个运行期字符串**，
//! 而不是靠每个构造点记得别塞。
//!
//! 代价说清楚：日志里不会有"你写的那个值是什么"。补偿是 [`Expectation`] 说清"应该是什么"，
//! 而操作员手上就有那份 `.env`。

use core::fmt;

use crate::config::migration::{Replacement, RetirementReason};

/// 一个值**应该**长什么样 —— 封闭枚举，因为它要被本地化。
///
/// 不写成一句英文的理由同 [`RetirementReason`]：v3 §15.3 要求稳定 code 不随文案变化，
/// 而 GUI 与 CLI 会各自把它渲染成人话。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expectation {
    /// `0..=65535` 的整数（`0` 是合法值，含义是"由内核挑一个空闲端口"）。
    TcpPort,
    /// 至少 1 的整数天数。留空表示永久保留。
    WholeDaysAtLeastOne,
    /// 带 scheme 与 host 的绝对 `http` / `https` URL。
    AbsoluteHttpUrl,
    /// `production` 或 `development`，二者之一，全小写。
    DeploymentEnvironmentName,
    /// 一段合法 JSON。
    ActionPolicyJson,
    /// 一个 JSON **对象**（不是数组、不是标量）。
    ActionPolicyObject,
    /// `mode` 字段是 `"enforce"` 或 `"dry-run"`，**必填**。
    ///
    /// 上游 `policy-store.ts::parseActionPolicy` 对 `mode` 不设缺省：写策略的人必须自己说
    /// 这条边界是拦截还是只记录。缺省成 `enforce` 会把一份想先 dry-run 观察的策略
    /// 直接变成拦截档，而缺省成 `dry-run` 会把一份想拦截的策略变成什么都不挡。
    ActionPolicyMode,
    /// `deny` 是字符串数组（缺省空表）。
    ActionPolicyDenyList,
    /// `allow` 是字符串数组（缺省空表）。
    ActionPolicyAllowList,
    /// `openai` / `anthropic` / `google`。
    ProviderName,
    /// Whole milliseconds ≥0；0 disables。
    WholeMillisecondsOrZero,
    /// Provider output token cap in `1..=1_000_000`。
    WholeTokensOneToMillion,
    /// Selected provider key must be nonempty after trim。
    NonEmptySecret,
    /// Complete operator-attested provider price snapshot.
    ProviderRateCard,
}

impl Expectation {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcpPort => "tcp_port",
            Self::WholeDaysAtLeastOne => "whole_days_at_least_one",
            Self::AbsoluteHttpUrl => "absolute_http_url",
            Self::DeploymentEnvironmentName => "deployment_environment_name",
            Self::ActionPolicyJson => "action_policy_json",
            Self::ActionPolicyObject => "action_policy_object",
            Self::ActionPolicyMode => "action_policy_mode",
            Self::ActionPolicyDenyList => "action_policy_deny_list",
            Self::ActionPolicyAllowList => "action_policy_allow_list",
            Self::ProviderName => "provider_name",
            Self::WholeMillisecondsOrZero => "whole_milliseconds_or_zero",
            Self::WholeTokensOneToMillion => "whole_tokens_one_to_million",
            Self::NonEmptySecret => "non_empty_secret",
            Self::ProviderRateCard => "provider_rate_card",
        }
    }
}

/// 配置里的**一个**毛病。
///
/// `Copy`，因为每个字段都是 `&'static str` 或标量 —— 这正是"值不进错误"那条约束在
/// 类型层面的副产品。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigProblem {
    /// 出现了一个已退役的变量（v3 §15.4 remove 行）。
    Retired {
        /// 变量名。
        variable: &'static str,
        /// 退役理由的稳定 code。
        reason: RetirementReason,
    },
    /// 出现了一个已改名变量的**旧名**（v3 §15.4 rename 行）。
    Renamed {
        /// 旧名。
        old: &'static str,
        /// 改名之后由什么承载。
        replacement: Replacement,
        /// 这一条改名自己的稳定 code，取自
        /// [`RenamedEnvVar::code`](crate::config::migration::RenamedEnvVar::code)。
        ///
        /// 绝大多数是 `renamed_env_var`；单用户旗标那条单开一条，理由见
        /// [`RENAMED_SINGLE_USER_FLAG_CODE`](crate::config::migration::RENAMED_SINGLE_USER_FLAG_CODE)。
        code: &'static str,
    },
    /// 旧名与新名**同时**出现。裁决与理由见 [`crate::config::migration`] 模块文档。
    RenameCollision {
        /// 旧名。
        old: &'static str,
        /// 新名。
        new: &'static str,
    },
    /// 一个保留下来的变量，值的形状不对。
    Malformed {
        /// 变量名。
        variable: &'static str,
        /// 应该是什么。
        expectation: Expectation,
    },
}

impl ConfigProblem {
    /// 稳定的问题 code。GUI / CLI 按它挑文案，日志按它做聚类。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Retired { .. } => "retired_env_var",
            Self::Renamed { code, .. } => code,
            Self::RenameCollision { .. } => "renamed_env_var_collision",
            Self::Malformed { .. } => "malformed_env_var",
        }
    }

    /// 出问题的变量名。改名冲突报的是**旧名** —— 要被删掉的是那一行。
    #[must_use]
    pub const fn variable(self) -> &'static str {
        match self {
            Self::Retired { variable, .. } | Self::Malformed { variable, .. } => variable,
            Self::Renamed { old, .. } | Self::RenameCollision { old, .. } => old,
        }
    }
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Retired { variable, reason } => write!(
                formatter,
                "{} {variable}: 已退役（{}），请从配置中删除这一行",
                self.code(),
                reason.as_str()
            ),
            Self::Renamed {
                old, replacement, ..
            } => match replacement {
                Replacement::Variable(new) => write!(
                    formatter,
                    "{} {old}: 已更名为 {new}，改用新名后重启",
                    self.code()
                ),
                Replacement::ComputerSecurityScope => write!(
                    formatter,
                    "{} {old}: 不再由环境变量承载，改由 ComputerSecurityScope 逐容器注入",
                    self.code()
                ),
            },
            Self::RenameCollision { old, new } => write!(
                formatter,
                "{} {old} 与 {new} 同时存在：无法判断哪一个是你想用的，请只保留 {new}",
                self.code()
            ),
            Self::Malformed {
                variable,
                expectation,
            } => write!(
                formatter,
                "{} {variable}: 期望 {}",
                self.code(),
                expectation.as_str()
            ),
        }
    }
}

/// 一次启动配置解析的全部失败。
///
/// 恒非空：只有确实有问题时才会被构造（[`ConfigError::new`] 在空表时返回 `None`），
/// 于是"有 `Err` 却一条问题都没有"这种自相矛盾的状态在类型层面不存在。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    problems: Vec<ConfigProblem>,
}

impl ConfigError {
    /// 由问题清单构造。空清单返回 `None` —— 见类型文档。
    #[must_use]
    pub fn new(problems: Vec<ConfigProblem>) -> Option<Self> {
        if problems.is_empty() {
            None
        } else {
            Some(Self { problems })
        }
    }

    /// 全部问题，按解析顺序。
    #[must_use]
    pub fn problems(&self) -> &[ConfigProblem] {
        &self.problems
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "启动配置有 {} 处问题：", self.problems.len())?;
        for problem in &self.problems {
            write!(formatter, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl core::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 空清单构不出错误 —— 并配"非空确实构得出"的正向对照。
    #[test]
    fn an_empty_problem_list_is_not_an_error() {
        assert!(ConfigError::new(Vec::new()).is_none());
        // 正向对照：否则一个恒返回 None 的构造器也能过。
        let error = ConfigError::new(vec![ConfigProblem::Malformed {
            variable: "PORT",
            expectation: Expectation::TcpPort,
        }])
        .expect("非空清单必须构得出错误");
        assert_eq!(error.problems().len(), 1);
    }

    /// 四个 code 两两不同，且渲染里都带上了自己的 code。
    #[test]
    fn problem_codes_are_pairwise_distinct_and_rendered() {
        let all = [
            ConfigProblem::Retired {
                variable: "AGENT_TOOL_TOKEN",
                reason: RetirementReason::SharedAgentToolTokenRemoved,
            },
            ConfigProblem::Renamed {
                old: "NODE_ENV",
                replacement: Replacement::Variable("OPENBOT_ENV"),
                code: "renamed_env_var",
            },
            ConfigProblem::RenameCollision {
                old: "NODE_ENV",
                new: "OPENBOT_ENV",
            },
            ConfigProblem::Malformed {
                variable: "PORT",
                expectation: Expectation::TcpPort,
            },
        ];
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                assert_ne!(left.code(), right.code(), "code 撞了");
            }
            assert!(left.to_string().contains(left.code()), "{left}");
            assert!(left.to_string().contains(left.variable()), "{left}");
        }
    }

    /// 一次渲染把所有问题都列出来 —— 这是聚合的全部意义。
    #[test]
    fn display_lists_every_problem() {
        let error = ConfigError::new(vec![
            ConfigProblem::Retired {
                variable: "INTELLIGENCE_API_URL",
                reason: RetirementReason::IntelligenceRemoved,
            },
            ConfigProblem::Malformed {
                variable: "AUDIT_RETENTION_DAYS",
                expectation: Expectation::WholeDaysAtLeastOne,
            },
        ])
        .expect("两条问题");
        let rendered = error.to_string();
        assert!(rendered.contains("INTELLIGENCE_API_URL"), "{rendered}");
        assert!(rendered.contains("AUDIT_RETENTION_DAYS"), "{rendered}");
        assert!(rendered.contains('2'), "{rendered}");
    }

    /// scope 化的改名不能被渲染成"改用新名 xxx" —— 那句话会是假的。
    #[test]
    fn scope_migration_does_not_claim_a_new_variable_name() {
        let scoped = ConfigProblem::Renamed {
            old: "PROFILES_DIR",
            replacement: Replacement::ComputerSecurityScope,
            code: "renamed_env_var",
        }
        .to_string();
        assert!(scoped.contains("ComputerSecurityScope"), "{scoped}");
        assert!(!scoped.contains("更名为"), "{scoped}");

        // 正向对照：真正换了名字的那一类**确实**说出了新名字。
        let renamed = ConfigProblem::Renamed {
            old: "BETTER_AUTH_URL",
            replacement: Replacement::Variable("OPENBOT_PUBLIC_URL"),
            code: "renamed_env_var",
        }
        .to_string();
        assert!(renamed.contains("OPENBOT_PUBLIC_URL"), "{renamed}");
        assert!(renamed.contains("更名为"), "{renamed}");
    }

    /// 值不进错误：整个渲染里不出现任何运行期字符串。
    ///
    /// 这条靠类型已经保证了（每个字段都是 `&'static str` 或枚举），这里把它钉成
    /// 一条会在有人把字段改成 `String` 时红掉的机械判据。
    #[test]
    fn no_runtime_value_can_reach_the_message() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ConfigProblem>();
    }
}
