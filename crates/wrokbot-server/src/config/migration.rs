//! 环境变量三档处置里的两档：**退役**与**改名**（v3 §15.4）。
//!
//! 第三档 preserve 不需要机制 —— 它就是各个 `from_env_map` 照常读那个名字。需要机制的
//! 恰恰是另外两档，因为它们的正确行为是**主动去找一个我们不再使用的名字**。
//!
//! # 为什么"读不到就当没设"是错的
//!
//! v3 §15.4 末句逐字：「任何 remove 都必须在启动期被识别并报错，禁止『读不到就当没设』」。
//!
//! 理由用 `AGENT_TOOL_TOKEN` 讲最清楚：上游它是"一个框架 Bot 回调本服务器时出示的密钥"，
//! 一份还留着这一行的 `.env` 说明这个部署**现在正有外部 Bot 在用共享 token 路径回调**。
//! Rust 版删掉了那条路径（v3 §3.4）。如果启动时只是把这一行当没看见，部署会安静地起来，
//! 而那些 Bot 的回调从此全部被拒 —— 症状出现在别人的机器上，原因留在这台机器的 `.env` 里，
//! 中间没有任何一行日志把两者连起来。
//!
//! 同一条论证对 Intelligence 四件套更重：它们在**上游是必填**（四个缺一即拒绝启动），
//! 所以任何一份从上游迁过来的 `.env` 都带着它们。把它们当没看见，等于让每一次迁移都
//! 从"看起来一切正常"开始。
//!
//! # 为什么改名也拒绝启动，而不是"兼容旧名"
//!
//! `BETTER_AUTH_SECRET` → `OPENBOT_SESSION_SECRET` 这类改名，"顺手兼容旧名"看起来体贴，
//! 代价却是：旧名从此**永远**要留着，而且没有任何时刻会有人来删它。更糟的是它把一次
//! 需要人过目的迁移（session 密钥换名意味着**所有旧 session 失效**，见 v3 §6.3 末条）
//! 变成了一次静默升级。一次性拒绝启动 + 说出新名字，是把这件事摆到人面前的唯一办法。
//!
//! # 旧名与新名**同时**出现：仍然拒绝
//!
//! 这是本模块自己的裁决（§15.4 没有写）。理由：两个名字同时在场时，我们**无法知道**
//! 操作员想让哪个赢。
//!
//! - 若偏向新名：一个只改了旧名的操作员（比如轮换了 `BETTER_AUTH_SECRET`）会带着一个
//!   陈旧的新名值在跑，而且**没有任何提示**。
//! - 若偏向旧名：改名这件事就白做了。
//! - 若相等就放行：这是最坏的一种 —— 判据会在两个值恰好相同的那次通过，在轮换的那次
//!   突然拒绝，看起来像随机故障。
//!
//! 拒绝是唯一一个**不会静默使用一个操作员没打算使用的值**的选项。它与退役共用同一条
//! 论证：配置面上任何我们读不懂的东西，都要在启动期响亮地说出来。
//!
//! # 这两张表是唯一真源
//!
//! §15.4 那张表被逐条翻译成 [`RETIRED_ENV_VARS`]（6 项）与 [`RENAMED_ENV_VARS`]（6 项），
//! 判定只有一处：[`check_migrated_env_vars`]。测试
//! `no_other_config_file_decides_about_a_migrated_variable` 用源码级判据钉住"没有第三处
//! 在做同一件事"：这些变量名的字面量只允许出现在本文件里。

use crate::config::env::EnvMap;
use crate::config::error::ConfigProblem;

/// 一个变量为什么退役 —— **稳定 code，不是英文散文**。
///
/// 用枚举而不是一句话：这条理由会被 GUI 与 CLI 各自本地化成人话，而 v3 §15.3 逐字要求
/// 「stable code、HTTP status 和 audit event 类型不能随文案变化」。一个变量的退役理由
/// 同样是给人做决定用的（"我该删掉这一行还是该去找替代品"），把它钉成取值域，
/// 前端就能在不改后端的前提下把话说到位。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetirementReason {
    /// CopilotKit Intelligence 整条链路不在 Rust 版里。
    ///
    /// 只有 v3 §20.3 的**导入工具**还会读这些值，正式二进制一个都不读。
    IntelligenceRemoved,
    /// deployment 级共享的 Bot 回调 token 路径已删除（v3 §3.4）。
    ///
    /// preflight 必须列出仍在用它的端点 —— 那是迁移工具的活，本模块只负责让启动停下来。
    SharedAgentToolTokenRemoved,
    /// 没有任何第一方遥测外发（v3 §16.4「零 phone-home」），这个开关无事可控。
    ///
    /// 上游它只关 CopilotKit runtime 自带的 Segment / Scarf 上报，而那个 runtime 不在了。
    TelemetryRemoved,
}

impl RetirementReason {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntelligenceRemoved => "intelligence_removed",
            Self::SharedAgentToolTokenRemoved => "shared_agent_tool_token_removed",
            Self::TelemetryRemoved => "telemetry_removed",
        }
    }
}

/// 一个退役变量。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredEnvVar {
    /// 变量名。
    pub name: &'static str,
    /// 退役理由。
    pub reason: RetirementReason,
}

/// 改名之后，这个设置由什么承载。
///
/// **不是**一律"另一个变量名"：`COMPUTER_BOT_ID` / `PROFILES_DIR` / `WORKSPACE_DIR`
/// 在 v3 §15.4 里是「rename → scope 化」，它们不再由环境变量承载，而是按
/// `ComputerSecurityScope` 逐容器注入（§10.1）。把它们硬写成某个新变量名会是一句谎话，
/// 而这句谎话会原样出现在给操作员看的迁移提示里。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replacement {
    /// 换了一个环境变量名。
    Variable(&'static str),
    /// 不再由环境变量承载：容器内按 `ComputerSecurityScope` 注入（v3 §10.1 / §15.4）。
    ComputerSecurityScope,
}

impl Replacement {
    /// 稳定的线上取值，供 GUI / CLI 本地化提示时分辨这两种形态。
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Variable(_) => "variable",
            Self::ComputerSecurityScope => "computer_security_scope",
        }
    }

    /// 新的变量名，仅在 [`Replacement::Variable`] 时存在。
    #[must_use]
    pub const fn variable(self) -> Option<&'static str> {
        match self {
            Self::Variable(name) => Some(name),
            Self::ComputerSecurityScope => None,
        }
    }
}

/// 一个改名的变量。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenamedEnvVar {
    /// 旧名 —— 启动期扫描要找的就是它。
    pub old: &'static str,
    /// 改名之后由什么承载。
    pub replacement: Replacement,
    /// 这一条改名**自己的**稳定 code。
    ///
    /// 绝大多数是 [`RENAMED_ENV_VAR_CODE`]。给某一条单开 code 的判据是：
    /// **忽略它的后果与忽略其它改名不同类**。目前唯一这样的是
    /// `OPENBOT_DEV_NO_AUTH`，理由见 [`RENAMED_SINGLE_USER_FLAG_CODE`]。
    pub code: &'static str,
}

/// 普通改名的稳定 code。
pub const RENAMED_ENV_VAR_CODE: &str = "renamed_env_var";

/// 单用户旗标改名的稳定 code。
///
/// # 为什么它不能共用普通改名那条 code
///
/// 因为**忽略它的后果与忽略别的改名不是同一类事**。
///
/// 一个靠旧旗标跑单用户模式的部署，如果我们只是"不认"这个名字，它会以
/// `single_user_not_requested` 失败 —— 那句话是"你没有配置任何身份提供方，也没说要单用户
/// 模式"。而操作员**明明配了**（用的是旧名字）。这条报错指向一个他已经做过的动作，
/// 于是他会去翻 IdP 配置，翻不出问题，最后大概率去做那个最危险的事：随便找个旗标打开它。
///
/// 单开一条 code，GUI 与 CLI 就能说出真正有用的那句话：**"这个旗标改名了，新名字是
/// `OPENBOT_SINGLE_USER`"**。它守的是本仓最危险的那个开关（"每个访客都是管理员"），
/// 迁移提示说不清楚的代价与别的变量不在一个量级。
pub const RENAMED_SINGLE_USER_FLAG_CODE: &str = "renamed_single_user_flag";

/// 退役变量表 —— 逐条对应 v3 §15.4 的 `remove` 行，**恰 6 项**。
///
/// 与 `parity/env.yaml` 里 `migration_rule: "remove"` 的 6 条一一对应
/// （`intelligence-api-url` / `intelligence-api-key` / `intelligence-gateway-ws-url` /
/// `copilotkit-license-token` / `agent-tool-token` / `openbot-accessibility-disabled`）。
///
/// 按名字升序排列，且由 `tables_are_sorted_and_disjoint` 钉住：一张会被人手工追加的表，
/// 排序是"新增项去哪里"这个问题的唯一确定答案，也让 diff 只包含真正新增的那一行。
pub const RETIRED_ENV_VARS: &[RetiredEnvVar] = &[
    RetiredEnvVar {
        name: "AGENT_TOOL_TOKEN",
        reason: RetirementReason::SharedAgentToolTokenRemoved,
    },
    RetiredEnvVar {
        name: "COPILOTKIT_LICENSE_TOKEN",
        reason: RetirementReason::IntelligenceRemoved,
    },
    RetiredEnvVar {
        name: "INTELLIGENCE_API_KEY",
        reason: RetirementReason::IntelligenceRemoved,
    },
    RetiredEnvVar {
        name: "INTELLIGENCE_API_URL",
        reason: RetirementReason::IntelligenceRemoved,
    },
    RetiredEnvVar {
        name: "INTELLIGENCE_GATEWAY_WS_URL",
        reason: RetirementReason::IntelligenceRemoved,
    },
    RetiredEnvVar {
        name: "OPENBOT_ACCESSIBILITY_DISABLED",
        reason: RetirementReason::TelemetryRemoved,
    },
];

/// 改名变量表 —— **恰 7 项**。
///
/// 其中 6 项逐条对应 v3 §15.4 的 `rename` 行（`better-auth-secret` / `better-auth-url` /
/// `node-env` / `computer-bot-id` / `profiles-dir` / `workspace-dir`）。
///
/// # 第 7 项 `OPENBOT_DEV_NO_AUTH` 是本轮新补的，它不在 §15.4 的表里
///
/// 它**不是**死变量，而是上游活着的生产代码路径：
/// `server/src/auth/dev-actor.ts::singleUserEnabled` 里那个 `||` 的右半边读它，
/// `server/tests/single-user.test.ts` 有它的用例，CHANGELOG 也提到它。
/// 而 `parity/env.yaml` 原本 70 条里 0 命中（正向对照：同一批文件里
/// `OPENBOT_SINGLE_USER` 命中 20 处）。
///
/// 也就是说，现网**存在**靠这一行跑单用户模式的部署。既不认它、也不点名它，
/// 那些部署会以一个看起来毫不相干的理由启动失败 —— 详见
/// [`RENAMED_SINGLE_USER_FLAG_CODE`]。
///
/// `NODE_ENV` 在这张表里是**方向被翻转**的一条：上游它只做一件事（`production` 时拒绝示例
/// `KEY_ENCRYPTION_KEY`），而未设是默认值，于是唯一需要它管住的那个部署恰恰是它放过的那个。
/// `OPENBOT_ENV` 缺省即生产语义，只有显式 `development` 才放行示例 key。这也是为什么它
/// 必须**拒绝**而不是"当作 `OPENBOT_ENV` 读一遍"：一个写着 `NODE_ENV=development` 的
/// `.env` 若被照单全收，示例 key 会在一台生产机上被放行。
pub const RENAMED_ENV_VARS: &[RenamedEnvVar] = &[
    RenamedEnvVar {
        old: "BETTER_AUTH_SECRET",
        replacement: Replacement::Variable("OPENBOT_SESSION_SECRET"),
        code: RENAMED_ENV_VAR_CODE,
    },
    RenamedEnvVar {
        old: "BETTER_AUTH_URL",
        replacement: Replacement::Variable("OPENBOT_PUBLIC_URL"),
        code: RENAMED_ENV_VAR_CODE,
    },
    RenamedEnvVar {
        old: "COMPUTER_BOT_ID",
        replacement: Replacement::ComputerSecurityScope,
        code: RENAMED_ENV_VAR_CODE,
    },
    RenamedEnvVar {
        old: "NODE_ENV",
        replacement: Replacement::Variable("OPENBOT_ENV"),
        code: RENAMED_ENV_VAR_CODE,
    },
    RenamedEnvVar {
        old: "OPENBOT_DEV_NO_AUTH",
        replacement: Replacement::Variable("OPENBOT_SINGLE_USER"),
        code: RENAMED_SINGLE_USER_FLAG_CODE,
    },
    RenamedEnvVar {
        old: "PROFILES_DIR",
        replacement: Replacement::ComputerSecurityScope,
        code: RENAMED_ENV_VAR_CODE,
    },
    RenamedEnvVar {
        old: "WORKSPACE_DIR",
        replacement: Replacement::ComputerSecurityScope,
        code: RENAMED_ENV_VAR_CODE,
    },
];

/// 全环境扫描：把每一个退役 / 改名变量的出现都变成一条问题。
///
/// # 为什么是"全环境扫描"而不是"各字段自己检查"
///
/// 退役变量在 Rust 版里**没有对应字段**。让"读 `AGENT_TOOL_TOKEN` 的那段代码"去报错是不可能的
/// ——那段代码已经不存在了。这正是这一档需要一个独立机制的原因：判据必须挂在
/// **变量名的存在性**上，而不是挂在某个消费者上。
///
/// # 空值算不算"出现"
///
/// 算。这里刻意**不**走 [`crate::config::env::optional`] 的"空串等同未设"：一份写着
/// `AGENT_TOOL_TOKEN=` 的 `.env` 与写着 `AGENT_TOOL_TOKEN=abc` 的，在"这个部署以为自己
/// 还在用共享 token 路径"这件事上是同一个事实，而后者才是我们要说的话。`optional` 的空串
/// 语义服务的是"这个设置有没有值"，而这里问的是"这一行还在不在文件里"。
#[must_use]
pub fn check_migrated_env_vars(env: &EnvMap) -> Vec<ConfigProblem> {
    let mut problems = Vec::new();

    for retired in RETIRED_ENV_VARS {
        if env.contains_key(retired.name) {
            problems.push(ConfigProblem::Retired {
                variable: retired.name,
                reason: retired.reason,
            });
        }
    }

    for renamed in RENAMED_ENV_VARS {
        if !env.contains_key(renamed.old) {
            continue;
        }
        match renamed.replacement.variable() {
            Some(new_name) if env.contains_key(new_name) => {
                problems.push(ConfigProblem::RenameCollision {
                    old: renamed.old,
                    new: new_name,
                });
            }
            _ => problems.push(ConfigProblem::Renamed {
                old: renamed.old,
                replacement: renamed.replacement,
                code: renamed.code,
            }),
        }
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(names: &[&str]) -> EnvMap {
        names
            .iter()
            .map(|name| ((*name).to_owned(), "value".to_owned()))
            .collect()
    }

    /// 两张表逐条等于 v3 §15.4 的 remove / rename 行。
    ///
    /// 全集写死在这里，而不是只断言条数：条数相等在"改错了一项"的世界里同样通过。
    #[test]
    fn tables_match_the_decision_table_verbatim() {
        let retired: Vec<(&str, &str)> = RETIRED_ENV_VARS
            .iter()
            .map(|entry| (entry.name, entry.reason.as_str()))
            .collect();
        assert_eq!(
            retired,
            vec![
                ("AGENT_TOOL_TOKEN", "shared_agent_tool_token_removed"),
                ("COPILOTKIT_LICENSE_TOKEN", "intelligence_removed"),
                ("INTELLIGENCE_API_KEY", "intelligence_removed"),
                ("INTELLIGENCE_API_URL", "intelligence_removed"),
                ("INTELLIGENCE_GATEWAY_WS_URL", "intelligence_removed"),
                ("OPENBOT_ACCESSIBILITY_DISABLED", "telemetry_removed"),
            ]
        );

        let renamed: Vec<(&str, &str, Option<&str>, &str)> = RENAMED_ENV_VARS
            .iter()
            .map(|entry| {
                (
                    entry.old,
                    entry.replacement.kind(),
                    entry.replacement.variable(),
                    entry.code,
                )
            })
            .collect();
        assert_eq!(
            renamed,
            vec![
                (
                    "BETTER_AUTH_SECRET",
                    "variable",
                    Some("OPENBOT_SESSION_SECRET"),
                    "renamed_env_var"
                ),
                (
                    "BETTER_AUTH_URL",
                    "variable",
                    Some("OPENBOT_PUBLIC_URL"),
                    "renamed_env_var"
                ),
                (
                    "COMPUTER_BOT_ID",
                    "computer_security_scope",
                    None,
                    "renamed_env_var"
                ),
                (
                    "NODE_ENV",
                    "variable",
                    Some("OPENBOT_ENV"),
                    "renamed_env_var"
                ),
                (
                    "OPENBOT_DEV_NO_AUTH",
                    "variable",
                    Some("OPENBOT_SINGLE_USER"),
                    "renamed_single_user_flag"
                ),
                (
                    "PROFILES_DIR",
                    "computer_security_scope",
                    None,
                    "renamed_env_var"
                ),
                (
                    "WORKSPACE_DIR",
                    "computer_security_scope",
                    None,
                    "renamed_env_var"
                ),
            ]
        );

        // remove 6 项 = §15.4 那一行 = parity/env.yaml 的 recount。
        assert_eq!(RETIRED_ENV_VARS.len(), 6);
        // rename **7** 项 = §15.4 的 6 项 + 本轮新补的 OPENBOT_DEV_NO_AUTH。
        // 台账那条（`parity/env.yaml` 第 71 条）与 §15.4 的表由reviewer同步。
        assert_eq!(RENAMED_ENV_VARS.len(), 7);
    }

    /// 单用户旗标那条改名有**自己的** code，其余六条共用普通那条。
    ///
    /// 判据是"恰好一条特殊"：多一条或少一条都红。理由见
    /// [`RENAMED_SINGLE_USER_FLAG_CODE`] 的文档 —— 那条 code 存在的意义就是让迁移提示
    /// 说得出"这个旗标改名了"，而不是让操作员对着一句 `single_user_not_requested` 发呆。
    #[test]
    fn the_single_user_flag_rename_carries_its_own_code() {
        let special: Vec<&str> = RENAMED_ENV_VARS
            .iter()
            .filter(|entry| entry.code != RENAMED_ENV_VAR_CODE)
            .map(|entry| entry.old)
            .collect();
        assert_eq!(special, vec!["OPENBOT_DEV_NO_AUTH"]);
        assert_ne!(RENAMED_SINGLE_USER_FLAG_CODE, RENAMED_ENV_VAR_CODE);

        // 扫描出来的问题确实带着那条 code（表里写对了 ≠ 扫描用对了）。
        let problems = check_migrated_env_vars(&env(&["OPENBOT_DEV_NO_AUTH"]));
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].code(), RENAMED_SINGLE_USER_FLAG_CODE);
        // 而且它点得出新名字 —— 这正是单开 code 要换来的东西。
        assert!(
            problems[0].to_string().contains("OPENBOT_SINGLE_USER"),
            "{}",
            problems[0]
        );

        // 正向对照：普通改名走的是另一条 code，否则本条在"所有改名都用特殊 code"
        // 的世界里同样通过。
        let ordinary = check_migrated_env_vars(&env(&["NODE_ENV"]));
        assert_eq!(ordinary[0].code(), RENAMED_ENV_VAR_CODE);
    }

    /// 两张表各自有序、无重复，且互不相交。
    ///
    /// 相交会是个真缺陷：同一个名字既退役又改名，扫描会为它报两条互相矛盾的问题。
    #[test]
    fn tables_are_sorted_and_disjoint() {
        let retired: Vec<&str> = RETIRED_ENV_VARS.iter().map(|e| e.name).collect();
        let renamed: Vec<&str> = RENAMED_ENV_VARS.iter().map(|e| e.old).collect();

        let mut sorted = retired.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(retired, sorted, "退役表必须有序且无重复");

        let mut sorted = renamed.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(renamed, sorted, "改名表必须有序且无重复");

        for name in &retired {
            assert!(!renamed.contains(name), "{name} 同时出现在两张表里");
        }
    }

    /// 干净的环境**没有**任何问题 —— 这是全组的正向对照。
    ///
    /// 没有它，一个恒返回"有问题"的实现会让下面每一条都通过。
    #[test]
    fn a_clean_environment_reports_nothing() {
        let clean = env(&[
            "PORT",
            "DATABASE_URL",
            "OPENBOT_SESSION_SECRET",
            "OPENBOT_PUBLIC_URL",
            "OPENBOT_ENV",
            "KEY_ENCRYPTION_KEY",
        ]);
        assert!(check_migrated_env_vars(&clean).is_empty());
    }

    /// 每一个退役变量，单独出现时都被认出来。
    #[test]
    fn every_retired_variable_is_caught_on_its_own() {
        for entry in RETIRED_ENV_VARS {
            let problems = check_migrated_env_vars(&env(&[entry.name]));
            assert_eq!(
                problems,
                vec![ConfigProblem::Retired {
                    variable: entry.name,
                    reason: entry.reason,
                }],
                "{} 没被认出来",
                entry.name
            );
        }
    }

    /// 每一个改名变量，单独出现时都被认出来。
    #[test]
    fn every_renamed_variable_is_caught_on_its_own() {
        for entry in RENAMED_ENV_VARS {
            let problems = check_migrated_env_vars(&env(&[entry.old]));
            assert_eq!(
                problems,
                vec![ConfigProblem::Renamed {
                    old: entry.old,
                    replacement: entry.replacement,
                    code: entry.code,
                }],
                "{} 没被认出来",
                entry.old
            );
        }
    }

    /// 空值也算"这一行还在文件里"。
    #[test]
    fn an_empty_value_still_counts_as_present() {
        let mut map = EnvMap::new();
        map.insert("AGENT_TOOL_TOKEN".to_owned(), String::new());
        assert_eq!(
            check_migrated_env_vars(&map),
            vec![ConfigProblem::Retired {
                variable: "AGENT_TOOL_TOKEN",
                reason: RetirementReason::SharedAgentToolTokenRemoved,
            }]
        );
    }

    /// 旧名与新名同时出现 → 另一种问题，仍然拒绝。理由见模块文档。
    #[test]
    fn old_and_new_together_is_its_own_refusal() {
        let both = env(&["BETTER_AUTH_SECRET", "OPENBOT_SESSION_SECRET"]);
        assert_eq!(
            check_migrated_env_vars(&both),
            vec![ConfigProblem::RenameCollision {
                old: "BETTER_AUTH_SECRET",
                new: "OPENBOT_SESSION_SECRET",
            }]
        );

        // 正向对照：只有新名时什么都不报，否则本条在"新名也被拒"的世界里同样通过。
        assert!(check_migrated_env_vars(&env(&["OPENBOT_SESSION_SECRET"])).is_empty());
    }

    /// scope 化的三个没有"新名"可撞，所以永远走 [`ConfigProblem::Renamed`]。
    #[test]
    fn scope_migrated_variables_have_no_collision_form() {
        for entry in RENAMED_ENV_VARS
            .iter()
            .filter(|entry| entry.replacement.variable().is_none())
        {
            let problems = check_migrated_env_vars(&env(&[entry.old]));
            assert_eq!(problems.len(), 1);
            assert!(matches!(problems[0], ConfigProblem::Renamed { .. }));
        }
        // 正向对照：确实有这样的条目，否则上面的循环体一次都不跑也算通过。
        assert_eq!(
            RENAMED_ENV_VARS
                .iter()
                .filter(|entry| entry.replacement.variable().is_none())
                .count(),
            3
        );
    }

    /// 一次扫描把**所有**毛病列全，而不是报一个停一个。
    ///
    /// 这条不是体验优化：运维在容器里修一次重启一次，一次只告诉他一个问题，
    /// 一份带四个 Intelligence 变量的 `.env` 就是四轮重启。
    #[test]
    fn one_pass_lists_every_problem_at_once() {
        let messy = env(&[
            "INTELLIGENCE_API_URL",
            "INTELLIGENCE_API_KEY",
            "AGENT_TOOL_TOKEN",
            "BETTER_AUTH_URL",
            "NODE_ENV",
            "PORT",
        ]);
        let problems = check_migrated_env_vars(&messy);
        assert_eq!(problems.len(), 5, "{problems:?}");
    }

    /// 只取一份源码的**生产部分**（`#[cfg(test)]` 之前）。
    ///
    /// 测试里出现这些名字是正常的 —— 上面每一条用例都在构造带旧名的环境。要钉住的是
    /// **判定**只有一处，而判定住在生产代码里。
    fn production_part(source: &'static str) -> &'static str {
        match source.find("#[cfg(test)]") {
            Some(index) => &source[..index],
            None => source,
        }
    }

    /// **没有第三处地方在做同样的判定。**
    ///
    /// 判据是源码级的：这 12 个变量名的字面量只允许出现在本文件的生产部分里。别处一旦
    /// 出现，就意味着有人在某个 `from_env_map` 里"顺手也判一下"，而两处判定迟早会分叉
    /// （其中一处会先被人改）。
    ///
    /// `mod.rs` 不在被查名单里 —— 它只做模块声明与再导出，不做判定。
    #[test]
    fn no_other_config_file_decides_about_a_migrated_variable() {
        let siblings: [(&str, &str); 6] = [
            ("env.rs", production_part(include_str!("env.rs"))),
            ("secret.rs", production_part(include_str!("secret.rs"))),
            ("error.rs", production_part(include_str!("error.rs"))),
            ("address.rs", production_part(include_str!("address.rs"))),
            (
                "transport.rs",
                production_part(include_str!("transport.rs")),
            ),
            ("server.rs", production_part(include_str!("server.rs"))),
        ];

        for entry in RETIRED_ENV_VARS {
            for (file, source) in siblings {
                assert!(
                    !source.contains(entry.name),
                    "{} 出现在 {file} 的生产代码里 —— 退役判定只允许有一处",
                    entry.name
                );
            }
        }
        for entry in RENAMED_ENV_VARS {
            for (file, source) in siblings {
                assert!(
                    !source.contains(entry.old),
                    "{} 出现在 {file} 的生产代码里 —— 改名判定只允许有一处",
                    entry.old
                );
            }
        }

        // 正向对照：同一条判据对一个**应该**出现在 server.rs 生产代码里的名字确实为真。
        // 没有它，`include_str!` 拿到空串、路径写错、或 `production_part` 切过头时，
        // 上面全部恒过。
        let server_source = production_part(include_str!("server.rs"));
        assert!(server_source.contains("TENANT_PACKAGE_DIR"));
        assert!(server_source.contains("OPENBOT_ENV"));
    }
}
