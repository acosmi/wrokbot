//! 判定本身：deny 先于 allow，坏规则 fail-closed，`dry-run` 只改放不放行。
//!
//! # 判据逐条对应上游 `evaluateActionPolicy`
//!
//! | 上游 | 这里 |
//! | --- | --- |
//! | `mode = policy?.mode ?? "enforce"` | [`super::CompiledActionPolicy::mode`]（未配置报 `Enforce`） |
//! | `deny` 全表先走一遍，`matches(expr, ctx, true)` | `rule_fires` 的 `on_error = true` |
//! | `allow` 后走，`matches(expr, ctx, false)` | `rule_fires` 的 `on_error = false` |
//! | 命中 deny → `allowed:false, source:"deny", forward: mode === "dry-run"` | [`PolicySource::Deny`] 分支 |
//! | 命中 allow → `allowed:true, source:"allow", forward:true` | [`PolicySource::Allow`] 分支 |
//! | 都没命中 → `allowed:false, matched:null, source:"default"` | [`PolicySource::Default`] 分支 |
//!
//! # `on_error` 为什么必须是两个不同的值
//!
//! 上游注释逐字：「a broken `allow` must not permit, and a broken `deny` must not stop denying」。
//! 一个坏规则的"安全答案"取决于它在哪张表上 —— 这不是可以统一成一个常量的东西。把两侧都设成
//! `true`，一条 allow 里的手误会放行一切；都设成 `false`，一条 deny 里的手误会让被禁的动作
//! 静默通过，而设置页上那条规则还挂着，看起来一切正常。
//!
//! # `false` 不是坏
//!
//! [`super::ResultClass::False`] 走的是"这条规则不适用"的分支，不是 `on_error`。上游同一段注释
//! 的最后一句就是这条：一张把每个 `false` 都读成拒绝的 deny 表会拒绝一切。
//!
//! # 拒绝理由是类型不是句子
//!
//! [`Refusal`] 取代上游的 `reason: string`（repository contract §4a：文案不进 domain）。**分支顺序与
//! 判据逐条照抄** `describeRefusal`，理由见 [`Refusal::for_context`]。

use super::cel::ResultClass;
use super::context::PolicyContext;
use super::{CompiledActionPolicy, CompiledRule, PolicyMode, PolicyVersion};

/// 一次判定的结果。
///
/// 生命周期参数只为 [`PolicyDecision::matched`]：它借的是策略里那条规则的原文，**不是**副本。
/// 借用而不是拷贝，是为了让"决策指的就是这条规则"在类型上成立 —— 一份被替换掉的策略活不过
/// 它产出的决策，编译器会说话。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision<'policy> {
    /// 这次动作被允许了吗。
    pub allowed: bool,
    /// 做判定时生效的档位。
    pub mode: PolicyMode,
    /// 拍板的那条规则原文。`None` = 没有任何规则命中，落到了 default-deny。
    pub matched: Option<&'policy str>,
    /// 那条规则来自哪张表。
    pub source: PolicySource,
    /// 动作**实际上**要不要执行。
    ///
    /// 它与 `allowed` 分开，正是 `dry-run` 存在的形状：一次被记录在案的拒绝，动作照样放过去。
    pub forward: bool,
    /// 拒绝的结构化理由。`None` 当且仅当 `allowed == true`。
    pub refusal: Option<Refusal>,
    /// 做这次判定时用的策略版本。
    ///
    /// §8.3 要求它进每个 decision：多 replica 部署里策略传播不是瞬时的，**一个 replica 用旧
    /// 版本做出的 decision 必须在 audit 里可辨认**。
    pub policy_version: PolicyVersion,
}

/// 拍板的规则来自哪张表。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicySource {
    /// deny 表。
    Deny,
    /// allow 表。
    Allow,
    /// 两张表都没命中，落到了 default-deny 这块地板。
    Default,
}

impl PolicySource {
    /// 稳定的线上表示，与上游 `PolicyDecision["source"]` 的联合类型逐字相同。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Default => "default",
        }
    }
}

impl core::fmt::Display for PolicySource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 被拒的是**哪一类东西**。给审计做分桶用的扁平判别式。
///
/// 与 [`Refusal`] 并存而不是让调用方自己 `match`：审计行要的是一个可索引的稳定字符串，
/// 而 GUI 要的是结构化字段。两个需求，两个类型，同一个真源（[`Refusal::subject`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalSubject {
    /// 一条命令。
    Command,
    /// 一次第三方 MCP 工具调用。
    Mcp,
    /// 一个工作区文件。
    File,
    /// 页面上一个有名字的元素。
    Element,
    /// 其它 —— 只知道用了哪个工具、在哪个站点上。
    Tool,
}

impl RefusalSubject {
    /// 稳定的分类标识符，进审计与日志用。
    ///
    /// 它是**标识符**不是文案（repository contract §4a）：GUI 拿它去查本地化表，domain 不组句。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Command => "policy_refused_command",
            Self::Mcp => "policy_refused_mcp_tool",
            Self::File => "policy_refused_file",
            Self::Element => "policy_refused_element",
            Self::Tool => "policy_refused_tool",
        }
    }
}

impl core::fmt::Display for RefusalSubject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

/// 一次拒绝的结构化理由：**被拒的是什么**，加上组句所需的字段。
///
/// 与 [`super::CelFailure`] 的规矩正好相反，这里**刻意**携带 context 取值。分界线不是"是不是
/// 用户数据"，而是**给谁看**：`CelFailure` 会进日志与审计 payload（§8.6 有字段 allowlist），
/// 而 [`Refusal`] 只回给发起这次动作的人 —— 他本来就在看这个页面、敲这条命令。上游的
/// `reason` 字符串携带的是同一批字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// 被拒的是一条命令。
    Command {
        /// 命令原文。
        command: String,
    },
    /// 被拒的是一次第三方 MCP 工具调用。
    Mcp {
        /// server 名。
        server: String,
        /// 工具名。
        tool: String,
    },
    /// 被拒的是一个工作区文件。
    File {
        /// 文件路径。
        path: String,
    },
    /// 被拒的是页面上一个有名字的元素。
    Element {
        /// 元素的可访问名。
        name: String,
        /// 页面主机名。
        host: String,
    },
    /// 兜底：只说得出用了哪个工具、在哪个站点上。
    Tool {
        /// 工具名。**原样**，不做任何前缀裁剪。
        ///
        /// 上游在这里做了 `tool.name.replace("computer_", "")`，那是**排版**：它是为了把
        /// `computer_click` 念成 "a click action"。裁剪属于组句，组句在 GUI，所以这里给原值。
        tool: String,
        /// 页面主机名。
        host: String,
    },
}

impl Refusal {
    /// 从上下文推出被拒的是什么。**分支顺序即判据，逐条照抄上游 `describeRefusal`。**
    ///
    /// # 顺序为什么是这个顺序
    ///
    /// 1. **`command` 最先**。一次 shell 调用没有页面，落到最后那条分支会得到"某个动作 on
    ///    （空主机）"。
    /// 2. **`mcp` 其次**。上游注释解释得最细：MCP 形态的 context 里浏览器字段**全都在场且
    ///    全都是空串**（刻意如此，好让写给页面的规则求值成 `false` 而不是不可求值）。于是
    ///    后面每一条判断对一次工具调用都"成立"却全都错 —— 不先认它，一次被拒的 Jira 调用会
    ///    报成"the file  is blocked"，指着一个它从没碰过的工作区。上游原话：**Checked first
    ///    because it is the only one of these that is ever certain.**
    /// 3. **`file.path` 第三**，且判据是**路径非空**不是"file 字段在场"（同一个理由：MCP 与
    ///    command 形态的 context 里 `file` 可能在场且全空）。上游另有一条：文件拒绝绝不能说成
    ///    "on `<host>`" —— 工作区跟浏览器此刻显示什么页面毫无关系，那么说会把人送错地方。
    /// 4. **`element.name` 非空 → 元素**，否则退到工具 + 主机。
    ///
    /// # 空串为什么算"不在场"
    ///
    /// 上游这四个判断写的是 JS 真值判断（`if (context.command)` / `context.file?.path`），
    /// 空串是假值。这不是可以忽略的细节：正因为 gateway 会给非浏览器形态塞满空串字段，
    /// 判据必须是"非空"而不是"在场"，否则第 3 条会把每一次 MCP 拒绝都说成文件拒绝。
    /// 闸门是 `refusal_branch_order_matches_upstream`。
    #[must_use]
    pub fn for_context(context: &PolicyContext) -> Self {
        if let Some(command) = context.command.as_deref().filter(|value| !value.is_empty()) {
            return Self::Command {
                command: command.to_string(),
            };
        }
        if let Some(mcp) = context.mcp.as_ref() {
            return Self::Mcp {
                server: mcp.server.clone(),
                tool: mcp.tool.clone(),
            };
        }
        if let Some(file) = context.file.as_ref().filter(|file| !file.path.is_empty()) {
            return Self::File {
                path: file.path.clone(),
            };
        }
        if let Some(element) = context.element.as_ref().filter(|el| !el.name.is_empty()) {
            return Self::Element {
                name: element.name.clone(),
                host: context.page.host.clone(),
            };
        }
        Self::Tool {
            tool: context.tool.name.clone(),
            host: context.page.host.clone(),
        }
    }

    /// 扁平判别式，给审计分桶用。
    #[must_use]
    pub const fn subject(&self) -> RefusalSubject {
        match self {
            Self::Command { .. } => RefusalSubject::Command,
            Self::Mcp { .. } => RefusalSubject::Mcp,
            Self::File { .. } => RefusalSubject::File,
            Self::Element { .. } => RefusalSubject::Element,
            Self::Tool { .. } => RefusalSubject::Tool,
        }
    }

    /// 稳定的分类标识符，等价于 `self.subject().code()`。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.subject().code()
    }
}

/// 一条规则算不算"命中"。
///
/// `on_error` 就是上游 `matches(expression, context, onError)` 的第三个参数：**坏规则的安全
/// 答案取决于它在哪张表上**。deny 侧传 `true`，allow 侧传 `false`。
fn rule_fires(rule: &CompiledRule, context: &PolicyContext, on_error: bool) -> bool {
    match rule.evaluate(context) {
        ResultClass::True => true,
        ResultClass::False => false,
        ResultClass::Error(_) => on_error,
    }
}

/// 判定这次动作可不可以跑。
///
/// 两个状态都有答案：未配置的部署一律拒绝（§8.3「新安装没有隐式 `allow: ["true"]`」），
/// 已配置的按 deny → allow → default 三段走。
#[must_use]
pub fn evaluate<'policy>(
    policy: &'policy CompiledActionPolicy,
    context: &PolicyContext,
) -> PolicyDecision<'policy> {
    let mode = policy.mode();
    let policy_version = policy.version();

    let rules = match policy {
        // 未完成首次设置：没有规则可命中，也**不能** forward。
        // 这里不写 `forward: mode == DryRun` 不是偷懒 —— `mode()` 对这个状态恒为 `Enforce`
        // （见它的类型文档），两种写法同值；写成常量是为了让"没有策略就没有试运行"这条判断
        // 直接可读，而不是绕一圈去查 `mode()` 返回什么。
        CompiledActionPolicy::Unconfigured => {
            return PolicyDecision {
                allowed: false,
                mode,
                matched: None,
                source: PolicySource::Default,
                forward: false,
                refusal: Some(Refusal::for_context(context)),
                policy_version,
            };
        }
        CompiledActionPolicy::Configured(rules) => rules,
    };

    // deny 先走完整张表。一条手误的 deny 规则照样拒绝：失败是响亮、即时且安全的，
    // 而另一种选择是一个自以为禁掉了某件事、其实没有的部署。
    for rule in rules.deny() {
        if rule_fires(rule, context, true) {
            return PolicyDecision {
                allowed: false,
                mode,
                matched: Some(rule.source()),
                source: PolicySource::Deny,
                // dry-run 记录这次拒绝并让活继续 —— 这正是它敢对真实流量打开的原因。
                forward: mode == PolicyMode::DryRun,
                refusal: Some(Refusal::for_context(context)),
                policy_version,
            };
        }
    }

    for rule in rules.allow() {
        if rule_fires(rule, context, false) {
            return PolicyDecision {
                allowed: true,
                mode,
                matched: Some(rule.source()),
                source: PolicySource::Allow,
                forward: true,
                refusal: None,
                policy_version,
            };
        }
    }

    PolicyDecision {
        allowed: false,
        mode,
        matched: None,
        source: PolicySource::Default,
        forward: mode == PolicyMode::DryRun,
        refusal: Some(Refusal::for_context(context)),
        policy_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ActionPolicy;
    use crate::policy::context::{
        ActorRef, BotRef, ElementRef, FileRef, McpEffect, McpRef, PageRef, ToolRef,
    };

    fn compile(mode: PolicyMode, deny: &[&str], allow: &[&str]) -> CompiledActionPolicy {
        CompiledActionPolicy::compile(&ActionPolicy {
            mode,
            deny: deny.iter().map(|rule| (*rule).to_string()).collect(),
            allow: allow.iter().map(|rule| (*rule).to_string()).collect(),
        })
    }

    fn click_submit() -> PolicyContext {
        PolicyContext {
            tool: ToolRef {
                name: "computer_click".to_string(),
            },
            bot: BotRef {
                id: "risk-analyst".to_string(),
            },
            page: PageRef {
                url: "https://example.com/order".to_string(),
                host: "example.com".to_string(),
            },
            actor: ActorRef {
                id: "dev-local-user".to_string(),
            },
            element: Some(ElementRef {
                reference: "e13".to_string(),
                role: "button".to_string(),
                name: "Submit order".to_string(),
                kind: None,
            }),
            key: None,
            intent: None,
            file: None,
            mcp: None,
            command: None,
        }
    }

    /// deny 压过 allow，哪怕 allow 里写着 `true`。
    ///
    /// 正向对照：去掉 deny 之后同一份 allow **确实**放行 —— 否则本条在"allow 从来不放行"的
    /// 世界里同样通过。
    #[test]
    fn deny_beats_allow() {
        let context = click_submit();

        let with_deny = compile(
            PolicyMode::Enforce,
            &["contains(element.name, \"submit\")"],
            &["true"],
        );
        let refused = evaluate(&with_deny, &context);
        assert!(!refused.allowed);
        assert_eq!(refused.source, PolicySource::Deny);
        assert_eq!(refused.matched, Some("contains(element.name, \"submit\")"));
        assert!(!refused.forward);

        let without_deny = compile(PolicyMode::Enforce, &[], &["true"]);
        let permitted = evaluate(&without_deny, &context);
        assert!(permitted.allowed);
        assert_eq!(permitted.source, PolicySource::Allow);
        assert_eq!(permitted.matched, Some("true"));
        assert!(permitted.forward);
        assert_eq!(permitted.refusal, None);
    }

    /// 坏 deny 仍然 deny；坏 allow 不放行。**同一条坏规则，两张表上两个答案。**
    #[test]
    fn a_broken_rule_fails_closed_on_both_lists() {
        let context = click_submit();

        for broken in [
            "this is not ( valid cel",
            "repeat.count",
            "\"Submit order\"",
        ] {
            let on_deny = compile(PolicyMode::Enforce, &[broken], &["true"]);
            let decision = evaluate(&on_deny, &context);
            assert!(!decision.allowed, "坏 deny 规则 {broken} 必须仍然拒绝");
            assert_eq!(decision.source, PolicySource::Deny);
            assert_eq!(decision.matched, Some(broken));

            let on_allow = compile(PolicyMode::Enforce, &[], &[broken]);
            let decision = evaluate(&on_allow, &context);
            assert!(!decision.allowed, "坏 allow 规则 {broken} 必须不放行");
            assert_eq!(decision.source, PolicySource::Default);
            assert_eq!(decision.matched, None);
        }
    }

    /// 非布尔答案算坏规则 —— 上游把它与抛错归入同一条 fail-closed 路径。
    ///
    /// 正向对照在同一条里：**同一张 deny 表**上一条真的答 `false` 的规则不命中。
    #[test]
    fn a_non_boolean_answer_is_broken_but_false_is_an_answer() {
        let context = click_submit();

        let non_boolean = compile(PolicyMode::Enforce, &["element.name"], &["true"]);
        let decision = evaluate(&non_boolean, &context);
        assert_eq!(decision.source, PolicySource::Deny);
        assert!(!decision.allowed);

        let honest_false = compile(
            PolicyMode::Enforce,
            &["contains(element.name, \"cancel\")"],
            &["true"],
        );
        let decision = evaluate(&honest_false, &context);
        assert_eq!(
            decision.source,
            PolicySource::Allow,
            "false 不是坏规则，deny 不该命中"
        );
        assert!(decision.allowed);
    }

    /// `dry-run` **只**改 `forward`，`allowed` / `matched` / `source` 一个都不动。
    #[test]
    fn dry_run_only_changes_forward() {
        let context = click_submit();
        let deny = ["contains(element.name, \"submit\")"];

        let enforcing_policy = compile(PolicyMode::Enforce, &deny, &[]);
        let dry_running_policy = compile(PolicyMode::DryRun, &deny, &[]);
        let enforcing = evaluate(&enforcing_policy, &context);
        let dry_running = evaluate(&dry_running_policy, &context);

        assert_eq!(enforcing.allowed, dry_running.allowed);
        assert_eq!(enforcing.matched, dry_running.matched);
        assert_eq!(enforcing.source, dry_running.source);
        assert_eq!(enforcing.refusal, dry_running.refusal);
        assert!(!enforcing.forward);
        assert!(dry_running.forward);

        // default-deny 那条地板上也一样。
        let enforcing_floor = compile(PolicyMode::Enforce, &[], &[]);
        let dry_running_floor = compile(PolicyMode::DryRun, &[], &[]);
        let enforcing = evaluate(&enforcing_floor, &context);
        let dry_running = evaluate(&dry_running_floor, &context);
        assert_eq!(enforcing.source, PolicySource::Default);
        assert_eq!(dry_running.source, PolicySource::Default);
        assert!(!enforcing.forward);
        assert!(dry_running.forward);
    }

    /// 空 allow 表 = 什么都不放行，`source` 是 `default` 而不是 `allow`。
    #[test]
    fn an_empty_allow_list_permits_nothing() {
        let context = click_submit();
        let policy = compile(PolicyMode::Enforce, &[], &[]);
        let decision = evaluate(&policy, &context);
        assert!(!decision.allowed);
        assert_eq!(decision.source, PolicySource::Default);
        assert_eq!(decision.matched, None);
        assert!(decision.refusal.is_some());
    }

    /// 未完成首次设置的部署拒绝一切，且**没有** dry-run 可言。
    ///
    /// 正向对照：同一个上下文在一份写了 `allow: ["true"]` 的策略下**确实**被放行。
    #[test]
    fn an_unconfigured_deployment_denies_everything() {
        let context = click_submit();

        let unconfigured = CompiledActionPolicy::unconfigured();
        let decision = evaluate(&unconfigured, &context);
        assert!(!decision.allowed);
        assert!(!decision.forward);
        assert_eq!(decision.mode, PolicyMode::Enforce);
        assert_eq!(decision.source, PolicySource::Default);
        assert_eq!(decision.matched, None);
        assert_eq!(decision.policy_version, PolicyVersion::unconfigured());

        let configured_policy = compile(PolicyMode::Enforce, &[], &["true"]);
        let configured = evaluate(&configured_policy, &context);
        assert!(configured.allowed);
        assert_ne!(configured.policy_version, PolicyVersion::unconfigured());
    }

    /// 每个 decision 都带策略版本，而且带的是**做这次判定时**那一份的版本。
    #[test]
    fn every_decision_carries_the_policy_version() {
        let context = click_submit();
        let first = compile(PolicyMode::Enforce, &["true"], &[]);
        let second = compile(PolicyMode::Enforce, &["false"], &["true"]);

        let refused = evaluate(&first, &context);
        let permitted = evaluate(&second, &context);

        assert_eq!(refused.policy_version, first.version());
        assert_eq!(permitted.policy_version, second.version());
        assert_ne!(refused.policy_version, permitted.policy_version);
    }

    /// 拒绝理由的分支顺序与判据逐条对齐上游 `describeRefusal`。
    ///
    /// 每一档都配一条"如果顺序错了会得到什么"的对照：MCP 上下文同时带着空的浏览器字段与空的
    /// `file`，所以只要 file / element 那两档排到前面，答案就会变。
    #[test]
    fn refusal_branch_order_matches_upstream() {
        let mut context = click_submit();

        // 1. command 最先 —— 即使 element 也在场。
        context.command = Some("rm -rf /".to_string());
        context.mcp = Some(McpRef {
            server: "notes".to_string(),
            tool: "search_notes".to_string(),
            effect: McpEffect::Read,
        });
        assert_eq!(
            Refusal::for_context(&context),
            Refusal::Command {
                command: "rm -rf /".to_string()
            }
        );
        assert_eq!(
            Refusal::for_context(&context).subject(),
            RefusalSubject::Command
        );

        // 空串 command 算"不在场"（上游是 JS 真值判断），于是落到下一档。
        context.command = Some(String::new());
        assert_eq!(
            Refusal::for_context(&context),
            Refusal::Mcp {
                server: "notes".to_string(),
                tool: "search_notes".to_string()
            }
        );

        // 2. mcp 先于 file —— 而 MCP 形态的上下文里 file 是在场且全空的。
        context.file = Some(FileRef {
            path: String::new(),
            name: String::new(),
            extension: String::new(),
        });
        assert_eq!(
            Refusal::for_context(&context).subject(),
            RefusalSubject::Mcp
        );

        // 3. 没有 mcp 时，file 的判据是**路径非空**而不是"file 在场"。
        context.mcp = None;
        assert_eq!(
            Refusal::for_context(&context).subject(),
            RefusalSubject::Element,
            "路径为空的 file 不该被当成文件拒绝"
        );
        context.file = Some(FileRef {
            path: "/workspace/secrets.env".to_string(),
            name: "secrets.env".to_string(),
            extension: "env".to_string(),
        });
        assert_eq!(
            Refusal::for_context(&context),
            Refusal::File {
                path: "/workspace/secrets.env".to_string()
            }
        );

        // 4. element.name 非空 → 元素；空名或无 element → 工具 + 主机。
        context.file = None;
        assert_eq!(
            Refusal::for_context(&context),
            Refusal::Element {
                name: "Submit order".to_string(),
                host: "example.com".to_string()
            }
        );
        context.element.as_mut().expect("上面构造过").name = String::new();
        assert_eq!(
            Refusal::for_context(&context),
            Refusal::Tool {
                tool: "computer_click".to_string(),
                host: "example.com".to_string()
            }
        );
        context.element = None;
        assert_eq!(
            Refusal::for_context(&context).subject(),
            RefusalSubject::Tool
        );
    }

    /// 五个 subject 的稳定 code 两两不同 —— 压成同一个字符串，审计就分不开它们。
    #[test]
    fn refusal_codes_are_pairwise_distinct() {
        let subjects = [
            RefusalSubject::Command,
            RefusalSubject::Mcp,
            RefusalSubject::File,
            RefusalSubject::Element,
            RefusalSubject::Tool,
        ];
        let mut codes: Vec<&str> = subjects.iter().map(|subject| subject.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), subjects.len());
        for subject in subjects {
            assert_eq!(subject.to_string(), subject.code());
        }
    }

    /// `source` 的线上取值与上游联合类型逐字相同。
    #[test]
    fn source_wire_values_are_exact() {
        assert_eq!(PolicySource::Deny.as_str(), "deny");
        assert_eq!(PolicySource::Allow.as_str(), "allow");
        assert_eq!(PolicySource::Default.as_str(), "default");
    }

    /// 只有被拒的决策才带 [`Refusal`]。
    #[test]
    fn refusal_is_present_exactly_when_the_action_was_refused() {
        let context = click_submit();
        for (policy, expected_allowed) in [
            (compile(PolicyMode::Enforce, &["true"], &[]), false),
            (compile(PolicyMode::Enforce, &[], &["true"]), true),
            (compile(PolicyMode::Enforce, &[], &[]), false),
            (compile(PolicyMode::DryRun, &["true"], &[]), false),
            (CompiledActionPolicy::unconfigured(), false),
        ] {
            let decision = evaluate(&policy, &context);
            assert_eq!(decision.allowed, expected_allowed);
            assert_eq!(decision.refusal.is_some(), !expected_allowed);
        }
    }
}
