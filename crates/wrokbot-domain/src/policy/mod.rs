//! 一个 Bot 可不可以在某一页上做某一件事（v3 §8.3）。
//!
//! # 形状取自上游，不是重新推导的
//!
//! 真源是 `server/src/computer/policy.ts`。保留的东西：CEL 表达式、`dry-run` / `enforce` 两档、
//! default-deny、fail-closed 求值，以及 **deny 先于 allow**。上游对最后这条的理由值得原样搬
//! 过来：一条收回权限的规则绝不能被一条更宽的授权规则打败，否则一个部署没法推理"我到底禁掉了
//! 什么"。
//!
//! 用表达式而不是规则表，理由同样是上游的：企业想要的边界是**一句话**（"绝不点击我们自己域
//! 之外任何写着 Submit 的东西"）。一张列固定的表只能表达我们想到的形态，表达式语言能表达他们
//! 想到的那个。
//!
//! # 本项目的三处**有意偏离**
//!
//! 1. **拒绝理由不是散文，是类型**（repository contract §4a：文案不进 domain）。上游 `describeRefusal`
//!    产出一段面向人的英文；这里产出 [`evaluate::Refusal`] —— 一个封闭枚举加结构化字段，
//!    GUI 自己组句、自己本地化。**分支顺序与判据逐条照抄上游**（command → mcp → file →
//!    element / page），因为那个顺序本身有理由：一次 MCP 调用的浏览器字段全是刻意留空的，
//!    不先认它就会得到"the file  is blocked"这种指向它从未碰过的工作区的说法。
//! 2. **版本由内容派生**（[`PolicyVersion`]）。`action_policy` 表的主键按构造恒为常量
//!    `'current'`，表里没有版本列（`parity/tables.yaml::tbl-action-policy`）。拿 `updated_at`
//!    当版本，会让一次内容完全相同的重写白白作废所有既有 approval（§8.5：版本变化后旧批准
//!    失效）。
//! 3. **"没有策略文档"是一个类型状态**（[`CompiledActionPolicy::Unconfigured`]），不是
//!    `Option<ActionPolicy>`。§8.3 逐字：「新安装没有隐式 `allow: ["true"]`……在完成前所有
//!    acting tool deny。」把它交给 `Option`，就是把 default-deny 交给每个调用点自己记得。
//!
//! # 多 replica 下为什么每个 decision 都要带版本
//!
//! §8.3 沿用上游 `policy-listener.ts` 的形态：`LISTEN/NOTIFY` 只做唤醒，每个 replica 收到通知
//! 或重连后整表重读。传播不是瞬时的，所以**一个 replica 用旧版本做出的 decision 必须在 audit
//! 里可辨认** —— 这就是 [`evaluate::PolicyDecision::policy_version`] 存在的全部理由。

pub mod cel;
pub mod context;
pub mod evaluate;
pub mod preflight;

use core::fmt;
use core::str::FromStr;

use sha2::{Digest, Sha256};

pub use cel::{CelFailure, CelTypeName, CompiledExpression, ResultClass, ResultKind};
pub use context::{
    ActorRef, BotRef, ElementRef, FileRef, Intent, McpEffect, McpRef, PageRef, PolicyContext,
    ToolRef,
};
pub use evaluate::{PolicyDecision, PolicySource, Refusal, RefusalSubject, evaluate};
pub use preflight::{
    MigrationEffect, PreflightCase, PreflightReport, PreflightRule, PreflightSample,
};

/// 策略是拦截还是只记录。
///
/// `dry-run` 存在的理由（上游原话）：运维要能拿真实流量试一条规则、读完审计再让它开始拒绝
/// 别人的活。**一个没人敢打开的治理功能不是治理功能。**
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyMode {
    /// 拦截。缺省档 —— 上游 `evaluateActionPolicy` 的 `policy?.mode ?? "enforce"` 同义。
    #[default]
    Enforce,
    /// 决策照做、审计照写，但动作照样放行。
    DryRun,
}

impl PolicyMode {
    /// 稳定的线上表示。
    ///
    /// `action_policy.mode` 是 **text 不是 enum**（`parity/tables.yaml::tbl-action-policy`），
    /// 所以这两个字符串就是落库的字节，改一个字符就是一次数据迁移。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::DryRun => "dry-run",
        }
    }
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析 [`PolicyMode`] 失败。
///
/// 刻意不回落：唯一"安全"的回落是 [`PolicyMode::Enforce`]，而静默地把一份被管理员设成
/// dry-run 的策略变成拦截档，会让人以为是功能坏了而不是数据坏了。加载方必须自己决定，
/// 并且必须把它当故障记录 —— 一个 mode 列里出现第三个取值本身就是一次事故。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown_policy_mode")]
pub struct UnknownPolicyMode;

impl FromStr for PolicyMode {
    type Err = UnknownPolicyMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "dry-run" => Ok(Self::DryRun),
            _ => Err(UnknownPolicyMode),
        }
    }
}

/// 一份策略文档的**原文**形态：从 `action_policy` 行读上来是什么样，这里就是什么样。
///
/// 规则文本没有在这一层被解析 —— 解析发生在 [`CompiledActionPolicy::compile`]，而且**解析失败
/// 不阻止加载**（理由见 [`CompiledRule`]）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionPolicy {
    /// 拦截还是只记录。
    pub mode: PolicyMode,
    /// 先求值。任一条为真即拒绝，**无论 allow 说什么**。
    pub deny: Vec<String>,
    /// 任一条为真即放行。**空列表意味着什么都不放行。**
    pub allow: Vec<String>,
}

impl ActionPolicy {
    /// 这份策略的内容版本。
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        PolicyVersion::of(self)
    }
}

/// 一份策略的**内容**版本：`sha256` over 一段无歧义的规范编码。
///
/// # 为什么必须是内容派生
///
/// `action_policy` 的主键按构造恒为常量 `'current'`，每次保存都是对同一行的 upsert，表里没有
/// 版本列。可用的替代品只有 `updated_at`，而它会让一次**内容完全相同**的重写（管理员点开设置
/// 页又点了保存）作废全部既有 approval —— §8.5 规定版本变化即旧批准失效。
///
/// # 为什么编码必须无歧义
///
/// 朴素做法是把规则用换行拼起来再摘要。那样 `deny = ["a", "b"]` 与 `deny = ["a\nb"]` 得到同一
/// 个版本 —— 两份语义完全不同的策略共用一个版本号，于是针对前者签发的 approval 在后者下继续
/// 有效。本实现给每个片段加 `u64` 长度前缀、给每个列表加元素计数前缀，任何分隔符都不再有歧义；
/// 闸门是 `version_encoding_has_no_concatenation_ambiguity`。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion([u8; 32]);

/// 已配置策略的域分隔串。
const CONFIGURED_VERSION_DOMAIN: &[u8] = b"openbot.action-policy.v1";

/// **未配置**部署的域分隔串。
///
/// 它与 [`CONFIGURED_VERSION_DOMAIN`] 不同，是为了让"管理员保存了一份空策略"与"这个部署从来
/// 没跑过首次设置向导"在审计里可分辨 —— 前者是一次决定，后者是一次缺席。
const UNCONFIGURED_VERSION_DOMAIN: &[u8] = b"openbot.action-policy.unconfigured.v1";

impl PolicyVersion {
    /// 一份策略文档的版本。
    #[must_use]
    pub fn of(policy: &ActionPolicy) -> Self {
        let mut hasher = Sha256::new();
        absorb(&mut hasher, CONFIGURED_VERSION_DOMAIN);
        absorb(&mut hasher, policy.mode.as_str().as_bytes());
        absorb_list(&mut hasher, &policy.deny);
        absorb_list(&mut hasher, &policy.allow);
        Self(hasher.finalize().into())
    }

    /// 尚未完成首次设置的部署所用的版本。
    ///
    /// 它仍然是一个**真**版本号而不是全零占位：§8.3 要求每个 decision 都带版本，而"设置向导
    /// 完成之前做出的拒绝"同样要在 audit 里能被指认。
    #[must_use]
    pub fn unconfigured() -> Self {
        let mut hasher = Sha256::new();
        absorb(&mut hasher, UNCONFIGURED_VERSION_DOMAIN);
        Self(hasher.finalize().into())
    }

    /// 摘要原始字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 小写十六进制表示，64 个字符。审计行与 approval 绑定用的就是它。
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PolicyVersion {
    /// 与 [`fmt::Display`] 同形。
    ///
    /// 手写而不是 `derive`：`derive` 会打出 32 个十进制数字的数组，人没法把它和审计行里的
    /// 十六进制串对上 —— 一个对不上号的调试输出等于没有调试输出。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyVersion({})", self.to_hex())
    }
}

/// 吸收一个**长度前缀**过的片段。
fn absorb(hasher: &mut Sha256, frame: &[u8]) {
    hasher.update((frame.len() as u64).to_le_bytes());
    hasher.update(frame);
}

/// 吸收一个列表：先元素个数，再逐个吸收。
///
/// 个数前缀不能省：没有它，`deny = ["a"] / allow = ["b"]` 与 `deny = ["a", "b"] / allow = []`
/// 会喂给摘要完全相同的字节流。
fn absorb_list(hasher: &mut Sha256, items: &[String]) {
    hasher.update((items.len() as u64).to_le_bytes());
    for item in items {
        absorb(hasher, item.as_bytes());
    }
}

/// 一条规则：原文，加上"它编译出来了没有"。
///
/// # 编译失败**不**阻止策略加载
///
/// 这是一条从上游原样继承的语义，不是宽容：上游把 `evaluate()` 包在 `matches()` 的 `try/catch`
/// 里，于是一条坏规则在 deny 侧照旧拒绝、在 allow 侧照旧不放行。若改成"加载时校验，坏规则拒绝
/// 整份策略"，一次手误就会让整个部署失去策略 —— 而失去策略的部署要么什么都做不了（default-deny
/// 全拦），要么更糟：有人为了把它救回来临时清空 deny 列表。
///
/// 所以坏规则在这里被保留成"一求值就返回那个 [`CelFailure`]"的条目，语义与上游逐条相同。
#[derive(Debug)]
pub struct CompiledRule {
    source: String,
    compiled: Result<CompiledExpression, CelFailure>,
}

impl CompiledRule {
    /// 编译一条规则。**永不失败** —— 失败被记进条目本身。
    #[must_use]
    pub fn compile(source: &str) -> Self {
        Self {
            source: source.to_string(),
            compiled: cel::compile(source),
        }
    }

    /// 规则原文。
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// 编译期失败（如果有）。给设置页做"这条规则坏了"的标注用。
    #[must_use]
    pub fn compile_failure(&self) -> Option<CelFailure> {
        self.compiled.as_ref().err().copied()
    }

    /// 对一份上下文求值。编译失败的规则**每次**都返回它当初的失败。
    #[must_use]
    pub fn evaluate(&self, context: &PolicyContext) -> ResultClass {
        match &self.compiled {
            Ok(expression) => expression.evaluate(context),
            Err(failure) => ResultClass::Error(*failure),
        }
    }
}

/// 可以直接拿来做判定的策略。**两个状态，没有第三个。**
///
/// 用枚举而不是 `Option<…>`：§8.3 的"新安装没有隐式 allow"必须由类型承载。`Option` 会让
/// default-deny 变成每个调用点自己要记得的事，而 [`evaluate()`] 对这两个状态都给得出答案。
#[derive(Debug)]
pub enum CompiledActionPolicy {
    /// 这个部署还没完成首次设置向导：**任何 acting tool 都不放行**。
    ///
    /// 上游对"没有策略"的读法是同一条：An unconfigured deployment is one that has not said what
    /// its Bots may do, and the safe reading of silence is "nothing", not "anything".
    Unconfigured,
    /// 管理员保存过一份有版本的策略。
    Configured(CompiledRules),
}

/// 一份已保存策略编译后的样子。
#[derive(Debug)]
pub struct CompiledRules {
    mode: PolicyMode,
    version: PolicyVersion,
    deny: Vec<CompiledRule>,
    allow: Vec<CompiledRule>,
}

impl CompiledRules {
    /// 拦截还是只记录。
    #[must_use]
    pub const fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// 内容版本。
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// deny 列表，**保持管理员写下的顺序**。
    ///
    /// 顺序是可观察的：决策里的 `matched` 是**第一条**命中的规则，运维要靠它找到那条规则。
    #[must_use]
    pub fn deny(&self) -> &[CompiledRule] {
        &self.deny
    }

    /// allow 列表，同样保持原顺序。
    #[must_use]
    pub fn allow(&self) -> &[CompiledRule] {
        &self.allow
    }
}

impl CompiledActionPolicy {
    /// 尚未完成首次设置的部署。
    #[must_use]
    pub const fn unconfigured() -> Self {
        Self::Unconfigured
    }

    /// 编译一份已保存的策略。每条规则编译一次并缓存。
    #[must_use]
    pub fn compile(policy: &ActionPolicy) -> Self {
        Self::Configured(CompiledRules {
            mode: policy.mode,
            version: policy.version(),
            deny: policy
                .deny
                .iter()
                .map(|rule| CompiledRule::compile(rule))
                .collect(),
            allow: policy
                .allow
                .iter()
                .map(|rule| CompiledRule::compile(rule))
                .collect(),
        })
    }

    /// 生效的 mode。
    ///
    /// 未配置的部署报 [`PolicyMode::Enforce`]：`dry-run` 是管理员对一份**已经写下来的**策略
    /// 做出的选择，一个还没写下任何东西的部署没有资格声称自己在试运行。
    #[must_use]
    pub const fn mode(&self) -> PolicyMode {
        match self {
            Self::Unconfigured => PolicyMode::Enforce,
            Self::Configured(rules) => rules.mode,
        }
    }

    /// 生效的版本。两个状态都有真版本，理由见 [`PolicyVersion::unconfigured`]。
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        match self {
            Self::Unconfigured => PolicyVersion::unconfigured(),
            Self::Configured(rules) => rules.version,
        }
    }

    /// 是否已完成首次设置。
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        matches!(self, Self::Configured(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::context::{ActorRef, BotRef, ElementRef, PageRef, ToolRef};

    fn policy(mode: PolicyMode, deny: &[&str], allow: &[&str]) -> ActionPolicy {
        ActionPolicy {
            mode,
            deny: deny.iter().map(|rule| (*rule).to_string()).collect(),
            allow: allow.iter().map(|rule| (*rule).to_string()).collect(),
        }
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

    /// mode 的线上取值逐字对齐 `action_policy.mode` 列里的字节。
    #[test]
    fn mode_wire_values_are_exact() {
        assert_eq!(PolicyMode::Enforce.as_str(), "enforce");
        assert_eq!(PolicyMode::DryRun.as_str(), "dry-run");
        assert_eq!(PolicyMode::from_str("enforce"), Ok(PolicyMode::Enforce));
        assert_eq!(PolicyMode::from_str("dry-run"), Ok(PolicyMode::DryRun));
        // 负向对照：相近但不相同的写法必须被拒，不能"猜"。
        assert_eq!(PolicyMode::from_str("dry_run"), Err(UnknownPolicyMode));
        assert_eq!(PolicyMode::from_str("DRY-RUN"), Err(UnknownPolicyMode));
        assert_eq!(PolicyMode::from_str(""), Err(UnknownPolicyMode));
        // 缺席的策略读作 enforce，与上游 `policy?.mode ?? "enforce"` 同义。
        assert_eq!(PolicyMode::default(), PolicyMode::Enforce);
    }

    /// 内容相同 ⇒ 版本相同。这正是不能用 `updated_at` 当版本的那条理由的正面。
    #[test]
    fn identical_content_yields_an_identical_version() {
        let first = policy(PolicyMode::Enforce, &["a", "b"], &["c"]);
        let second = policy(PolicyMode::Enforce, &["a", "b"], &["c"]);
        assert_eq!(first.version(), second.version());
    }

    /// 规范编码没有拼接歧义 —— 任何一处不同都必须换来不同的版本。
    ///
    /// 三组构造分别打击三种朴素编码：
    /// 1. 用分隔符连接列表元素（`["a","b"]` vs `["a\u{1}b"]`）；
    /// 2. 不带元素计数（deny/allow 之间的边界可以滑动）；
    /// 3. 不带 mode。
    ///
    /// 负向对照是上一条测试：内容相同的两份**确实**同版本，所以本条不是在"版本恒不同"的
    /// 世界里成立的。
    #[test]
    fn version_encoding_has_no_concatenation_ambiguity() {
        let split = policy(PolicyMode::Enforce, &["a", "b"], &[]);
        let joined_with_separator = policy(PolicyMode::Enforce, &["a\u{1}b"], &[]);
        let joined_with_newline = policy(PolicyMode::Enforce, &["a\nb"], &[]);
        assert_ne!(split.version(), joined_with_separator.version());
        assert_ne!(split.version(), joined_with_newline.version());

        let boundary_left = policy(PolicyMode::Enforce, &["a"], &["b"]);
        let boundary_right = policy(PolicyMode::Enforce, &["a", "b"], &[]);
        assert_ne!(boundary_left.version(), boundary_right.version());

        let enforcing = policy(PolicyMode::Enforce, &["a"], &["b"]);
        let dry_running = policy(PolicyMode::DryRun, &["a"], &["b"]);
        assert_ne!(enforcing.version(), dry_running.version());

        // 空串规则不是"没有规则"。
        let empty_rule = policy(PolicyMode::Enforce, &[""], &[]);
        let no_rule = policy(PolicyMode::Enforce, &[], &[]);
        assert_ne!(empty_rule.version(), no_rule.version());
    }

    /// "管理员存了一份空策略" ≠ "这个部署从没设置过"。
    ///
    /// 两者在行为上都拒绝一切，但在审计上是两件事：前者是一次决定，后者是一次缺席。
    #[test]
    fn an_empty_saved_policy_is_not_an_unconfigured_deployment() {
        let saved_empty = CompiledActionPolicy::compile(&policy(PolicyMode::Enforce, &[], &[]));
        let never_configured = CompiledActionPolicy::unconfigured();
        assert_ne!(saved_empty.version(), never_configured.version());
        assert!(saved_empty.is_configured());
        assert!(!never_configured.is_configured());
        // 未配置的部署报 enforce，而不是"没有 mode"。
        assert_eq!(never_configured.mode(), PolicyMode::Enforce);
    }

    /// 版本的十六进制表示是 64 个小写十六进制字符，`Display` 与 `to_hex` 同源。
    #[test]
    fn version_hex_is_stable_and_lowercase() {
        let hex = policy(PolicyMode::Enforce, &["a"], &[]).version().to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        assert_eq!(
            policy(PolicyMode::Enforce, &["a"], &[])
                .version()
                .to_string(),
            hex
        );
        assert!(format!("{:?}", policy(PolicyMode::Enforce, &["a"], &[]).version()).contains(&hex));
    }

    /// 坏规则不阻止编译整份策略，并且**每次**求值都还给同一个失败。
    ///
    /// 正向对照在同一条里：同一份策略里的好规则照常求值。没有它，本条在"编译恒失败"的世界里
    /// 同样通过。
    #[test]
    fn a_broken_rule_is_kept_as_a_rule_that_always_fails() {
        let compiled = CompiledActionPolicy::compile(&policy(
            PolicyMode::Enforce,
            &["this is not ( valid cel"],
            &["contains(element.name, \"submit\")"],
        ));
        let CompiledActionPolicy::Configured(rules) = &compiled else {
            panic!("刚编译出来的必须是 Configured");
        };

        let broken = &rules.deny()[0];
        assert_eq!(broken.compile_failure(), Some(CelFailure::Parse));
        assert_eq!(broken.source(), "this is not ( valid cel");
        let context = click_submit();
        assert_eq!(
            broken.evaluate(&context),
            ResultClass::Error(CelFailure::Parse)
        );
        // 第二次求值给同一个答案 —— 它是一个稳定的条目，不是一次性的加载错误。
        assert_eq!(
            broken.evaluate(&context),
            ResultClass::Error(CelFailure::Parse)
        );

        let healthy = &rules.allow()[0];
        assert_eq!(healthy.compile_failure(), None);
        assert_eq!(healthy.evaluate(&context), ResultClass::True);
    }

    /// 规则顺序被保留：决策里的 `matched` 指的是**第一条**命中的规则。
    #[test]
    fn rule_order_is_preserved() {
        let compiled = CompiledActionPolicy::compile(&policy(
            PolicyMode::Enforce,
            &[
                "page.host == \"a\"",
                "page.host == \"b\"",
                "page.host == \"c\"",
            ],
            &[],
        ));
        let CompiledActionPolicy::Configured(rules) = &compiled else {
            panic!("刚编译出来的必须是 Configured");
        };
        let sources: Vec<&str> = rules.deny().iter().map(CompiledRule::source).collect();
        assert_eq!(
            sources,
            [
                "page.host == \"a\"",
                "page.host == \"b\"",
                "page.host == \"c\""
            ]
        );
    }
}
