//! 迁移 preflight：换引擎之前，逐条问"这条规则的答案变了吗，变了会怎样"。
//!
//! # 它为什么必须存在（v3 §8.3 条 2）
//!
//! 逐字：「迁移 preflight 对每条已持久化规则在两个引擎上各跑一遍 corpus context，**结果类别**
//! （true / false / error）任一不同即在迁移报告高亮并要求管理员逐条确认后才导入；不确认的部署
//! 不切 policy writer。这是 §8.3『不悄悄收紧或放宽』的机械执行面。」
//!
//! 换句话说：两个引擎不一致**不是缺陷**，是既成事实（`cel-js@0.8.2` 没有字符串方法、`||` 不
//! 短路，标准 CEL 两样都有）。缺陷是**没人知道哪几条规则的含义变了**。本模块把"变了几条"从
//! 一句需要相信的话变成一份可以逐条读的清单。
//!
//! # 报告里最重要的那一列不是"变没变"，是"往哪边变"
//!
//! 同一个类别翻转在两张表上后果相反，所以只报"类别不同"对管理员没用：
//!
//! | 类别变化 | 在 deny 表上 | 在 allow 表上 |
//! | --- | --- | --- |
//! | `error → false` | 本来拒绝，现在不拒 = **放宽** | 本来不放行，现在也不放行 = 不变 |
//! | `error → true` | 本来拒绝，现在也拒 = 不变 | 本来不放行，现在放行 = **放宽** |
//! | `true → error` | 不变（照拒） | 本来放行，现在不放 = 收紧 |
//! | `false → error` | 本来不拒，现在拒 = 收紧 | 不变 |
//!
//! 这张表就是 [`MigrationEffect::on_deny_list`] / [`MigrationEffect::on_allow_list`] 的全部内容。
//! 报告因此能回答那个真正要紧的问题：[`PreflightReport::would_loosen`]。
//!
//! # 为什么两侧都要报，而不是只报规则实际所在的那一侧
//!
//! corpus 里的一条表达式不属于任何一张表 —— 它是一条**语义样本**。同一条规则文本可以被管理员
//! 写进 deny，也可以写进 allow，甚至两张表都有。把两侧后果都摆出来，管理员看的是"这条语义的
//! 变化"，而不是"我这次恰好把它放在哪儿"。

use super::CompiledRule;
use super::cel::ResultKind;
use super::context::PolicyContext;

/// 一条待比对的样本：表达式 + 上下文 + oracle 给出的结果类别。
///
/// 借用而不是持有：调用方（迁移工具、`tests/cel_corpus_parity.rs`）本来就把 corpus 完整读在
/// 内存里，再复制一遍只会让"报告里的表达式"与"被求值的表达式"有机会不是同一个。
#[derive(Clone, Copy, Debug)]
pub struct PreflightCase<'a> {
    /// 样本 id（corpus 里的 `entries[].id`，或迁移工具给已持久化规则铸的 id）。
    pub entry_id: &'a str,
    /// 规则原文。
    pub expression: &'a str,
    /// 上下文的名字，供报告指认是哪一种动作形态。
    pub context_name: &'a str,
    /// 上下文本身。
    pub context: &'a PolicyContext,
    /// oracle（`cel-js@0.8.2`）在这条样本上给出的结果类别。
    pub oracle: ResultKind,
}

/// 一处分歧对某一张表的后果。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationEffect {
    /// 这张表上的行为没变。
    Unchanged,
    /// **放宽**：本来会被挡下的动作，换引擎后能过去了。
    Loosened,
    /// 收紧：本来能过去的动作，换引擎后被挡下了。
    Tightened,
}

impl MigrationEffect {
    /// 稳定的分类标识符，进迁移报告与审计用。**不是文案**（repository contract §4a）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unchanged => "policy_migration_unchanged",
            Self::Loosened => "policy_migration_loosened",
            Self::Tightened => "policy_migration_tightened",
        }
    }

    /// 这条规则**写在 deny 表上**时，类别变化的后果。
    ///
    /// deny 侧 `on_error = true`（见 `super::evaluate::rule_fires`），所以"这条规则会拒绝"
    /// 等价于类别是 `true` 或 `error`。
    #[must_use]
    pub const fn on_deny_list(oracle: ResultKind, candidate: ResultKind) -> Self {
        Self::from_restrictiveness(denies(oracle), denies(candidate))
    }

    /// 这条规则**写在 allow 表上**时，类别变化的后果。
    ///
    /// allow 侧 `on_error = false`，所以只有类别 `true` 才放行；其余（含 `error`）都是"不放行"
    /// —— 而"不放行"是**更严**的一侧，正好与 deny 相反。
    #[must_use]
    pub const fn on_allow_list(oracle: ResultKind, candidate: ResultKind) -> Self {
        Self::from_restrictiveness(!permits(oracle), !permits(candidate))
    }

    /// 两侧共用的判据：以"这个类别会不会让动作被挡下"为轴。
    ///
    /// 把 deny / allow 折进同一个函数是有意的：两侧的**方向**已经由调用点各自算好，
    /// 这里只剩一条判据。写成两份实现，就是本仓反复吃过亏的"同一判据两份实现"。
    const fn from_restrictiveness(before_blocks: bool, after_blocks: bool) -> Self {
        match (before_blocks, after_blocks) {
            (true, false) => Self::Loosened,
            (false, true) => Self::Tightened,
            _ => Self::Unchanged,
        }
    }
}

/// 这个类别在 deny 表上会不会拒绝。
const fn denies(kind: ResultKind) -> bool {
    matches!(kind, ResultKind::True | ResultKind::Error)
}

/// 这个类别在 allow 表上会不会放行。
const fn permits(kind: ResultKind) -> bool {
    matches!(kind, ResultKind::True)
}

/// 两个引擎给出同一个结果类别的样本。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreement {
    /// 样本 id。
    pub entry_id: String,
    /// 上下文名字。
    pub context_name: String,
    /// 双方一致的结果类别。
    pub class: ResultKind,
}

/// 两个引擎给出不同结果类别的样本 —— 报告里要管理员逐条确认的就是这些。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// 样本 id。
    pub entry_id: String,
    /// 规则原文。管理员要靠它在设置页里找到这条规则。
    pub expression: String,
    /// 上下文名字。
    pub context_name: String,
    /// oracle 侧的结果类别。
    pub oracle: ResultKind,
    /// 本引擎的结果类别。
    pub candidate: ResultKind,
    /// 这条规则写在 deny 表上时的后果。
    pub deny_side: MigrationEffect,
    /// 这条规则写在 allow 表上时的后果。
    pub allow_side: MigrationEffect,
}

impl Divergence {
    /// 这处分歧在**任一**张表上是否构成放宽。
    #[must_use]
    pub const fn loosens(&self) -> bool {
        matches!(self.deny_side, MigrationEffect::Loosened)
            || matches!(self.allow_side, MigrationEffect::Loosened)
    }
}

/// 一次 preflight 的完整结论。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreflightReport {
    agreements: Vec<Agreement>,
    divergences: Vec<Divergence>,
}

impl PreflightReport {
    /// 两侧一致的样本，**按输入顺序**。
    ///
    /// 一致项也要留在报告里：一份只列分歧的报告没法回答"那另外那些呢，跑过了吗"。
    #[must_use]
    pub fn agreements(&self) -> &[Agreement] {
        &self.agreements
    }

    /// 分歧项，按输入顺序。
    #[must_use]
    pub fn divergences(&self) -> &[Divergence] {
        &self.divergences
    }

    /// 需不需要管理员逐条确认。
    ///
    /// 判据是**有没有分歧**，不是"有没有放宽"：§8.3 要求的是"不悄悄收紧或放宽"，收紧同样
    /// 需要有人看 —— 一条突然开始拒绝的 allow 规则会让部署以为功能坏了。
    #[must_use]
    pub fn requires_operator_confirmation(&self) -> bool {
        !self.divergences.is_empty()
    }

    /// 这次迁移会不会**悄悄放宽**。
    ///
    /// 这是报告存在的头号理由：收紧会被用户当场发现（活干不了了），放宽不会 —— 它只是让一件
    /// 本该被挡下的事安静地发生。
    #[must_use]
    pub fn would_loosen(&self) -> bool {
        self.divergences.iter().any(Divergence::loosens)
    }

    /// 只挑出会放宽的那些分歧。
    #[must_use]
    pub fn loosening_divergences(&self) -> Vec<&Divergence> {
        self.divergences.iter().filter(|d| d.loosens()).collect()
    }
}

/// 在本引擎上跑一遍全部样本，与 oracle 比对结果类别。
///
/// **每条样本编译一次。** 一条表达式配 M 个 context 就编译 M 次，而编译要 spawn 一条
/// [`super::cel::PARSER_STACK_BYTES`] 的线程 —— 真实迁移是「N 条已持久化规则 × M 个 corpus context」，
/// 走这条入口就是 N×M 次编译，而语义上只需要 N 次。规模上来了请改用 [`run_compiled`]。
///
/// 这条入口保留原样，是因为它是"一条样本自带一段文本"的最简形状，写一次性对照时不必先自己
/// 分组；语义与 [`run_compiled`] 逐字段相同，由 `both_paths_produce_identical_reports` 钉住。
///
/// 编译失败的表达式记作 [`ResultKind::Error`]，与 [`super::CompiledRule`] 的语义一致 ——
/// 一条编译不出来的规则在运行时的表现就是"每次求值都失败"，preflight 必须看到同一件事，
/// 否则报告说的和线上跑的不是一回事。这条一致性不是靠"两边都记得这么写"：本函数**就是**
/// 用 [`super::CompiledRule`] 求值的，与线上同一个类型、同一段代码。
#[must_use]
pub fn run(cases: &[PreflightCase<'_>]) -> PreflightReport {
    let mut report = PreflightReport::default();

    for case in cases {
        let rule = CompiledRule::compile(case.expression);
        let candidate = rule.evaluate(case.context).kind();
        record(
            &mut report,
            case.entry_id,
            case.expression,
            case.context_name,
            case.oracle,
            candidate,
        );
    }

    report
}

/// 一条规则在一个 context 上的一次比对，**不带表达式文本** —— 文本挂在
/// [`PreflightRule`] 上，一条规则一份。
#[derive(Clone, Copy, Debug)]
pub struct PreflightSample<'a> {
    /// 样本 id。
    pub entry_id: &'a str,
    /// 上下文的名字，供报告指认是哪一种动作形态。
    pub context_name: &'a str,
    /// 上下文本身。
    pub context: &'a PolicyContext,
    /// oracle（`cel-js@0.8.2`）在这条样本上给出的结果类别。
    pub oracle: ResultKind,
}

/// 一条规则，加上它要在哪些 context 上被比对。
///
/// 这就是 [`run`] 与 [`run_compiled`] 的全部形状差别：前者把表达式文本挂在**每条样本**上，
/// 后者把**编译结果**挂在规则上、样本只带 context。
#[derive(Clone, Copy, Debug)]
pub struct PreflightRule<'a> {
    /// 已经编译好的规则。原文由 [`super::CompiledRule::source`] 提供，报告直接用它，
    /// 所以"报告里写的规则"与"被求值的规则"在构造上是同一个对象。
    pub rule: &'a CompiledRule,
    /// 这条规则要跑的全部 context。
    pub samples: &'a [PreflightSample<'a>],
}

/// compile-once / evaluate-many：**本函数一次都不编译。**
///
/// # 编译次数是 N，不是 N×M
///
/// 签名只收 `&`[`super::CompiledRule`]，编译由调用方在构造这些规则时各做一次 —— N 条规则
/// N 次，与它们各自要跑多少个 context 无关。[`run`] 那条路径是 N×M 次，而编译一次要 spawn
/// 一条 [`super::cel::PARSER_STACK_BYTES`] = 16 MiB 的线程（理由见 [`super::cel::compile`]），所以 M 一大
/// 那些线程就是纯浪费：同一段文本解析出来的 AST 逐字节相同。
///
/// 本函数体内没有任何 `cel::compile` 调用点，这一点由类型承载而不是靠纪律：它拿不到表达式
/// 文本以外的东西，[`super::CompiledRule`] 已经是编译后的产物。
///
/// # 语义与 [`run`] 逐字段相同
///
/// 两条路径共用同一个判定核心（`record`）与同一个求值类型（[`super::CompiledRule::evaluate`]），
/// 所以"复用编译"不可能顺带改变答案。闸门是 `both_paths_produce_identical_reports`，以及
/// `tests/cel_corpus_parity.rs::both_preflight_paths_agree_on_the_whole_corpus`（在真实 69 条
/// 样本上跑两条路径，断言两份报告逐字段相等）。
///
/// 报告顺序是**规则优先、规则内按样本顺序**。[`run`] 的顺序是样本顺序 —— 想让两者逐字段相等，
/// 喂给 [`run`] 的样本就得按同样的分组次序摊平，上面那两条测试都是这么做的。
#[must_use]
pub fn run_compiled(rules: &[PreflightRule<'_>]) -> PreflightReport {
    let mut report = PreflightReport::default();

    for rule in rules {
        for sample in rule.samples {
            let candidate = rule.rule.evaluate(sample.context).kind();
            record(
                &mut report,
                sample.entry_id,
                rule.rule.source(),
                sample.context_name,
                sample.oracle,
                candidate,
            );
        }
    }

    report
}

/// 把一次比对结果记进报告。**两条入口共用的唯一判定点。**
///
/// 抽出来不是为了少写几行：一致 / 分歧的判据加上两侧后果的计算，如果在 [`run`] 与
/// [`run_compiled`] 各写一份，就是本仓反复吃过亏的"同一判据两份实现" —— 那种实现迟早在
/// 一条路径上被改而另一条没有，而两条路径本来就该给同一个答案。
fn record(
    report: &mut PreflightReport,
    entry_id: &str,
    expression: &str,
    context_name: &str,
    oracle: ResultKind,
    candidate: ResultKind,
) {
    if candidate == oracle {
        report.agreements.push(Agreement {
            entry_id: entry_id.to_string(),
            context_name: context_name.to_string(),
            class: candidate,
        });
    } else {
        report.divergences.push(Divergence {
            entry_id: entry_id.to_string(),
            expression: expression.to_string(),
            context_name: context_name.to_string(),
            oracle,
            candidate,
            deny_side: MigrationEffect::on_deny_list(oracle, candidate),
            allow_side: MigrationEffect::on_allow_list(oracle, candidate),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::context::{ActorRef, BotRef, ElementRef, PageRef, ToolRef};

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

    fn case<'a>(
        id: &'a str,
        expression: &'a str,
        context: &'a PolicyContext,
        oracle: ResultKind,
    ) -> PreflightCase<'a> {
        PreflightCase {
            entry_id: id,
            expression,
            context_name: "click_submit",
            context,
            oracle,
        }
    }

    /// 后果表的四个角，逐格钉死。
    ///
    /// 负向对照就在同一条里：类别相同的那两格是 `Unchanged`，所以这不是一张恒返回
    /// `Loosened` 的表。
    #[test]
    fn the_effect_table_has_four_corners() {
        use MigrationEffect::{Loosened, Tightened, Unchanged};
        use ResultKind::{Error, False, True};

        // error → false：deny 侧放宽，allow 侧不变。
        assert_eq!(MigrationEffect::on_deny_list(Error, False), Loosened);
        assert_eq!(MigrationEffect::on_allow_list(Error, False), Unchanged);
        // error → true：deny 侧不变，allow 侧放宽。
        assert_eq!(MigrationEffect::on_deny_list(Error, True), Unchanged);
        assert_eq!(MigrationEffect::on_allow_list(Error, True), Loosened);
        // true → error：deny 侧不变，allow 侧收紧。
        assert_eq!(MigrationEffect::on_deny_list(True, Error), Unchanged);
        assert_eq!(MigrationEffect::on_allow_list(True, Error), Tightened);
        // false → error：deny 侧收紧，allow 侧不变。
        assert_eq!(MigrationEffect::on_deny_list(False, Error), Tightened);
        assert_eq!(MigrationEffect::on_allow_list(False, Error), Unchanged);
        // true ↔ false 是最直白的一对。
        assert_eq!(MigrationEffect::on_deny_list(True, False), Loosened);
        assert_eq!(MigrationEffect::on_allow_list(True, False), Tightened);
        assert_eq!(MigrationEffect::on_deny_list(False, True), Tightened);
        assert_eq!(MigrationEffect::on_allow_list(False, True), Loosened);
        // 类别没变就什么都没变。
        for kind in [True, False, Error] {
            assert_eq!(MigrationEffect::on_deny_list(kind, kind), Unchanged);
            assert_eq!(MigrationEffect::on_allow_list(kind, kind), Unchanged);
        }
    }

    /// 三个后果的稳定 code 两两不同。
    #[test]
    fn effect_codes_are_pairwise_distinct() {
        let all = [
            MigrationEffect::Unchanged,
            MigrationEffect::Loosened,
            MigrationEffect::Tightened,
        ];
        let mut codes: Vec<&str> = all.iter().map(|effect| effect.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    /// 一致的样本进 agreements，不需要任何人确认。
    ///
    /// 这是整份报告的正向对照：没有它，"分歧被抓到了"这件事在"什么都算分歧"的世界里同样成立。
    #[test]
    fn agreeing_cases_need_no_confirmation() {
        let context = click_submit();
        let report = run(&[
            case(
                "global-form-contains",
                "contains(element.name, \"submit\")",
                &context,
                ResultKind::True,
            ),
            case(
                "contains-miss",
                "contains(element.name, \"cancel\")",
                &context,
                ResultKind::False,
            ),
            case(
                "broken-deny-expression",
                "this is not ( valid cel",
                &context,
                ResultKind::Error,
            ),
        ]);

        assert_eq!(report.divergences().len(), 0);
        assert_eq!(report.agreements().len(), 3);
        assert!(!report.requires_operator_confirmation());
        assert!(!report.would_loosen());
    }

    /// F-CEL-1 的两种形状：`error → false`（deny 侧放宽）与 `error → true`（allow 侧放宽）。
    #[test]
    fn engine_divergences_are_flagged_with_their_direction() {
        let context = click_submit();
        let report = run(&[
            case(
                "method-form-contains",
                "element.name.contains(\"submit\")",
                &context,
                ResultKind::Error,
            ),
            case(
                "method-form-startswith",
                "element.name.startsWith(\"Submit\")",
                &context,
                ResultKind::Error,
            ),
        ]);

        assert_eq!(report.agreements().len(), 0);
        assert_eq!(report.divergences().len(), 2);
        assert!(report.requires_operator_confirmation());
        assert!(report.would_loosen());

        let contains = &report.divergences()[0];
        assert_eq!(contains.entry_id, "method-form-contains");
        assert_eq!(contains.oracle, ResultKind::Error);
        assert_eq!(contains.candidate, ResultKind::False);
        assert_eq!(contains.deny_side, MigrationEffect::Loosened);
        assert_eq!(contains.allow_side, MigrationEffect::Unchanged);

        let starts_with = &report.divergences()[1];
        assert_eq!(starts_with.candidate, ResultKind::True);
        assert_eq!(starts_with.deny_side, MigrationEffect::Unchanged);
        assert_eq!(starts_with.allow_side, MigrationEffect::Loosened);

        assert_eq!(report.loosening_divergences().len(), 2);
    }

    /// 只收紧的迁移**仍然**要人确认，但 `would_loosen` 必须答 `false`。
    ///
    /// 这条是 [`PreflightReport::would_loosen`] 的负向对照：没有它，一个恒返回 `true` 的
    /// 实现也能让上一条测试通过。
    ///
    /// oracle 值在这里是**构造出来**的（真实 corpus 里没有 `true → error` 的样本）——
    /// oracle 是数据不是代码，构造一个类别翻转正是在测这张后果表。
    #[test]
    fn a_tightening_only_migration_still_needs_confirmation() {
        let context = click_submit();
        // `repeat.count` 在本引擎上是 error；把 oracle 记成 true 就构造出 `true → error`。
        let report = run(&[case(
            "synthetic-tightening",
            "repeat.count",
            &context,
            ResultKind::True,
        )]);

        assert_eq!(report.divergences().len(), 1);
        let divergence = &report.divergences()[0];
        assert_eq!(divergence.deny_side, MigrationEffect::Unchanged);
        assert_eq!(divergence.allow_side, MigrationEffect::Tightened);
        assert!(!divergence.loosens());
        assert!(report.requires_operator_confirmation());
        assert!(!report.would_loosen(), "只收紧的迁移不应被报成放宽");
        assert_eq!(report.loosening_divergences().len(), 0);
    }

    /// 编译失败的规则在 preflight 里也记 `error` —— 与它在线上求值时的表现一致。
    #[test]
    fn an_uncompilable_rule_is_reported_as_error_not_skipped() {
        let context = click_submit();
        let too_deep = format!(
            "{}true{}",
            "(".repeat(crate::policy::cel::guard::MAX_EXPRESSION_DEPTH + 1),
            ")".repeat(crate::policy::cel::guard::MAX_EXPRESSION_DEPTH + 1)
        );
        let report = run(&[case("too-deep", &too_deep, &context, ResultKind::True)]);
        assert_eq!(report.divergences().len(), 1);
        assert_eq!(report.divergences()[0].candidate, ResultKind::Error);
    }

    /// 报告保持输入顺序 —— 管理员逐条确认时看到的顺序必须和迁移工具喂进去的一致。
    #[test]
    fn report_preserves_input_order() {
        let context = click_submit();
        let report = run(&[
            case(
                "a",
                "element.name.contains(\"submit\")",
                &context,
                ResultKind::Error,
            ),
            case(
                "b",
                "element.name.endsWith(\"order\")",
                &context,
                ResultKind::Error,
            ),
            case(
                "c",
                "element.name.startsWith(\"Submit\")",
                &context,
                ResultKind::Error,
            ),
        ]);
        let ids: Vec<&str> = report
            .divergences()
            .iter()
            .map(|divergence| divergence.entry_id.as_str())
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }

    /// 造 M 份互不相同的 context：`page.host` 各不相同，好让规则在它们上面给出不同答案 ——
    /// 全都一样的话，"跑了 M 次"和"跑了 1 次再复制 M 份"在报告上不可区分。
    fn distinct_contexts(count: usize) -> Vec<PolicyContext> {
        (0..count)
            .map(|index| {
                let mut context = click_submit();
                context.page.host = format!("host-{index}.example.com");
                context
            })
            .collect()
    }

    /// **两条路径逐字段相等**，而复用路径只编译 N 次。
    ///
    /// 编译次数在这条测试里是**测试自己数出来的**，不是靠相信实现：`rules` 这个 `Vec` 是本测试
    /// 一条一条 `CompiledRule::compile` 出来的，它的长度就是编译次数（N=2）。[`run`] 那条路径
    /// 对同一批数据要编译 `cases.len()`（N×M=50）次。断言把这两个数字直接摆在一起，所以
    /// "50 降到 2"是可读的算术，不是一句注释。
    ///
    /// 正向对照有两处，缺任一条这个测试都测不到东西：
    ///
    /// 1. 两份报告**逐字段相等**（含顺序、含 `expression` 原文、含两侧后果），所以复用编译没有
    ///    顺带改变任何答案；
    /// 2. 报告里同时有一致项和分歧项（下面两条 `assert!`）—— 否则一份空报告、或一份"什么都算
    ///    分歧"的报告，也能让第 1 条成立。
    #[test]
    fn both_paths_produce_identical_reports() {
        let contexts = distinct_contexts(25);
        // 两条规则：一条在部分 host 上命中，一条是引擎分歧样本。
        let expressions = [
            "contains(page.host, \"host-7.\")",
            "element.name.startsWith(\"Submit\")",
        ];

        // 复用路径：本测试亲手编译 N 次。
        let rules: Vec<CompiledRule> = expressions
            .iter()
            .map(|e| CompiledRule::compile(e))
            .collect();
        assert_eq!(rules.len(), 2, "N = 2 次编译");

        // 样本按「规则优先」摊平，好让两条路径的报告顺序一致。
        let mut samples_per_rule: Vec<Vec<PreflightSample<'_>>> = Vec::new();
        let mut flat_cases: Vec<PreflightCase<'_>> = Vec::new();
        for (rule_index, expression) in expressions.iter().enumerate() {
            let mut samples = Vec::new();
            for (context_index, context) in contexts.iter().enumerate() {
                // oracle 一律记 error：真实 corpus 里这两条形状的 oracle 就是 error，
                // 而且它保证报告里两类都有（规则一在多数 host 上答 false → 分歧，
                // 在 host-7 上答 true → 仍是分歧；规则二恒 true → 分歧）。
                let oracle = if rule_index == 0 && context_index == 7 {
                    ResultKind::True
                } else {
                    ResultKind::Error
                };
                let entry_id: &'static str = ENTRY_IDS[rule_index * 25 + context_index];
                let context_name: &'static str = CONTEXT_NAMES[context_index];
                samples.push(PreflightSample {
                    entry_id,
                    context_name,
                    context,
                    oracle,
                });
                flat_cases.push(PreflightCase {
                    entry_id,
                    expression,
                    context_name,
                    context,
                    oracle,
                });
            }
            samples_per_rule.push(samples);
        }
        assert_eq!(flat_cases.len(), 50, "N×M = 50 次编译（run 那条路径）");

        let compiled_rules: Vec<PreflightRule<'_>> = rules
            .iter()
            .zip(samples_per_rule.iter())
            .map(|(rule, samples)| PreflightRule {
                rule,
                samples: samples.as_slice(),
            })
            .collect();

        let compiling_path = run(&flat_cases);
        let reusing_path = run_compiled(&compiled_rules);

        assert_eq!(
            compiling_path, reusing_path,
            "复用编译的路径必须与逐条编译的路径逐字段相等"
        );
        assert!(
            !reusing_path.agreements().is_empty(),
            "正向对照：报告里必须有一致项，否则空报告也能让上面那条相等成立"
        );
        assert!(
            !reusing_path.divergences().is_empty(),
            "正向对照：报告里必须有分歧项"
        );
        assert_eq!(
            reusing_path.agreements().len() + reusing_path.divergences().len(),
            50,
            "50 个样本一条都不能丢"
        );
        // 复用路径的编译次数（2）严格小于逐条路径（50）——这就是本条要买的东西。
        assert!(rules.len() < flat_cases.len());
    }

    /// 复用路径上，一条**编译不出来**的规则在它的每个 context 上都返回 `error`。
    ///
    /// 它证明 [`run_compiled`] 没有偷偷跳过坏规则（跳过会让报告少几行而不是多几条分歧），
    /// 也证明 [`super::CompiledRule`] 那条"坏规则被保留成一求值就失败的条目"的语义确实被复用
    /// 路径继承了。正向对照是同一条测试里的好规则：它在同一批 context 上给出真答案。
    #[test]
    fn a_broken_rule_stays_broken_across_every_context_on_the_reused_path() {
        let contexts = distinct_contexts(3);
        let broken = CompiledRule::compile("this is not ( valid cel");
        let healthy = CompiledRule::compile("contains(element.name, \"submit\")");

        let broken_samples: Vec<PreflightSample<'_>> = contexts
            .iter()
            .enumerate()
            .map(|(index, context)| PreflightSample {
                entry_id: ENTRY_IDS[index],
                context_name: CONTEXT_NAMES[index],
                context,
                oracle: ResultKind::True,
            })
            .collect();
        let healthy_samples: Vec<PreflightSample<'_>> = contexts
            .iter()
            .enumerate()
            .map(|(index, context)| PreflightSample {
                entry_id: ENTRY_IDS[25 + index],
                context_name: CONTEXT_NAMES[index],
                context,
                oracle: ResultKind::True,
            })
            .collect();

        let report = run_compiled(&[
            PreflightRule {
                rule: &broken,
                samples: &broken_samples,
            },
            PreflightRule {
                rule: &healthy,
                samples: &healthy_samples,
            },
        ]);

        // 坏规则：3 个 context 全是 error，全部与 oracle(true) 分歧。
        assert_eq!(report.divergences().len(), 3);
        for divergence in report.divergences() {
            assert_eq!(divergence.candidate, ResultKind::Error);
            assert_eq!(divergence.expression, "this is not ( valid cel");
        }
        // 正向对照：好规则在同一批 context 上答出真答案，与 oracle 一致。
        assert_eq!(report.agreements().len(), 3);
        for agreement in report.agreements() {
            assert_eq!(agreement.class, ResultKind::True);
        }
    }

    /// 报告里的规则原文取自 [`super::CompiledRule::source`]，与被求值的对象是同一个。
    #[test]
    fn the_reused_path_reports_the_rule_text_it_actually_evaluated() {
        let contexts = distinct_contexts(1);
        let rule = CompiledRule::compile("element.name.endsWith(\"order\")");
        let samples = [PreflightSample {
            entry_id: ENTRY_IDS[0],
            context_name: CONTEXT_NAMES[0],
            context: &contexts[0],
            oracle: ResultKind::Error,
        }];
        let report = run_compiled(&[PreflightRule {
            rule: &rule,
            samples: &samples,
        }]);
        assert_eq!(report.divergences().len(), 1);
        assert_eq!(report.divergences()[0].expression, rule.source());
        assert_eq!(report.divergences()[0].candidate, ResultKind::True);
    }

    /// 给上面几条测试用的定值 id / context 名。
    ///
    /// 写成 `&'static str` 表而不是 `format!` 出来的 `String`：`PreflightSample` 借用它们，
    /// 而借用一个循环内临时 `String` 编译不过 —— 与其在测试里绕一圈存活期，不如把 50 个名字
    /// 直接列出来，读起来也更像它模拟的那份 corpus。
    const ENTRY_IDS: [&str; 50] = [
        "e00", "e01", "e02", "e03", "e04", "e05", "e06", "e07", "e08", "e09", "e10", "e11", "e12",
        "e13", "e14", "e15", "e16", "e17", "e18", "e19", "e20", "e21", "e22", "e23", "e24", "e25",
        "e26", "e27", "e28", "e29", "e30", "e31", "e32", "e33", "e34", "e35", "e36", "e37", "e38",
        "e39", "e40", "e41", "e42", "e43", "e44", "e45", "e46", "e47", "e48", "e49",
    ];

    /// 25 个 context 名，与 [`ENTRY_IDS`] 同理。
    const CONTEXT_NAMES: [&str; 25] = [
        "c00", "c01", "c02", "c03", "c04", "c05", "c06", "c07", "c08", "c09", "c10", "c11", "c12",
        "c13", "c14", "c15", "c16", "c17", "c18", "c19", "c20", "c21", "c22", "c23", "c24",
    ];
}
