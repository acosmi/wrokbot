//! CEL 求值器 —— 编译一次、求值多次，且**失败永远是三类之一**。
//!
//! # 这一层要解决的三件事
//!
//! 1. **解析不能打死进程**。`cel 0.14.3` 的解析器是递归下降，栈消耗随括号嵌套线性增长，而
//!    Rust 的栈溢出是 abort 不是 panic。表达式来自管理员可写的列，于是"一条写歪的规则打死
//!    进程"是一条真实路径。[`guard::check`] 在解析前拦掉过深的输入，[`compile`] 再把解析放到
//!    栈大小写死的线程上 —— 两件事缺一不可，实测数据与推理见 [`guard`] 的模块文档。
//! 2. **失败必须被压成封闭分类**。`cel::ExecutionError` 的若干变体把参与运算的 `Value` 塞进
//!    错误本体，`Display` 会把 context 取值逐字打出来。所以本模块的分类**只匹配变体**，
//!    不读消息文本，并且 `cel::ExecutionError` 的 `Display` 一个字节都不出本模块。理由与实测
//!    样例见 [`failure`] 的模块文档，闸门是 `context_values_never_leak_through_the_failure_type`。
//! 3. **结果只有三类**。上游 `server/src/computer/policy.ts::matches` 把"抛错"与"答出非布尔"
//!    归入同一条 fail-closed 路径，`false` 则是真答案。[`ResultKind`] 的三个取值与
//!    `fixtures/policy/cel-corpus.json` 的 `result_class_vocabulary` 逐字对齐，因为迁移
//!    preflight（[`super::preflight`]）比对的就是这个类别。
//!
//! # 为什么"编译一次"值得单独有个类型
//!
//! [`CompiledExpression`] 存在的理由不是性能，是**语义**：一条编译不出来的规则必须在**每次
//! 求值时**都表现为失败（deny 侧照拒、allow 侧不放行），而不是在加载策略时把整份策略拒之门外。
//! 上游是靠 `matches()` 里的 `try/catch` 在求值时兜住的；本项目把这条语义搬进
//! [`super::CompiledRule`]，[`CompiledExpression`] 只负责"编译成功的那一半"。

pub mod failure;
pub mod globals;
pub mod guard;

use core::fmt;
use core::str::FromStr;

pub use failure::{CelFailure, CelTypeName};

use super::context::{PolicyContext, bind_policy_context};

/// 解析线程的栈大小：**16 MiB**。
///
/// 它与 [`guard::MAX_EXPRESSION_DEPTH`] 是一对，不能单独改。取值依据是 [`guard`] 模块文档
/// **已记录的**那张实测深度表（斜率约每 MiB 6 层），本模块不重复它：按那张表折算，16 MiB 的
/// 崩溃点在 96 层附近，对上限 8 有约 12 倍余量。改这里必须连那张表一起重测。
///
/// 本轮在本模块自己实跑并钉住的只有边界那一半：深度 8 编译得过、深度 9 被闸门拒
/// （`the_input_gate_runs_before_the_parser`），以及编译出来的 AST 在**调用方线程**上照常求值
/// （`evaluation_does_not_need_the_parser_thread`）。
///
/// 之所以要自己拉线程而不是要求调用方"在栈够大的线程上调用"：那样一来同一条表达式的成败
/// 就取决于它跑在哪个线程上 —— 本仓反复判定为**不是闸门**的形态。
pub const PARSER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// 一条已经编译好的策略表达式。
///
/// 它是 `Send + Sync` 的（由 `compiled_expression_is_send_and_sync` 编译期钉住），因为
/// application 层的服务是 `Send + Sync`，而策略在多个连接上共享同一份编译结果。
#[derive(Debug)]
pub struct CompiledExpression {
    source: String,
    program: cel::Program,
}

impl CompiledExpression {
    /// 表达式原文。
    ///
    /// 原文**可以**带出去：它是管理员自己写下的规则，不是被检查对象的数据。审计行要靠它
    /// 回答"是哪条规则拒的"，上游同样把 expression 写进决策。分界线见 [`failure`] 模块文档。
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// 对一份上下文求值，把一切失败压成 [`ResultClass::Error`]。
    ///
    /// **永不 panic、永不返回 `Result`**：调用方（deny / allow 两条列表）对"坏规则"各有一个
    /// 固定答案，多一个错误通道只会让某个调用点忘记处理其中一种。
    #[must_use]
    pub fn evaluate(&self, context: &PolicyContext) -> ResultClass {
        let mut cel_context = cel::Context::default();
        globals::install(&mut cel_context);
        if let Err(failure) = bind_policy_context(context, &mut cel_context) {
            return ResultClass::Error(failure);
        }
        match self.program.execute(&cel_context) {
            Ok(cel::Value::Bool(true)) => ResultClass::True,
            Ok(cel::Value::Bool(false)) => ResultClass::False,
            Ok(other) => ResultClass::Error(CelFailure::NonBoolean {
                got: type_name_of(&other),
            }),
            Err(error) => ResultClass::Error(classify(&error)),
        }
    }
}

/// 求值结果的三类之一。`Error` 携带**无载荷**的分类，不携带任何 context 取值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResultClass {
    /// 规则适用。
    True,
    /// 规则不适用 —— 这是**真答案**，不是坏掉。
    ///
    /// 上游注释逐字：「False is a real answer and stays one; a deny list that read every false as
    /// a denial would refuse everything.」
    False,
    /// 规则坏了：解析失败、引用不存在的东西、答出非布尔、pattern 编不出正则……
    Error(CelFailure),
}

impl ResultClass {
    /// 丢掉分类细节，只留三类中的哪一类。
    ///
    /// 迁移 preflight 比对的是**类别**而不是失败原因：oracle（`cel-js@0.8.2`）与本引擎的失败
    /// 原因本来就不可能相同（两套错误模型），能对齐也只有类别。
    #[must_use]
    pub const fn kind(self) -> ResultKind {
        match self {
            Self::True => ResultKind::True,
            Self::False => ResultKind::False,
            Self::Error(_) => ResultKind::Error,
        }
    }

    /// 与 corpus 的 `result_class` 词表逐字对齐的稳定名字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.kind().as_str()
    }
}

/// 三类结果的**无载荷**形态。
///
/// 单独存在的理由：oracle 那一侧只有类别没有失败对象（`fixtures/policy/cel-corpus.json` 记的是
/// `result_class`），而比对必须在同一个类型上进行 —— 让两侧类型不同，比对就得靠人手转换，
/// 那正是"同一判据两份实现"的起点。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResultKind {
    /// 求值为 `true`。
    True,
    /// 求值为 `false`。
    False,
    /// 求值失败，或答出非布尔。
    Error,
}

impl ResultKind {
    /// 与 corpus 的 `result_class_vocabulary.values` 逐字相同。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::True => "true",
            Self::False => "false",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for ResultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析 [`ResultKind`] 失败。
///
/// corpus 是入库的定值，出现第四个词表取值说明 fixture 被改过 —— 那必须是一次红，不是一次
/// 默默回落。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown_result_class")]
pub struct UnknownResultKind;

impl FromStr for ResultKind {
    type Err = UnknownResultKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "true" => Ok(Self::True),
            "false" => Ok(Self::False),
            "error" => Ok(Self::Error),
            _ => Err(UnknownResultKind),
        }
    }
}

/// 编译一条策略表达式。
///
/// 顺序是**先闸门后解析**，不可交换：[`guard::check`] 的整个存在理由就是不让解析器看到过深的
/// 输入（[`guard`] 模块文档：Rust 栈溢出是 abort，`catch_unwind` 拦不住）。
///
/// 解析发生在一条 [`PARSER_STACK_BYTES`] 大小的**一次性线程**上，随即 `join`。调用方观察不到
/// 任何异步性：没有并发，没有不确定性，只是把"此刻还剩多少栈"这个环境变量移出等式。
///
/// # Errors
///
/// - [`CelFailure::TooLong`] / [`CelFailure::TooDeep`]：输入闸门拒绝。
/// - [`CelFailure::Parse`]：解析器拒绝了这段文本，**或**解析线程 panic。后者归到这里而不是
///   兜底变体，因为它仍然由这条表达式触发，运维要看的还是这条规则。
/// - [`CelFailure::Runtime`]：线程起不来（`spawn` 失败）。它与表达式无关，所以不能诬告成
///   语法错误 —— 那会把人送去改一条没坏的规则。fail-closed 方向相同。
pub fn compile(source: &str) -> Result<CompiledExpression, CelFailure> {
    guard::check(source)?;

    let owned = source.to_string();
    let parsed = std::thread::Builder::new()
        .name("openbot-cel-parse".to_string())
        .stack_size(PARSER_STACK_BYTES)
        .spawn(move || cel::Program::compile(&owned).map_err(|_| CelFailure::Parse))
        .map_err(|_| CelFailure::Runtime)?
        .join()
        .map_err(|_| CelFailure::Parse)?;

    Ok(CompiledExpression {
        source: source.to_string(),
        program: parsed?,
    })
}

/// 把一次执行期失败压成封闭分类。
///
/// **只匹配变体，不读消息文本。** 唯一一处看名字的是 [`CelFailure::InvalidPattern`]，看的是
/// `FunctionError::function`（一个我们自己注册的函数名，见 [`globals::MATCHES`]），仍然不是
/// 消息文本 —— 消息文本里有 pattern 原文，而本模块的规矩是它不出求值器。
fn classify(error: &cel::ExecutionError) -> CelFailure {
    match error {
        cel::ExecutionError::UndeclaredReference(_) => CelFailure::UnknownReference,
        cel::ExecutionError::NoSuchKey(_) => CelFailure::MissingField,
        cel::ExecutionError::InvalidArgumentCount { .. } => CelFailure::Arity,
        cel::ExecutionError::FunctionError { function, .. }
            if function.as_str() == globals::MATCHES =>
        {
            CelFailure::InvalidPattern
        }
        _ => CelFailure::Runtime,
    }
}

/// CEL 值的类型名。**只取类型，不取值** —— 这是 [`CelFailure::NonBoolean`] 唯一被允许携带的信息。
///
/// `bool` 不在映射里：它压根不会走到这里（[`CompiledExpression::evaluate`] 先把两个布尔分支
/// 摘走）。`Value::Float` 映射成 [`CelTypeName::Double`]，因为 CEL 规范里那个类型叫 `double`，
/// `cel` crate 自己的 `ValueType::Float` 用的是 Rust 名字，不是线上名字。
fn type_name_of(value: &cel::Value) -> CelTypeName {
    match value {
        cel::Value::List(_) => CelTypeName::List,
        cel::Value::Map(_) => CelTypeName::Map,
        cel::Value::Int(_) => CelTypeName::Int,
        cel::Value::UInt(_) => CelTypeName::Uint,
        cel::Value::Float(_) => CelTypeName::Double,
        cel::Value::String(_) => CelTypeName::String,
        cel::Value::Bytes(_) => CelTypeName::Bytes,
        cel::Value::Null => CelTypeName::Null,
        _ => CelTypeName::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::context::{ActorRef, BotRef, ElementRef, PageRef, ToolRef};

    /// 独特到不可能自然出现在任何错误模板里的标记串。
    const CANARY: &str = "CANARY-8f2b1c7d-do-not-leak";

    fn context_with_canary() -> PolicyContext {
        PolicyContext {
            tool: ToolRef {
                name: "computer_click".to_string(),
            },
            bot: BotRef {
                id: "risk-analyst".to_string(),
            },
            page: PageRef {
                url: format!("https://example.com/order?token={CANARY}"),
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

    /// 直接拿到未经压缩的 `cel::ExecutionError` —— 只给测试用，用来做正向对照。
    fn raw_error(source: &str, context: &PolicyContext) -> cel::ExecutionError {
        let program = cel::Program::compile(source).expect("测试表达式必须可解析");
        let mut cel_context = cel::Context::default();
        globals::install(&mut cel_context);
        bind_policy_context(context, &mut cel_context).expect("绑定不应失败");
        program
            .execute(&cel_context)
            .expect_err("这条测试表达式必须失败")
    }

    fn class_of(source: &str, context: &PolicyContext) -> ResultClass {
        compile(source)
            .expect("这条测试表达式必须可编译")
            .evaluate(context)
    }

    /// [`CompiledExpression`] 必须能跨线程共享：`ApplicationService` 是 `Send + Sync`，
    /// 而编译结果在多个连接之间共用同一份。
    ///
    /// 编译期断言 —— 一旦 `cel::Program` 哪天塞进一个 `Rc`，这条当场红。
    #[test]
    fn compiled_expression_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CompiledExpression>();
        assert_send_sync::<ResultClass>();
        assert_send_sync::<ResultKind>();
    }

    /// 三类结果的名字与 corpus 词表逐字对齐。
    #[test]
    fn result_class_names_match_the_corpus_vocabulary() {
        assert_eq!(ResultClass::True.as_str(), "true");
        assert_eq!(ResultClass::False.as_str(), "false");
        assert_eq!(ResultClass::Error(CelFailure::Parse).as_str(), "error");
        for name in ["true", "false", "error"] {
            assert_eq!(ResultKind::from_str(name).expect("词表内").as_str(), name);
        }
        assert_eq!(ResultKind::from_str("errored"), Err(UnknownResultKind));
    }

    /// `false` 是真答案，不是坏规则 —— 与 [`ResultClass::Error`] 严格区分。
    #[test]
    fn false_is_an_answer_and_not_a_failure() {
        let context = context_with_canary();
        assert_eq!(
            class_of("contains(element.name, \"cancel\")", &context),
            ResultClass::False
        );
        assert_eq!(
            class_of("contains(element.name, \"submit\")", &context),
            ResultClass::True
        );
    }

    /// 已知的失败形态各自落到自己的分类，**不掉进兜底**。
    ///
    /// [`failure`] 的模块文档点名要这条测试：兜底变体存在是为了扛住 `cel` 升版本新增变体，
    /// 但它不能悄悄吃掉本该分类的东西。负向对照在最后一段：五个分类两两不同，
    /// 所以这条不是在"classify 恒返回同一个值"的世界里成立的。
    #[test]
    fn known_execution_error_variants_map_to_their_own_classes() {
        let context = context_with_canary();

        let unknown_reference = classify(&raw_error("repeat.count", &context));
        let missing_field = classify(&raw_error("element.type == \"textbox\"", &context));
        let arity = classify(&raw_error("element.name.matches(\"sub.*\")", &context));
        let invalid_pattern = classify(&raw_error("matches(element.name, \"(\")", &context));
        let fallback = classify(&raw_error("page.url + 1", &context));

        assert_eq!(unknown_reference, CelFailure::UnknownReference);
        assert_eq!(missing_field, CelFailure::MissingField);
        assert_eq!(arity, CelFailure::Arity);
        assert_eq!(invalid_pattern, CelFailure::InvalidPattern);
        assert_eq!(fallback, CelFailure::Runtime);

        let classes = [
            unknown_reference,
            missing_field,
            arity,
            invalid_pattern,
            fallback,
        ];
        let mut codes: Vec<&str> = classes.iter().map(|failure| failure.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), classes.len(), "五种失效模式不得压成同一个分类");
    }

    /// 答出非布尔归 [`CelFailure::NonBoolean`]，并且**只**携带类型名。
    #[test]
    fn non_boolean_answers_carry_only_a_type_name() {
        let context = context_with_canary();
        assert_eq!(
            class_of("\"Submit order\"", &context),
            ResultClass::Error(CelFailure::NonBoolean {
                got: CelTypeName::String
            })
        );
        assert_eq!(
            class_of("size(element.name)", &context),
            ResultClass::Error(CelFailure::NonBoolean {
                got: CelTypeName::Int
            })
        );
        assert_eq!(
            class_of("[element.name]", &context),
            ResultClass::Error(CelFailure::NonBoolean {
                got: CelTypeName::List
            })
        );
    }

    /// context 取值**一个字节都不能**经由失败类型渗出。
    ///
    /// 正向对照在同一条测试里：同一次失败的原始 `cel::ExecutionError` 的 `Display`
    /// **确实**含有那个标记。没有它，本测试在"标记压根没进 context"的世界里同样通过。
    #[test]
    fn context_values_never_leak_through_the_failure_type() {
        let context = context_with_canary();

        // 正向对照：这一变体确实会把 context 取值原样打出来。
        let leaking = raw_error("page.url + 1", &context);
        assert!(
            leaking.to_string().contains(CANARY),
            "正向对照失效：原始错误没有携带标记，本测试测不到东西。实得 {leaking}"
        );

        for source in [
            "page.url + 1",                    // 携值变体（上面刚证实）
            "repeat.count",                    // 未声明引用
            "element.type == \"textbox\"",     // 缺字段
            "element.name.matches(\"sub.*\")", // 实参个数
            "matches(element.name, \"(\")",    // 坏 pattern
            "page.url",                        // 非布尔，答案本身就是那个标记串
        ] {
            let class = class_of(source, &context);
            let ResultClass::Error(failure) = class else {
                panic!("{source} 必须落在 error 类，实得 {class:?}");
            };
            assert!(
                !failure.to_string().contains(CANARY),
                "{source} 的 Display 泄漏了 context 取值"
            );
            assert!(
                !format!("{class:?}").contains(CANARY),
                "{source} 的 Debug 泄漏了 context 取值"
            );
        }
    }

    /// 输入闸门先于解析：过深的表达式**不会**被交给解析器。
    ///
    /// 负向对照是同一条里深度 8 的表达式 —— 它编译成功，说明这条闸门不是"拒绝一切"。
    #[test]
    fn the_input_gate_runs_before_the_parser() {
        let too_deep = format!(
            "{}true{}",
            "(".repeat(guard::MAX_EXPRESSION_DEPTH + 1),
            ")".repeat(guard::MAX_EXPRESSION_DEPTH + 1)
        );
        assert_eq!(compile(&too_deep).err(), Some(CelFailure::TooDeep));

        let at_limit = format!(
            "{}true{}",
            "(".repeat(guard::MAX_EXPRESSION_DEPTH),
            ")".repeat(guard::MAX_EXPRESSION_DEPTH)
        );
        assert!(compile(&at_limit).is_ok(), "深度 8 必须仍然可编译");

        let too_long = "a".repeat(guard::MAX_EXPRESSION_BYTES + 1);
        assert_eq!(compile(&too_long).err(), Some(CelFailure::TooLong));
    }

    /// 语法错误落 [`CelFailure::Parse`]，且 `source()` 原样保留规则文本供运维定位。
    #[test]
    fn syntax_errors_are_classified_and_the_rule_text_survives() {
        assert_eq!(
            compile("this is not ( valid cel").err(),
            Some(CelFailure::Parse)
        );

        let ok = compile("tool.name == \"computer_click\"").expect("合法表达式");
        assert_eq!(ok.source(), "tool.name == \"computer_click\"");
    }

    /// 解析跑在自己的线程上，**而求值不需要**。
    ///
    /// 这条不复刻 [`guard`] 模块文档里那次"64 MiB 上编译、~1 MiB 主线程上执行"的实验
    /// （测试线程的栈大小不由本测试决定，钉它就成了对不受控环境的断言）。它钉的是本模块真正
    /// 依赖的那半条：[`compile`] 出来的 AST 交回**调用方线程**照常求值 —— 于是"求值不再包一层
    /// 线程"这个决定有一条会红的证据，而不是一句注释。
    ///
    /// 深度取上限 8：这是闸门允许的最深表达式。
    #[test]
    fn evaluation_does_not_need_the_parser_thread() {
        let depth = guard::MAX_EXPRESSION_DEPTH;
        let source = format!("{}true{}", "(".repeat(depth), ")".repeat(depth));
        let compiled = compile(&source).expect("深度 8 可编译");
        // 在**当前**线程（测试线程，非解析线程）上求值。
        assert_eq!(compiled.evaluate(&context_with_canary()), ResultClass::True);
    }

    /// 注册全局函数不改变方法形式的语义 —— 两条路径互不干扰。
    ///
    /// 这条把 [`globals`] 模块文档里那张分派表钉成可复算的证据：方法形式走 cel 内建
    /// （大小写敏感，`"Submit order".contains("submit")` = false），全局形式走本仓实现
    /// （大小写不敏感 = true）。`matches` 因为关掉了 `regex` feature 而没有内建方法，
    /// 落到全局函数上只带一个实参，报实参个数错。
    #[test]
    fn method_form_and_global_form_are_different_dispatch_paths() {
        let context = context_with_canary();
        assert_eq!(
            class_of("element.name.contains(\"submit\")", &context),
            ResultClass::False
        );
        assert_eq!(
            class_of("contains(element.name, \"submit\")", &context),
            ResultClass::True
        );
        assert_eq!(
            class_of("element.name.startsWith(\"Submit\")", &context),
            ResultClass::True
        );
        assert_eq!(
            class_of("element.name.endsWith(\"order\")", &context),
            ResultClass::True
        );
        assert_eq!(
            class_of("element.name.matches(\"sub.*\")", &context),
            ResultClass::Error(CelFailure::Arity)
        );
    }
}
