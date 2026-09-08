//! [`CelFailure`] —— 求值失败的**封闭**分类，且**永不携带 context 取值**。
//!
//! # 为什么不能直接用 `cel::ExecutionError`
//!
//! `cel 0.14.3` 的 `ExecutionError` 有多个变体把参与运算的 `Value` 塞进了错误本体，它的
//! `Display` 会把那些值逐字打出来。本轮实测（`cel 0.14.3`，把一个带 token 的 URL 放进
//! context 后求值 `page.url + 1`）：
//!
//! ```text
//! Unsupported binary operator 'add': String("https://example.com/order?token=SECRET123"), Int(1)
//! ```
//!
//! 同一次测量里的**正向对照**是 `page.url < 1`，它落到 `NoSuchOverload`，输出只有
//! `No such overload` —— 说明泄漏是**变体相关**的，不是「所有错误都带值」也不是「所有错误
//! 都不带值」。于是「小心别打印错误」这种纪律型防线必然漏：漏的是那几个恰好带值的变体。
//!
//! 这与 fixtures/policy/cel-corpus.json 里记的 F-CEL-6 是**同一族缺陷**：上游 cel-js 的
//! `Identifier not found` 把整份 context 的 JSON 拼进消息体，而 `server/src/computer/policy.ts`
//! 用 `console.error(String(error))` 原样打日志。v3 §2.4 已把它列为**不得照译**，§8.6 又要求
//! 审计 payload 走字段 allowlist。所以本项目的规矩是构造性的：
//!
//! **CEL 失败在离开求值器的那一刻就被压成本模块这组无载荷的分类，`cel::ExecutionError`
//! 的 `Display` 一个字节都不会出现在日志、审计、错误响应或 GUI 里。**
//!
//! 表达式原文**可以**带（它是管理员自己写下的策略规则，不是被检查对象的数据），并且不带
//! 它的话运维根本找不到是哪条规则坏了 —— 上游同样打印 expression。分界线是：**规则文本是
//! 我们的，context 取值是被检查对象的。**

use core::fmt;

/// CEL 求值失败的封闭分类。
///
/// 每个变体只携带**静态描述**（类型名、位置计数），绝不携带 context 里的取值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum CelFailure {
    /// 表达式超过 [`super::guard::MAX_EXPRESSION_BYTES`]。
    ///
    /// 在**解析之前**判定，见 [`super::guard`] 的模块文档。
    #[error("policy_expression_too_long")]
    TooLong,

    /// 表达式的括号嵌套超过 [`super::guard::MAX_EXPRESSION_DEPTH`]。
    ///
    /// 同样在解析之前判定 —— 这是本模块唯一一条**必须**先于解析器执行的检查，理由（解析器
    /// 会爆栈，而 Rust 的栈溢出是 abort 不是 panic）见 [`super::guard`]。
    #[error("policy_expression_too_deep")]
    TooDeep,

    /// 语法错误：解析器拒绝了这段文本。
    #[error("policy_expression_parse_error")]
    Parse,

    /// 引用了未声明的标识符或未注册的函数。
    ///
    /// 上游 cel-js 在同一情形下抛 `Identifier not found`，并把整份 context 拼进消息 ——
    /// 那正是 F-CEL-6。本变体不带任何名字：标识符名来自表达式，运维可以从 expression 原文
    /// 看到，不需要在错误里复述一遍。
    #[error("policy_expression_unknown_reference")]
    UnknownReference,

    /// 对象存在，但没有被读的那个键。
    ///
    /// 与 [`Self::UnknownReference`] 分开，是因为它们对应两种不同的规则缺陷：前者是"根本没
    /// 这个字段"，后者是"这个 context 形态下没有这一层"。上游把两者都归为抛错（F-CEL-4），
    /// 结果类别相同，但排障时值得分辨。
    #[error("policy_expression_missing_field")]
    MissingField,

    /// 求值成功，但答案不是布尔。
    ///
    /// 上游 `policy.ts::matches` 明确把它与抛错归入同一条 fail-closed 路径，理由原文是
    /// 「`"Submit order"` 是合法 CEL，它解析、求值，答出一个字符串，而那不是『这条规则适不
    /// 适用』的答案」。本项目照搬这条语义，但**保留类型名**，好让审计能分辨两种失效模式。
    #[error("policy_expression_non_boolean")]
    NonBoolean {
        /// 实际答出来的 CEL 类型名（静态字符串，非取值）。
        got: CelTypeName,
    },

    /// 全局函数 `matches(value, pattern)` 的 pattern 编译不出正则。
    ///
    /// 上游注释逐字：「An unparseable regex is a broken rule, not a match.」—— 它显式
    /// `throw`，好让 deny 侧的 fail-closed 生效。本项目同语义。
    #[error("policy_expression_invalid_pattern")]
    InvalidPattern,

    /// 实参个数不对。
    ///
    /// 单列而不是并进 [`Self::Runtime`]，因为它是**方法形式调用全局函数**的确定指纹：
    /// `x.matches(p)` 只把 `p` 交给一个两参函数。corpus 的 `method-form-matches` 就落在这里。
    #[error("policy_expression_arity")]
    Arity,

    /// 其余执行期失败：类型不匹配、无重载、不可比较、算术溢出……
    ///
    /// 刻意做成一个**兜底**变体：`cel::ExecutionError` 标了 `#[non_exhaustive]`，升版本会加
    /// 新变体。有兜底才不会因为上游加了一个变体就编译不过；而
    /// `known_execution_error_variants_map_to_their_own_classes` 用一组构造出来的真实失败
    /// 钉住"已知的那些**没有**掉进兜底"，所以兜底不会悄悄吃掉本该分类的东西。
    #[error("policy_expression_runtime_error")]
    Runtime,
}

impl CelFailure {
    /// 稳定的分类标识符，进审计与日志用。
    ///
    /// 它是**标识符**不是文案：不随 locale 变化（repository contract §4a「文案不进 domain」）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLong => "policy_expression_too_long",
            Self::TooDeep => "policy_expression_too_deep",
            Self::Parse => "policy_expression_parse_error",
            Self::UnknownReference => "policy_expression_unknown_reference",
            Self::MissingField => "policy_expression_missing_field",
            Self::NonBoolean { .. } => "policy_expression_non_boolean",
            Self::InvalidPattern => "policy_expression_invalid_pattern",
            Self::Arity => "policy_expression_arity",
            Self::Runtime => "policy_expression_runtime_error",
        }
    }
}

/// CEL 值的类型名。封闭集合，只有名字，没有值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CelTypeName {
    /// `list`
    List,
    /// `map`
    Map,
    /// `int`
    Int,
    /// `uint`
    Uint,
    /// `double`
    Double,
    /// `string`
    String,
    /// `bytes`
    Bytes,
    /// `null`
    Null,
    /// 其余（函数值、opaque、以及 `cel` 升版本后新增的类型）。
    Other,
}

impl CelTypeName {
    /// 稳定名字。取自 CEL 规范的类型名，不是 Rust 的枚举名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Map => "map",
            Self::Int => "int",
            Self::Uint => "uint",
            Self::Double => "double",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Null => "null",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for CelTypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Display` 与 [`CelFailure::code`] 是同一个字符串 —— 防止有人改了一处忘了另一处。
    #[test]
    fn display_and_code_agree() {
        let all = [
            CelFailure::TooLong,
            CelFailure::TooDeep,
            CelFailure::Parse,
            CelFailure::UnknownReference,
            CelFailure::MissingField,
            CelFailure::NonBoolean {
                got: CelTypeName::String,
            },
            CelFailure::InvalidPattern,
            CelFailure::Arity,
            CelFailure::Runtime,
        ];
        for failure in all {
            assert_eq!(failure.to_string(), failure.code());
        }
    }

    /// 分类标识符两两不同 —— 两个不同的失效模式压成同一个字符串，审计就分不开它们。
    #[test]
    fn codes_are_pairwise_distinct() {
        let codes = [
            CelFailure::TooLong.code(),
            CelFailure::TooDeep.code(),
            CelFailure::Parse.code(),
            CelFailure::UnknownReference.code(),
            CelFailure::MissingField.code(),
            CelFailure::NonBoolean {
                got: CelTypeName::String,
            }
            .code(),
            CelFailure::InvalidPattern.code(),
            CelFailure::Arity.code(),
            CelFailure::Runtime.code(),
        ];
        let mut sorted = codes;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), codes.len(), "分类标识符必须两两不同");
    }

    /// [`CelFailure`] 是 `Copy` 且不含 `String` —— 一个不能携带堆上字符串的类型，
    /// 在构造上就没法把 context 取值带出去。
    ///
    /// 这条是**类型层面的**约束，比"记得别 format 进去"强一档：想加一个 `String` 字段的人
    /// 会先撞上 `Copy` 编译失败。
    #[test]
    fn failure_is_copy_so_it_cannot_carry_owned_text() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<CelFailure>();
        assert_copy::<CelTypeName>();
    }
}
