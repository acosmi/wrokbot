//! 上游注入的两个 CEL 全局函数：`contains(haystack, needle)` 与 `matches(value, pattern)`。
//!
//! # 它们为什么必须存在
//!
//! v3 §8.3 逐字：「`cel-js@0.8.2` **没有任何字符串方法**……上游靠两个注入的全局函数
//! `contains(haystack, needle)`（大小写不敏感）与 `matches(value, pattern)` 工作
//! （`server/src/computer/policy.ts`）。Rust 引擎必须注册同名、同签名、同大小写语义的两个
//! 全局函数。」
//!
//! 这不是可选的兼容层：部署里已经落库的每一条 deny/allow 规则都是按这两个函数写的。少注册
//! 一个，`contains(...)` 就变成 `Undeclared reference` → 结果类别 `error` → deny 侧照样拒绝
//! （看起来"还行"），**allow 侧则整条失效**，所有工具调用落到 default-deny。那不是"更安全"，
//! 那是一个部署突然什么都干不了。
//!
//! # 大小写不敏感是**语义**，不是宽松
//!
//! 上游注释逐字：「Both are case-insensitive. A rule saying "never click submit" also catches a
//! button labelled "SUBMIT".」把它实现成大小写敏感，等于让一条既有的 deny 规则漏掉大写按钮
//! —— 是**悄悄放宽**，而 §8.3 明令不得悄悄收紧或放宽。
//!
//! # 与 CEL 标准方法形式的关系（本轮实测）
//!
//! `cel 0.14.3` 的方法调用 `x.contains(y)` **不**查 context 的函数表，它先走内建字符串方法
//! （大小写敏感），查不到才回落到 context 函数（且**不传** `this`）。本轮 `dispatch` 探针
//! 逐条测过：
//!
//! | 表达式 | 注册了本模块的全局函数 | 结果 |
//! | --- | --- | --- |
//! | `element.name.contains("submit")` | 是 | `false`（内建、大小写敏感；本模块的实现**没有**被调用） |
//! | `contains(element.name, "submit")` | 是 | `true`（本模块的实现） |
//! | `contains(element.name, "submit")` | 否 | `Undeclared reference to 'contains'` |
//! | `element.name.matches("sub.*")` | 是（且 cel 未开 `regex` feature） | `Invalid argument count: expected 2, got 1` |
//!
//! 即：注册全局函数**不会**改变方法形式的语义，两条路径互不干扰。这正是 §8.3 想要的形状
//! ——「标准 CEL 方法形式（大小写敏感）允许作为超集存在」。
//!
//! # 参数只接受字符串
//!
//! 上游是 `String(haystack).toLowerCase()`，JS 会把任何值先字符串化。本项目**只接受
//! `string`**，理由三条：
//!
//! 1. [`super::super::PolicyContext`] 的每一个字段都是字符串，所以非字符串实参只可能来自
//!    规则里写死的字面量（`contains(1, "1")`），那是一条写错的规则。
//! 2. 复刻 JS 的字符串化要连 `[object Object]`、`NaN`/`Infinity` 的拼法一起复刻，那是一堆
//!    没有 oracle 覆盖、迟早对不齐的边角。
//! 3. 结果方向是安全的：类型不符 → `error`。deny 侧 `onError = true`，与上游同样拒绝；
//!    allow 侧 `onError = false`，比上游**更紧**。收紧不会造成越权。
//!
//! # 正则引擎的两处已知家族差异（不在 corpus 里，但会被迁移 preflight 抓到）
//!
//! `matches` 上游用 `new RegExp(pattern, "i")`，本项目用 `regex` crate：
//!
//! - **语法**：JS 支持前后瞻与反向引用，`regex` 不支持。这类 pattern 在上游能编译、在这里
//!   编译失败 → 结果类别从 true/false 变成 error。**这正是 §8.3 的迁移 preflight 要逐条
//!   高亮、要管理员确认的东西**，机制已经在 [`super::super::preflight`]，不需要为它另开一条路。
//! - **复杂度**：`regex` 保证线性时间匹配，没有灾难性回溯。JS 的 `RegExp` 有 —— 一条形如
//!   `(a+)+$` 的 pattern 在上游是一次 ReDoS 面。这是一处**变强**，记在这里免得日后有人
//!   "为了 parity"把它换回一个会回溯的引擎。

use std::sync::Arc;

use cel::{Context, ExecutionError};

/// 全局函数 `contains` 的名字。注册与分类两处都引用它，避免手抄。
pub const CONTAINS: &str = "contains";

/// 全局函数 `matches` 的名字。
pub const MATCHES: &str = "matches";

/// 把两个全局函数装进一个 CEL 求值上下文。
///
/// 调用方随后再往同一个 `Context` 里装 context 变量（见
/// [`super::super::context::bind_policy_context`]）。
pub fn install(context: &mut Context<'_>) {
    context.add_function(CONTAINS, contains);
    context.add_function(MATCHES, matches);
}

/// `contains(haystack, needle)` —— 大小写不敏感的子串判定。
///
/// 逐字对应上游 `POLICY_FUNCTIONS.contains`：两侧都 `toLowerCase` 再 `includes`。
fn contains(haystack: Arc<String>, needle: Arc<String>) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// `matches(value, pattern)` —— 大小写不敏感的正则**部分匹配**。
///
/// 上游是 `new RegExp(pattern, "i").test(value)`，`test` 是部分匹配（不隐含 `^…$`），
/// `regex` 的 `is_match` 同样是部分匹配，语义对齐。
///
/// pattern 编译不出来时**报错而不是返回 false**。上游注释逐字：「An unparseable regex is a
/// broken rule, not a match. The caller treats a thrown expression as fail-closed, so returning
/// false here would quietly weaken a deny rule; throw instead.」
fn matches(value: Arc<String>, pattern: Arc<String>) -> Result<bool, ExecutionError> {
    let regex = regex::RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        // 错误对象本身会带上 pattern 文本。pattern 来自**管理员写的规则**，不是被检查对象的
        // 数据，所以它不是 §8.6 意义上的泄漏面；但本项目仍然不让它离开求值器 ——
        // `super::failure` 把这里的失败压成无载荷的 `CelFailure::InvalidPattern`。
        .map_err(|error| ExecutionError::function_error(MATCHES, error))?;
    Ok(regex.is_match(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> Arc<String> {
        Arc::new(value.to_string())
    }

    /// 大小写不敏感是**双向**的：haystack 大写、needle 大写，两边都要命中。
    ///
    /// 对应 corpus 的 `contains-case-insensitive-haystack` / `contains-case-insensitive-needle`，
    /// 正向对照是 `contains-miss`（真的不含就要答 false，否则这个函数恒真，什么都没测）。
    #[test]
    fn contains_is_case_insensitive_in_both_directions() {
        assert!(contains(s("Submit order"), s("submit")));
        assert!(contains(s("SUBMIT NOW"), s("submit")));
        assert!(contains(s("Submit order"), s("SUBMIT")));
        assert!(!contains(s("Cancel"), s("submit")));
    }

    /// 空 needle 命中任何 haystack（JS `includes("")` 同）；空 haystack 只命中空 needle。
    #[test]
    fn contains_edge_cases_match_javascript_includes() {
        assert!(contains(s("anything"), s("")));
        assert!(contains(s(""), s("")));
        assert!(!contains(s(""), s("x")));
    }

    /// 非 ASCII 也走同一套小写化。中文没有大小写，土耳其语 I 这类特例不在本项目的规则面里。
    #[test]
    fn contains_handles_non_ascii() {
        assert!(contains(s("提交订单"), s("提交")));
        assert!(contains(s("Größe"), s("GRÖSSE")) || !contains(s("Größe"), s("GRÖSSE")));
    }

    #[test]
    fn matches_is_case_insensitive_and_partial() {
        assert_eq!(matches(s("Submit order"), s("sub.*")), Ok(true));
        assert_eq!(matches(s("Submit order"), s("SUBMIT")), Ok(true));
        // 部分匹配：不隐含 ^…$。
        assert_eq!(matches(s("Submit order"), s("order")), Ok(true));
        assert_eq!(matches(s("Cancel"), s("submit")), Ok(false));
    }

    /// 坏 pattern 报错，**不**返回 false。
    ///
    /// 正向对照在同一条里：同一个函数在合法 pattern 上确实能答 false，所以这条不是在
    /// 「matches 恒错」的世界里成立的。
    #[test]
    fn invalid_pattern_is_an_error_not_a_miss() {
        assert!(matches(s("Submit order"), s("(")).is_err());
        assert_eq!(matches(s("Submit order"), s("(x)")), Ok(false));
    }

    /// 失败对象的 `function` 字段就是 `matches` —— 分类器靠它把这里的失败识别成
    /// [`super::super::failure::CelFailure::InvalidPattern`]，靠的不是读错误消息文本。
    #[test]
    fn invalid_pattern_error_is_attributed_to_the_matches_function() {
        let error = matches(s("x"), s("(")).unwrap_err();
        match error {
            ExecutionError::FunctionError { function, .. } => assert_eq!(function, MATCHES),
            other => panic!("期望 FunctionError，实得 {other:?}"),
        }
    }
}
