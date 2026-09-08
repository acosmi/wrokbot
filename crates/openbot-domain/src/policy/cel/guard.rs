//! 解析前的**非递归**输入闸门：长度与括号嵌套深度。
//!
//! # 为什么必须有它：`cel 0.14.3` 的解析器会把进程打死
//!
//! `cel` 的语法分析走 `antlr4rust` 生成的递归下降。每多一层括号，就要多走一遍
//! `conditional → logical-or → logical-and → relation → calc → unary → member → primary`
//! 这条规则链，栈消耗随嵌套层数**线性**增长。本轮在本机（Windows / `rustc 1.98.0` / debug）
//! 逐档二分实测，第一个把栈打穿的嵌套深度是：
//!
//! | 线程栈 | 第一个崩溃的深度 |
//! | --- | ---: |
//! | ~1 MiB（Windows 主线程默认） | **6** |
//! | 2 MiB（`std::thread` 默认） | 12 |
//! | 4 MiB | 28 |
//! | 8 MiB | 64 |
//! | 64 MiB | 不崩；深度 ≥ 100 时解析器自己报语法错误 |
//!
//! 测的是 `"(".repeat(n) + "true" + ")".repeat(n)`。斜率约每 MiB 6 层，即每层约 170 KiB。
//!
//! 两条推论决定了本模块的形状：
//!
//! 1. **Rust 的栈溢出是 abort，不是 panic**，`catch_unwind` 拦不住，进程直接没了。
//!    而策略表达式来自管理员可写的 `action_policy.deny` / `.allow` —— 一条写歪的规则
//!    （或一次刻意的输入）就是一次进程级 DoS。
//! 2. **同一条表达式的成败取决于它跑在哪个线程上**。这正是本仓判定「不是闸门」的那种形态：
//!    答案取决于运行环境而不是取决于输入。所以不能靠"调用方记得给够栈"。
//!
//! 因此本项目做两件事，缺一不可：
//!
//! - **这里**：在解析器看到字符串之前，用一次线性扫描判定长度与嵌套深度，超限即拒。
//!   扫描本身零递归，不可能爆栈。
//! - [`super::compile`]：把解析放在**本模块自己拉起的、栈大小写死的线程**上，于是
//!   "调用者此刻还剩多少栈"这个变量被彻底移出等式。
//!
//! # 为什么执行不需要同样的待遇
//!
//! 同一轮实测：在 64 MiB 线程上编译出深度 64 的 AST，再拿回 **~1 MiB 的主线程**执行，
//! 正常返回 `Bool(true)`。求值的递归每层只有一个 `Value::resolve` 帧，比解析那条八级规则链
//! 便宜得多。深度上限 8 之下，执行侧余量在 8 倍以上，不必再包一层线程 —— 而且求值在工具
//! 调用的热路径上，每次评估都 spawn 一个线程是不可接受的开销。

/// 策略表达式的字节上限。
///
/// **4096 字节。** 取值理由：`fixtures/policy/cel-corpus.json` 全部 69 条表达式里最长的一条是
/// **143 字节**（`preset-never-submit-on-click-button`，即上游随包的 Boundaries preset），
/// 4 KiB 给了约 28 倍余量；同时它足够小，使「先扫一遍再解析」的成本可以忽略。
///
/// 它不是安全边界的主力（主力是 [`MAX_EXPRESSION_DEPTH`]），而是让扫描本身有界。
pub use openbot_contracts::policy::MAX_ACTION_POLICY_EXPRESSION_BYTES as MAX_EXPRESSION_BYTES;

use super::failure::CelFailure;

/// 策略表达式的括号嵌套深度上限。
///
/// **8。** 取值来自本模块开头那张实测表与实际规则的形状：
///
/// - corpus 里 69 条表达式的最大嵌套深度是 **2**（函数调用的括号也计入），最深的就是那两条
///   随包 preset。8 给了 4 倍书写余量。
/// - 解析放在 [`super::PARSER_STACK_BYTES`] = 16 MiB 的线程上，按每 MiB 6 层折算，崩溃点
///   在 96 层附近 —— 对上限 8 有 12 倍余量。
///
/// 提高它必须同时重测那张表：**这两个数字是一对，单独改一个就是把余量花掉而不自知。**
pub const MAX_EXPRESSION_DEPTH: usize = 8;

/// 在解析之前检查一条表达式。
///
/// 通过则返回它的实测嵌套深度（供诊断用），否则返回 [`CelFailure::TooLong`] /
/// [`CelFailure::TooDeep`]。
///
/// # Errors
///
/// 见上。**不会**因为括号不配对而报错 —— 那是语法错误，归解析器判；本函数只保证解析器
/// 不会因为深度而爆栈。
pub fn check(expression: &str) -> Result<usize, CelFailure> {
    if expression.len() > MAX_EXPRESSION_BYTES {
        return Err(CelFailure::TooLong);
    }
    let depth = max_bracket_depth(expression);
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(CelFailure::TooDeep);
    }
    Ok(depth)
}

/// 一条表达式里 `(` / `[` / `{` 的最大嵌套深度，**字符串字面量内的括号不计**。
///
/// # 为什么要认字符串字面量
///
/// 不认的话，`contains(page.url, "(((((((((")` 会被算成深度 10 而被拒 —— 一条完全正常的
/// 规则被闸门误杀。反过来，如果认错了（把不是字面量的东西当成字面量跳过），就会**漏算**
/// 真实深度，那是危险的方向。所以下面这个扫描器宁可在不确定时**停止跳过**（遇到未闭合的
/// 引号就把剩下的部分当普通文本继续数括号），让计数偏大而不偏小。
///
/// CEL 的字符串字面量形态（按 CEL 规范）：单引号 / 双引号，各有三引号变体；可带 `r`/`R`
/// 前缀表示裸串（反斜杠不转义），可带 `b`/`B` 前缀表示字节串。前缀可以组合（`rb"..."`）。
fn max_bracket_depth(expression: &str) -> usize {
    let bytes = expression.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut max_depth = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        // 字符串字面量前缀：r / R / b / B 的任意组合，后面紧跟引号才算前缀。
        if matches!(byte, b'r' | b'R' | b'b' | b'B') {
            let mut lookahead = index;
            while lookahead < bytes.len()
                && matches!(bytes[lookahead], b'r' | b'R' | b'b' | b'B')
                && lookahead - index < 2
            {
                lookahead += 1;
            }
            if lookahead < bytes.len() && matches!(bytes[lookahead], b'"' | b'\'') {
                let raw = expression[index..lookahead]
                    .bytes()
                    .any(|b| b == b'r' || b == b'R');
                index = skip_string(bytes, lookahead, raw);
                continue;
            }
        }

        match byte {
            b'"' | b'\'' => {
                index = skip_string(bytes, index, false);
                continue;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            b')' | b']' | b'}' => {
                // 括号不配对是语法错误，由解析器报。这里只要不让深度绕回负数即可。
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        index += 1;
    }

    max_depth
}

/// 从 `start`（一个引号字节）开始跳过一段字符串字面量，返回字面量之后的下标。
///
/// 未闭合时返回 `start + 1` —— 也就是**不跳过**，让调用方把剩下的内容当普通文本继续数。
/// 这条选择让计数只会偏大（误拒），不会偏小（漏放）。
fn skip_string(bytes: &[u8], start: usize, raw: bool) -> usize {
    let quote = bytes[start];
    let triple = bytes.len() >= start + 3 && bytes[start + 1] == quote && bytes[start + 2] == quote;
    let delimiter_len = if triple { 3 } else { 1 };
    let mut index = start + delimiter_len;

    while index < bytes.len() {
        if !raw && bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == quote {
            if !triple {
                return index + 1;
            }
            if bytes.len() >= index + 3 && bytes[index + 1] == quote && bytes[index + 2] == quote {
                return index + 3;
            }
        }
        index += 1;
    }

    // 未闭合：不跳过。
    start + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(depth: usize) -> String {
        format!("{}true{}", "(".repeat(depth), ")".repeat(depth))
    }

    #[test]
    fn depth_counts_nesting_not_occurrences() {
        // 并列而非嵌套：三对括号，深度仍是 1。
        assert_eq!(max_bracket_depth("(a) && (b) && (c)"), 1);
        assert_eq!(max_bracket_depth("((a))"), 2);
        // 函数调用的括号一样计入 —— 解析器的递归不区分它们。
        assert_eq!(max_bracket_depth("contains(page.url, \"x\")"), 1);
        assert_eq!(
            max_bracket_depth("(a && contains(x, y)) || ((b && c) && d)"),
            2
        );
        // 列表与 map 的括号同样进入递归。
        assert_eq!(
            max_bracket_depth("\"Enter\" in [\"Enter\", [\"Space\"]]"),
            2
        );
    }

    /// 字符串字面量里的括号不计 —— 否则一条合法规则会被闸门误杀。
    #[test]
    fn brackets_inside_string_literals_do_not_count() {
        assert_eq!(max_bracket_depth("contains(page.url, \"((((((((((\")"), 1);
        assert_eq!(max_bracket_depth("matches(x, '(((')"), 1);
        assert_eq!(max_bracket_depth("matches(x, r\"\\(\\(\\(\")"), 1);
        assert_eq!(max_bracket_depth("contains(x, \"\"\"((((\"\"\")"), 1);
    }

    /// 转义的引号不结束字面量。
    ///
    /// 负向对照在同一条里：如果扫描器把 `\"` 当成结束引号，后面那串括号就会被当成代码数进去，
    /// 深度变成 4 而不是 1。
    #[test]
    fn escaped_quote_does_not_end_the_literal() {
        assert_eq!(max_bracket_depth("contains(x, \"a\\\"(((\")"), 1);
        // 裸串里反斜杠不转义，所以 r"a\" 到那个引号就结束了，后面的括号是代码。
        assert_eq!(max_bracket_depth("f(r\"a\\\", (((x)))"), 4);
    }

    /// 未闭合的引号：宁可把剩下的当代码数（偏大，误拒），也不要整段跳过（偏小，漏放）。
    #[test]
    fn unterminated_string_falls_back_to_counting() {
        assert_eq!(max_bracket_depth("f(\"abc ((((("), 6);
    }

    /// 边界正好：深度 8 通过，深度 9 被拒。
    #[test]
    fn depth_limit_is_exact() {
        assert_eq!(
            check(&nested(MAX_EXPRESSION_DEPTH)),
            Ok(MAX_EXPRESSION_DEPTH)
        );
        assert_eq!(
            check(&nested(MAX_EXPRESSION_DEPTH + 1)),
            Err(CelFailure::TooDeep)
        );
    }

    /// 长度上限同样是精确边界。
    #[test]
    fn length_limit_is_exact() {
        let ok = "a".repeat(MAX_EXPRESSION_BYTES);
        assert!(check(&ok).is_ok());
        let too_long = "a".repeat(MAX_EXPRESSION_BYTES + 1);
        assert_eq!(check(&too_long), Err(CelFailure::TooLong));
    }

    /// 长度先判：一条既超长又超深的表达式报 `TooLong`。
    ///
    /// 顺序本身是有意义的 —— 深度扫描是线性的，先卡住长度就给了扫描一个上界。
    #[test]
    fn length_is_checked_before_depth() {
        let both = format!("{}{}", "(".repeat(64), "a".repeat(MAX_EXPRESSION_BYTES));
        assert_eq!(check(&both), Err(CelFailure::TooLong));
    }

    /// 括号不配对**不是**本闸门的判定对象。
    #[test]
    fn unbalanced_brackets_are_left_to_the_parser() {
        assert_eq!(check(")))"), Ok(0));
        assert!(check("(((").is_ok());
    }

    /// 上游随包的两条 preset 实测深度 = 2、最长 143 字节，都落在上限之内。
    ///
    /// 这条是 [`MAX_EXPRESSION_DEPTH`] 那个 4 倍余量与 [`MAX_EXPRESSION_BYTES`] 那个 28 倍
    /// 余量的可复算证据。两条表达式逐字取自 `fixtures/policy/cel-corpus.json` 的
    /// `preset-never-submit-on-click-button` 与 `preset-social-media-hit`，**不是手抄近似**
    /// —— 手抄一条"差不多的"表达式，测的就不再是随包规则的形状。
    #[test]
    fn shipped_preset_expressions_are_within_the_limit() {
        let never_submit = "(intent == \"activate\" && contains(element.name, \"submit\")) || ((tool.name == \"computer_key\" || tool.name == \"computer_type\") && key == \"Enter\")";
        assert_eq!(never_submit.len(), 143, "corpus 里最长的一条表达式");
        assert_eq!(max_bracket_depth(never_submit), 2);
        assert_eq!(check(never_submit), Ok(2));

        let social = "intent == \"navigate\" && (contains(page.host, \"facebook.com\") || contains(page.host, \"x.com\"))";
        assert_eq!(max_bracket_depth(social), 2);
        assert_eq!(check(social), Ok(2));
    }
}
