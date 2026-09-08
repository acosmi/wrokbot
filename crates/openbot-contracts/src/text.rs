//! 跨 native/WASM 边界共用的 ECMAScript 文本语义。
//!
//! 这里只收必须与 JavaScript 逐字符对齐、且被多个 crate 消费的规则。
//! `openbot-domain::text` 重导出本模块，所有调用点仍只有这一份实现。

/// ECMAScript `TrimString` 的 `WhiteSpace ∪ LineTerminator` 封闭集合。
///
/// 不能换成 [`char::is_whitespace`]：Rust 少认 U+FEFF，却多认 ECMAScript 不认的 U+0085。
#[must_use]
pub const fn is_ecmascript_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// 与 ECMAScript `String.prototype.trim()` 相同的首尾裁剪。
#[must_use]
pub fn trim_ecmascript(value: &str) -> &str {
    value.trim_matches(is_ecmascript_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_string_includes_bom_and_excludes_next_line() {
        assert_eq!(trim_ecmascript("\u{FEFF}\u{3000}v\u{00A0}"), "v");
        assert_eq!(trim_ecmascript("\u{0085}v\u{0085}"), "\u{0085}v\u{0085}");
        assert!(!'\u{FEFF}'.is_whitespace(), "Rust 的负向对照");
        assert!('\u{0085}'.is_whitespace(), "Rust 的另一方向正向对照");
    }
}
