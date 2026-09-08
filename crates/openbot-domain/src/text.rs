//! 固定上游 JavaScript 文本边界的 domain 入口。
//!
//! 实现上收到 wasm-safe `openbot-contracts`，以便 GUI 也能复用同一份
//! ECMAScript `TrimString`；本模块保留 R51 已固定的公开路径。

pub use openbot_contracts::text::{is_ecmascript_whitespace, trim_ecmascript};

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个语言集合不相等的两端都必须被行使，避免退回 `str::trim()` 仍然全绿。
    #[test]
    fn trim_string_includes_bom_and_excludes_next_line() {
        assert_eq!(trim_ecmascript("\u{FEFF}\u{3000}v\u{00A0}"), "v");
        assert_eq!(trim_ecmascript("\u{0085}v\u{0085}"), "\u{0085}v\u{0085}");
        assert!(!'\u{FEFF}'.is_whitespace(), "Rust 的负向对照");
        assert!('\u{0085}'.is_whitespace(), "Rust 的另一方向正向对照");
    }
}
