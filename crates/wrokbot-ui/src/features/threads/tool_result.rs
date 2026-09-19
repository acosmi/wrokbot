//! 解码 transcript 里的 tool 结果，并把 vendor JSON envelope 变成可读文本。

use openbot_contracts::error::ErrorCode;
use openbot_contracts::text::trim_ecmascript;
use openbot_contracts::tool::ToolResult;
use serde_json::{Map, Value};

/// 旧 transcript 跨网络传递的拒绝标记。
///
/// 新 typed `ToolResult` 使用 [`ErrorCode::POLICY_REFUSED`]；此字面量只用于读旧结果。
pub const LEGACY_REFUSAL_MARKER: &str = "Refused.";

/// typed 结果是否为 policy refusal；不从可变文案猜测。
#[must_use]
pub fn is_policy_refusal(result: &ToolResult) -> bool {
    result.error_code.as_deref() == Some(ErrorCode::POLICY_REFUSED.as_str())
}

/// 只解开 JSON string 外层；object/array 留给 [`for_display`]。
#[must_use]
pub fn as_text(text: &str) -> String {
    let trimmed = trim_ecmascript(text);
    if !trimmed.starts_with('"') {
        return text.to_owned();
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::String(value)) => value,
        _ => text.to_owned(),
    }
}

/// 把 tool 结果投影成 markdown/格式化 JSON，不丢弃 envelope 其余字段。
#[must_use]
pub fn for_display(text: &str) -> String {
    let decoded = as_text(text);
    let trimmed = trim_ecmascript(&decoded);
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return trimmed.to_owned();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return text.to_owned();
    };
    if let Value::Object(entries) = &parsed
        && let Some((markdown_key, markdown)) = longest_markdown(entries)
    {
        let rest = entries
            .iter()
            .filter(|(key, _)| key.as_str() != markdown_key)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        if rest.is_empty() {
            return markdown.to_owned();
        }
        return format!(
            "{markdown}\n\n```json\n{}\n```",
            serde_json::to_string_pretty(&Value::Object(rest))
                .expect("serde_json::Value 序列化不会失败")
        );
    }
    format!(
        "```json\n{}\n```",
        serde_json::to_string_pretty(&parsed).expect("serde_json::Value 序列化不会失败")
    )
}

fn longest_markdown(entries: &Map<String, Value>) -> Option<(&str, &str)> {
    entries
        .iter()
        .filter_map(|(key, value)| {
            let Value::String(text) = value else {
                return None;
            };
            (text.starts_with('#') || text.contains("\n#")).then_some((key.as_str(), text.as_str()))
        })
        .max_by_key(|(_, text)| text.encode_utf16().count())
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::ToolCallId;
    use openbot_contracts::tool::ToolCommitState;

    use super::*;

    #[test]
    fn a_json_encoded_string_is_unwrapped_escapes_and_all() {
        let refusal = "This deployment's policy does not allow that: search_notes on notes is blocked by the rule `mcp.server == \"notes\"`.";
        assert_eq!(as_text(&serde_json::to_string(refusal).unwrap()), refusal);
    }

    #[test]
    fn a_refusal_is_still_recognisable_as_one_after_decoding() {
        let encoded = serde_json::to_string("Refused. The rule says no.").unwrap();
        assert!(!encoded.starts_with(LEGACY_REFUSAL_MARKER));
        assert!(as_text(&encoded).starts_with(LEGACY_REFUSAL_MARKER));

        let typed = ToolResult {
            call_id: ToolCallId::new("call"),
            content: "administrator wording may change".to_owned(),
            error_code: Some(ErrorCode::POLICY_REFUSED.as_str().to_owned()),
            commit_state: ToolCommitState::NotCommitted,
            visible_bytes: 32,
            truncated: false,
        };
        assert!(is_policy_refusal(&typed));
    }

    #[test]
    fn plain_text_is_left_alone() {
        let text = "Meals under $75 need no receipt.";
        assert_eq!(as_text(text), text);
    }

    #[test]
    fn a_json_object_or_array_is_left_for_fordisplay() {
        assert_eq!(
            as_text(r##"{"results":"# Found"}"##),
            r##"{"results":"# Found"}"##
        );
        assert_eq!(as_text("[1,2]"), "[1,2]");
    }

    #[test]
    fn something_that_only_looks_like_json_is_drawn_as_it_came() {
        assert_eq!(as_text("\"unterminated"), "\"unterminated");
    }

    #[test]
    fn an_encoded_envelope_is_decoded_and_then_unwrapped() {
        let envelope = serde_json::to_string(r##"{"results":"# Found\n\nBody"}"##).unwrap();
        assert_eq!(for_display(&envelope), "# Found\n\nBody");
    }

    #[test]
    fn ecmascript_trim_is_the_shared_implementation_not_rust_trim() {
        let encoded = format!("\u{FEFF}{}\u{3000}", serde_json::to_string("ok").unwrap());
        assert_eq!(as_text(&encoded), "ok");
        assert_eq!(as_text("\u{0085}\"ok\"\u{0085}"), "\u{0085}\"ok\"\u{0085}");
    }
}
