//! 把模型使用的唯一 tool key 投影成人可读名称。

/// 一次 tool call 的人可读名称。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolDisplayName {
    /// 主动作名。
    pub label: String,
    /// MCP server 名；动作名已包含它时省略。
    pub detail: Option<String>,
}

/// 读取 tool key；非 `mcp__server__tool` 名字原样保留。
#[must_use]
pub fn read_tool_name(name: &str) -> ToolDisplayName {
    let mut parts = name.split("__");
    if parts.next() != Some("mcp") {
        return unchanged(name);
    }
    let Some(server) = parts.next() else {
        return unchanged(name);
    };
    let rest = parts.collect::<Vec<_>>();
    if rest.is_empty() {
        return unchanged(name);
    }
    let label = humanise(&rest.join("__"));
    let named = label
        .to_ascii_lowercase()
        .contains(&server.to_ascii_lowercase());
    ToolDisplayName {
        label,
        detail: (!named).then(|| server.to_owned()),
    }
}

fn unchanged(name: &str) -> ToolDisplayName {
    ToolDisplayName {
        label: name.to_owned(),
        detail: None,
    }
}

fn humanise(tool: &str) -> String {
    let mut separated = String::with_capacity(tool.len());
    let mut previous: Option<char> = None;
    let mut separator_pending = false;
    for current in tool.chars() {
        if matches!(current, '_' | '-') {
            separator_pending = true;
            continue;
        }
        let camel_boundary = previous.is_some_and(|value| {
            (value.is_ascii_lowercase() || value.is_ascii_digit()) && current.is_ascii_uppercase()
        });
        if !separated.is_empty() && (separator_pending || camel_boundary) {
            separated.push(' ');
        }
        separator_pending = false;
        separated.push(current);
        previous = Some(current);
    }
    let words = separated.trim().to_ascii_lowercase();
    let mut chars = words.chars();
    let Some(first) = chars.next() else {
        return tool.to_owned();
    };
    let mut label = String::with_capacity(words.len());
    label.push(first.to_ascii_uppercase());
    label.extend(chars);
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_mcp_tool_reads_as_an_action_against_a_named_server() {
        assert_eq!(
            read_tool_name("mcp__slack__post_message"),
            ToolDisplayName {
                label: "Post message".to_owned(),
                detail: Some("slack".to_owned()),
            }
        );
    }

    #[test]
    fn the_server_is_dropped_when_the_action_already_names_it() {
        assert_eq!(
            read_tool_name("mcp__notes__search_notes"),
            ToolDisplayName {
                label: "Search notes".to_owned(),
                detail: None,
            }
        );
    }

    #[test]
    fn camelcase_from_a_vendor_reads_the_same_way() {
        assert_eq!(
            read_tool_name("mcp__jira__searchJiraIssues"),
            ToolDisplayName {
                label: "Search jira issues".to_owned(),
                detail: None,
            }
        );
    }

    #[test]
    fn a_tool_name_containing_the_separator_keeps_all_of_it() {
        assert_eq!(
            read_tool_name("mcp__box__list__files"),
            ToolDisplayName {
                label: "List files".to_owned(),
                detail: Some("box".to_owned()),
            }
        );
    }

    #[test]
    fn a_component_the_app_registered_is_left_alone() {
        assert_eq!(
            read_tool_name("showBarChart"),
            ToolDisplayName {
                label: "showBarChart".to_owned(),
                detail: None,
            }
        );
    }
}
