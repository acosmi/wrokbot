//! Explicit memory 的 WASM-safe command/reply DTO（v3 §4.3 条 8–11）。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{BotId, ThreadId};

/// R1 只允许 preference/fact。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// 用户偏好。
    Preference,
    /// 带可验证来源的事实。
    Fact,
}

/// Memory sensitivity。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySensitivity {
    /// 普通。
    Normal,
    /// 敏感，只能严格同 scope 召回。
    Sensitive,
}

/// 用户可选择的 recall scope；owner 始终来自 AuthContext。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryScope {
    /// 当前用户全部 Bot。
    User,
    /// 一个 Bot。
    Bot {
        /// Bot id。
        bot_id: BotId,
    },
    /// 一个 thread。
    Thread {
        /// Thread id。
        thread_id: ThreadId,
    },
}

/// Fact/correction 的可验证来源。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemorySource {
    /// 来源 thread。
    pub thread_id: ThreadId,
    /// 来源 durable message id。
    pub message_id: String,
}

/// 唯一允许的三种 origin；GUI command 不接收本 enum，而由 application 固定 UserAction。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOrigin {
    /// GUI “记住这条”。
    UserAction,
    /// Built-in `remember` tool，经完整 tool pipeline。
    RememberTool,
    /// 验签 importer。
    VerifiedImport,
}

/// Memory 生命周期。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    /// 可召回。
    Active,
    /// 已由 correction 取代。
    Superseded,
    /// 禁止且内容已擦除。
    Forbidden,
    /// 删除且内容已擦除。
    Deleted,
}

/// Actor-scoped runtime memory write control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryControl {
    /// Whether runtime GUI/tool/correction paths may retain new memory content.
    pub writes_enabled: bool,
}

impl Default for MemoryControl {
    fn default() -> Self {
        Self {
            writes_enabled: true,
        }
    }
}

/// Closed update body for the actor's memory write control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMemoryControl {
    /// New authoritative write setting.
    pub writes_enabled: bool,
}

/// GUI “记住这条”的输入；没有 owner/origin/created_by 字段。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RememberMemory {
    /// Preference/fact。
    pub memory_kind: MemoryKind,
    /// Scope。
    pub scope: MemoryScope,
    /// 原文；application 不做 Unicode normalization。
    pub content: String,
    /// 结构化 tags。
    pub tags: Vec<String>,
    /// Sensitivity。
    pub sensitivity: MemorySensitivity,
    /// Fact 必填，preference 可选。
    pub source: Option<MemorySource>,
    /// 可选过期时刻。
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// Correct 操作允许修改的字段；scope/kind/source 继承原记录。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrectMemory {
    /// 新内容。
    pub content: String,
    /// 新 tags。
    pub tags: Vec<String>,
    /// 新 sensitivity。
    pub sensitivity: MemorySensitivity,
    /// 新 expiry；null/缺省清除旧 expiry。
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// 内容擦除操作。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryMutation {
    /// 禁止召回。
    Forbid,
    /// 用户删除。
    Delete,
}

/// 用户可见 memory 记录；forbidden/deleted 的 content 必须为 null。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryRecord {
    /// Memory id。
    pub memory_id: String,
    /// Owner；来自权威身份。
    pub owner_user_id: String,
    /// Scope。
    pub scope: MemoryScope,
    /// Kind。
    pub memory_kind: MemoryKind,
    /// 内容；擦除后为 None。
    pub content: Option<String>,
    /// 排序去重 tags。
    pub tags: Vec<String>,
    /// Sensitivity。
    pub sensitivity: MemorySensitivity,
    /// Provenance。
    pub source: Option<MemorySource>,
    /// Origin。
    pub origin: MemoryOrigin,
    /// 权威创建 actor。
    pub created_by: String,
    /// 被本条取代的旧 memory。
    pub supersedes_id: Option<String>,
    /// 状态。
    pub status: MemoryStatus,
    /// Expiry。
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// 创建时刻。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// 最近状态写时刻。
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Memory keyset 页。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryPage {
    /// 当前页。
    pub memories: Vec<MemoryRecord>,
    /// 下一页 cursor（上一页最后一条 memory id）；无下一页为 null。
    pub next_cursor: Option<String>,
}

/// Agent/GUI 显式召回请求；user scope 自动包含，Bot/thread scope 需权威可见性验证。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecallMemories {
    /// PostgreSQL simple FTS 查询文本；汉字可补充字面块 AND 匹配（R209）。
    pub query: String,
    /// 结构化 tag 精确过滤；多项采用 AND（记录必须包含全部请求 tag）。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 当前 Bot；None 时不召回 Bot-scoped memory。
    pub bot_id: Option<BotId>,
    /// 当前 thread；None 时不召回 Thread-scoped memory。
    pub thread_id: Option<ThreadId>,
    /// Application 钳到 1..=100。
    pub limit: Option<u32>,
}

/// 相关度/recency 顺序的 recall 结果。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecall {
    /// Recallable active records。
    pub memories: Vec<MemoryRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_wire_has_no_owner_origin_or_created_by_input() {
        let input = RememberMemory {
            memory_kind: MemoryKind::Preference,
            scope: MemoryScope::User,
            content: "tea".to_owned(),
            tags: vec!["drink".to_owned()],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("owner"), "{json}");
        assert!(!json.contains("origin"), "{json}");
        assert!(!json.contains("createdBy"), "{json}");
        assert!(serde_json::from_str::<RememberMemory>(&json).is_ok());
        assert!(
            serde_json::from_str::<RememberMemory>(
                r#"{"memoryKind":"preference","scope":{"kind":"user"},"content":"tea","tags":[],"sensitivity":"normal","source":null,"expiresAt":null,"origin":"verified_import"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn empty_page_is_messages_style_empty_not_null() {
        assert_eq!(
            serde_json::to_string(&MemoryPage::default()).unwrap(),
            r#"{"memories":[],"nextCursor":null}"#
        );
    }

    #[test]
    fn memory_control_defaults_enabled_and_rejects_extra_authority_fields() {
        assert_eq!(
            serde_json::to_string(&MemoryControl::default()).unwrap(),
            r#"{"writesEnabled":true}"#
        );
        assert!(
            serde_json::from_str::<UpdateMemoryControl>(
                r#"{"writesEnabled":false,"actor":"forged"}"#
            )
            .is_err()
        );
    }
}
