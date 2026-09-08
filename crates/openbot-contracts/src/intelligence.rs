//! Intelligence maintenance export/import 的中立 bundle DTO（v3 §20.3）。

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::command::ThreadRunEventKind;
use crate::memory::{MemoryKind, MemorySensitivity, MemorySource};

/// 唯一接受的 bundle envelope format。
pub const INTELLIGENCE_BUNDLE_FORMAT: &str = "openbot-intelligence-bundle-v1";
/// 唯一 payload schema version。
pub const INTELLIGENCE_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// 加密签名外信封；所有二进制字段为 RFC4648 base64。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceBundleEnvelope {
    /// 固定 format/算法版本。
    pub format: String,
    /// Bundle identity。
    pub bundle_id: String,
    /// Export 来源 deployment；不是 target authority。
    pub source_deployment_id: String,
    /// AES-GCM 12-byte nonce 的 base64。
    pub nonce: String,
    /// AES-256-GCM ciphertext+tag 的 base64。
    pub ciphertext: String,
    /// 解密后 payload 原始字节 SHA-256 lowercase hex。
    pub payload_sha256: String,
    /// 管理员选择 verification key 的非 secret id。
    pub signing_key_id: String,
    /// Ed25519 signature 的 base64。
    pub signature: String,
}

/// 解密后的 canonical payload。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceBundlePayload {
    /// 必须为 1。
    pub schema_version: u32,
    /// 必须与 envelope 相等。
    pub bundle_id: String,
    /// 必须与 envelope 相等。
    pub source_deployment_id: String,
    /// Export 时间。
    #[serde(with = "time::serde::rfc3339")]
    pub exported_at: OffsetDateTime,
    /// 固定来源证明。
    pub provenance: IntelligenceBundleProvenance,
    /// Thread aggregate；importer 按 thread_id 稳定排序，不信任输入顺序。
    pub threads: Vec<IntelligenceThreadExport>,
}

/// Exporter provenance。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceBundleProvenance {
    /// 固定 legacy OpenBot commit。
    pub upstream_commit: String,
    /// Exporter format implementation version。
    pub exporter_version: String,
    /// Intelligence project identity；只作报告/provenance。
    pub project_id: String,
}

/// 一个完整 thread aggregate。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceThreadExport {
    /// Legacy/native thread id。
    pub thread_id: String,
    /// Legacy creator user id；由独立 mapping 映射。
    pub created_by: String,
    /// Legacy member user ids。
    pub members: Vec<String>,
    /// Optional user-visible title。
    pub title: Option<String>,
    /// Thread anchor。
    pub anchor: IntelligenceThreadAnchor,
    /// Active/deleted final state。
    pub status: IntelligenceThreadStatus,
    /// Messages。
    pub messages: Vec<IntelligenceMessageExport>,
    /// Maintenance 已 drain 的 terminal runs。
    pub runs: Vec<IntelligenceRunExport>,
    /// 仅可观察且有 source 的 memory。
    pub memories: Vec<IntelligenceMemoryExport>,
    /// Exporter 给出的独立 per-thread oracle。
    pub checksum: IntelligenceThreadChecksum,
    /// Thread times。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// 最近更新时间。
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Deleted timestamp。
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
}

/// Legacy anchor；ID 仍须经 mapping/target DB 验证。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntelligenceThreadAnchor {
    /// Direct Bot。
    DirectBot {
        /// Legacy Bot id。
        bot_id: String,
    },
    /// Channel。
    Channel {
        /// Legacy channel id。
        channel_id: String,
    },
}

/// Thread final state。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceThreadStatus {
    /// 可继续读写。
    Active,
    /// Read-only archived。
    Archived,
    /// Soft-deleted。
    Deleted,
}

/// Durable message export。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceMessageExport {
    /// Message id。
    pub message_id: String,
    /// Thread-local sequence。
    pub sequence: u64,
    /// Role。
    pub role: IntelligenceMessageRole,
    /// AG-UI-compatible structured content。
    pub content: Value,
    /// Exporter render/full-text projection。
    pub search_text: String,
    /// Optional run binding。
    pub run_id: Option<String>,
    /// Optional legacy actor id。
    pub actor_id: Option<String>,
    /// Created timestamp。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Native messages role set，保留 summary 与 system 的区别。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceMessageRole {
    /// User。
    User,
    /// Assistant。
    Assistant,
    /// System。
    System,
    /// Tool result。
    Tool,
    /// Automatic context summary；不是 memory。
    Summary,
}

impl IntelligenceMessageRole {
    /// PostgreSQL literal。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
            Self::Summary => "summary",
        }
    }
}

/// Maintenance 后只允许 terminal run。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceRunExport {
    /// Run id。
    pub run_id: String,
    /// Legacy Bot id。
    pub bot_id: String,
    /// Legacy actor id。
    pub actor_id: String,
    /// Foreground/background。
    pub foreground: bool,
    /// Terminal status。
    pub status: IntelligenceRunStatus,
    /// Failed/reconciliation stable error code。
    pub error_code: Option<String>,
    /// Ordered semantic events。
    pub events: Vec<IntelligenceRunEventExport>,
    /// Created。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Started；cancel-before-start 可为空。
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    /// Terminal time。
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
}

/// Importable terminal run states。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceRunStatus {
    /// Completed。
    Completed,
    /// Deterministic failure。
    Failed,
    /// Cancelled。
    Cancelled,
    /// Unknown external commit。
    ReconciliationRequired,
}

impl IntelligenceRunStatus {
    /// PostgreSQL literal。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// Required terminal event kind。
    #[must_use]
    pub const fn event_kind(self) -> ThreadRunEventKind {
        match self {
            Self::Completed => ThreadRunEventKind::Completed,
            Self::Failed => ThreadRunEventKind::Failed,
            Self::Cancelled => ThreadRunEventKind::Cancelled,
            Self::ReconciliationRequired => ThreadRunEventKind::ReconciliationRequired,
        }
    }
}

/// Semantic event export。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceRunEventExport {
    /// Run-local sequence。
    pub sequence: u64,
    /// Thread-global cursor。
    pub event_sequence: u64,
    /// Closed event type。
    pub event_type: ThreadRunEventKind,
    /// Semantic payload object。
    pub payload: Value,
    /// Created。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// 仅 active、有 source 的 observable memory export。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceMemoryExport {
    /// Memory id。
    pub memory_id: String,
    /// Legacy owner user id；由独立 mapping 映射。
    pub owner_user_id: String,
    /// Legacy scope。
    pub scope: IntelligenceMemoryScope,
    /// Preference/fact。
    pub memory_kind: MemoryKind,
    /// Observable content。
    pub content: String,
    /// Tags。
    pub tags: Vec<String>,
    /// Sensitivity。
    pub sensitivity: MemorySensitivity,
    /// Mandatory verifiable source。
    pub source: MemorySource,
    /// Legacy creator id；由 mapping 映射。
    pub created_by: String,
    /// Optional superseded predecessor。
    pub supersedes_id: Option<String>,
    /// Active/superseded final state；forbidden/deleted 无 observable content，不进入 bundle。
    pub status: IntelligenceMemoryStatus,
    /// Expiry。
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Created。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Updated。
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Observable import memory final state。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceMemoryStatus {
    /// Recallable。
    Active,
    /// 被 correction 取代但仍保留 provenance/content。
    Superseded,
}

impl IntelligenceMemoryStatus {
    /// PostgreSQL literal。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
        }
    }
}

/// Import memory scope；user scope 的 owner 来自 mapped created_by/source membership。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntelligenceMemoryScope {
    /// User scope。
    User,
    /// Legacy Bot scope。
    Bot {
        /// Legacy Bot id。
        bot_id: String,
    },
    /// Thread scope；必须等于当前 aggregate thread。
    Thread {
        /// Thread id。
        thread_id: String,
    },
}

/// Exporter/importer 双方独立计算的 thread oracle。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceThreadChecksum {
    /// Thread core/membership/anchor/title projection hash。
    pub projection_hash: String,
    /// Message count。
    pub message_count: u64,
    /// Ordered canonical message hash。
    pub message_hash: String,
    /// Run event count。
    pub event_count: u64,
    /// Ordered canonical event hash。
    pub event_hash: String,
    /// Ordered run terminal state hash。
    pub terminal_state_hash: String,
    /// Observable memory count。
    pub memory_count: u64,
    /// Ordered observable memory hash。
    pub memory_hash: String,
    /// Deterministic sample render hash。
    pub sample_render_hash: String,
}

/// 独立管理员 mapping；bundle 自己不能决定 target authority。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelligenceImportMapping {
    /// Target deployment。
    pub target_deployment_id: String,
    /// Target tenant。
    pub target_tenant_id: String,
    /// Legacy user → current actor。
    pub users: BTreeMap<String, String>,
    /// Legacy Bot → current Bot。
    pub bots: BTreeMap<String, String>,
    /// Legacy channel → current channel。
    pub channels: BTreeMap<String, String>,
    /// Fingerprint 不匹配/命名前前缀期 UUID 的逐项管理员 claim。
    #[serde(default)]
    pub claimed_thread_ids: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_and_running_runs_have_no_bundle_wire_variant() {
        for value in [r#""queued""#, r#""running""#] {
            assert!(serde_json::from_str::<IntelligenceRunStatus>(value).is_err());
        }
        for value in [
            r#""completed""#,
            r#""failed""#,
            r#""cancelled""#,
            r#""reconciliation_required""#,
        ] {
            assert!(serde_json::from_str::<IntelligenceRunStatus>(value).is_ok());
        }
    }

    #[test]
    fn envelope_is_closed_and_cannot_smuggle_target_authority() {
        let valid = serde_json::json!({
            "format":INTELLIGENCE_BUNDLE_FORMAT,
            "bundleId":"bundle-1",
            "sourceDeploymentId":"source-1",
            "nonce":"AA==",
            "ciphertext":"AA==",
            "payloadSha256":"00",
            "signingKeyId":"key-1",
            "signature":"AA==",
        });
        assert!(serde_json::from_value::<IntelligenceBundleEnvelope>(valid.clone()).is_ok());
        let mut smuggled = valid;
        smuggled
            .as_object_mut()
            .unwrap()
            .insert("targetDeploymentId".to_owned(), serde_json::json!("admin"));
        assert!(serde_json::from_value::<IntelligenceBundleEnvelope>(smuggled).is_err());
    }
}
