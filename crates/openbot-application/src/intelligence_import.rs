//! Verified Intelligence bundle 的纯校验、mapping、checksum 与断点编排（v3 §20.3）。

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{DeploymentId, ThreadId};
use openbot_contracts::intelligence::{
    INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundlePayload, IntelligenceImportMapping,
    IntelligenceMemoryScope, IntelligenceRunStatus, IntelligenceThreadAnchor,
    IntelligenceThreadChecksum, IntelligenceThreadExport, IntelligenceThreadStatus,
};
use openbot_contracts::memory::MemoryKind;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// 固定 legacy OpenBot source commit。
pub const INTELLIGENCE_SOURCE_COMMIT: &str = "891df72f1827454d8b353d108fe5dd2313b7e30d";
const IMPORT_KINDS: [&str; 4] = ["thread", "message", "run_event", "memory"];

/// Bundle 已完成 crypto/schema 外层验证后的值；不实现 Deserialize。
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedIntelligenceBundle {
    payload: IntelligenceBundlePayload,
    payload_sha256: String,
    signing_key_id: String,
}

impl VerifiedIntelligenceBundle {
    /// Infra verifier 的唯一输出构造器。
    pub fn new(
        payload: IntelligenceBundlePayload,
        payload_sha256: String,
        signing_key_id: String,
    ) -> Result<Self, IntelligenceImportError> {
        validate_hash(&payload_sha256, "payload_sha256")?;
        validate_id(&signing_key_id, "signing_key_id")?;
        Ok(Self {
            payload,
            payload_sha256,
            signing_key_id,
        })
    }

    /// Payload。
    #[must_use]
    pub const fn payload(&self) -> &IntelligenceBundlePayload {
        &self.payload
    }

    /// Verified plaintext hash。
    #[must_use]
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    /// Verification key id。
    #[must_use]
    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }
}

/// Import 稳定错误域；不携带 bundle/数据库原文。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntelligenceImportError {
    /// Schema/mapping/checksum 输入错误。
    #[error("intelligence_import_invalid field={field}")]
    Invalid {
        /// 静态字段。
        field: &'static str,
    },
    /// Existing native row 与 bundle 不同。
    #[error("intelligence_import_conflict field={field}")]
    Conflict {
        /// 静态字段。
        field: &'static str,
    },
    /// PostgreSQL/crypto/file dependency unavailable。
    #[error("intelligence_import_unavailable")]
    Unavailable,
    /// Durable cursor/row corruption。
    #[error("intelligence_import_corrupt field={field}")]
    Corrupt {
        /// 静态字段。
        field: &'static str,
    },
    /// Commit unknown；同 bundle/cursor 可安全重跑。
    #[error("intelligence_import_commit_unknown")]
    CommitUnknown,
}

/// 四类 cursor 的累计状态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelligenceImportProgress {
    /// Last committed thread id；`$none` 表示尚未写 thread。
    pub cursor: String,
    /// Thread aggregates。
    pub thread_count: u64,
    /// Messages。
    pub message_count: u64,
    /// Run events。
    pub event_count: u64,
    /// Observable memories。
    pub memory_count: u64,
    /// Per-kind ordered chain hashes。
    pub thread_hash: String,
    /// Message chain hash。
    pub message_hash: String,
    /// Event chain hash。
    pub event_hash: String,
    /// Memory chain hash。
    pub memory_hash: String,
    /// running/completed/failed。
    pub status: IntelligenceImportCursorStatus,
}

impl IntelligenceImportProgress {
    fn empty() -> Self {
        let empty = hex_sha256(&[]);
        Self {
            cursor: "$none".to_owned(),
            thread_count: 0,
            message_count: 0,
            event_count: 0,
            memory_count: 0,
            thread_hash: empty.clone(),
            message_hash: empty.clone(),
            event_hash: empty.clone(),
            memory_hash: empty,
            status: IntelligenceImportCursorStatus::Running,
        }
    }
}

/// Cursor status。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelligenceImportCursorStatus {
    /// 正在导入。
    Running,
    /// 全 bundle checksum 完成。
    Completed,
    /// 已验证 bundle 的 DB/import failure。
    Failed,
}

impl IntelligenceImportCursorStatus {
    /// PostgreSQL literal。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// 单 thread 原子写请求；thread 已完成 target mapping 与 source checksum 验证。
#[derive(Clone, Debug)]
pub struct IntelligenceThreadImportRequest {
    /// Bundle id。
    pub bundle_id: String,
    /// Verified payload hash。
    pub payload_sha256: String,
    /// Target deployment。
    pub target_deployment_id: String,
    /// Target tenant。
    pub target_tenant_id: String,
    /// Verification provenance。
    pub provenance: Value,
    /// Target-normalized thread aggregate。
    pub thread: IntelligenceThreadExport,
    /// 该 thread 的 target checksum oracle。
    pub checksum: IntelligenceThreadChecksum,
    /// 事务开始前必须精确匹配的累计 progress。
    pub previous_progress: IntelligenceImportProgress,
    /// 事务 commit 后应得到的累计 progress。
    pub progress: IntelligenceImportProgress,
}

/// Store 对本次 thread 的 observed checksum。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelligenceThreadImportReceipt {
    /// PostgreSQL 重算值。
    pub checksum: IntelligenceThreadChecksum,
    /// Cursor 已是相同 progress 的精确重放。
    pub replayed: bool,
}

/// PostgreSQL import port；最终请求路径不持有它。
#[async_trait]
pub trait IntelligenceImportStore: Send + Sync {
    /// 读取并验证四行同步 cursor；不存在返回 None。
    async fn load_progress(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
    ) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError>;

    /// 单 thread + 四 cursor 同事务。
    async fn import_thread(
        &self,
        request: IntelligenceThreadImportRequest,
    ) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError>;

    /// 从 PostgreSQL 重建一个已导入 thread 的 ordered checksum；completed 重跑也必须执行。
    async fn verify_thread(
        &self,
        thread_id: &str,
    ) -> Result<IntelligenceThreadChecksum, IntelligenceImportError>;

    /// 四 cursor 同事务 completed；重复完成幂等。
    async fn complete_bundle(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
        progress: &IntelligenceImportProgress,
    ) -> Result<(), IntelligenceImportError>;

    /// 已验证 bundle 的失败标记；不得覆盖 completed。
    async fn mark_failed(
        &self,
        bundle_id: &str,
        target_deployment_id: &str,
        payload_sha256: &str,
    ) -> Result<(), IntelligenceImportError>;

    /// 全部 bundle 完成后的 tool_calls→runs historical FK preflight + VALIDATE。
    async fn validate_tool_run_fk(
        &self,
    ) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError>;
}

/// Staged historical tool→run FK 的最终报告。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntelligenceToolRunFkReport {
    /// 尚未 completed 的 bundle 数。
    pub incomplete_bundle_count: u64,
    /// Historical orphan tool call 数；不输出 ID。
    pub orphan_tool_call_count: u64,
    /// `pg_constraint.convalidated`。
    pub validated: bool,
}

impl IntelligenceToolRunFkReport {
    /// 是否需要管理员先补 bundle/orphan。
    #[must_use]
    pub fn requires_action(&self) -> bool {
        self.incomplete_bundle_count != 0 || self.orphan_tool_call_count != 0 || !self.validated
    }
}

/// Import 全部完成后才调用；显式 CLI 调用本身是“本 deployment bundle 已齐”的管理员确认。
pub async fn validate_intelligence_tool_run_fk<S: IntelligenceImportStore + ?Sized>(
    store: &S,
) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
    store.validate_tool_run_fk().await
}

/// CLI 可安全输出的 import 结果。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntelligenceImportReport {
    /// Bundle id。
    pub bundle_id: String,
    /// Target deployment。
    pub target_deployment_id: String,
    /// Outcome。
    pub status: IntelligenceImportReportStatus,
    /// 必须由管理员逐项加入 mapping claim 后重跑的 thread ids。
    pub claim_required: Vec<String>,
    /// Committed totals。
    pub thread_count: u64,
    /// Message total。
    pub message_count: u64,
    /// Event total。
    pub event_count: u64,
    /// Memory total。
    pub memory_count: u64,
    /// Last cursor。
    pub cursor: String,
}

impl IntelligenceImportReport {
    /// 是否需要管理员动作。
    #[must_use]
    pub fn requires_action(&self) -> bool {
        self.status == IntelligenceImportReportStatus::ClaimsRequired
    }
}

/// Import report status。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceImportReportStatus {
    /// 全部 committed + checksum verified。
    Completed,
    /// 未写 DB，等待 thread claim。
    ClaimsRequired,
}

/// 验证、mapping、resume、逐 thread import 与 completed cursor 的唯一 use case。
pub async fn import_intelligence_bundle<S: IntelligenceImportStore + ?Sized>(
    store: &S,
    verified: VerifiedIntelligenceBundle,
    mapping: IntelligenceImportMapping,
) -> Result<IntelligenceImportReport, IntelligenceImportError> {
    validate_mapping(&mapping)?;
    let mut threads = validate_payload(verified.payload())?;
    for thread in &threads {
        let observed = compute_intelligence_thread_checksum(thread)?;
        if observed != thread.checksum {
            return Err(IntelligenceImportError::Invalid {
                field: "thread_checksum",
            });
        }
    }
    let target_identity = ThreadIdentity::new(&DeploymentId::new(&mapping.target_deployment_id));
    let bundle_ids: BTreeSet<_> = threads
        .iter()
        .map(|thread| thread.thread_id.clone())
        .collect();
    if mapping
        .claimed_thread_ids
        .iter()
        .any(|thread| !bundle_ids.contains(thread))
    {
        return Err(IntelligenceImportError::Invalid {
            field: "claimed_thread_ids",
        });
    }
    let mut claim_required = Vec::new();
    for thread in &threads {
        let id = ThreadId::new(&thread.thread_id);
        if !target_identity.owns(&id) && !mapping.claimed_thread_ids.contains(&thread.thread_id) {
            claim_required.push(thread.thread_id.clone());
        }
    }
    if !claim_required.is_empty() {
        return Ok(IntelligenceImportReport {
            bundle_id: verified.payload().bundle_id.clone(),
            target_deployment_id: mapping.target_deployment_id,
            status: IntelligenceImportReportStatus::ClaimsRequired,
            claim_required,
            thread_count: 0,
            message_count: 0,
            event_count: 0,
            memory_count: 0,
            cursor: "$none".to_owned(),
        });
    }
    for thread in &mut threads {
        normalize_thread(thread, &mapping)?;
        thread.checksum = compute_intelligence_thread_checksum(thread)?;
    }

    let provenance = json!({
        "payloadSha256": verified.payload_sha256(),
        "signingKeyId": verified.signing_key_id(),
        "sourceDeploymentId": verified.payload().source_deployment_id,
        "upstreamCommit": verified.payload().provenance.upstream_commit,
        "exporterVersion": verified.payload().provenance.exporter_version,
        "projectId": verified.payload().provenance.project_id,
    });
    let mut progress = store
        .load_progress(
            &verified.payload().bundle_id,
            &mapping.target_deployment_id,
            verified.payload_sha256(),
        )
        .await?
        .unwrap_or_else(IntelligenceImportProgress::empty);
    let start = resume_index(&threads, &progress)?;
    for thread in threads.iter().skip(start).cloned() {
        let checksum = thread.checksum.clone();
        let next = advance_progress(&progress, &thread.thread_id, &checksum)?;
        let request = IntelligenceThreadImportRequest {
            bundle_id: verified.payload().bundle_id.clone(),
            payload_sha256: verified.payload_sha256().to_owned(),
            target_deployment_id: mapping.target_deployment_id.clone(),
            target_tenant_id: mapping.target_tenant_id.clone(),
            provenance: provenance.clone(),
            thread,
            checksum: checksum.clone(),
            previous_progress: progress.clone(),
            progress: next.clone(),
        };
        match store.import_thread(request).await {
            Ok(receipt) if receipt.checksum == checksum => progress = next,
            Ok(_) => {
                let _ = store
                    .mark_failed(
                        &verified.payload().bundle_id,
                        &mapping.target_deployment_id,
                        verified.payload_sha256(),
                    )
                    .await;
                return Err(IntelligenceImportError::Corrupt {
                    field: "database_checksum",
                });
            }
            Err(error) => {
                let _ = store
                    .mark_failed(
                        &verified.payload().bundle_id,
                        &mapping.target_deployment_id,
                        verified.payload_sha256(),
                    )
                    .await;
                return Err(error);
            }
        }
    }
    for thread in &threads {
        if store.verify_thread(&thread.thread_id).await? != thread.checksum {
            let _ = store
                .mark_failed(
                    &verified.payload().bundle_id,
                    &mapping.target_deployment_id,
                    verified.payload_sha256(),
                )
                .await;
            return Err(IntelligenceImportError::Corrupt {
                field: "final_database_checksum",
            });
        }
    }
    store
        .complete_bundle(
            &verified.payload().bundle_id,
            &mapping.target_deployment_id,
            verified.payload_sha256(),
            &progress,
        )
        .await?;
    Ok(IntelligenceImportReport {
        bundle_id: verified.payload().bundle_id.clone(),
        target_deployment_id: mapping.target_deployment_id,
        status: IntelligenceImportReportStatus::Completed,
        claim_required: Vec::new(),
        thread_count: progress.thread_count,
        message_count: progress.message_count,
        event_count: progress.event_count,
        memory_count: progress.memory_count,
        cursor: progress.cursor,
    })
}

/// 规范 checksum；exporter 必须按同一字段/排序/length framing 实现。
pub fn compute_intelligence_thread_checksum(
    thread: &IntelligenceThreadExport,
) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
    let projection_hash = hash_values([json!({
        "threadId":thread.thread_id,
        "createdBy":thread.created_by,
        "members":thread.members,
        "title":thread.title,
        "anchor":thread.anchor,
        "status":thread.status,
        "createdAt":thread.created_at.unix_timestamp_nanos().to_string(),
        "updatedAt":thread.updated_at.unix_timestamp_nanos().to_string(),
        "deletedAt":thread.deleted_at.map(|value| value.unix_timestamp_nanos().to_string()),
    })])?;
    let mut messages = thread.messages.iter().collect::<Vec<_>>();
    messages.sort_by_key(|message| message.sequence);
    let message_hash = hash_values(messages.iter().map(|message| {
        json!({
            "id":message.message_id,
            "seq":message.sequence,
            "role":message.role.as_str(),
            "content":message.content,
            "searchText":message.search_text,
            "runId":message.run_id,
            "createdAt":message.created_at.unix_timestamp_nanos().to_string(),
        })
    }))?;
    let mut events = Vec::new();
    let mut terminals = Vec::new();
    for run in &thread.runs {
        for event in &run.events {
            events.push((run.run_id.as_str(), event));
        }
        let terminal_sequence = run
            .events
            .iter()
            .find(|event| event.event_type.is_terminal())
            .map(|event| event.sequence)
            .ok_or(IntelligenceImportError::Invalid {
                field: "terminal_event",
            })?;
        terminals.push(json!({
            "runId":run.run_id,
            "status":run.status.as_str(),
            "errorCode":run.error_code,
            "terminalSequence":terminal_sequence,
        }));
    }
    events.sort_by_key(|(run_id, event)| (event.event_sequence, *run_id, event.sequence));
    terminals.sort_by(|left, right| left["runId"].as_str().cmp(&right["runId"].as_str()));
    let event_hash = hash_values(events.iter().map(|(run_id, event)| {
        json!({
            "runId":run_id,
            "seq":event.sequence,
            "eventSeq":event.event_sequence,
            "type":event.event_type,
            "payload":event.payload,
            "createdAt":event.created_at.unix_timestamp_nanos().to_string(),
        })
    }))?;
    let terminal_state_hash = hash_values(terminals)?;
    let mut memories = thread.memories.iter().collect::<Vec<_>>();
    memories.sort_by(|left, right| left.memory_id.cmp(&right.memory_id));
    let memory_hash = hash_values(memories.iter().map(|memory| {
        json!({
            "id":memory.memory_id,
            "owner":memory.owner_user_id,
            "scope":memory.scope,
            "kind":memory.memory_kind,
            "content":memory.content,
            "tags":memory.tags,
            "sensitivity":memory.sensitivity,
            "source":memory.source,
            "createdBy":memory.created_by,
            "supersedesId":memory.supersedes_id,
            "status":memory.status,
            "expiresAt":memory.expires_at.map(|value| value.unix_timestamp_nanos().to_string()),
            "createdAt":memory.created_at.unix_timestamp_nanos().to_string(),
            "updatedAt":memory.updated_at.unix_timestamp_nanos().to_string(),
        })
    }))?;
    let sample_render_hash = hash_values(
        messages
            .into_iter()
            .map(|message| json!({"role":message.role.as_str(),"text":message.search_text})),
    )?;
    Ok(IntelligenceThreadChecksum {
        projection_hash,
        message_count: u64::try_from(thread.messages.len()).map_err(|_| {
            IntelligenceImportError::Invalid {
                field: "message_count",
            }
        })?,
        message_hash,
        event_count: u64::try_from(events.len()).map_err(|_| IntelligenceImportError::Invalid {
            field: "event_count",
        })?,
        event_hash,
        terminal_state_hash,
        memory_count: u64::try_from(thread.memories.len()).map_err(|_| {
            IntelligenceImportError::Invalid {
                field: "memory_count",
            }
        })?,
        memory_hash,
        sample_render_hash,
    })
}

fn validate_payload(
    payload: &IntelligenceBundlePayload,
) -> Result<Vec<IntelligenceThreadExport>, IntelligenceImportError> {
    if payload.schema_version != INTELLIGENCE_BUNDLE_SCHEMA_VERSION {
        return Err(IntelligenceImportError::Invalid {
            field: "schema_version",
        });
    }
    validate_id(&payload.bundle_id, "bundle_id")?;
    validate_id(&payload.source_deployment_id, "source_deployment_id")?;
    if payload.provenance.upstream_commit != INTELLIGENCE_SOURCE_COMMIT {
        return Err(IntelligenceImportError::Invalid {
            field: "upstream_commit",
        });
    }
    validate_id(&payload.provenance.exporter_version, "exporter_version")?;
    validate_id(&payload.provenance.project_id, "project_id")?;
    let mut threads = payload.threads.clone();
    threads.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
    let mut ids = BTreeSet::new();
    for thread in &threads {
        validate_thread(thread)?;
        if !ids.insert(thread.thread_id.clone()) {
            return Err(IntelligenceImportError::Invalid {
                field: "thread_id_duplicate",
            });
        }
    }
    Ok(threads)
}

fn validate_thread(thread: &IntelligenceThreadExport) -> Result<(), IntelligenceImportError> {
    validate_id(&thread.thread_id, "thread_id")?;
    let thread_id = ThreadId::new(&thread.thread_id);
    if !ThreadIdentity::is_plausible(&thread_id) {
        return Err(IntelligenceImportError::Invalid { field: "thread_id" });
    }
    validate_id(&thread.created_by, "created_by")?;
    if thread
        .title
        .as_ref()
        .is_some_and(|title| title.len() > 4096 || title.as_bytes().contains(&0))
    {
        return Err(IntelligenceImportError::Invalid {
            field: "thread_title",
        });
    }
    if thread.members.is_empty() || !thread.members.contains(&thread.created_by) {
        return Err(IntelligenceImportError::Invalid { field: "members" });
    }
    let mut members = BTreeSet::new();
    for member in &thread.members {
        validate_id(member, "member")?;
        if !members.insert(member) {
            return Err(IntelligenceImportError::Invalid {
                field: "member_duplicate",
            });
        }
    }
    if thread
        .members
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(IntelligenceImportError::Invalid {
            field: "members_order",
        });
    }
    match &thread.anchor {
        IntelligenceThreadAnchor::DirectBot { bot_id } => validate_id(bot_id, "anchor_bot")?,
        IntelligenceThreadAnchor::Channel { channel_id } => {
            validate_id(channel_id, "anchor_channel")?;
        }
    }
    match thread.status {
        IntelligenceThreadStatus::Active | IntelligenceThreadStatus::Archived
            if thread.deleted_at.is_some() =>
        {
            return Err(IntelligenceImportError::Invalid {
                field: "thread_deleted_at",
            });
        }
        IntelligenceThreadStatus::Deleted if thread.deleted_at.is_none() => {
            return Err(IntelligenceImportError::Invalid {
                field: "thread_deleted_at",
            });
        }
        IntelligenceThreadStatus::Active
        | IntelligenceThreadStatus::Archived
        | IntelligenceThreadStatus::Deleted => {}
    }
    if thread.updated_at < thread.created_at
        || thread
            .deleted_at
            .is_some_and(|value| value < thread.created_at)
    {
        return Err(IntelligenceImportError::Invalid {
            field: "thread_time",
        });
    }
    validate_pg_time(thread.created_at, "thread_time")?;
    validate_pg_time(thread.updated_at, "thread_time")?;
    if let Some(value) = thread.deleted_at {
        validate_pg_time(value, "thread_time")?;
    }
    validate_messages(thread)?;
    validate_runs(thread)?;
    validate_memories(thread)
}

fn validate_messages(thread: &IntelligenceThreadExport) -> Result<(), IntelligenceImportError> {
    let run_ids: BTreeSet<_> = thread.runs.iter().map(|run| run.run_id.as_str()).collect();
    let mut messages = thread.messages.iter().collect::<Vec<_>>();
    messages.sort_by_key(|message| message.sequence);
    let mut ids = BTreeSet::new();
    for (expected, message) in messages.into_iter().enumerate() {
        validate_id(&message.message_id, "message_id")?;
        if message.sequence != expected as u64 || !ids.insert(message.message_id.as_str()) {
            return Err(IntelligenceImportError::Invalid {
                field: "message_sequence",
            });
        }
        if message.content.is_null()
            || message.search_text.as_bytes().contains(&0)
            || message
                .run_id
                .as_ref()
                .is_some_and(|run| !run_ids.contains(run.as_str()))
        {
            return Err(IntelligenceImportError::Invalid {
                field: "message_shape",
            });
        }
        if let Some(actor) = &message.actor_id {
            validate_id(actor, "message_actor")?;
        }
        validate_pg_time(message.created_at, "message_time")?;
    }
    Ok(())
}

fn validate_runs(thread: &IntelligenceThreadExport) -> Result<(), IntelligenceImportError> {
    let mut run_ids = BTreeSet::new();
    let mut global_events = Vec::new();
    for run in &thread.runs {
        validate_id(&run.run_id, "run_id")?;
        validate_id(&run.bot_id, "run_bot")?;
        validate_id(&run.actor_id, "run_actor")?;
        if let Some(code) = &run.error_code {
            validate_id(code, "run_error_code")?;
        }
        if !run_ids.insert(run.run_id.as_str()) {
            return Err(IntelligenceImportError::Invalid {
                field: "run_id_duplicate",
            });
        }
        if matches!(
            run.status,
            IntelligenceRunStatus::Failed | IntelligenceRunStatus::ReconciliationRequired
        ) != run.error_code.is_some()
            || run.finished_at < run.created_at
            || run
                .started_at
                .is_some_and(|value| value < run.created_at || value > run.finished_at)
            || (run.status != IntelligenceRunStatus::Cancelled && run.started_at.is_none())
        {
            return Err(IntelligenceImportError::Invalid { field: "run_shape" });
        }
        validate_pg_time(run.created_at, "run_time")?;
        validate_pg_time(run.finished_at, "run_time")?;
        if let Some(value) = run.started_at {
            validate_pg_time(value, "run_time")?;
        }
        let mut events = run.events.iter().collect::<Vec<_>>();
        events.sort_by_key(|event| event.sequence);
        let event_start_valid = match (run.started_at, events.first()) {
            (Some(_), Some(event)) => {
                event.event_type == openbot_contracts::command::ThreadRunEventKind::Started
            }
            (None, Some(event)) => {
                run.status == IntelligenceRunStatus::Cancelled
                    && events.len() == 1
                    && event.event_type == openbot_contracts::command::ThreadRunEventKind::Cancelled
            }
            (_, None) => false,
        };
        if !event_start_valid {
            return Err(IntelligenceImportError::Invalid {
                field: "run_events",
            });
        }
        let mut terminal_count = 0;
        for (expected, event) in events.iter().enumerate() {
            if event.sequence != expected as u64 || !event.payload.is_object() {
                return Err(IntelligenceImportError::Invalid {
                    field: "run_event_sequence",
                });
            }
            if event.event_type.is_terminal() {
                terminal_count += 1;
                if event.event_type != run.status.event_kind() || expected + 1 != events.len() {
                    return Err(IntelligenceImportError::Invalid {
                        field: "terminal_event",
                    });
                }
            }
            validate_pg_time(event.created_at, "run_event_time")?;
            global_events.push(event.event_sequence);
        }
        if terminal_count != 1 {
            return Err(IntelligenceImportError::Invalid {
                field: "terminal_event",
            });
        }
    }
    global_events.sort_unstable();
    if global_events
        .iter()
        .enumerate()
        .any(|(expected, actual)| *actual != expected as u64)
    {
        return Err(IntelligenceImportError::Invalid {
            field: "thread_event_sequence",
        });
    }
    Ok(())
}

fn validate_memories(thread: &IntelligenceThreadExport) -> Result<(), IntelligenceImportError> {
    let message_ids: BTreeSet<_> = thread
        .messages
        .iter()
        .map(|message| message.message_id.as_str())
        .collect();
    let memory_ids: BTreeSet<_> = thread
        .memories
        .iter()
        .map(|memory| memory.memory_id.as_str())
        .collect();
    if memory_ids.len() != thread.memories.len() {
        return Err(IntelligenceImportError::Invalid {
            field: "memory_id_duplicate",
        });
    }
    for memory in &thread.memories {
        validate_id(&memory.memory_id, "memory_id")?;
        validate_id(&memory.owner_user_id, "memory_owner")?;
        validate_id(&memory.created_by, "memory_created_by")?;
        if memory.content.is_empty()
            || memory.content.as_bytes().contains(&0)
            || !thread.members.contains(&memory.owner_user_id)
            || !thread.members.contains(&memory.created_by)
            || memory.source.thread_id.as_str() != thread.thread_id
            || !message_ids.contains(memory.source.message_id.as_str())
            || memory.memory_kind == MemoryKind::Fact && memory.source.message_id.is_empty()
            || memory.tags.len() > crate::use_cases::MAX_MEMORY_TAGS
            || memory.tags.iter().any(|tag| {
                tag.is_empty()
                    || tag.as_bytes().contains(&0)
                    || tag.len() > crate::use_cases::MAX_MEMORY_TAG_BYTES
            })
            || memory
                .expires_at
                .is_some_and(|value| value <= memory.created_at)
            || memory.updated_at < memory.created_at
            || memory
                .tags
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
            || memory
                .supersedes_id
                .as_ref()
                .is_some_and(|id| !memory_ids.contains(id.as_str()) || id == &memory.memory_id)
        {
            return Err(IntelligenceImportError::Invalid {
                field: "memory_shape",
            });
        }
        validate_pg_time(memory.created_at, "memory_time")?;
        validate_pg_time(memory.updated_at, "memory_time")?;
        if let Some(value) = memory.expires_at {
            validate_pg_time(value, "memory_time")?;
        }
        match &memory.scope {
            IntelligenceMemoryScope::User => {}
            IntelligenceMemoryScope::Bot { bot_id } => validate_id(bot_id, "memory_bot")?,
            IntelligenceMemoryScope::Thread { thread_id } if thread_id == &thread.thread_id => {}
            IntelligenceMemoryScope::Thread { .. } => {
                return Err(IntelligenceImportError::Invalid {
                    field: "memory_thread_scope",
                });
            }
        }
    }
    let by_id: BTreeMap<_, _> = thread
        .memories
        .iter()
        .map(|memory| (memory.memory_id.as_str(), memory))
        .collect();
    let mut successor_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for memory in &thread.memories {
        if let Some(parent) = memory.supersedes_id.as_deref() {
            *successor_counts.entry(parent).or_default() += 1;
            if by_id[parent].status
                != openbot_contracts::intelligence::IntelligenceMemoryStatus::Superseded
                || successor_counts[parent] > 1
            {
                return Err(IntelligenceImportError::Invalid {
                    field: "memory_supersession",
                });
            }
        }
        let mut seen = BTreeSet::new();
        let mut cursor = Some(memory.memory_id.as_str());
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(IntelligenceImportError::Invalid {
                    field: "memory_supersession_cycle",
                });
            }
            cursor = by_id[id].supersedes_id.as_deref();
        }
    }
    for memory in &thread.memories {
        if (memory.status == openbot_contracts::intelligence::IntelligenceMemoryStatus::Superseded)
            != (successor_counts
                .get(memory.memory_id.as_str())
                .copied()
                .unwrap_or(0)
                == 1)
        {
            return Err(IntelligenceImportError::Invalid {
                field: "memory_supersession",
            });
        }
    }
    Ok(())
}

fn validate_mapping(mapping: &IntelligenceImportMapping) -> Result<(), IntelligenceImportError> {
    validate_id(&mapping.target_deployment_id, "target_deployment_id")?;
    validate_id(&mapping.target_tenant_id, "target_tenant_id")?;
    for (source, target) in mapping
        .users
        .iter()
        .chain(mapping.bots.iter())
        .chain(mapping.channels.iter())
    {
        validate_id(source, "mapping_source")?;
        validate_id(target, "mapping_target")?;
    }
    Ok(())
}

fn normalize_thread(
    thread: &mut IntelligenceThreadExport,
    mapping: &IntelligenceImportMapping,
) -> Result<(), IntelligenceImportError> {
    thread.created_by = mapped(&mapping.users, &thread.created_by, "user_mapping")?;
    thread.members = thread
        .members
        .iter()
        .map(|value| mapped(&mapping.users, value, "user_mapping"))
        .collect::<Result<_, _>>()?;
    thread.members.sort();
    thread.members.dedup();
    match &mut thread.anchor {
        IntelligenceThreadAnchor::DirectBot { bot_id } => {
            *bot_id = mapped(&mapping.bots, bot_id, "bot_mapping")?;
        }
        IntelligenceThreadAnchor::Channel { channel_id } => {
            *channel_id = mapped(&mapping.channels, channel_id, "channel_mapping")?;
        }
    }
    for message in &mut thread.messages {
        if let Some(actor) = &mut message.actor_id {
            *actor = mapped(&mapping.users, actor, "user_mapping")?;
        }
    }
    for run in &mut thread.runs {
        run.bot_id = mapped(&mapping.bots, &run.bot_id, "bot_mapping")?;
        run.actor_id = mapped(&mapping.users, &run.actor_id, "user_mapping")?;
    }
    for memory in &mut thread.memories {
        memory.owner_user_id = mapped(&mapping.users, &memory.owner_user_id, "user_mapping")?;
        memory.created_by = mapped(&mapping.users, &memory.created_by, "user_mapping")?;
        if let IntelligenceMemoryScope::Bot { bot_id } = &mut memory.scope {
            *bot_id = mapped(&mapping.bots, bot_id, "bot_mapping")?;
        }
        memory.tags.sort();
        memory.tags.dedup();
    }
    Ok(())
}

fn mapped(
    mapping: &BTreeMap<String, String>,
    value: &str,
    field: &'static str,
) -> Result<String, IntelligenceImportError> {
    mapping
        .get(value)
        .cloned()
        .ok_or(IntelligenceImportError::Invalid { field })
}

fn resume_index(
    threads: &[IntelligenceThreadExport],
    progress: &IntelligenceImportProgress,
) -> Result<usize, IntelligenceImportError> {
    if progress.cursor == "$none" {
        return Ok(0);
    }
    threads
        .iter()
        .position(|thread| thread.thread_id == progress.cursor)
        .map(|index| index + 1)
        .ok_or(IntelligenceImportError::Conflict {
            field: "cursor_bundle_binding",
        })
}

fn advance_progress(
    previous: &IntelligenceImportProgress,
    thread_id: &str,
    checksum: &IntelligenceThreadChecksum,
) -> Result<IntelligenceImportProgress, IntelligenceImportError> {
    Ok(IntelligenceImportProgress {
        cursor: thread_id.to_owned(),
        thread_count: previous.thread_count.checked_add(1).ok_or(
            IntelligenceImportError::Invalid {
                field: "thread_count",
            },
        )?,
        message_count: previous
            .message_count
            .checked_add(checksum.message_count)
            .ok_or(IntelligenceImportError::Invalid {
                field: "message_count",
            })?,
        event_count: previous
            .event_count
            .checked_add(checksum.event_count)
            .ok_or(IntelligenceImportError::Invalid {
                field: "event_count",
            })?,
        memory_count: previous
            .memory_count
            .checked_add(checksum.memory_count)
            .ok_or(IntelligenceImportError::Invalid {
                field: "memory_count",
            })?,
        thread_hash: chain_hash(&previous.thread_hash, &hash_checksum(checksum)?)?,
        message_hash: chain_hash(&previous.message_hash, &checksum.message_hash)?,
        event_hash: chain_hash(&previous.event_hash, &checksum.event_hash)?,
        memory_hash: chain_hash(&previous.memory_hash, &checksum.memory_hash)?,
        status: IntelligenceImportCursorStatus::Running,
    })
}

fn hash_checksum(checksum: &IntelligenceThreadChecksum) -> Result<String, IntelligenceImportError> {
    hash_values([
        serde_json::to_value(checksum).map_err(|_| IntelligenceImportError::Invalid {
            field: "thread_checksum",
        })?,
    ])
}

fn chain_hash(previous: &str, next: &str) -> Result<String, IntelligenceImportError> {
    validate_hash(previous, "cursor_hash")?;
    validate_hash(next, "thread_hash")?;
    let mut bytes = decode_hex(previous)?;
    bytes.extend(decode_hex(next)?);
    Ok(hex_sha256(&bytes))
}

fn hash_values<I>(values: I) -> Result<String, IntelligenceImportError>
where
    I: IntoIterator<Item = Value>,
{
    let mut digest = Sha256::new();
    for value in values {
        let bytes = serde_json::to_vec(&value).map_err(|_| IntelligenceImportError::Invalid {
            field: "canonical_json",
        })?;
        digest.update(
            u64::try_from(bytes.len())
                .map_err(|_| IntelligenceImportError::Invalid {
                    field: "canonical_json",
                })?
                .to_be_bytes(),
        );
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_hash(value: &str, field: &'static str) -> Result<(), IntelligenceImportError> {
    if value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(IntelligenceImportError::Invalid { field })
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, IntelligenceImportError> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(IntelligenceImportError::Invalid { field: "hash" });
    }
    pairs
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair)
                .map_err(|_| IntelligenceImportError::Invalid { field: "hash" })?;
            u8::from_str_radix(text, 16)
                .map_err(|_| IntelligenceImportError::Invalid { field: "hash" })
        })
        .collect()
}

fn validate_id(value: &str, field: &'static str) -> Result<(), IntelligenceImportError> {
    if value.is_empty() || value.len() > 512 || value.as_bytes().contains(&0) {
        Err(IntelligenceImportError::Invalid { field })
    } else {
        Ok(())
    }
}

fn validate_pg_time(
    value: time::OffsetDateTime,
    field: &'static str,
) -> Result<(), IntelligenceImportError> {
    if value.nanosecond().is_multiple_of(1_000) {
        Ok(())
    } else {
        Err(IntelligenceImportError::Invalid { field })
    }
}

/// Cursor kinds，供 adapter 机械遍历。
#[must_use]
pub const fn intelligence_import_kinds() -> [&'static str; 4] {
    IMPORT_KINDS
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use openbot_contracts::ids::thread::ThreadIdentity;
    use openbot_contracts::intelligence::{
        IntelligenceBundlePayload, IntelligenceBundleProvenance, IntelligenceMessageExport,
        IntelligenceMessageRole, IntelligenceThreadAnchor, IntelligenceThreadExport,
        IntelligenceThreadStatus,
    };
    use time::macros::datetime;

    use super::*;

    #[derive(Default)]
    struct FakeStore {
        progress: Mutex<Option<IntelligenceImportProgress>>,
        threads: Mutex<BTreeMap<String, IntelligenceThreadChecksum>>,
        imports: Mutex<Vec<IntelligenceThreadImportRequest>>,
        unavailable_on_load: bool,
    }

    #[async_trait]
    impl IntelligenceImportStore for FakeStore {
        async fn load_progress(
            &self,
            _bundle_id: &str,
            _target_deployment_id: &str,
            _payload_sha256: &str,
        ) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
            if self.unavailable_on_load {
                return Err(IntelligenceImportError::Unavailable);
            }
            Ok(self.progress.lock().expect("fake lock").clone())
        }

        async fn import_thread(
            &self,
            request: IntelligenceThreadImportRequest,
        ) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError> {
            self.threads
                .lock()
                .expect("fake lock")
                .insert(request.thread.thread_id.clone(), request.checksum.clone());
            *self.progress.lock().expect("fake lock") = Some(request.progress.clone());
            let checksum = request.checksum.clone();
            self.imports.lock().expect("fake lock").push(request);
            Ok(IntelligenceThreadImportReceipt {
                checksum,
                replayed: false,
            })
        }

        async fn verify_thread(
            &self,
            thread_id: &str,
        ) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
            self.threads
                .lock()
                .expect("fake lock")
                .get(thread_id)
                .cloned()
                .ok_or(IntelligenceImportError::Corrupt {
                    field: "fake_thread",
                })
        }

        async fn complete_bundle(
            &self,
            _bundle_id: &str,
            _target_deployment_id: &str,
            _payload_sha256: &str,
            progress: &IntelligenceImportProgress,
        ) -> Result<(), IntelligenceImportError> {
            let mut completed = progress.clone();
            completed.status = IntelligenceImportCursorStatus::Completed;
            *self.progress.lock().expect("fake lock") = Some(completed);
            Ok(())
        }

        async fn mark_failed(
            &self,
            _bundle_id: &str,
            _target_deployment_id: &str,
            _payload_sha256: &str,
        ) -> Result<(), IntelligenceImportError> {
            Ok(())
        }

        async fn validate_tool_run_fk(
            &self,
        ) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
            Ok(IntelligenceToolRunFkReport {
                incomplete_bundle_count: 0,
                orphan_tool_call_count: 0,
                validated: true,
            })
        }
    }

    fn unavailable_store() -> FakeStore {
        FakeStore {
            unavailable_on_load: true,
            ..FakeStore::default()
        }
    }

    fn bundle(target_owned: bool) -> VerifiedIntelligenceBundle {
        let target = DeploymentId::new("target-deployment");
        let thread_id = if target_owned {
            ThreadIdentity::new(&target)
                .mint_from_entropy([7; 16])
                .as_str()
                .to_owned()
        } else {
            "550e8400-e29b-41d4-a716-446655440000".to_owned()
        };
        let mut thread = IntelligenceThreadExport {
            thread_id,
            created_by: "legacy-user".to_owned(),
            members: vec!["legacy-user".to_owned()],
            title: Some("Imported thread".to_owned()),
            anchor: IntelligenceThreadAnchor::DirectBot {
                bot_id: "legacy-bot".to_owned(),
            },
            status: IntelligenceThreadStatus::Active,
            messages: vec![IntelligenceMessageExport {
                message_id: "message-1".to_owned(),
                sequence: 0,
                role: IntelligenceMessageRole::User,
                content: json!({"text":"hello"}),
                search_text: "hello".to_owned(),
                run_id: None,
                actor_id: Some("legacy-user".to_owned()),
                created_at: datetime!(2026-08-24 00:00 UTC),
            }],
            runs: Vec::new(),
            memories: Vec::new(),
            checksum: zero_checksum(),
            created_at: datetime!(2026-08-24 00:00 UTC),
            updated_at: datetime!(2026-08-24 00:00 UTC),
            deleted_at: None,
        };
        thread.checksum = compute_intelligence_thread_checksum(&thread).unwrap();
        VerifiedIntelligenceBundle::new(
            IntelligenceBundlePayload {
                schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
                bundle_id: "bundle-1".to_owned(),
                source_deployment_id: "source-deployment".to_owned(),
                exported_at: datetime!(2026-08-24 00:00 UTC),
                provenance: IntelligenceBundleProvenance {
                    upstream_commit: INTELLIGENCE_SOURCE_COMMIT.to_owned(),
                    exporter_version: "legacy-exporter-v1".to_owned(),
                    project_id: "project-1".to_owned(),
                },
                threads: vec![thread],
            },
            "a".repeat(64),
            "key-1".to_owned(),
        )
        .unwrap()
    }

    fn mapping() -> IntelligenceImportMapping {
        IntelligenceImportMapping {
            target_deployment_id: "target-deployment".to_owned(),
            target_tenant_id: "tenant-a".to_owned(),
            users: [("legacy-user".to_owned(), "actor-a".to_owned())]
                .into_iter()
                .collect(),
            bots: [("legacy-bot".to_owned(), "bot-1".to_owned())]
                .into_iter()
                .collect(),
            channels: BTreeMap::new(),
            claimed_thread_ids: BTreeSet::new(),
        }
    }

    fn zero_checksum() -> IntelligenceThreadChecksum {
        IntelligenceThreadChecksum {
            projection_hash: "0".repeat(64),
            message_count: 0,
            message_hash: "0".repeat(64),
            event_count: 0,
            event_hash: "0".repeat(64),
            terminal_state_hash: "0".repeat(64),
            memory_count: 0,
            memory_hash: "0".repeat(64),
            sample_render_hash: "0".repeat(64),
        }
    }

    #[tokio::test]
    async fn foreign_thread_requires_explicit_claim_before_any_store_call() {
        let store = FakeStore::default();
        let report = import_intelligence_bundle(&store, bundle(false), mapping())
            .await
            .unwrap();
        assert!(report.requires_action());
        assert_eq!(report.claim_required.len(), 1);
        assert!(store.imports.lock().expect("fake lock").is_empty());
    }

    #[tokio::test]
    async fn owned_bundle_maps_once_and_completed_rerun_only_reverifies() {
        let store = FakeStore::default();
        let first = import_intelligence_bundle(&store, bundle(true), mapping())
            .await
            .unwrap();
        assert_eq!(first.status, IntelligenceImportReportStatus::Completed);
        assert_eq!((first.thread_count, first.message_count), (1, 1));
        {
            let requests = store.imports.lock().expect("fake lock");
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].thread.created_by, "actor-a");
            assert!(matches!(
                requests[0].thread.anchor,
                IntelligenceThreadAnchor::DirectBot { ref bot_id } if bot_id == "bot-1"
            ));
        }

        let replay = import_intelligence_bundle(&store, bundle(true), mapping())
            .await
            .unwrap();
        assert_eq!(replay.status, IntelligenceImportReportStatus::Completed);
        assert_eq!(store.imports.lock().expect("fake lock").len(), 1);
    }

    #[tokio::test]
    async fn checksum_tamper_is_rejected_before_claim_report_or_store() {
        let store = FakeStore::default();
        let mut verified = bundle(false);
        verified.payload.threads[0].checksum.message_hash = "b".repeat(64);
        assert_eq!(
            import_intelligence_bundle(&store, verified, mapping()).await,
            Err(IntelligenceImportError::Invalid {
                field: "thread_checksum",
            })
        );
        assert!(store.imports.lock().expect("fake lock").is_empty());
    }

    #[tokio::test]
    async fn omitted_unknown_thread_is_an_empty_success_not_a_failure() {
        let store = FakeStore::default();
        let mut verified = bundle(true);
        verified.payload.threads.clear();
        let report = import_intelligence_bundle(&store, verified, mapping())
            .await
            .unwrap();
        assert_eq!(report.status, IntelligenceImportReportStatus::Completed);
        assert_eq!((report.thread_count, report.message_count), (0, 0));
    }

    #[tokio::test]
    async fn dependency_failure_is_not_swallowed_as_unknown_or_empty() {
        assert_eq!(
            import_intelligence_bundle(&unavailable_store(), bundle(true), mapping()).await,
            Err(IntelligenceImportError::Unavailable)
        );
    }

    #[tokio::test]
    async fn plain_closed_error_without_status_duck_typing_is_propagated() {
        assert_eq!(
            import_intelligence_bundle(&unavailable_store(), bundle(true), mapping()).await,
            Err(IntelligenceImportError::Unavailable)
        );
    }

    #[tokio::test]
    async fn exact_thread_and_user_mapping_reaches_the_store() {
        let store = FakeStore::default();
        import_intelligence_bundle(&store, bundle(true), mapping())
            .await
            .unwrap();
        let imports = store.imports.lock().expect("fake lock");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].thread.created_by, "actor-a");
        assert_eq!(imports[0].thread.members, ["actor-a"]);
    }
}
