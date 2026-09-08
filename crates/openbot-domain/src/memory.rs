//! 显式 memory、scope 与 provenance 规则（v3 §4.3 条 8–11）。

use openbot_contracts::ids::{ActorId, BotId, TenantId, ThreadId};
use time::OffsetDateTime;

use crate::thread::MessageId;

/// Memory 内部 ID；不是新增 wire ID，不实现 serde/display。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryId(String);

impl MemoryId {
    /// 接受迁移期既有 string id。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层值。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// R1 只保存两类 memory。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    /// 用户明确要求保留的 preference。
    Preference,
    /// 有可验证 message/thread 来源的事实。
    Fact,
}

impl MemoryKind {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preference => "preference",
            Self::Fact => "fact",
        }
    }
}

/// Memory sensitivity；召回层必须据此收窄投影。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemorySensitivity {
    /// 普通用户事实。
    Normal,
    /// 只在严格同 scope、明确需要时召回。
    Sensitive,
}

impl MemorySensitivity {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Sensitive => "sensitive",
        }
    }
}

/// Memory 召回 scope；owner 永远另存，scope 不能扩大到另一个用户。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryScope {
    /// 用户所有 Bot 可用。
    User,
    /// 只给一个 Bot。
    Bot(BotId),
    /// 只给一个 thread。
    Thread(ThreadId),
}

impl MemoryScope {
    /// PostgreSQL `scope_kind`。
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Bot(_) => "bot",
            Self::Thread(_) => "thread",
        }
    }

    /// PostgreSQL `scope_id`；user scope 不需要第二个 id。
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::User => None,
            Self::Bot(id) => Some(id.as_str()),
            Self::Thread(id) => Some(id.as_str()),
        }
    }
}

/// 可验证的 memory 来源。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemorySource {
    thread: ThreadId,
    message: MessageId,
}

impl MemorySource {
    /// 将 source message 与其 thread 同时绑定。
    #[must_use]
    pub fn new(thread: ThreadId, message: MessageId) -> Self {
        Self { thread, message }
    }

    /// 来源 thread。
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// 来源 message。
    #[must_use]
    pub const fn message(&self) -> &MessageId {
        &self.message
    }
}

/// 唯一允许的三种显式写入口；没有 background learning。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOrigin {
    /// GUI“记住这条”。
    UserAction,
    /// Built-in Agent 的 `remember` tool，经 §8.1 effect=write 管线。
    RememberTool,
    /// §20.3 可验证 bundle 导入。
    VerifiedImport,
}

impl MemoryOrigin {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserAction => "user_action",
            Self::RememberTool => "remember_tool",
            Self::VerifiedImport => "verified_import",
        }
    }
}

/// Memory 生命周期。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryStatus {
    /// 可召回。
    Active,
    /// 已被一条新 memory 取代，保留 provenance 但不召回。
    Superseded,
    /// 用户禁止召回且内容已擦除。
    Forbidden,
    /// 用户删除且内容已擦除。
    Deleted,
}

impl MemoryStatus {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Forbidden => "forbidden",
            Self::Deleted => "deleted",
        }
    }
}

/// 一条 explicit memory。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memory {
    id: MemoryId,
    tenant: TenantId,
    owner: ActorId,
    scope: MemoryScope,
    kind: MemoryKind,
    content: Option<String>,
    tags: Vec<String>,
    sensitivity: MemorySensitivity,
    source: Option<MemorySource>,
    origin: MemoryOrigin,
    created_by: ActorId,
    supersedes: Option<MemoryId>,
    status: MemoryStatus,
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Memory {
    /// 构造 active memory。
    ///
    /// Fact 或 verified import 没有来源时拒绝；空内容同样拒绝，避免“存在但不可解释”的行。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: MemoryId,
        tenant: TenantId,
        owner: ActorId,
        scope: MemoryScope,
        kind: MemoryKind,
        content: String,
        tags: Vec<String>,
        sensitivity: MemorySensitivity,
        source: Option<MemorySource>,
        origin: MemoryOrigin,
        created_by: ActorId,
        supersedes: Option<MemoryId>,
        expires_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<Self, MemoryError> {
        if content.is_empty() {
            return Err(MemoryError::ContentEmpty);
        }
        if (kind == MemoryKind::Fact || origin == MemoryOrigin::VerifiedImport) && source.is_none()
        {
            return Err(MemoryError::SourceRequired);
        }
        if expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(MemoryError::ExpiryInvalid);
        }
        let mut tags = tags;
        tags.sort();
        tags.dedup();
        if tags.iter().any(String::is_empty) {
            return Err(MemoryError::TagEmpty);
        }
        Ok(Self {
            id,
            tenant,
            owner,
            scope,
            kind,
            content: Some(content),
            tags,
            sensitivity,
            source,
            origin,
            created_by,
            supersedes,
            status: MemoryStatus::Active,
            expires_at,
            created_at: now,
            updated_at: now,
        })
    }

    /// ID。
    #[must_use]
    pub const fn id(&self) -> &MemoryId {
        &self.id
    }

    /// Tenant。
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Owner actor。
    #[must_use]
    pub const fn owner(&self) -> &ActorId {
        &self.owner
    }

    /// Scope。
    #[must_use]
    pub const fn scope(&self) -> &MemoryScope {
        &self.scope
    }

    /// 两类之一。
    #[must_use]
    pub const fn kind(&self) -> MemoryKind {
        self.kind
    }

    /// 内容；forbidden/deleted 后为 `None`。
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// 结构化 tags（排序去重）。
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Sensitivity。
    #[must_use]
    pub const fn sensitivity(&self) -> MemorySensitivity {
        self.sensitivity
    }

    /// Provenance source。
    #[must_use]
    pub const fn source(&self) -> Option<&MemorySource> {
        self.source.as_ref()
    }

    /// 显式入口。
    #[must_use]
    pub const fn origin(&self) -> MemoryOrigin {
        self.origin
    }

    /// 权威创建 actor。
    #[must_use]
    pub const fn created_by(&self) -> &ActorId {
        &self.created_by
    }

    /// 被本条取代的旧 memory。
    #[must_use]
    pub const fn supersedes(&self) -> Option<&MemoryId> {
        self.supersedes.as_ref()
    }

    /// 当前状态。
    #[must_use]
    pub const fn status(&self) -> MemoryStatus {
        self.status
    }

    /// 过期时刻。
    #[must_use]
    pub const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }

    /// 创建时刻。
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// 最近状态写时刻。
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// 标记被新 memory 取代；内容保留作可追溯来源，但不再召回。
    pub fn mark_superseded(&mut self, now: OffsetDateTime) -> Result<(), MemoryError> {
        if self.status != MemoryStatus::Active {
            return Err(MemoryError::NotActive);
        }
        self.status = MemoryStatus::Superseded;
        self.updated_at = now;
        Ok(())
    }

    /// 禁止该 memory；立即擦除召回内容。
    pub fn forbid(&mut self, now: OffsetDateTime) {
        self.status = MemoryStatus::Forbidden;
        self.content = None;
        self.updated_at = now;
    }

    /// 删除该 memory；立即擦除召回内容，事件行保留动作事实。
    pub fn delete(&mut self, now: OffsetDateTime) {
        self.status = MemoryStatus::Deleted;
        self.content = None;
        self.updated_at = now;
    }

    /// 当前时刻是否可召回。
    #[must_use]
    pub fn is_recallable_at(&self, now: OffsetDateTime) -> bool {
        self.status == MemoryStatus::Active
            && self.content.is_some()
            && self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

/// Memory 输入/状态错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MemoryError {
    /// 内容为空。
    #[error("memory_content_empty")]
    ContentEmpty,
    /// Fact/import 缺可验证 source。
    #[error("memory_source_required")]
    SourceRequired,
    /// Tag 为空。
    #[error("memory_tag_empty")]
    TagEmpty,
    /// 创建时已经过期。
    #[error("memory_expiry_invalid")]
    ExpiryInvalid,
    /// 只有 active memory 可以进入 superseded。
    #[error("memory_not_active")]
    NotActive,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn fact(source: Option<MemorySource>) -> Result<Memory, MemoryError> {
        Memory::new(
            MemoryId::new("memory-1"),
            TenantId::new("tenant-1"),
            ActorId::new("user-1"),
            MemoryScope::User,
            MemoryKind::Fact,
            "The office is closed Friday".to_owned(),
            vec!["schedule".to_owned()],
            MemorySensitivity::Normal,
            source,
            MemoryOrigin::UserAction,
            ActorId::new("user-1"),
            None,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn a_fact_without_message_and_thread_provenance_is_refused() {
        assert_eq!(fact(None), Err(MemoryError::SourceRequired));
        assert!(
            fact(Some(MemorySource::new(
                ThreadId::new("thread-1"),
                MessageId::new("message-1")
            )))
            .is_ok()
        );
    }

    #[test]
    fn deleting_or_forbidding_erases_recallable_content() {
        let source = Some(MemorySource::new(
            ThreadId::new("thread-1"),
            MessageId::new("message-1"),
        ));
        let mut deleted = fact(source.clone()).unwrap();
        deleted.delete(OffsetDateTime::UNIX_EPOCH + Duration::SECOND);
        assert_eq!(deleted.content(), None);
        assert!(!deleted.is_recallable_at(OffsetDateTime::UNIX_EPOCH));

        let mut forbidden = fact(source).unwrap();
        forbidden.forbid(OffsetDateTime::UNIX_EPOCH + Duration::SECOND);
        assert_eq!(forbidden.content(), None);
        assert!(!forbidden.is_recallable_at(OffsetDateTime::UNIX_EPOCH));
    }

    #[test]
    fn no_background_learning_origin_exists() {
        assert_eq!(
            [
                MemoryOrigin::UserAction,
                MemoryOrigin::RememberTool,
                MemoryOrigin::VerifiedImport
            ]
            .map(MemoryOrigin::as_str),
            ["user_action", "remember_tool", "verified_import"]
        );
    }
}
