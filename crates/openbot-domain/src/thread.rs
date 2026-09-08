//! Native thread、message 与 fencing lease 的纯领域模型（v3 §4.3）。

use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use serde_json::Value;
use time::OffsetDateTime;

/// Thread 的用户可观察生命周期。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadStatus {
    /// 可继续追加消息/启动 run。
    Active,
    /// 历史可读，但不能启动新 run。
    Archived,
    /// 用户已删除；等待 retention 后物理清理。
    Deleted,
}

impl ThreadStatus {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Deleted => "deleted",
        }
    }
}

/// Thread 只属于 channel 或一次 direct Bot chat，不能同时自报两个归属。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadAnchor {
    /// Channel transcript。
    Channel(ChannelId),
    /// Direct Bot chat。
    DirectBot(BotId),
}

/// Thread 领域行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    id: ThreadId,
    tenant: TenantId,
    deployment: DeploymentId,
    created_by: ActorId,
    anchor: ThreadAnchor,
    status: ThreadStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

impl Thread {
    /// 创建 active thread；时间由调用方注入，领域层不读时钟。
    #[must_use]
    pub fn new(
        id: ThreadId,
        tenant: TenantId,
        deployment: DeploymentId,
        created_by: ActorId,
        anchor: ThreadAnchor,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            tenant,
            deployment,
            created_by,
            anchor,
            status: ThreadStatus::Active,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Thread id。
    #[must_use]
    pub const fn id(&self) -> &ThreadId {
        &self.id
    }

    /// Tenant。
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Deployment。
    #[must_use]
    pub const fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// 权威创建 actor。
    #[must_use]
    pub const fn created_by(&self) -> &ActorId {
        &self.created_by
    }

    /// Channel/direct Bot 归属。
    #[must_use]
    pub const fn anchor(&self) -> &ThreadAnchor {
        &self.anchor
    }

    /// 当前状态。
    #[must_use]
    pub const fn status(&self) -> ThreadStatus {
        self.status
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

    /// 删除时刻。
    #[must_use]
    pub const fn deleted_at(&self) -> Option<OffsetDateTime> {
        self.deleted_at
    }

    /// 归档 active thread；重复归档幂等，deleted 不可复活。
    pub fn archive(&mut self, now: OffsetDateTime) -> Result<(), ThreadStateError> {
        match self.status {
            ThreadStatus::Active => {
                self.status = ThreadStatus::Archived;
                self.updated_at = now;
                Ok(())
            }
            ThreadStatus::Archived => Ok(()),
            ThreadStatus::Deleted => Err(ThreadStateError::Deleted),
        }
    }

    /// 软删除并保留 run/message provenance 到 retention 清理；重复删除幂等。
    pub fn delete(&mut self, now: OffsetDateTime) {
        if self.status != ThreadStatus::Deleted {
            self.status = ThreadStatus::Deleted;
            self.updated_at = now;
            self.deleted_at = Some(now);
        }
    }
}

/// Thread 生命周期拒绝。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadStateError {
    /// 已删除 thread 不可归档/复活。
    #[error("thread_deleted")]
    Deleted,
}

/// Native message 的内部 ID；不是新增 wire ID，不实现 serde/display。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(String);

impl MessageId {
    /// 接受迁移期既有 string id，不擅自限制格式。
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

/// Message role；summary 是上下文压缩，不是 memory。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageRole {
    /// 人类输入。
    User,
    /// Agent 输出。
    Assistant,
    /// 系统上下文。
    System,
    /// Tool transcript。
    Tool,
    /// 自动 thread summary。
    Summary,
}

impl MessageRole {
    /// PostgreSQL 封闭值。
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

/// 一条已按 semantic chunk 边界持久化的 message。
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    id: MessageId,
    thread: ThreadId,
    sequence: u64,
    role: MessageRole,
    content: Value,
    search_text: String,
    run: Option<RunId>,
    actor: Option<ActorId>,
    created_at: OffsetDateTime,
}

impl Message {
    /// 构造完整 message；token 合并由 application 的 50ms/8KiB accumulator 先完成。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: MessageId,
        thread: ThreadId,
        sequence: u64,
        role: MessageRole,
        content: Value,
        search_text: String,
        run: Option<RunId>,
        actor: Option<ActorId>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            thread,
            sequence,
            role,
            content,
            search_text,
            run,
            actor,
            created_at,
        }
    }

    /// Message id。
    #[must_use]
    pub const fn id(&self) -> &MessageId {
        &self.id
    }

    /// Thread id。
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Thread 内严格递增 sequence。
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Role。
    #[must_use]
    pub const fn role(&self) -> MessageRole {
        self.role
    }

    /// 结构化内容。
    #[must_use]
    pub const fn content(&self) -> &Value {
        &self.content
    }

    /// Full-text 投影文本。
    #[must_use]
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// 产生它的 run；用户消息可为空。
    #[must_use]
    pub const fn run(&self) -> Option<&RunId> {
        self.run.as_ref()
    }

    /// 产生它的 actor；system/summary 可为空。
    #[must_use]
    pub const fn actor(&self) -> Option<&ActorId> {
        self.actor.as_ref()
    }

    /// 创建时刻。
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// 单调 fencing token；值域与 PostgreSQL nonnegative bigint 精确一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencingToken(i64);

impl FencingToken {
    /// 从数据库权威值构造；负数拒绝。
    pub const fn new(value: i64) -> Result<Self, FencingTokenInvalid> {
        if value < 0 {
            Err(FencingTokenInvalid)
        } else {
            Ok(Self(value))
        }
    }

    /// 原始值。
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// 下一 token，不回绕。
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Fencing token 不能为负。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("thread_fencing_token_negative")]
pub struct FencingTokenInvalid;

/// 每 thread 唯一 foreground 写租约。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadLease {
    thread: ThreadId,
    owner: String,
    fencing: FencingToken,
    acquired_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl ThreadLease {
    /// 构造租约；expiry 必须严格晚于 acquired_at。
    pub fn new(
        thread: ThreadId,
        owner: String,
        fencing: FencingToken,
        acquired_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, ThreadLeaseError> {
        if owner.is_empty() {
            return Err(ThreadLeaseError::OwnerEmpty);
        }
        if expires_at <= acquired_at {
            return Err(ThreadLeaseError::ExpiryInvalid);
        }
        Ok(Self {
            thread,
            owner,
            fencing,
            acquired_at,
            expires_at,
        })
    }

    /// Thread id。
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Replica owner 标识。
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// 当前 fencing token。
    #[must_use]
    pub const fn fencing(&self) -> FencingToken {
        self.fencing
    }

    /// 获取时刻。
    #[must_use]
    pub const fn acquired_at(&self) -> OffsetDateTime {
        self.acquired_at
    }

    /// 过期时刻。
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// 只有 token 精确相等且当前时刻仍早于 expiry 才可提交。
    #[must_use]
    pub fn admits(&self, token: FencingToken, now: OffsetDateTime) -> bool {
        token == self.fencing && now < self.expires_at
    }
}

/// 租约构造错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadLeaseError {
    /// Owner 不能为空。
    #[error("thread_lease_owner_empty")]
    OwnerEmpty,
    /// Expiry 不晚于获取时刻。
    #[error("thread_lease_expiry_invalid")]
    ExpiryInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn deleted_thread_never_reactivates_and_delete_is_idempotent() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut thread = Thread::new(
            ThreadId::new("thread-1"),
            TenantId::new("tenant-1"),
            DeploymentId::new("deployment-1"),
            ActorId::new("actor-1"),
            ThreadAnchor::DirectBot(BotId::new("bot-1")),
            now,
        );
        thread.delete(now + Duration::SECOND);
        thread.delete(now + Duration::seconds(2));
        assert_eq!(thread.deleted_at(), Some(now + Duration::SECOND));
        assert_eq!(
            thread.archive(now + Duration::seconds(3)),
            Err(ThreadStateError::Deleted)
        );
    }

    #[test]
    fn old_fencing_owner_is_rejected_even_before_the_new_lease_expires() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let lease = ThreadLease::new(
            ThreadId::new("thread-1"),
            "replica-b".to_owned(),
            FencingToken::new(8).unwrap(),
            now,
            now + Duration::MINUTE,
        )
        .unwrap();
        assert!(!lease.admits(FencingToken::new(7).unwrap(), now));
        assert!(lease.admits(FencingToken::new(8).unwrap(), now));
        assert!(!lease.admits(FencingToken::new(8).unwrap(), now + Duration::MINUTE));
    }

    #[test]
    fn fencing_token_saturates_instead_of_reusing_zero() {
        assert_eq!(FencingToken::new(i64::MAX).unwrap().next().get(), i64::MAX);
        assert_eq!(FencingToken::new(-1), Err(FencingTokenInvalid));
    }
}
