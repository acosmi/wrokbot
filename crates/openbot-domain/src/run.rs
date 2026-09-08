//! Native run 与 semantic event 状态机（v3 §4.3）。

use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId};
use serde_json::Value;
use time::OffsetDateTime;

use crate::thread::FencingToken;

/// Run 状态；`reconciliation_required` 继续占用 foreground slot，避免未知副作用后自动续跑。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunStatus {
    /// 已 durable，尚未开始 provider 调用。
    Queued,
    /// 正在运行。
    Running,
    /// 正常完成。
    Completed,
    /// 确定失败且没有未知提交。
    Failed,
    /// 已取消。
    Cancelled,
    /// 外部 effect 发生但提交状态未知，必须人工 reconciliation。
    ReconciliationRequired,
}

impl RunStatus {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// 是否继续占用“每 thread 仅一个 foreground run”的 slot。
    #[must_use]
    pub const fn blocks_foreground_slot(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Running | Self::ReconciliationRequired
        )
    }

    /// 是否必须恰有一个 terminal semantic event。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::ReconciliationRequired
        )
    }
}

/// 一次 foreground/background Agent run。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    id: RunId,
    thread: ThreadId,
    bot: BotId,
    actor: ActorId,
    foreground: bool,
    fencing: FencingToken,
    status: RunStatus,
    created_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    finished_at: Option<OffsetDateTime>,
    terminal_event_sequence: Option<u64>,
    error_code: Option<&'static str>,
}

impl Run {
    /// 创建 queued run；调用方必须先持有对应 thread lease。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn queued(
        id: RunId,
        thread: ThreadId,
        bot: BotId,
        actor: ActorId,
        foreground: bool,
        fencing: FencingToken,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            thread,
            bot,
            actor,
            foreground,
            fencing,
            status: RunStatus::Queued,
            created_at: now,
            started_at: None,
            finished_at: None,
            terminal_event_sequence: None,
            error_code: None,
        }
    }

    /// Run id。
    #[must_use]
    pub const fn id(&self) -> &RunId {
        &self.id
    }

    /// Thread id。
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Bot id。
    #[must_use]
    pub const fn bot(&self) -> &BotId {
        &self.bot
    }

    /// 权威 actor。
    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 是否 foreground。
    #[must_use]
    pub const fn foreground(&self) -> bool {
        self.foreground
    }

    /// 启动时绑定的 fencing token。
    #[must_use]
    pub const fn fencing(&self) -> FencingToken {
        self.fencing
    }

    /// 当前状态。
    #[must_use]
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    /// 创建时刻。
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// 开始时刻。
    #[must_use]
    pub const fn started_at(&self) -> Option<OffsetDateTime> {
        self.started_at
    }

    /// 完成/阻断时刻。
    #[must_use]
    pub const fn finished_at(&self) -> Option<OffsetDateTime> {
        self.finished_at
    }

    /// 唯一 terminal event 的 run sequence。
    #[must_use]
    pub const fn terminal_event_sequence(&self) -> Option<u64> {
        self.terminal_event_sequence
    }

    /// 稳定错误码。
    #[must_use]
    pub const fn error_code(&self) -> Option<&'static str> {
        self.error_code
    }

    /// queued → running。
    pub fn start(&mut self, now: OffsetDateTime) -> Result<(), RunTransitionError> {
        if self.status != RunStatus::Queued {
            return Err(RunTransitionError::InvalidTransition);
        }
        self.status = RunStatus::Running;
        self.started_at = Some(now);
        Ok(())
    }

    /// 以唯一 terminal event 收口；第二次 terminal 永远拒绝。
    pub fn finish(
        &mut self,
        status: RunStatus,
        event_sequence: u64,
        error_code: Option<&'static str>,
        now: OffsetDateTime,
    ) -> Result<(), RunTransitionError> {
        if !status.is_terminal()
            || self.status.is_terminal()
            || !matches!(self.status, RunStatus::Queued | RunStatus::Running)
        {
            return Err(RunTransitionError::InvalidTransition);
        }
        if matches!(
            status,
            RunStatus::Failed | RunStatus::ReconciliationRequired
        ) && error_code.is_none()
        {
            return Err(RunTransitionError::ErrorCodeRequired);
        }
        self.status = status;
        self.finished_at = Some(now);
        self.terminal_event_sequence = Some(event_sequence);
        self.error_code = error_code;
        Ok(())
    }
}

/// Run 状态转换拒绝。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RunTransitionError {
    /// 来源/目标状态不允许。
    #[error("run_transition_invalid")]
    InvalidTransition,
    /// 失败/reconciliation 必须携带稳定错误码。
    #[error("run_error_code_required")]
    ErrorCodeRequired,
}

/// Semantic run event 类型；terminal 属性由类型决定，不能由调用方自报布尔值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEventKind {
    /// Run 开始。
    Started,
    /// 合并后的可恢复 semantic chunk。
    SemanticChunk,
    /// Operational checkpoint；不是 memory。
    Checkpoint,
    /// 正常结束。
    Completed,
    /// 确定失败。
    Failed,
    /// 取消。
    Cancelled,
    /// 未知提交，等待 reconciliation。
    ReconciliationRequired,
}

impl RunEventKind {
    /// PostgreSQL 封闭值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::SemanticChunk => "semantic_chunk",
            Self::Checkpoint => "checkpoint",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// 是否 terminal。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::ReconciliationRequired
        )
    }
}

/// 一条 `(run_id, seq)` / `(thread_id, event_seq)` 双序 semantic event。
#[derive(Clone, Debug, PartialEq)]
pub struct RunEvent {
    run: RunId,
    sequence: u64,
    thread: ThreadId,
    thread_sequence: u64,
    kind: RunEventKind,
    payload: Value,
    created_at: OffsetDateTime,
}

impl RunEvent {
    /// 构造事件；序列分配由同一 PostgreSQL 事务持有的 aggregate row 决定。
    #[must_use]
    pub fn new(
        run: RunId,
        sequence: u64,
        thread: ThreadId,
        thread_sequence: u64,
        kind: RunEventKind,
        payload: Value,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            run,
            sequence,
            thread,
            thread_sequence,
            kind,
            payload,
            created_at,
        }
    }

    /// Run id。
    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// Run-local sequence。
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Thread id。
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Thread-global event sequence/reconnect cursor。
    #[must_use]
    pub const fn thread_sequence(&self) -> u64 {
        self.thread_sequence
    }

    /// Event kind。
    #[must_use]
    pub const fn kind(&self) -> RunEventKind {
        self.kind
    }

    /// 结构化 semantic payload。
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    /// 创建时刻。
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Run {
        Run::queued(
            RunId::new("run-1"),
            ThreadId::new("thread-1"),
            BotId::new("bot-1"),
            ActorId::new("actor-1"),
            true,
            FencingToken::new(3).unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn every_terminal_path_is_exactly_once() {
        for status in [
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::ReconciliationRequired,
        ] {
            let mut value = run();
            value.start(OffsetDateTime::UNIX_EPOCH).unwrap();
            let error = matches!(
                status,
                RunStatus::Failed | RunStatus::ReconciliationRequired
            )
            .then_some("provider_failed");
            value
                .finish(status, 9, error, OffsetDateTime::UNIX_EPOCH)
                .unwrap();
            assert_eq!(value.terminal_event_sequence(), Some(9));
            assert_eq!(
                value.finish(status, 10, error, OffsetDateTime::UNIX_EPOCH),
                Err(RunTransitionError::InvalidTransition)
            );
        }
    }

    #[test]
    fn reconciliation_blocks_a_new_foreground_run() {
        assert!(RunStatus::ReconciliationRequired.blocks_foreground_slot());
        assert!(!RunStatus::Completed.blocks_foreground_slot());
    }

    #[test]
    fn terminal_event_flag_cannot_be_forged_by_payload() {
        assert!(!RunEventKind::SemanticChunk.is_terminal());
        assert!(RunEventKind::Completed.is_terminal());
    }
}
