//! 取消与关停 —— v3 §13.2「shutdown deadline 5 秒」。
//!
//! # 为什么这里自己写 `CancellationToken`，而不依赖 `tokio-util`
//!
//! §13.2 的骨架把 `DesktopSession::shutdown` 写成 `CancellationToken`，那个名字来自
//! `tokio-util`。本 crate 仍然自己实现，理由三条，按权重排：
//!
//! 1. **`tokio-util` 不在 `[workspace.dependencies]` 里**，而仓根 `deny.toml` 的
//!    `[bans.workspace-dependencies]` 逐字写着「workspace 根的 `[workspace.dependencies]`
//!    是唯一钉版点，成员 crate 只能 `{ workspace = true }`」。在本 crate 内联一个版本号
//!    会直接跟那条闸门对撞，而改仓根 `Cargo.toml` 不在本轮授权范围内。
//! 2. **「它已经在 `Cargo.lock` 里」不是可依赖的事实**。`tokio-util` 出现在 lock 里是
//!    因为 `tokio-postgres` 用了它 —— 那是别人的实现细节。哪天 `tokio-postgres` 换掉它，
//!    本 crate 就凭空多出一棵新依赖树，而 §16.3 要求供应链变更是一次显式决定。
//!    （`openbot-application` 依赖 `futures-core` 时也踩到同一处，它的做法是**在交付
//!    报告里单列一条请reviewer上收**，不是默默内联版本号。）
//! 3. 我们需要的全部语义 —— 取消一次、永久保持已取消、可 clone、多个等待者、
//!    已取消时 `cancelled()` 立即返回 —— 恰好就是 `watch::Sender<bool>` 的语义。
//!
//! **代价说清楚**：本类型没有 `tokio-util` 的 child token / `DropGuard` / `run_until_cancelled`。
//! G1 一个都没用到。真需要时把这个文件换成 `pub use tokio_util::sync::CancellationToken;`
//! 即可 —— 公开面（[`CancellationToken::cancel`] / [`CancellationToken::is_cancelled`] /
//! [`CancellationToken::cancelled`]）是刻意按 `tokio-util` 的同名方法取的，换过去调用点零改动。

use core::fmt;
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::watch;

/// 关停 deadline。
///
/// **§13.2 逐字规定**：「shutdown deadline 5 秒」。它是 finite shutdown 的那个 finite ——
/// 没有它，「等所有生产者停下来」就是一句可以无限等下去的话。
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// 一次性、单调、可广播的取消信号。
///
/// 语义与 `tokio_util::sync::CancellationToken` 的基础面相同（选型理由见模块文档）：
///
/// - **单调**：取消之后永远是取消，没有 reset。可 reset 的取消会让「旧代际立即全失效」
///   （§17.2 条 6）那族不变量失去锚点。
/// - **可 clone 且共享状态**：clone 出来的 token 与原件是同一个信号，不是副本。
/// - **已取消时 [`Self::cancelled`] 立即返回**：等待者不会因为“错过了那一下”而永远挂住。
#[derive(Clone)]
pub struct CancellationToken {
    // 只持 `Sender`。`watch::Sender` 在零 receiver 时仍可 `send_replace` 与 `subscribe`，
    // 所以不需要额外留一个 receiver 活着 —— 留着反而会让「谁是最后一个」变成一件要想的事。
    inner: Arc<watch::Sender<bool>>,
}

impl CancellationToken {
    /// 新建一个**未取消**的 token。
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            inner: Arc::new(tx),
        }
    }

    /// 取消。幂等：重复调用没有额外效果，也不会 panic。
    pub fn cancel(&self) {
        // `send_replace` 而不是 `send`：`send` 在零 receiver 时返回 `Err`，于是「取消」
        // 会变成一件取决于此刻有没有人在等的事 —— 那正是取消信号最不能有的性质。
        self.inner.send_replace(true);
    }

    /// 是否已取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.inner.borrow()
    }

    /// 等待取消发生。已经取消时立即返回。
    pub async fn cancelled(&self) {
        let mut rx = self.inner.subscribe();
        // `wait_for` 会**先看当前值**再等待，所以"已取消"这一支不需要单独写。
        //
        // 返回的 `Err` 只在 sender 被 drop 时出现，而 `&self` 借着 `Arc<Sender>`，
        // 结构上不可能。真出现也按 fail-closed 处理：当作已取消返回，而不是永远挂住。
        let _ = rx.wait_for(|cancelled| *cancelled).await;
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CancellationToken {
    // 手写而不是 derive：derive 会把 `watch::Sender` 的内部状态打出来，那对读日志的人
    // 没有任何意义，而“这个 token 取消了没有”才是。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration as TokioDuration, timeout};

    #[test]
    fn the_deadline_is_the_five_seconds_from_the_spec() {
        assert_eq!(SHUTDOWN_DEADLINE, Duration::from_secs(5));
    }

    /// 负向 + 正向成对：新 token 未取消，取消后为真且**不可回退**。
    #[tokio::test]
    async fn cancellation_is_monotonic_and_idempotent() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled(), "新 token 必须是未取消的");

        token.cancel();
        assert!(token.is_cancelled());

        // 幂等：再取消一次不 panic，也不会把状态弄回去。
        token.cancel();
        assert!(token.is_cancelled());
    }

    /// clone 出来的是**同一个信号**，不是副本。
    ///
    /// 这条是 `DesktopSession::shutdown` 能工作的前提：session 拿到的是 clone。
    #[tokio::test]
    async fn clones_share_one_signal() {
        let token = CancellationToken::new();
        let clone = token.clone();
        assert!(!clone.is_cancelled());

        clone.cancel();
        assert!(token.is_cancelled(), "从 clone 取消必须让原件也看见");
    }

    /// 已取消时 `cancelled()` 立即返回 —— 不会因为"错过了那一下"永远挂住。
    #[tokio::test]
    async fn cancelled_returns_immediately_when_already_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        timeout(TokioDuration::from_secs(1), token.cancelled())
            .await
            .expect("已取消的 token 必须立即返回");
    }

    /// 正向对照：**未**取消时 `cancelled()` 确实会挂住。
    ///
    /// 没有这一条，上一条在「`cancelled()` 恒立即返回」的世界里同样通过 —— 那是一个
    /// 什么都证明不了的断言。
    #[tokio::test]
    async fn cancelled_actually_waits_while_not_cancelled() {
        let token = CancellationToken::new();
        let outcome = timeout(TokioDuration::from_millis(50), token.cancelled()).await;
        assert!(outcome.is_err(), "未取消时 cancelled() 必须挂住");
    }

    /// 多个等待者全部被同一次取消唤醒。
    #[tokio::test]
    async fn every_waiter_is_woken_by_one_cancel() {
        let token = CancellationToken::new();
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let token = token.clone();
                tokio::spawn(async move { token.cancelled().await })
            })
            .collect();

        token.cancel();
        for waiter in waiters {
            timeout(TokioDuration::from_secs(1), waiter)
                .await
                .expect("取消必须唤醒每一个等待者")
                .expect("等待任务不会 panic");
        }
    }

    #[test]
    fn debug_reports_the_state_not_the_channel_internals() {
        let token = CancellationToken::new();
        assert_eq!(
            format!("{token:?}"),
            "CancellationToken { cancelled: false }"
        );
        token.cancel();
        assert_eq!(
            format!("{token:?}"),
            "CancellationToken { cancelled: true }"
        );
    }
}
