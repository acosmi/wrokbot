//! [`DesktopSession`] —— v3 §13.2 给出的骨架，逐字段保留。
//!
//! §13.2 原文：
//!
//! ```text
//! pub struct DesktopSession {
//!     pub window: WindowIdentity,
//!     pub auth_generation: u64,
//!     pub events: mpsc::Receiver<AppEventRef>,
//!     pub shutdown: CancellationToken,
//! }
//! ```
//!
//! 四个字段一个不增、一个不减，公开性也照原样。
//!
//! # `auth_generation` 与 `window.auth_generation()` 重复，为什么保留
//!
//! 因为骨架里就是两个字段。删掉一个"更整洁"的写法会让本类型与方案对不上，而这个类型
//! 是 Desktop 与 GUI 之间那份契约的形状本身。重复的代价由构造收口消掉：唯一构造入口
//! [`DesktopSession::new`] 从同一个 [`WindowIdentity`] 取值，
//! `auth_generation_mirrors_the_window_identity` 把这条不变量钉住。

use openbot_contracts::command::AppEvent;
use tokio::sync::mpsc;

use crate::cancel::CancellationToken;
use crate::event::AppEventRef;
use crate::window::WindowIdentity;

/// 一个窗口的 in-process 会话：身份 + 有界事件队列 + 取消信号。
///
/// # 生命周期
///
/// - **拿到它** = [`crate::broker::EventBroker::open_window`] 已经为这个窗口建好了路由。
/// - **drop 它** = 生产侧停止。broker 在下一次投递时看到接收端消失
///   （[`crate::broker::DeliveryOutcome::ReceiverGone`]），摘除路由；
///   [`crate::transport::InProcessTransport`] 的事件泵看到同一个信号后退出。
///   这是「drop 接收端应当让生产侧停止」的实现路径 —— 它不依赖任何人记得去调 close。
/// - **`shutdown` 被取消** = 宿主在关停。事件泵会在 5 秒 deadline 内停下
///   （[`crate::cancel::SHUTDOWN_DEADLINE`]），窗口会收到一帧
///   [`crate::broker::DisconnectReason::Shutdown`] 终止帧。
///
/// # 读这条队列时该做什么
///
/// 每帧都过一遍 [`crate::event::SequenceTracker`]。它是接收端判定"我漏了没有"的唯一
/// 手段（§13.2「不能让 GUI 误以为完整」），[`Self::next_frame`] 的文档给了完整用法。
pub struct DesktopSession {
    /// 本窗口的权威身份（§13.3 的定址依据）。
    pub window: WindowIdentity,

    /// 开窗时刻的 auth generation。恒等于 `window.auth_generation()`（见模块文档）。
    pub auth_generation: u64,

    /// 有界事件队列。可用容量 = [`crate::budget::CRITICAL_EVENT_QUEUE_CAPACITY`]，
    /// 另有一格保留给终止帧（[`crate::event::TERMINAL_FRAME_RESERVE`]）。
    ///
    /// `recv()` 返回 `None` **只**发生在终止帧之后 —— 流不会不声不响地结束。
    pub events: mpsc::Receiver<AppEventRef>,

    /// 宿主关停信号，与 broker 共用同一个。
    pub shutdown: CancellationToken,
}

impl DesktopSession {
    pub(crate) fn new(
        window: WindowIdentity,
        events: mpsc::Receiver<AppEventRef>,
        shutdown: CancellationToken,
    ) -> Self {
        let auth_generation = window.auth_generation();
        Self {
            window,
            auth_generation,
            events,
            shutdown,
        }
    }

    /// 取下一帧；流结束时返回 `None`。
    ///
    /// 只是 `self.events.recv()` 的转发，存在的意义是**把用法写在一个能被 rustdoc 链接
    /// 到的地方**：
    ///
    /// ```ignore
    /// let mut tracker = SequenceTracker::new();
    /// while let Some(frame) = session.next_frame().await {
    ///     tracker.observe(&frame)?;              // 漏了没有，这里就知道
    ///     if let Some(reason) = frame.terminal_reason() {
    ///         // 流到此为止；tracker.missing_total() > 0 就从 durable cursor replay
    ///         break;
    ///     }
    ///     render(frame.event().expect("非终止帧必有事件"));
    /// }
    /// ```
    pub async fn next_frame(&mut self) -> Option<AppEventRef> {
        let mut frame = self.events.recv().await?;
        frame.release_queue_permit();
        Some(frame)
    }

    /// 本窗口的标签。
    #[must_use]
    pub fn label(&self) -> &crate::window::WindowLabel {
        self.window.label()
    }

    /// 队列此刻还能再放几个**事件**帧（保留格不计）。
    ///
    /// 给宿主做背压观测用：它是"这个窗口的 renderer 是不是读不过来了"的直接读数，
    /// 而那正是队列满、进而触发丢弃或断开的前兆。
    #[must_use]
    pub fn remaining_event_capacity(&self) -> usize {
        self.events
            .capacity()
            .saturating_sub(crate::event::TERMINAL_FRAME_RESERVE)
    }
}

/// 把一帧渲染成事件；终止帧返回 `None`。
///
/// 这个自由函数存在的理由是它**不接受**任何"默认事件"：调用方必须自己处理终止帧那一支。
/// 一个 `unwrap_or(默认心跳)` 式的便利函数会让终止帧被静默吃掉，而那正是 §13.2 最后
/// 一句要防的事。
#[must_use]
pub fn event_of(frame: &AppEventRef) -> Option<&AppEvent> {
    frame.event()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::EventBroker;
    use crate::budget::CRITICAL_EVENT_QUEUE_CAPACITY;
    use crate::event::BrokerEvent;
    use crate::testing::{TEST_AUTH_GENERATION, auth_with, tenant};
    use crate::window::{EventScope, ThreadSubscriptions, WindowLabel};

    fn session_with_generation(generation: u64) -> (EventBroker, DesktopSession) {
        let broker = EventBroker::new(CancellationToken::new());
        let identity =
            WindowIdentity::bind(WindowLabel::new("main"), &auth_with("actor-1", generation));
        let session = broker
            .open_window(identity, ThreadSubscriptions::none())
            .expect("开窗成功");
        (broker, session)
    }

    /// 两个字段永远说同一件事 —— 骨架里的重复由构造收口消掉。
    #[test]
    fn auth_generation_mirrors_the_window_identity() {
        for generation in [0_u64, 1, TEST_AUTH_GENERATION, u64::MAX] {
            let (_broker, session) = session_with_generation(generation);
            assert_eq!(session.auth_generation, generation);
            assert_eq!(session.auth_generation, session.window.auth_generation());
        }
    }

    #[test]
    fn label_and_identity_agree() {
        let (_broker, session) = session_with_generation(TEST_AUTH_GENERATION);
        assert_eq!(session.label(), &WindowLabel::new("main"));
        assert_eq!(session.window.label().as_str(), "main");
    }

    /// 新开的窗口有整整 256 格可用容量；保留格不算在里面。
    #[test]
    fn a_fresh_session_reports_the_spec_capacity() {
        let (_broker, session) = session_with_generation(TEST_AUTH_GENERATION);
        assert_eq!(
            session.remaining_event_capacity(),
            CRITICAL_EVENT_QUEUE_CAPACITY
        );
    }

    /// 背压读数确实会随排队下降 —— 正向对照，否则上一条在"这个函数返回常量"的世界里也成立。
    #[tokio::test]
    async fn remaining_capacity_drops_as_frames_queue_up() {
        let (broker, mut session) = session_with_generation(TEST_AUTH_GENERATION);
        for seq in 0..3 {
            broker
                .publish(BrokerEvent::new(
                    EventScope::window(tenant(), WindowLabel::new("main")),
                    TEST_AUTH_GENERATION,
                    AppEvent::Heartbeat { seq },
                ))
                .expect("投递被接受");
        }
        assert_eq!(
            session.remaining_event_capacity(),
            CRITICAL_EVENT_QUEUE_CAPACITY - 3
        );

        let frame = session.next_frame().await.expect("有帧");
        assert_eq!(event_of(&frame), Some(&AppEvent::Heartbeat { seq: 0 }));
        assert_eq!(
            session.remaining_event_capacity(),
            CRITICAL_EVENT_QUEUE_CAPACITY - 2
        );
    }

    /// 终止帧上 `event_of` 返回 `None` —— 调用方必须自己处理这一支。
    #[tokio::test]
    async fn event_of_returns_none_on_a_terminal_frame() {
        let (broker, mut session) = session_with_generation(TEST_AUTH_GENERATION);
        broker.close_all();

        let frame = session.next_frame().await.expect("终止帧");
        assert!(frame.is_terminal());
        assert_eq!(event_of(&frame), None);
        // 终止帧之后流才结束 —— 结束**不是**静默的。
        assert!(session.next_frame().await.is_none());
    }
}
