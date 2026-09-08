//! 多窗口事件 broker —— v3 §13.2 的有界队列与投递等级 + §13.3 的窗口 ACL。
//!
//! # 一个 broker、多个窗口、每窗口一条有界队列
//!
//! §13.3 逐字：「一个 native broker 可以服务多个窗口，但 Rust 按 window label、actor、
//! thread subscription 和 auth generation 过滤……**过滤不能由前端自行完成**。」
//!
//! [`EventBroker::publish`] 是唯一的投递入口，它对每个已开窗口做一次
//! [`crate::window::EventScope::admits`]，**通过之后才**把帧放进那个窗口的 channel。
//! 于是"前端只能看见属于自己的帧"是一条构造性事实：不属于它的帧从来没有进过它的队列。
//!
//! # 队列满时的四种行为（§13.2）
//!
//! | 投递等级 | 队列满 | 接收端看到 |
//! | --- | --- | --- |
//! | [`DeliveryClass::Critical`] | **显式断开** | 一帧终止帧（带 gap 说明）后流关闭 |
//! | [`DeliveryClass::Coalescable`] | 同上（G1 无合并器，见该变体文档） | 同上 |
//! | [`DeliveryClass::LatestValue`] | 新帧进待发槽，顶掉更旧的一帧 | 后续某帧上挂着 gap 说明 |
//! | [`DeliveryClass::Screen`] | —— | 压根不接受（§13.4：画面另走 binary channel） |
//!
//! **四种都不静默**：前两种给终止帧，第三种给 gap，第四种给
//! [`PublishRejected::ScreenMustNotUseTheEventChannel`]。这就是「不能让 GUI 误以为完整」
//! 在代码里的样子。
//!
//! # 丢弃与合并都留痕
//!
//! §13.2 逐字「任意丢弃或合并都产生 metric 和 sequence gap」。本模块两样都给：
//! [`DeliveryMetrics`] 是可读的计数器，[`crate::event::SequenceGap`] 是给接收端的证据，
//! 另有一条 `tracing::warn!`。三者缺一：只有 metric 则客户端不知道自己漏了；只有 gap 则
//! 运维看不见；只有日志则两边都拿不到可判定的量。

use std::sync::Arc;
use std::sync::Mutex;

use openbot_contracts::telemetry::Transport;
use tokio::sync::mpsc;

use crate::budget::{CRITICAL_EVENT_QUEUE_CAPACITY, DeliveryClass, EventQueueBudget};
use crate::cancel::CancellationToken;
use crate::event::{
    AppEventRef, BrokerEvent, FramePayload, GapCause, SequenceGap, TERMINAL_FRAME_RESERVE,
};
use crate::session::DesktopSession;
use crate::window::{FilterReason, ThreadSubscriptions, WindowIdentity, WindowLabel};

/// 一条窗口流被显式断开的原因。
///
/// 它随终止帧发给接收端 —— 客户端据此决定要不要从 durable cursor replay（§13.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisconnectReason {
    /// 队列满，而这一帧的等级不允许丢弃。
    ///
    /// §13.2 逐字：「队列满即显式断开/失败，客户端从 durable cursor replay」。
    QueueOverflow {
        /// 触发断开的那一帧的投递等级。
        class: DeliveryClass,
    },

    /// broker 关停（§13.2 的 5 秒 shutdown deadline）。
    Shutdown,

    /// The application subscription ended after its final structured event.
    UpstreamEnded,

    /// The host closed this one subscription while the process remained alive.
    SubscriptionClosed,
}

impl DisconnectReason {
    /// 稳定的低基数标签名（§16.4）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueOverflow { .. } => "queue_overflow",
            Self::Shutdown => "shutdown",
            Self::UpstreamEnded => "upstream_ended",
            Self::SubscriptionClosed => "subscription_closed",
        }
    }
}

/// 一帧对**一个窗口**的投递结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// 已进入该窗口的队列。
    Delivered {
        /// 本帧在该窗口序列中的序号。
        seq: u64,
    },

    /// latest-value：本帧进了待发槽，取代了槽里更旧的一帧。
    ///
    /// 它**不是**失败：被取代的那一帧的序号已记进 gap，接收端会看见。
    Superseded {
        /// 本帧被分配到的序号（它会在下一次有空位时送达）。
        seq: u64,
    },

    /// 这一帧不属于该窗口（§13.3 的 ACL）。**不占序号、不计丢帧**。
    Filtered(FilterReason),

    /// 该窗口的流被显式断开，终止帧已入队。
    Disconnected {
        /// 终止帧的序号。
        terminal_seq: u64,
        /// 断开原因。
        reason: DisconnectReason,
    },

    /// 接收端已经没了（`DesktopSession` 被 drop）—— 连终止帧都无处可投。
    ///
    /// 这是「drop 接收端让生产侧停止」的可观察形态：路由随即被摘除，
    /// [`crate::transport::InProcessTransport`] 的事件泵看到它就退出。
    ReceiverGone,

    /// 该窗口此前已断开（终止帧早已投过）。
    AlreadyDisconnected,
}

/// 一帧对某个窗口的投递结果（带窗口标签）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowDelivery {
    /// 收件窗口。
    pub window: WindowLabel,
    /// 结果。
    pub outcome: DeliveryOutcome,
}

/// 一次 [`EventBroker::publish`] 的逐窗口结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublishReport {
    deliveries: Vec<WindowDelivery>,
}

impl PublishReport {
    /// 逐窗口结果。
    #[must_use]
    pub fn deliveries(&self) -> &[WindowDelivery] {
        &self.deliveries
    }

    /// 某个窗口的结果；该窗口不存在时返回 `None`。
    #[must_use]
    pub fn outcome_for(&self, window: &WindowLabel) -> Option<DeliveryOutcome> {
        self.deliveries
            .iter()
            .find(|delivery| &delivery.window == window)
            .map(|delivery| delivery.outcome)
    }

    /// 真正进了队列的窗口数。
    #[must_use]
    pub fn delivered_count(&self) -> usize {
        self.deliveries
            .iter()
            .filter(|delivery| matches!(delivery.outcome, DeliveryOutcome::Delivered { .. }))
            .count()
    }
}

/// 整帧被拒 —— 一个窗口都没投。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublishRejected {
    /// screen 等级的帧不走这条通道（§13.4）。
    ///
    /// # 这是缺陷信号，不是降级路径
    ///
    /// §13.4 逐字：「持续画面……正式路线使用 loopback binary WebSocket。Tauri Channel
    /// 只承载结构化 Agent/tool/policy 事件。」所以一帧 screen 出现在这里，说明有人把
    /// 画面接到了错误的通道上。正确反应是当场拒绝：**"先凑合发着"会让那条 binary
    /// channel 永远不必被建出来**，而画面帧会把这条 256 格的结构化事件队列瞬间打满，
    /// 顺带把同一个窗口的 approval 与 terminal 一起挤掉。
    #[error("screen_must_not_use_the_event_channel")]
    ScreenMustNotUseTheEventChannel,

    /// broker 已关停，不再接受新帧。
    #[error("broker_shutting_down")]
    ShuttingDown,
}

/// 同一个 broker 内出现重名窗口标签。
///
/// 重名不是小事：[`crate::window::ScopeTarget::Window`] 靠标签定址，两个同名窗口会
/// **同时**收到本该定向给其中一个的私有帧 —— 那正是 §13.3 要挡住的跨窗口泄漏。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("window_already_open label={0}")]
pub struct WindowAlreadyOpen(pub WindowLabel);

/// broker 的投递计数器（§13.2「任意丢弃或合并都产生 metric」）。
///
/// 刻意是**纯计数**、无标签维度：§16.4 要求 metrics label 基数有界，而窗口标签与
/// actor 是高基数。要按窗口下钻请看 [`PublishReport`] 与 `tracing` 事件（受控 trace）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeliveryMetrics {
    /// 被接受的事件数（拒收的不计）。
    pub published: u64,
    /// 成功入队的帧数（跨全部窗口累计）。
    pub delivered: u64,
    /// 被 ACL 挡下的次数。**不是丢帧**（见 [`FilterReason`]）。
    pub filtered: u64,
    /// latest-value 取代掉的帧数。
    pub superseded: u64,
    /// 丢弃的帧数（不可丢等级遇满队列，或关停时待发槽送不出去）。
    pub dropped: u64,
    /// 显式断开的窗口路由数。
    pub disconnected: u64,
    /// 因接收端消失而摘除的窗口路由数。
    pub receiver_gone: u64,
    /// 被整帧拒收的次数（screen 或已关停）。
    pub rejected: u64,
}

impl DeliveryMetrics {
    /// 已知**没有到达**的帧总数 = 取代 + 丢弃。
    ///
    /// 它应当与接收端 [`crate::event::SequenceTracker::missing_total`] 的总和相等 ——
    /// 两边算的是同一件事，一边给运维、一边给客户端。由
    /// `metrics_and_receiver_side_gaps_agree` 钉住。
    #[must_use]
    pub const fn shed_total(&self) -> u64 {
        self.superseded.saturating_add(self.dropped)
    }
}

/// 一个窗口的投递路由（broker 私有）。
struct WindowRoute {
    identity: WindowIdentity,
    subscriptions: ThreadSubscriptions,
    tx: mpsc::Sender<AppEventRef>,
    queue_budget: Arc<EventQueueBudget>,
    next_seq: u64,
    /// latest-value 的待发槽：队列满时最新的那一帧压在这里，等下一次有空位再送。
    pending_latest: Option<(u64, Arc<BrokerEvent>)>,
    /// 待挂到下一帧上的 gap 说明。
    pending_gap: Option<SequenceGap>,
    terminated: bool,
    shed_superseded: u64,
    shed_dropped: u64,
}

/// `try_push` 的三种结局。
enum PushResult {
    Sent,
    NoRoom,
    Closed,
}

impl WindowRoute {
    fn new(
        identity: WindowIdentity,
        subscriptions: ThreadSubscriptions,
        tx: mpsc::Sender<AppEventRef>,
        queue_budget: Arc<EventQueueBudget>,
    ) -> Self {
        Self {
            identity,
            subscriptions,
            tx,
            queue_budget,
            next_seq: 0,
            pending_latest: None,
            pending_gap: None,
            terminated: false,
            shed_superseded: 0,
            shed_dropped: 0,
        }
    }

    fn label(&self) -> &WindowLabel {
        self.identity.label()
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        // 饱和：回绕会让接收端的单调性判据在 2^64 帧之后给出错误答案。到顶需要连续投递
        // 1.8e19 帧，实践中不可达；饱和的最坏结果是序号停住（接收端判 NotMonotonic），
        // 回绕的最坏结果是接收端认为自己漏了 2^64 帧。
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    fn record_gap(&mut self, seq: u64, cause: GapCause) {
        match cause {
            GapCause::Superseded => self.shed_superseded = self.shed_superseded.saturating_add(1),
            GapCause::Dropped => self.shed_dropped = self.shed_dropped.saturating_add(1),
        }
        match &mut self.pending_gap {
            Some(gap) => gap.absorb(seq, cause),
            None => {
                self.pending_gap = Some(SequenceGap {
                    from_seq: seq,
                    through_seq: seq,
                    cause,
                });
            }
        }
    }

    fn take_shed(&mut self) -> (u64, u64) {
        (
            core::mem::take(&mut self.shed_superseded),
            core::mem::take(&mut self.shed_dropped),
        )
    }

    /// 普通事件帧还有没有位置。保留格不算 —— 它只归终止帧用
    /// （见 [`TERMINAL_FRAME_RESERVE`]）。
    fn room_for_event(&self) -> bool {
        self.tx.capacity() > TERMINAL_FRAME_RESERVE
    }

    fn try_push(&mut self, seq: u64, payload: FramePayload, reserved: bool) -> PushResult {
        if !reserved && !self.room_for_event() {
            return PushResult::NoRoom;
        }
        let queue_permit = if reserved {
            None
        } else {
            let Some(permit) = self.queue_budget.try_acquire() else {
                return PushResult::NoRoom;
            };
            Some(permit)
        };
        let frame = AppEventRef::new(seq, self.pending_gap.take(), payload, queue_permit);
        match self.tx.try_send(frame) {
            Ok(()) => PushResult::Sent,
            Err(mpsc::error::TrySendError::Full(frame)) => {
                // 把 gap 说明放回去 —— 它还没被任何人看见，丢了就等于把"漏了哪些"擦掉。
                self.pending_gap = frame.skipped();
                PushResult::NoRoom
            }
            Err(mpsc::error::TrySendError::Closed(frame)) => {
                self.pending_gap = frame.skipped();
                PushResult::Closed
            }
        }
    }

    /// 把待发槽里的帧冲出去（有空位才冲）。
    ///
    /// 返回 `Err(())` 表示接收端没了。
    fn flush_pending(&mut self) -> Result<(), ()> {
        let Some((seq, event)) = self.pending_latest.take() else {
            return Ok(());
        };
        match self.try_push(seq, FramePayload::Event(Arc::clone(&event)), false) {
            PushResult::Sent => Ok(()),
            PushResult::NoRoom => {
                self.pending_latest = Some((seq, event));
                Ok(())
            }
            PushResult::Closed => Err(()),
        }
    }

    /// 显式断开：把待发槽里那帧记成缺失，投一帧终止帧（走保留格），关闭路由。
    fn terminate(&mut self, reason: DisconnectReason) -> DeliveryOutcome {
        if let Some((seq, _)) = self.pending_latest.take() {
            // 它永远不会到达了。`absorb` 两端取极值，所以这里的记录顺序与序号顺序相反
            // 也不会把它漏在区间外（见 `SequenceGap::absorb`）。
            self.record_gap(seq, GapCause::Dropped);
        }
        self.terminated = true;
        let seq = self.take_seq();
        match self.try_push(seq, FramePayload::Terminal(reason), true) {
            PushResult::Sent => DeliveryOutcome::Disconnected {
                terminal_seq: seq,
                reason,
            },
            PushResult::NoRoom | PushResult::Closed => DeliveryOutcome::ReceiverGone,
        }
    }

    fn deliver(&mut self, event: &Arc<BrokerEvent>) -> DeliveryOutcome {
        if self.terminated {
            return DeliveryOutcome::AlreadyDisconnected;
        }
        if self.tx.is_closed() {
            self.terminated = true;
            return DeliveryOutcome::ReceiverGone;
        }

        // §13.3 的四个过滤维度全部在这一次调用里走到。**在任何帧进入 channel 之前。**
        if let Err(reason) =
            event
                .scope()
                .admits(&self.identity, &self.subscriptions, event.auth_generation())
        {
            return DeliveryOutcome::Filtered(reason);
        }

        // 迟发的 latest-value 帧优先于新帧，保持序号单调递增。
        if self.flush_pending().is_err() {
            self.terminated = true;
            return DeliveryOutcome::ReceiverGone;
        }

        let seq = self.take_seq();
        match self.try_push(seq, FramePayload::Event(Arc::clone(event)), false) {
            PushResult::Sent => DeliveryOutcome::Delivered { seq },
            PushResult::Closed => {
                self.terminated = true;
                DeliveryOutcome::ReceiverGone
            }
            PushResult::NoRoom => match event.class() {
                DeliveryClass::LatestValue => {
                    if let Some((older, _)) = self.pending_latest.replace((seq, Arc::clone(event)))
                    {
                        self.record_gap(older, GapCause::Superseded);
                    }
                    DeliveryOutcome::Superseded { seq }
                }
                // `Screen` 走不到这里 —— `publish` 已在更早拒掉整帧。把它并进这一支而不是
                // `unreachable!()`：transport 里一条会 panic 的路径，比一条永远走不到的
                // 保守路径危险得多。真走到了，行为是最保守的那个（显式断开）。
                class @ (DeliveryClass::Critical
                | DeliveryClass::Coalescable
                | DeliveryClass::Screen) => {
                    self.record_gap(seq, GapCause::Dropped);
                    self.terminate(DisconnectReason::QueueOverflow { class })
                }
            },
        }
    }
}

/// 服务多个窗口的事件 broker。
///
/// 线程安全（内部 `Mutex`），可放进 `Arc` 交给多个生产者。锁内**从不 await** ——
/// 全部投递走 `try_send`，所以 `std::sync::Mutex` 是正确选择，不需要 async 锁。
pub struct EventBroker {
    routes: Mutex<Vec<WindowRoute>>,
    metrics: Mutex<DeliveryMetrics>,
    shutdown: CancellationToken,
}

impl EventBroker {
    /// 新建一个 broker，共用给定的取消信号。
    #[must_use]
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            routes: Mutex::new(Vec::new()),
            metrics: Mutex::new(DeliveryMetrics::default()),
            shutdown,
        }
    }

    /// 本 broker 的取消信号（每个 [`DesktopSession`] 拿到的是它的 clone）。
    #[must_use]
    pub fn shutdown_token(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// 当前打开的窗口数。
    #[must_use]
    pub fn window_count(&self) -> usize {
        self.routes.lock().expect("broker 路由锁不会中毒").len()
    }

    /// 投递计数器快照。
    #[must_use]
    pub fn metrics(&self) -> DeliveryMetrics {
        *self.metrics.lock().expect("broker 计数器锁不会中毒")
    }

    /// 开一个窗口，拿到它的 [`DesktopSession`]。
    ///
    /// # Errors
    ///
    /// 标签在本 broker 内已存在时返回 [`WindowAlreadyOpen`]（理由见该类型文档）。
    pub fn open_window(
        &self,
        identity: WindowIdentity,
        subscriptions: ThreadSubscriptions,
    ) -> Result<DesktopSession, WindowAlreadyOpen> {
        self.open_window_with_budget(
            identity,
            subscriptions,
            Arc::new(EventQueueBudget::spec_window()),
        )
    }

    /// Open one broker route using a caller-owned shared event-ref budget.
    ///
    /// Structured Tauri subscriptions use this path so all internal routes belonging to one actual
    /// Webview share the same 256 permits. The physical mpsc still retains one terminal-only slot
    /// per route; terminal delivery must remain possible even when the aggregate event budget is
    /// exhausted.
    pub(crate) fn open_window_with_budget(
        &self,
        identity: WindowIdentity,
        subscriptions: ThreadSubscriptions,
        queue_budget: Arc<EventQueueBudget>,
    ) -> Result<DesktopSession, WindowAlreadyOpen> {
        let mut routes = self.routes.lock().expect("broker 路由锁不会中毒");
        if routes.iter().any(|route| route.label() == identity.label()) {
            return Err(WindowAlreadyOpen(identity.label().clone()));
        }
        // 容量 = 可用 256 + 终止帧保留格。可投递的事件帧上限逐字仍是 §13.2 的 256。
        let (tx, rx) = mpsc::channel(CRITICAL_EVENT_QUEUE_CAPACITY + TERMINAL_FRAME_RESERVE);
        routes.push(WindowRoute::new(
            identity.clone(),
            subscriptions,
            tx,
            queue_budget,
        ));
        Ok(DesktopSession::new(identity, rx, self.shutdown.clone()))
    }

    /// 把一帧投给全部**准入**的窗口。
    ///
    /// # Errors
    ///
    /// screen 等级的帧或已关停的 broker 返回 [`PublishRejected`]。
    pub fn publish(&self, event: BrokerEvent) -> Result<PublishReport, PublishRejected> {
        if event.class() == DeliveryClass::Screen {
            self.bump_rejected();
            tracing::error!(
                transport = Transport::InProcess.as_str(),
                class = DeliveryClass::Screen.as_str(),
                "screen 帧被投到结构化事件通道上；画面必须走 loopback binary WebSocket（§13.4）"
            );
            return Err(PublishRejected::ScreenMustNotUseTheEventChannel);
        }
        if self.shutdown.is_cancelled() {
            self.bump_rejected();
            return Err(PublishRejected::ShuttingDown);
        }

        let shared = Arc::new(event);
        let mut deliveries = Vec::new();
        let mut delta = DeliveryMetrics {
            published: 1,
            ..DeliveryMetrics::default()
        };

        {
            let mut routes = self.routes.lock().expect("broker 路由锁不会中毒");
            for route in routes.iter_mut() {
                let outcome = route.deliver(&shared);
                let (superseded, dropped) = route.take_shed();
                delta.superseded = delta.superseded.saturating_add(superseded);
                delta.dropped = delta.dropped.saturating_add(dropped);
                match outcome {
                    DeliveryOutcome::Delivered { .. } => {
                        delta.delivered = delta.delivered.saturating_add(1);
                    }
                    DeliveryOutcome::Filtered(_) => {
                        delta.filtered = delta.filtered.saturating_add(1);
                    }
                    DeliveryOutcome::Disconnected { reason, .. } => {
                        delta.disconnected = delta.disconnected.saturating_add(1);
                        tracing::warn!(
                            transport = Transport::InProcess.as_str(),
                            window = %route.label(),
                            reason = reason.as_str(),
                            class = shared.class().as_str(),
                            "窗口事件流显式断开；客户端应从 durable cursor replay（§13.2）"
                        );
                    }
                    DeliveryOutcome::ReceiverGone => {
                        delta.receiver_gone = delta.receiver_gone.saturating_add(1);
                    }
                    DeliveryOutcome::Superseded { .. } | DeliveryOutcome::AlreadyDisconnected => {}
                }
                if superseded > 0 || dropped > 0 {
                    tracing::warn!(
                        transport = Transport::InProcess.as_str(),
                        window = %route.label(),
                        class = shared.class().as_str(),
                        superseded,
                        dropped,
                        "窗口队列压力导致帧未送达；已在序列上留下 gap（§13.2）"
                    );
                }
                deliveries.push(WindowDelivery {
                    window: route.label().clone(),
                    outcome,
                });
            }
            // 已断开或接收端消失的路由立刻摘除：drop 掉 `Sender` 正是接收端在读完终止帧
            // 之后拿到 `None` 的原因。留着它只会让下一次 publish 再走一遍死路由。
            routes.retain(|route| !route.terminated);
        }

        self.merge_metrics(delta);
        Ok(PublishReport { deliveries })
    }

    /// 尝试把各窗口待发槽里压着的 latest-value 帧冲出去。
    ///
    /// 生产链路上不需要显式调用它（[`Self::publish`] 每次都会先冲一遍），但**最后一帧**
    /// 例外：没有下一次 publish，那帧就一直压在槽里。所以关停前必须冲一次，
    /// [`Self::close_all`] 已经这么做了。
    ///
    /// # gap 的送达时点：生产侧的**下一次动作**
    ///
    /// 一条已经满了的队列**装不进任何东西**，包括"你漏了几帧"这句话本身。所以 gap 说明
    /// 只能挂在下一帧真正出得去的帧上，而那要等接收端腾出位置、且生产侧再动一次
    /// （publish / [`Self::flush_pending`] / [`Self::close_all`]）。
    ///
    /// 这**不是**"接收端可能永远不知道"：`pending_gap` 只在两处产生，两处都留下了载体 ——
    ///
    /// 1. latest-value 取代：取代之后待发槽里必然压着一帧，那帧就是载体；
    /// 2. 不可丢等级遇满队列：当场终止，终止帧就是载体（走保留格，一定进得去）。
    ///
    /// 所以「有 gap 却没有载体」在构造上不存在，由
    /// `a_pending_gap_always_has_a_carrier` 钉住。而在 gap 送达之前，接收端看到的序号是
    /// **真连续**的 —— 它只是还没走到缺失那一段，不存在被误导的时刻。
    pub fn flush_pending(&self) {
        let mut routes = self.routes.lock().expect("broker 路由锁不会中毒");
        for route in routes.iter_mut() {
            if route.flush_pending().is_err() {
                route.terminated = true;
            }
        }
        routes.retain(|route| !route.terminated);
    }

    /// Close one exact host-owned route with an explicit terminal frame.
    ///
    /// Returns `false` when the route no longer exists. This is idempotent cleanup, not an error.
    pub fn close_window(&self, label: &WindowLabel, reason: DisconnectReason) -> bool {
        let mut routes = self.routes.lock().expect("broker 路由锁不会中毒");
        let Some(index) = routes.iter().position(|route| route.label() == label) else {
            return false;
        };
        let mut route = routes.remove(index);
        let _ = route.flush_pending();
        let outcome = if route.terminated {
            DeliveryOutcome::AlreadyDisconnected
        } else {
            route.terminate(reason)
        };
        let (superseded, dropped) = route.take_shed();
        drop(routes);

        let mut delta = DeliveryMetrics {
            superseded,
            dropped,
            ..DeliveryMetrics::default()
        };
        match outcome {
            DeliveryOutcome::Disconnected { .. } => delta.disconnected = 1,
            DeliveryOutcome::ReceiverGone => delta.receiver_gone = 1,
            DeliveryOutcome::Delivered { .. }
            | DeliveryOutcome::Filtered(_)
            | DeliveryOutcome::Superseded { .. }
            | DeliveryOutcome::AlreadyDisconnected => {}
        }
        self.merge_metrics(delta);
        true
    }

    /// 关停全部窗口：先冲待发槽，再给每个窗口投一帧
    /// [`DisconnectReason::Shutdown`] 终止帧，然后摘除路由。
    ///
    /// 返回被关掉的窗口数。**不取消 [`Self::shutdown_token`]** —— 取消是调用方的决定
    /// （[`crate::transport::InProcessTransport::shutdown`] 会先取消再调这里），
    /// 让 broker 自己去取消一个它只是共用的信号是越权。
    pub fn close_all(&self) -> usize {
        let mut routes = self.routes.lock().expect("broker 路由锁不会中毒");
        let mut delta = DeliveryMetrics::default();
        let closed = routes.len();
        for route in routes.iter_mut() {
            // 先冲槽：关停不该顺手吃掉最后一个已知的 presence 值。
            let _ = route.flush_pending();
            if !route.terminated {
                match route.terminate(DisconnectReason::Shutdown) {
                    DeliveryOutcome::Disconnected { .. } => {
                        delta.disconnected = delta.disconnected.saturating_add(1);
                    }
                    _ => {
                        delta.receiver_gone = delta.receiver_gone.saturating_add(1);
                    }
                }
            }
            let (superseded, dropped) = route.take_shed();
            delta.superseded = delta.superseded.saturating_add(superseded);
            delta.dropped = delta.dropped.saturating_add(dropped);
        }
        routes.clear();
        drop(routes);
        self.merge_metrics(delta);
        closed
    }

    fn bump_rejected(&self) {
        let mut metrics = self.metrics.lock().expect("broker 计数器锁不会中毒");
        metrics.rejected = metrics.rejected.saturating_add(1);
    }

    fn merge_metrics(&self, delta: DeliveryMetrics) {
        let mut metrics = self.metrics.lock().expect("broker 计数器锁不会中毒");
        metrics.published = metrics.published.saturating_add(delta.published);
        metrics.delivered = metrics.delivered.saturating_add(delta.delivered);
        metrics.filtered = metrics.filtered.saturating_add(delta.filtered);
        metrics.superseded = metrics.superseded.saturating_add(delta.superseded);
        metrics.dropped = metrics.dropped.saturating_add(delta.dropped);
        metrics.disconnected = metrics.disconnected.saturating_add(delta.disconnected);
        metrics.receiver_gone = metrics.receiver_gone.saturating_add(delta.receiver_gone);
        metrics.rejected = metrics.rejected.saturating_add(delta.rejected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SequenceError, SequenceTracker};
    use crate::testing::{auth_for, auth_in_tenant, auth_with, tenant};
    use crate::window::{EventScope, WindowIdentity, WindowLabel};
    use openbot_contracts::command::AppEvent;
    use openbot_contracts::ids::{ActorId, ThreadId};

    fn broker() -> EventBroker {
        EventBroker::new(CancellationToken::new())
    }

    fn open(broker: &EventBroker, label: &str, actor: &str) -> DesktopSession {
        broker
            .open_window(
                WindowIdentity::bind(WindowLabel::new(label), &auth_for(actor)),
                ThreadSubscriptions::none(),
            )
            .expect("首次开窗必须成功")
    }

    fn heartbeat(seq: u64) -> AppEvent {
        AppEvent::Heartbeat { seq }
    }

    fn to_actor(actor: &str, seq: u64) -> BrokerEvent {
        BrokerEvent::new(
            EventScope::actor(tenant(), ActorId::new(actor)),
            crate::testing::TEST_AUTH_GENERATION,
            heartbeat(seq),
        )
    }

    fn to_window(label: &str, seq: u64) -> BrokerEvent {
        BrokerEvent::new(
            EventScope::window(tenant(), WindowLabel::new(label)),
            crate::testing::TEST_AUTH_GENERATION,
            heartbeat(seq),
        )
    }

    fn critical_to_window(label: &str, seq: u64) -> BrokerEvent {
        BrokerEvent::with_class_for_test(
            EventScope::window(tenant(), WindowLabel::new(label)),
            crate::testing::TEST_AUTH_GENERATION,
            heartbeat(seq),
            DeliveryClass::Critical,
        )
    }

    /// 把一个 session 里此刻已经排好的帧全部取出来。
    fn drain(session: &mut DesktopSession) -> Vec<AppEventRef> {
        let mut frames = Vec::new();
        while let Ok(mut frame) = session.events.try_recv() {
            frame.release_queue_permit();
            frames.push(frame);
        }
        frames
    }

    fn observe_all(frames: &[AppEventRef]) -> Result<SequenceTracker, SequenceError> {
        let mut tracker = SequenceTracker::new();
        for frame in frames {
            tracker.observe(frame)?;
        }
        Ok(tracker)
    }

    // -----------------------------------------------------------------------
    // 开窗
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_duplicate_window_label_is_rejected() {
        let broker = broker();
        let _a = open(&broker, "main", "actor-1");
        assert_eq!(broker.window_count(), 1);

        let duplicate = broker.open_window(
            WindowIdentity::bind(WindowLabel::new("main"), &auth_for("actor-1")),
            ThreadSubscriptions::none(),
        );
        assert_eq!(
            duplicate.err(),
            Some(WindowAlreadyOpen(WindowLabel::new("main")))
        );

        // 正向对照：换一个标签就开得出来。
        let _b = open(&broker, "settings", "actor-1");
        assert_eq!(broker.window_count(), 2);
    }

    #[tokio::test]
    async fn the_session_carries_the_brokers_shutdown_signal() {
        let broker = broker();
        let session = open(&broker, "main", "actor-1");
        assert!(!session.shutdown.is_cancelled());
        broker.shutdown_token().cancel();
        assert!(
            session.shutdown.is_cancelled(),
            "session 拿到的必须是同一个信号"
        );
    }

    // -----------------------------------------------------------------------
    // 窗口隔离（§13.3）
    // -----------------------------------------------------------------------

    /// 负向 + 正向：A 收不到 B 的帧，但收得到自己的。
    #[tokio::test]
    async fn window_a_never_receives_window_b_events_but_does_receive_its_own() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        let mut b = open(&broker, "b", "actor-2");

        // 定向到 B 的 actor。
        let report = broker.publish(to_actor("actor-2", 0)).expect("投递被接受");
        assert_eq!(
            report.outcome_for(&WindowLabel::new("a")),
            Some(DeliveryOutcome::Filtered(FilterReason::ActorMismatch))
        );
        assert_eq!(
            report.outcome_for(&WindowLabel::new("b")),
            Some(DeliveryOutcome::Delivered { seq: 0 })
        );
        assert!(drain(&mut a).is_empty(), "A 的队列里一帧都不该有");
        assert_eq!(drain(&mut b).len(), 1, "正向对照：B 确实收到了");

        // 定向到 A 这个窗口。
        let report = broker.publish(to_window("a", 1)).expect("投递被接受");
        assert_eq!(
            report.outcome_for(&WindowLabel::new("a")),
            Some(DeliveryOutcome::Delivered { seq: 0 })
        );
        assert_eq!(
            report.outcome_for(&WindowLabel::new("b")),
            Some(DeliveryOutcome::Filtered(FilterReason::WindowMismatch))
        );
        let a_frames = drain(&mut a);
        assert_eq!(a_frames.len(), 1);
        assert_eq!(a_frames[0].event(), Some(&heartbeat(1)));
        assert!(drain(&mut b).is_empty());
    }

    /// 被过滤的帧**不占序号** —— 否则 A 能从自己的序号跳变里推断 B 的流量。
    ///
    /// 这条是跨 scope 旁路信道的直接封堵（§17.2 条 12）。
    #[tokio::test]
    async fn another_windows_traffic_does_not_perturb_my_sequence() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        let _b = open(&broker, "b", "actor-2");

        for seq in 0..5 {
            broker
                .publish(to_actor("actor-2", seq))
                .expect("投递被接受");
        }
        assert!(drain(&mut a).is_empty());

        broker.publish(to_actor("actor-1", 99)).expect("投递被接受");
        let frames = drain(&mut a);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].seq(), 0, "A 的第一帧必须是序号 0");
        assert_eq!(frames[0].skipped(), None, "A 不该看到任何 gap");
        assert_eq!(observe_all(&frames).expect("序列合法").missing_total(), 0);
    }

    /// 跨租户：同一个 actor id 也进不来。
    #[tokio::test]
    async fn a_frame_from_another_tenant_is_filtered() {
        let broker = broker();
        let identity = WindowIdentity::bind(
            WindowLabel::new("a"),
            &auth_in_tenant(
                "tenant-other",
                "actor-1",
                crate::testing::TEST_AUTH_GENERATION,
            ),
        );
        let mut a = broker
            .open_window(identity, ThreadSubscriptions::none())
            .expect("开窗成功");

        let report = broker.publish(to_actor("actor-1", 0)).expect("投递被接受");
        assert_eq!(
            report.outcome_for(&WindowLabel::new("a")),
            Some(DeliveryOutcome::Filtered(FilterReason::TenantMismatch))
        );
        assert!(drain(&mut a).is_empty());
    }

    /// 代际：陈旧窗口收不到新帧；正向对照是同代际的窗口收得到。
    #[tokio::test]
    async fn a_stale_generation_window_is_cut_off_while_a_current_one_is_not() {
        let broker = broker();
        let stale = WindowIdentity::bind(WindowLabel::new("stale"), &auth_with("actor-1", 6));
        let mut stale_session = broker
            .open_window(stale, ThreadSubscriptions::none())
            .expect("开窗成功");
        let mut current = open(&broker, "current", "actor-1");

        let report = broker.publish(to_actor("actor-1", 0)).expect("投递被接受");
        assert_eq!(
            report.outcome_for(&WindowLabel::new("stale")),
            Some(DeliveryOutcome::Filtered(FilterReason::StaleAuthGeneration))
        );
        assert_eq!(
            report.outcome_for(&WindowLabel::new("current")),
            Some(DeliveryOutcome::Delivered { seq: 0 })
        );
        assert!(drain(&mut stale_session).is_empty());
        assert_eq!(drain(&mut current).len(), 1);
    }

    /// thread 维度：订阅了才收得到。
    #[tokio::test]
    async fn thread_scoped_frames_reach_only_subscribed_windows() {
        let broker = broker();
        let thread = ThreadId::new("thread-1");
        let mut subscribed = broker
            .open_window(
                WindowIdentity::bind(WindowLabel::new("sub"), &auth_for("actor-1")),
                ThreadSubscriptions::from_threads([thread.clone()]),
            )
            .expect("开窗成功");
        let mut bare = open(&broker, "bare", "actor-1");

        let event = BrokerEvent::new(
            EventScope::thread(tenant(), ActorId::new("actor-1"), thread),
            crate::testing::TEST_AUTH_GENERATION,
            heartbeat(0),
        );
        let report = broker.publish(event).expect("投递被接受");
        assert_eq!(
            report.outcome_for(&WindowLabel::new("sub")),
            Some(DeliveryOutcome::Delivered { seq: 0 })
        );
        assert_eq!(
            report.outcome_for(&WindowLabel::new("bare")),
            Some(DeliveryOutcome::Filtered(FilterReason::NotSubscribed))
        );
        assert_eq!(drain(&mut subscribed).len(), 1);
        assert!(drain(&mut bare).is_empty());
    }

    // -----------------------------------------------------------------------
    // 正向对照：不撑队列时序号连续、零 gap
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn without_pressure_the_sequence_is_continuous_and_gap_free() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        for seq in 0..10 {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }
        let frames = drain(&mut a);
        assert_eq!(frames.len(), 10);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.seq(), index as u64);
            assert_eq!(frame.skipped(), None, "没有压力就不该有 gap");
        }
        let tracker = observe_all(&frames).expect("序列合法");
        assert_eq!(tracker.missing_total(), 0);
        assert_eq!(broker.metrics().shed_total(), 0);
    }

    // -----------------------------------------------------------------------
    // 撑满队列：gap 必须可见（§13.2 的核心判据）
    // -----------------------------------------------------------------------

    /// latest-value 撑满队列后，接收端**看得见** gap，而不是收到一段连续序号。
    ///
    /// 四条断言合起来才是那句「不能让 GUI 误以为完整」：
    /// ① 自检器全程 `Ok`（每次跳变都有说明）；② `missing_total > 0`（确实漏了）；
    /// ③ 收到的序号**不是**连续的 0..N（不是靠"其实没丢"蒙混过关）；
    /// ④ metric 与接收端算出的缺失数相等。
    ///
    /// 中间那次 `flush_pending` 不是测试技巧，是被测语义本身：满队列装不进任何东西，
    /// 所以 gap 只能在接收端腾出位置、生产侧再动一次时才送达（见
    /// [`EventBroker::flush_pending`] 的文档）。第一段 drain 顺带钉住了另一半 ——
    /// **在 gap 送达之前，接收端看到的连续序号是真连续**，没有被误导的时刻。
    #[tokio::test]
    async fn overflow_is_visible_as_a_gap_not_as_a_silent_continuous_run() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        let published = CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 64;
        for seq in 0..published {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }

        // 第一段：队列里排着的那 256 帧。它们是**真连续**的 —— 缺失的那一段序号还在后面。
        let queued = drain(&mut a);
        assert_eq!(queued.len(), CRITICAL_EVENT_QUEUE_CAPACITY);
        assert!(
            queued.iter().all(|frame| frame.skipped().is_none()),
            "已经排上队的帧之前没有缺失"
        );

        // 生产侧的下一次动作把 gap 说明带出来。
        broker.flush_pending();
        let mut frames = queued;
        frames.extend(drain(&mut a));

        let tracker = observe_all(&frames).expect("每一次跳变都必须带 gap 说明");

        assert!(tracker.missing_total() > 0, "撑满之后必须有已知缺失");
        assert!(
            frames.iter().any(|frame| frame.skipped().is_some()),
            "至少有一帧要挂着 gap 说明"
        );
        assert!(
            frames.len() < published as usize,
            "确实有帧没送达：收到 {} / 投出 {published}",
            frames.len()
        );
        // 负向：收到的不是连续的 0..len。
        let continuous = frames
            .iter()
            .enumerate()
            .all(|(index, frame)| frame.seq() == index as u64);
        assert!(!continuous, "序号若连续就说明丢帧被藏起来了");

        // metric 与接收端看到的 gap 是同一件事（§13.2「产生 metric 和 sequence gap」）。
        assert_eq!(broker.metrics().shed_total(), tracker.missing_total());
    }

    /// latest-value 真的是 latest：冲一次槽之后，最后到的那帧是**最新**的那个值。
    #[tokio::test]
    async fn latest_value_keeps_the_newest_frame_not_the_oldest() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        let published = CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 10;
        for seq in 0..published {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }
        let _first_batch = drain(&mut a);
        broker.flush_pending();
        let flushed = drain(&mut a);

        let last = flushed.last().expect("待发槽里压着最新那帧");
        assert_eq!(
            last.event(),
            Some(&heartbeat(published - 1)),
            "槽里留下的必须是最新值"
        );
        assert_eq!(last.seq(), published - 1);
    }

    // -----------------------------------------------------------------------
    // 关键帧不可静默丢（§13.2）
    // -----------------------------------------------------------------------

    /// 关键帧遇到满队列 → **显式断开**：终止帧 + 流关闭，绝不静默丢。
    #[tokio::test]
    async fn a_critical_frame_on_a_full_queue_disconnects_explicitly() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        // 正向对照：前 256 帧一条不落全部入队。
        for seq in 0..CRITICAL_EVENT_QUEUE_CAPACITY as u64 {
            let report = broker
                .publish(critical_to_window("a", seq))
                .expect("投递被接受");
            assert_eq!(
                report.outcome_for(&WindowLabel::new("a")),
                Some(DeliveryOutcome::Delivered { seq })
            );
        }

        // 第 257 帧：队列满了，必须显式断开而不是丢掉。
        let overflow = broker
            .publish(critical_to_window(
                "a",
                CRITICAL_EVENT_QUEUE_CAPACITY as u64,
            ))
            .expect("投递被接受");
        let outcome = overflow
            .outcome_for(&WindowLabel::new("a"))
            .expect("该窗口必须有结果");
        assert!(
            matches!(
                outcome,
                DeliveryOutcome::Disconnected {
                    reason: DisconnectReason::QueueOverflow {
                        class: DeliveryClass::Critical
                    },
                    ..
                }
            ),
            "拿到 {outcome:?}"
        );
        assert_eq!(broker.window_count(), 0, "断开的路由必须被摘除");

        // 接收端看到的是：256 条事件 + 一帧终止帧，然后流关闭。
        let frames = drain(&mut a);
        assert_eq!(frames.len(), CRITICAL_EVENT_QUEUE_CAPACITY + 1);
        let terminal = frames.last().expect("最后一帧");
        assert!(terminal.is_terminal());
        assert_eq!(
            terminal.terminal_reason(),
            Some(DisconnectReason::QueueOverflow {
                class: DeliveryClass::Critical
            })
        );
        // 终止帧上挂着"这些序号永远不会到达"。
        let gap = terminal.skipped().expect("终止帧必须说明缺了哪些");
        assert_eq!(gap.cause, GapCause::Dropped);
        let tracker = observe_all(&frames).expect("序列合法");
        assert_eq!(tracker.missing_total(), gap.len());
        assert_eq!(broker.metrics().dropped, gap.len());

        // 流确实结束了（不是"安静地什么都不再来"）。
        assert!(session_is_closed(&mut a));
    }

    /// 断开之后再投同一个窗口不会复活它。
    #[tokio::test]
    async fn publishing_after_a_disconnect_does_not_resurrect_the_route() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        for seq in 0..=CRITICAL_EVENT_QUEUE_CAPACITY as u64 {
            broker
                .publish(critical_to_window("a", seq))
                .expect("投递被接受");
        }
        assert_eq!(broker.window_count(), 0);

        let after = broker
            .publish(critical_to_window("a", 999))
            .expect("投递被接受");
        assert!(
            after.deliveries().is_empty(),
            "已摘除的路由不再出现在报告里"
        );
        let frames = drain(&mut a);
        assert!(
            frames.last().expect("最后一帧").is_terminal(),
            "终止帧之后不该再有事件帧"
        );
    }

    // -----------------------------------------------------------------------
    // screen 不走这条通道（§13.4）
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_screen_class_frame_is_rejected_outright() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        let screen = BrokerEvent::with_class_for_test(
            EventScope::window(tenant(), WindowLabel::new("a")),
            crate::testing::TEST_AUTH_GENERATION,
            heartbeat(0),
            DeliveryClass::Screen,
        );
        assert_eq!(
            broker.publish(screen),
            Err(PublishRejected::ScreenMustNotUseTheEventChannel)
        );
        assert!(drain(&mut a).is_empty(), "被拒的帧一格都不该占");
        assert_eq!(broker.metrics().rejected, 1);

        // 正向对照：同一个窗口此刻仍然收得到结构化事件。
        broker.publish(to_window("a", 1)).expect("投递被接受");
        assert_eq!(drain(&mut a).len(), 1);
    }

    // -----------------------------------------------------------------------
    // drop 接收端让生产侧停下来
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dropping_the_session_stops_delivery_and_removes_the_route() {
        let broker = broker();
        let a = open(&broker, "a", "actor-1");
        let mut b = open(&broker, "b", "actor-2");

        // 正向对照：drop 之前投得进去。
        let before = broker.publish(to_window("a", 0)).expect("投递被接受");
        assert_eq!(
            before.outcome_for(&WindowLabel::new("a")),
            Some(DeliveryOutcome::Delivered { seq: 0 })
        );

        drop(a);

        let after = broker.publish(to_window("a", 1)).expect("投递被接受");
        assert_eq!(
            after.outcome_for(&WindowLabel::new("a")),
            Some(DeliveryOutcome::ReceiverGone)
        );
        assert_eq!(broker.window_count(), 1, "只剩窗口 b");
        assert_eq!(broker.metrics().receiver_gone, 1);

        // 负向对照：别的窗口没被牵连。
        broker.publish(to_window("b", 2)).expect("投递被接受");
        assert_eq!(drain(&mut b).len(), 1);
    }

    // -----------------------------------------------------------------------
    // 关停
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn close_window_is_exact_terminal_and_idempotent() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        let mut b = open(&broker, "b", "actor-1");
        broker.publish(to_window("a", 0)).expect("投递被接受");

        assert!(broker.close_window(&WindowLabel::new("a"), DisconnectReason::SubscriptionClosed));
        assert!(!broker.close_window(&WindowLabel::new("a"), DisconnectReason::SubscriptionClosed));
        assert_eq!(broker.window_count(), 1);

        let frames = drain(&mut a);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].event(), Some(&heartbeat(0)));
        assert_eq!(
            frames[1].terminal_reason(),
            Some(DisconnectReason::SubscriptionClosed)
        );
        assert!(observe_all(&frames).is_ok());
        assert!(session_is_closed(&mut a));

        broker.publish(to_window("b", 1)).expect("另一窗口仍可投递");
        assert_eq!(drain(&mut b).len(), 1);
        assert_eq!(broker.metrics().disconnected, 1);
    }

    #[tokio::test]
    async fn close_all_gives_every_window_a_terminal_frame_then_ends_the_stream() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        let mut b = open(&broker, "b", "actor-2");
        broker.publish(to_window("a", 0)).expect("投递被接受");

        assert_eq!(broker.close_all(), 2);
        assert_eq!(broker.window_count(), 0);

        for session in [&mut a, &mut b] {
            let frames = drain(session);
            let terminal = frames.last().expect("每个窗口都要收到终止帧");
            assert!(terminal.is_terminal());
            assert_eq!(terminal.terminal_reason(), Some(DisconnectReason::Shutdown));
            assert!(observe_all(&frames).is_ok());
        }
        assert!(session_is_closed(&mut a));
        assert!(session_is_closed(&mut b));
    }

    /// 关停前会先把待发槽冲出去 —— 最后一个已知的 presence 值不该被顺手吃掉。
    #[tokio::test]
    async fn close_all_flushes_the_pending_latest_value_first() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        let published = CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 4;
        for seq in 0..published {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }
        let _ = drain(&mut a); // 腾出空位

        broker.close_all();
        let frames = drain(&mut a);
        assert!(
            frames
                .iter()
                .any(|frame| frame.event() == Some(&heartbeat(published - 1))),
            "关停前必须把槽里最新那帧送出去"
        );
    }

    #[tokio::test]
    async fn a_cancelled_broker_refuses_new_frames() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        // 正向对照：取消之前收得下。
        broker.publish(to_window("a", 0)).expect("投递被接受");

        broker.shutdown_token().cancel();
        assert_eq!(
            broker.publish(to_window("a", 1)),
            Err(PublishRejected::ShuttingDown)
        );
        assert_eq!(drain(&mut a).len(), 1, "取消之后一帧都不该再进来");
    }

    /// metric 与接收端各自算出的"漏了多少"必须相等。
    #[tokio::test]
    async fn metrics_and_receiver_side_gaps_agree() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");
        for seq in 0..(CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 33) {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }
        let mut frames = drain(&mut a);
        broker.flush_pending();
        frames.extend(drain(&mut a));
        let tracker = observe_all(&frames).expect("序列合法");
        let metrics = broker.metrics();

        assert_eq!(metrics.shed_total(), tracker.missing_total());
        assert!(metrics.superseded > 0, "latest-value 确实取代了帧");
        assert_eq!(metrics.dropped, 0, "latest-value 路径不该产生丢弃");
        assert_eq!(metrics.published, CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 33);
        assert_eq!(metrics.disconnected, 0);
    }

    /// **有 gap 就一定有载体**：生产侧从此不再投任何事件，关停时那段缺失照样送达。
    ///
    /// 这条堵的是"接收端永远不知道自己漏了"那个洞 —— 没有它，
    /// [`EventBroker::flush_pending`] 文档里那两句「两处都留下了载体」只是一句声明。
    #[tokio::test]
    async fn a_pending_gap_always_has_a_carrier() {
        let broker = broker();
        let mut a = open(&broker, "a", "actor-1");

        let published = CRITICAL_EVENT_QUEUE_CAPACITY as u64 + 20;
        for seq in 0..published {
            broker.publish(to_window("a", seq)).expect("投递被接受");
        }
        let mut frames = drain(&mut a);
        assert!(
            frames.iter().all(|frame| frame.skipped().is_none()),
            "此刻 gap 还压在生产侧"
        );

        // 从这里开始**一帧都不再投**，只关停。
        broker.close_all();
        frames.extend(drain(&mut a));

        let tracker = observe_all(&frames).expect("序列合法");
        assert_eq!(
            tracker.missing_total(),
            broker.metrics().shed_total(),
            "关停必须把缺失说明送到接收端"
        );
        assert!(tracker.missing_total() > 0);
        assert!(
            frames.iter().any(|frame| frame.skipped().is_some()),
            "缺失说明必须真的出现在某一帧上"
        );
        assert!(frames.last().expect("最后一帧").is_terminal());
    }

    #[test]
    fn disconnect_reason_labels_are_closed_and_distinct() {
        assert_eq!(
            DisconnectReason::QueueOverflow {
                class: DeliveryClass::Critical
            }
            .as_str(),
            "queue_overflow"
        );
        assert_eq!(DisconnectReason::Shutdown.as_str(), "shutdown");
        assert_eq!(DisconnectReason::UpstreamEnded.as_str(), "upstream_ended");
        assert_eq!(
            DisconnectReason::SubscriptionClosed.as_str(),
            "subscription_closed"
        );
        assert_ne!(
            DisconnectReason::Shutdown.as_str(),
            DisconnectReason::QueueOverflow {
                class: DeliveryClass::Critical
            }
            .as_str()
        );
        assert_ne!(
            DisconnectReason::UpstreamEnded.as_str(),
            DisconnectReason::SubscriptionClosed.as_str()
        );
    }

    /// 队列抽干且 `Sender` 已 drop 时，`try_recv` 报 `Disconnected` 而不是 `Empty`。
    fn session_is_closed(session: &mut DesktopSession) -> bool {
        matches!(
            session.events.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        )
    }
}
