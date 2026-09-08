//! 投递帧、序号与 gap —— v3 §13.2「任意丢弃或合并都产生 metric 和 sequence gap，
//! **不能让 GUI 误以为完整**」。
//!
//! # 三个类型，三件事
//!
//! - [`BrokerEvent`]：生产侧铸造一次的事件，带上它的可见性范围、代际与投递等级。
//!   跨窗口**共享**（内部以 `Arc` 传递），不逐窗口复制载荷。
//! - [`AppEventRef`]：某个窗口投递序列上的**一帧**。它是一个引用（见下），带序号，
//!   并且可以携带一段"这些序号永远不会到达"的说明。
//! - [`SequenceTracker`]：接收端自检器。它把"我漏了没有"从一句需要人去想的话，变成
//!   一次 `Result`。
//!
//! # 为什么是 `AppEventRef` 而不是 `AppEvent`
//!
//! §13.2 的骨架把队列写成 `mpsc::Receiver<AppEventRef>` —— 名字里的 ref 是有分量的，
//! 三条理由：
//!
//! 1. **有界队列必须真的有界**。一个 broker 服务 N 个窗口，一帧要进 N 条队列。若队列
//!    装的是 `AppEvent` 值，那么"每窗口 256"限的是**条数**，而每条的载荷可以任意大，
//!    N × 256 条各自持有一份完整载荷 —— 内存维度上根本没有界。装引用之后，256 限的是
//!    256 个定长句柄，载荷在整个 broker 里只有一份。
//! 2. **所有窗口必须看到同一份事实**。共享同一个 `Arc<BrokerEvent>` 意味着两个窗口拿到的
//!    是逐字节同一帧；逐窗口克隆则给了"某条路径上被改过"的可能性一个存在的位置。
//! 3. **一帧不只是一个事件**。终止帧（[`FramePayload::Terminal`]）不携带任何 `AppEvent`，
//!    但它占一个序号、也可能捎带一段 gap 说明。`AppEventRef` 是"序列上的一个位置"，
//!    这个抽象容得下它；`AppEvent` 容不下。
//!
//! # 序号与 gap 的表达方式（接收端凭什么判定"我漏了"）
//!
//! - 序号是**每窗口**的，从 0 开始，对**该窗口准入的每一帧**加一。被 ACL 过滤掉的帧
//!   **不占**序号 —— 否则窗口 A 能从自己序号的跳变里推断窗口 B 的流量，那本身就是跨
//!   scope 泄漏（详见 [`crate::window::FilterReason`] 的类型文档）。
//! - 丢弃或合并发生时，被跳过的那一段序号记进 [`SequenceGap`]，**挂在下一帧真正送达的
//!   帧上**（[`AppEventRef::skipped`]）。于是接收端的不变量非常好查：
//!
//!   ```text
//!   下一帧的 seq == 我期待的 seq             （没丢）
//!   或
//!   下一帧带 gap，且 gap 恰好覆盖 [我期待的 seq, 下一帧 seq - 1]   （丢了，而且我知道丢了哪些）
//!   ```
//!
//!   两者都不成立 = 静默丢帧，[`SequenceTracker::observe`] 当场返回
//!   [`SequenceError::SilentLoss`]。**这就是"不能让 GUI 误以为完整"的可判定形式。**

use core::fmt;
use std::sync::Arc;

use openbot_contracts::command::AppEvent;

use crate::broker::DisconnectReason;
use crate::budget::{DeliveryClass, EventQueuePermit, delivery_class};
use crate::window::EventScope;

/// 每窗口队列里**永久留给终止帧**的格数。
///
/// # 为什么必须预留
///
/// §13.2 要求关键帧「队列满即显式断开/失败」。可是"显式"这两个字有个物理前提：断开
/// 的消息本身也得进得去那条已经满了的队列。若不预留，实现就只剩下"drop 掉 sender"
/// 一条路 —— 而接收端看到的 `recv() == None` 与**正常收完**长得一模一样，那正是
/// 「让 GUI 误以为完整」。
///
/// 所以底层 `mpsc` 建成 `CRITICAL_EVENT_QUEUE_CAPACITY + TERMINAL_FRAME_RESERVE`，
/// 普通事件帧只允许用到前 256 格（[`crate::budget::CRITICAL_EVENT_QUEUE_CAPACITY`]
/// 逐字等于方案里那个 256），最后一格任何时候都留着，只有终止帧能用。
pub const TERMINAL_FRAME_RESERVE: usize = 1;

/// 生产侧铸造的一条事件，连同它的**可见性范围、代际与投递等级**。
///
/// 三样东西在铸造时一次交齐，之后不可变：没有"先发出去，再决定给谁看"的中间态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerEvent {
    scope: EventScope,
    auth_generation: u64,
    class: DeliveryClass,
    event: AppEvent,
}

impl BrokerEvent {
    /// 生产构造。投递等级由 [`delivery_class`] 从事件本身推出 —— **调用方不能自己指定**。
    ///
    /// 这一条是刻意的：谁都不该有"把一条 terminal 声明成 progress"的能力，那等于让调用点
    /// 决定自己的帧可不可以被丢。分类是事件种类的函数，不是调用点的选项。
    #[must_use]
    pub fn new(scope: EventScope, auth_generation: u64, event: AppEvent) -> Self {
        let class = delivery_class(&event);
        Self {
            scope,
            auth_generation,
            class,
            event,
        }
    }

    /// 指定投递等级的构造 —— **仅测试**（`cfg(test)` 或 `testkit` feature）。
    ///
    /// # 它为什么必须存在
    ///
    /// G1 的 [`AppEvent`] 只有心跳一个变体，而 [`delivery_class`] 把它判为
    /// [`DeliveryClass::LatestValue`]。于是「关键帧队列满时显式断开」这条 §13.2 的
    /// 硬要求，在 G1 **没有任何生产事件能触发**。
    ///
    /// 两条路：要么等 G3 有了 terminal 事件再写那段代码与测试，要么现在就写代码、用一个
    /// 测试专用的铸造口去验它。选后者的理由是前者会让 G1 交付一段**从未被执行过**的
    /// 断开路径 —— 而"写了但没跑过"正是这类分支最常见的失效形态。
    ///
    /// 它跟 `AuthContext::for_test` 同一手法：门在 feature 后面，生产 feature 图里
    /// 压根没编译进去。
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn with_class_for_test(
        scope: EventScope,
        auth_generation: u64,
        event: AppEvent,
        class: DeliveryClass,
    ) -> Self {
        Self {
            scope,
            auth_generation,
            class,
            event,
        }
    }

    /// 可见性范围。
    #[must_use]
    pub fn scope(&self) -> &EventScope {
        &self.scope
    }

    /// 铸造时刻的 auth generation。
    #[must_use]
    pub fn auth_generation(&self) -> u64 {
        self.auth_generation
    }

    /// 投递等级。
    #[must_use]
    pub fn class(&self) -> DeliveryClass {
        self.class
    }

    /// 事件本身。
    #[must_use]
    pub fn event(&self) -> &AppEvent {
        &self.event
    }
}

/// 一段**永远不会到达**的序号区间。
///
/// 闭区间 `[from_seq, through_seq]`，两端都含。`cause` 是诊断信息，**区间本身才是权威**
/// —— 接收端据以判定完整性的是区间，不是原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceGap {
    /// 缺失区间的第一个序号（含）。
    pub from_seq: u64,
    /// 缺失区间的最后一个序号（含）。
    pub through_seq: u64,
    /// 缺失原因中**最严重**的那一项（见 [`GapCause`]）。
    pub cause: GapCause,
}

impl SequenceGap {
    /// 缺失了多少帧。
    #[must_use]
    pub const fn len(&self) -> u64 {
        // `through >= from` 由构造与合并两处共同维持（见 `broker` 里的 `record_gap`）。
        // 万一被破坏也不 panic：饱和相减给 0，宁可少报也不要在 transport 里炸。
        self.through_seq
            .saturating_sub(self.from_seq)
            .saturating_add(1)
    }

    /// 区间是否为空。恒为 `false`（闭区间至少含一个序号），提供它只是为了配合
    /// [`Self::len`] 满足 clippy 的成对约定。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// 把一个新的缺失序号并进本区间。
    ///
    /// 两端都取极值（`min` / `max`）而不是只往后延：终止路径上，"当前这一帧"与"待发槽里
    /// 那一帧"的记录顺序与它们的序号顺序**相反**（槽里那帧的序号更小、却更晚被记）。
    /// 只往后延会把更小的那个序号漏在区间外，于是接收端会判出一次 `SilentLoss` ——
    /// 一个由记录顺序造成的假警报。
    pub(crate) fn absorb(&mut self, seq: u64, cause: GapCause) {
        self.from_seq = self.from_seq.min(seq);
        self.through_seq = self.through_seq.max(seq);
        self.cause = self.cause.max(cause);
    }
}

/// 缺失的原因。**恰两种，两种都有生产者**。
///
/// `Ord` 的顺序即严重度：[`Self::Dropped`] > [`Self::Superseded`]。区间合并时取更严重的
/// 那一项（见 [`SequenceGap::absorb`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapCause {
    /// latest-value 取代：更新的一帧顶掉了待发槽里更旧的一帧。
    ///
    /// 生产者：[`DeliveryClass::LatestValue`] 在队列满时的正常路径。
    Superseded,

    /// 丢弃：这一帧没能送达，且不是被更新的值顶掉的。
    ///
    /// 生产者两处：① 不可丢的等级遇到满队列（随即显式断开）；② 路由关停时待发槽里
    /// 还压着一帧且队列没有空位。
    Dropped,
}

impl GapCause {
    /// 稳定的低基数标签名（§16.4）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Superseded => "superseded",
            Self::Dropped => "dropped",
        }
    }
}

/// 一帧的载荷：要么是一条事件，要么是这条流的终止说明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FramePayload {
    /// 一条事件（跨窗口共享的引用）。
    Event(Arc<BrokerEvent>),
    /// 终止帧 —— 本窗口的流到此为止，附断开原因。它**总是**该窗口收到的最后一帧。
    Terminal(DisconnectReason),
}

/// 某个窗口投递序列上的一帧。
///
/// 名字里的 `Ref` 见模块文档：它是"序列上的一个位置 + 一个共享引用"，不是事件的副本。
#[derive(Clone, Debug)]
pub struct AppEventRef {
    seq: u64,
    skipped: Option<SequenceGap>,
    payload: FramePayload,
    // Operational ownership only: it is not part of frame identity or wire semantics. Keeping the
    // permit inside the frame makes receiver drop, send failure, and frame clones release exactly
    // once without trying to infer how many entries a closed mpsc receiver discarded.
    _queue_permit: Option<Arc<EventQueuePermit>>,
}

impl AppEventRef {
    pub(crate) fn new(
        seq: u64,
        skipped: Option<SequenceGap>,
        payload: FramePayload,
        queue_permit: Option<Arc<EventQueuePermit>>,
    ) -> Self {
        Self {
            seq,
            skipped,
            payload,
            _queue_permit: queue_permit,
        }
    }

    /// Mark this frame as dequeued from its broker route.
    ///
    /// Raw receiver users that skip [`crate::DesktopSession::next_frame`] merely retain the permit
    /// until frame drop, which is stricter but cannot exceed the aggregate bound.
    pub(crate) fn release_queue_permit(&mut self) {
        self._queue_permit = None;
    }

    /// 构造任意一帧 —— **仅测试**（`cfg(test)` 或 `testkit` feature）。
    ///
    /// 用途只有一个：给 [`SequenceTracker`] 喂**手工构造的坏序列**，证明这个自检器不是
    /// 一个恒返回 `Ok` 的摆设。没有它，"tracker 全程 Ok"这条断言在"tracker 永远说 Ok"
    /// 的世界里同样成立。
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn for_test(seq: u64, skipped: Option<SequenceGap>, payload: FramePayload) -> Self {
        Self::new(seq, skipped, payload, None)
    }

    /// 本帧在该窗口序列中的位置。
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// 紧接在本帧之前、**永远不会到达**的那一段序号（没有则为 `None`）。
    #[must_use]
    pub fn skipped(&self) -> Option<SequenceGap> {
        self.skipped
    }

    /// 载荷。
    #[must_use]
    pub fn payload(&self) -> &FramePayload {
        &self.payload
    }

    /// 事件本身；本帧是终止帧时返回 `None`。
    #[must_use]
    pub fn event(&self) -> Option<&AppEvent> {
        match &self.payload {
            FramePayload::Event(event) => Some(event.event()),
            FramePayload::Terminal(_) => None,
        }
    }

    /// 本帧的投递等级；终止帧没有等级，返回 `None`。
    #[must_use]
    pub fn class(&self) -> Option<DeliveryClass> {
        match &self.payload {
            FramePayload::Event(event) => Some(event.class()),
            FramePayload::Terminal(_) => None,
        }
    }

    /// 本帧的可见性范围；终止帧没有范围，返回 `None`。
    #[must_use]
    pub fn scope(&self) -> Option<&EventScope> {
        match &self.payload {
            FramePayload::Event(event) => Some(event.scope()),
            FramePayload::Terminal(_) => None,
        }
    }

    /// 本帧铸造时的 auth generation；终止帧返回 `None`。
    #[must_use]
    pub fn auth_generation(&self) -> Option<u64> {
        match &self.payload {
            FramePayload::Event(event) => Some(event.auth_generation()),
            FramePayload::Terminal(_) => None,
        }
    }

    /// 是终止帧则返回断开原因。
    #[must_use]
    pub fn terminal_reason(&self) -> Option<DisconnectReason> {
        match &self.payload {
            FramePayload::Event(_) => None,
            FramePayload::Terminal(reason) => Some(*reason),
        }
    }

    /// 是否为终止帧。
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.payload, FramePayload::Terminal(_))
    }
}

impl PartialEq for AppEventRef {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.skipped == other.skipped && self.payload == other.payload
    }
}

impl Eq for AppEventRef {}

/// 接收端的完整性自检器 —— 把"我漏了没有"变成一次 `Result`。
///
/// 用法：对收到的**每一帧**调用 [`Self::observe`]。它维护"下一个该来的序号"，并按模块
/// 文档里那条不变量校验。GUI 侧的正确反应是：
///
/// - `Ok(())` 且 [`Self::missing_total`] 仍为 0 → 完整；
/// - `Ok(())` 但 `missing_total > 0` → **有帧没到，而且我知道是哪些** → 该从 durable
///   cursor replay（§13.2）；
/// - `Err(..)` → 这条流违反了它自己的契约，属于缺陷，不该被当成"网络抖动"吞掉。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SequenceTracker {
    expected: u64,
    missing: u64,
}

impl SequenceTracker {
    /// 新建（期待从序号 0 开始）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 下一个应当到达的序号。
    #[must_use]
    pub fn expected(&self) -> u64 {
        self.expected
    }

    /// 到目前为止**已知缺失**的帧数。
    #[must_use]
    pub fn missing_total(&self) -> u64 {
        self.missing
    }

    /// 观察一帧。
    ///
    /// # Errors
    ///
    /// 序号跳变而没有 gap 说明、gap 说明与跳变对不上、或序号倒退 / 重复时返回
    /// [`SequenceError`]。
    pub fn observe(&mut self, frame: &AppEventRef) -> Result<(), SequenceError> {
        if let Some(gap) = frame.skipped() {
            let covers_from_here = gap.from_seq == self.expected;
            let ends_right_before = gap.through_seq.checked_add(1) == Some(frame.seq());
            if !covers_from_here || !ends_right_before {
                return Err(SequenceError::InconsistentGap {
                    expected: self.expected,
                    gap,
                    observed: frame.seq(),
                });
            }
            self.missing = self.missing.saturating_add(gap.len());
            self.expected = frame.seq();
        }

        if frame.seq() > self.expected {
            return Err(SequenceError::SilentLoss {
                expected: self.expected,
                observed: frame.seq(),
            });
        }
        if frame.seq() < self.expected {
            return Err(SequenceError::NotMonotonic {
                expected: self.expected,
                observed: frame.seq(),
            });
        }

        self.expected = self.expected.saturating_add(1);
        Ok(())
    }
}

/// 接收端自检失败 —— 这条流违反了它自己的序号契约。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SequenceError {
    /// 序号往前跳了，却没有任何 gap 说明。**这就是"让 GUI 误以为完整"的那一刻。**
    #[error("silent_loss expected={expected} observed={observed}")]
    SilentLoss {
        /// 本应到达的序号。
        expected: u64,
        /// 实际到达的序号。
        observed: u64,
    },

    /// 有 gap 说明，但它与实际跳变对不上（起点不接、终点不接）。
    #[error("inconsistent_gap expected={expected} gap={gap:?} observed={observed}")]
    InconsistentGap {
        /// 本应到达的序号。
        expected: u64,
        /// 帧上携带的 gap 说明。
        gap: SequenceGap,
        /// 实际到达的序号。
        observed: u64,
    },

    /// 序号倒退或重复。
    #[error("not_monotonic expected={expected} observed={observed}")]
    NotMonotonic {
        /// 本应到达的序号。
        expected: u64,
        /// 实际到达的序号。
        observed: u64,
    },
}

impl fmt::Display for GapCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::DeliveryClass;
    use crate::testing::tenant;
    use crate::window::WindowLabel;
    use openbot_contracts::ids::ActorId;

    fn scope() -> EventScope {
        EventScope::actor(tenant(), ActorId::new("actor-1"))
    }

    fn event_frame(seq: u64, skipped: Option<SequenceGap>) -> AppEventRef {
        let event = BrokerEvent::new(scope(), 7, AppEvent::Heartbeat { seq });
        AppEventRef::for_test(seq, skipped, FramePayload::Event(Arc::new(event)))
    }

    // -----------------------------------------------------------------------
    // BrokerEvent
    // -----------------------------------------------------------------------

    /// 生产构造的等级来自事件本身，调用方指定不了。
    #[test]
    fn production_minting_derives_the_class_from_the_event() {
        let minted = BrokerEvent::new(scope(), 7, AppEvent::Heartbeat { seq: 0 });
        assert_eq!(minted.class(), DeliveryClass::LatestValue);
        assert_eq!(minted.class(), delivery_class(minted.event()));
        assert_eq!(minted.auth_generation(), 7);
        assert_eq!(minted.scope(), &scope());
    }

    /// 正向对照：测试铸造口确实能造出**别的**等级 —— 否则关键帧那条路径的测试是假的。
    #[test]
    fn the_test_only_minting_can_produce_other_classes() {
        let critical = BrokerEvent::with_class_for_test(
            scope(),
            7,
            AppEvent::Heartbeat { seq: 0 },
            DeliveryClass::Critical,
        );
        assert_eq!(critical.class(), DeliveryClass::Critical);
        assert_ne!(critical.class(), delivery_class(critical.event()));
    }

    // -----------------------------------------------------------------------
    // SequenceGap
    // -----------------------------------------------------------------------

    #[test]
    fn a_single_seq_gap_has_length_one() {
        let gap = SequenceGap {
            from_seq: 5,
            through_seq: 5,
            cause: GapCause::Superseded,
        };
        assert_eq!(gap.len(), 1);
        assert!(!gap.is_empty());
    }

    /// 合并往**两个方向**都扩，且原因取更严重的那个。
    ///
    /// 后半句是关键：终止路径上先记当前帧（`Dropped`）、再记待发槽里更旧那帧
    /// （序号更小）。只往后延会把更小的序号漏在区间外。
    #[test]
    fn absorbing_extends_in_both_directions_and_keeps_the_worse_cause() {
        let mut gap = SequenceGap {
            from_seq: 9,
            through_seq: 9,
            cause: GapCause::Dropped,
        };
        gap.absorb(7, GapCause::Superseded);
        assert_eq!(gap.from_seq, 7);
        assert_eq!(gap.through_seq, 9);
        assert_eq!(gap.cause, GapCause::Dropped, "更严重的原因胜出");
        assert_eq!(gap.len(), 3);

        gap.absorb(12, GapCause::Superseded);
        assert_eq!(gap.through_seq, 12);
    }

    #[test]
    fn dropped_is_more_severe_than_superseded() {
        assert!(GapCause::Dropped > GapCause::Superseded);
        assert_eq!(GapCause::Dropped.as_str(), "dropped");
        assert_eq!(GapCause::Superseded.to_string(), "superseded");
    }

    // -----------------------------------------------------------------------
    // AppEventRef
    // -----------------------------------------------------------------------

    #[test]
    fn an_event_frame_exposes_the_event_and_a_terminal_frame_does_not() {
        let frame = event_frame(3, None);
        assert!(!frame.is_terminal());
        assert_eq!(frame.event(), Some(&AppEvent::Heartbeat { seq: 3 }));
        assert_eq!(frame.class(), Some(DeliveryClass::LatestValue));
        assert_eq!(frame.auth_generation(), Some(7));
        assert!(frame.scope().is_some());
        assert_eq!(frame.terminal_reason(), None);

        let terminal =
            AppEventRef::for_test(4, None, FramePayload::Terminal(DisconnectReason::Shutdown));
        assert!(terminal.is_terminal());
        assert_eq!(terminal.event(), None);
        assert_eq!(terminal.class(), None);
        assert_eq!(terminal.scope(), None);
        assert_eq!(terminal.auth_generation(), None);
        assert_eq!(terminal.terminal_reason(), Some(DisconnectReason::Shutdown));
    }

    /// 同一个 `Arc<BrokerEvent>` 分发给两个窗口时，两边看到的是**同一份**载荷。
    #[test]
    fn one_payload_is_shared_by_every_windows_frame() {
        let shared = Arc::new(BrokerEvent::new(
            EventScope::window(tenant(), WindowLabel::new("a")),
            7,
            AppEvent::Heartbeat { seq: 1 },
        ));
        let to_a = AppEventRef::for_test(0, None, FramePayload::Event(Arc::clone(&shared)));
        let to_b = AppEventRef::for_test(0, None, FramePayload::Event(Arc::clone(&shared)));

        assert_eq!(
            Arc::strong_count(&shared),
            3,
            "两帧各持一个引用，加上本地这个"
        );
        assert_eq!(to_a.event(), to_b.event());
    }

    // -----------------------------------------------------------------------
    // SequenceTracker —— 自检器本身必须先被证明不是摆设
    // -----------------------------------------------------------------------

    /// 正向对照：连续序列全程 `Ok`，且 `missing_total` 为 0。
    #[test]
    fn a_continuous_run_is_accepted_with_zero_missing() {
        let mut tracker = SequenceTracker::new();
        for seq in 0..8 {
            assert_eq!(tracker.observe(&event_frame(seq, None)), Ok(()));
        }
        assert_eq!(tracker.missing_total(), 0);
        assert_eq!(tracker.expected(), 8);
    }

    /// 负向：序号跳变而**没有** gap 说明 —— 这正是"GUI 误以为完整"的那一刻，必须被抓住。
    #[test]
    fn a_jump_without_a_gap_annotation_is_reported_as_silent_loss() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));
        assert_eq!(
            tracker.observe(&event_frame(5, None)),
            Err(SequenceError::SilentLoss {
                expected: 1,
                observed: 5
            })
        );
    }

    /// 正向：跳变**带**正确 gap 说明时被接受，并且缺失数被算进去。
    #[test]
    fn an_annotated_jump_is_accepted_and_counted() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));

        let gap = SequenceGap {
            from_seq: 1,
            through_seq: 4,
            cause: GapCause::Superseded,
        };
        assert_eq!(tracker.observe(&event_frame(5, Some(gap))), Ok(()));
        assert_eq!(tracker.missing_total(), 4);
        assert_eq!(tracker.expected(), 6);
    }

    /// 负向：gap 说明与实际跳变对不上（起点不接 / 终点不接）一律判红。
    ///
    /// 少了这一条，"带 gap 就放行"会退化成"随便带个 gap 就能把任意跳变洗白"。
    #[test]
    fn a_gap_that_does_not_line_up_is_rejected() {
        // 起点不接：期待 1，gap 从 2 开始。
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));
        let wrong_start = SequenceGap {
            from_seq: 2,
            through_seq: 4,
            cause: GapCause::Dropped,
        };
        assert!(matches!(
            tracker.observe(&event_frame(5, Some(wrong_start))),
            Err(SequenceError::InconsistentGap { .. })
        ));

        // 终点不接：gap 到 3 结束，下一帧却是 5。
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));
        let wrong_end = SequenceGap {
            from_seq: 1,
            through_seq: 3,
            cause: GapCause::Dropped,
        };
        assert!(matches!(
            tracker.observe(&event_frame(5, Some(wrong_end))),
            Err(SequenceError::InconsistentGap { .. })
        ));
    }

    /// 负向：序号倒退 / 重复。
    #[test]
    fn a_repeated_or_backwards_seq_is_rejected() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));
        assert_eq!(tracker.observe(&event_frame(1, None)), Ok(()));
        assert_eq!(
            tracker.observe(&event_frame(1, None)),
            Err(SequenceError::NotMonotonic {
                expected: 2,
                observed: 1
            })
        );
    }

    /// 终止帧同样占一个序号，也同样可以捎带 gap。
    #[test]
    fn a_terminal_frame_participates_in_the_sequence() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(&event_frame(0, None)), Ok(()));

        let gap = SequenceGap {
            from_seq: 1,
            through_seq: 2,
            cause: GapCause::Dropped,
        };
        let terminal = AppEventRef::for_test(
            3,
            Some(gap),
            FramePayload::Terminal(DisconnectReason::QueueOverflow {
                class: DeliveryClass::Critical,
            }),
        );
        assert_eq!(tracker.observe(&terminal), Ok(()));
        assert_eq!(tracker.missing_total(), 2);
    }
}
