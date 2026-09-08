//! 队列预算与投递等级 —— v3 §13.2 的两段规定，逐条落成常量与一个封闭分类函数。
//!
//! # 五个默认值，一个都不改
//!
//! §13.2 原文：「默认队列：command 256；每窗口 critical event ref 256；token delta 每
//! 50 ms/8 KiB 合并；progress/presence 使用 latest-value；shutdown deadline 5 秒。」
//!
//! 这五个数在本 crate 里各有**一个**具名落点（第五个在 [`crate::cancel::SHUTDOWN_DEADLINE`]）。
//! 具名的理由不是可读性，是可复算：
//! `grep -c '^pub const CRITICAL_EVENT_QUEUE_CAPACITY' src/budget.rs` = 1
//! 能一条命令回答「代码里那个 256 还是不是方案里那个 256」。行首锚点是必须的 ——
//! 不加它，本行自己也会被数进去（复算不上的计数不如不写）。
//!
//! # 投递等级不是注释，是封闭 match
//!
//! [`delivery_class`] 对 [`AppEvent`] 做穷举 match、无通配分支。G1 只有一个事件变体，
//! 但这个函数现在就必须立住：新增事件时**忘记给它定投递等级会编译失败**，而不是默默
//! 落进某个 `_ =>` 的默认档。默认档正是「terminal 被当成 progress 静默丢掉」这类事故的
//! 唯一入口。

use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use openbot_contracts::command::AppEvent;

/// command 通道的并发预算。
///
/// **§13.2 逐字**：「默认队列：command 256」。
///
/// # 直连调用怎么会有"队列"
///
/// §13.2 同时规定「普通 request 直接 typed 调用」—— 直连调用没有队列对象。这个数在
/// in-process 通道上的等价物是**同时在飞的 command 数上限**：
/// [`crate::transport::InProcessTransport`] 用一个 256 permit 的信号量守着
/// [`crate::transport::InProcessTransport::execute`]，第 257 个调用等待而不是并发下去。
///
/// 两者的可观察后果相同：生产侧被反压，而不是让 renderer 一次点 5000 下就在
/// application 层堆出 5000 个并发 use case。刻意选**等待**而不是**报错**：命令是
/// 用户动作，丢掉一次点击没有正确的用户可见语义；事件流那边才是「满即显式断开」
/// （见 [`DeliveryClass::Critical`]）。
pub const COMMAND_QUEUE_CAPACITY: usize = 256;

/// 每窗口事件队列的**可用**容量。
///
/// **§13.2 逐字**：「每窗口 critical event ref 256」。
///
/// 底层 `mpsc` 建成 `CRITICAL_EVENT_QUEUE_CAPACITY + TERMINAL_FRAME_RESERVE`，多出来的
/// 那一格永久留给终止帧（理由见 [`crate::event::TERMINAL_FRAME_RESERVE`]）。所以
/// **可投递的事件帧上限逐字是 256**，与方案一致。
pub const CRITICAL_EVENT_QUEUE_CAPACITY: usize = 256;

/// One shared queued-event-ref budget.
///
/// Ordinary broker windows own one instance. Structured Desktop subscriptions that belong to the
/// same actual Webview deliberately share one instance, so opening a second Tauri Channel cannot
/// multiply §13.2's per-window 256-frame allowance.
#[derive(Debug)]
pub(crate) struct EventQueueBudget {
    capacity: usize,
    in_use: AtomicUsize,
}

impl EventQueueBudget {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            in_use: AtomicUsize::new(0),
        }
    }

    pub(crate) fn spec_window() -> Self {
        Self::new(CRITICAL_EVENT_QUEUE_CAPACITY)
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<Arc<EventQueuePermit>> {
        let mut current = self.in_use.load(Ordering::Acquire);
        loop {
            if current >= self.capacity {
                return None;
            }
            match self.in_use.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Arc::new(EventQueuePermit {
                        budget: Arc::clone(self),
                    }));
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity
            .saturating_sub(self.in_use.load(Ordering::Acquire))
    }
}

/// A queued event's share of [`EventQueueBudget`]. Clones of the enclosing frame share this guard;
/// only the final frame clone releases the slot.
#[derive(Debug)]
pub(crate) struct EventQueuePermit {
    budget: Arc<EventQueueBudget>,
}

impl Drop for EventQueuePermit {
    fn drop(&mut self) {
        let released =
            self.budget
                .in_use
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
        debug_assert!(released.is_ok(), "event queue permit underflow");
    }
}

/// token delta 的合并时间窗。
///
/// **§13.2 逐字**：「token delta 每 50 ms/8 KiB 合并」。
///
/// # G1 没有消费者，这是刻意的
///
/// 合并 delta 要求有一个**不改变最终文本**的拼接函数，而 G1 的 [`AppEvent`] 里还没有
/// 任何带文本的变体（thread 订阅是 G3）。没有拼接函数就去丢 delta 会直接违反 §13.2 的
/// 「可合并，**不改变最终文本**」—— 所以 G1 对
/// [`DeliveryClass::Coalescable`] 采取的是 fail-closed：队列满即显式断开，绝不静默丢。
///
/// 常量先立在这里，是为了让 G3 接合并器时有唯一落点，而不是各自现编一个 50。
pub const TOKEN_DELTA_COALESCE_WINDOW: Duration = Duration::from_millis(50);

/// token delta 的合并字节窗。**§13.2 逐字**：「token delta 每 50 ms/8 KiB 合并」。
///
/// 消费者情况同 [`TOKEN_DELTA_COALESCE_WINDOW`]。
pub const TOKEN_DELTA_COALESCE_BYTES: usize = 8 * 1024;

/// 投递等级 —— §13.2 的四档，封闭 enum。
///
/// 队列满时每一档的行为不同，这正是它必须是类型而不是布尔的原因：
/// 「可不可以丢」有四个答案，不是两个。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliveryClass {
    /// terminal、approval、policy decision、server request。
    ///
    /// **§13.2 逐字**：「不可静默丢；队列满即显式断开/失败，客户端从 durable cursor
    /// replay」。本 crate 的实现是：队列满 → 投一帧终止帧（走保留格）→ 关闭该窗口路由。
    /// 客户端于是拿到一个**明确的**「你的流断在这里」，而不是一段安静的空白。
    Critical,

    /// text / reasoning delta。
    ///
    /// **§13.2 逐字**：「可合并，不改变最终文本」。G1 没有可合并的载荷，所以此档暂按
    /// [`Self::Critical`] 一样 fail-closed（理由见 [`TOKEN_DELTA_COALESCE_WINDOW`]）。
    /// 「可以合并」是一项**许可**，不是义务；在没有合并函数的时候行使它就是丢字。
    Coalescable,

    /// progress / presence。**§13.2 逐字**：「latest-value」。
    ///
    /// 队列满时新帧进待发槽并**取代**槽里更旧的一帧，被取代的序号记进
    /// [`crate::event::SequenceGap`]。取代的是**旧值**不是新值 —— 反过来（丢新留旧）
    /// 会让 GUI 停在一个越来越陈旧的进度条上，那恰恰是 latest-value 要避免的。
    LatestValue,

    /// screen 帧。**§13.2 / §13.4**：独立 binary channel、latest-frame。
    ///
    /// # 它在本通道上是**错误**，不是一档待实现的行为
    ///
    /// §13.4 逐字规定持续画面走 loopback binary WebSocket，「Tauri Channel 只承载结构化
    /// Agent/tool/policy 事件」。所以一个 screen 等级的事件出现在这条通道上，唯一正确的
    /// 反应是拒绝（[`crate::broker::PublishRejected::ScreenMustNotUseTheEventChannel`]），
    /// 而不是"先凑合发着"。
    ///
    /// G1 的 [`delivery_class`] 不会返回它 —— 它此刻的作用是：G7 加
    /// `AppEvent::ScreenFrame` 时，分类函数必须给出一个答案，给出 `Screen` 就会被 broker
    /// 当场拒掉，于是"另建 binary channel"这件事没法被跳过。
    Screen,
}

/// 把一个 [`AppEvent`] 映射到它的投递等级。
///
/// **穷举 match、无通配分支**：新增事件变体会在这里编译失败。这是本函数存在的全部理由
/// —— 它不是一张查找表，是一道编译期的强制分类。
///
/// # Heartbeat 是 `LatestValue`，durable thread frame 是 `Critical`
///
/// 判据不是"心跳听起来不重要"，是两条可查的事实：
///
/// 1. §13.2 把 latest-value 档定义为 **progress / presence**，而心跳逐字就是 presence
///    ——「我还活着」这句话只有最新的那一遍有意义，补发过去的十遍没有任何信息量。
/// 2. `openbot_contracts::command::AppEvent::Heartbeat` 的字段文档原文写着「`seq` 单调
///    递增，供 viewer 判断是否**丢帧**」。契约里已经写明这条流的帧**是可以丢的**，
///    并且给了 viewer 判丢的手段。把它归进 `Critical`（丢一帧就断开整条流）会直接和
///    那句话矛盾。
#[must_use]
pub const fn delivery_class(event: &AppEvent) -> DeliveryClass {
    match event {
        AppEvent::Heartbeat { .. } => DeliveryClass::LatestValue,
        // Thread durable event 与显式 stream error 不能在 broker 内静默丢弃；thread 断开后
        // 用 cursor replay。Channel activity 自身不是 durable 真源，但漏一帧会让 roster UI
        // 暂时陈旧，所以同样断开；GUI 重连时从 PostgreSQL roster 全量 refetch。
        AppEvent::ThreadRunEvent(_)
        | AppEvent::ThreadStreamError { .. }
        | AppEvent::ChannelActivity(_)
        | AppEvent::ChannelStreamError { .. }
        | AppEvent::ToolApprovalActivity(_)
        | AppEvent::ToolApprovalStreamError { .. } => DeliveryClass::Critical,
    }
}

impl DeliveryClass {
    /// 队列满时**是否允许丢弃或取代**本帧。
    ///
    /// 只有 [`Self::LatestValue`] 为真。[`Self::Coalescable`] 在有合并函数之前为假
    /// （理由见该变体文档）。
    #[must_use]
    pub const fn may_shed_under_pressure(self) -> bool {
        match self {
            Self::LatestValue => true,
            Self::Critical | Self::Coalescable | Self::Screen => false,
        }
    }

    /// 稳定的低基数标签名，用于 metric 与受控 trace（§16.4：label 基数必须有界）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Coalescable => "coalescable",
            Self::LatestValue => "latest_value",
            Self::Screen => "screen",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 五个默认值逐字等于 §13.2。改动其一必须先改方案。
    #[test]
    fn the_five_defaults_are_verbatim_from_the_spec() {
        assert_eq!(COMMAND_QUEUE_CAPACITY, 256);
        assert_eq!(CRITICAL_EVENT_QUEUE_CAPACITY, 256);
        assert_eq!(TOKEN_DELTA_COALESCE_WINDOW, Duration::from_millis(50));
        assert_eq!(TOKEN_DELTA_COALESCE_BYTES, 8 * 1024);
        // 第五个（shutdown deadline 5 秒）在 `cancel` 模块，由那边的测试钉住。
        assert_eq!(crate::cancel::SHUTDOWN_DEADLINE, Duration::from_secs(5));
    }

    #[test]
    fn shared_event_budget_releases_only_after_the_last_frame_clone_drops() {
        let budget = Arc::new(EventQueueBudget::new(2));
        let first = budget.try_acquire().expect("first slot");
        let first_clone = Arc::clone(&first);
        let second = budget.try_acquire().expect("second slot");
        assert_eq!(budget.remaining(), 0);
        assert!(budget.try_acquire().is_none());

        drop(first);
        assert_eq!(budget.remaining(), 0, "one frame clone still owns the slot");
        drop(first_clone);
        assert_eq!(budget.remaining(), 1);
        drop(second);
        assert_eq!(budget.remaining(), 2);
    }

    /// 心跳是 presence ⇒ latest-value。
    #[test]
    fn heartbeat_is_presence_and_therefore_latest_value() {
        assert_eq!(
            delivery_class(&AppEvent::Heartbeat { seq: 0 }),
            DeliveryClass::LatestValue
        );
        // seq 不参与分类：分类看的是事件**种类**，不是取值。
        assert_eq!(
            delivery_class(&AppEvent::Heartbeat { seq: u64::MAX }),
            DeliveryClass::LatestValue
        );
    }

    #[test]
    fn durable_thread_frames_are_critical_and_never_silently_shed() {
        assert_eq!(
            delivery_class(&AppEvent::ThreadStreamError {
                code: "not_visible".to_owned(),
            }),
            DeliveryClass::Critical
        );
        assert!(!DeliveryClass::Critical.may_shed_under_pressure());
    }

    #[test]
    fn channel_activity_is_critical_so_pressure_forces_reconnect_and_roster_refetch() {
        assert_eq!(
            delivery_class(&AppEvent::ChannelActivity(
                openbot_contracts::command::ChannelActivityEvent {
                    channel_id: openbot_contracts::ids::ChannelId::new("channel-1"),
                    last_message: Some("hello".to_owned()),
                    last_message_at: Some(time::OffsetDateTime::UNIX_EPOCH),
                    last_message_agent_id: None,
                },
            )),
            DeliveryClass::Critical
        );
        assert_eq!(
            delivery_class(&AppEvent::ChannelStreamError {
                code: "dependency_unavailable".to_owned(),
            }),
            DeliveryClass::Critical
        );
    }

    #[test]
    fn approval_activity_is_critical_so_pressure_forces_reconnect_and_durable_refetch() {
        assert_eq!(
            delivery_class(&AppEvent::ToolApprovalActivity(
                openbot_contracts::tool::ToolApprovalActivityEvent { pending_count: 1 },
            )),
            DeliveryClass::Critical
        );
        assert_eq!(
            delivery_class(&AppEvent::ToolApprovalStreamError {
                code: "dependency_unavailable".to_owned(),
            }),
            DeliveryClass::Critical
        );
    }

    /// 「可丢」这条判据在四档上各给一个答案，而且不是恒真也不是恒假。
    ///
    /// 正向 + 负向成对：没有下面这两句，`may_shed_under_pressure` 可以恒返回 false 而
    /// 上面的断言照样绿。
    #[test]
    fn only_latest_value_may_be_shed() {
        assert!(DeliveryClass::LatestValue.may_shed_under_pressure());
        assert!(!DeliveryClass::Critical.may_shed_under_pressure());
        assert!(!DeliveryClass::Coalescable.may_shed_under_pressure());
        assert!(!DeliveryClass::Screen.may_shed_under_pressure());
    }

    /// label 取值封闭且互不相同 —— metric label 的基数必须有界（§16.4）。
    #[test]
    fn class_labels_are_closed_and_distinct() {
        let labels = [
            DeliveryClass::Critical.as_str(),
            DeliveryClass::Coalescable.as_str(),
            DeliveryClass::LatestValue.as_str(),
            DeliveryClass::Screen.as_str(),
        ];
        let mut sorted = labels;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), labels.len(), "投递等级 label 不得重名");
    }

    /// 结构化事件分类函数**不会**返回 `Screen`。
    ///
    /// 这条不是废话：它是「screen 走另一条通道」在 G1 的可判定形式。正向对照在同一条
    /// 里 —— 该函数确实会返回某个等级（否则本断言在"函数不可调用"的世界里也成立）。
    #[test]
    fn structured_events_never_classify_as_screen() {
        let class = delivery_class(&AppEvent::Heartbeat { seq: 1 });
        assert_ne!(class, DeliveryClass::Screen);
        assert_eq!(class, DeliveryClass::LatestValue);
    }
}
