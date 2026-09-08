//! 窗口身份与可见性范围 —— v3 §13.3 的四个过滤维度，做成类型而不是注释。
//!
//! §13.3 逐字：「一个 native broker 可以服务多个窗口，但 Rust 按 window label、actor、
//! thread subscription 和 auth generation 过滤。window A 永远收不到 window B 的私有
//! thread、screen ticket 或 approval；**过滤不能由前端自行完成**。」
//!
//! # 类型怎么承载这条
//!
//! 三个构造性约束叠起来，缺任一条都会退回"靠复核"：
//!
//! 1. [`WindowIdentity`] **只能**由一个已存在的 `AuthContext` 绑定而来
//!    （[`WindowIdentity::bind`]），字段全部私有、只读。于是不存在"renderer 自报自己是
//!    哪个 actor"这条路 —— 那正是 §5.2 逐字禁止的形态。
//! 2. 事件在铸造时就必须交出一个 [`EventScope`]（[`crate::event::BrokerEvent::new`] 的
//!    必填参数），没有"先发出去再想给谁看"的中间态。
//! 3. 判定唯一入口是 [`EventScope::admits`]，返回 `Result<(), FilterReason>`。它在
//!    [`crate::broker::EventBroker`] 里被调用，**发生在把帧交给任何 channel 之前**；
//!    前端拿到的 `mpsc::Receiver` 里已经不含别人的帧。
//!
//! # 租户是最外层
//!
//! [`EventScope`] 是「租户 + 目标」而不是单独的目标枚举。依据是 §17.2 条 12「任一跨
//! scope 数据 / 帧 / 凭据泄漏是 P0」与 `TenantId` 的类型文档「一切 scope 判定的最外层」。
//! 把租户做成 scope 的固有部分，「忘了比租户」就不再是一种可能的写法。

use std::collections::BTreeSet;

use core::fmt;

use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};

/// 窗口标签 —— 宿主给每个窗口的进程内唯一名字（Tauri 的 `WebviewWindow::label()`）。
///
/// # 它**不是**第 16 个核心 ID
///
/// §5.3 把核心 ID 的集合固定为十五个，本类型不在其中，也刻意不放进
/// `openbot-contracts`：它是**transport 作用域**的标识符，进程重启即失效，永远不落库、
/// 不跨进程、不进任何 DTO。放进 contracts 会让它看起来像一个可以被序列化来去的身份，
/// 而那正是我们不希望前端拿到的东西。
///
/// 与 ID newtype 一样**不做任何格式校验**：宿主给什么就是什么，我们只要求它在一个
/// broker 内唯一（由 [`crate::broker::EventBroker::open_window`] 拒绝重名兑现）。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowLabel(String);

impl WindowLabel {
    /// 由宿主给出的标签构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for WindowLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// 一个窗口的权威身份。
///
/// 字段私有 + 唯一构造入口 [`Self::bind`]，所以持有一个 `WindowIdentity` 就等于持有
/// 「这个窗口背后有一次已完成的认证」这条证据。本 crate **不铸造** `AuthContext`
/// （见 crate 文档〈认证：G1 刻意没有〉）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowIdentity {
    label: WindowLabel,
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    auth_generation: AuthGeneration,
}

impl WindowIdentity {
    /// 把一个窗口标签绑到一次**已认证**的上下文上。
    ///
    /// 刻意只取需要的四项而不是持有整个 `AuthContext`：角色集合与 `single_user` 是
    /// **授权**输入，属于 application 的判定面；transport 只需要"这帧该不该进这个窗口"
    /// 所需的定址信息。少拿一样，就少一样可能被 transport 顺手拿去做业务判定的东西。
    #[must_use]
    pub fn bind(label: WindowLabel, auth: &AuthContext) -> Self {
        Self {
            label,
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
        }
    }

    /// 窗口标签。
    #[must_use]
    pub fn label(&self) -> &WindowLabel {
        &self.label
    }

    /// 部署身份。
    #[must_use]
    pub fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// 租户身份。
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// 行动者身份。
    #[must_use]
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 绑定时刻的 auth generation。
    ///
    /// 它**不会**随后台的代际推进自动更新：一个窗口的身份是它认证那一刻的快照。
    /// 代际推进之后这个窗口就是陈旧的，于是 [`EventScope::admits`] 会把所有新帧挡在
    /// 外面（[`FilterReason::StaleAuthGeneration`]），直到 G2 的 session 层把它重建。
    #[must_use]
    pub fn auth_generation(&self) -> u64 {
        self.auth_generation.get()
    }
}

/// 一个窗口当前订阅的 thread 集合 —— §13.3 的第三个过滤维度。
///
/// 空集是**默认**且是最安全的默认：没订阅就一条 thread 事件都收不到。这与
/// 「deny 优先；空 / 坏 / 未知 fail-closed」（§17.2 条 3）同向。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadSubscriptions {
    threads: BTreeSet<ThreadId>,
}

impl ThreadSubscriptions {
    /// 空订阅集。
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// 由一组 thread 构造。
    #[must_use]
    pub fn from_threads(threads: impl IntoIterator<Item = ThreadId>) -> Self {
        Self {
            threads: threads.into_iter().collect(),
        }
    }

    /// 是否订阅了某条 thread。
    #[must_use]
    pub fn contains(&self, thread: &ThreadId) -> bool {
        self.threads.contains(thread)
    }

    /// 订阅数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// 是否一条都没订阅。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

/// 事件的可见性目标 —— §13.3 的前三个维度（label / actor / thread 订阅）。
///
/// 封闭 enum：新增一种定址方式必须来这里加一个变体，而加变体会让
/// [`EventScope::admits`] 的 match 编译失败，逼作者当场写出它的准入判据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeTarget {
    /// 只发给某一个窗口。
    ///
    /// 用于窗口私有的东西：绑定窗口的审批提示、screen ticket、该窗口自己的订阅流。
    Window(WindowLabel),

    /// 发给某个 actor 的**全部**窗口。
    ///
    /// 用于账号级的事情：配额变化、全局通知。注意它仍然受租户与代际两道门约束。
    Actor(ActorId),

    /// 发给某个 actor 中**订阅了该 thread** 的窗口。
    ///
    /// # G1 没有生产者，这是刻意的
    ///
    /// thread 订阅是 G3 的工作（`SubscriptionRequest` 目前只有 `Health` 一项）。它现在
    /// 就立在这里，是因为 §13.3 把 thread 订阅逐字列为四个过滤维度之一：一个只实现了
    /// 三个维度的过滤器，会在 G3 被人以"顺手加个字段"的方式补第四个，而那时没有任何
    /// 闸门会问"这个维度的准入判据是什么"。变体在此，判据就必须在 [`EventScope::admits`]
    /// 里，且由本模块的测试覆盖。
    Thread {
        /// thread 的所属 actor。
        actor: ActorId,
        /// thread 身份。
        thread: ThreadId,
    },
}

/// 事件的可见性范围 = **租户 + 目标**。
///
/// 租户单列而不是塞进各个变体：它是最外层判据（§17.2 条 12），必须在每一条路径上都被
/// 比对。做成结构体的固有字段之后，"某个变体忘了比租户"这种写法在类型上就不存在。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventScope {
    tenant: TenantId,
    target: ScopeTarget,
}

impl EventScope {
    /// 只发给一个窗口。
    #[must_use]
    pub fn window(tenant: TenantId, label: WindowLabel) -> Self {
        Self {
            tenant,
            target: ScopeTarget::Window(label),
        }
    }

    /// 发给某 actor 的全部窗口。
    #[must_use]
    pub fn actor(tenant: TenantId, actor: ActorId) -> Self {
        Self {
            tenant,
            target: ScopeTarget::Actor(actor),
        }
    }

    /// 发给订阅了某条 thread 的窗口（G3 起有生产者，见 [`ScopeTarget::Thread`]）。
    #[must_use]
    pub fn thread(tenant: TenantId, actor: ActorId, thread: ThreadId) -> Self {
        Self {
            tenant,
            target: ScopeTarget::Thread { actor, thread },
        }
    }

    /// 租户。
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// 目标。
    #[must_use]
    pub fn target(&self) -> &ScopeTarget {
        &self.target
    }

    /// 判定一帧是否可以进入某个窗口 —— §13.3 的四个维度在这一个函数里全部走到。
    ///
    /// 顺序是**租户 → 代际 → 目标**，不是随意排的：前两道是与目标种类无关的外层门，
    /// 放在前面能保证任何一种新增的 [`ScopeTarget`] 都自动受它们约束。
    ///
    /// # Errors
    ///
    /// 不准入时返回具体的 [`FilterReason`]。刻意返回原因而不是 `bool`：metric 需要知道
    /// 「被挡下来是因为陈旧代际还是因为不是这个 actor」，这两件事的运维含义完全不同。
    pub fn admits(
        &self,
        window: &WindowIdentity,
        subscriptions: &ThreadSubscriptions,
        event_auth_generation: u64,
    ) -> Result<(), FilterReason> {
        if window.tenant() != &self.tenant {
            return Err(FilterReason::TenantMismatch);
        }
        if window.auth_generation() != event_auth_generation {
            return Err(FilterReason::StaleAuthGeneration);
        }
        match &self.target {
            ScopeTarget::Window(label) => {
                if window.label() == label {
                    Ok(())
                } else {
                    Err(FilterReason::WindowMismatch)
                }
            }
            ScopeTarget::Actor(actor) => {
                if window.actor() == actor {
                    Ok(())
                } else {
                    Err(FilterReason::ActorMismatch)
                }
            }
            ScopeTarget::Thread { actor, thread } => {
                if window.actor() != actor {
                    return Err(FilterReason::ActorMismatch);
                }
                if subscriptions.contains(thread) {
                    Ok(())
                } else {
                    Err(FilterReason::NotSubscribed)
                }
            }
        }
    }
}

/// 一帧被挡在窗口之外的原因。
///
/// **被过滤不是丢帧**：这帧本来就不属于这个窗口，所以它既不产生 sequence gap，也不占
/// 这个窗口的序号。把过滤计进丢帧率会让"跨窗口流量"变成一个可观测的旁路信道 ——
/// 窗口 A 能从自己的序号跳变里推断窗口 B 收了多少帧，那本身就是一次跨 scope 泄漏。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilterReason {
    /// 租户不同（§17.2 条 12 的最外层门）。
    TenantMismatch,
    /// 窗口的 auth generation 与事件铸造时的代际不同（§17.2 条 6）。
    StaleAuthGeneration,
    /// 事件定向到另一个窗口。
    WindowMismatch,
    /// 事件定向到另一个 actor。
    ActorMismatch,
    /// 事件定向到一条本窗口没有订阅的 thread。
    NotSubscribed,
}

impl FilterReason {
    /// 稳定的低基数标签名（§16.4：metric label 基数必须有界）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantMismatch => "tenant_mismatch",
            Self::StaleAuthGeneration => "stale_auth_generation",
            Self::WindowMismatch => "window_mismatch",
            Self::ActorMismatch => "actor_mismatch",
            Self::NotSubscribed => "not_subscribed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{auth_for, auth_with, tenant};

    fn window(label: &str, actor: &str) -> WindowIdentity {
        WindowIdentity::bind(WindowLabel::new(label), &auth_for(actor))
    }

    #[test]
    fn identity_is_a_projection_of_a_verified_auth_context() {
        let auth = auth_for("actor-1");
        let identity = WindowIdentity::bind(WindowLabel::new("main"), &auth);

        assert_eq!(identity.label().as_str(), "main");
        assert_eq!(identity.deployment(), auth.deployment());
        assert_eq!(identity.tenant(), auth.tenant());
        assert_eq!(identity.actor(), auth.actor());
        assert_eq!(identity.auth_generation(), auth.auth_generation().get());
    }

    /// 正向对照：定向到本窗口 / 本 actor 的帧确实进得来。
    ///
    /// 下面所有"收不到"的断言都靠它才有意义 —— 没有它，那些断言在
    /// 「`admits` 恒返回 Err」的世界里同样通过。
    #[test]
    fn a_window_receives_what_is_addressed_to_it() {
        let a = window("a", "actor-1");
        let subs = ThreadSubscriptions::none();

        let to_window = EventScope::window(tenant(), WindowLabel::new("a"));
        assert_eq!(to_window.admits(&a, &subs, a.auth_generation()), Ok(()));

        let to_actor = EventScope::actor(tenant(), ActorId::new("actor-1"));
        assert_eq!(to_actor.admits(&a, &subs, a.auth_generation()), Ok(()));
    }

    /// 负向：window A 收不到 window B 的私有帧（§13.3 逐字）。
    #[test]
    fn window_a_never_sees_window_b_private_frames() {
        let a = window("a", "actor-1");
        let subs = ThreadSubscriptions::none();

        let to_b = EventScope::window(tenant(), WindowLabel::new("b"));
        assert_eq!(
            to_b.admits(&a, &subs, a.auth_generation()),
            Err(FilterReason::WindowMismatch)
        );
    }

    /// 负向：同租户、同代际，但换一个 actor 就收不到。
    #[test]
    fn another_actors_frames_are_filtered() {
        let a = window("a", "actor-1");
        let subs = ThreadSubscriptions::none();

        let to_other = EventScope::actor(tenant(), ActorId::new("actor-2"));
        assert_eq!(
            to_other.admits(&a, &subs, a.auth_generation()),
            Err(FilterReason::ActorMismatch)
        );
    }

    /// 负向：**同一个 actor id** 落在另一个租户上照样收不到（§17.2 条 12）。
    ///
    /// 这条单列，是因为它是最容易被"反正 actor id 全局唯一"这句话绕过去的一条。
    #[test]
    fn the_same_actor_id_in_another_tenant_is_still_filtered() {
        let a = window("a", "actor-1");
        let subs = ThreadSubscriptions::none();

        let other_tenant =
            EventScope::actor(TenantId::new("tenant-other"), ActorId::new("actor-1"));
        assert_eq!(
            other_tenant.admits(&a, &subs, a.auth_generation()),
            Err(FilterReason::TenantMismatch)
        );
    }

    /// 代际两个方向都挡：陈旧的收不到，**更新的也收不到**。
    ///
    /// 更新的那一支不是多余：窗口身份是认证那一刻的快照，代际推进之后这个窗口就该被
    /// 重建而不是继续接新帧（§17.2 条 6）。fail-closed 的写法是严格相等。
    #[test]
    fn auth_generation_must_match_exactly_in_both_directions() {
        let auth = auth_with("actor-1", 7);
        let a = WindowIdentity::bind(WindowLabel::new("a"), &auth);
        let subs = ThreadSubscriptions::none();
        let scope = EventScope::actor(tenant(), ActorId::new("actor-1"));

        assert_eq!(
            scope.admits(&a, &subs, 6),
            Err(FilterReason::StaleAuthGeneration)
        );
        assert_eq!(
            scope.admits(&a, &subs, 8),
            Err(FilterReason::StaleAuthGeneration)
        );
        // 正向对照：相等就放行。
        assert_eq!(scope.admits(&a, &subs, 7), Ok(()));
    }

    /// thread 维度：没订阅就收不到；订阅了才收得到。
    #[test]
    fn thread_frames_need_a_subscription() {
        let a = window("a", "actor-1");
        let thread = ThreadId::new("thread-1");
        let scope = EventScope::thread(tenant(), ActorId::new("actor-1"), thread.clone());

        let none = ThreadSubscriptions::none();
        assert!(none.is_empty());
        assert_eq!(
            scope.admits(&a, &none, a.auth_generation()),
            Err(FilterReason::NotSubscribed)
        );

        // 订阅了别的 thread 也不行。
        let other = ThreadSubscriptions::from_threads([ThreadId::new("thread-2")]);
        assert_eq!(other.len(), 1);
        assert_eq!(
            scope.admits(&a, &other, a.auth_generation()),
            Err(FilterReason::NotSubscribed)
        );

        // 正向对照：订阅了就放行。
        let subscribed = ThreadSubscriptions::from_threads([thread]);
        assert_eq!(scope.admits(&a, &subscribed, a.auth_generation()), Ok(()));
    }

    /// thread 事件的 actor 门在订阅门**之前**：别人的 thread 就算我订阅了同名 id 也不行。
    #[test]
    fn a_thread_subscription_cannot_reach_across_actors() {
        let a = window("a", "actor-1");
        let thread = ThreadId::new("thread-1");
        let subscribed = ThreadSubscriptions::from_threads([thread.clone()]);
        let scope = EventScope::thread(tenant(), ActorId::new("actor-2"), thread);

        assert_eq!(
            scope.admits(&a, &subscribed, a.auth_generation()),
            Err(FilterReason::ActorMismatch)
        );
    }

    #[test]
    fn filter_reason_labels_are_closed_and_distinct() {
        let labels = [
            FilterReason::TenantMismatch.as_str(),
            FilterReason::StaleAuthGeneration.as_str(),
            FilterReason::WindowMismatch.as_str(),
            FilterReason::ActorMismatch.as_str(),
            FilterReason::NotSubscribed.as_str(),
        ];
        let mut deduped = labels.to_vec();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), labels.len());
    }

    #[test]
    fn window_label_keeps_the_host_string_verbatim() {
        let label = WindowLabel::new("设置窗口-2");
        assert_eq!(label.as_str(), "设置窗口-2");
        assert_eq!(label.to_string(), "设置窗口-2");
    }
}
