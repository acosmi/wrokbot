//! typed in-process transport —— v3 §13.2「Tauri `setup` 创建一个
//! `Arc<dyn ApplicationService>`。普通 request 直接 typed 调用，server request/stream
//! 使用有界 channel」。
//!
//! # 它做的四件事，以及它**不**做的那一件
//!
//! §5.2 给 transport 的活恰好四样：认证、framing、输入大小限制、错误映射。本类型逐条对应：
//!
//! | transport 职责 | 在这里的形态 |
//! | --- | --- |
//! | 认证 | 不在 G1（见 crate 文档）。身份以 `AuthContext` 的形式**传入**，本 crate 不铸造 |
//! | framing | [`crate::event::AppEventRef`]：序号、gap 说明、终止帧 |
//! | 输入大小限制 | 有界队列（每窗口 256）与 command 并发预算（256） |
//! | 错误映射 | in-process 的映射是**恒等**：`AppError` 原样穿过（理由见 [`InProcessTransport::execute`]） |
//!
//! **不做的那一件是业务判定**（§5.2 逐字禁止）。可判定形式：本模块里没有一处 `match` 是
//! 在看 [`AppCommand`] 的变体，也没有一处在看 [`AppReply`] 的内容 —— 命令原样递给
//! [`ApplicationService::execute`]，应答原样返回。`in_process_execute_equals_a_direct_service_call`
//! 把这条钉成"经 transport 与直连 service 的结果逐字段相等"。
//!
//! # 「不复制 JSON-RPC」是构造性的
//!
//! §13.2 的标题就是「typed in-process，不复制 JSON-RPC」。[`InProcessTransport`] 本身不
//! 引用任何 codec，命令逐类型直接进入 service。G6 的 opt-in `tauri-host` custom protocol
//! 必须为 WebView HTTP framing 使用 serde_json，但它在本模块之外且依赖全为 optional；由
//! `the_in_process_lane_has_no_json_codec` 同时扫源码与 feature 边界。

use std::sync::{Arc, Mutex};
use std::time::Instant;

use core::time::Duration;

use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppEvent, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::telemetry::Transport;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::broker::{DeliveryOutcome, EventBroker, WindowAlreadyOpen};
use crate::budget::{COMMAND_QUEUE_CAPACITY, EventQueueBudget};
use crate::cancel::{CancellationToken, SHUTDOWN_DEADLINE};
use crate::event::BrokerEvent;
use crate::session::DesktopSession;
use crate::window::{EventScope, ThreadSubscriptions, WindowIdentity, WindowLabel};

/// 打开一条窗口会话失败。
#[derive(Debug, thiserror::Error)]
pub enum OpenSessionError {
    /// application 拒绝了这次订阅（未登录 / 不可见 / 依赖不可用……）。
    ///
    /// **原样上抛**：transport 不改写业务判定的结果，也不替它决定该给用户看什么
    /// （文案由 GUI 按 code 本地化，§15.3）。
    #[error(transparent)]
    Application(#[from] AppError),

    /// 该窗口标签在本 broker 内已存在（见 [`WindowAlreadyOpen`]）。
    #[error(transparent)]
    WindowAlreadyOpen(#[from] WindowAlreadyOpen),

    /// transport 正在关停。
    #[error("shutting_down")]
    ShuttingDown,
}

/// 一次关停的结果（§13.2「shutdown deadline 5 秒」）。
///
/// 它是**报告**不是日志：`within_deadline` 为假意味着有事件泵没能在 5 秒内停下、
/// 被强制 abort —— 那是一条需要有人去看的事实，不该只留在一行 warn 里。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    /// 被关掉的窗口数。
    pub windows_closed: usize,
    /// 关停时在跑的事件泵总数。
    pub pumps_total: usize,
    /// 在 deadline 内自行停下的事件泵数。
    pub pumps_joined: usize,
    /// 超过 deadline 被 abort 的事件泵数。
    pub pumps_aborted: usize,
    /// 实际耗时。
    pub elapsed: Duration,
    /// 是否在 [`SHUTDOWN_DEADLINE`] 内干净停住（没有任何 abort）。
    pub within_deadline: bool,
}

/// 把一个 [`ApplicationService`] 包成 Desktop 的 in-process 通道。
///
/// 一个进程一个实例（Tauri 的 `setup` 里建，放进 managed state），服务全部窗口。
pub struct InProcessTransport {
    service: Arc<dyn ApplicationService>,
    broker: Arc<EventBroker>,
    commands: Semaphore,
    pumps: Mutex<Vec<PumpHandle>>,
}

struct PumpHandle {
    label: WindowLabel,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

impl InProcessTransport {
    /// 用一个新的取消信号包起来。
    #[must_use]
    pub fn new(service: Arc<dyn ApplicationService>) -> Self {
        Self::with_shutdown(service, CancellationToken::new())
    }

    /// 用调用方给定的取消信号包起来（宿主已有一个全局关停信号时用这个）。
    #[must_use]
    pub fn with_shutdown(
        service: Arc<dyn ApplicationService>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            service,
            broker: Arc::new(EventBroker::new(shutdown)),
            commands: Semaphore::new(COMMAND_QUEUE_CAPACITY),
            pumps: Mutex::new(Vec::new()),
        }
    }

    /// 底下那个 service。
    ///
    /// 公开它是为了让「Axum 与 Tauri 穿的是**同一个** `ApplicationService`」可以被断言
    /// （`Arc::ptr_eq`），而不是只能被相信。§24 的 G1 判据「ApplicationService 经
    /// Axum/Tauri 结果一致」的前提正是这个"同一个"。
    #[must_use]
    pub fn service(&self) -> &Arc<dyn ApplicationService> {
        &self.service
    }

    /// 事件 broker（多窗口 ACL 与有界队列都在它那里）。
    #[must_use]
    pub fn broker(&self) -> &Arc<EventBroker> {
        &self.broker
    }

    /// 关停信号。
    #[must_use]
    pub fn shutdown_token(&self) -> &CancellationToken {
        self.broker.shutdown_token()
    }

    /// command 通道此刻还剩几个并发额度（§13.2「command 256」）。
    #[must_use]
    pub fn available_command_permits(&self) -> usize {
        self.commands.available_permits()
    }

    /// 执行一条命令 —— **直接 typed 调用，不经任何序列化**。
    ///
    /// # 背压而不是报错
    ///
    /// 在飞命令达到 [`COMMAND_QUEUE_CAPACITY`] 时，第 257 个调用**等待**而不是失败。
    /// 理由见该常量的文档：命令是用户动作，丢一次点击没有正确的用户可见语义；
    /// 事件流那边才是"满即显式断开"。
    ///
    /// # 错误映射为什么是恒等
    ///
    /// §5.2 把"错误映射"列为 transport 的活，但映射的**目标**由通道决定：Axum 要映射到
    /// HTTP 状态码，因为那头是 HTTP；in-process 这头是同一个进程里的 Rust GUI，它消费的
    /// 就是 [`AppError`] 的稳定 code。在这里插一层自定义错误类型只会多一份必须与
    /// `AppError` 同步的枚举，而每一次不同步都是一次静默的语义漂移。
    ///
    /// # Errors
    ///
    /// 原样返回 [`ApplicationService::execute`] 的 [`AppError`]。
    pub async fn execute(
        &self,
        auth: AuthContext,
        command: AppCommand,
    ) -> Result<AppReply, AppError> {
        let _permit = self
            .commands
            .acquire()
            .await
            .expect("command 信号量从不关闭");
        // 这一行是本模块的全部业务参与度：把参数原样递过去。
        self.service.execute(auth, command).await
    }

    /// 为一个窗口打开订阅，返回它的 [`DesktopSession`]。
    ///
    /// 流程：`subscribe` 拿到 [`AppEventStream`] → 在 broker 上开一条有界路由 → spawn 一个
    /// 事件泵把流抽进那条路由。泵的三个退出条件缺一不可：
    ///
    /// 1. 关停信号被取消；
    /// 2. 上游流结束；
    /// 3. 该窗口的路由没了（接收端被 drop、或被显式断开）。
    ///
    /// 第 3 条是「drop 接收端让生产侧停止」的落点。少了它，一个关掉的窗口会让上游流
    /// 继续跑到进程退出为止。
    ///
    /// # Errors
    ///
    /// 见 [`OpenSessionError`]。
    pub async fn open_session(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
    ) -> Result<DesktopSession, OpenSessionError> {
        self.open_session_inner(label, auth, request, subscriptions, None)
            .await
    }

    /// Open an internal route that shares the caller's aggregate event-ref budget.
    pub(crate) async fn open_session_with_budget(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
        queue_budget: Arc<EventQueueBudget>,
    ) -> Result<DesktopSession, OpenSessionError> {
        self.open_session_inner(label, auth, request, subscriptions, Some(queue_budget))
            .await
    }

    async fn open_session_inner(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
        queue_budget: Option<Arc<EventQueueBudget>>,
    ) -> Result<DesktopSession, OpenSessionError> {
        if self.shutdown_token().is_cancelled() {
            return Err(OpenSessionError::ShuttingDown);
        }

        let identity = WindowIdentity::bind(label, auth);
        let stream = self.service.subscribe(auth.clone(), request).await?;
        let session = match queue_budget {
            Some(queue_budget) => self.broker.open_window_with_budget(
                identity.clone(),
                subscriptions,
                queue_budget,
            )?,
            None => self.broker.open_window(identity.clone(), subscriptions)?,
        };
        let session_cancellation = CancellationToken::new();

        // 订阅流是**这个窗口自己的**，所以 scope 就是这个窗口。换成 actor scope 会让同一
        // 个 actor 的第二个窗口收到第一个窗口的订阅帧 —— 两条独立订阅会互相灌帧。
        let scope = EventScope::window(identity.tenant().clone(), identity.label().clone());
        let handle = tokio::spawn(pump(
            Arc::clone(&self.broker),
            self.shutdown_token().clone(),
            session_cancellation.clone(),
            identity.label().clone(),
            scope,
            identity.auth_generation(),
            stream,
        ));
        let mut pumps = self.pumps.lock().expect("事件泵句柄锁不会中毒");
        pumps.retain(|pump| !pump.task.is_finished());
        pumps.push(PumpHandle {
            label: identity.label().clone(),
            cancellation: session_cancellation,
            task: handle,
        });

        Ok(session)
    }

    /// Close one host-owned subscription without shutting down the process.
    ///
    /// The exact broker route is synchronously removed after receiving one explicit terminal frame,
    /// then its upstream pump is cancelled. Returning `true` therefore proves that the route is no
    /// longer eligible for delivery; callers do not need to wait for another upstream event.
    pub fn close_session(&self, label: &WindowLabel) -> bool {
        let cancellations = self
            .pumps
            .lock()
            .expect("事件泵句柄锁不会中毒")
            .iter()
            .filter(|pump| &pump.label == label)
            .map(|pump| pump.cancellation.clone())
            .collect::<Vec<_>>();
        let closed = self
            .broker
            .close_window(label, crate::broker::DisconnectReason::SubscriptionClosed);
        for cancellation in cancellations {
            cancellation.cancel();
        }
        closed
    }

    /// 关停：取消信号 → 给每个窗口投终止帧 → 在 [`SHUTDOWN_DEADLINE`] 内收拢事件泵。
    ///
    /// 顺序是有讲究的：**先取消再关窗口**。反过来的话，一个正阻塞在上游流上的泵不会被
    /// 唤醒，它要等到下一次上游产帧才发现路由没了 —— 而对一条 30 秒心跳的流来说，那就是
    /// 最多 30 秒，远超 5 秒 deadline。
    ///
    /// deadline 到了仍未停下的泵会被 `abort`：**deadline 是 deadline，不是建议**。
    /// 被 abort 的数量如实记进 [`ShutdownReport::pumps_aborted`]，不掩盖。
    pub async fn shutdown(&self) -> ShutdownReport {
        let started = Instant::now();
        self.shutdown_token().cancel();
        let windows_closed = self.broker.close_all();

        let mut handles: Vec<PumpHandle> =
            core::mem::take(&mut *self.pumps.lock().expect("事件泵句柄锁不会中毒"));
        let pumps_total = handles.len();

        let deadline = tokio::time::sleep(SHUTDOWN_DEADLINE);
        tokio::pin!(deadline);
        let mut pumps_joined = 0_usize;
        for handle in &mut handles {
            tokio::select! {
                () = &mut deadline => break,
                _ = &mut handle.task => pumps_joined += 1,
            }
        }

        let mut pumps_aborted = 0_usize;
        for handle in handles {
            if !handle.task.is_finished() {
                handle.task.abort();
                pumps_aborted += 1;
            }
        }
        if pumps_aborted > 0 {
            tracing::warn!(
                transport = Transport::InProcess.as_str(),
                pumps_aborted,
                pumps_total,
                "有事件泵未能在 shutdown deadline 内停下，已强制中止（§13.2）"
            );
        }

        let elapsed = started.elapsed();
        ShutdownReport {
            windows_closed,
            pumps_total,
            pumps_joined,
            pumps_aborted,
            elapsed,
            within_deadline: pumps_aborted == 0 && elapsed <= SHUTDOWN_DEADLINE,
        }
    }
}

/// 事件泵：把一条 [`AppEventStream`] 抽进某个窗口的有界路由。
async fn pump(
    broker: Arc<EventBroker>,
    shutdown: CancellationToken,
    session_cancellation: CancellationToken,
    label: WindowLabel,
    scope: EventScope,
    auth_generation: u64,
    mut stream: AppEventStream,
) {
    loop {
        enum PumpInput {
            Shutdown,
            SessionClosed,
            Event(Option<AppEvent>),
        }
        let next = tokio::select! {
            () = shutdown.cancelled() => PumpInput::Shutdown,
            () = session_cancellation.cancelled() => PumpInput::SessionClosed,
            item = next_event(&mut stream) => PumpInput::Event(item),
        };
        let event = match next {
            PumpInput::Shutdown => break,
            PumpInput::SessionClosed => {
                broker.close_window(&label, crate::broker::DisconnectReason::SubscriptionClosed);
                break;
            }
            PumpInput::Event(Some(event)) => event,
            PumpInput::Event(None) => {
                broker.close_window(&label, crate::broker::DisconnectReason::UpstreamEnded);
                break;
            }
        };

        let Ok(report) = broker.publish(BrokerEvent::new(scope.clone(), auth_generation, event))
        else {
            // broker 拒收（关停 / screen）—— 没有继续抽这条流的理由。
            break;
        };
        match report.outcome_for(&label) {
            // 路由已经不在报告里 = 它被摘除了（接收端 drop / 已断开）。
            None
            | Some(DeliveryOutcome::ReceiverGone)
            | Some(DeliveryOutcome::AlreadyDisconnected)
            | Some(DeliveryOutcome::Disconnected { .. }) => break,
            Some(
                DeliveryOutcome::Delivered { .. }
                | DeliveryOutcome::Superseded { .. }
                | DeliveryOutcome::Filtered(_),
            ) => {}
        }
    }
}

/// 从 [`AppEventStream`] 取下一项。
///
/// 手写 `poll_fn` 而不是 `futures::StreamExt::next`：本 crate 只依赖 `futures-core`
/// （`Stream` trait 本身），为一个辅助函数把 `futures-util` 拉进依赖图不划算 ——
/// `openbot-application` 在同一处做了同样的选择。
async fn next_event(stream: &mut AppEventStream) -> Option<AppEvent> {
    core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SequenceTracker;
    use crate::testing::{TEST_AUTH_GENERATION, auth_for};
    use async_trait::async_trait;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use openbot_application::{ChannelReader, OpenBotApplication, PortError};
    use openbot_contracts::command::{ChannelSummary, HealthReport};
    use openbot_contracts::ids::{ActorId, BotId, ChannelId};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;
    use tokio::time::{Duration as TokioDuration, timeout};

    // -----------------------------------------------------------------------
    // 一个真实业务实现（不是 mock）：真的 OpenBotApplication + 内存 port
    // -----------------------------------------------------------------------

    struct FakeChannels {
        rows: Vec<ChannelSummary>,
        calls: AtomicUsize,
    }

    impl FakeChannels {
        fn with_one_row() -> Self {
            Self {
                rows: vec![ChannelSummary {
                    id: ChannelId::new("c-1"),
                    name: "总控".to_owned(),
                    agent_ids: vec![BotId::new("bot-1")],
                    last_message: Some("上一条".to_owned()),
                    last_message_at: Some(OffsetDateTime::UNIX_EPOCH),
                    last_message_agent_id: Some(BotId::new("bot-1")),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    thread_id: None,
                    active: true,
                }],
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ChannelReader for FakeChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<openbot_application::ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.rows.clone())
        }
    }

    fn application() -> Arc<dyn ApplicationService> {
        Arc::new(
            OpenBotApplication::new(FakeChannels::with_one_row())
                .with_heartbeat_period(Duration::from_millis(1)),
        )
    }

    /// 一个**会失败**的 service：用来证明 transport 不改写业务判定的结果。
    struct AlwaysRefuses;

    #[async_trait]
    impl ApplicationService for AlwaysRefuses {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Err(AppError::NotVisible)
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Err(AppError::NotVisible)
        }
    }

    struct FiniteEventStream(VecDeque<AppEvent>);

    impl futures_core::Stream for FiniteEventStream {
        type Item = AppEvent;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct FiniteSubscriptionService;

    #[async_trait]
    impl ApplicationService for FiniteSubscriptionService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(Box::pin(FiniteEventStream(VecDeque::from([
                AppEvent::Heartbeat { seq: 41 },
            ]))))
        }
    }

    // -----------------------------------------------------------------------
    // G1 判据的本地一半：经 transport == 直连 service
    // -----------------------------------------------------------------------

    /// 同一个 `(AuthContext, AppCommand)` 经 in-process 调用与直连
    /// [`ApplicationService::execute`] 的结果**逐字段相等**。
    ///
    /// 这是 §24 G1「ApplicationService 经 Axum/Tauri 结果一致」在本 crate 能证到的那一半
    /// （跨 transport 的另一半由 `openbot-testkit` 做）。
    #[tokio::test]
    async fn in_process_execute_equals_a_direct_service_call() {
        let service = application();
        let transport = InProcessTransport::new(Arc::clone(&service));
        let auth = auth_for("actor-1");

        // 探活。
        let via_transport = transport
            .execute(auth.clone(), AppCommand::Health)
            .await
            .expect("探活成功");
        let direct = service
            .execute(auth.clone(), AppCommand::Health)
            .await
            .expect("探活成功");
        assert_eq!(via_transport, direct);
        assert_eq!(via_transport, AppReply::Health(HealthReport { ok: true }));

        // 一条真实读用例。
        let command = AppCommand::ListVisibleChannels {
            limit: None,
            cursor: None,
        };
        let via_transport = transport
            .execute(auth.clone(), command.clone())
            .await
            .expect("列表成功");
        let direct = service.execute(auth, command).await.expect("列表成功");
        assert_eq!(via_transport, direct);

        // 逐字段对：不只比一个 `==`，把投影里的每一项都点名。
        let (AppReply::Channels(page), AppReply::Channels(reference)) = (&via_transport, &direct)
        else {
            panic!("命令与应答必须一一对应");
        };
        assert_eq!(page.channels.len(), reference.channels.len());
        assert_eq!(page.next_cursor, reference.next_cursor);
        let (row, expected) = (&page.channels[0], &reference.channels[0]);
        assert_eq!(row.id, expected.id);
        assert_eq!(row.name, expected.name);
        assert_eq!(row.agent_ids, expected.agent_ids);
        assert_eq!(row.last_message, expected.last_message);
        assert_eq!(row.last_message_at, expected.last_message_at);
        assert_eq!(row.last_message_agent_id, expected.last_message_agent_id);
        assert_eq!(row.created_at, expected.created_at);
        assert_eq!(row.thread_id, expected.thread_id);
        assert_eq!(row.active, expected.active);
    }

    /// transport 持有的是**同一个** `Arc`，不是一层包装或一份拷贝。
    #[tokio::test]
    async fn the_transport_holds_the_very_same_service_arc() {
        let service = application();
        let transport = InProcessTransport::new(Arc::clone(&service));
        assert!(Arc::ptr_eq(transport.service(), &service));
    }

    /// 业务拒绝原样穿过 transport —— 不被改写、不被吞、不被翻译成别的 code。
    #[tokio::test]
    async fn a_business_refusal_passes_through_verbatim() {
        let transport = InProcessTransport::new(Arc::new(AlwaysRefuses));
        let error = transport
            .execute(auth_for("actor-1"), AppCommand::Health)
            .await
            .expect_err("service 拒绝了");
        assert_eq!(error, AppError::NotVisible);
        assert_eq!(error.http_status(), 404);

        // 订阅路径同样原样上抛。
        let opened = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(
            opened,
            Err(OpenSessionError::Application(AppError::NotVisible))
        ));
        assert_eq!(
            transport.broker().window_count(),
            0,
            "订阅失败不留下半开的窗口"
        );
    }

    // -----------------------------------------------------------------------
    // command 并发预算（§13.2「command 256」）
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn the_command_budget_is_the_spec_256_and_is_really_taken() {
        let transport = InProcessTransport::new(application());
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );

        // 正向对照：额度确实会被占用（否则上一行在"信号量根本没接上"的世界里也成立）。
        let permit = transport.commands.acquire().await.expect("信号量从不关闭");
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY - 1
        );
        drop(permit);
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );
    }

    /// 命令跑完之后额度必须还回去 —— 否则 256 次调用之后整个通道就永久卡死。
    #[tokio::test]
    async fn a_finished_command_returns_its_permit() {
        let transport = InProcessTransport::new(application());
        for _ in 0..8 {
            transport
                .execute(auth_for("actor-1"), AppCommand::Health)
                .await
                .expect("探活成功");
        }
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );
    }

    // -----------------------------------------------------------------------
    // 订阅 → 有界队列
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn open_session_pumps_the_subscription_into_the_bounded_queue() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");

        assert_eq!(session.auth_generation, TEST_AUTH_GENERATION);
        assert_eq!(transport.broker().window_count(), 1);

        let mut tracker = SequenceTracker::new();
        for expected in 0..3_u64 {
            let frame = timeout(TokioDuration::from_secs(5), session.next_frame())
                .await
                .expect("心跳必须在 5 秒内到")
                .expect("流未结束");
            tracker.observe(&frame).expect("序列合法");
            assert_eq!(frame.event(), Some(&AppEvent::Heartbeat { seq: expected }));
            assert_eq!(frame.seq(), expected);
        }
        assert_eq!(tracker.missing_total(), 0);

        transport.shutdown().await;
    }

    /// 同一个 actor 的两个窗口是**两条独立订阅**，互不灌帧。
    #[tokio::test]
    async fn two_windows_of_the_same_actor_get_independent_streams() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut a = transport
            .open_session(
                WindowLabel::new("a"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗 a");
        let mut b = transport
            .open_session(
                WindowLabel::new("b"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗 b");

        // 两条流各自从 seq 0 开始 —— 若两条订阅串到一起，其中一条会看到跳号。
        for session in [&mut a, &mut b] {
            let frame = timeout(TokioDuration::from_secs(5), session.next_frame())
                .await
                .expect("心跳必须在 5 秒内到")
                .expect("流未结束");
            assert_eq!(frame.seq(), 0);
            assert_eq!(frame.event(), Some(&AppEvent::Heartbeat { seq: 0 }));
        }

        transport.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // 取消与 deadline
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upstream_end_is_an_explicit_terminal_before_receiver_close() {
        let transport = InProcessTransport::new(Arc::new(FiniteSubscriptionService));
        let mut session = transport
            .open_session(
                WindowLabel::new("finite"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("finite subscription opens");

        let event = session.next_frame().await.expect("event frame");
        let terminal = session.next_frame().await.expect("terminal frame");
        assert_eq!(event.seq(), 0);
        assert_eq!(event.event(), Some(&AppEvent::Heartbeat { seq: 41 }));
        assert_eq!(terminal.seq(), 1);
        assert_eq!(
            terminal.terminal_reason(),
            Some(crate::broker::DisconnectReason::UpstreamEnded)
        );
        assert!(session.next_frame().await.is_none());
        assert_eq!(transport.broker().window_count(), 0);
        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
    }

    #[tokio::test]
    async fn close_session_removes_the_exact_route_and_wakes_its_pump() {
        let transport = InProcessTransport::new(application());
        let label = WindowLabel::new("main");
        let mut session = transport
            .open_session(
                label.clone(),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("subscription opens");

        assert!(transport.close_session(&label));
        assert!(!transport.close_session(&label));
        assert_eq!(transport.broker().window_count(), 0);
        let reason = timeout(TokioDuration::from_secs(2), async {
            loop {
                let frame = session
                    .next_frame()
                    .await
                    .expect("receiver cannot close before terminal");
                if let Some(reason) = frame.terminal_reason() {
                    break reason;
                }
            }
        })
        .await
        .expect("close must wake receiver");
        assert_eq!(reason, crate::broker::DisconnectReason::SubscriptionClosed);
        assert!(session.next_frame().await.is_none());

        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
        assert!(report.within_deadline);
    }

    /// 取消之后：生产停止、在 deadline 内停住、没有任何泵被 abort。
    ///
    /// 「不再产生事件」的证据是：终止帧之后流就结束了（`next_frame()` 返回 `None`），
    /// 而不是又冒出新的心跳。
    #[tokio::test]
    async fn cancelling_stops_production_within_the_deadline() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");

        // 正向对照：关停之前它确实在产事件。
        timeout(TokioDuration::from_secs(5), session.next_frame())
            .await
            .expect("关停前必须有心跳")
            .expect("流未结束");

        let report = timeout(
            SHUTDOWN_DEADLINE + TokioDuration::from_secs(2),
            transport.shutdown(),
        )
        .await
        .expect("shutdown 本身不能超过 deadline 还不返回");

        assert!(report.within_deadline, "拿到 {report:?}");
        assert_eq!(report.pumps_total, 1);
        assert_eq!(report.pumps_joined, 1);
        assert_eq!(report.pumps_aborted, 0);
        assert!(
            report.elapsed < SHUTDOWN_DEADLINE,
            "耗时 {:?}",
            report.elapsed
        );
        assert_eq!(report.windows_closed, 1);
        assert!(transport.shutdown_token().is_cancelled());

        // 抽干：最后一帧必须是终止帧，之后流结束，**不再有新事件**。
        let mut saw_terminal = false;
        while let Some(frame) = session.next_frame().await {
            assert!(
                !saw_terminal,
                "终止帧之后不该再有任何帧，却拿到 {:?}",
                frame.event()
            );
            saw_terminal = frame.is_terminal();
        }
        assert!(saw_terminal, "流结束前必须先收到终止帧");
    }

    /// 关停之后不再开得出新窗口。
    #[tokio::test]
    async fn no_new_session_after_shutdown() {
        let transport = InProcessTransport::new(application());
        transport.shutdown().await;
        let opened = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(opened, Err(OpenSessionError::ShuttingDown)));
    }

    /// drop 掉 session ⇒ 事件泵自己退出（不需要任何人去调 close）。
    #[tokio::test]
    async fn dropping_the_session_stops_the_pump() {
        let transport = InProcessTransport::new(application());
        let session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");
        assert_eq!(transport.broker().window_count(), 1);

        drop(session);

        // 心跳周期 1 ms：泵会在下一拍发现接收端没了，然后退出。给它一个宽裕的上界。
        let deadline = Instant::now() + Duration::from_secs(5);
        while transport.broker().window_count() > 0 && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            transport.broker().window_count(),
            0,
            "drop 接收端必须让生产侧停下来并摘除路由"
        );

        // 泵已经自行结束，所以关停时它是"joined"而不是"aborted"。
        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
        assert!(report.within_deadline);
    }

    /// 重名窗口在 transport 这一层同样被拒。
    #[tokio::test]
    async fn a_duplicate_window_label_is_rejected_at_the_transport_too() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let _first = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("首次开窗成功");
        let second = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(
            second,
            Err(OpenSessionError::WindowAlreadyOpen(_))
        ));
        transport.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // 「不复制 JSON-RPC」的构造性证据
    // -----------------------------------------------------------------------

    /// In-process 模块没有任何序列化调用；Tauri WebView framing 的 codec 只在显式 host
    /// feature 内，默认 typed lane 不会把 DTO 抄成 JSON 再抄回来。
    #[test]
    fn the_in_process_lane_has_no_json_codec() {
        let source = include_str!("transport.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let code = production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["serde::", "serde_json::", "bincode::", "prost::"] {
            assert!(
                !code.contains(forbidden),
                "typed lane contains codec {forbidden}"
            );
        }

        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("读得到本 crate 的 Cargo.toml");
        assert!(manifest.contains("tauri-host = ["));
        assert!(manifest.contains("serde_json = { workspace = true, optional = true }"));
        assert!(!manifest.contains("serde_json.workspace = true"));
    }
}
