//! Native thread ID 与可见性用例（v3 §4.1 / §4.3，API ledger T-API-0035/0036）。

use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{
    BeginThreadRun, CancelThreadRun, MAX_THREAD_MESSAGE_BYTES, ThreadConversationSnapshot,
    ThreadHistory, ThreadMinted, ThreadRunAnchor, ThreadRunCancellation, ThreadRunStarted,
    ThreadStatus,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ThreadId;
use openbot_contracts::ids::thread::ThreadIdentity;

use crate::ports::{
    BeginThreadRunRequest, CancelThreadRunRequest, ChannelActivitySubscription,
    ThreadConversationRequest, ThreadDirectory, ThreadEventSubscription, ThreadHistoryRequest,
};
use crate::service::AppEventStream;

/// 为权威 deployment 铸造一个 thread ID。
pub async fn mint_thread_id<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
) -> Result<ThreadMinted, AppError> {
    let thread_id = directory
        .mint_thread_id(auth.deployment())
        .await
        .map_err(|error| error.into_app_error())?;
    Ok(ThreadMinted { thread_id })
}

/// 查询当前权威 scope 是否仍可产生一条 native thread。
///
/// UUID 外形检查保留固定上游输入契约；ownership 不能参与判定，因为另一个 deployment 或
/// 旧版铸造的 UUID 仍可能经迁移属于当前 actor。不存在、已删除与不可见统一 `known:false`。
pub async fn get_thread_status<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread_id: &ThreadId,
) -> Result<ThreadStatus, AppError> {
    if !ThreadIdentity::is_plausible(thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    let known = directory
        .thread_known(auth.deployment(), auth.tenant(), auth.actor(), thread_id)
        .await
        .map_err(|error| error.into_app_error())?;
    Ok(ThreadStatus { known })
}

/// 校验 caller-controlled 字段后，把一次 foreground turn 交给唯一事务端口。
pub async fn begin_thread_run<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    command: BeginThreadRun,
) -> Result<ThreadRunStarted, AppError> {
    if !ThreadIdentity::is_plausible(&command.thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if command.run_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    if command.bot_id.as_str().is_empty() {
        return Err(AppError::MalformedPayload { field: "bot_id" });
    }
    if matches!(
        &command.anchor,
        ThreadRunAnchor::Channel { channel_id } if channel_id.as_str().is_empty()
    ) {
        return Err(AppError::MalformedPayload {
            field: "channel_id",
        });
    }
    if command.message.is_empty()
        || command.message.as_bytes().contains(&0)
        || command.message.len() > MAX_THREAD_MESSAGE_BYTES
    {
        return Err(AppError::MalformedPayload { field: "message" });
    }
    if !openbot_contracts::command::valid_selected_skill_slugs(&command.selected_skill_slugs) {
        return Err(AppError::MalformedPayload {
            field: "selected_skill_slugs",
        });
    }
    if command
        .model_selection
        .as_ref()
        .is_some_and(|selection| !selection.is_valid())
    {
        return Err(AppError::MalformedPayload {
            field: "model_selection",
        });
    }
    directory
        .begin_thread_run(BeginThreadRunRequest {
            auth_generation: auth.auth_generation(),
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            command,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Validate public identities, then persist cancellation through the single authority-aware port.
pub async fn cancel_thread_run<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    command: CancelThreadRun,
) -> Result<ThreadRunCancellation, AppError> {
    if !ThreadIdentity::is_plausible(&command.thread_id) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if command.run_id.as_str().is_empty() || command.run_id.as_str().as_bytes().contains(&0) {
        return Err(AppError::MalformedPayload { field: "run_id" });
    }
    directory
        .cancel_thread_run(CancelThreadRunRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            command,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 建立 scope-aware durable thread event stream。
pub async fn subscribe_thread_events<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
    after_event_sequence: Option<u64>,
) -> Result<AppEventStream, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    if after_event_sequence.is_some_and(|value| i64::try_from(value).is_err()) {
        return Err(AppError::MalformedPayload {
            field: "after_event_sequence",
        });
    }
    directory
        .subscribe_thread_events(ThreadEventSubscription {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
            after_event_sequence,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Establish an authority-scoped channel activity stream.
pub async fn subscribe_channel_activity<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
) -> Result<AppEventStream, AppError> {
    directory
        .subscribe_channel_activity(ChannelActivitySubscription {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 读取 scope-aware durable history；未知/不可见/已删除由 port 统一投影为空列表。
pub async fn get_thread_history<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
) -> Result<ThreadHistory, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    directory
        .thread_history(ThreadHistoryRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Read an atomic history/foreground/cursor snapshot for gap-free realtime attachment.
pub async fn get_thread_conversation<D: ThreadDirectory>(
    directory: &D,
    auth: &AuthContext,
    thread: ThreadId,
) -> Result<ThreadConversationSnapshot, AppError> {
    if !ThreadIdentity::is_plausible(&thread) {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    directory
        .thread_conversation(ThreadConversationRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            thread,
        })
        .await
        .map_err(|error| error.into_app_error())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    use super::*;
    use crate::ports::ThreadDirectoryError;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct KnownCall {
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        thread: ThreadId,
    }

    struct FakeDirectory {
        minted: ThreadId,
        known: Result<bool, ThreadDirectoryError>,
        mint_deployments: Mutex<Vec<DeploymentId>>,
        known_calls: Mutex<Vec<KnownCall>>,
    }

    impl FakeDirectory {
        fn new(known: Result<bool, ThreadDirectoryError>) -> Self {
            Self {
                minted: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                known,
                mint_deployments: Mutex::new(Vec::new()),
                known_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ThreadDirectory for FakeDirectory {
        async fn mint_thread_id(
            &self,
            deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            self.mint_deployments
                .lock()
                .expect("fake lock")
                .push(deployment.clone());
            Ok(self.minted.clone())
        }

        async fn thread_known(
            &self,
            deployment: &DeploymentId,
            tenant: &TenantId,
            actor: &ActorId,
            thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            self.known_calls.lock().expect("fake lock").push(KnownCall {
                deployment: deployment.clone(),
                tenant: tenant.clone(),
                actor: actor.clone(),
                thread: thread.clone(),
            });
            self.known
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-authoritative"),
            TenantId::new("tenant-authoritative"),
            ActorId::new("actor-authoritative"),
            [Role::User],
            AuthGeneration::new(7),
            false,
        )
    }

    #[tokio::test]
    async fn mint_uses_the_authoritative_deployment_and_returns_the_port_id() {
        let directory = FakeDirectory::new(Ok(false));
        let reply = mint_thread_id(&directory, &auth()).await.unwrap();
        assert_eq!(reply.thread_id, directory.minted);
        assert_eq!(
            directory
                .mint_deployments
                .lock()
                .expect("fake lock")
                .as_slice(),
            &[DeploymentId::new("dep-authoritative")]
        );
    }

    #[tokio::test]
    async fn status_uses_all_three_authoritative_scope_axes() {
        let directory = FakeDirectory::new(Ok(true));
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        assert!(
            get_thread_status(&directory, &auth(), &thread)
                .await
                .unwrap()
                .known
        );
        assert_eq!(
            directory.known_calls.lock().expect("fake lock").as_slice(),
            &[KnownCall {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_id_is_rejected_before_the_directory_is_touched() {
        let directory = FakeDirectory::new(Ok(true));
        let error = get_thread_status(&directory, &auth(), &ThreadId::new("not-a-uuid"))
            .await
            .unwrap_err();
        assert_eq!(error, AppError::MalformedPayload { field: "thread_id" });
        assert!(directory.known_calls.lock().expect("fake lock").is_empty());
    }

    #[tokio::test]
    async fn directory_failure_is_a_stable_dependency_error() {
        let directory = FakeDirectory::new(Err(ThreadDirectoryError::Unavailable));
        let error = get_thread_status(
            &directory,
            &auth(),
            &ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AppError::DependencyUnavailable {
                dependency: "thread_directory"
            }
        );
    }

    struct BeginDirectory {
        result: Result<ThreadRunStarted, ThreadDirectoryError>,
        calls: Mutex<Vec<BeginThreadRunRequest>>,
    }

    #[async_trait]
    impl ThreadDirectory for BeginDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn begin_thread_run(
            &self,
            request: BeginThreadRunRequest,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }
    }

    fn begin_command() -> BeginThreadRun {
        BeginThreadRun {
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            bot_id: openbot_contracts::ids::BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello".to_owned(),
        }
    }

    fn begin_directory(result: Result<ThreadRunStarted, ThreadDirectoryError>) -> BeginDirectory {
        BeginDirectory {
            result,
            calls: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn begin_injects_authoritative_scope_and_returns_the_durable_receipt() {
        let expected = ThreadRunStarted {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            message_sequence: 0,
            event_sequence: 0,
            replayed: false,
        };
        let directory = begin_directory(Ok(expected.clone()));
        let command = begin_command();
        assert_eq!(
            begin_thread_run(&directory, &auth(), command.clone())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[BeginThreadRunRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(7),
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                command,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_begin_is_rejected_before_any_transaction_port_call() {
        let invalid = [
            ("model_selection", {
                let mut value = begin_command();
                value.model_selection =
                    Some(openbot_contracts::model_connections::RunModelSelection {
                        connection_id: "not-a-uuid".to_owned(),
                        expected_revision: 1,
                    });
                value
            }),
            ("model_selection", {
                let mut value = begin_command();
                value.model_selection =
                    Some(openbot_contracts::model_connections::RunModelSelection {
                        connection_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
                        expected_revision: 0,
                    });
                value
            }),
            ("thread_id", {
                let mut value = begin_command();
                value.thread_id = ThreadId::new("bad");
                value
            }),
            ("run_id", {
                let mut value = begin_command();
                value.run_id = openbot_contracts::ids::RunId::new("");
                value
            }),
            ("bot_id", {
                let mut value = begin_command();
                value.bot_id = openbot_contracts::ids::BotId::new("");
                value
            }),
            ("message", {
                let mut value = begin_command();
                value.message.clear();
                value
            }),
            ("message", {
                let mut value = begin_command();
                value.message = "bad\0message".to_owned();
                value
            }),
            ("channel_id", {
                let mut value = begin_command();
                value.anchor = ThreadRunAnchor::Channel {
                    channel_id: openbot_contracts::ids::ChannelId::new(""),
                };
                value
            }),
        ];
        for (field, command) in invalid {
            let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
            assert_eq!(
                begin_thread_run(&directory, &auth(), command)
                    .await
                    .unwrap_err(),
                AppError::MalformedPayload { field }
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
        for slugs in [
            vec!["missing/grammar".to_owned()],
            vec!["repeat".to_owned(), "repeat".to_owned()],
            (0..17).map(|index| format!("skill-{index}")).collect(),
        ] {
            let directory = begin_directory(Err(ThreadDirectoryError::Unavailable));
            let mut command = begin_command();
            command.selected_skill_slugs = slugs;
            assert_eq!(
                begin_thread_run(&directory, &auth(), command).await,
                Err(AppError::MalformedPayload {
                    field: "selected_skill_slugs"
                }),
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
    }

    #[tokio::test]
    async fn begin_conflicts_keep_their_distinct_stable_semantics() {
        for (port, expected) in [
            (ThreadDirectoryError::NotVisible, AppError::NotVisible),
            (
                ThreadDirectoryError::LeaseConflict,
                AppError::LeaseConflict { holder: None },
            ),
            (
                ThreadDirectoryError::RequestConflict,
                AppError::RequestConflict { resource: "run" },
            ),
            (
                ThreadDirectoryError::CommitUnknown,
                AppError::ReconciliationRequired { accepted: true },
            ),
        ] {
            let directory = begin_directory(Err(port));
            assert_eq!(
                begin_thread_run(&directory, &auth(), begin_command())
                    .await
                    .unwrap_err(),
                expected
            );
        }
    }

    struct CancelDirectory {
        result: Result<ThreadRunCancellation, ThreadDirectoryError>,
        calls: Mutex<Vec<CancelThreadRunRequest>>,
    }

    #[async_trait]
    impl ThreadDirectory for CancelDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn cancel_thread_run(
            &self,
            request: CancelThreadRunRequest,
        ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }
    }

    fn cancel_command() -> CancelThreadRun {
        CancelThreadRun {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
        }
    }

    #[tokio::test]
    async fn cancel_injects_authoritative_scope_and_returns_only_the_durable_ack() {
        let expected = ThreadRunCancellation {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            state: openbot_contracts::command::ThreadRunCancellationState::Requested,
        };
        let directory = CancelDirectory {
            result: Ok(expected.clone()),
            calls: Mutex::new(Vec::new()),
        };
        let command = cancel_command();
        assert_eq!(
            cancel_thread_run(&directory, &auth(), command.clone())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[CancelThreadRunRequest {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                command,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_cancel_identities_never_reach_the_port() {
        let invalid = [
            ("thread_id", {
                let mut command = cancel_command();
                command.thread_id = ThreadId::new("not-a-uuid");
                command
            }),
            ("run_id", {
                let mut command = cancel_command();
                command.run_id = openbot_contracts::ids::RunId::new("");
                command
            }),
            ("run_id", {
                let mut command = cancel_command();
                command.run_id = openbot_contracts::ids::RunId::new("bad\0run");
                command
            }),
        ];
        for (field, command) in invalid {
            let directory = CancelDirectory {
                result: Err(ThreadDirectoryError::Unavailable),
                calls: Mutex::new(Vec::new()),
            };
            assert_eq!(
                cancel_thread_run(&directory, &auth(), command)
                    .await
                    .unwrap_err(),
                AppError::MalformedPayload { field }
            );
            assert!(directory.calls.lock().expect("fake lock").is_empty());
        }
    }

    struct SubscriptionDirectory {
        thread_calls: Mutex<Vec<ThreadEventSubscription>>,
        channel_calls: Mutex<Vec<ChannelActivitySubscription>>,
    }

    #[async_trait]
    impl ThreadDirectory for SubscriptionDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn subscribe_thread_events(
            &self,
            request: ThreadEventSubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.thread_calls.lock().expect("fake lock").push(request);
            Ok(crate::use_cases::health_stream(
                core::time::Duration::from_secs(1),
            ))
        }

        async fn subscribe_channel_activity(
            &self,
            request: ChannelActivitySubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.channel_calls.lock().expect("fake lock").push(request);
            Ok(crate::use_cases::health_stream(
                core::time::Duration::from_secs(1),
            ))
        }
    }

    #[tokio::test]
    async fn subscribe_injects_scope_and_rejects_unrepresentable_cursor_before_port() {
        let directory = SubscriptionDirectory {
            thread_calls: Mutex::new(Vec::new()),
            channel_calls: Mutex::new(Vec::new()),
        };
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let _stream = subscribe_thread_events(&directory, &auth(), thread.clone(), Some(7))
            .await
            .unwrap();
        assert_eq!(
            directory.thread_calls.lock().expect("fake lock").as_slice(),
            &[ThreadEventSubscription {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
                after_event_sequence: Some(7),
            }]
        );

        let before = directory.thread_calls.lock().expect("fake lock").len();
        assert_eq!(
            subscribe_thread_events(&directory, &auth(), ThreadId::new("not-a-uuid"), None,)
                .await
                .err(),
            Some(AppError::MalformedPayload { field: "thread_id" })
        );
        assert_eq!(
            directory.thread_calls.lock().expect("fake lock").len(),
            before
        );

        if usize::BITS > 32 {
            assert_eq!(
                subscribe_thread_events(
                    &directory,
                    &auth(),
                    ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
                    Some(i64::MAX as u64 + 1),
                )
                .await
                .err(),
                Some(AppError::MalformedPayload {
                    field: "after_event_sequence"
                })
            );
            assert_eq!(
                directory.thread_calls.lock().expect("fake lock").len(),
                before
            );
        }

        let _stream = subscribe_channel_activity(&directory, &auth())
            .await
            .unwrap();
        assert_eq!(
            directory
                .channel_calls
                .lock()
                .expect("fake lock")
                .as_slice(),
            &[ChannelActivitySubscription {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
            }]
        );
    }

    struct HistoryDirectory {
        result: Result<ThreadHistory, ThreadDirectoryError>,
        calls: Mutex<Vec<ThreadHistoryRequest>>,
    }

    #[async_trait]
    impl ThreadDirectory for HistoryDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_history(
            &self,
            request: ThreadHistoryRequest,
        ) -> Result<ThreadHistory, ThreadDirectoryError> {
            self.calls.lock().expect("fake lock").push(request);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn history_uses_authoritative_scope_and_empty_is_a_success_value() {
        let directory = HistoryDirectory {
            result: Ok(ThreadHistory::default()),
            calls: Mutex::new(Vec::new()),
        };
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            get_thread_history(&directory, &auth(), thread.clone())
                .await
                .unwrap(),
            ThreadHistory::default()
        );
        assert_eq!(
            directory.calls.lock().expect("fake lock").as_slice(),
            &[ThreadHistoryRequest {
                deployment: DeploymentId::new("dep-authoritative"),
                tenant: TenantId::new("tenant-authoritative"),
                actor: ActorId::new("actor-authoritative"),
                thread,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_history_id_never_reaches_the_port() {
        let directory = HistoryDirectory {
            result: Ok(ThreadHistory::default()),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            get_thread_history(&directory, &auth(), ThreadId::new("not-a-uuid"))
                .await
                .unwrap_err(),
            AppError::MalformedPayload { field: "thread_id" }
        );
        assert!(directory.calls.lock().expect("fake lock").is_empty());
    }
}
