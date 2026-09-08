//! Explicit memory GUI use cases；owner/origin/created_by 只取权威上下文。

use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::MAX_MEMORY_PAGE;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::memory::{
    CorrectMemory, MemoryControl, MemoryKind, MemoryMutation, MemoryPage, MemoryRecall,
    MemoryRecord, MemoryScope, RecallMemories, RememberMemory, UpdateMemoryControl,
};

use crate::ports::{
    CorrectMemoryRequest, MemoryAdministration, MemoryControlRequest, MemoryPageRequest,
    MutateMemoryRequest, RecallMemoriesRequest, RememberMemoryRequest, UpdateMemoryControlRequest,
};

/// 默认 memory 页长。
pub const DEFAULT_MEMORY_PAGE: u32 = 50;
/// 单条 memory 文本上限。
pub const MAX_MEMORY_CONTENT_BYTES: usize = 64 * 1024;
/// Tags 个数上限。
pub const MAX_MEMORY_TAGS: usize = 32;
/// 单 tag UTF-8 字节上限。
pub const MAX_MEMORY_TAG_BYTES: usize = 64;
/// FTS query 字节上限。
pub const MAX_MEMORY_QUERY_BYTES: usize = 4096;

/// Read the current actor's runtime memory write control.
pub async fn get_memory_control<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
) -> Result<MemoryControl, AppError> {
    memory
        .memory_control(MemoryControlRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Persist a closed runtime memory write control using only authoritative scope.
pub async fn update_memory_control<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    update: UpdateMemoryControl,
) -> Result<MemoryControl, AppError> {
    memory
        .update_memory_control(UpdateMemoryControlRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            update,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// GUI “记住这条”；origin 在 adapter 固定为 user_action。
pub async fn remember_memory<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    input: RememberMemory,
) -> Result<MemoryRecord, AppError> {
    validate_remember(&input)?;
    memory
        .remember(RememberMemoryRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            input,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// 当前 actor 的 keyset 页。
pub async fn list_memories<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    cursor: Option<String>,
    limit: Option<u32>,
) -> Result<MemoryPage, AppError> {
    if cursor
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.as_bytes().contains(&0))
    {
        return Err(AppError::MalformedPayload { field: "cursor" });
    }
    memory
        .list_memories(MemoryPageRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            cursor,
            limit: limit
                .unwrap_or(DEFAULT_MEMORY_PAGE)
                .clamp(1, MAX_MEMORY_PAGE),
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Correct 一条 owner memory；scope/kind/source 在 store 内继承。
pub async fn correct_memory<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    memory_id: String,
    correction: CorrectMemory,
) -> Result<MemoryRecord, AppError> {
    validate_memory_id(&memory_id)?;
    validate_content(&correction.content)?;
    validate_tags(&correction.tags)?;
    memory
        .correct(CorrectMemoryRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            memory_id,
            correction,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Forbid/delete；两者都必须擦除 content。
pub async fn mutate_memory<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    memory_id: String,
    mutation: MemoryMutation,
) -> Result<MemoryRecord, AppError> {
    validate_memory_id(&memory_id)?;
    memory
        .mutate(MutateMemoryRequest {
            auth_generation: auth.auth_generation(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            memory_id,
            mutation,
        })
        .await
        .map_err(|error| error.into_app_error())
}

/// Recall user scope + 当前可见的 exact Bot/thread scope。
pub async fn recall_memories<M: MemoryAdministration>(
    memory: &M,
    auth: &AuthContext,
    mut input: RecallMemories,
) -> Result<MemoryRecall, AppError> {
    if input.query.is_empty()
        || input.query.as_bytes().contains(&0)
        || input.query.len() > MAX_MEMORY_QUERY_BYTES
    {
        return Err(AppError::MalformedPayload { field: "query" });
    }
    validate_tags(&input.tags)?;
    input.tags.sort();
    input.tags.dedup();
    if input
        .bot_id
        .as_ref()
        .is_some_and(|id| id.as_str().is_empty() || id.as_str().as_bytes().contains(&0))
    {
        return Err(AppError::MalformedPayload { field: "bot_id" });
    }
    if input
        .thread_id
        .as_ref()
        .is_some_and(|id| !ThreadIdentity::is_plausible(id))
    {
        return Err(AppError::MalformedPayload { field: "thread_id" });
    }
    input.limit = Some(
        input
            .limit
            .unwrap_or(DEFAULT_MEMORY_PAGE)
            .clamp(1, MAX_MEMORY_PAGE),
    );
    memory
        .recall(RecallMemoriesRequest {
            auth_generation: auth.auth_generation(),
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            input,
        })
        .await
        .map_err(|error| error.into_app_error())
}

fn validate_remember(input: &RememberMemory) -> Result<(), AppError> {
    validate_content(&input.content)?;
    validate_tags(&input.tags)?;
    match &input.scope {
        MemoryScope::User => {}
        MemoryScope::Bot { bot_id }
            if bot_id.as_str().is_empty() || bot_id.as_str().as_bytes().contains(&0) =>
        {
            return Err(AppError::MalformedPayload { field: "bot_id" });
        }
        MemoryScope::Thread { thread_id } if !ThreadIdentity::is_plausible(thread_id) => {
            return Err(AppError::MalformedPayload { field: "thread_id" });
        }
        MemoryScope::Bot { .. } | MemoryScope::Thread { .. } => {}
    }
    if input.memory_kind == MemoryKind::Fact && input.source.is_none() {
        return Err(AppError::MalformedPayload { field: "source" });
    }
    if let Some(source) = &input.source {
        if !ThreadIdentity::is_plausible(&source.thread_id) {
            return Err(AppError::MalformedPayload {
                field: "source_thread_id",
            });
        }
        if source.message_id.is_empty() || source.message_id.as_bytes().contains(&0) {
            return Err(AppError::MalformedPayload {
                field: "source_message_id",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_content(content: &str) -> Result<(), AppError> {
    if content.is_empty()
        || content.as_bytes().contains(&0)
        || content.len() > MAX_MEMORY_CONTENT_BYTES
    {
        Err(AppError::MalformedPayload { field: "content" })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_tags(tags: &[String]) -> Result<(), AppError> {
    if tags.len() > MAX_MEMORY_TAGS
        || tags.iter().any(|tag| {
            tag.is_empty() || tag.as_bytes().contains(&0) || tag.len() > MAX_MEMORY_TAG_BYTES
        })
    {
        Err(AppError::MalformedPayload { field: "tags" })
    } else {
        Ok(())
    }
}

fn validate_memory_id(memory_id: &str) -> Result<(), AppError> {
    if memory_id.is_empty() || memory_id.as_bytes().contains(&0) {
        Err(AppError::MalformedPayload { field: "memory_id" })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::memory::{MemoryOrigin, MemorySensitivity, MemorySource, MemoryStatus};
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::MemoryAdministrationError;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        GetControl(MemoryControlRequest),
        UpdateControl(UpdateMemoryControlRequest),
        Remember(RememberMemoryRequest),
        List(MemoryPageRequest),
        Correct(CorrectMemoryRequest),
        Mutate(MutateMemoryRequest),
        Recall(RecallMemoriesRequest),
    }

    struct FakeMemory {
        calls: Mutex<Vec<Call>>,
    }

    fn record() -> MemoryRecord {
        MemoryRecord {
            memory_id: "memory-1".to_owned(),
            owner_user_id: "actor-memory".to_owned(),
            scope: MemoryScope::User,
            memory_kind: MemoryKind::Preference,
            content: Some("tea".to_owned()),
            tags: vec!["drink".to_owned()],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            origin: MemoryOrigin::UserAction,
            created_by: "actor-memory".to_owned(),
            supersedes_id: None,
            status: MemoryStatus::Active,
            expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[async_trait]
    impl MemoryAdministration for FakeMemory {
        async fn memory_control(
            &self,
            request: MemoryControlRequest,
        ) -> Result<MemoryControl, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::GetControl(request));
            Ok(MemoryControl::default())
        }

        async fn update_memory_control(
            &self,
            request: UpdateMemoryControlRequest,
        ) -> Result<MemoryControl, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::UpdateControl(request.clone()));
            Ok(MemoryControl {
                writes_enabled: request.update.writes_enabled,
            })
        }

        async fn remember(
            &self,
            request: RememberMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Remember(request));
            Ok(record())
        }

        async fn list_memories(
            &self,
            request: MemoryPageRequest,
        ) -> Result<MemoryPage, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::List(request));
            Ok(MemoryPage::default())
        }

        async fn correct(
            &self,
            request: CorrectMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Correct(request));
            Ok(record())
        }

        async fn mutate(
            &self,
            request: MutateMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Mutate(request));
            Ok(record())
        }

        async fn recall(
            &self,
            request: RecallMemoriesRequest,
        ) -> Result<MemoryRecall, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Recall(request));
            Ok(MemoryRecall::default())
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-memory"),
            TenantId::new("tenant-memory"),
            ActorId::new("actor-memory"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    fn input() -> RememberMemory {
        RememberMemory {
            memory_kind: MemoryKind::Preference,
            scope: MemoryScope::User,
            content: "tea".to_owned(),
            tags: vec!["drink".to_owned()],
            sensitivity: MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn control_read_and_update_inject_only_authoritative_scope() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        assert!(
            get_memory_control(&memory, &auth())
                .await
                .unwrap()
                .writes_enabled
        );
        let update = UpdateMemoryControl {
            writes_enabled: false,
        };
        assert_eq!(
            update_memory_control(&memory, &auth(), update)
                .await
                .unwrap(),
            MemoryControl {
                writes_enabled: false,
            }
        );
        assert_eq!(
            memory.calls.lock().expect("fake lock").as_slice(),
            &[
                Call::GetControl(MemoryControlRequest {
                    auth_generation: AuthGeneration::new(1),
                    tenant: TenantId::new("tenant-memory"),
                    actor: ActorId::new("actor-memory"),
                }),
                Call::UpdateControl(UpdateMemoryControlRequest {
                    auth_generation: AuthGeneration::new(1),
                    tenant: TenantId::new("tenant-memory"),
                    actor: ActorId::new("actor-memory"),
                    update,
                }),
            ]
        );
    }

    #[tokio::test]
    async fn remember_injects_owner_and_has_no_origin_input() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        remember_memory(&memory, &auth(), input()).await.unwrap();
        assert_eq!(
            memory.calls.lock().expect("fake lock").as_slice(),
            &[Call::Remember(RememberMemoryRequest {
                auth_generation: AuthGeneration::new(1),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
                input: input(),
            })]
        );
    }

    #[tokio::test]
    async fn fact_requires_source_and_malformed_input_never_calls_port() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        let mut fact = input();
        fact.memory_kind = MemoryKind::Fact;
        assert_eq!(
            remember_memory(&memory, &auth(), fact).await.unwrap_err(),
            AppError::MalformedPayload { field: "source" }
        );
        let mut bad = input();
        bad.content = "bad\0content".to_owned();
        assert!(remember_memory(&memory, &auth(), bad).await.is_err());
        let mut bad_source = input();
        bad_source.source = Some(MemorySource {
            thread_id: openbot_contracts::ids::ThreadId::new(
                "550e8400-e29b-41d4-a716-446655440000",
            ),
            message_id: "bad\0message".to_owned(),
        });
        assert!(remember_memory(&memory, &auth(), bad_source).await.is_err());
        assert!(memory.calls.lock().expect("fake lock").is_empty());

        let mut fact = input();
        fact.memory_kind = MemoryKind::Fact;
        fact.source = Some(MemorySource {
            thread_id: openbot_contracts::ids::ThreadId::new(
                "550e8400-e29b-41d4-a716-446655440000",
            ),
            message_id: "m-1".to_owned(),
        });
        remember_memory(&memory, &auth(), fact).await.unwrap();
    }

    #[tokio::test]
    async fn list_limit_is_clamped_and_scope_is_authoritative() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        list_memories(&memory, &auth(), None, Some(u32::MAX))
            .await
            .unwrap();
        assert_eq!(
            memory.calls.lock().expect("fake lock").as_slice(),
            &[Call::List(MemoryPageRequest {
                auth_generation: AuthGeneration::new(1),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
                cursor: None,
                limit: MAX_MEMORY_PAGE,
            })]
        );
        assert!(
            list_memories(&memory, &auth(), Some("bad\0cursor".to_owned()), Some(10))
                .await
                .is_err()
        );
        assert_eq!(memory.calls.lock().expect("fake lock").len(), 1);
    }

    #[tokio::test]
    async fn correct_and_mutate_forward_only_validated_owner_requests() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        let correction = CorrectMemory {
            content: "coffee".to_owned(),
            tags: vec!["drink".to_owned()],
            sensitivity: MemorySensitivity::Sensitive,
            expires_at: None,
        };
        correct_memory(&memory, &auth(), "memory-1".to_owned(), correction.clone())
            .await
            .unwrap();
        mutate_memory(
            &memory,
            &auth(),
            "memory-1".to_owned(),
            MemoryMutation::Delete,
        )
        .await
        .unwrap();
        assert_eq!(
            memory.calls.lock().expect("fake lock").as_slice(),
            &[
                Call::Correct(CorrectMemoryRequest {
                    auth_generation: AuthGeneration::new(1),
                    tenant: TenantId::new("tenant-memory"),
                    actor: ActorId::new("actor-memory"),
                    memory_id: "memory-1".to_owned(),
                    correction,
                }),
                Call::Mutate(MutateMemoryRequest {
                    auth_generation: AuthGeneration::new(1),
                    tenant: TenantId::new("tenant-memory"),
                    actor: ActorId::new("actor-memory"),
                    memory_id: "memory-1".to_owned(),
                    mutation: MemoryMutation::Delete,
                }),
            ]
        );
    }

    #[tokio::test]
    async fn recall_clamps_limit_and_injects_owner_scope() {
        let memory = FakeMemory {
            calls: Mutex::new(Vec::new()),
        };
        recall_memories(
            &memory,
            &auth(),
            RecallMemories {
                query: "office schedule".to_owned(),
                tags: vec!["work".to_owned(), "work".to_owned()],
                bot_id: None,
                thread_id: None,
                limit: Some(u32::MAX),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            memory.calls.lock().expect("fake lock").as_slice(),
            &[Call::Recall(RecallMemoriesRequest {
                auth_generation: AuthGeneration::new(1),
                deployment: DeploymentId::new("dep-memory"),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
                input: RecallMemories {
                    query: "office schedule".to_owned(),
                    tags: vec!["work".to_owned()],
                    bot_id: None,
                    thread_id: None,
                    limit: Some(MAX_MEMORY_PAGE),
                },
            })]
        );
    }
}
