//! Explicit memory GUI journey 的 PostgreSQL 17 真库证据。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    CorrectMemoryRequest, MemoryAdministration, MemoryAdministrationError, MemoryControlRequest,
    MemoryPageRequest, MutateMemoryRequest, RecallMemoriesRequest, RememberMemoryRequest,
    RememberToolMemory, RememberToolMemoryRequest, UpdateMemoryControlRequest,
    parse_remember_tool_arguments,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, BotId, RunId, TenantId, ThreadId};
use openbot_contracts::memory::{
    CorrectMemory, MemoryKind, MemoryMutation, MemoryScope, MemorySensitivity, MemorySource,
    MemoryStatus, RecallMemories, RememberMemory, UpdateMemoryControl,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;

async fn provision(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES
               ('actor-a','a@example.test',0),('actor-b','b@example.test',0);
             INSERT INTO public.user_roles(user_id,role) VALUES
               ('actor-a','user'),('actor-b','user');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES('bot-1','Bot 1','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);
             INSERT INTO public.threads(
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_message_seq
             ) VALUES(
               '550e8400-e29b-41d4-a716-446655440000','tenant-a','dep-a','actor-a',
               'direct_bot','bot-1',1
             );
             INSERT INTO public.thread_memberships(thread_id,user_id)
               VALUES('550e8400-e29b-41d4-a716-446655440000','actor-a');
             INSERT INTO public.runs(
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at
             ) VALUES('run-memory','550e8400-e29b-41d4-a716-446655440000','bot-1','actor-a',
                      true,'running',1,clock_timestamp());
             INSERT INTO public.thread_leases(
               thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
             ) VALUES('550e8400-e29b-41d4-a716-446655440000','memory-runtime',1,
                      clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp());
             INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,actor_id)
               VALUES('message-1','550e8400-e29b-41d4-a716-446655440000',0,'user',
                      '{\"text\":\"The office is closed Friday\"}'::jsonb,
                      'The office is closed Friday','actor-a');
             UPDATE public.messages SET run_id='run-memory' WHERE message_id='message-1';",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn write_control_blocks_gui_tool_and_correction_but_never_erasure() {
    let admin = admin_config("write_control_blocks_gui_tool_and_correction_but_never_erasure");
    with_temp_database(&admin, "memorycontrol", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let tenant = TenantId::new("tenant-a");
            let actor = ActorId::new("actor-a");
            let scope = MemoryControlRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                tenant: tenant.clone(),
                actor: actor.clone(),
            };
            if !store
                .memory_control(scope.clone())
                .await
                .map_err(|error| error.to_string())?
                .writes_enabled
            {
                return Err("absent control must default enabled".to_owned());
            }
            let existing = store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RememberMemory {
                        memory_kind: MemoryKind::Preference,
                        scope: MemoryScope::User,
                        content: "Prefer concise answers".to_owned(),
                        tags: vec!["style".to_owned()],
                        sensitivity: MemorySensitivity::Normal,
                        source: None,
                        expires_at: None,
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            let disabled = store
                .update_memory_control(UpdateMemoryControlRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    update: UpdateMemoryControl {
                        writes_enabled: false,
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if disabled.writes_enabled
                || store
                    .memory_control(scope)
                    .await
                    .map_err(|error| error.to_string())?
                    .writes_enabled
            {
                return Err("disabled control did not persist".to_owned());
            }
            if store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: fact(),
                })
                .await
                != Err(MemoryAdministrationError::WritesDisabled)
            {
                return Err("disabled GUI remember must fail before insert".to_owned());
            }
            if store
                .correct(CorrectMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: existing.memory_id.clone(),
                    correction: CorrectMemory {
                        content: "Prefer detailed answers".to_owned(),
                        tags: Vec::new(),
                        sensitivity: MemorySensitivity::Normal,
                        expires_at: None,
                    },
                })
                .await
                != Err(MemoryAdministrationError::WritesDisabled)
            {
                return Err("disabled correction must not create a replacement".to_owned());
            }
            let tool_arguments = parse_remember_tool_arguments(&serde_json::json!({
                "memoryKind":"preference",
                "scope":"user",
                "content":"Remember from tool",
                "tags":[],
                "sensitivity":"normal"
            }))
            .map_err(|error| error.to_string())?;
            if store
                .remember_from_tool(RememberToolMemoryRequest {
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    auth_generation: AuthGeneration::new(0),
                    run: RunId::new("run-memory"),
                    bot: BotId::new("bot-1"),
                    thread: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
                    arguments: tool_arguments,
                })
                .await
                != Err(MemoryAdministrationError::WritesDisabled)
            {
                return Err("disabled remember tool must fail before insert".to_owned());
            }
            let deleted = store
                .mutate(MutateMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: existing.memory_id,
                    mutation: MemoryMutation::Delete,
                })
                .await
                .map_err(|error| error.to_string())?;
            if deleted.status != MemoryStatus::Deleted || deleted.content.is_some() {
                return Err("disable must never block user erasure".to_owned());
            }
            store
                .update_memory_control(UpdateMemoryControlRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    update: UpdateMemoryControl {
                        writes_enabled: true,
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: fact(),
                })
                .await
                .map_err(|error| error.to_string())?;

            let other = store
                .memory_control(MemoryControlRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: TenantId::new("tenant-b"),
                    actor,
                })
                .await
                .map_err(|error| error.to_string())?;
            if !other.writes_enabled {
                return Err("memory control crossed tenant scope".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

fn fact() -> RememberMemory {
    RememberMemory {
        memory_kind: MemoryKind::Fact,
        scope: MemoryScope::Thread {
            thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
        },
        content: "The office is closed Friday".to_owned(),
        tags: vec![
            "schedule".to_owned(),
            "office".to_owned(),
            "schedule".to_owned(),
        ],
        sensitivity: MemorySensitivity::Normal,
        source: Some(MemorySource {
            thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
            message_id: "message-1".to_owned(),
        }),
        expires_at: None,
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn explicit_journey_binds_scope_pages_corrects_and_erases_content() {
    let admin = admin_config("explicit_journey_binds_scope_pages_corrects_and_erases_content");
    with_temp_database(&admin, "memoryjourney", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let tenant = TenantId::new("tenant-a");
            let actor = ActorId::new("actor-a");
            let other = ActorId::new("actor-b");

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let before: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.memories", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if before != 0 {
                return Err("仅写 message 不得触发 background memory".to_owned());
            }
            drop(client);

            let created = store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: fact(),
                })
                .await
                .map_err(|error| error.to_string())?;
            if created.owner_user_id != "actor-a"
                || created.created_by != "actor-a"
                || created.origin != openbot_contracts::memory::MemoryOrigin::UserAction
                || created.tags != ["office", "schedule"]
            {
                return Err(format!("remember authority/tag/origin 错误：{created:?}"));
            }

            let mut stolen = fact();
            stolen.source.as_mut().unwrap().message_id = "missing".to_owned();
            if store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: other.clone(),
                    input: stolen,
                })
                .await
                != Err(MemoryAdministrationError::NotVisible)
            {
                return Err("不可见 source 不得创建 memory".to_owned());
            }

            let preference = store
                .remember(RememberMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RememberMemory {
                        memory_kind: MemoryKind::Preference,
                        scope: MemoryScope::User,
                        content: "Prefer concise answers".to_owned(),
                        tags: vec!["style".to_owned()],
                        sensitivity: MemorySensitivity::Sensitive,
                        source: None,
                        expires_at: None,
                    },
                })
                .await
                .map_err(|error| error.to_string())?;

            let thread_recall = store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RecallMemories {
                        query: "office Friday".to_owned(),
                        tags: vec!["office".to_owned()],
                        bot_id: None,
                        thread_id: Some(ThreadId::new("550e8400-e29b-41d4-a716-446655440000")),
                        limit: Some(10),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if thread_recall.memories.len() != 1
                || thread_recall.memories[0].memory_id != created.memory_id
            {
                return Err(format!("thread-scoped fact recall 错误：{thread_recall:?}"));
            }
            let wrong_tag_recall = store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RecallMemories {
                        query: "office Friday".to_owned(),
                        tags: vec!["missing".to_owned()],
                        bot_id: None,
                        thread_id: Some(ThreadId::new("550e8400-e29b-41d4-a716-446655440000")),
                        limit: Some(10),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if !wrong_tag_recall.memories.is_empty() {
                return Err("structured tag 必须精确收窄 FTS recall".to_owned());
            }
            let no_thread = store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RecallMemories {
                        query: "office Friday".to_owned(),
                        tags: Vec::new(),
                        bot_id: None,
                        thread_id: None,
                        limit: Some(10),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if !no_thread.memories.is_empty() {
                return Err("没有 thread context 时不得扩大召回 thread memory".to_owned());
            }
            let user_recall = store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    input: RecallMemories {
                        query: "concise answers".to_owned(),
                        tags: vec!["style".to_owned()],
                        bot_id: None,
                        thread_id: None,
                        limit: Some(10),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if user_recall.memories.len() != 1
                || user_recall.memories[0].memory_id != preference.memory_id
            {
                return Err(format!("user-scope recall 错误：{user_recall:?}"));
            }
            if store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: tenant.clone(),
                    actor: other.clone(),
                    input: RecallMemories {
                        query: "office".to_owned(),
                        tags: Vec::new(),
                        bot_id: None,
                        thread_id: Some(ThreadId::new("550e8400-e29b-41d4-a716-446655440000")),
                        limit: Some(10),
                    },
                })
                .await
                != Err(MemoryAdministrationError::NotVisible)
            {
                return Err("不可见 thread context 必须在 recall 前拒绝".to_owned());
            }

            let first_page = store
                .list_memories(MemoryPageRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    cursor: None,
                    limit: 1,
                })
                .await
                .map_err(|error| error.to_string())?;
            if first_page.memories.len() != 1 || first_page.next_cursor.is_none() {
                return Err(format!("memory 第一页/next cursor 错误：{first_page:?}"));
            }
            let second_page = store
                .list_memories(MemoryPageRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    cursor: first_page.next_cursor,
                    limit: 1,
                })
                .await
                .map_err(|error| error.to_string())?;
            if second_page.memories.len() != 1 || second_page.next_cursor.is_some() {
                return Err(format!("memory 第二页错误：{second_page:?}"));
            }
            let invisible = store
                .list_memories(MemoryPageRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: other.clone(),
                    cursor: None,
                    limit: 10,
                })
                .await
                .map_err(|error| error.to_string())?;
            if !invisible.memories.is_empty() {
                return Err("另一 actor 不得列出 owner memory".to_owned());
            }

            let corrected = store
                .correct(CorrectMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: preference.memory_id.clone(),
                    correction: CorrectMemory {
                        content: "Prefer detailed answers".to_owned(),
                        tags: vec!["style".to_owned(), "response".to_owned()],
                        sensitivity: MemorySensitivity::Normal,
                        expires_at: None,
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if corrected.supersedes_id.as_deref() != Some(&preference.memory_id)
                || corrected.status != MemoryStatus::Active
            {
                return Err(format!("correction/supersedes 错误：{corrected:?}"));
            }
            if store
                .correct(CorrectMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: preference.memory_id,
                    correction: CorrectMemory {
                        content: "again".to_owned(),
                        tags: Vec::new(),
                        sensitivity: MemorySensitivity::Normal,
                        expires_at: None,
                    },
                })
                .await
                != Err(MemoryAdministrationError::Conflict)
            {
                return Err("superseded memory 不得再次 correct".to_owned());
            }

            let forbidden = store
                .mutate(MutateMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: corrected.memory_id.clone(),
                    mutation: MemoryMutation::Forbid,
                })
                .await
                .map_err(|error| error.to_string())?;
            if forbidden.status != MemoryStatus::Forbidden || forbidden.content.is_some() {
                return Err("forbid 必须擦除 content".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let events_before: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.memory_events WHERE memory_id=$1",
                    &[&corrected.memory_id],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            store
                .mutate(MutateMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    memory_id: corrected.memory_id.clone(),
                    mutation: MemoryMutation::Forbid,
                })
                .await
                .map_err(|error| error.to_string())?;
            let deleted = store
                .mutate(MutateMemoryRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant,
                    actor,
                    memory_id: corrected.memory_id.clone(),
                    mutation: MemoryMutation::Delete,
                })
                .await
                .map_err(|error| error.to_string())?;
            if deleted.status != MemoryStatus::Deleted || deleted.content.is_some() {
                return Err("delete 必须保持 content 擦除".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let events_after: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.memory_events WHERE memory_id=$1",
                    &[&corrected.memory_id],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if events_after != events_before + 1 {
                return Err(format!(
                    "重复 forbid 必须零事件，随后 delete 恰加一：{events_before}->{events_after}"
                ));
            }
            drop(client);
            let after_delete = store
                .recall(RecallMemoriesRequest {
                    auth_generation: AuthGeneration::new(0),
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
                    tenant: TenantId::new("tenant-a"),
                    actor: ActorId::new("actor-a"),
                    input: RecallMemories {
                        query: "detailed answers".to_owned(),
                        tags: Vec::new(),
                        bot_id: None,
                        thread_id: None,
                        limit: Some(10),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if !after_delete.memories.is_empty() {
                return Err("deleted/superseded memory 不得 recall".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn memory_event_failure_rolls_back_the_memory_row() {
    let admin = admin_config("memory_event_failure_rolls_back_the_memory_row");
    with_temp_database(&admin, "memoryrollback", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION public.fail_memory_event() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN RAISE EXCEPTION 'synthetic-memory-event-failure'; END
                     $$;
                     CREATE TRIGGER fail_memory_event BEFORE INSERT ON public.memory_events
                       FOR EACH ROW EXECUTE FUNCTION public.fail_memory_event();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let store = PostgresMemoryAdministration::new(pool.clone());
            if store
                .remember(RememberMemoryRequest { auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    tenant: TenantId::new("tenant-a"),
                    actor: ActorId::new("actor-a"),
                    input: fact(),
                })
                .await
                != Err(MemoryAdministrationError::Unavailable)
            {
                return Err("memory event 末段失败必须报 unavailable".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let count: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.memories", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if count != 0 {
                return Err(format!("memory event 失败后 memories 仍有 {count} 行"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
