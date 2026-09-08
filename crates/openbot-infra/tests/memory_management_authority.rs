//! Current-actor Memory management fencing, proved on an isolated synthetic PostgreSQL instance.
//! Table locks below are test barriers only; production acquires user SHARE, then data/event locks.

mod harness;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    ApplicationService, MemoryAdministration, MemoryAdministrationError, OpenBotApplication,
    PeopleAdministration, RememberMemoryRequest, RememberToolMemory, RememberToolMemoryRequest,
    parse_remember_tool_arguments,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::memory::{
    CorrectMemory, MemoryKind, MemoryMutation, MemoryScope, MemorySensitivity, MemorySource,
    RememberMemory, UpdateMemoryControl,
};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use tokio::task::JoinSet;

const THREAD: &str = "550e8400-e29b-41d4-a716-446655440000";
const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum Operation {
    Control,
    UpdateControl,
    List,
    Remember,
    Correct,
    Forbid,
    Delete,
    Tool,
}

const OPERATIONS: [Operation; 8] = [
    Operation::Control,
    Operation::UpdateControl,
    Operation::List,
    Operation::Remember,
    Operation::Correct,
    Operation::Forbid,
    Operation::Delete,
    Operation::Tool,
];

fn auth(actor: &str, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("dep-a"),
        TenantId::new("tenant-a"),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_role(Role::User)
    .build()
}

fn input() -> RememberMemory {
    RememberMemory {
        memory_kind: MemoryKind::Fact,
        scope: MemoryScope::User,
        content: "managementauthority synthetic saved fact".into(),
        tags: Vec::new(),
        sensitivity: MemorySensitivity::Normal,
        source: Some(MemorySource {
            thread_id: ThreadId::new(THREAD),
            message_id: "message-memory-authority".into(),
        }),
        expires_at: None,
    }
}

fn tool_request(actor: &str, generation: u64) -> RememberToolMemoryRequest {
    RememberToolMemoryRequest {
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new(actor),
        auth_generation: AuthGeneration::new(generation),
        run: RunId::new("run-memory-authority"),
        bot: BotId::new("bot-a"),
        thread: ThreadId::new(THREAD),
        arguments: parse_remember_tool_arguments(&serde_json::json!({
            "memoryKind":"preference", "scope":"user", "content":"synthetic tool preference",
            "tags":[], "sensitivity":"normal"
        }))
        .expect("closed synthetic remember arguments"),
    }
}

async fn execute(
    pool: &Pool,
    operation: Operation,
    actor: &str,
    generation: u64,
    memory_id: &str,
) -> Result<(), AppError> {
    let store = PostgresMemoryAdministration::new(pool.clone());
    if matches!(operation, Operation::Tool) {
        return store
            .remember_from_tool(tool_request(actor, generation))
            .await
            .map(|_| ())
            .map_err(MemoryAdministrationError::into_app_error);
    }
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())).with_memory(store));
    let command = match operation {
        Operation::Control => AppCommand::GetMemoryControl,
        Operation::UpdateControl => AppCommand::UpdateMemoryControl(UpdateMemoryControl {
            writes_enabled: true,
        }),
        Operation::List => AppCommand::ListMemories {
            cursor: None,
            limit: Some(100),
        },
        Operation::Remember => AppCommand::RememberMemory(input()),
        Operation::Correct => AppCommand::CorrectMemory {
            memory_id: memory_id.into(),
            correction: CorrectMemory {
                content: "synthetic corrected preference".into(),
                tags: Vec::new(),
                sensitivity: MemorySensitivity::Normal,
                expires_at: None,
            },
        },
        Operation::Forbid | Operation::Delete => AppCommand::MutateMemory {
            memory_id: memory_id.into(),
            mutation: if matches!(operation, Operation::Forbid) {
                MemoryMutation::Forbid
            } else {
                MemoryMutation::Delete
            },
        },
        Operation::Tool => unreachable!("tool dispatched through its existing authorized port"),
    };
    let reply = application
        .execute(auth(actor, generation), command)
        .await?;
    let matches = match operation {
        Operation::Control | Operation::UpdateControl => {
            matches!(reply, AppReply::MemoryControl(_))
        }
        Operation::List => matches!(reply, AppReply::Memories(_)),
        _ => matches!(reply, AppReply::Memory(_)),
    };
    assert!(matches, "wrong Memory reply");
    Ok(())
}

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

async fn seed(pool: &Pool, generation: u64) -> Result<String, String> {
    PostgresMemoryAdministration::new(pool.clone())
        .remember(RememberMemoryRequest {
            auth_generation: AuthGeneration::new(generation),
            tenant: TenantId::new("tenant-a"),
            actor: ActorId::new("actor-a"),
            input: input(),
        })
        .await
        .map(|record| record.memory_id)
        .map_err(|e| e.to_string())
}

async fn provision(pool: &Pool) -> Result<String, String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&client).await.map_err(|e| e.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|e| e.to_string())?;
    client.batch_execute(&format!(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
         ('actor-a','a@example.test',0),('actor-admin','admin@example.test',0);
         INSERT INTO public.user_roles(user_id,role) VALUES ('actor-a','user'),('actor-admin','admin');
         INSERT INTO public.agents(id,name,type,configuration) VALUES ('bot-a','A','built_in','{{}}');
         INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
         VALUES ('bot-a',NULL,'A','synthetic','a','public');
         INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id)
         VALUES ('{THREAD}','tenant-a','dep-a','actor-a','direct_bot','bot-a');
         INSERT INTO public.thread_memberships(thread_id,user_id) VALUES ('{THREAD}','actor-a');
         INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at)
         VALUES ('run-memory-authority','{THREAD}','bot-a','actor-a',true,'running',1,clock_timestamp());
         INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,actor_id,run_id)
         VALUES ('message-memory-authority','{THREAD}',0,'user','{{\"text\":\"synthetic source\"}}','synthetic source','actor-a','run-memory-authority');
         UPDATE public.threads SET next_message_seq=1 WHERE thread_id='{THREAD}';"
    )).await.map_err(|e|e.to_string())?;
    drop(client);
    seed(pool, 0).await
}

async fn fixture<F, Fut>(name: &'static str, tag: &str, body: F)
where
    F: FnOnce(Pool, DatabaseConfig, String) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    with_temp_database(&admin_config(name), tag, |config| async move {
        let config = config.with_max_pool_size(6);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            let memory_id = provision(&pool).await?;
            body(pool.clone(), config, memory_id).await
        }
        .await;
        pool.close();
        result
    })
    .await;
}

// Whole-row snapshots catch silent content/status changes as well as extra Memory events,
// control writes and audit records. These values stay in assertions and are never logged.
async fn state(pool: &Pool) -> Result<serde_json::Value, String> {
    pool.get().await.map_err(|e|e.to_string())?
        .query_one(
            "SELECT jsonb_build_object(
             'memories',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY memory_id),'[]') FROM public.memories m),
             'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq),'[]') FROM public.memory_events e),
             'controls',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY tenant_id,actor_user_id),'[]') FROM public.user_memory_controls c),
             'audit',(SELECT count(*) FROM public.audit_events))",
            &[],
        ).await.map_err(|e|e.to_string())?
        .try_get(0).map_err(|e|e.to_string())
}

async fn assert_all_rejected(
    pool: &Pool,
    actor: &str,
    generation: u64,
    id: &str,
) -> Result<(), String> {
    let before = state(pool).await?;
    for operation in OPERATIONS {
        require(
            matches!(
                execute(pool, operation, actor, generation, id).await,
                Err(AppError::NotVisible)
            ),
            "invalid actor reached a Memory read or write",
        )?;
    }
    require(
        state(pool).await? == before,
        "rejected operation changed data/events/control/audit",
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn all_management_and_tool_operations_reject_old_actor_after_people_revoke_and_restore() {
    fixture(
        "management actual revoke",
        "mgmtrevoke",
        |pool, _, id| async move {
            execute(&pool, Operation::List, "actor-a", 0, &id)
                .await
                .map_err(|e| e.to_string())?;
            let people = PostgresPeopleAdministration::new(
                pool.clone(),
                None,
                b"synthetic-management-audit-key".to_vec(),
            )
            .map_err(|e| e.to_string())?;
            people
                .change_access(&ActorId::new("actor-admin"), &ActorId::new("actor-a"), true)
                .await
                .map_err(|e| e.to_string())?;
            assert_all_rejected(&pool, "actor-a", 0, &id).await?;
            // The same saved data remain inaccessible even when the old actor is restored.
            people
                .change_access(
                    &ActorId::new("actor-admin"),
                    &ActorId::new("actor-a"),
                    false,
                )
                .await
                .map_err(|e| e.to_string())?;
            assert_all_rejected(&pool, "actor-a", 0, &id).await?;
            for operation in OPERATIONS {
                let fresh = seed(&pool, 1).await?;
                execute(&pool, operation, "actor-a", 1, &fresh)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn missing_actor_role_deny_and_generation_are_independent_not_visible_checks() {
    fixture("management predicates", "mgmtpred", |pool, _, id| async move {
        assert_all_rejected(&pool,"missing-actor",0,&id).await?;
        for generation in [1,u64::MAX] { assert_all_rejected(&pool,"actor-a",generation,&id).await?; }
        let client=pool.get().await.map_err(|e|e.to_string())?;
        client.batch_execute("DELETE FROM public.user_roles WHERE user_id='actor-a'").await.map_err(|e|e.to_string())?;
        assert_all_rejected(&pool,"actor-a",0,&id).await?;
        client.batch_execute("INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user'); INSERT INTO public.revoked_access(email,revoked_by) VALUES('a@example.test','actor-admin')")
            .await.map_err(|e|e.to_string())?;
        assert_all_rejected(&pool,"actor-a",0,&id).await?;
        client.batch_execute("DELETE FROM public.revoked_access WHERE email='a@example.test'; UPDATE public.users SET auth_generation=NULL WHERE id='actor-a'")
            .await.map_err(|e|e.to_string())?;
        for operation in OPERATIONS {
            let fresh=seed(&pool,0).await?;
            execute(&pool,operation,"actor-a",0,&fresh).await.map_err(|e|e.to_string())?;
        }
        Ok(())
    }).await;
}

async fn actor_pool(config: &DatabaseConfig, name: &'static str) -> Result<(Pool, i32), String> {
    let pool = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(name),
    )
    .await
    .map_err(|e| e.to_string())?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let pid = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    drop(client);
    Ok((pool, pid))
}

async fn blocked_by(
    observer: &tokio_postgres::Client,
    blocked: i32,
    blocker: i32,
) -> Result<(), String> {
    tokio::time::timeout(WAIT, async {
        loop {
            let found: bool = observer
                .query_one("SELECT $2=ANY(pg_blocking_pids($1))", &[&blocked, &blocker])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            if found {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "expected user/table lock dependency not observed".to_owned())?
}

async fn next<T: Send + 'static>(tasks: &mut JoinSet<T>) -> Result<T, String> {
    tokio::time::timeout(WAIT, tasks.join_next())
        .await
        .map_err(|_| "operation did not finish after lock release".to_owned())?
        .ok_or_else(|| "missing worker task".to_owned())?
        .map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn revoker_user_update_wins_before_every_operation_and_prevents_all_effects() {
    fixture(
        "management revoker first",
        "mgmtfirst",
        |pool, config, id| async move {
            let (worker_pool, worker_pid) = actor_pool(&config, "memory-management-worker").await?;
            let observer = pool.get().await.map_err(|e| e.to_string())?;
            let mut revoker = pool.get().await.map_err(|e| e.to_string())?;
            let revoker_pid: i32 = revoker
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            for (generation, operation) in OPERATIONS.into_iter().enumerate() {
                let before = state(&pool).await?;
                let tx = revoker.transaction().await.map_err(|e| e.to_string())?;
                tx.execute(
                    "UPDATE public.users SET auth_generation=auth_generation+1 WHERE id='actor-a'",
                    &[],
                )
                .await
                .map_err(|e| e.to_string())?;
                let mut tasks = JoinSet::new();
                let (work, id) = (worker_pool.clone(), id.clone());
                tasks.spawn(async move {
                    execute(&work, operation, "actor-a", generation as u64, &id).await
                });
                blocked_by(&observer, worker_pid, revoker_pid).await?;
                tx.commit().await.map_err(|e| e.to_string())?;
                require(
                    matches!(next(&mut tasks).await?, Err(AppError::NotVisible)),
                    "old generation survived user lock wait",
                )?;
                require(
                    state(&pool).await? == before,
                    "revoke-first operation changed Memory state",
                )?;
            }
            execute(
                &worker_pool,
                Operation::List,
                "actor-a",
                OPERATIONS.len() as u64,
                &id,
            )
            .await
            .map_err(|e| e.to_string())?;
            worker_pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn every_operation_holds_user_share_while_reading_or_committing_memory_and_events() {
    fixture("management operation first", "mgmtheld", |pool,config,_|async move {
        let (worker_pool,worker_pid)=actor_pool(&config,"memory-management-worker").await?;
        let (revoker_pool,revoker_pid)=actor_pool(&config,"memory-management-revoker").await?;
        let observer=pool.get().await.map_err(|e|e.to_string())?;
        let mut blocker=pool.get().await.map_err(|e|e.to_string())?;
        let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        for (generation,operation) in OPERATIONS.into_iter().enumerate() {
            let id=seed(&pool,generation as u64).await?;
            let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
            // Writes with events are paused after their data mutation but before their event/commit.
            let sql=match operation {
                Operation::Control|Operation::UpdateControl=>"LOCK TABLE public.user_memory_controls IN ACCESS EXCLUSIVE MODE",
                Operation::List=>"LOCK TABLE public.memories IN ACCESS EXCLUSIVE MODE",
                _=>"LOCK TABLE public.memory_events IN ACCESS EXCLUSIVE MODE",
            };
            tx.batch_execute(sql).await.map_err(|e|e.to_string())?;
            let mut workers=JoinSet::new();
            let work=worker_pool.clone();
            workers.spawn(async move {execute(&work,operation,"actor-a",generation as u64,&id).await});
            blocked_by(&observer,worker_pid,blocker_pid).await?;
            let mut revokers=JoinSet::new();
            let revoker=revoker_pool.clone();
            revokers.spawn(async move {
                let client=revoker.get().await.map_err(|e|e.to_string())?;
                client.execute("UPDATE public.users SET auth_generation=auth_generation+1 WHERE id='actor-a'",&[])
                    .await.map_err(|e|e.to_string()).map(|_|())
            });
            blocked_by(&observer,revoker_pid,worker_pid).await?;
            tx.commit().await.map_err(|e|e.to_string())?;
            next(&mut workers).await?.map_err(|e|e.to_string())?;
            next(&mut revokers).await??;
        }
        worker_pool.close(); revoker_pool.close();
        Ok(())
    }).await;
}
