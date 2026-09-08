//! Recall actor fencing and context snapshot linearization on isolated PostgreSQL.
//! Synthetic fixtures only; deliberate locks make ordering observable without timing guesses.

mod harness;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    ApplicationService, MemoryAdministration, MemoryAdministrationError, OpenBotApplication,
    PeopleAdministration, RecallMemoriesRequest, RememberMemoryRequest,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use openbot_contracts::memory::{
    MemoryKind, MemoryRecall, MemoryScope, MemorySensitivity, RecallMemories, RememberMemory,
};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use tokio::task::JoinSet;

const DIRECT: &str = "550e8400-e29b-41d4-a716-446655440000";
const CHANNEL: &str = "550e8400-e29b-41d4-a716-446655440001";
const SAME_PACKAGE: &str = "650e8400-e29b-41d4-a716-446655440000";
const OTHER_PACKAGE: &str = "650e8400-e29b-41d4-a716-446655440001";
const WAIT: Duration = Duration::from_secs(5);

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn request() -> RecallMemoriesRequest {
    RecallMemoriesRequest {
        auth_generation: AuthGeneration::new(0),
        deployment: DeploymentId::new("dep-a"),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        input: RecallMemories {
            query: "recallauthority".to_owned(),
            tags: Vec::new(),
            bot_id: None,
            thread_id: None,
            limit: Some(100),
        },
    }
}

fn auth(generation: u64) -> AuthContext {
    // Synthetic harness has provisioned this exact actor/tenant/deployment and generation.
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("dep-a"),
        TenantId::new("tenant-a"),
        ActorId::new("actor-a"),
        AuthGeneration::new(generation),
        false,
    )
    .with_role(Role::User)
    .build()
}

async fn provision(pool: &Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&client).await.map_err(|e| e.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|e| e.to_string())?;
    client.batch_execute(&format!(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
         ('actor-a','a@example.test',0),('actor-b','b@example.test',0),('actor-admin','admin@example.test',0);
         INSERT INTO public.user_roles(user_id,role) VALUES
         ('actor-a','user'),('actor-b','user'),('actor-admin','admin');
         INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES
         ('{SAME_PACKAGE}','tenant-a','/synthetic-a',repeat('a',64)),
         ('{OTHER_PACKAGE}','tenant-b','/synthetic-b',repeat('b',64));
         INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
         ('bot-a','A','built_in','{{}}','{SAME_PACKAGE}'),
         ('bot-private','P','built_in','{{}}',NULL),('bot-other','O','built_in','{{}}','{OTHER_PACKAGE}');
         INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES
         ('bot-a',NULL,'A','synthetic','a','public'),
         ('bot-private','actor-b','P','synthetic','p','private'),
         ('bot-other',NULL,'O','synthetic','o','public');
         INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups,package_id)
         VALUES('channel-a','A','','{{}}','{{all}}','{SAME_PACKAGE}');
         INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel-a','actor-a');
         INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id) VALUES
         ('{DIRECT}','tenant-a','dep-a','actor-a','direct_bot','bot-a'),
         ('{CHANNEL}','tenant-a','dep-a','actor-a','channel','channel-a');
         INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
         ('{DIRECT}','actor-a'),('{CHANNEL}','actor-a');"
    )).await.map_err(|e| e.to_string())?;
    drop(client);
    let store = PostgresMemoryAdministration::new(pool.clone());
    for scope in [
        MemoryScope::User,
        MemoryScope::Bot {
            bot_id: BotId::new("bot-a"),
        },
        MemoryScope::Thread {
            thread_id: ThreadId::new(DIRECT),
        },
        MemoryScope::Thread {
            thread_id: ThreadId::new(CHANNEL),
        },
    ] {
        store
            .remember(RememberMemoryRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
                input: RememberMemory {
                    memory_kind: MemoryKind::Preference,
                    scope,
                    content: "recallauthority synthetic preference".to_owned(),
                    tags: Vec::new(),
                    sensitivity: MemorySensitivity::Normal,
                    source: None,
                    expires_at: None,
                },
            })
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn fixture<F, Fut>(name: &'static str, tag: &str, body: F)
where
    F: FnOnce(Pool, DatabaseConfig) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    with_temp_database(&admin_config(name), tag, |config| async move {
        let config = config.with_max_pool_size(6);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            provision(&pool).await?;
            body(pool.clone(), config).await
        }
        .await;
        pool.close();
        result
    })
    .await;
}

async fn count(
    store: &PostgresMemoryAdministration,
    req: RecallMemoriesRequest,
) -> Result<usize, String> {
    store
        .recall(req)
        .await
        .map(|r| r.memories.len())
        .map_err(|e| e.to_string())
}

async fn recall_pool(config: &DatabaseConfig) -> Result<(Pool, i32), String> {
    let pool = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name("memory-recall-authority-reader"),
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
    .map_err(|_| "expected PostgreSQL lock dependency was not observed".to_owned())?
}

async fn next_read(
    tasks: &mut JoinSet<Result<MemoryRecall, MemoryAdministrationError>>,
) -> Result<Result<MemoryRecall, MemoryAdministrationError>, String> {
    tokio::time::timeout(WAIT, tasks.join_next())
        .await
        .map_err(|_| "recall failed to finish after lock release".to_owned())?
        .ok_or_else(|| "missing recall task".to_owned())?
        .map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn old_application_auth_is_rejected_after_people_revoke_and_restore() {
    fixture("memory actor revoke", "memoryauth", |pool, _| async move {
        let store = PostgresMemoryAdministration::new(pool.clone());
        let app: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())).with_memory(store));
        let old = auth(0);
        let positive = app
            .execute(old.clone(), AppCommand::RecallMemories(request().input))
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(positive, AppReply::MemoryRecall(r) if r.memories.len()==1),
            "current actor positive control failed",
        )?;
        let people = PostgresPeopleAdministration::new(
            pool.clone(),
            None,
            b"synthetic-memory-audit-key".to_vec(),
        )
        .map_err(|e| e.to_string())?;
        people
            .change_access(&ActorId::new("actor-admin"), &ActorId::new("actor-a"), true)
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(
                app.execute(old.clone(), AppCommand::RecallMemories(request().input))
                    .await,
                Err(AppError::NotVisible)
            ),
            "pre-revocation auth recalled memories after revoke commit",
        )?;
        people
            .change_access(
                &ActorId::new("actor-admin"),
                &ActorId::new("actor-a"),
                false,
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(
                app.execute(old, AppCommand::RecallMemories(request().input))
                    .await,
                Err(AppError::NotVisible)
            ),
            "restore revived the old generation",
        )?;
        let current = app
            .execute(auth(1), AppCommand::RecallMemories(request().input))
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(current, AppReply::MemoryRecall(r) if r.memories.len()==1),
            "restored current generation did not recall",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn missing_role_deny_and_generation_mismatch_are_independent_fail_closed_checks() {
    fixture("memory auth predicates", "memorypred", |pool, _| async move {
        let store = PostgresMemoryAdministration::new(pool.clone());
        require(count(&store, request()).await?==1, "initial recall failed")?;
        for generation in [1, u64::MAX] {
            let mut req=request(); req.auth_generation=AuthGeneration::new(generation);
            require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible), "invalid generation accepted")?;
        }
        let client=pool.get().await.map_err(|e|e.to_string())?;
        client.batch_execute("DELETE FROM public.user_roles WHERE user_id='actor-a'").await.map_err(|e|e.to_string())?;
        require(store.recall(request()).await==Err(MemoryAdministrationError::NotVisible), "missing role accepted")?;
        client.batch_execute("INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user'); INSERT INTO public.revoked_access(email,revoked_by) VALUES('a@example.test','actor-admin')").await.map_err(|e|e.to_string())?;
        require(store.recall(request()).await==Err(MemoryAdministrationError::NotVisible), "deny accepted without generation change")?;
        client.batch_execute("DELETE FROM public.revoked_access WHERE email='a@example.test'").await.map_err(|e|e.to_string())?;
        require(count(&store, request()).await?==1, "current actor did not recover")
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn context_authority_is_independent_of_results_and_checks_deployment_and_package() {
    fixture("memory explicit context", "memoryctx", |pool, _| async move {
        let store=PostgresMemoryAdministration::new(pool.clone());
        let mut req=request(); req.input.bot_id=Some(BotId::new("bot-a")); req.input.thread_id=Some(ThreadId::new(DIRECT));
        require(count(&store,req.clone()).await?==3,"scope union did not recall exact user/bot/thread memories")?;
        req.input.query="no-match".to_owned(); require(count(&store,req.clone()).await?==0,"visible empty context was not an empty list")?;
        req.deployment=DeploymentId::new("different-deployment");
        require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"wrong deployment did not reject an empty recall")?;
        let mut req=request(); req.tenant=TenantId::new("tenant-b"); req.input.thread_id=Some(ThreadId::new(DIRECT));
        require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"wrong thread tenant was accepted")?;
        for bot in ["missing", "bot-private", "bot-other"] {
            let mut req=request(); req.input.bot_id=Some(BotId::new(bot)); req.input.query="no-match".to_owned();
            require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"invisible Bot was inferred from matching memory rows")?;
        }
        let client=pool.get().await.map_err(|e|e.to_string())?;
        let mut req=request(); req.input.bot_id=Some(BotId::new("bot-a"));
        client.batch_execute("UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='bot-a'").await.map_err(|e|e.to_string())?;
        require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"soft-deleted Bot remained visible")?;
        let mut req=request(); req.input.thread_id=Some(ThreadId::new(DIRECT));
        client.execute("DELETE FROM public.thread_memberships WHERE thread_id=$1 AND user_id='actor-a'",&[&DIRECT]).await.map_err(|e|e.to_string())?;
        require(store.recall(req.clone()).await==Err(MemoryAdministrationError::NotVisible),"revoked direct-thread membership remained visible")?;
        client.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'actor-a')",&[&DIRECT]).await.map_err(|e|e.to_string())?;
        client.execute("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id=$1",&[&DIRECT]).await.map_err(|e|e.to_string())?;
        require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"soft-deleted thread remained visible")
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn channel_context_uses_current_channel_membership_and_channel_package_tenant() {
    fixture("memory channel context", "memorychannel", |pool,_|async move {
        let store=PostgresMemoryAdministration::new(pool.clone()); let mut req=request(); req.input.thread_id=Some(ThreadId::new(CHANNEL));
        require(count(&store,req.clone()).await?==2,"channel positive failed")?;
        let client=pool.get().await.map_err(|e|e.to_string())?;
        client.execute("DELETE FROM public.thread_memberships WHERE thread_id=$1",&[&CHANNEL]).await.map_err(|e|e.to_string())?;
        require(count(&store,req.clone()).await?==2,"current channel member required stale materialized tm")?;
        client.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'actor-a')",&[&CHANNEL]).await.map_err(|e|e.to_string())?;
        client.batch_execute("DELETE FROM public.channel_memberships WHERE channel_id='channel-a'").await.map_err(|e|e.to_string())?;
        require(store.recall(req.clone()).await==Err(MemoryAdministrationError::NotVisible),"stale tm bypassed channel membership revocation")?;
        client.batch_execute(&format!("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel-a','actor-a'); UPDATE public.channels SET package_id='{OTHER_PACKAGE}' WHERE id='channel-a'")).await.map_err(|e|e.to_string())?;
        require(store.recall(req).await==Err(MemoryAdministrationError::NotVisible),"foreign package channel remained visible")
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn actor_update_lock_wins_before_recall_and_old_generation_is_rejected_after_wait() {
    fixture(
        "memory revoke first",
        "memoryfirst",
        |pool, config| async move {
            let (reader_pool, reader_pid) = recall_pool(&config).await?;
            let mut revoker = pool.get().await.map_err(|e| e.to_string())?;
            let revoker_pid: i32 = revoker
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            let tx = revoker.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'")
                .await
                .map_err(|e| e.to_string())?;
            let mut tasks = JoinSet::new();
            let store = PostgresMemoryAdministration::new(reader_pool.clone());
            tasks.spawn(async move { store.recall(request()).await });
            let observer = pool.get().await.map_err(|e| e.to_string())?;
            blocked_by(&observer, reader_pid, revoker_pid).await?;
            tx.commit().await.map_err(|e| e.to_string())?;
            require(
                next_read(&mut tasks).await? == Err(MemoryAdministrationError::NotVisible),
                "old generation survived lock wait",
            )?;
            let store = PostgresMemoryAdministration::new(reader_pool.clone());
            let mut fresh = request();
            fresh.auth_generation = AuthGeneration::new(1);
            let result = require(
                count(&store, fresh).await? == 1,
                "fresh generation failed after wait",
            );
            reader_pool.close();
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn recall_actor_share_lock_holds_until_memory_read_and_transaction_finish() {
    fixture(
        "memory recall first",
        "memoryshare",
        |pool, config| async move {
            let (reader_pool, reader_pid) = recall_pool(&config).await?;
            let mut blocker = pool.get().await.map_err(|e| e.to_string())?;
            let blocker_pid: i32 = blocker
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute("LOCK TABLE public.memories IN ACCESS EXCLUSIVE MODE")
                .await
                .map_err(|e| e.to_string())?;
            let mut reads = JoinSet::new();
            let store = PostgresMemoryAdministration::new(reader_pool.clone());
            reads.spawn(async move { store.recall(request()).await });
            let observer = pool.get().await.map_err(|e| e.to_string())?;
            blocked_by(&observer, reader_pid, blocker_pid).await?;
            let writer = pool.get().await.map_err(|e| e.to_string())?;
            let writer_pid: i32 = writer
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            let mut writes = JoinSet::new();
            writes.spawn(async move {
                writer
                    .batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'")
                    .await
            });
            blocked_by(&observer, writer_pid, reader_pid).await?;
            tx.rollback().await.map_err(|e| e.to_string())?;
            require(
                next_read(&mut reads)
                    .await?
                    .map_err(|e| e.to_string())?
                    .memories
                    .len()
                    == 1,
                "read before actor revocation failed",
            )?;
            tokio::time::timeout(WAIT, writes.join_next())
                .await
                .map_err(|_| "writer remained blocked".to_owned())?
                .ok_or_else(|| "missing writer".to_owned())?
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            let store = PostgresMemoryAdministration::new(reader_pool.clone());
            let result = require(
                store.recall(request()).await == Err(MemoryAdministrationError::NotVisible),
                "next stale recall survived committed revocation",
            );
            reader_pool.close();
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn context_revocation_after_statement_start_respects_that_snapshot_and_next_read_rejects() {
    fixture("memory context snapshot", "memorysnapshot", |pool, config| async move {
        let observer = pool.get().await.map_err(|e| e.to_string())?;
        // Test-only slow storage: the real recall SELECT still owns the authority predicate,
        // candidate filter, ordering and limit. A view delays execution after its snapshot exists.
        observer.batch_execute(
            "CREATE FUNCTION public.memory_recall_test_gate() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
             BEGIN PERFORM pg_advisory_xact_lock(712301); RETURN true; END $$;
             ALTER TABLE public.memories RENAME TO memory_recall_test_rows;
             CREATE VIEW public.memories AS SELECT * FROM public.memory_recall_test_rows
             WHERE public.memory_recall_test_gate();"
        ).await.map_err(|e| e.to_string())?;
        let (reader_pool, reader_pid) = recall_pool(&config).await?;
        let mut blocker = pool.get().await.map_err(|e| e.to_string())?;
        let blocker_pid: i32 = blocker.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        let gate = blocker.transaction().await.map_err(|e| e.to_string())?;
        gate.query_one("SELECT pg_advisory_xact_lock(712301)", &[]).await.map_err(|e| e.to_string())?;
        let mut req = request(); req.input.thread_id = Some(ThreadId::new(CHANNEL)); req.input.bot_id = Some(BotId::new("bot-a"));
        let selected = req.clone();
        let mut reads = JoinSet::new(); let store = PostgresMemoryAdministration::new(reader_pool.clone());
        reads.spawn(async move { store.recall(selected).await });
        blocked_by(&observer, reader_pid, blocker_pid).await?;
        // Isolate context from global-actor fencing: no user-generation write in this fixture.
        observer.batch_execute("DELETE FROM public.channel_memberships WHERE channel_id='channel-a' AND user_id='actor-a';
            UPDATE public.agent_profiles SET visibility='private',owner_user_id='actor-b' WHERE agent_id='bot-a';")
            .await.map_err(|e| e.to_string())?;
        gate.rollback().await.map_err(|e| e.to_string())?;
        require(next_read(&mut reads).await?.map_err(|e| e.to_string())?.memories.len() == 3,
            "in-flight query mixed pre/post-revocation context snapshots")?;
        let store = PostgresMemoryAdministration::new(reader_pool.clone());
        require(store.recall(req).await == Err(MemoryAdministrationError::NotVisible), "next SELECT ignored committed context revocation")?;
        let result = require(count(&store, request()).await? == 1, "context revocation removed independent User scope");
        reader_pool.close(); result
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn package_writer_lock_order_cannot_invert_with_recall_actor_lock() {
    fixture("memory package lock order", "memorypackage", |pool, config| async move {
        let mut writer = pool.get().await.map_err(|e| e.to_string())?;
        let tx = writer.transaction().await.map_err(|e| e.to_string())?;
        // Match tenant/postgres.rs: table locks, package/agent/profile rows, then users.
        tx.batch_execute("LOCK TABLE public.deployment_packages,public.agents,public.agent_profiles,
            public.channels,public.channel_agents,public.channel_memberships IN SHARE ROW EXCLUSIVE MODE;
            UPDATE public.deployment_packages SET loaded_at=clock_timestamp() WHERE tenant_id='tenant-a';
            UPDATE public.agents SET updated_at=clock_timestamp() WHERE id='bot-a';
            UPDATE public.agent_profiles SET updated_at=clock_timestamp() WHERE agent_id='bot-a';")
            .await.map_err(|e| e.to_string())?;
        let (reader_pool, _) = recall_pool(&config).await?;
        let mut reads = JoinSet::new(); let store = PostgresMemoryAdministration::new(reader_pool.clone());
        let mut req = request(); req.input.bot_id = Some(BotId::new("bot-a")); req.input.thread_id = Some(ThreadId::new(CHANNEL));
        reads.spawn(async move { store.recall(req).await });
        require(next_read(&mut reads).await?.map_err(|e| e.to_string())?.memories.len() == 3,
            "read-only context snapshots waited on package writer row locks")?;
        tokio::time::timeout(WAIT, tx.batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'"))
            .await.map_err(|_| "package writer could not advance actor generation after recall".to_owned())?
            .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        let store = PostgresMemoryAdministration::new(reader_pool.clone());
        let result = require(store.recall(request()).await == Err(MemoryAdministrationError::NotVisible), "post-package old generation remained valid");
        reader_pool.close(); result
    }).await;
}
