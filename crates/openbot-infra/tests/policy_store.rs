//! W-5 batch 3：action policy durability / multi-replica fanout 真库矩阵。

mod harness;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use harness::{admin_config, with_temp_database};
use openbot_application::PolicyAdministration;
use openbot_contracts::ids::ActorId;
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::{ACTION_POLICY_TOPIC, PolicyListener, PolicyOrigin, PolicyStore};

fn configured() -> ActionPolicy {
    ActionPolicy {
        mode: PolicyMode::Enforce,
        deny: Vec::new(),
        allow: vec!["true".to_owned()],
    }
}

fn policy(mode: PolicyMode, deny: &str) -> ActionPolicy {
    ActionPolicy {
        mode,
        deny: vec![deny.to_owned()],
        allow: vec!["true".to_owned()],
    }
}

async fn with_policy_database<F, Fut>(test_name: &'static str, tag: &'static str, body: F)
where
    F: FnOnce(deadpool_postgres::Pool, openbot_infra::db::pool::DatabaseConfig) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(test_name);
    with_temp_database(&admin, tag, move |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            body(pool.clone(), config).await
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

async fn scalar(pool: &deadpool_postgres::Pool, sql: &str) -> Result<i64, String> {
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(sql, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

async fn until(
    mut condition: impl FnMut() -> bool,
    description: &'static str,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| format!("等待 {description} 超时"))
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_boundary_set_while_running_is_still_there_after_restart() {
    with_policy_database(
        "a_boundary_set_while_running_is_still_there_after_restart",
        "policy_restart",
        |pool, _config| async move {
            let before = PolicyStore::postgres(pool.clone(), Some(configured()));
            if before.load().await.map_err(|error| error.to_string())?
                != PolicyOrigin::Configuration
            {
                return Err("空库没有从 configuration 启动".to_owned());
            }
            let saved = policy(PolicyMode::Enforce, "intent == 'activate'");
            before
                .set(saved.clone(), Some("admin@example.test"))
                .await
                .map_err(|error| error.to_string())?;

            let after = PolicyStore::postgres(pool, Some(configured()));
            if after.load().await.map_err(|error| error.to_string())? != PolicyOrigin::Database
                || after.current() != Some(saved)
            {
                return Err("新 store 没有从数据库恢复已保存 policy".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_deployment_that_never_set_one_gets_its_configured_default() {
    with_policy_database(
        "a_deployment_that_never_set_one_gets_its_configured_default",
        "policy_default",
        |pool, _config| async move {
            let expected = configured();
            let store = PolicyStore::postgres(pool, Some(expected.clone()));
            let origin = store.load().await.map_err(|error| error.to_string())?;
            if origin != PolicyOrigin::Configuration || store.current() != Some(expected) {
                return Err(format!("configured default 不符：{origin:?} {store:?}"));
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn resetting_forgets_the_saved_row_and_restart_returns_to_configuration() {
    with_policy_database(
        "resetting_forgets_the_saved_row_and_restart_returns_to_configuration",
        "policy_reset",
        |pool, _config| async move {
            let fallback = configured();
            let store = PolicyStore::postgres(pool.clone(), Some(fallback.clone()));
            store
                .set(policy(PolicyMode::Enforce, "blocked"), None)
                .await
                .map_err(|error| error.to_string())?;
            store.reset().await.map_err(|error| error.to_string())?;
            let after = PolicyStore::postgres(pool.clone(), Some(fallback.clone()));
            if after.load().await.map_err(|error| error.to_string())? != PolicyOrigin::Configuration
                || after.current() != Some(fallback)
                || scalar(&pool, "SELECT count(*)::bigint FROM public.action_policy").await? != 0
            {
                return Err("reset 后没有回到配置/仍残留数据库行".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn setting_twice_keeps_one_row_and_the_latest_rule() {
    with_policy_database(
        "setting_twice_keeps_one_row_and_the_latest_rule",
        "policy_upsert",
        |pool, _config| async move {
            let store = PolicyStore::postgres(pool.clone(), Some(configured()));
            store
                .set(policy(PolicyMode::Enforce, "first"), None)
                .await
                .map_err(|error| error.to_string())?;
            let latest = policy(PolicyMode::DryRun, "second");
            store
                .set(latest.clone(), None)
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT count(*) OVER()::bigint,mode,deny FROM public.action_policy",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let count: i64 = row.get(0);
            let mode: String = row.get(1);
            let deny: Vec<Option<String>> = row.get(2);
            if count != 1
                || mode != "dry-run"
                || deny != [Some("second".to_owned())]
                || store.current() != Some(latest)
            {
                return Err(format!(
                    "policy upsert 不符：count={count} mode={mode} deny={deny:?}"
                ));
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn setting_records_who_changed_it() {
    with_policy_database(
        "setting_records_who_changed_it",
        "policy_actor",
        |pool, _config| async move {
            let store = PolicyStore::postgres(pool.clone(), Some(configured()));
            store
                .set(
                    policy(PolicyMode::Enforce, "blocked"),
                    Some("admin@example.test"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let by: Option<String> = client
                .query_one(
                    "SELECT updated_by FROM public.action_policy WHERE id='current'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if by.as_deref() != Some("admin@example.test") {
                return Err(format!("updated_by 不符：{by:?}"));
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
async fn without_a_database_it_still_works_in_memory() {
    let fallback = configured();
    let store = PolicyStore::in_memory(Some(fallback.clone()));
    assert_eq!(store.load().await.unwrap(), PolicyOrigin::Configuration);
    let compiled_before = store.compiled();
    assert!(Arc::ptr_eq(&compiled_before, &store.compiled()));
    let saved = policy(PolicyMode::Enforce, "blocked");
    store.set(saved.clone(), None).await.unwrap();
    assert_eq!(store.current(), Some(saved));
    assert!(
        !Arc::ptr_eq(&compiled_before, &store.compiled()),
        "policy 变化时才允许替换预编译快照",
    );
    store.reset().await.unwrap();
    assert_eq!(store.current(), Some(fallback));

    let unconfigured = PolicyStore::in_memory(None);
    assert_eq!(
        unconfigured.load().await.unwrap(),
        PolicyOrigin::Unconfigured
    );
    assert!(unconfigured.current().is_none());
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_rule_added_on_one_server_is_enforced_on_the_other_server() {
    with_policy_database(
        "a_rule_added_on_one_server_is_enforced_on_the_other_server",
        "policy_fanout",
        |pool, config| async move {
            let writer = PolicyStore::postgres(pool.clone(), Some(configured()));
            let other = Arc::new(PolicyStore::postgres(pool, Some(configured())));
            writer.load().await.map_err(|error| error.to_string())?;
            other.load().await.map_err(|error| error.to_string())?;
            let listener = PolicyListener::start(config, other.clone())
                .await
                .map_err(|error| error.to_string())?;
            let expected = policy(PolicyMode::Enforce, "submit");
            let outcome = async {
                writer
                    .set(expected.clone(), None)
                    .await
                    .map_err(|error| error.to_string())?;
                until(
                    || other.current() == Some(expected.clone()),
                    "other replica policy",
                )
                .await
            }
            .await;
            listener.stop().await;
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_reset_reaches_the_other_servers_too() {
    with_policy_database(
        "a_reset_reaches_the_other_servers_too",
        "policy_fanout_reset",
        |pool, config| async move {
            let fallback = configured();
            let writer = PolicyStore::postgres(pool.clone(), Some(fallback.clone()));
            writer
                .set(policy(PolicyMode::Enforce, "submit"), None)
                .await
                .map_err(|error| error.to_string())?;
            let other = Arc::new(PolicyStore::postgres(pool, Some(fallback.clone())));
            other.load().await.map_err(|error| error.to_string())?;
            let listener = PolicyListener::start(config, other.clone())
                .await
                .map_err(|error| error.to_string())?;
            let outcome = async {
                writer.reset().await.map_err(|error| error.to_string())?;
                until(|| other.current() == Some(fallback.clone()), "fanout reset").await
            }
            .await;
            listener.stop().await;
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn the_mode_travels_so_dry_run_does_not_stay_on_somewhere() {
    with_policy_database(
        "the_mode_travels_so_dry_run_does_not_stay_on_somewhere",
        "policy_fanout_mode",
        |pool, config| async move {
            let writer = PolicyStore::postgres(pool.clone(), Some(configured()));
            writer
                .set(policy(PolicyMode::DryRun, "submit"), None)
                .await
                .map_err(|error| error.to_string())?;
            let other = Arc::new(PolicyStore::postgres(pool, Some(configured())));
            other.load().await.map_err(|error| error.to_string())?;
            let listener = PolicyListener::start(config, other.clone())
                .await
                .map_err(|error| error.to_string())?;
            let outcome = async {
                writer
                    .set(policy(PolicyMode::Enforce, "submit"), None)
                    .await
                    .map_err(|error| error.to_string())?;
                until(
                    || {
                        other
                            .current()
                            .is_some_and(|value| value.mode == PolicyMode::Enforce)
                    },
                    "fanout enforce mode",
                )
                .await
            }
            .await;
            listener.stop().await;
            outcome
        },
    )
    .await;
}

#[tokio::test]
async fn a_store_with_no_database_is_unaffected_by_refresh() {
    let store = PolicyStore::in_memory(Some(configured()));
    let expected = policy(PolicyMode::Enforce, "submit");
    store.set(expected.clone(), None).await.unwrap();
    store.refresh().await.unwrap();
    assert_eq!(store.current(), Some(expected));
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_server_catches_up_when_its_subscription_comes_back() {
    with_policy_database(
        "a_server_catches_up_when_its_subscription_comes_back",
        "policy_listener_catchup",
        |pool, config| async move {
            let writer = PolicyStore::postgres(pool.clone(), Some(configured()));
            let was_down = Arc::new(PolicyStore::postgres(pool, Some(configured())));
            was_down.load().await.map_err(|error| error.to_string())?;
            let expected = policy(PolicyMode::Enforce, "submit");
            writer
                .set(expected.clone(), None)
                .await
                .map_err(|error| error.to_string())?;
            if was_down.current() == Some(expected.clone()) {
                return Err("没有订阅的 replica 被进程内状态串线".to_owned());
            }
            let listener = PolicyListener::start(config, was_down.clone())
                .await
                .map_err(|error| error.to_string())?;
            let outcome = until(
                || was_down.current() == Some(expected.clone()),
                "listener establish catch-up",
            )
            .await;
            listener.stop().await;
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_write_that_rolls_back_announces_nothing() {
    with_policy_database(
        "a_write_that_rolls_back_announces_nothing",
        "policy_notify_rollback",
        |pool, config| async move {
            let listening = Arc::new(PolicyStore::postgres(pool.clone(), Some(configured())));
            listening.load().await.map_err(|error| error.to_string())?;
            let listener = PolicyListener::start(config, listening.clone())
                .await
                .map_err(|error| error.to_string())?;
            let outcome = async {
                let mut client = pool.get().await.map_err(|error| error.to_string())?;
                let transaction = client.transaction().await.map_err(|error| error.to_string())?;
                let deny = vec!["rolled-back".to_owned()];
                let allow = vec!["true".to_owned()];
                transaction
                    .execute(
                        "INSERT INTO public.action_policy(id,mode,deny,allow) VALUES('current','enforce',$1,$2)",
                        &[&deny, &allow],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                transaction
                    .query_one("SELECT pg_notify($1,'')", &[&ACTION_POLICY_TOPIC])
                    .await
                    .map_err(|error| error.to_string())?;
                transaction.rollback().await.map_err(|error| error.to_string())?;
                tokio::time::sleep(Duration::from_millis(200)).await;
                if listening.current() != Some(configured())
                    || scalar(&pool, "SELECT count(*)::bigint FROM public.action_policy").await? != 0
                {
                    return Err("rollback 后通知或 policy 行发生了可见副作用".to_owned());
                }

                // 正向对照：同一 listener 对真正 commit 的下一次通知必须移动。
                let writer = PolicyStore::postgres(pool.clone(), Some(configured()));
                let committed = policy(PolicyMode::Enforce, "committed");
                writer
                    .set(committed.clone(), None)
                    .await
                    .map_err(|error| error.to_string())?;
                until(
                    || listening.current() == Some(committed.clone()),
                    "post-rollback positive notify",
                )
                .await
            }
            .await;
            listener.stop().await;
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_saved_rule_is_not_lost_when_no_listener_received_the_announcement() {
    with_policy_database(
        "a_saved_rule_is_not_lost_when_no_listener_received_the_announcement",
        "policy_notify_no_receiver",
        |pool, _config| async move {
            let store = PolicyStore::postgres(pool.clone(), Some(configured()));
            let saved = policy(PolicyMode::Enforce, "saved-without-receiver");
            store
                .set(saved.clone(), None)
                .await
                .map_err(|error| error.to_string())?;
            let restarted = PolicyStore::postgres(pool.clone(), Some(configured()));
            if store.current() != Some(saved.clone())
                || restarted.load().await.map_err(|error| error.to_string())?
                    != PolicyOrigin::Database
                || restarted.current() != Some(saved)
                || scalar(&pool, "SELECT count(*)::bigint FROM public.action_policy").await? != 1
            {
                return Err("无人接收 NOTIFY 时已提交 rule 丢失".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn application_policy_port_persists_authoritative_actor_and_updates_compiled_snapshot() {
    with_policy_database(
        "application_policy_port_persists_authoritative_actor_and_updates_compiled_snapshot",
        "policy_application_port",
        |pool, _config| async move {
            let store = PolicyStore::postgres(pool.clone(), Some(configured()));
            store.load().await.map_err(|error| error.to_string())?;
            let before = store.compiled();
            let saved = policy(PolicyMode::DryRun, "from-application");
            PolicyAdministration::set_policy(&store, &ActorId::new("admin-id"), saved.clone())
                .await
                .map_err(|error| error.to_string())?;
            let current = PolicyAdministration::current_policy(&store)
                .await
                .map_err(|error| error.to_string())?;
            let updated_by: Option<String> = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT updated_by FROM public.action_policy WHERE id='current'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if current != Some(saved)
                || updated_by.as_deref() != Some("admin-id")
                || Arc::ptr_eq(&before, &store.compiled())
            {
                return Err(format!(
                    "application policy port 不符：current={current:?} updated_by={updated_by:?}"
                ));
            }
            Ok(())
        },
    )
    .await;
}
