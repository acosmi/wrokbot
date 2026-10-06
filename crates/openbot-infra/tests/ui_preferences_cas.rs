//! R415 production preference CAS on newly owned PostgreSQL databases.
//! SQL arranges and observes counterexamples; every preference write uses the real adapter.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use openbot_application::{UiPreferenceAdministration, UiPreferenceAdministrationError as Error};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
    ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences},
};
use openbot_domain::vault::SecretBytes;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    db::{fresh, pool},
    ui_preferences::PostgresUiPreferenceAdministration,
};
use serde_json::Value;

const DEPLOYMENT: &str = "preference-cas-deployment";
const TENANT: &str = "preference-cas-tenant";
const OWNER: &str = "preference-cas-owner";
const OTHER: &str = "preference-cas-other";
const AUDIT_KEY: &[u8] = b"owned-ui-preferences-audit-key-at-least-32-bytes";

fn scoped_auth(deployment: &str, tenant: &str, actor: &str, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_roles([Role::User])
    .build()
}

fn auth(actor: &str, generation: u64) -> AuthContext {
    scoped_auth(DEPLOYMENT, TENANT, actor, generation)
}

fn update(
    expected_revision: Option<i64>,
    theme: Option<UiTheme>,
    locale: Option<UiLocale>,
) -> UpdateUiPreferences {
    UpdateUiPreferences {
        expected_revision,
        theme,
        locale,
    }
}

fn scoped_store(p: &Pool, deployment: &str, tenant: &str) -> PostgresUiPreferenceAdministration {
    PostgresUiPreferenceAdministration::new(
        p.clone(),
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        SecretBytes::new(AUDIT_KEY.to_vec()),
    )
    .unwrap()
}

async fn setup(p: &Pool) -> PostgresUiPreferenceAdministration {
    let mut c = p.get().await.unwrap();
    fresh::apply(&mut c).await.unwrap();
    c.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
           ('preference-cas-owner','owner@preference-cas.test',0),
           ('preference-cas-other','other@preference-cas.test',0);
         INSERT INTO public.user_roles(user_id,role) VALUES
           ('preference-cas-owner','user'),('preference-cas-other','user');",
    )
    .await
    .unwrap();
    drop(c);
    scoped_store(p, DEPLOYMENT, TENANT)
}

async fn durable(p: &Pool) -> Value {
    let c = p.get().await.unwrap();
    c.query_one(
        "SELECT jsonb_build_object(
          'preferences',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY deployment_id,tenant_id,actor_user_id),'[]') FROM public.user_ui_preferences p),
          'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a),
          'checkpoints',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY sequence),'[]') FROM public.audit_checkpoints c))",
        &[],
    ).await.unwrap().get(0)
}

async fn pool_pids(p: &Pool) -> Vec<i32> {
    let first = p.get().await.unwrap();
    let second = p.get().await.unwrap();
    let mut pids = Vec::new();
    for c in [&first, &second] {
        c.batch_execute("SET default_transaction_isolation='repeatable read'")
            .await
            .unwrap();
        assert_eq!(
            c.query_one("SHOW default_transaction_isolation", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            "repeatable read"
        );
        pids.push(
            c.query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0),
        );
    }
    pids
}

async fn control_transaction(
    client: &mut tokio_postgres::Client,
) -> tokio_postgres::Transaction<'_> {
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .unwrap();
    assert_eq!(
        tx.query_one("SHOW transaction_isolation", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "read committed"
    );
    tx
}

async fn control_pid<C: tokio_postgres::GenericClient + Sync>(c: &C, pids: &[i32]) -> i32 {
    let pid = c
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        !pids.contains(&pid),
        "the owned control connection must be independent of both production pool connections"
    );
    pid
}

async fn wait_blocked<C: tokio_postgres::GenericClient + Sync>(
    c: &C,
    pids: &[i32],
    barrier_pid: i32,
) -> Vec<(i32, Vec<i32>)> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            c.batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            let waiting: Vec<(i32, Vec<i32>)> = c
                .query(
                    "SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid=ANY($1)
                   AND wait_event_type='Lock'",
                    &[&pids],
                )
                .await
                .unwrap()
                .iter().map(|row| (row.get(0), row.get(1))).collect();
            if waiting.len() == pids.len() && waiting.iter().all(|(_, blockers)| {
                blockers.contains(&barrier_pid) || blockers.iter().any(|blocking_pid| {
                    waiting.iter().any(|(pid, next)| pid == blocking_pid && next.contains(&barrier_pid))
                })
            }) {
                break waiting;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both production requests must wait directly on the recorded control PID or through the other owned production waiter")
}

async fn wait_first<C: tokio_postgres::GenericClient + Sync>(
    c: &C,
    pids: &[i32],
    barrier_pid: i32,
) -> i32 {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            c.batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            if let Some(row) = c
                .query_opt(
                    "SELECT pid FROM pg_stat_activity WHERE pid=ANY($1)
                   AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid))",
                    &[&pids, &barrier_pid],
                )
                .await
                .unwrap()
            {
                break row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the production source waiter must be blocked by the recorded control PID")
}

async fn revisions(p: &Pool, actor: &str) -> Vec<i64> {
    let c = p.get().await.unwrap();
    c.query(
        "SELECT (payload->>'ui_preferences_revision')::bigint FROM public.audit_events
          WHERE target_type='ui_preferences' AND target_id=$1
          ORDER BY (payload->>'ui_preferences_revision')::bigint",
        &[&actor],
    )
    .await
    .unwrap()
    .iter()
    .map(|row| row.get(0))
    .collect()
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn partial_cas_equal_content_and_stale_snapshot_preserve_independent_fallbacks() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcasstale"),
        "uiprefcasstale",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let store = setup(&p).await;
            let actor = auth(OWNER, 0);
            let empty = durable(&p).await;
            assert_eq!(store.get(&actor).await.unwrap(), UiPreferences::default());
            assert_eq!(
                durable(&p).await,
                empty,
                "unset reads do not create rows or audits"
            );

            let first = store
                .update(&actor, update(None, Some(UiTheme::Dark), None))
                .await
                .unwrap();
            assert_eq!(
                (first.theme, first.locale, first.revision),
                (Some(UiTheme::Dark), None, Some(1))
            );
            assert!(first.updated_at.is_some());
            let second = store
                .update(&actor, update(Some(1), None, Some(UiLocale::ZhCn)))
                .await
                .unwrap();
            assert_eq!(
                (second.theme, second.locale, second.revision),
                (Some(UiTheme::Dark), Some(UiLocale::ZhCn), Some(2))
            );
            let equal = store
                .update(&actor, update(Some(2), None, Some(UiLocale::ZhCn)))
                .await
                .unwrap();
            assert_eq!((equal.theme, equal.locale), (second.theme, second.locale));
            assert_eq!(
                equal.revision,
                Some(3),
                "equal-content writes consume the same version sequence"
            );
            let expected = Error::StaleSnapshot(equal.revision_snapshot().unwrap());
            let before = durable(&p).await;
            for revision in [None, Some(1), Some(2)] {
                assert_eq!(
                    store
                        .update(
                            &actor,
                            update(revision, Some(UiTheme::Light), Some(UiLocale::En))
                        )
                        .await
                        .unwrap_err(),
                    expected
                );
            }
            assert_eq!(store.get(&actor).await.unwrap(), equal);
            assert_eq!(durable(&p).await, before);
            let body = serde_json::to_value(equal.revision_snapshot().unwrap()).unwrap();
            assert_eq!(body.as_object().unwrap().len(), 3);
            assert_eq!(body["currentRevision"], 3);
            let digest = body["currentSha256"].as_str().unwrap();
            assert_eq!(digest.len(), 64);
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(
                time::OffsetDateTime::parse(
                    body["updatedAt"].as_str().unwrap(),
                    &time::format_description::well_known::Rfc3339
                )
                .is_ok()
            );
            assert_eq!(revisions(&p, OWNER).await, [1, 2, 3]);
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn two_old_version_writers_under_rr_defaults_have_one_current_winner_after_real_waiting() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcaswriters"), "uiprefcaswriters", |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let store = Arc::new(setup(&p).await);
            store.update(&auth(OWNER, 0), update(None, Some(UiTheme::System), Some(UiLocale::En))).await.unwrap();
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = control_transaction(&mut barrier).await;
            let barrier_pid = control_pid(&tx, &pids).await;
            tx.query_one("SELECT actor_user_id FROM public.user_ui_preferences WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3 FOR UPDATE", &[&DEPLOYMENT, &TENANT, &OWNER]).await.unwrap();
            let left = store.clone();
            let first = tokio::spawn(async move { left.update(&auth(OWNER, 0), update(Some(1), Some(UiTheme::Dark), None)).await });
            let right = store.clone();
            let second = tokio::spawn(async move { right.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await });
            let waiting = wait_blocked(&tx, &pids, barrier_pid).await;
            let direct: Vec<i32> = waiting.iter().filter(|(_, blockers)| blockers.contains(&barrier_pid)).map(|(pid, _)| *pid).collect();
            assert_eq!(direct.len(), 1, "one source writer owns the scoped advisory lock and waits on the recorded control PID");
            let (_, queued_blockers) = waiting.iter().find(|(pid, _)| *pid != direct[0]).unwrap();
            assert!(queued_blockers.contains(&direct[0]), "the second production writer must wait on the first writer, which waits on the owned source barrier");
            tx.commit().await.unwrap();
            let (won, lost) = match (first.await.unwrap(), second.await.unwrap()) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (a, b),
                other => panic!("one CAS winner was required: {other:?}"),
            };
            assert_eq!(won.revision, Some(2));
            assert_eq!(lost, Error::StaleSnapshot(won.revision_snapshot().unwrap()));
            assert!(
                (won.theme == Some(UiTheme::Dark) && won.locale == Some(UiLocale::En))
                || (won.theme == Some(UiTheme::System) && won.locale == Some(UiLocale::ZhCn)),
                "losing partial write must not be silently merged into the winner"
            );
            assert_eq!(store.get(&auth(OWNER, 0)).await.unwrap(), won);
            assert_eq!(revisions(&p, OWNER).await, [1, 2]);
            drop(barrier); connection_task.await.unwrap().unwrap(); p.close(); Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn two_creators_under_rr_defaults_commit_only_one_initial_configuration() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcascreators"),
        "uiprefcascreators",
        |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let store = Arc::new(setup(&p).await);
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config
                .to_pg_config()
                .connect(tokio_postgres::NoTls)
                .await
                .unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = control_transaction(&mut barrier).await;
            let barrier_pid = control_pid(&tx, &pids).await;
            tx.query_one(
                "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
                &[&OWNER],
            )
            .await
            .unwrap();
            let left = store.clone();
            let first = tokio::spawn(async move {
                left.update(&auth(OWNER, 0), update(None, Some(UiTheme::Dark), None))
                    .await
            });
            let right = store.clone();
            let second = tokio::spawn(async move {
                right
                    .update(&auth(OWNER, 0), update(None, None, Some(UiLocale::ZhCn)))
                    .await
            });
            let waiting = wait_blocked(&tx, &pids, barrier_pid).await;
            assert!(
                waiting
                    .iter()
                    .all(|(_, blockers)| blockers.contains(&barrier_pid)),
                "both creators must wait directly on the independent current-actor control lock"
            );
            tx.commit().await.unwrap();
            let (won, lost) = match (first.await.unwrap(), second.await.unwrap()) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (a, b),
                other => panic!("one initial creator was required: {other:?}"),
            };
            assert_eq!(won.revision, Some(1));
            assert_eq!(lost, Error::StaleSnapshot(won.revision_snapshot().unwrap()));
            assert!(
                (won.theme == Some(UiTheme::Dark) && won.locale.is_none())
                    || (won.theme.is_none() && won.locale == Some(UiLocale::ZhCn)),
                "a losing creator must not fill the initial winner's absent field"
            );
            assert_eq!(store.get(&auth(OWNER, 0)).await.unwrap(), won);
            assert_eq!(revisions(&p, OWNER).await, [1]);
            drop(barrier);
            connection_task.await.unwrap().unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn read_and_stale_write_wait_for_current_actor_then_reject_generation_role_or_deny() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcasauthority"), "uiprefcasauthority", |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let store = Arc::new(setup(&p).await);
            store.update(&auth(OWNER, 0), update(None, Some(UiTheme::Dark), None)).await.unwrap();
            store.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await.unwrap();
            for change in [
                "UPDATE public.users SET auth_generation=1 WHERE id='preference-cas-owner'",
                "DELETE FROM public.user_roles WHERE user_id='preference-cas-owner'",
                "INSERT INTO public.revoked_access(email,revoked_by) VALUES('owner@preference-cas.test','preference-cas-other')",
            ] {
                let before = durable(&p).await;
                let pids = pool_pids(&p).await;
                let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
                let connection_task = tokio::spawn(connection);
                let tx = control_transaction(&mut barrier).await;
                let barrier_pid = control_pid(&tx, &pids).await;
                tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE", &[&OWNER]).await.unwrap();
                tx.batch_execute(change).await.unwrap();
                let reader = store.clone();
                let get = tokio::spawn(async move { reader.get(&auth(OWNER, 0)).await });
                let writer = store.clone();
                let put = tokio::spawn(async move { writer.update(&auth(OWNER, 0), update(Some(1), Some(UiTheme::Light), None)).await });
                let waiting = wait_blocked(&tx, &pids, barrier_pid).await;
                assert!(waiting.iter().all(|(_, blockers)| blockers.contains(&barrier_pid)), "both get and stale PUT must wait directly on the recorded actor-authorization barrier");
                tx.commit().await.unwrap();
                assert_eq!(get.await.unwrap().unwrap_err(), Error::NotVisible);
                assert_eq!(put.await.unwrap().unwrap_err(), Error::NotVisible, "current denial precedes stale snapshot metadata");
                assert_eq!(durable(&p).await, before);
                let c = p.get().await.unwrap();
                c.batch_execute("UPDATE public.users SET auth_generation=0 WHERE id='preference-cas-owner'; INSERT INTO public.user_roles(user_id,role) VALUES('preference-cas-owner','user') ON CONFLICT DO NOTHING; DELETE FROM public.revoked_access WHERE email='owner@preference-cas.test'").await.unwrap();
                drop(c); drop(barrier); connection_task.await.unwrap().unwrap();
            }
            p.close(); Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn host_scope_and_actor_keys_keep_independent_rows_and_reject_scope_drift() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcasscope"),
        "uiprefcasscope",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let store = setup(&p).await;
            let owner = auth(OWNER, 0);
            let original = store
                .update(
                    &owner,
                    update(None, Some(UiTheme::Dark), Some(UiLocale::ZhCn)),
                )
                .await
                .unwrap();
            let before = durable(&p).await;
            assert_eq!(
                store.get(&auth(OTHER, 0)).await.unwrap(),
                UiPreferences::default()
            );
            for foreign in [
                scoped_auth("other-preference-deployment", TENANT, OWNER, 0),
                scoped_auth(DEPLOYMENT, "other-preference-tenant", OWNER, 0),
                auth("missing-preference-actor", 0),
            ] {
                assert_eq!(store.get(&foreign).await.unwrap_err(), Error::NotVisible);
                assert_eq!(
                    store
                        .update(&foreign, update(None, Some(UiTheme::Light), None))
                        .await
                        .unwrap_err(),
                    Error::NotVisible
                );
            }
            assert_eq!(durable(&p).await, before);
            let other_actor = store
                .update(&auth(OTHER, 0), update(None, Some(UiTheme::Light), None))
                .await
                .unwrap();
            let other_deployment_store = scoped_store(&p, "other-preference-deployment", TENANT);
            let other_deployment_auth =
                scoped_auth("other-preference-deployment", TENANT, OWNER, 0);
            assert_eq!(
                other_deployment_store
                    .get(&other_deployment_auth)
                    .await
                    .unwrap(),
                UiPreferences::default()
            );
            let other_deployment = other_deployment_store
                .update(
                    &other_deployment_auth,
                    update(None, None, Some(UiLocale::En)),
                )
                .await
                .unwrap();
            let other_tenant_store = scoped_store(&p, DEPLOYMENT, "other-preference-tenant");
            let other_tenant_auth = scoped_auth(DEPLOYMENT, "other-preference-tenant", OWNER, 0);
            assert_eq!(
                other_tenant_store.get(&other_tenant_auth).await.unwrap(),
                UiPreferences::default()
            );
            let other_tenant = other_tenant_store
                .update(
                    &other_tenant_auth,
                    update(None, Some(UiTheme::System), None),
                )
                .await
                .unwrap();
            assert_eq!(
                (
                    other_actor.revision,
                    other_deployment.revision,
                    other_tenant.revision
                ),
                (Some(1), Some(1), Some(1))
            );
            assert_eq!(store.get(&owner).await.unwrap(), original);
            assert_eq!(store.get(&auth(OTHER, 0)).await.unwrap(), other_actor);
            assert_eq!(
                other_deployment_store
                    .get(&other_deployment_auth)
                    .await
                    .unwrap(),
                other_deployment
            );
            assert_eq!(
                other_tenant_store.get(&other_tenant_auth).await.unwrap(),
                other_tenant
            );
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one("SELECT count(*) FROM public.user_ui_preferences", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                4
            );
            drop(c);
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn audit_failure_rolls_back_creation_partial_update_and_chain_without_retry() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcasrollback"), "uiprefcasrollback", |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let store = setup(&p).await;
            store.update(&auth(OWNER, 0), update(None, Some(UiTheme::Dark), None)).await.unwrap();
            let c = p.get().await.unwrap();
            // nextval survives transaction rollback and counts attempted audit inserts.
            // This newly owned fixture exposes retries without adding a product audit path.
            c.batch_execute("CREATE SEQUENCE ui_preference_fault_hits; CREATE FUNCTION ui_preference_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('ui_preference_fault_hits'); RAISE EXCEPTION 'owned synthetic audit failure'; END $$; CREATE TRIGGER ui_preference_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION ui_preference_audit_fault()").await.unwrap();
            drop(c);
            let before = durable(&p).await;
            assert_eq!(store.update(&auth(OTHER, 0), update(None, Some(UiTheme::Light), Some(UiLocale::En))).await.unwrap_err(), Error::Unavailable);
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap();
            let hit = c.query_one("SELECT last_value,is_called FROM ui_preference_fault_hits", &[]).await.unwrap();
            assert_eq!((hit.get::<_, i64>(0), hit.get::<_, bool>(1)), (1, true));
            drop(c);
            assert_eq!(store.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await.unwrap_err(), Error::Unavailable);
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap();
            assert_eq!(c.query_one("SELECT last_value FROM ui_preference_fault_hits", &[]).await.unwrap().get::<_, i64>(0), 2, "one failed insert per explicit request, with zero automatic replay");
            c.batch_execute("DROP TRIGGER ui_preference_audit_fault ON public.audit_events; DROP FUNCTION ui_preference_audit_fault(); DROP SEQUENCE ui_preference_fault_hits").await.unwrap();
            drop(c);
            assert_eq!(store.get(&auth(OTHER, 0)).await.unwrap(), UiPreferences::default());
            let retried = store.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await.unwrap();
            assert_eq!((retried.theme, retried.locale, retried.revision), (Some(UiTheme::Dark), Some(UiLocale::ZhCn), Some(2)));
            assert_eq!(revisions(&p, OWNER).await, [1, 2]);
            p.close(); Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn legacy_null_missing_expected_revision_and_overflow_fail_without_effects() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcaslegacy"), "uiprefcaslegacy", |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let store = setup(&p).await;
            let before = durable(&p).await;
            assert_eq!(store.update(&auth(OTHER, 0), update(Some(1), Some(UiTheme::Light), None)).await.unwrap_err(), Error::NotVisible);
            assert_eq!(durable(&p).await, before);
            store.update(&auth(OWNER, 0), update(None, Some(UiTheme::Dark), None)).await.unwrap();
            let c = p.get().await.unwrap();
            c.execute("UPDATE public.user_ui_preferences SET revision=NULL WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3", &[&DEPLOYMENT, &TENANT, &OWNER]).await.unwrap();
            drop(c);
            let legacy = store.get(&auth(OWNER, 0)).await.unwrap();
            assert_eq!((legacy.theme, legacy.locale, legacy.revision), (Some(UiTheme::Dark), None, Some(1)));
            assert!(legacy.updated_at.is_some());
            let next = store.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await.unwrap();
            assert_eq!(next.revision, Some(2));
            let before = durable(&p).await;
            for invalid in [0_i64, -1_i64] {
                let c = p.get().await.unwrap();
                let error = c.execute("UPDATE public.user_ui_preferences SET revision=$4 WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3", &[&DEPLOYMENT, &TENANT, &OWNER, &invalid]).await.unwrap_err();
                assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
                drop(c);
                assert!(matches!(store.update(&auth(OWNER, 0), update(Some(invalid), Some(UiTheme::Light), None)).await, Err(Error::InvalidInput { .. })));
                assert_eq!(durable(&p).await, before);
            }
            assert_eq!(store.update(&auth(OWNER, 0), update(Some(2), None, None)).await.unwrap_err(), Error::InvalidInput { field: "body" });
            assert_eq!(durable(&p).await, before);
            let max_request = update(Some(i64::MAX), Some(UiTheme::Light), None);
            assert_eq!(store.update(&auth(OWNER, 0), max_request).await.unwrap_err(), Error::StaleSnapshot(next.revision_snapshot().unwrap()), "a positive MAX submitted to ordinary current revision 2 must compare first and reveal only its authorized current snapshot");
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap();
            c.execute("UPDATE public.users SET auth_generation=1 WHERE id=$1", &[&OWNER]).await.unwrap();
            drop(c);
            assert_eq!(store.update(&auth(OWNER, 0), max_request).await.unwrap_err(), Error::NotVisible, "current actor revocation precedes the same MAX request's stale metadata");
            assert_eq!(durable(&p).await, before);
            let c = p.get().await.unwrap();
            c.execute("UPDATE public.users SET auth_generation=0 WHERE id=$1", &[&OWNER]).await.unwrap();
            drop(c);
            let c = p.get().await.unwrap();
            c.execute("UPDATE public.user_ui_preferences SET revision=$4 WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3", &[&DEPLOYMENT, &TENANT, &OWNER, &i64::MAX]).await.unwrap();
            drop(c);
            assert_eq!(store.get(&auth(OWNER, 0)).await.unwrap().revision, Some(i64::MAX));
            let before = durable(&p).await;
            assert!(matches!(store.update(&auth(OWNER, 0), max_request).await, Err(Error::Corrupt { .. })));
            assert_eq!(durable(&p).await, before);
            p.close(); Ok(())
        },
    ).await;
}

#[tokio::test]
#[ignore = "requires newly owned isolated PostgreSQL"]
async fn real_source_lock_timeout_is_unavailable_without_effects_or_automatic_retry() {
    harness::with_temp_database(
        &harness::admin_config("uiprefcastimeout"), "uiprefcastimeout", |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let store = Arc::new(setup(&p).await);
            let actor = auth(OWNER, 0);
            store.update(&actor, update(None, Some(UiTheme::Dark), None)).await.unwrap();
            let before = durable(&p).await;
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
            let connection_task = tokio::spawn(connection);
            let tx = control_transaction(&mut barrier).await;
            let barrier_pid = control_pid(&tx, &pids).await;
            tx.query_one("SELECT actor_user_id FROM public.user_ui_preferences WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3 FOR UPDATE", &[&DEPLOYMENT, &TENANT, &OWNER]).await.unwrap();
            let writer = store.clone();
            let pending = tokio::spawn(async move { writer.update(&auth(OWNER, 0), update(Some(1), None, Some(UiLocale::ZhCn))).await });
            let first_pid = wait_first(&tx, &pids, barrier_pid).await;
            assert!(pids.contains(&first_pid));
            let rejected = tokio::time::timeout(Duration::from_secs(7), pending).await
                .expect("the production 5s lock timeout must return without an automatic second attempt")
                .unwrap();
            assert_eq!(rejected.unwrap_err(), Error::Unavailable);
            assert_eq!(durable(&p).await, before);
            tx.commit().await.unwrap();
            let explicit_retry = store.update(&actor, update(Some(1), None, Some(UiLocale::ZhCn))).await.unwrap();
            assert_eq!((explicit_retry.theme, explicit_retry.locale, explicit_retry.revision), (Some(UiTheme::Dark), Some(UiLocale::ZhCn), Some(2)));
            assert_eq!(revisions(&p, OWNER).await, [1, 2]);
            drop(barrier); connection_task.await.unwrap().unwrap(); p.close(); Ok(())
        },
    ).await;
}
