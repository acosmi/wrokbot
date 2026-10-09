//! Directed current Host/PG tests. Each N case owns its temporary database and TLS producer.
use super::*;
use openbot_domain::vault::SecretBytes;
use openbot_infra::db::pool::{self, ConnectionObservation, DatabaseConfig};
use openbot_infra::db::tables::gateway_authorization_attempts::Row;
use openbot_infra::{
    ControlledCloseReason, CreatedAttemptOwner,
    GatewayAuthorizationCancellationToken as CancellationToken, GatewayAuthorizationJournal,
    GatewayAuthorizationJournalAck as Ack, GatewayAuthorizationJournalError as JournalError,
    GatewayAuthorizationJournalErrorKind as Kind, GatewayAuthorizationJournalRuntimeOwner,
};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod support;
use support::{
    ACTOR, COOKIE, DEP, Fixture, INSTALLATION, NEXT_COOKIE, PgTerminalAckGate, REDIRECT, TENANT,
    TerminalStage, harness,
};

fn check(value: bool, message: &str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn error<T>(result: Result<T, JournalError>) -> Result<JournalError, String> {
    match result {
        Err(e) => Ok(e),
        Ok(_) => Err("journal unexpectedly returned a live receipt".into()),
    }
}
fn exact_error<T>(result: Result<T, JournalError>, kind: Kind) -> Result<JournalError, String> {
    let e = error(result)?;
    check(
        e.kind() == kind,
        &format!("expected {kind:?}, observed {e:?}"),
    )?;
    Ok(e)
}
fn parts(cookie: Option<&str>) -> Result<http::request::Parts, String> {
    let mut request = http::Request::builder().uri("/owned-journal");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("openbot_session={cookie}"));
    }
    Ok(request.body(()).map_err(|e| e.to_string())?.into_parts().0)
}
async fn create_on(
    f: &Fixture,
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    parent: CancellationToken,
    budget: Duration,
) -> Result<CreatedAttemptOwner, String> {
    let metadata = f.metadata(parent.clone()).await?;
    journal
        .create_attempt(
            auth,
            metadata,
            Zeroizing::new(REDIRECT.to_owned()),
            parent,
            Instant::now() + budget,
        )
        .await
        .map_err(|e| e.to_string())
}
async fn created(f: &Fixture, auth: &AuthContext) -> Result<CreatedAttemptOwner, String> {
    create_on(
        f,
        &f.journal,
        auth,
        CancellationToken::new(),
        Duration::from_secs(60),
    )
    .await
}
fn created_facts(row: &Row, f: &Fixture, actor: &str) -> Result<(), String> {
    check(
        row.journal_schema == 1 && row.attempt_id.get_version_num() == 7,
        "canonical attempt/schema",
    )?;
    check(
        row.deployment_id == DEP
            && row.tenant_id == TENANT
            && row.owner_user_id == actor
            && row.auth_generation == 7,
        "original scope and generation",
    )?;
    check(
        row.installation_id == INSTALLATION
            && row.runtime_epoch.len() == 64
            && row
                .runtime_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "original installation/runtime tag",
    )?;
    check(
        row.issuer == f.issuer() && row.redirect_uri == REDIRECT,
        "original raw issuer and redirect",
    )?;
    check(
        row.phase == "created"
            && row.client_id.is_none()
            && row.enrollment_id.is_none()
            && row.registration_admitted_at.is_none()
            && row.code_admitted_at.is_none()
            && row.finished_at.is_none()
            && row.outcome_code.is_none(),
        "created six NULL facts",
    )?;
    check(
        row.created_at == row.updated_at
            && row.expires_at > row.created_at
            && row.expires_at - row.created_at <= time::Duration::seconds(180),
        "saved flow times",
    )?;
    check(
        [row.created_at, row.expires_at, row.updated_at]
            .iter()
            .all(|t| t.nanosecond() % 1_000 == 0),
        "canonical PG microseconds",
    )
}
fn audit_facts(
    payload: &Value,
    id: uuid::Uuid,
    phase: &str,
    outcome: Option<&str>,
) -> Result<(), String> {
    check(
        *payload
            == json!({"journal_schema":1,"attempt_id":id.to_string(),"phase":phase,"outcome_code":outcome}),
        "exact four typed audit facts",
    )
}
async fn execute(f: &Fixture, sql: &str) -> Result<(), String> {
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    client.batch_execute(sql).await.map_err(|e| e.to_string())
}
async fn retired(
    f: &Fixture,
    original: &ConnectionObservation,
    pid: i32,
    direct: &pool::DatabasePool,
) -> Result<(), String> {
    original
        .wait_for_destruction_before(Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|e| e.to_string())?;
    let snapshot = original.snapshot();
    check(
        snapshot.retirement_requested && snapshot.connection_destroyed,
        "actual original connection retirement/destruction",
    )?;
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    let next: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    drop(client);
    check(next != pid, "retired original backend never recycled")?;
    let client = direct.get().await.map_err(|e| e.to_string())?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let count: i64 = client
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE pid=$1",
                &[&pid],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        if count == 0 {
            break;
        }
        check(Instant::now() < until, "original backend still live")?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    eprintln!(
        "GATEWAY_JOURNAL_ORIGINAL_RETIRE old_backend={pid} new_backend={next} retired=true destroyed=true old_pg_absent=true individual_production_driver_join=UNPROVEN"
    );
    Ok(())
}

#[test]
fn p01_startup_raw_installation_configuration() {
    let absent = crate::config::ServerConfig::from_env_map(&crate::config::EnvMap::new()).unwrap();
    assert!(absent.gateway_authorization_installation_id.is_none());
    let valid = crate::config::ServerConfig::from_env_map(&crate::config::EnvMap::from([(
        "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".into(),
        INSTALLATION.into(),
    )]))
    .unwrap();
    assert_eq!(
        valid
            .gateway_authorization_installation_id
            .as_ref()
            .unwrap()
            .as_str(),
        INSTALLATION
    );
    assert!(!format!("{:?}", valid.gateway_authorization_installation_id).contains(INSTALLATION));
    for invalid in [
        String::new(),
        " ".into(),
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        format!(" {INSTALLATION}"),
        format!("{INSTALLATION}\n"),
    ] {
        let e = crate::config::ServerConfig::from_env_map(&crate::config::EnvMap::from([(
            "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".into(),
            invalid.clone(),
        )]))
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("OPENBOT_GATEWAY_AUTH_INSTALLATION_ID")
        );
        if invalid.len() > 1 {
            assert!(!e.to_string().contains(&invalid));
        }
    }
}

#[test]
fn p02_absent_installation_does_not_assemble_or_checkout() {
    let pool = pool::DatabasePool::build_unprobed(
        &"host=127.0.0.1 port=1 user=journal-unused dbname=unused"
            .parse::<DatabaseConfig>()
            .unwrap(),
    )
    .unwrap();
    let config = crate::config::ServerConfig::from_env_map(&crate::config::EnvMap::new()).unwrap();
    assert!(
        assemble_gateway_authorization_journal(
            &config,
            pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![1; 32])
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(pool.status().size, 0);
    assert!(pool.connection_observations().is_empty());
    pool.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n01_actual_session_created_ack_readback() {
    let admin = harness::admin_config("journal-n01");
    harness::with_temp_database(&admin, "ga_n01", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let owner = created(&f, &auth).await?;
        let rows = f.rows().await?;
        check(rows.len() == 1, "created one original row")?;
        created_facts(&rows[0], &f, ACTOR)?;
        let audits = f.audits().await?;
        check(audits.len() == 1, "created one same-Tx audit")?;
        audit_facts(&audits[0], rows[0].attempt_id, "created", None)?;
        drop(owner);
        check(
            f.rows().await? == rows,
            "owner Drop cannot close or restore",
        )?;
        check(f.captures()?.len() == 1, "real discovery setup GET counted")?;
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n02_actual_singleuser_registration_admitted() {
    let admin = harness::admin_config("journal-n02");
    harness::with_temp_database(&admin, "ga_n02", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (runtime, journal) = f.fresh_pair()?;
        let resolver = f.single(&journal).await?;
        let auth = resolver
            .resolve(&parts(None)?)
            .await
            .map_err(|e| e.to_string())?;
        let owner = create_on(
            &f,
            &journal,
            &auth,
            CancellationToken::new(),
            Duration::from_secs(60),
        )
        .await?;
        let before = f.rows().await?.remove(0);
        created_facts(&before, &f, "dev-local-user")?;
        let receipt = journal
            .admit_registration(&auth, owner)
            .await
            .map_err(|e| e.to_string())?;
        let after = f.row(before.attempt_id).await?;
        let mut expected = before.clone();
        expected.phase = "registration_admitted".into();
        expected.registration_admitted_at = after.registration_admitted_at;
        expected.updated_at = after.updated_at;
        check(
            after == expected && after.registration_admitted_at == Some(after.updated_at),
            "admission changes only three of20 typed facts",
        )?;
        let audits = f.audits().await?;
        check(audits.len() == 2, "actual SingleUser two audit rows")?;
        audit_facts(&audits[0], before.attempt_id, "created", None)?;
        audit_facts(&audits[1], before.attempt_id, "registration_admitted", None)?;
        drop(receipt);
        resolver.close_request_bindings();
        runtime.close();
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n03_exact_scope_binding_cas_refuses() {
    let admin = harness::admin_config("journal-n03");
    harness::with_temp_database(&admin,"ga_n03",|cfg|async move {
        let f=Fixture::new(cfg,2).await?; let auth=f.auth().await?;
        for mutation in ["deployment_id='other-deployment'","tenant_id='other-tenant'","owner_user_id='owned-journal-other'","auth_generation=8","installation_id=repeat('a',64)","runtime_epoch=repeat('b',64)","issuer='https://other.test'","redirect_uri='http://127.0.0.1:48282/callback'","created_at=created_at-interval '1 microsecond'","expires_at=expires_at+interval '1 microsecond'","updated_at=updated_at+interval '1 microsecond'"] {
            let owner=created(&f,&auth).await?; let row=f.rows().await?.pop().ok_or("attempt missing")?;
            let client=f.pool.get().await.map_err(|e|e.to_string())?;
            check(client.execute(&format!("UPDATE openbot_internal.gateway_authorization_attempts SET {mutation} WHERE attempt_id=$1"),&[&row.attempt_id]).await.map_err(|e|e.to_string())?==1,"owned legal mutation affected1")?; drop(client);
            let changed=f.row(row.attempt_id).await?; check(changed!=row,"actual old fact changed")?;
            let audits=f.audits().await?; exact_error(f.journal.admit_registration(&auth,owner).await,Kind::Refused)?;
            check(f.row(row.attempt_id).await?==changed && f.audits().await?==audits,"CAS refusal preserves durable prefix")?;
        }
        let owner=created(&f,&auth).await?; let next=f.auth_cookie(NEXT_COOKIE).await?;
        check(!auth.request_binding().unwrap().identity().same_binding(next.request_binding().unwrap().identity()),"actual different original session epoch")?;
        exact_error(f.journal.admit_registration(&next,owner).await,Kind::Refused)?; f.finish().await
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n04_original_pool_and_namespace() {
    let admin = harness::admin_config("journal-n04");
    harness::with_temp_database(&admin, "ga_n04", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let other = f.direct().await?;
        check(
            f.journal.matches_pool_scope(
                &f.pool.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            ),
            "same original Pool clone",
        )?;
        check(
            !f.journal
                .matches_pool_scope(&other, &DeploymentId::new(DEP), &TenantId::new(TENANT)),
            "same DSN is a different manager",
        )?;
        check(
            !f.journal.matches_pool_scope(
                &f.pool,
                &DeploymentId::new("other"),
                &TenantId::new(TENANT),
            ),
            "exact deployment",
        )?;
        check(
            !f.journal.matches_pool_scope(
                &f.pool,
                &DeploymentId::new(DEP),
                &TenantId::new("other"),
            ),
            "exact tenant",
        )?;
        exact_error(
            GatewayAuthorizationJournal::new(
                other.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![1; 32]),
                f.runtime.as_ref().unwrap(),
            ),
            Kind::Unavailable,
        )?;
        let (runtime, journal) =
            support::fresh_pair(other.clone(), DeploymentId::new(DEP), TenantId::new(TENANT))?;
        let resolver = support::session_resolver(
            f.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )?;
        check(
            resolver
                .install_gateway_authorization_journal(&journal)
                .is_err(),
            "fresh producer rejects different original Pool",
        )?;
        let (wrong_runtime, wrong_journal) = support::fresh_pair(
            f.pool.clone(),
            DeploymentId::new("other"),
            TenantId::new(TENANT),
        )?;
        check(
            resolver
                .install_gateway_authorization_journal(&wrong_journal)
                .is_err(),
            "fresh producer rejects different namespace",
        )?;
        check(
            f.rows().await?.is_empty() && f.audits().await?.is_empty(),
            "assembly/install no journal write",
        )?;
        resolver.close_request_bindings();
        runtime.close();
        wrong_runtime.close();
        other.close();
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n05_original_weak_enrollment_default_closed() {
    let admin = harness::admin_config("journal-n05");
    harness::with_temp_database(&admin, "ga_n05", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let resolver = support::session_resolver(
            f.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )?;
        let (runtime, journal) = f.fresh_pair()?;
        let auth = resolver
            .resolve(&parts(Some(COOKIE))?)
            .await
            .map_err(|e| e.to_string())?;
        let parent = CancellationToken::new();
        let metadata = f.metadata(parent.clone()).await?;
        let e = exact_error(
            journal
                .create_attempt(
                    &auth,
                    metadata,
                    Zeroizing::new(REDIRECT.into()),
                    parent,
                    Instant::now() + Duration::from_secs(30),
                )
                .await,
            Kind::Unavailable,
        )?;
        check(
            e.write_ack() == Ack::NotAttempted && e.readback_ack() == Ack::NotAttempted,
            "missing real producer enrollment fails before checkout",
        )?;
        resolver
            .install_gateway_authorization_journal(&journal)
            .map_err(|e| format!("{e:?}"))?;
        check(
            resolver
                .install_gateway_authorization_journal(&journal)
                .is_err(),
            "enrollment is once only",
        )?;
        let owner = create_on(
            &f,
            &journal,
            &auth,
            CancellationToken::new(),
            Duration::from_secs(30),
        )
        .await?;
        let prefix = f.rows().await?;
        drop(journal);
        let (next_runtime, next) = f.fresh_pair()?;
        check(
            resolver
                .install_gateway_authorization_journal(&next)
                .is_err(),
            "ended Weak enrollment cannot reopen",
        )?;
        exact_error(
            next.admit_registration(&auth, owner).await,
            Kind::Unavailable,
        )?;
        let fake = AuthContext::for_test(
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            ActorId::new(ACTOR),
            [Role::User],
            AuthGeneration::new(7),
            false,
        );
        let parent = CancellationToken::new();
        let metadata = f.metadata(parent.clone()).await?;
        let e = error(
            f.journal
                .create_attempt(
                    &fake,
                    metadata,
                    Zeroizing::new(REDIRECT.into()),
                    parent,
                    Instant::now() + Duration::from_secs(30),
                )
                .await,
        )?;
        check(
            e.kind() == Kind::Refused,
            "test identity alone does not grant Host",
        )?;
        // Synthetic Contracts attachment tests the default port only. This is not
        // Desktop production assembly or an independent journal authority source.
        use openbot_contracts::request_binding::{
            GatewayAuthorizationHostTarget, HostRequestBindingError, HostRequestBindingGuard,
            HostRequestBindingKind, RequestBindingOwnerLease,
        };
        struct DefaultGuard;
        impl HostRequestBindingGuard for DefaultGuard {
            fn verify_current<'a>(
                &'a self,
                _: &'a AuthContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), HostRequestBindingError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async { Ok(()) })
            }
        }
        struct ShapeTarget<'a>(&'a AuthContext);
        impl GatewayAuthorizationHostTarget for ShapeTarget<'_> {
            fn matches_authority(&self, _: &Arc<()>) -> bool {
                false
            }
            fn matches_auth(&self, auth: &AuthContext) -> bool {
                self.0 == auth
            }
        }
        let (lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
        let binding = issuer
            .bind_desktop_window(
                &auth,
                "owned-default-desktop-negative".into(),
                1,
                Arc::new(DefaultGuard),
            )
            .map_err(|e| format!("{e:?}"))?;
        let attached = auth
            .clone()
            .with_verified_request_binding(binding)
            .map_err(|e| format!("{e:?}"))?;
        let target = ShapeTarget(&attached);
        check(
            matches!(
                attached
                    .request_binding()
                    .unwrap()
                    .borrow_gateway_authorization_host_before(
                        &attached,
                        &target,
                        Instant::now() + Duration::from_secs(30)
                    ),
                Err(HostRequestBindingError::Unavailable)
            ),
            "synthetic Desktop default port is explicitly unavailable",
        )?;
        let parent = CancellationToken::new();
        let metadata = f.metadata(parent.clone()).await?;
        exact_error(
            f.journal
                .create_attempt(
                    &attached,
                    metadata,
                    Zeroizing::new(REDIRECT.into()),
                    parent,
                    Instant::now() + Duration::from_secs(30),
                )
                .await,
            Kind::Refused,
        )?;
        lease.close();
        check(
            f.rows().await? == prefix && f.audits().await?.len() == 1,
            "default/Weak/fake refusal no added write",
        )?;
        resolver.close_request_bindings();
        runtime.close();
        next_runtime.close();
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n06_current_actor_and_session_revocation() {
    let admin = harness::admin_config("journal-n06");
    for (index,mutation) in ["UPDATE public.users SET auth_generation=8 WHERE id='owned-journal-owner'","DELETE FROM public.user_roles WHERE user_id='owned-journal-owner'","INSERT INTO public.revoked_access(email,revoked_by) VALUES('journal@example.test','owned-journal-owner')","UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='owned-journal-session'","DELETE FROM public.sessions WHERE id='owned-journal-session'","DELETE FROM public.users WHERE id='owned-journal-owner'"].iter().enumerate() {
        harness::with_temp_database(&admin,&format!("ga_n06_{index}"),|cfg|async move {
            let f=Fixture::new(cfg,2).await?; let auth=f.auth().await?; let owner=created(&f,&auth).await?;
            execute(&f,mutation).await?; let audits=f.audits().await?;
            exact_error(f.journal.admit_registration(&auth,owner).await,Kind::Refused)?;
            check(f.audits().await?==audits,"revoked current facts cannot append admission")?;
            if index!=5 { check(f.rows().await?[0].phase=="created","rejected attempt remains created")?; }
            else { check(f.rows().await?.is_empty(),"actual owner FK cascade is recorded")?; }
            if index==4 {
                let fresh=f.auth_cookie(NEXT_COOKIE).await?; let new_owner=created(&f,&fresh).await?;
                check(f.rows().await?.len()==2 && f.audits().await?.len()==2,"revoked old session does not poison a new valid session")?; drop(new_owner);
            }
            f.finish().await
        }).await;
    }
    harness::with_temp_database(&admin, "ga_n06_host", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let owner = created(&f, &auth).await?;
        f.disarm_host();
        exact_error(
            f.journal.admit_registration(&auth, owner).await,
            Kind::Refused,
        )?;
        check(
            f.rows().await?[0].phase == "created" && f.audits().await?.len() == 1,
            "closed original Host no admission",
        )?;
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n07_actor_share_before_attempt_update() {
    let admin = harness::admin_config("journal-n07");
    harness::with_temp_database(&admin,"ga_n07",|cfg|async move {
        let f=Fixture::new(cfg,3).await?; let auth=f.auth().await?; let direct=f.direct().await?;
        for actor_blocked in [false,true] {
            let owner=created(&f,&auth).await?; let row=f.rows().await?.pop().ok_or("attempt missing")?;
            let mut blocker=direct.get().await.map_err(|e|e.to_string())?;
            let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
            if actor_blocked {tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&ACTOR]).await.map_err(|e|e.to_string())?;}
            else {tx.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE",&[&row.attempt_id]).await.map_err(|e|e.to_string())?;}
            let journal=f.journal.clone(); let auth_copy=auth.clone(); let pending=tokio::spawn(async move {journal.admit_registration(&auth_copy,owner).await});
            let mut observer=direct.get().await.map_err(|e|e.to_string())?; let until=Instant::now()+Duration::from_secs(3);
            let (backend,query)=loop {
                let seen=observer.query("SELECT pid,query FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))",&[&blocker_pid]).await.map_err(|e|e.to_string())?;
                if let Some(r)=seen.first() {break (r.get::<_,i32>(0),r.get::<_,String>(1));}
                check(Instant::now()<until,"actual producer never blocked on the original owned blocker")?; tokio::time::sleep(Duration::from_millis(10)).await;
            };
            if actor_blocked {check(query.contains("FROM public.users u") && query.contains("FOR SHARE OF u"),"actual actor SHARE query blocked before attempt lock")?;}
            else {
                check(query.contains("gateway_authorization_attempt_lock") && query.contains("FOR UPDATE"),"actual attempt UPDATE query blocked after actor SHARE")?;
                let locks=observer.query("SELECT mode,granted,relation::regclass::text FROM pg_locks WHERE pid=$1 AND relation IN('public.users'::regclass,'openbot_internal.gateway_authorization_attempts'::regclass)",&[&backend]).await.map_err(|e|e.to_string())?;
                check(locks.iter().any(|r|r.get::<_,String>(0)=="RowShareLock" && r.get::<_,bool>(1) && r.get::<_,String>(2)=="users"),"actual actor relation SHARE lock before attempt wait")?;
            }
            let probe=observer.transaction().await.map_err(|e|e.to_string())?;
            if actor_blocked {
                probe.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE NOWAIT",&[&row.attempt_id]).await.map_err(|e|e.to_string())?;
            } else {
                let e=probe.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT",&[&ACTOR]).await.err().ok_or("actor row was not SHARE locked before attempt wait")?;
                check(e.as_db_error().is_some_and(|d|d.code().code()=="55P03"),"actual actor SHARE blocks NOWAIT update")?;
            }
            probe.rollback().await.map_err(|e|e.to_string())?; drop(observer);
            eprintln!("GATEWAY_JOURNAL_LOCK_ORDER actual_backend={backend} original_blocker={blocker_pid} actor_blocked={actor_blocked} target_query_observed=true independent_NOWAIT_checked=true");
            tx.rollback().await.map_err(|e|e.to_string())?; drop(blocker);
            let receipt=pending.await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?; drop(receipt);
            check(f.row(row.attempt_id).await?.phase=="registration_admitted","original waiter continued only after lock release")?;
        }
        direct.close(); f.finish().await
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n08_exact48_schema_and_observation_errors() {
    let admin = harness::admin_config("journal-n08");
    for (index, sql, kind) in [
        (
            0,
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=48",
            Kind::LedgerInvalid,
        ),
        (
            1,
            "DELETE FROM openbot_internal.schema_migrations WHERE version=48",
            Kind::LedgerInvalid,
        ),
        (
            2,
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DROP CONSTRAINT ga_attempts_schema_check",
            Kind::SchemaInvalid,
        ),
        (
            3,
            "ALTER TABLE public.sessions RENAME TO sessions_query_unavailable",
            Kind::ObservationUnknown,
        ),
        (
            4,
            "ALTER TABLE public.users ALTER COLUMN auth_generation TYPE numeric USING auth_generation::numeric",
            Kind::ObservationUnknown,
        ),
    ] {
        harness::with_temp_database(&admin, &format!("ga_n08_{index}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let auth = f.auth().await?;
            let parent = CancellationToken::new();
            let metadata = f.metadata(parent.clone()).await?;
            execute(&f, sql).await?;
            if index == 4 {
                let client=f.pool.get().await.map_err(|e|e.to_string())?;
                let observed=client.query_one("SELECT pg_typeof(auth_generation)::text AS kind,auth_generation::text AS raw,auth_generation FROM public.users WHERE id=$1",&[&ACTOR]).await.map_err(|e|e.to_string())?;
                check(observed.get::<_,String>("kind")=="numeric" && observed.get::<_,String>("raw")=="7" && observed.try_get::<_,i64>("auth_generation").is_err(),"actual query succeeds with numeric7 while original i64 decoder fails")?;
                eprintln!("GATEWAY_JOURNAL_DECODE actual_query_succeeded=true actual_type=numeric original_value=7 original_i64_decode_failed=true");
            }
            let e = exact_error(
                f.journal
                    .create_attempt(
                        &auth,
                        metadata,
                        Zeroizing::new(REDIRECT.into()),
                        parent,
                        Instant::now() + Duration::from_secs(30),
                    )
                    .await,
                kind,
            )?;
            check(
                e.write_ack() == Ack::Timely && e.readback_ack() == Ack::NotAttempted,
                "actual failed write original ROLLBACK ACK",
            )?;
            check(
                f.rows().await?.is_empty() && f.audits().await?.is_empty(),
                "ledger/schema/query failure leaves no write",
            )?;
            f.finish().await
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n09_actual_audit_failure_rollback() {
    let admin = harness::admin_config("journal-n09");
    harness::with_temp_database(&admin,"ga_n09",|cfg|async move {
        let f=Fixture::new(cfg,2).await?; let auth=f.auth().await?;
        execute(&f,"CREATE FUNCTION public.owned_journal_audit_refusal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit refusal'; END $$; CREATE TRIGGER owned_journal_audit_refusal BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_journal_audit_refusal();").await?;
        let parent=CancellationToken::new(); let metadata=f.metadata(parent.clone()).await?;
        let e=exact_error(f.journal.create_attempt(&auth,metadata,Zeroizing::new(REDIRECT.into()),parent,Instant::now()+Duration::from_secs(30)).await,Kind::ObservationUnknown)?;
        check(e.write_ack()==Ack::Timely && e.readback_ack()==Ack::NotAttempted,"same original failed audit transaction true rollback ACK")?;
        check(f.rows().await?.is_empty() && f.audits().await?.is_empty(),"actual audit failure rolls back journal insert")?; f.finish().await
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n10_actual_commit_ack_known_late() {
    let admin = harness::admin_config("journal-n10");
    harness::with_temp_database(&admin,"ga_n10",|cfg|async move {
        let gate=PgTerminalAckGate::new(&cfg,TerminalStage::CreateCommit,false).await;
        let f=Fixture::new(gate.config.clone(),1).await?; let direct=pool::connect(&cfg).await.map_err(|e|e.to_string())?;
        let auth=f.auth().await?; let parent=CancellationToken::new(); let metadata=f.metadata(parent.clone()).await?;
        let original=gate.arm_original(&f).await; let pid=gate.original_pid();
        let deadline=Instant::now()+Duration::from_millis(900);
        let mut future=Box::pin(f.journal.create_attempt(&auth,metadata,Zeroizing::new(REDIRECT.into()),parent,deadline));
        tokio::select! { result=&mut future=>return Err(format!("original COMMIT was not held: {:?}",error(result)?)), ()=gate.held()=>{} }
        // The original business future stays unpolled across its own saved caller cap.
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline+Duration::from_millis(180))).await;
        gate.release_original_ack().await;
        let e=exact_error(future.await,Kind::CommitAcknowledgedAfterDeadline)?;
        check(e.write_ack()==Ack::Late && e.readback_ack()==Ack::NotAttempted,"real original late C/Z remains known Late")?; gate.assert_target(1);
        retired(&f,&original,pid,&direct).await?;
        check(f.rows().await?.len()==1 && f.rows().await?[0].phase=="created" && f.audits().await?.len()==1,"known committed row cannot mint a replacement owner")?;
        direct.close(); f.finish().await?; gate.stop().await; Ok(())
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n11_actual_commit_ack_loss_unknown() {
    let admin = harness::admin_config("journal-n11");
    for (index, stage) in [
        TerminalStage::CreateCommit,
        TerminalStage::AdmitCommit,
        TerminalStage::CloseCommit,
    ]
    .into_iter()
    .enumerate()
    {
        harness::with_temp_database(&admin, &format!("ga_n11_{index}"), |cfg| async move {
            let gate = PgTerminalAckGate::new(&cfg, stage, true).await;
            let f = Fixture::new(gate.config.clone(), 1).await?;
            let direct = pool::connect(&cfg).await.map_err(|e| e.to_string())?;
            let auth = f.auth().await?;
            let prepared = if index == 0 {
                None
            } else {
                Some(created(&f, &auth).await?)
            };
            let parent = CancellationToken::new();
            let metadata = if index == 0 {
                Some(f.metadata(parent.clone()).await?)
            } else {
                None
            };
            let original = gate.arm_original(&f).await;
            let pid = gate.original_pid();
            let e = if index == 0 {
                error(
                    f.journal
                        .create_attempt(
                            &auth,
                            metadata.unwrap(),
                            Zeroizing::new(REDIRECT.into()),
                            parent,
                            Instant::now() + Duration::from_secs(30),
                        )
                        .await,
                )?
            } else if index == 1 {
                error(f.journal.admit_registration(&auth, prepared.unwrap()).await)?
            } else {
                error(
                    f.journal
                        .close_created(&auth, prepared.unwrap(), ControlledCloseReason::Refused)
                        .await,
                )?
            };
            gate.held().await;
            gate.assert_target(0);
            check(
                e.kind() == Kind::CommitUnknown
                    && e.write_ack() == Ack::Unknown
                    && e.readback_ack() == Ack::NotAttempted,
                "lost original C/Z stays Unknown across all three writes",
            )?;
            retired(&f, &original, pid, &direct).await?;
            let rows = f.rows().await?;
            let phase = ["created", "registration_admitted", "closed"][index];
            check(
                rows.len() == 1 && rows[0].phase == phase,
                "later durable committed row observed only as data",
            )?;
            check(
                f.audits().await?.len() == if index == 0 { 1 } else { 2 },
                "actual lost ACK write/audit committed together",
            )?;
            direct.close();
            f.finish().await?;
            gate.stop().await;
            Ok(())
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n12_actual_readback_and_rollback_closure() {
    let admin = harness::admin_config("journal-n12");
    for index in 0..2 {
        harness::with_temp_database(&admin,&format!("ga_n12_m{index}"),|cfg|async move {
            let gate=PgTerminalAckGate::new(&cfg,TerminalStage::CreateCommit,false).await; let f=Fixture::new(gate.config.clone(),1).await?;
            let direct=pool::connect(&cfg).await.map_err(|e|e.to_string())?; let auth=f.auth().await?; let parent=CancellationToken::new(); let metadata=f.metadata(parent.clone()).await?;
            gate.arm_original(&f).await;
            let mut future=Box::pin(f.journal.create_attempt(&auth,metadata,Zeroizing::new(REDIRECT.into()),parent,Instant::now()+Duration::from_secs(30)));
            tokio::select! { result=&mut future=>return Err(format!("original write not held before readback: {:?}",error(result)?)), ()=gate.held()=>{} }
            let client=direct.get().await.map_err(|e|e.to_string())?;
            client.batch_execute(if index==0 {"UPDATE openbot_internal.gateway_authorization_attempts SET issuer='https://changed-readback.test'"} else {"ALTER TABLE public.sessions RENAME TO sessions_readback_query_unavailable"}).await.map_err(|e|e.to_string())?; drop(client);
            gate.release_original_ack().await;
            let e=error(future.await)?; check(e.kind()==if index==0 {Kind::ReadbackUnproven} else {Kind::ObservationUnknown},"actual readback mismatch/query unknown")?;
            check(e.write_ack()==Ack::Timely && e.readback_ack()==Ack::Timely,"known original COMMIT survives readback refusal and true ROLLBACK")?; gate.assert_target(1);
            check(f.rows().await?.len()==1 && f.audits().await?.len()==1,"later row is no replacement owner")?;
            direct.close(); f.finish().await?; gate.stop().await; Ok(())
        }).await;
    }
    for discard in [false, true] {
        harness::with_temp_database(&admin,if discard {"ga_n12_loss"} else {"ga_n12_late"},|cfg|async move {
            let gate=PgTerminalAckGate::new(&cfg,TerminalStage::ReadbackRollback,discard).await; let f=Fixture::new(gate.config.clone(),1).await?;
            let direct=pool::connect(&cfg).await.map_err(|e|e.to_string())?; let auth=f.auth().await?; let parent=CancellationToken::new(); let metadata=f.metadata(parent.clone()).await?;
            let original=gate.arm_original(&f).await; let pid=gate.original_pid(); let deadline=Instant::now()+Duration::from_millis(900);
            let mut future=Box::pin(f.journal.create_attempt(&auth,metadata,Zeroizing::new(REDIRECT.into()),parent,deadline));
            let e=if discard {let result=future.await; gate.held().await; error(result)?} else {
                tokio::select! { result=&mut future=>return Err(format!("original read-only rollback not held: {:?}",error(result)?)), ()=gate.held()=>{} }
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline+Duration::from_millis(180))).await;
                gate.release_original_ack().await; error(future.await)?
            };
            check(e.kind()==if discard {Kind::RollbackUnproven} else {Kind::RollbackAcknowledgedAfterDeadline},"actual original read-only rollback terminal")?;
            check(e.write_ack()==Ack::Timely && e.readback_ack()==if discard {Ack::Unknown} else {Ack::Late},"readback terminal never downgrades original timely write ACK")?;
            gate.assert_target(usize::from(!discard)); retired(&f,&original,pid,&direct).await?;
            check(f.rows().await?.len()==1 && f.audits().await?.len()==1,"unproven readback cannot restore live owner")?;
            direct.close(); f.finish().await?; gate.stop().await; Ok(())
        }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n13_original_parent_flow_and_capture_deadlines() {
    let admin = harness::admin_config("journal-n13");
    harness::with_temp_database(&admin, "ga_n13", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let parent = CancellationToken::new();
        let metadata = f.metadata(parent.clone()).await?;
        parent.cancel();
        exact_error(
            f.journal
                .create_attempt(
                    &auth,
                    metadata,
                    Zeroizing::new(REDIRECT.into()),
                    parent,
                    Instant::now() + Duration::from_secs(30),
                )
                .await,
            Kind::Cancelled,
        )?;
        check(
            f.rows().await?.is_empty() && f.audits().await?.is_empty(),
            "cancelled original parent before first sample writes0",
        )?;
        let parent = CancellationToken::new();
        let owner = create_on(
            &f,
            &f.journal,
            &auth,
            parent.clone(),
            Duration::from_secs(60),
        )
        .await?;
        parent.cancel();
        exact_error(
            f.journal.admit_registration(&auth, owner).await,
            Kind::Cancelled,
        )?;
        let parent = CancellationToken::new();
        let owner = create_on(
            &f,
            &f.journal,
            &auth,
            parent.clone(),
            Duration::from_millis(700),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(800)).await;
        exact_error(
            f.journal.admit_registration(&auth, owner).await,
            Kind::Deadline,
        )?;
        let parent = CancellationToken::new();
        let owner = create_on(
            &f,
            &f.journal,
            &auth,
            parent.clone(),
            Duration::from_secs(60),
        )
        .await?;
        // Real monotonic elapsed time, no synthetic public clock and no replacement10s budget.
        tokio::time::sleep(Duration::from_millis(10_200)).await;
        check(
            !parent.is_cancelled(),
            "original parent remains live at captured cap",
        )?;
        exact_error(
            f.journal.admit_registration(&auth, owner).await,
            Kind::Deadline,
        )?;
        check(
            f.rows().await?.len() == 3
                && f.rows().await?.iter().all(|r| r.phase == "created")
                && f.audits().await?.len() == 3,
            "original caller/parent/entered10s refuse without new admission",
        )?;
        f.finish().await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n14_controlled_created_and_admitted_close() {
    let admin = harness::admin_config("journal-n14");
    for admitted in [false, true] {
        for reason in [
            ControlledCloseReason::Refused,
            ControlledCloseReason::DependencyUnknown,
        ] {
            harness::with_temp_database(
                &admin,
                if admitted {
                    "ga_n14_admit"
                } else {
                    "ga_n14_create"
                },
                |cfg| async move {
                    let f = Fixture::new(cfg, 2).await?;
                    let auth = f.auth().await?;
                    let owner = created(&f, &auth).await?;
                    let id = f.rows().await?[0].attempt_id;
                    let before = if admitted {
                        let receipt = f
                            .journal
                            .admit_registration(&auth, owner)
                            .await
                            .map_err(|e| e.to_string())?;
                        let before = f.row(id).await?;
                        f.journal
                            .close_admitted(&auth, receipt, reason)
                            .await
                            .map_err(|e| e.to_string())?;
                        before
                    } else {
                        let before = f.row(id).await?;
                        f.journal
                            .close_created(&auth, owner, reason)
                            .await
                            .map_err(|e| e.to_string())?;
                        before
                    };
                    let after = f.row(id).await?;
                    let outcome = if matches!(reason, ControlledCloseReason::Refused) {
                        "refused"
                    } else {
                        "dependency_unknown"
                    };
                    let mut expected = before.clone();
                    expected.phase = "closed".into();
                    expected.updated_at = after.updated_at;
                    expected.finished_at = Some(after.updated_at);
                    expected.outcome_code = Some(outcome.into());
                    check(
                        after == expected
                            && after.updated_at >= before.updated_at
                            && after.updated_at < before.expires_at,
                        "close changes only four facts in original finite budget",
                    )?;
                    let audits = f.audits().await?;
                    check(
                        audits.len() == if admitted { 3 } else { 2 },
                        "close same-Tx audit prefix",
                    )?;
                    audit_facts(audits.last().unwrap(), id, "closed", Some(outcome))?;
                    f.finish().await
                },
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n15_closed_prefix_and_terminal_refusal() {
    let admin = harness::admin_config("journal-n15");
    for (index,set) in ["phase='registration_admitted',registration_admitted_at=created_at","phase='registered',registration_admitted_at=created_at,client_id='owned-client',enrollment_id=$2","phase='code_admitted',registration_admitted_at=created_at,client_id='owned-client',enrollment_id=$2,code_admitted_at=created_at","phase='enrolled',registration_admitted_at=created_at,client_id='owned-client',enrollment_id=$2,code_admitted_at=created_at,finished_at=updated_at,outcome_code='enrolled'","phase='closed',finished_at=updated_at,outcome_code='restart_denied'","phase='closed',registration_admitted_at=created_at,client_id='owned-client',enrollment_id=$2,finished_at=updated_at,outcome_code='registration_unknown'"].iter().enumerate() {
        harness::with_temp_database(&admin,&format!("ga_n15_{index}"),|cfg|async move {
            let f=Fixture::new(cfg,2).await?; let auth=f.auth().await?; let owner=created(&f,&auth).await?; let id=f.rows().await?[0].attempt_id;
            let client=f.pool.get().await.map_err(|e|e.to_string())?; let enrollment=uuid::Uuid::now_v7(); let sql=format!("UPDATE openbot_internal.gateway_authorization_attempts SET {set} WHERE attempt_id=$1");
            if set.contains("$2") {client.execute(&sql,&[&id,&enrollment]).await.map_err(|e|e.to_string())?;} else {client.execute(&sql,&[&id]).await.map_err(|e|e.to_string())?;} drop(client);
            let prefix=f.row(id).await?; let audits=f.audits().await?;
            exact_error(f.journal.close_created(&auth,owner,ControlledCloseReason::Refused).await,Kind::Refused)?;
            check(f.row(id).await?==prefix && f.audits().await?==audits,"original owner cannot overwrite foreign/later/closed prefix or NULL shape")?; f.finish().await
        }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL17.11 and pinned local TLS Python"]
async fn n16_old_runtime_and_owner_lifetime() {
    let admin = harness::admin_config("journal-n16");
    for close in [true, false] {
        harness::with_temp_database(
            &admin,
            if close { "ga_n16_close" } else { "ga_n16_drop" },
            |cfg| async move {
                let mut f = Fixture::new(cfg, 2).await?;
                let auth = f.auth().await?;
                let owner = created(&f, &auth).await?;
                let original = f.rows().await?.remove(0);
                if close {
                    f.runtime.as_ref().unwrap().close();
                } else {
                    drop(f.runtime.take());
                }
                exact_error(
                    f.journal.admit_registration(&auth, owner).await,
                    Kind::Unavailable,
                )?;
                let (runtime, journal) = f.fresh_pair()?;
                let resolver = support::session_resolver(
                    f.pool.clone(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )?;
                resolver
                    .install_gateway_authorization_journal(&journal)
                    .map_err(|e| format!("{e:?}"))?;
                let auth = resolver
                    .resolve(&parts(Some(COOKIE))?)
                    .await
                    .map_err(|e| e.to_string())?;
                let owner = create_on(
                    &f,
                    &journal,
                    &auth,
                    CancellationToken::new(),
                    Duration::from_secs(30),
                )
                .await?;
                let rows = f.rows().await?;
                check(
                    rows.len() == 2
                        && rows[0] == original
                        && rows[1].installation_id == original.installation_id
                        && rows[1].runtime_epoch != original.runtime_epoch,
                    "new boot keeps installation but never restores prior runtime/ID",
                )?;
                drop(owner);
                check(
                    f.rows().await? == rows,
                    "opaque owner Drop leaves created prefix as data",
                )?;
                resolver.close_request_bindings();
                runtime.close();
                f.finish().await
            },
        )
        .await;
    }
    harness::with_temp_database(&admin, "ga_n16_other", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let owner = created(&f, &auth).await?;
        let (runtime, journal) = f.fresh_pair()?;
        exact_error(
            journal.admit_registration(&auth, owner).await,
            Kind::Refused,
        )?;
        check(
            f.rows().await?[0].phase == "created" && f.audits().await?.len() == 1,
            "another journal cannot assume original Weak authority",
        )?;
        runtime.close();
        f.finish().await
    })
    .await;
}
