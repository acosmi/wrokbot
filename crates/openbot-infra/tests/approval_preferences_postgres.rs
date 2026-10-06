//! Internal preference refusal and original pool-owner mechanics. Synthetic guards and the
//! black-hole socket below are deliberate fault fixtures, never production host authority.

mod harness;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_application::approval_preferences::{
    RememberPreferenceRepository, RememberPreferenceRepositoryError as Error,
};
use openbot_contracts::approval_preferences::{RememberPreference, RememberPreferenceTarget};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    RequestBindingOwnerLease,
};
use openbot_domain::vault::SecretBytes;
use openbot_infra::approval_preferences::PostgresRememberPreferenceRepository;
use openbot_infra::db::pool::{ConnectionDestruction, DatabaseConfig, DatabasePool};
use openbot_infra::db::{baseline, native, pool};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct SyntheticAllowGuard;
impl HostRequestBindingGuard for SyntheticAllowGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    // The production same-Pool preference host loan is deliberately not implemented.
}

fn synthetic_auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("refusal-deployment"),
        TenantId::new("refusal-tenant"),
        ActorId::new("synthetic-owner"),
        AuthGeneration::new(0),
        true,
    )
    .with_role(Role::Admin)
    .build()
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn missing_and_unenrolled_host_cannot_create_preference() {
    harness::with_temp_database(
        &harness::admin_config("missing_and_unenrolled_host_cannot_create_preference"),
        "preference_refusal",
        |config| async move {
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            {
                let mut client = pool.get().await.map_err(|e| e.to_string())?;
                baseline::apply(&client).await.map_err(|e| e.to_string())?;
                native::apply(&mut client)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let make_repository = || {
                PostgresRememberPreferenceRepository::new(
                    pool.clone(),
                    DeploymentId::new("refusal-deployment"),
                    TenantId::new("refusal-tenant"),
                    SecretBytes::new(vec![0x61; 32]),
                )
                .map_err(|e| e.to_string())
            };
            let plain = synthetic_auth();
            let repository = make_repository()?;
            let bot = BotId::new("not-a-production-bot");
            require(
                repository
                    .write(
                        &plain,
                        &bot,
                        RememberPreferenceTarget::User,
                        RememberPreference::Never,
                        None,
                    )
                    .await
                    == Err(Error::Unavailable),
                "unenrolled repository accepted a plain context",
            )?;
            let (owner, issuer) = RequestBindingOwnerLease::for_trusted_host(
                HostRequestBindingKind::ServerSingleUserOwner,
            );
            let synthetic = plain
                .clone()
                .with_verified_request_binding(
                    issuer
                        .bind_single_user_owner(&plain, Arc::new(SyntheticAllowGuard))
                        .map_err(|_| "synthetic fixture binding failed".to_owned())?,
                )
                .map_err(|_| "synthetic fixture attachment failed".to_owned())?;
            require(
                repository
                    .write(
                        &synthetic,
                        &bot,
                        RememberPreferenceTarget::User,
                        RememberPreference::Never,
                        None,
                    )
                    .await
                    == Err(Error::Unavailable),
                "unenrolled synthetic host accepted",
            )?;
            repository
                .enroll_host_issuer(&issuer)
                .map_err(|_| "synthetic enrollment fixture failed".to_owned())?;
            require(
                repository
                    .read(&plain, &bot, RememberPreferenceTarget::User)
                    .await
                    == Err(Error::NotVisible),
                "missing original host was treated as current",
            )?;
            require(
                repository
                    .write(
                        &synthetic,
                        &bot,
                        RememberPreferenceTarget::User,
                        RememberPreference::Never,
                        None,
                    )
                    .await
                    == Err(Error::Unavailable),
                "verify_current=true supplied production preference authority",
            )?;
            require(
                repository
                    .write(
                        &synthetic,
                        &bot,
                        RememberPreferenceTarget::User,
                        RememberPreference::Ask,
                        Some(0),
                    )
                    .await
                    == Err(Error::InvalidInput {
                        field: "expected_revision",
                    }),
                "nonpositive expected revision did not fail before host/database access",
            )?;
            owner.close();
            let client = pool.get().await.map_err(|e| e.to_string())?;
            let row = client
                .query_one(
                    "SELECT (SELECT count(*) FROM openbot_internal.approval_preferences),
                        (SELECT count(*) FROM public.audit_events),
                        (SELECT count(*) FROM public.audit_checkpoints)",
                    &[],
                )
                .await
                .map_err(|e| e.to_string())?;
            require(
                (0..3).all(|i| row.get::<_, i64>(i) == 0),
                "refusal wrote a preference, audit or checkpoint",
            )?;
            drop(client);
            pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly invoked owned loopback fault fixture; no external database"]
async fn synthetic_connect_cancellation_destroys_original_connect_future() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("owned black-hole listener");
    let port = listener
        .local_addr()
        .expect("owned listener address")
        .port();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("owned original socket");
        let _ = accepted_tx.send(());
        let mut buffer = [0_u8; 4096];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    let _ = eof_tx.send(());
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    let config =
        DatabaseConfig::new("127.0.0.1", port, "synthetic", "synthetic").with_max_pool_size(1);
    let pool = DatabasePool::build_unprobed(&config).expect("unprobed owned pool");
    let connecting_pool = pool.clone();
    let original_get = tokio::spawn(async move { connecting_pool.get().await });
    tokio::time::timeout(Duration::from_secs(2), accepted_rx)
        .await
        .expect("original socket accepted within fixture budget")
        .expect("accepted signal");
    let observation = pool
        .connection_observations()
        .into_iter()
        .next()
        .expect("original connecting owner observation before cancellation");
    assert!(observation.snapshot().connecting_future_started);
    assert!(!observation.snapshot().connection_started);
    original_get.abort();
    assert!(
        original_get
            .await
            .expect_err("original get cancelled")
            .is_cancelled()
    );
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(
        observation
            .wait_for_destruction_before(cleanup_deadline)
            .await
            .expect("real original connect future destructor"),
        ConnectionDestruction::ConnectingFutureDestroyed
    );
    tokio::time::timeout_at(tokio::time::Instant::from_std(cleanup_deadline), eof_rx)
        .await
        .expect("same accepted socket EOF after cancellation")
        .expect("EOF signal");
    peer.await.expect("owned socket observer completed");
    pool.close();
}
