//! W-5 batch 4：Policy HTTP → ApplicationService → PostgreSQL store 真腿。

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use harness::{admin_config, with_temp_database};
use openbot_application::{ApplicationService, OpenBotApplication};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::session::{SessionLifetimePolicy, TrustedOrigins};
use openbot_domain::policy::PolicyMode;
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::{PolicyOrigin, PolicyStore};
use openbot_infra::repo::ChannelRepo;
use openbot_server::{
    SINGLE_USER_ACTOR_ID, SensitiveWriteSecurity, ServerBuilder, SingleUserAuthResolver, router,
};
use time::Duration;
use tower::ServiceExt as _;

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(Duration::hours(8), Duration::days(7), Duration::minutes(15))
        .unwrap()
}

async fn send(
    router: axum::Router,
    request: Request<Body>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn policy_http_persists_authoritative_actor_and_survives_a_new_store() {
    let admin = admin_config("policy_http_persists_authoritative_actor_and_survives_a_new_store");
    with_temp_database(&admin, "policy_http", |config| async move {
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

            let policies = PolicyStore::postgres(pool.clone(), None);
            if policies.load().await.map_err(|error| error.to_string())?
                != PolicyOrigin::Unconfigured
            {
                return Err("fresh policy store 没有保持 Unconfigured".to_owned());
            }
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policies.clone()),
            );
            initialize_single_user(&pool, true)
                .await
                .map_err(|error| error.to_string())?;
            let principal = load_single_user_principal(
                &pool,
                DeploymentId::new("dep"),
                TenantId::new("tenant"),
            )
            .await
            .map_err(|error| error.to_string())?;
            let resolver = SingleUserAuthResolver::from_verified_principal(principal, lifetime());
            let security = SensitiveWriteSecurity::new(
                lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"])
                    .map_err(|error| error.to_string())?,
            );
            let router = router(
                ServerBuilder::new(application, Arc::new(resolver))
                    .with_sensitive_write_security(security)
                    .build(),
            );

            let (status, body) = send(
                router.clone(),
                Request::builder()
                    .uri("/api/computers/policy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            if status != axum::http::StatusCode::OK || !body["policy"].is_null() {
                return Err(format!("fresh policy GET 不符：{status} {body}"));
            }

            let payload = r#"{"mode":"dry-run","deny":["false"],"allow":["true"]}"#;
            let (status, body) = send(
                router.clone(),
                Request::builder()
                    .method("PUT")
                    .uri("/api/computers/policy")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await;
            if status != axum::http::StatusCode::FORBIDDEN
                || body["code"] != "identity_sensitive_write_origin_missing"
            {
                return Err(format!("缺 Origin policy PUT 不符：{status} {body}"));
            }

            let (status, body) = send(
                router,
                Request::builder()
                    .method("PUT")
                    .uri("/api/computers/policy")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .header(axum::http::header::ORIGIN, "https://app.example.test")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await;
            if status != axum::http::StatusCode::OK || body["policy"]["mode"] != "dry-run" {
                return Err(format!("trusted policy PUT 不符：{status} {body}"));
            }

            let row = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT mode,updated_by FROM public.action_policy WHERE id='current'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let mode: String = row.get(0);
            let updated_by: Option<String> = row.get(1);
            let restarted = PolicyStore::postgres(pool.clone(), None);
            if mode != "dry-run"
                || updated_by.as_deref() != Some(SINGLE_USER_ACTOR_ID)
                || restarted.load().await.map_err(|error| error.to_string())?
                    != PolicyOrigin::Database
                || restarted
                    .current()
                    .is_none_or(|policy| policy.mode != PolicyMode::DryRun)
            {
                return Err(format!(
                    "policy 真行/重启不符：mode={mode} updated_by={updated_by:?}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
