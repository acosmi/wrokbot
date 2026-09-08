//! W-4 production PostgreSQL AuthResolver 的 PostgreSQL 17 真库矩阵。

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use axum::body::{Body, to_bytes};
use harness::{admin_config, with_temp_database};
use http::Request;
use openbot_application::{ApplicationService, OpenBotApplication};
use openbot_contracts::auth::Role;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder, router,
};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

const RAW_TOKEN: &str = "raw-session-token-with-enough-entropy-001";
const SECOND_RAW_TOKEN: &str = "raw-session-token-with-enough-entropy-002";
const SESSION_KEY: &[u8] = b"postgres-auth-resolver-test-session-key";

async fn provision(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn seed_session(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let now = OffsetDateTime::now_utc();
    let token_hash = SessionTokenHash::compute(
        SessionToken::new(RAW_TOKEN.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.users(id,email,name,auth_generation) VALUES($1,$2,$3,$4)",
            &[&"actor-1", &"actor@example.test", &"Actor", &2_i64],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::role)",
            &[&"actor-1", &"admin"],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.sessions \
             (id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
             VALUES($1,$2,$3,$4,$5,$5,$6)",
            &[
                &"session-1",
                &"actor-1",
                &token_hash,
                &(now + Duration::hours(1)),
                &(now - Duration::minutes(1)),
                &2_i64,
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn resolver(pool: &deadpool_postgres::Pool) -> PostgresSessionAuthResolver {
    PostgresSessionAuthResolver::new(
        pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        DeploymentId::new("dep-1"),
        TenantId::new("tenant-1"),
    )
    .unwrap()
}

fn parts(cookie: &str) -> http::request::Parts {
    Request::builder()
        .header(http::header::COOKIE, cookie)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn keyed_cookie_resolves_authoritative_acl_generation_and_live_session() {
    let admin = admin_config("keyed_cookie_resolves_authoritative_acl_generation_and_live_session");
    with_temp_database(&admin, "server_auth_valid", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            seed_session(&pool).await?;
            let resolver = resolver(&pool);
            let resolved = resolver
                .resolve_with_assurance(&parts(&format!("openbot_session={RAW_TOKEN}")))
                .await
                .map_err(|error| error.to_string())?;
            if resolved.context().actor().as_str() != "actor-1"
                || !resolved.context().has_role(Role::Admin)
                || resolved.context().auth_generation()
                    != openbot_contracts::auth::AuthGeneration::new(2)
                || resolved.live_session().is_none()
            {
                return Err(format!("解析出的权威身份不符：{resolved:?}"));
            }
            let stored: String = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT token FROM public.sessions WHERE id='session-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !stored.starts_with("sh1_") || stored.contains(RAW_TOKEN) {
                return Err("数据库没有只存 keyed hash".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn old_plaintext_duplicate_cookie_and_generation_change_all_fail_closed() {
    let admin =
        admin_config("old_plaintext_duplicate_cookie_and_generation_change_all_fail_closed");
    with_temp_database(&admin, "server_auth_reject", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            seed_session(&pool).await?;
            let resolver = resolver(&pool);
            let duplicate = resolver
                .resolve(&parts(&format!(
                    "openbot_session={RAW_TOKEN}; openbot_session={RAW_TOKEN}"
                )))
                .await;
            if duplicate != Err(AppError::Unauthenticated) {
                return Err(format!("重复 cookie 未 fail-closed：{duplicate:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.sessions \
                     (id,user_id,token,expires_at,auth_generation) VALUES($1,$2,$3,$4,NULL)",
                    &[
                        &"legacy-session",
                        &"actor-1",
                        &"legacy-plaintext-token",
                        &(OffsetDateTime::now_utc() + Duration::hours(1)),
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;
            if resolver
                .resolve(&parts("openbot_session=legacy-plaintext-token"))
                .await
                != Err(AppError::Unauthenticated)
            {
                return Err("旧 plaintext session 被 Rust resolver 接受".to_owned());
            }

            client
                .execute(
                    "UPDATE public.users SET auth_generation=3 WHERE id='actor-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if resolver
                .resolve(&parts(&format!("openbot_session={RAW_TOKEN}")))
                .await
                != Err(AppError::Unauthenticated)
            {
                return Err("旧 generation session 在角色变化后仍可用".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn revoke_expiry_and_missing_role_never_degrade_to_a_user_session() {
    let admin = admin_config("revoke_expiry_and_missing_role_never_degrade_to_a_user_session");
    with_temp_database(&admin, "server_auth_guards", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            seed_session(&pool).await?;
            let resolver = resolver(&pool);
            let client = pool.get().await.map_err(|error| error.to_string())?;

            client
                .execute("DELETE FROM public.user_roles WHERE user_id='actor-1'", &[])
                .await
                .map_err(|error| error.to_string())?;
            let missing_role = resolver
                .resolve(&parts(&format!("openbot_session={RAW_TOKEN}")))
                .await;
            if !matches!(missing_role, Err(AppError::ForbiddenRole { .. })) {
                return Err(format!("缺角色被降级成 user：{missing_role:?}"));
            }
            client
                .execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES('actor-1','admin')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.revoked_access(email,revoked_by) VALUES($1,$2)",
                    &[&"actor@example.test", &"admin"],
                )
                .await
                .map_err(|error| error.to_string())?;
            if resolver
                .resolve(&parts(&format!("openbot_session={RAW_TOKEN}")))
                .await
                != Err(AppError::Unauthenticated)
            {
                return Err("revoked actor 仍可用 session".to_owned());
            }
            client
                .execute("DELETE FROM public.revoked_access", &[])
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.sessions SET expires_at=clock_timestamp()-interval '1 second' \
                     WHERE id='session-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if resolver
                .resolve(&parts(&format!("openbot_session={RAW_TOKEN}")))
                .await
                != Err(AppError::Unauthenticated)
            {
                return Err("expired session 仍可用".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn real_cookie_to_http_application_people_and_audit_is_one_vertical_slice() {
    let admin =
        admin_config("real_cookie_to_http_application_people_and_audit_is_one_vertical_slice");
    with_temp_database(&admin, "server_auth_http", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            seed_session(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.users(id,email,name) VALUES($1,$2,$3)",
                    &[&"target", &"target@example.test", &"Target"],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::role)",
                    &[&"target", &"user"],
                )
                .await
                .map_err(|error| error.to_string())?;

            let people = PostgresPeopleAdministration::new(
                pool.clone(),
                None,
                b"server-http-people-audit-key".to_vec(),
            )
            .map_err(|error| error.to_string())?;
            let application: std::sync::Arc<dyn ApplicationService> = std::sync::Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone())).with_people(people),
            );
            let auth = resolver(&pool);
            let security = SensitiveWriteSecurity::new(
                default_session_lifetime(),
                openbot_domain::identity::session::TrustedOrigins::from_configured([
                    "https://app.example.test",
                ])
                .unwrap(),
            );
            let app = router(
                ServerBuilder::new(application, std::sync::Arc::new(auth))
                    .with_sensitive_write_security(security)
                    .build(),
            );
            let cookie = format!("openbot_session={RAW_TOKEN}");

            let me = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/me")
                        .header(http::header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if me.status() != http::StatusCode::OK {
                return Err(format!("真实 /api/me 状态不符：{}", me.status()));
            }
            let body = to_bytes(me.into_body(), 1024 * 1024)
                .await
                .map_err(|error| error.to_string())?;
            let json: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            if json["user"]["id"] != "actor-1" || json["user"]["role"] != "admin" {
                return Err(format!("真实 /api/me body 不符：{json}"));
            }

            let touched_before_rejection: OffsetDateTime = client
                .query_one(
                    "SELECT updated_at FROM public.sessions WHERE id='session-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/people/target/role")
                        .header(http::header::COOKIE, &cookie)
                        .header(http::header::ORIGIN, "https://evil.example.test")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"role":"admin"}"#))
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if rejected.status() != http::StatusCode::FORBIDDEN {
                return Err("坏 Origin 没被拒绝".to_owned());
            }
            let touched_after_rejection: OffsetDateTime = client
                .query_one(
                    "SELECT updated_at FROM public.sessions WHERE id='session-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if touched_after_rejection != touched_before_rejection {
                return Err("被拒 CSRF 请求错误续了 session idle".to_owned());
            }

            let changed = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/people/target/role")
                        .header(http::header::COOKIE, &cookie)
                        .header(http::header::ORIGIN, "https://app.example.test")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"role":"admin"}"#))
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if changed.status() != http::StatusCode::OK {
                return Err(format!("真实 role route 状态不符：{}", changed.status()));
            }
            let changed = to_bytes(changed.into_body(), 1024 * 1024)
                .await
                .map_err(|error| error.to_string())?;
            let json: serde_json::Value =
                serde_json::from_slice(&changed).map_err(|error| error.to_string())?;
            if json["person"]["role"] != "admin" {
                return Err(format!("真实 role response 不符：{json}"));
            }
            let facts = client
                .query_one(
                    "SELECT \
                       (SELECT coalesce(auth_generation,0) FROM public.users WHERE id='target'), \
                       (SELECT count(*)::bigint FROM public.audit_events \
                        WHERE event_type='person.role_changed')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if facts.get::<_, i64>(0) != 1 || facts.get::<_, i64>(1) != 1 {
                return Err("HTTP role 写没有同批推进 generation/audit".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn sign_out_deletes_only_the_resolved_session_and_same_cookie_immediately_fails() {
    let admin = admin_config(
        "sign_out_deletes_only_the_resolved_session_and_same_cookie_immediately_fails",
    );
    with_temp_database(&admin, "server_auth_signout", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            seed_session(&pool).await?;
            let now = OffsetDateTime::now_utc();
            let second_hash = SessionTokenHash::compute(
                SessionToken::new(SECOND_RAW_TOKEN.as_bytes()),
                SessionHashKey::new(SESSION_KEY),
            )
            .to_column_value();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.sessions \
                     (id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
                     VALUES($1,$2,$3,$4,$5,$5,$6)",
                    &[
                        &"session-2",
                        &"actor-1",
                        &second_hash,
                        &(now + Duration::hours(1)),
                        &(now - Duration::minutes(1)),
                        &2_i64,
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;

            let application: std::sync::Arc<dyn ApplicationService> =
                std::sync::Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())));
            let app = router(
                ServerBuilder::new(application, std::sync::Arc::new(resolver(&pool)))
                    .with_sensitive_write_security(SensitiveWriteSecurity::new(
                        default_session_lifetime(),
                        openbot_domain::identity::session::TrustedOrigins::from_configured([
                            "https://app.example.test",
                        ])
                        .unwrap(),
                    ))
                    .build(),
            );
            let first_cookie = format!("openbot_session={RAW_TOKEN}");
            let second_cookie = format!("openbot_session={SECOND_RAW_TOKEN}");

            let status = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/me/session")
                        .header(http::header::COOKIE, &first_cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if status.status() != http::StatusCode::OK {
                return Err(format!("session status 非200：{}", status.status()));
            }
            let body = to_bytes(status.into_body(), 1024 * 1024)
                .await
                .map_err(|error| error.to_string())?;
            if serde_json::from_slice::<serde_json::Value>(&body)
                .map_err(|error| error.to_string())?["revocable"]
                != true
            {
                return Err("multi-user session 没投影 revocable=true".to_owned());
            }

            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/sign-out")
                        .header(http::header::COOKIE, &first_cookie)
                        .header(http::header::ORIGIN, "https://evil.example.test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if rejected.status() != http::StatusCode::FORBIDDEN {
                return Err("坏Origin登出未被拒绝".to_owned());
            }
            let before: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.sessions", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if before != 2 {
                return Err("被拒登出删了session".to_owned());
            }

            let signed_out = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/sign-out")
                        .header(http::header::COOKIE, &first_cookie)
                        .header(http::header::ORIGIN, "https://app.example.test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if signed_out.status() != http::StatusCode::NO_CONTENT {
                return Err(format!("登出非204：{}", signed_out.status()));
            }
            let clear_cookie = signed_out
                .headers()
                .get(http::header::SET_COOKIE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if clear_cookie != "openbot_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" {
                return Err(format!("清cookie不精确：{clear_cookie}"));
            }

            let remaining = client
                .query("SELECT id FROM public.sessions ORDER BY id", &[])
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| {
                    row.try_get::<_, String>(0)
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if remaining != ["session-2"] {
                return Err(format!("登出删除范围不精确：{remaining:?}"));
            }

            let old = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/channels")
                        .header(http::header::COOKIE, &first_cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if old.status() != http::StatusCode::UNAUTHORIZED {
                return Err("已登出cookie仍能认证".to_owned());
            }
            let other = app
                .oneshot(
                    Request::builder()
                        .uri("/api/channels")
                        .header(http::header::COOKIE, &second_cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .map_err(|error| error.to_string())?;
            if other.status() != http::StatusCode::OK {
                return Err("登出错误撤了其他session".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
