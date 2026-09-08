//! W-5 batch 3：audit typed write、append-only 与管理员 keyset reader 真库矩阵。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{AuditPageRequest, AuditReadError, AuditReader};
use openbot_contracts::ids::{ActorId, AuditEventId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::audit::{AuditEventRepo, PostgresAuditReader};
use time::macros::datetime;

const AUDIT_KEY: &[u8] = b"audit-reader-postgres17-test-key";

async fn provision(
    config: &openbot_infra::db::pool::DatabaseConfig,
) -> Result<deadpool_postgres::Pool, String> {
    let pool = pool::connect(config)
        .await
        .map_err(|error| format!("连接临时库失败：{error}"))?;
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    drop(client);
    Ok(pool)
}

fn event(
    id: &str,
    actor: &str,
    event_type: &str,
    target_type: &'static str,
    target_id: &str,
    at: time::OffsetDateTime,
    output_bytes: u64,
) -> AuditEvent {
    AuditEvent {
        id: AuditEventId::new(id),
        actor: Some(ActorId::new(actor)),
        event_type: AuditEventType::parse(event_type).expect("测试 event type 在固定目录"),
        target_kind: AuditLabel::new(target_type),
        target_id: Some(AuditIdentifier::new(target_id).unwrap()),
        payload: AuditPayload::from_facts([AuditFact::OutputBytes(output_bytes)]).unwrap(),
        created_at: at,
    }
}

async fn seed_events(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let repo = AuditEventRepo::new(pool.clone());
    for event in [
        event(
            "018f47d2-2c00-7000-8000-000000000001",
            "admin",
            "connector.sync_succeeded",
            "connector",
            "drive-1",
            datetime!(2026-08-13 12:00:00 UTC),
            1,
        ),
        event(
            "018f47d2-2c00-7000-8000-000000000002",
            "member",
            "connector.sync_failed",
            "connector",
            "drive-2",
            datetime!(2026-08-13 12:00:01 UTC),
            2,
        ),
        event(
            "018f47d2-2c00-7000-8000-000000000003",
            "admin",
            "connector.sync_succeeded",
            "connector",
            "drive-1",
            datetime!(2026-08-13 12:00:02 UTC),
            3,
        ),
    ] {
        repo.append(&event, AUDIT_KEY)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn filtered_audit_keyset_page_is_exact_and_reaches_every_row_once() {
    let admin = admin_config("filtered_audit_keyset_page_is_exact_and_reaches_every_row_once");
    with_temp_database(&admin, "audit_page", |config| async move {
        let pool = provision(&config).await?;
        let outcome = async {
            seed_events(&pool).await?;
            let reader = PostgresAuditReader::new(pool.clone());
            let request = |cursor| AuditPageRequest {
                cursor,
                event_types: vec!["connector.sync_succeeded".to_owned()],
                actor_user_id: Some(ActorId::new("admin")),
                target_type: Some("connector".to_owned()),
                target_id: Some("drive-1".to_owned()),
                from: Some(datetime!(2026-08-13 11:59:59 UTC)),
                to: Some(datetime!(2026-08-13 12:00:03 UTC)),
                limit: 1,
            };
            let first = reader
                .list_audit_events(request(None))
                .await
                .map_err(|error| error.to_string())?;
            if first.events.len() != 1
                || first.events[0].id.as_str() != "018f47d2-2c00-7000-8000-000000000003"
                || first.events[0].payload != serde_json::json!({"output_bytes": 3})
                || first.next_cursor.is_none()
            {
                return Err(format!("audit 第一页不符：{first:?}"));
            }
            let second = reader
                .list_audit_events(request(first.next_cursor))
                .await
                .map_err(|error| error.to_string())?;
            if second.events.len() != 1
                || second.events[0].id.as_str() != "018f47d2-2c00-7000-8000-000000000001"
                || second.next_cursor.is_some()
            {
                return Err(format!("audit 第二页/终止游标不符：{second:?}"));
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
async fn malformed_audit_cursor_is_rejected_and_valid_first_page_is_reachable() {
    let admin =
        admin_config("malformed_audit_cursor_is_rejected_and_valid_first_page_is_reachable");
    with_temp_database(&admin, "audit_cursor", |config| async move {
        let pool = provision(&config).await?;
        let outcome = async {
            seed_events(&pool).await?;
            let reader = PostgresAuditReader::new(pool.clone());
            let base = AuditPageRequest {
                cursor: None,
                event_types: Vec::new(),
                actor_user_id: None,
                target_type: None,
                target_id: None,
                from: None,
                to: None,
                limit: 2,
            };
            let first = reader
                .list_audit_events(base.clone())
                .await
                .map_err(|error| error.to_string())?;
            if first.events.len() != 2 {
                return Err("正向 audit 首页不可达".to_owned());
            }
            let error = reader
                .list_audit_events(AuditPageRequest {
                    cursor: Some("not-a-cursor".to_owned()),
                    ..base
                })
                .await
                .expect_err("坏 audit cursor 必须拒绝");
            if error != AuditReadError::InvalidCursor {
                return Err(format!("坏 cursor 错误不符：{error:?}"));
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
async fn secret_input_writes_only_allowlisted_metadata_never_the_value_or_hash() {
    let admin =
        admin_config("secret_input_writes_only_allowlisted_metadata_never_the_value_or_hash");
    with_temp_database(&admin, "audit_secret", |config| async move {
        let pool = provision(&config).await?;
        let outcome = async {
            let secret = b"plaintext-key-that-must-never-be-stored";
            let payload = AuditPayload::from_facts([AuditFact::SecretInput {
                secret_id: AuditIdentifier::new("credential-1").unwrap(),
                purpose: AuditLabel::new("provider_api_key"),
                target_field: AuditIdentifier::new("apiKey").unwrap(),
                value_len: u32::try_from(secret.len()).unwrap(),
            }])
            .unwrap();
            let event = AuditEvent {
                id: AuditEventId::new("018f47d2-2c00-7000-8000-000000000010"),
                actor: Some(ActorId::new("admin")),
                event_type: AuditEventType::parse("credential.created").unwrap(),
                target_kind: AuditLabel::new("credential"),
                target_id: Some(AuditIdentifier::new("credential-1").unwrap()),
                payload,
                created_at: datetime!(2026-08-13 12:00:00 UTC),
            };
            AuditEventRepo::new(pool.clone())
                .append(&event, AUDIT_KEY)
                .await
                .map_err(|error| error.to_string())?;
            let value: serde_json::Value = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one("SELECT payload FROM public.audit_events", &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            let rendered = value.to_string();
            if rendered.contains("plaintext-key")
                || rendered.contains("value_hash")
                || value["secret_input"]["value_len"] != serde_json::json!(secret.len())
                || value["secret_input"]["secret_id"] != "credential-1"
            {
                return Err(format!("secret audit payload 不符：{rendered}"));
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
async fn current_schema_installs_and_enforces_both_append_only_triggers() {
    let admin = admin_config("current_schema_installs_and_enforces_both_append_only_triggers");
    with_temp_database(&admin, "audit_triggers", |config| async move {
        let pool = provision(&config).await?;
        let outcome = async {
            seed_events(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let triggers: Vec<String> = client
                .query(
                    "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid \
                     JOIN pg_namespace n ON n.oid=c.relnamespace \
                     WHERE n.nspname='public' AND c.relname='audit_events' AND NOT t.tgisinternal \
                     ORDER BY tgname",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.get(0))
                .collect();
            if triggers != ["audit_events_append_only", "audit_events_no_truncate"] {
                return Err(format!("append-only trigger 集合不符：{triggers:?}"));
            }
            for sql in [
                "UPDATE public.audit_events SET target_type='changed'",
                "DELETE FROM public.audit_events",
                "TRUNCATE public.audit_events",
            ] {
                let error = client
                    .execute(sql, &[])
                    .await
                    .expect_err("mutation 必须被 trigger 拒绝");
                if error.code() != Some(&tokio_postgres::error::SqlState::RAISE_EXCEPTION) {
                    return Err(format!("append-only SQLSTATE 不符：{error}"));
                }
            }
            let count: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.audit_events", &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if count != 3 {
                return Err(format!("被拒 mutation 改变了 audit 行数：{count}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
