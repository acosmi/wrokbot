//! native 0015（session auth generation）的 PostgreSQL 17 真库验收。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::sessions;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0014: &str = include_str!("../../../fixtures/db/schema-0014.json");
const POST_0015: &str = include_str!("../../../fixtures/db/schema-0015.json");
const SEED_SQL: &str = include_str!("../../../fixtures/db/seed-0012.sql");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture 必须合法")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0015_is_exact_expand_only_and_legacy_sessions_remain_unclaimed() {
    let admin = admin_config("post_0015_is_exact_expand_only_and_legacy_sessions_remain_unclaimed");
    with_temp_database(&admin, "native0015facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0014_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0014) {
                return Err("0014 前提事实漂移".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0015_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("从 0014 升 0015 应施加一条 migration".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if after != facts(POST_0015) {
                return Err("0015 活库与 fixture 不相等".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0015 丢表 {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!("0015 改写旧列 {}.{}", old.name, column.name));
                    }
                }
            }
            let before_sessions = before.table("sessions").expect("0014 有 sessions");
            let after_sessions = after.table("sessions").expect("0015 有 sessions");
            if after_sessions.columns.len() != before_sessions.columns.len() + 1
                || after_sessions
                    .columns
                    .last()
                    .map(|column| column.name.as_str())
                    != Some("auth_generation")
                || after_sessions
                    .columns
                    .last()
                    .is_some_and(|column| column.notnull)
            {
                return Err("auth_generation 不是 sessions 末尾唯一 nullable 增量".to_owned());
            }

            client
                .batch_execute(SEED_SQL)
                .await
                .map_err(|error| error.to_string())?;
            let nulls: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.sessions WHERE auth_generation IS NULL",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if nulls != 6 {
                return Err(format!("旧 session 必须保持 NULL，实际 {nulls}"));
            }
            let updated = client
                .query_one(
                    "UPDATE public.sessions SET auth_generation=0 WHERE id='sessions_00' RETURNING *",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let row = sessions::CurrentRow::try_from(&updated).map_err(|error| error.to_string())?;
            if row.auth_generation != Some(0) {
                return Err("新 session generation 没有 typed 读回".to_owned());
            }
            let negative = client
                .execute(
                    "UPDATE public.sessions SET auth_generation=-1 WHERE id='sessions_01'",
                    &[],
                )
                .await
                .expect_err("负 generation 必须被 CHECK 拒绝");
            if negative.as_db_error().and_then(|error| error.constraint())
                != Some("sessions_auth_generation_nonnegative")
            {
                return Err("负 generation 未命中具名 CHECK".to_owned());
            }
            let ledger: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if ledger != 3 {
                return Err(format!("native 账本应有三行，实际 {ledger}"));
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
async fn two_replicas_apply_0013_through_0015_exactly_once() {
    let admin = admin_config("two_replicas_apply_0013_through_0015_exactly_once");
    with_temp_database(&admin, "native0015race", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                baseline::apply(&client)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            let mut first = pool.get().await.map_err(|error| error.to_string())?;
            let mut second = pool.get().await.map_err(|error| error.to_string())?;
            let (left, right) = tokio::join!(
                native::apply_through(&mut first, native::NATIVE_0015_VERSION),
                native::apply_through(&mut second, native::NATIVE_0015_VERSION)
            );
            let mut outcomes = vec![
                left.map_err(|error| error.to_string())?,
                right.map_err(|error| error.to_string())?,
            ];
            outcomes.sort_by_key(|outcome| match outcome {
                ApplyOutcome::Applied => 0,
                ApplyOutcome::AlreadyApplied => 1,
            });
            if outcomes != vec![ApplyOutcome::Applied, ApplyOutcome::AlreadyApplied] {
                return Err(format!("并发 current migration 结果不符：{outcomes:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
