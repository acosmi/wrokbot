//! Server fresh/legacy/Rust-managed 数据库启动分流的 PostgreSQL 17 真库矩阵。

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use harness::{admin_config, with_temp_database};
use openbot_infra::db::tables::{ALL_TABLES, NATIVE_0013_TABLES, NATIVE_0016_TABLES};
use openbot_infra::db::{baseline, native, pool};
use openbot_server::database::{DatabaseInitializationError, DatabaseOrigin, initialize};

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

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn fresh_bootstrap_survives_a_second_start_without_a_drizzle_ledger() {
    let admin = admin_config("fresh_bootstrap_survives_a_second_start_without_a_drizzle_ledger");
    with_temp_database(&admin, "server_fresh_restart", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let expected_native = i64::try_from(native::NATIVE_MIGRATION_COUNT).unwrap();
            let expected_public_tables = i64::try_from(
                ALL_TABLES.len() + NATIVE_0013_TABLES.len() + NATIVE_0016_TABLES.len(),
            )
            .unwrap();
            if initialize(&pool).await.map_err(|error| error.to_string())? != DatabaseOrigin::Fresh
            {
                return Err("空库首次启动没有识别为 Fresh".to_owned());
            }
            if scalar(&pool, "SELECT count(*)::bigint FROM public.users").await? != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                )
                .await?
                    != expected_native
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM information_schema.tables \
                     WHERE table_schema='public' AND table_type='BASE TABLE'",
                )
                .await?
                    != expected_public_tables
            {
                return Err("fresh baseline/native 终态计数不符".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let drizzle_exists: bool = client
                .query_one(
                    "SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if drizzle_exists {
                return Err("Rust fresh install 不得伪造上游 Drizzle 账本".to_owned());
            }
            drop(client);

            if initialize(&pool).await.map_err(|error| error.to_string())?
                != DatabaseOrigin::RustManaged
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                )
                .await?
                    != expected_native
            {
                return Err("二次启动没有以 checksum native ledger 识别 Rust-managed 库".to_owned());
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
async fn concurrent_fresh_initializers_serialize_to_fresh_plus_rust_managed() {
    let admin = admin_config("concurrent_fresh_initializers_serialize_to_fresh_plus_rust_managed");
    with_temp_database(&admin, "server_fresh_concurrent", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let expected_native = i64::try_from(native::NATIVE_MIGRATION_COUNT).unwrap();
            let (left, right) = tokio::join!(initialize(&pool), initialize(&pool));
            let origins = [
                left.map_err(|error| error.to_string())?,
                right.map_err(|error| error.to_string())?,
            ];
            if origins
                .iter()
                .filter(|origin| **origin == DatabaseOrigin::Fresh)
                .count()
                != 1
                || origins
                    .iter()
                    .filter(|origin| **origin == DatabaseOrigin::RustManaged)
                    .count()
                    != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                )
                .await?
                    != expected_native
            {
                return Err(format!("并发 fresh 分流/账本不符：{origins:?}"));
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
async fn existing_schema_without_either_ledger_remains_fail_closed() {
    let admin = admin_config("existing_schema_without_either_ledger_remains_fail_closed");
    with_temp_database(&admin, "server_unknown_legacy", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if !matches!(
                initialize(&pool).await,
                Err(DatabaseInitializationError::LegacyDataMigrationUnverifiable)
            ) {
                return Err("未知无账本 legacy 没有 fail-closed".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            if native::ledger_exists(&client)
                .await
                .map_err(|error| error.to_string())?
            {
                return Err("拒绝未知 legacy 时不该伪造 native ledger".to_owned());
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
async fn native_ledger_failure_rolls_back_every_baseline_object() {
    let admin = admin_config("native_ledger_failure_rolls_back_every_baseline_object");
    with_temp_database(&admin, "server_fresh_atomic", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE SCHEMA openbot_internal; \
                     CREATE TABLE openbot_internal.schema_migrations(version text PRIMARY KEY);",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            initialize(&pool)
                .await
                .expect_err("同名异形 native ledger 必须让 fresh bootstrap 失败");
            if scalar(
                &pool,
                "SELECT count(*)::bigint FROM information_schema.tables \
                 WHERE table_schema='public' AND table_type='BASE TABLE'",
            )
            .await?
                != 0
            {
                return Err("native 失败后 baseline public 对象没有整体回滚".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
