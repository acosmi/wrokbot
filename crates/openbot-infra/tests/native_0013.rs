//! native 0013 的 PostgreSQL 17 真库验收。
//!
//! 覆盖四个彼此独立的失效面：post fixture 逐字段相等、0012→0013 只 expand、账本幂等与
//! 并发串行化、以及中途 DDL 失败时不留下半个 schema。默认按 `#[ignore]` 可见跳过；显式
//! `--include-ignored` 时没有数据库就由共用 harness 硬失败。

mod harness;

use harness::{admin_config, with_temp_database};

use openbot_infra::db::native::{self, ApplyOutcome, NativeMigrationViolation};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables;
use openbot_infra::db::{InfraError, baseline, compat, pool, schema_facts};

const BASELINE_FACTS_JSON: &str = include_str!("../../../fixtures/db/schema-0012.json");
const POST_0013_FACTS_JSON: &str = include_str!("../../../fixtures/db/schema-0013.json");

fn facts(json: &str, label: &str) -> SchemaFacts {
    serde_json::from_str(json)
        .unwrap_or_else(|error| panic!("{label} 不是合法 schema fixture：{error}"))
}

fn assert_expand_only(before: &SchemaFacts, after: &SchemaFacts) {
    assert_eq!(before.enums, after.enums, "0013 不得修改 enum");
    assert_eq!(
        before.extensions, after.extensions,
        "0013 不得修改 extension"
    );
    assert_eq!(
        before.functions, after.functions,
        "0013 不得修改 public 函数"
    );

    for old in &before.tables {
        let new = after
            .table(&old.name)
            .unwrap_or_else(|| panic!("0013 删掉了 0012 表 {}", old.name));
        for old_column in &old.columns {
            assert_eq!(
                new.column(&old_column.name),
                Some(old_column),
                "0013 改写或删除了 {}.{}",
                old.name,
                old_column.name,
            );
        }
        for old_constraint in &old.constraints {
            assert!(
                new.constraints.contains(old_constraint),
                "0013 改写或删除了 {} 的约束 {}",
                old.name,
                old_constraint.name,
            );
        }
        for old_index in &old.indexes {
            assert!(
                new.indexes.contains(old_index),
                "0013 改写或删除了 {} 的索引 {}",
                old.name,
                old_index.name,
            );
        }
        for old_trigger in &old.triggers {
            assert!(
                new.triggers.contains(old_trigger),
                "0013 改写或删除了 {} 的触发器 {}",
                old.name,
                old_trigger.name,
            );
        }
    }

    let new_tables: Vec<&str> = after
        .tables
        .iter()
        .filter(|table| before.table(&table.name).is_none())
        .map(|table| table.name.as_str())
        .collect();
    assert_eq!(
        new_tables,
        vec!["audit_checkpoints", "tool_attempts", "tool_calls"],
    );
}

async fn relation(
    client: &tokio_postgres::Client,
    qualified: &str,
) -> Result<Option<String>, String> {
    client
        .query_one("SELECT to_regclass($1)::text", &[&qualified])
        .await
        .map_err(|error| format!("探测 relation {qualified} 失败：{error}"))?
        .try_get(0)
        .map_err(|error| format!("读取 relation {qualified} 探测结果失败：{error}"))
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0013_fixture_is_exact_and_every_0012_object_survives() {
    let admin = admin_config("post_0013_fixture_is_exact_and_every_0012_object_survives");
    with_temp_database(&admin, "native0013facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| format!("取连接失败：{error}"))?;
            baseline::apply(&client)
                .await
                .map_err(|error| format!("应用 baseline 失败：{error}"))?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| format!("提取 0012 事实失败：{error}"))?;
            if before != facts(BASELINE_FACTS_JSON, "schema-0012.json") {
                return Err("开工前提失败：活库 baseline 与 schema-0012.json 不相等".to_owned());
            }

            let applied = native::apply_through(&mut client, native::NATIVE_0013_VERSION)
                .await
                .map_err(|error| format!("施加 0013 失败：{error}"))?;
            if applied != ApplyOutcome::Applied {
                return Err(format!("全新 baseline 首次施加应为 Applied，实际 {applied:?}"));
            }

            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| format!("提取 0013 事实失败：{error}"))?;
            let expected = facts(POST_0013_FACTS_JSON, "schema-0013.json");
            if after != expected {
                return Err("post-0013 活库事实与 schema-0013.json 不相等".to_owned());
            }
            assert_expand_only(&before, &after);

            let _compatibility_report = compat::check_migration_boundary_on(&client)
                .await
                .map_err(|error| format!("expanded schema 过不了 0012 兼容边界：{error}"))?;

            let ledger = client
                .query_one(
                    "SELECT name, checksum FROM openbot_internal.schema_migrations WHERE version = $1",
                    &[&native::NATIVE_0013_VERSION],
                )
                .await
                .map_err(|error| format!("读取 native 账本失败：{error}"))?;
            let name: String = ledger.try_get("name").map_err(|error| error.to_string())?;
            let checksum: String = ledger
                .try_get("checksum")
                .map_err(|error| error.to_string())?;
            if name != native::NATIVE_0013_NAME || checksum != native::native_0013_checksum() {
                return Err(format!("0013 账本内容不符：name={name} checksum={checksum}"));
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
async fn native_0013_is_idempotent_and_concurrent_callers_serialize() {
    let admin = admin_config("native_0013_is_idempotent_and_concurrent_callers_serialize");
    with_temp_database(&admin, "native0013race", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            {
                let client = pool.get().await.map_err(|error| format!("取连接失败：{error}"))?;
                baseline::apply(&client)
                    .await
                    .map_err(|error| format!("应用 baseline 失败：{error}"))?;
            }

            let mut first = pool.get().await.map_err(|error| format!("取连接 1 失败：{error}"))?;
            let mut second = pool.get().await.map_err(|error| format!("取连接 2 失败：{error}"))?;
            let (left, right) = tokio::join!(
                native::apply_through(&mut first, native::NATIVE_0013_VERSION),
                native::apply_through(&mut second, native::NATIVE_0013_VERSION),
            );
            let mut outcomes = vec![
                left.map_err(|error| format!("并发施加 1 失败：{error}"))?,
                right.map_err(|error| format!("并发施加 2 失败：{error}"))?,
            ];
            outcomes.sort_by_key(|outcome| match outcome {
                ApplyOutcome::Applied => 0,
                ApplyOutcome::AlreadyApplied => 1,
            });
            if outcomes != vec![ApplyOutcome::Applied, ApplyOutcome::AlreadyApplied] {
                return Err(format!("并发施加结果不应重复执行：{outcomes:?}"));
            }
            drop(first);
            drop(second);

            let mut third = pool.get().await.map_err(|error| format!("取连接 3 失败：{error}"))?;
            if native::apply_through(&mut third, native::NATIVE_0013_VERSION)
                .await
                .map_err(|error| format!("第三次施加失败：{error}"))?
                != ApplyOutcome::AlreadyApplied
            {
                return Err("第三次施加必须是 AlreadyApplied".to_owned());
            }
            let rows: i64 = third
                .query_one(
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations WHERE version = $1",
                    &[&native::NATIVE_0013_VERSION],
                )
                .await
                .map_err(|error| format!("数账本失败：{error}"))?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if rows != 1 {
                return Err(format!("0013 账本应恰好 1 行，实际 {rows}"));
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
async fn object_collision_rolls_back_every_0013_change_and_does_not_forge_ledger() {
    let admin =
        admin_config("object_collision_rolls_back_every_0013_change_and_does_not_forge_ledger");
    with_temp_database(&admin, "native0013rollback", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool
                .get()
                .await
                .map_err(|error| format!("取连接失败：{error}"))?;
            baseline::apply(&client)
                .await
                .map_err(|error| format!("应用 baseline 失败：{error}"))?;
            client
                .batch_execute("CREATE TABLE public.tool_calls (wrong_shape text)")
                .await
                .map_err(|error| format!("制造对象碰撞失败：{error}"))?;

            let error = native::apply_through(&mut client, native::NATIVE_0013_VERSION)
                .await
                .expect_err("对象存在但账本缺失必须判红，不能 IF NOT EXISTS 跳过");
            if error.sqlstate() != Some("42P07") {
                return Err(format!("应因 duplicate_table 判红，实际 {error:?}"));
            }
            if relation(&client, "public.audit_checkpoints")
                .await?
                .is_some()
            {
                return Err("失败事务留下了 audit_checkpoints".to_owned());
            }
            if relation(&client, native::NATIVE_LEDGER_TABLE)
                .await?
                .is_some()
            {
                return Err("失败事务伪造了 native migration 账本".to_owned());
            }
            let hash_columns: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM information_schema.columns \
                     WHERE table_schema='public' AND table_name='audit_events' \
                     AND column_name IN ('prev_hash', 'row_hash')",
                    &[],
                )
                .await
                .map_err(|error| format!("数 audit hash 列失败：{error}"))?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if hash_columns != 0 {
                return Err(format!("失败事务留下 {hash_columns} 个 audit hash 列"));
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
async fn ledger_drift_is_refused_even_when_all_objects_exist() {
    let admin = admin_config("ledger_drift_is_refused_even_when_all_objects_exist");
    with_temp_database(&admin, "native0013drift", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool
                .get()
                .await
                .map_err(|error| format!("取连接失败：{error}"))?;
            baseline::apply(&client)
                .await
                .map_err(|error| format!("应用 baseline 失败：{error}"))?;
            native::apply_through(&mut client, native::NATIVE_0013_VERSION)
                .await
                .map_err(|error| format!("首次施加失败：{error}"))?;
            client
                .execute(
                    "UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=$2",
                    &[&"0".repeat(64), &native::NATIVE_0013_VERSION],
                )
                .await
                .map_err(|error| format!("制造账本漂移失败：{error}"))?;

            match native::apply_through(&mut client, native::NATIVE_0013_VERSION).await {
                Err(InfraError::NativeMigration(NativeMigrationViolation::LedgerDrift {
                    version,
                    actual_checksum,
                    ..
                })) if version == 13 && actual_checksum == "0".repeat(64) => Ok(()),
                other => Err(format!("账本漂移没有落到封闭错误：{other:?}")),
            }
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn database_constraints_preserve_chain_checkpoint_and_attempt_invariants() {
    let admin =
        admin_config("database_constraints_preserve_chain_checkpoint_and_attempt_invariants");
    with_temp_database(&admin, "native0013constraints", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| format!("取连接失败：{error}"))?;
            baseline::apply(&client)
                .await
                .map_err(|error| format!("应用 baseline 失败：{error}"))?;
            native::apply_through(&mut client, native::NATIVE_0013_VERSION)
                .await
                .map_err(|error| format!("施加 0013 失败：{error}"))?;

            client
                .execute(
                    "INSERT INTO public.audit_events \
                     (event_type, target_type, payload, prev_hash, row_hash) \
                     VALUES ('legacy', 'test', '{}'::jsonb, NULL, NULL)",
                    &[],
                )
                .await
                .map_err(|error| format!("合法旧行双 NULL 被拒：{error}"))?;
            let uppercase = "A".repeat(64);
            let bad_hash = client
                .execute(
                    "INSERT INTO public.audit_events \
                     (event_type, target_type, payload, row_hash) \
                     VALUES ('bad', 'test', '{}'::jsonb, $1)",
                    &[&uppercase],
                )
                .await
                .expect_err("大写摘要必须被 lower-hex CHECK 拒绝");
            if bad_hash
                .as_db_error()
                .and_then(|error| error.constraint())
                != Some("audit_events_row_hash_lower_hex")
            {
                return Err("大写摘要没有命中预期约束".to_owned());
            }
            let lower = "a".repeat(64);
            let bad_pair = client
                .execute(
                    "INSERT INTO public.audit_events \
                     (event_type, target_type, payload, prev_hash, row_hash) \
                     VALUES ('bad', 'test', '{}'::jsonb, $1, NULL)",
                    &[&lower],
                )
                .await
                .expect_err("prev 有值但 row 为空必须被拒");
            if bad_pair
                .as_db_error()
                .and_then(|error| error.constraint())
                != Some("audit_events_hash_pair_shape")
            {
                return Err("非法 hash pair 没有命中预期约束".to_owned());
            }

            client
                .execute(
                    "INSERT INTO public.audit_checkpoints \
                     (sequence, checkpoint_kind, first_event_id, first_row_hash, \
                      last_event_id, last_row_hash, event_count, unlinked_rows_before, \
                      retention_days, signature, created_at) \
                     VALUES (0, 'genesis', 'event-1', $1, 'event-1', $1, 1, 7, NULL, $2, now())",
                    &[&lower, &"b".repeat(64)],
                )
                .await
                .map_err(|error| format!("合法 genesis checkpoint 被拒：{error}"))?;
            let checkpoint_update = client
                .execute("UPDATE public.audit_checkpoints SET event_count=2", &[])
                .await
                .expect_err("checkpoint 必须 append-only");
            if checkpoint_update.code().map(|code| code.code()) != Some("P0001") {
                return Err("checkpoint UPDATE 没被 append-only trigger 拒绝".to_owned());
            }

            let orphan = client
                .execute(
                    "INSERT INTO public.tool_attempts \
                     (tool_call_id, attempt_seq, attempt_id, status) \
                     VALUES ('missing', 0, 'attempt-orphan', 'decision_recorded')",
                    &[],
                )
                .await
                .expect_err("attempt 没有 durable call 必须被 FK 拒绝");
            if orphan.code().map(|code| code.code()) != Some("23503") {
                return Err("orphan attempt 没有命中 foreign_key_violation".to_owned());
            }

            client
                .execute(
                    "INSERT INTO public.tool_calls \
                     (tool_call_id, run_id, call_seq, decision_id, actor_id, bot_id, tool_name, \
                      schema_hash, catalog_generation, args_hash, target_kind, target_id, effect, \
                      effect_downgraded, idempotency, idempotency_key, approval_class, policy_version) \
                     VALUES ('call-1','run-1',0,'decision-1','actor-1','bot-1','tool-1', \
                             $1,1,$2,'browser_tab','tab-1','write',false,'keyed','key-1', \
                             'every_call','pv-1')",
                    &[&"c".repeat(64), &"d".repeat(64)],
                )
                .await
                .map_err(|error| format!("插入 durable tool call 失败：{error}"))?;
            client
                .execute(
                    "INSERT INTO public.tool_attempts \
                     (tool_call_id, attempt_seq, attempt_id, status) \
                     VALUES ('call-1',0,'attempt-1','decision_recorded')",
                    &[],
                )
                .await
                .map_err(|error| format!("插入 durable attempt 失败：{error}"))?;

            let checkpoint = client
                .query_one("SELECT * FROM public.audit_checkpoints", &[])
                .await
                .map_err(|error| format!("读 checkpoint 失败：{error}"))?;
            tables::audit_checkpoints::Row::try_from(&checkpoint)
                .map_err(|error| format!("解 checkpoint 失败：{error}"))?;
            let call = client
                .query_one("SELECT * FROM public.tool_calls", &[])
                .await
                .map_err(|error| format!("读 tool call 失败：{error}"))?;
            tables::tool_calls::Row::try_from(&call)
                .map_err(|error| format!("解 tool call 失败：{error}"))?;
            let attempt = client
                .query_one("SELECT * FROM public.tool_attempts", &[])
                .await
                .map_err(|error| format!("读 attempt 失败：{error}"))?;
            tables::tool_attempts::Row::try_from(&attempt)
                .map_err(|error| format!("解 attempt 失败：{error}"))?;
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
