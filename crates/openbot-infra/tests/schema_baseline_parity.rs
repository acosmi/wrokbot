//! 需要真实 PostgreSQL 的集成测试：baseline 建出来的库必须与参照库逐字段相等。
//!
//! 这是 v3 §24 G1 判据「28 表/13 migration 映射」的**执行面**：`db::tables` 的台账、
//! `sql/baseline_0012.sql` 的 DDL、`fixtures/db/schema-0012.json` 的参照事实，三者在这里
//! 被同一条判据串起来。任何一处漂了都会在这里判红。
//!
//! # 怎么跑
//!
//! 默认 `cargo test` 会把本文件的用例按 `#[ignore]` 跳过，并在输出里逐条打印跳过理由
//! （`test ... ignored, 需要真实 PostgreSQL：...`）。要真跑：
//!
//! ```text
//! OPENBOT_TEST_DATABASE_URL="host=127.0.0.1 port=5432 user=postgres password=... dbname=postgres" \
//!   cargo test -p openbot-infra --all-features -- --include-ignored
//! ```
//!
//! 环境变量给的是**管理连接**（通常连 `postgres` 库）：每个用例自己 `CREATE DATABASE` 一个
//! 带随机后缀的临时库，跑完 `DROP DATABASE ... WITH (FORCE)` 删掉。用例**从不**改动
//! 环境变量指向的那个库，也从不碰参照库 `openbot_ref_0012`。
//!
//! 环境变量未设置时**硬失败**：`#[ignore]` 已经在默认路径上给了可见的跳过，
//! 显式加 `--include-ignored` 就是在明说"我要跑真库测试"，此时静默通过会让
//! "我跑了集成测试且全绿"变成一句假话。判据一条都不放宽。

mod harness;

use harness::{admin_config, unique_database_name, with_temp_database};

use openbot_infra::db::pool;
use openbot_infra::db::schema_facts::{SchemaFacts, TableFacts};
use openbot_infra::db::tables;
use openbot_infra::db::{baseline, compat, schema_facts};

/// 参照库事实的入仓副本，生成过程见 `fixtures/db/README.md`。
const REFERENCE_FACTS_JSON: &str = include_str!("../../../fixtures/db/schema-0012.json");

fn reference_facts() -> SchemaFacts {
    serde_json::from_str(REFERENCE_FACTS_JSON).expect("fixtures/db/schema-0012.json 应当能解析")
}

/// 逐字段比较两份事实，返回人类可读的差异描述；完全相等返回 `None`。
///
/// 刻意不直接 `assert_eq!` 两个 `SchemaFacts`：204 列 / 59 约束的结构体一整个打印出来
/// 没法读，定位不到是哪张表的哪一列。
fn describe_difference(expected: &SchemaFacts, actual: &SchemaFacts) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();

    let expected_names: Vec<&str> = expected.tables.iter().map(|t| t.name.as_str()).collect();
    let actual_names: Vec<&str> = actual.tables.iter().map(|t| t.name.as_str()).collect();
    for name in &expected_names {
        if !actual_names.contains(name) {
            lines.push(format!("缺表：{name}"));
        }
    }
    for name in &actual_names {
        if !expected_names.contains(name) {
            lines.push(format!("多表：{name}"));
        }
    }
    if expected_names != actual_names {
        lines.push(format!(
            "表顺序不同：期望 {expected_names:?}，实际 {actual_names:?}",
        ));
    }

    for expected_table in &expected.tables {
        let Some(actual_table) = actual.table(&expected_table.name) else {
            continue;
        };
        lines.extend(describe_table_difference(expected_table, actual_table));
    }

    if expected.enums != actual.enums {
        lines.push(format!(
            "enum 不同：期望 {:?}，实际 {:?}",
            expected.enums, actual.enums,
        ));
    }
    if expected.functions != actual.functions {
        let expected_names: Vec<&str> =
            expected.functions.iter().map(|f| f.name.as_str()).collect();
        let actual_names: Vec<&str> = actual.functions.iter().map(|f| f.name.as_str()).collect();
        lines.push(format!(
            "函数不同：期望 {expected_names:?}，实际 {actual_names:?}（定义文本也可能有差异）",
        ));
    }
    if expected.extensions != actual.extensions {
        lines.push(format!(
            "extension 不同：期望 {:?}，实际 {:?}",
            expected.extensions, actual.extensions,
        ));
    }

    if lines.is_empty() {
        None
    } else {
        Some(format!(
            "baseline 建出来的 schema 与参照库不等，共 {} 处：\n  - {}",
            lines.len(),
            lines.join("\n  - "),
        ))
    }
}

fn describe_table_difference(expected: &TableFacts, actual: &TableFacts) -> Vec<String> {
    let mut lines = Vec::new();
    let table = &expected.name;
    if expected.columns != actual.columns {
        for column in &expected.columns {
            match actual.column(&column.name) {
                None => lines.push(format!("{table}.{}：缺列", column.name)),
                Some(got) if got != column => lines.push(format!(
                    "{table}.{}：期望 {column:?}，实际 {got:?}",
                    column.name,
                )),
                Some(_) => {}
            }
        }
        for column in &actual.columns {
            if expected.column(&column.name).is_none() {
                lines.push(format!("{table}.{}：多出来的列", column.name));
            }
        }
        if lines.is_empty() {
            lines.push(format!("{table}：列顺序不同"));
        }
    }
    if expected.constraints != actual.constraints {
        lines.push(format!(
            "{table}：约束不同（期望 {} 条，实际 {} 条）",
            expected.constraints.len(),
            actual.constraints.len(),
        ));
    }
    if expected.indexes != actual.indexes {
        lines.push(format!(
            "{table}：索引不同（期望 {} 个，实际 {} 个）",
            expected.indexes.len(),
            actual.indexes.len(),
        ));
    }
    if expected.triggers != actual.triggers {
        lines.push(format!(
            "{table}：触发器不同（期望 {} 个，实际 {} 个）",
            expected.triggers.len(),
            actual.triggers.len(),
        ));
    }
    lines
}

/// G1 判据的执行面：baseline → 提取事实 → 与参照库逐字段相等 → 迁移边界检查放行。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn baseline_reproduces_the_reference_schema_exactly() {
    let admin = admin_config("baseline_reproduces_the_reference_schema_exactly");
    with_temp_database(&admin, "baseline", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline_0012.sql 失败：{e}"))?;

            let observed = schema_facts::fetch(&client)
                .await
                .map_err(|e| format!("提取 schema 事实失败：{e}"))?;
            if let Some(diff) = describe_difference(&reference_facts(), &observed) {
                return Err(diff);
            }

            let report = compat::check_migration_boundary_on(&client)
                .await
                .map_err(|e| format!("baseline 建出来的库居然过不了迁移边界检查：{e}"))?;
            // baseline 不写 drizzle 账本，所以数据迁移判定必须是"不可验证"而不是"通过"。
            if !report.data_migrations.is_unverifiable() {
                return Err(format!(
                    "baseline 库没有 drizzle 账本，判定应当是 Unverifiable：{:?}",
                    report.data_migrations,
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

/// 负向对照：上一条用例若因为「比对管线恒相等」而恒绿，这里会露馅 ——
/// 从 baseline 库里删掉一列之后，同一条比对必须报差异，同一条边界检查必须拒绝。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn the_comparison_and_the_boundary_check_both_notice_a_dropped_column() {
    let admin = admin_config("the_comparison_and_the_boundary_check_both_notice_a_dropped_column");
    with_temp_database(&admin, "dropcol", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            client
                .simple_query("ALTER TABLE public.users DROP COLUMN image")
                .await
                .map_err(|e| format!("删列失败：{e}"))?;

            let observed = schema_facts::fetch(&client)
                .await
                .map_err(|e| format!("提取 schema 事实失败：{e}"))?;
            let diff = describe_difference(&reference_facts(), &observed)
                .ok_or_else(|| "删掉一列之后比对仍报相等：比对管线是坏的".to_string())?;
            if !diff.contains("users.image") {
                return Err(format!("差异描述没点名 users.image：{diff}"));
            }

            match compat::check_migration_boundary_on(&client).await {
                Ok(_) => Err("删掉一列之后迁移边界检查仍然放行".to_string()),
                Err(error) => {
                    let rendered = error.to_string();
                    if rendered.contains("users") && rendered.contains("image") {
                        Ok(())
                    } else {
                        Err(format!("边界检查报错但没点名 users.image：{rendered}"))
                    }
                }
            }
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 负向对照：库里还留着 `chunks`（`0010` 之前的 document 索引）必须被拒，
/// 而且报告要指出「没迁过 0010」而不是笼统地说不兼容。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn the_boundary_check_rejects_a_database_that_never_ran_0010() {
    let admin = admin_config("the_boundary_check_rejects_a_database_that_never_ran_0010");
    with_temp_database(&admin, "pre0010", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            // 前提自检：干净的 baseline 库必须先能通过，否则下面的拒绝说明不了任何事。
            let report = compat::check_migration_boundary_on(&client)
                .await
                .map_err(|e| format!("前提自检失败：干净的 baseline 库应当通过：{e}"))?;
            if !report.data_migrations.is_unverifiable() {
                return Err(format!(
                    "前提自检失败：baseline 库应当报不可验证：{:?}",
                    report.data_migrations,
                ));
            }

            client
                .simple_query("CREATE TABLE public.chunks (id text PRIMARY KEY)")
                .await
                .map_err(|e| format!("建 chunks 表失败：{e}"))?;

            match compat::check_migration_boundary_on(&client).await {
                Ok(_) => Err("库里还有 chunks，迁移边界检查却放行了".to_string()),
                Err(error) => {
                    let rendered = error.to_string();
                    if rendered.contains("chunks")
                        && rendered.contains("0010_drop_the_document_index.sql")
                    {
                        Ok(())
                    } else {
                        Err(format!("拒绝了但没指出是没跑 0010：{rendered}"))
                    }
                }
            }
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 对抗性种子的每一行都必须能经它自己的 `Row` 结构体解出来。
///
/// `fixtures/db/seed-0012.sql` 是 28 张表 × 6 行 = 168 行，专挑会让类型映射出错的值：
/// 空串 vs NULL、空数组 vs 含 NULL 元素的数组、jsonb 里超 f64 精度的整数、
/// timestamptz 亚秒 + 非 UTC 偏移、CJK / emoji / 组合字符 / 引号 / 反斜杠 / 换行制表 / RTL、
/// `boolean` 的 false、`integer` 的 0 / 负数 / `i32::MAX`，以及 4 个 enum 的**每一个**取值。
///
/// 单测证明不了这件事：`Row` 的字段类型对不对，只有真的从 PostgreSQL 读回来才知道。
/// 这条用例真的抓过一个缺陷 —— `text[]` 原本写成 `Vec<String>`，遇到 `{NULL,x}` 直接解码失败。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn every_seeded_row_decodes_through_its_row_struct() {
    let admin = admin_config("every_seeded_row_decodes_through_its_row_struct");
    with_temp_database(&admin, "seed", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            client
                .batch_execute(SEED_SQL)
                .await
                .map_err(|e| format!("灌入 fixtures/db/seed-0012.sql 失败：{e}"))?;

            let mut problems: Vec<String> = Vec::new();
            let mut decoded = 0usize;
            decode_every_table(&client, &mut problems, &mut decoded).await;
            if !problems.is_empty() {
                return Err(format!(
                    "种子行解码有 {} 处问题：\n  - {}",
                    problems.len(),
                    problems.join("\n  - "),
                ));
            }
            if decoded != EXPECTED_SEEDED_ROWS {
                return Err(format!(
                    "解出来 {decoded} 行，期望 {EXPECTED_SEEDED_ROWS} 行（28 张表 × 6 行）",
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

/// 挑几处最容易被"能解出来就算对"蒙混过去的值，逐个断言解出来的**内容**。
///
/// 上一条用例只证明 168 行都没报错；一个把 `integer` 解成 `i32` 却读错字节序的实现，
/// 在那里同样绿。这里盯的是值本身。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn adversarial_values_survive_the_round_trip_intact() {
    let admin = admin_config("adversarial_values_survive_the_round_trip_intact");
    with_temp_database(&admin, "advval", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            client
                .batch_execute(SEED_SQL)
                .await
                .map_err(|e| format!("灌入种子失败：{e}"))?;

            // text[]：含 NULL 元素的数组、空数组、含逗号 / 引号 / 空格的元素。
            let rows = client
                .query("SELECT * FROM public.users ORDER BY id", &[])
                .await
                .map_err(|e| format!("查 users 失败：{e}"))?;
            let users = rows
                .iter()
                .map(tables::users::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 users 失败：{e}"))?;
            let by_id = |id: &str| {
                users
                    .iter()
                    .find(|u| u.id == id)
                    .unwrap_or_else(|| panic!("种子里应当有 {id}"))
            };
            if by_id("users_01").groups != vec![None, Some("x".to_string())] {
                return Err(format!(
                    "users_01.groups 的 NULL 元素没保住：{:?}",
                    by_id("users_01").groups,
                ));
            }
            if !by_id("users_02").groups.is_empty() {
                return Err(format!(
                    "users_02.groups 应当是空数组：{:?}",
                    by_id("users_02").groups,
                ));
            }
            if by_id("users_00").groups
                != vec![
                    Some("含,逗号".to_string()),
                    Some("含\"引号".to_string()),
                    Some("含 空格".to_string()),
                ]
            {
                return Err(format!(
                    "users_00.groups 的分隔符转义没还原：{:?}",
                    by_id("users_00").groups,
                ));
            }
            // NULL 与空串必须分得开。
            if by_id("users_01").name.is_some() {
                return Err("users_01.name 应当是 NULL".to_string());
            }
            if !by_id("users_00").email_verified || by_id("users_01").email_verified {
                return Err("boolean 的 true/false 没对上".to_string());
            }

            // integer：0 / 负数 / i32::MAX。
            let rows = client
                .query(
                    "SELECT * FROM public.computer_snapshot ORDER BY computer_id",
                    &[],
                )
                .await
                .map_err(|e| format!("查 computer_snapshot 失败：{e}"))?;
            let snapshots = rows
                .iter()
                .map(tables::computer_snapshot::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 computer_snapshot 失败：{e}"))?;
            let ints: Vec<i32> = snapshots.iter().map(|s| s.snapshot_id).collect();
            for want in [0_i32, -1, i32::MAX, 42] {
                if !ints.contains(&want) {
                    return Err(format!("computer_snapshot 里没解出 {want}：{ints:?}"));
                }
            }

            // jsonb：超 f64 精度的整数必须逐位保住。
            let rows = client
                .query("SELECT * FROM public.audit_events", &[])
                .await
                .map_err(|e| format!("查 audit_events 失败：{e}"))?;
            let events = rows
                .iter()
                .map(tables::audit_events::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 audit_events 失败：{e}"))?;
            let big = events
                .iter()
                .filter_map(|e| e.payload.get("big"))
                .next()
                .ok_or_else(|| "种子里应当有带 big 键的 jsonb".to_string())?;
            if big.as_i64() != Some(9_007_199_254_740_993) {
                return Err(format!("jsonb 大整数被 f64 磨掉了精度：{big}"));
            }
            // uuid：全 0 与全 f 两个边界值都必须解出来。
            let uuids: Vec<String> = events.iter().map(|e| e.id.to_string()).collect();
            for want in [
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ] {
                if !uuids.iter().any(|u| u == want) {
                    return Err(format!("uuid 边界值没解出来：{want} 不在 {uuids:?}"));
                }
            }

            // timestamptz：亚秒 + 非 UTC 偏移。种子里 `2026-08-22 07:30:45.123456-07`
            // 等于 UTC 的 14:30:45.123456。
            let has_subsecond = events
                .iter()
                .chain(std::iter::empty())
                .any(|e| e.created_at.microsecond() == 1)
                || snapshots.iter().any(|s| s.taken_at.microsecond() == 1);
            if !has_subsecond {
                return Err("timestamptz 的微秒位没保住".to_string());
            }
            let shifted = snapshots
                .iter()
                .map(|s| s.taken_at.to_offset(time::UtcOffset::UTC))
                .find(|t| t.microsecond() == 123_456)
                .ok_or_else(|| "种子里应当有 .123456 的时间戳".to_string())?;
            if (shifted.hour(), shifted.minute(), shifted.second()) != (14, 30, 45) {
                return Err(format!("非 UTC 偏移换算错了：{shifted}"));
            }

            // 4 个 enum 的每一个取值都要解出来。
            let credential_kinds = client
                .query("SELECT * FROM public.credentials", &[])
                .await
                .map_err(|e| format!("查 credentials 失败：{e}"))?
                .iter()
                .map(tables::credentials::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 credentials 失败：{e}"))?
                .into_iter()
                .map(|c| c.kind)
                .collect::<Vec<_>>();
            use openbot_infra::db::types::{AgentType, AgentVisibility, CredentialKind, Role};
            for want in [
                CredentialKind::Model,
                CredentialKind::Connector,
                CredentialKind::Agent,
                CredentialKind::Mcp,
                CredentialKind::McpOauthClient,
                CredentialKind::McpUserToken,
            ] {
                if !credential_kinds.contains(&want) {
                    return Err(format!("credential_kind 没解出 {want:?}"));
                }
            }

            let agent_types = client
                .query("SELECT * FROM public.agents", &[])
                .await
                .map_err(|e| format!("查 agents 失败：{e}"))?
                .iter()
                .map(tables::agents::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 agents 失败：{e}"))?
                .into_iter()
                .map(|a| a.r#type)
                .collect::<Vec<_>>();
            for want in [AgentType::BuiltIn, AgentType::RemoteAgUi] {
                if !agent_types.contains(&want) {
                    return Err(format!("agent_type 没解出 {want:?}"));
                }
            }

            let visibilities = client
                .query("SELECT * FROM public.agent_profiles", &[])
                .await
                .map_err(|e| format!("查 agent_profiles 失败：{e}"))?
                .iter()
                .map(tables::agent_profiles::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 agent_profiles 失败：{e}"))?
                .into_iter()
                .map(|p| p.visibility)
                .collect::<Vec<_>>();
            for want in [AgentVisibility::Public, AgentVisibility::Private] {
                if !visibilities.contains(&want) {
                    return Err(format!("agent_visibility 没解出 {want:?}"));
                }
            }

            let roles = client
                .query("SELECT * FROM public.user_roles", &[])
                .await
                .map_err(|e| format!("查 user_roles 失败：{e}"))?
                .iter()
                .map(tables::user_roles::Row::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("解 user_roles 失败：{e}"))?
                .into_iter()
                .map(|r| r.role)
                .collect::<Vec<_>>();
            for want in [Role::Admin, Role::User] {
                if !roles.contains(&want) {
                    return Err(format!("role 没解出 {want:?}"));
                }
            }

            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// `pool::connect` 必须在建池阶段就把参数验穿，而不是把「库不存在」推迟到第一条业务查询。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn connect_fails_immediately_when_the_database_does_not_exist() {
    let admin = admin_config("connect_fails_immediately_when_the_database_does_not_exist");
    // 正向对照：同样的参数连一个存在的库必须成功，否则下面的失败可能只是口令错了。
    let pool = pool::connect(&admin)
        .await
        .expect("连管理库必须成功，否则下面的负向断言说明不了任何事");
    pool.close();

    let missing = admin.with_dbname(unique_database_name("nonexistent"));
    let error = pool::connect(&missing)
        .await
        .expect_err("连一个不存在的库必须报错");
    assert!(
        matches!(error, openbot_infra::db::InfraError::Connect { .. }),
        "应当报连接失败而不是别的档：{error:?}",
    );
}

/// `uuid` 的**写**路径（`ToSql`）：用参数绑定把一个 `uuid::Uuid` 写进去，再按同一个值查回来。
///
/// 其余用例只走读路径（`FromSql`）。挑 `deployment_packages` 是因为它的 `id` 是 uuid 主键且
/// 整张表没有任何外键入边，不需要为了写一行先造一条 FK 链。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_uuid_round_trips_through_parameter_binding() {
    let admin = admin_config("a_uuid_round_trips_through_parameter_binding");
    with_temp_database(&admin, "uuidbind", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;

            // 非 nil、非全 f 的普通值：nil 在"参数根本没送出去"的实现下也可能凑巧对上。
            let id = uuid::Uuid::parse_str("9c5b94b1-35ad-49bb-b118-8e8fc24abf80")
                .map_err(|e| format!("测试用 uuid 字面量不合法：{e}"))?;

            let written = client
                .execute(
                    "INSERT INTO public.deployment_packages (id, tenant_id, source_path, checksum) \
                     VALUES ($1, $2, $3, $4)",
                    &[&id, &"tenant-a", &"/pkg/a", &"sha256:aa"],
                )
                .await
                .map_err(|e| format!("按参数绑定写 uuid 失败：{e}"))?;
            if written != 1 {
                return Err(format!("期望写入 1 行，实际 {written}"));
            }

            // 再用同一个 uuid 做谓词参数：这一次 ToSql 走的是 WHERE 而不是 VALUES。
            let rows = client
                .query(
                    "SELECT * FROM public.deployment_packages WHERE id = $1",
                    &[&id],
                )
                .await
                .map_err(|e| format!("按 uuid 参数查询失败：{e}"))?;
            if rows.len() != 1 {
                return Err(format!("按 uuid 谓词应当查到 1 行，实际 {}", rows.len()));
            }

            let package = tables::deployment_packages::Row::try_from(&rows[0])
                .map_err(|e| format!("解 deployment_packages 失败：{e}"))?;
            if package.id != id {
                return Err(format!("uuid 写读不一致：写入 {id}，读回 {}", package.id));
            }
            if package.tenant_id != "tenant-a" {
                return Err(format!("同一行的其它列也不对：{package:?}"));
            }

            // 负向对照：换一个 uuid 作谓词必须查不到 —— 否则上面的"查到 1 行"可能来自
            // "谓词根本没生效、返回了全表"。
            let other = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .map_err(|e| format!("对照 uuid 不合法：{e}"))?;
            let none = client
                .query(
                    "SELECT * FROM public.deployment_packages WHERE id = $1",
                    &[&other],
                )
                .await
                .map_err(|e| format!("对照查询失败：{e}"))?;
            if !none.is_empty() {
                return Err(format!("换一个 uuid 竟然也查到了 {} 行", none.len()));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 服务端错误必须不能把**列取值**带进日志。
///
/// PostgreSQL 的唯一约束冲突会在 `DETAIL` 里写 `Key (token)=(…) already exists.`，
/// 而 `DbError` 的 `Display` 打印 DETAIL、`Debug` 打印全部字段。这条用例先证实原始错误确实
/// 会泄漏（前提自检），再断言 `InfraError` 的 `Display` / `Debug` / `source()` 链一个字都不带。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_server_side_error_never_carries_the_offending_column_value() {
    const SENTINEL: &str = "SENTINEL-DO-NOT-LOG";
    let admin = admin_config("a_server_side_error_never_carries_the_offending_column_value");
    with_temp_database(&admin, "errleak", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            client
                .batch_execute(
                    "INSERT INTO public.users (id, email) VALUES ('u1', 'a@example.invalid');\n\
                     INSERT INTO public.sessions (id, user_id, token, expires_at)\n\
                     VALUES ('s1', 'u1', 'SENTINEL-DO-NOT-LOG', now());",
                )
                .await
                .map_err(|e| format!("插入首行失败：{e}"))?;

            // 撞 sessions_token_unique：服务端会把 token 的取值写进 DETAIL。
            let raw = client
                .execute(
                    "INSERT INTO public.sessions (id, user_id, token, expires_at) \
                     VALUES ('s2', 'u1', $1, now())",
                    &[&SENTINEL],
                )
                .await
                .expect_err("重复 token 必须撞唯一约束");

            // 前提自检：原始驱动错误**确实**会泄漏取值。没有这一条，下面的断言在
            // "PostgreSQL 本来就不回显取值"的世界里同样成立。
            let raw_leak = format!(
                "{raw:?} | {}",
                raw.as_db_error().map(ToString::to_string).unwrap_or_default(),
            );
            if !raw_leak.contains(SENTINEL) {
                return Err(format!(
                    "前提自检失败：原始 tokio_postgres::Error 没有回显取值，脱敏断言将失去意义：{raw_leak}",
                ));
            }

            let infra = openbot_infra::db::InfraError::query("插入会话", raw);
            let rendered = format!(
                "{infra} | {infra:?} | {}",
                openbot_infra::db::error_chain(&infra),
            );
            if rendered.contains(SENTINEL) {
                return Err(format!("InfraError 泄漏了列取值：{rendered}"));
            }
            // 正向对照：脱敏之后诊断信息还在 —— SQLSTATE 与约束名足以定位问题。
            if infra.sqlstate() != Some("23505") {
                return Err(format!("SQLSTATE 丢了：{:?}", infra.sqlstate()));
            }
            if !rendered.contains("sessions_token_unique") {
                return Err(format!("约束名丢了，脱敏过头：{rendered}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 从真库读回来的 `Row`，其 `Debug` 也必须遮住 secret 列。
///
/// 单测里的六条脱敏用例构造的是手写 `Row`；这一条走完整链路：真库 → `try_from` → `Debug`。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rows_read_from_a_live_database_still_redact_their_secret_columns() {
    const SENTINEL: &str = "SENTINEL-DO-NOT-LOG";
    let admin = admin_config("rows_read_from_a_live_database_still_redact_their_secret_columns");
    with_temp_database(&admin, "liveredact", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            client
                .batch_execute(
                    "INSERT INTO public.users (id, email) VALUES ('u1', 'a@example.invalid');\n\
                     INSERT INTO public.sessions (id, user_id, token, expires_at)\n\
                     VALUES ('MARKER-VISIBLE', 'u1', 'SENTINEL-DO-NOT-LOG', now());\n\
                     INSERT INTO public.accounts (id, account_id, provider_id, user_id,\n\
                       access_token, refresh_token, id_token, password, issuer)\n\
                     VALUES ('MARKER-VISIBLE', 'acc', 'google', 'u1',\n\
                       'SENTINEL-DO-NOT-LOG', 'SENTINEL-DO-NOT-LOG', 'SENTINEL-DO-NOT-LOG',\n\
                       'SENTINEL-DO-NOT-LOG', 'https://accounts.google.com');",
                )
                .await
                .map_err(|e| format!("插入样本行失败：{e}"))?;

            for (table, sql) in [
                ("sessions", "SELECT * FROM public.sessions"),
                ("accounts", "SELECT * FROM public.accounts"),
            ] {
                let row = client
                    .query_one(sql, &[])
                    .await
                    .map_err(|e| format!("查 {table} 失败：{e}"))?;
                let rendered = match table {
                    "sessions" => format!(
                        "{:?}",
                        tables::sessions::Row::try_from(&row)
                            .map_err(|e| format!("解 sessions 失败：{e}"))?
                    ),
                    _ => format!(
                        "{:?}",
                        tables::accounts::Row::try_from(&row)
                            .map_err(|e| format!("解 accounts 失败：{e}"))?
                    ),
                };
                if rendered.contains(SENTINEL) {
                    return Err(format!(
                        "{table} 从真库读回来的 Row 泄漏了 secret：{rendered}"
                    ));
                }
                // 正向对照：非 secret 列照常打印，否则上一条在"Debug 恒为空"下同样通过。
                if !rendered.contains("MARKER-VISIBLE") || !rendered.contains("<redacted>") {
                    return Err(format!("{table} 的 Debug 不成形：{rendered}"));
                }
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 建一张形状与 drizzle 账本一致的表，并塞进 `entries` 条记录。
///
/// 列名取自 drizzle-kit 自己建的账本表 `(id serial primary key, hash text not null,
/// created_at bigint)`。判据只数条目数、不依赖列语义，所以即使上游某版 drizzle 的列名有出入，
/// 这条测试仍然测的是同一件事。
async fn install_drizzle_ledger(
    client: &tokio_postgres::Client,
    entries: i64,
) -> Result<(), String> {
    client
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS drizzle;\n\
             CREATE TABLE drizzle.__drizzle_migrations (\n\
               id serial PRIMARY KEY,\n\
               hash text NOT NULL,\n\
               created_at bigint\n\
             );",
        )
        .await
        .map_err(|e| format!("建账本表失败：{e}"))?;
    for i in 0..entries {
        client
            .execute(
                "INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)",
                &[&format!("hash-{i:04}"), &i],
            )
            .await
            .map_err(|e| format!("写账本第 {i} 条失败：{e}"))?;
    }
    Ok(())
}

/// 账本齐全（13 条）⇒ 边界检查通过，且判定是 `Applied`。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_complete_drizzle_ledger_is_verified_as_applied() {
    let admin = admin_config("a_complete_drizzle_ledger_is_verified_as_applied");
    with_temp_database(&admin, "ledgerok", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            install_drizzle_ledger(&client, 13).await?;

            let ledger = compat::fetch_migration_ledger(&client)
                .await
                .map_err(|e| format!("读账本失败：{e}"))?;
            if ledger != (compat::MigrationLedger::Present { entries: 13 }) {
                return Err(format!("账本观测不对：{ledger:?}"));
            }

            let report = compat::check_migration_boundary_on(&client)
                .await
                .map_err(|e| format!("账本齐全却过不了边界检查：{e}"))?;
            if !report.data_migrations.is_applied() {
                return Err(format!("判定应当是 Applied：{:?}", report.data_migrations));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 账本不足（< 13 条）⇒ 判红，报文给出实得条数与账本表名。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_short_drizzle_ledger_is_rejected() {
    let admin = admin_config("a_short_drizzle_ledger_is_rejected");
    with_temp_database(&admin, "ledgershort", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;
            // 只跑到 0002 的库：账本里只有 3 条。
            install_drizzle_ledger(&client, 3).await?;

            // 前提自检：schema 级检查在这个库上必须通过 —— 这正是它照不到的盲区。
            let facts = schema_facts::fetch(&client)
                .await
                .map_err(|e| format!("提取 schema 事实失败：{e}"))?;
            if let Err(report) = compat::check_migration_boundary(&facts) {
                return Err(format!(
                    "前提自检失败：schema 级本不该看出问题，却报了 {report}"
                ));
            }

            let error = compat::check_migration_boundary_on(&client)
                .await
                .expect_err("账本不足必须被拒绝");
            if !matches!(
                error,
                openbot_infra::db::InfraError::IncompatibleDatabase(_)
            ) {
                return Err(format!("应当报「库不兼容」而不是别的档：{error:?}"));
            }
            let rendered = format!("{error} | {}", openbot_infra::db::error_chain(&error));
            for needle in ["drizzle.__drizzle_migrations", "3", "13"] {
                if !rendered.contains(needle) {
                    return Err(format!("报文没点名 {needle}：{rendered}"));
                }
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// **最重要的一条**：账本表不存在 ⇒ 报"不可验证"，既不判红也不默认通过。
///
/// baseline 建出来的库正是这种形态（Rust baseline 直接建 0012 终态，不写 drizzle 账本）。
/// 如果哪天有人把三态折叠成二值，这条会红：折进"通过"则 `is_unverifiable()` 变假，
/// 折进"判红"则边界检查会拒绝一个全新安装。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_missing_drizzle_ledger_is_reported_as_unverifiable() {
    let admin = admin_config("a_missing_drizzle_ledger_is_reported_as_unverifiable");
    with_temp_database(&admin, "ledgernone", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
            baseline::apply(&client)
                .await
                .map_err(|e| format!("应用 baseline 失败：{e}"))?;

            // 探表本身必须成功返回"不存在"，而不是把它伪装成查询失败。
            let ledger = compat::fetch_migration_ledger(&client)
                .await
                .map_err(|e| format!("账本表不存在时不该报错，却报了：{e}"))?;
            if ledger != compat::MigrationLedger::Absent {
                return Err(format!("账本本不该存在：{ledger:?}"));
            }

            // 不判红：边界检查必须通过（否则全新安装会被自己拒绝）。
            let report = compat::check_migration_boundary_on(&client)
                .await
                .map_err(|e| format!("没有账本不该判红，却报了：{e}"))?;

            let verdict = &report.data_migrations;
            if !verdict.is_unverifiable() {
                return Err(format!("判定应当是 Unverifiable：{verdict:?}"));
            }
            // 也不默认通过。
            if verdict.is_applied() {
                return Err("不可验证被折叠成了通过".to_string());
            }
            if verdict.is_incomplete() {
                return Err("不可验证被折叠成了判红".to_string());
            }
            let rendered = verdict.to_string();
            if !rendered.contains("无法验证") {
                return Err(format!("没如实报告不可验证：{rendered}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

/// 连接失败的错误里**不得**出现口令。
///
/// 这条把一个原本只写在 `db::error` 文档里、没验证过的断言变成实证：
/// `InfraError::Connect` 是四档里唯一仍持原始错误（而非 `PostgresErrorSummary`）的一档，
/// 理由是"建连阶段库里还没有行，服务端错误只可能提到库名、用户名与 SQLSTATE"。
/// 那是一条推断，不是测量 —— 所以这里用**错口令**连一个存在的库，把 `Display`、`Debug`
/// 与整条 `source()` 链都渲染出来，逐一断言口令不在里面。
///
/// 正向对照必须有：只断言"不含口令"，在"输出恒为空串"的世界里同样成立。
/// 所以同时断言输出里确实带得出可诊断信息（SQLSTATE `28P01`，或用户名 / 库名之一）。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_failed_connection_never_carries_the_password() {
    const WRONG_PASSWORD: &str = "SENTINEL-WRONG-PASSWORD-DO-NOT-LOG";

    let admin = admin_config("a_failed_connection_never_carries_the_password");

    // 前提自检一：正确口令连得上。否则下面的失败可能只是库不通，与口令无关。
    let ok = pool::connect(&admin)
        .await
        .expect("正确口令必须连得上，否则本用例的负向断言说明不了任何事");
    ok.close();

    // 前提自检二：服务端确实在校验口令。若本机 PostgreSQL 配的是 `trust`，
    // 错口令也会连上 —— 那时本用例什么都没测到，必须响亮地说出来而不是静默通过。
    let wrong = admin.clone().with_password(WRONG_PASSWORD);
    let error = match pool::connect(&wrong).await {
        Ok(pool) => {
            pool.close();
            panic!(
                "前提自检失败：服务端接受了错误口令（pg_hba 可能是 trust），\
                 本用例无法验证口令是否泄漏。请用 scram/md5 认证的实例重跑。"
            );
        }
        Err(error) => error,
    };

    // 档位要对：这是连接失败，不是查询失败。
    assert!(
        matches!(error, openbot_infra::db::InfraError::Connect { .. }),
        "应当报连接失败：{error:?}",
    );

    let rendered = format!(
        "{error} | {error:?} | {}",
        openbot_infra::db::error_chain(&error),
    );
    assert!(
        !rendered.contains(WRONG_PASSWORD),
        "连接错误泄漏了口令：{rendered}",
    );

    // 正向对照：脱敏之后仍然诊断得动。PostgreSQL 认证失败是 SQLSTATE 28P01，
    // 报文里一般还会带上用户名；三样里至少要有一样在，否则上一条断言是空的。
    let user = admin.user.as_str();
    let dbname = admin.dbname.as_str();
    assert!(
        rendered.contains("28P01") || rendered.contains(user) || rendered.contains(dbname),
        "错误里既没有 SQLSTATE 也没有用户名/库名，无法诊断：{rendered}",
    );
}

/// 每张表的种子行数（`fixtures/db/seed-0012.sql` 是 28 张表 × 6 行）。
const SEEDED_ROWS_PER_TABLE: usize = 6;

/// 种子总行数。
const EXPECTED_SEEDED_ROWS: usize = 28 * SEEDED_ROWS_PER_TABLE;

/// 仓内的对抗性种子。刻意不在这里另造一份 —— 两份种子会各自漂移，
/// 而漂移的那一刻两边的测试都还是绿的。
const SEED_SQL: &str = include_str!("../../../fixtures/db/seed-0012.sql");

/// 对 28 张表各跑一次 `SELECT *`，逐行过它自己的 `Row::try_from`。
///
/// 用宏展开而不是手写 28 段：表名清单只写一处，漏掉一张表在构造上就是编译不过。
macro_rules! decode_tables {
    ($client:expr, $problems:expr, $decoded:expr, $($module:ident),+ $(,)?) => {
        $({
            use openbot_infra::db::tables::$module as table;
            let sql = format!("SELECT * FROM public.{}", table::TABLE_NAME);
            match $client.query(sql.as_str(), &[]).await {
                Err(error) => $problems.push(format!("{}：查询失败 {error}", table::TABLE_NAME)),
                Ok(rows) => {
                    if rows.len() != SEEDED_ROWS_PER_TABLE {
                        $problems.push(format!(
                            "{}：期望 {SEEDED_ROWS_PER_TABLE} 行，实际 {}",
                            table::TABLE_NAME,
                            rows.len(),
                        ));
                    }
                    for row in &rows {
                        match table::Row::try_from(row) {
                            Ok(_) => *$decoded += 1,
                            Err(error) => $problems.push(format!(
                                "{}：{}",
                                table::TABLE_NAME,
                                openbot_infra::db::error_chain(&error),
                            )),
                        }
                    }
                }
            }
        })+
    };
}

async fn decode_every_table(
    client: &tokio_postgres::Client,
    problems: &mut Vec<String>,
    decoded: &mut usize,
) {
    decode_tables!(
        client,
        problems,
        decoded,
        accounts,
        action_policy,
        agent_preferences,
        agent_profiles,
        agents,
        audit_events,
        channel_agents,
        channel_memberships,
        channels,
        component_exclusions,
        component_functions,
        components,
        computer_snapshot,
        credentials,
        deployment_packages,
        intelligence_channel_mappings,
        mcp_servers,
        mcp_tools,
        mcp_user_credentials,
        plugin_grants,
        revoked_access,
        sandboxed_components,
        sessions,
        skills,
        sso_providers,
        user_roles,
        users,
        verifications,
    );
}
