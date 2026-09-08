//! **Read checksum** —— v3 §24 G1「read checksum 0 差异」/ §19.2 W5–10 退出闸门
//! 「DB read checksum 100%」的执行面。
//!
//! # 它证明的东西，比"能解码"强一档
//!
//! `schema_baseline_parity.rs::every_seeded_row_decodes_through_its_row_struct` 证明的是
//! **解码完整性**：168 行全都能解出来、不报错。但一个"能解但解错"的映射同样会通过它 ——
//! timestamptz 丢了时区偏移、jsonb 的大整数过了一遍 `f64`、`text[]` 元素顺序变了，
//! 每一种都解得出来，只是解出来的**值**不对。
//!
//! 本文件比的是**值**：
//!
//! 1. 源侧 —— `SELECT md5(t::text) FROM public.<表> t`，PostgreSQL 自己把整行渲染成复合类型
//!    文本再求摘要；
//! 2. 回送侧 —— Rust 把**解码出来的** `Row` 的每一列作为 `$1..$n` 送回去，
//!    `SELECT md5((ROW($1, …, $n)::public.<表>)::text)`，由**同一个** PostgreSQL 重新组装
//!    同一个复合类型再求摘要；
//! 3. 逐行比这两个摘要。
//!
//! 关键在于**两侧的渲染都由同一个 PostgreSQL 完成**，Rust 只负责"把读出来的值原样送回去"
//! —— 而那正是要检验的那件事。刻意**不**在 Rust 侧算摘要再和 PostgreSQL 的文本比：
//! 两边的规范化（浮点格式、时间戳渲染、数组转义）永远对不齐，那种实现要么恒绿要么恒红。
//!
//! 顺带覆盖了**写路径**：每一列都走了一遍 `ToSql`，包括 7 个 `uuid` 列。
//!
//! # 数据
//!
//! 用 `fixtures/db/seed-0012.sql`（28 张表 × 6 行 = 168 行）。这是那份对抗夹具**应有**的
//! 用法：它专挑会让类型映射出错的值（空串 vs NULL、含 NULL 元素的数组、超 `f64` 精度的整数、
//! 亚秒 + 非 UTC 偏移、CJK / emoji / 组合字符 / 引号 / 反斜杠、`i32::MAX`、全部 enum 取值）。

mod harness;

use harness::{admin_config, with_temp_database};

use openbot_infra::db::{baseline, pool};

/// 仓内对抗种子。
const SEED_SQL: &str = include_str!("../../../fixtures/db/seed-0012.sql");

/// 28 张表 × 6 行。
const EXPECTED_ROWS: usize = 168;

/// 拼出把参数重新组装成复合类型再求摘要的语句。
///
/// 这里确实在**构造** SQL 文本，但拼进去的两样东西都是编译期常量：表名来自
/// `db::tables::<表>::TABLE_NAME`（宏从台账展开的字面量），占位符个数来自
/// `COLUMNS.len()`。**没有任何外部值参与拼接** —— 行里的值全部走 `$n` 绑定。
fn reconstruct_checksum_sql(table: &str, columns: usize) -> String {
    let placeholders = (1..=columns)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("SELECT md5((ROW({placeholders})::public.{table})::text)")
}

/// 摘要不等时，逐列问 PostgreSQL 哪一列不同 —— 只回布尔，**不回取值**。
///
/// 行里可能有明文令牌与密文（`accounts` / `sessions` / `credentials` …），
/// 判红报文里不能出现取值（repository contract §5 不变量 8）。
fn column_diff_sql(table: &str, columns: &[&str]) -> String {
    let placeholders = (1..=columns.len())
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let comparisons = columns
        .iter()
        .map(|c| format!("(src.\"{c}\"::text IS NOT DISTINCT FROM back.\"{c}\"::text)"))
        .collect::<Vec<_>>()
        .join(", ");
    let checksum_param = columns.len() + 1;
    format!(
        "WITH src AS (\
             SELECT t.* FROM public.{table} t WHERE md5(t::text) = ${checksum_param} LIMIT 1\
         ), back AS (\
             SELECT (ROW({placeholders})::public.{table}).*\
         ) SELECT {comparisons} FROM src, back"
    )
}

/// 一张表的比对结果。
struct TableOutcome {
    checked: usize,
    problems: Vec<String>,
}

/// 对 28 张表逐张跑 read checksum。
///
/// 用宏展开而不是手写 28 段：表名清单只写一处，漏掉一张表在构造上就是编译不过。
/// `Row` 必须活到参数用完，所以整段内联在宏里 —— 抽成函数会让借用活不过返回。
macro_rules! checksum_tables {
    ($client:expr, $outcome:expr, $($module:ident),+ $(,)?) => {
        $({
            use openbot_infra::db::tables::$module as table;

            let source_sql = format!(
                "SELECT md5(t::text) AS __row_checksum, t.* FROM public.{} t",
                table::TABLE_NAME,
            );
            let reconstruct_sql =
                reconstruct_checksum_sql(table::TABLE_NAME, table::COLUMNS.len());

            match $client.query(source_sql.as_str(), &[]).await {
                Err(error) => $outcome
                    .problems
                    .push(format!("{}：源侧查询失败 {error}", table::TABLE_NAME)),
                Ok(rows) => {
                    for raw in &rows {
                        let source: String = match raw.try_get("__row_checksum") {
                            Ok(value) => value,
                            Err(error) => {
                                $outcome.problems.push(format!(
                                    "{}：取源侧摘要失败 {error}",
                                    table::TABLE_NAME,
                                ));
                                continue;
                            }
                        };

                        let decoded = match table::Row::try_from(raw) {
                            Ok(row) => row,
                            Err(error) => {
                                $outcome.problems.push(format!(
                                    "{}：解码失败 {}",
                                    table::TABLE_NAME,
                                    openbot_infra::db::error_chain(&error),
                                ));
                                continue;
                            }
                        };

                        let params = decoded.as_sql_params();
                        let returned: Result<String, _> = $client
                            .query_one(reconstruct_sql.as_str(), &params)
                            .await
                            .and_then(|row| row.try_get(0));

                        match returned {
                            Err(error) => $outcome.problems.push(format!(
                                "{}：回送重组失败 {error}",
                                table::TABLE_NAME,
                            )),
                            Ok(returned) if returned == source => $outcome.checked += 1,
                            Ok(returned) => {
                                let differing = pinpoint_columns(
                                    $client,
                                    table::TABLE_NAME,
                                    table::COLUMNS,
                                    &params,
                                    &source,
                                )
                                .await;
                                $outcome.problems.push(format!(
                                    "{}：行摘要不等（源 {source} != 回送 {returned}），差异列 {differing:?}",
                                    table::TABLE_NAME,
                                ));
                            }
                        }
                    }
                }
            }
        })+
    };
}

/// 问 PostgreSQL 哪些列不同。失败时返回一条说明，不返回取值。
async fn pinpoint_columns(
    client: &tokio_postgres::Client,
    table: &str,
    columns: &[&str],
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    source_checksum: &str,
) -> Vec<String> {
    let sql = column_diff_sql(table, columns);
    let mut with_checksum: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params.to_vec();
    with_checksum.push(&source_checksum);
    match client.query_opt(sql.as_str(), &with_checksum).await {
        Err(error) => vec![format!("<逐列定位查询失败：{error}>")],
        Ok(None) => vec!["<按源摘要找不回原行>".to_owned()],
        Ok(Some(row)) => {
            let mut differing = Vec::new();
            for (index, column) in columns.iter().enumerate() {
                match row.try_get::<_, bool>(index) {
                    Ok(true) => {}
                    Ok(false) => differing.push((*column).to_owned()),
                    Err(error) => differing.push(format!("{column}<读比较位失败：{error}>")),
                }
            }
            differing
        }
    }
}

/// 168 行逐行往返，摘要必须逐行相等。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn every_seeded_row_survives_a_decode_and_send_back_round_trip() {
    let admin = admin_config("every_seeded_row_survives_a_decode_and_send_back_round_trip");
    with_temp_database(&admin, "readsum", |config| async move {
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

            let mut outcome = TableOutcome {
                checked: 0,
                problems: Vec::new(),
            };
            checksum_tables!(
                &client,
                outcome,
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

            if !outcome.problems.is_empty() {
                return Err(format!(
                    "read checksum 有 {} 处差异：\n  - {}",
                    outcome.problems.len(),
                    outcome.problems.join("\n  - "),
                ));
            }
            if outcome.checked != EXPECTED_ROWS {
                return Err(format!(
                    "只比对了 {} 行，期望 {EXPECTED_ROWS} 行（28 张表 × 6 行）",
                    outcome.checked,
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

/// 负向对照：把一个值在送回去之前改一个字节，比对必须当场判红并点名表与列。
///
/// 没有这一条，上面那条在"比对函数恒返回相等"的世界里同样通过。
/// 刻意挑 `users.email`（`text`，非 secret 列，改动可见）与 `computer_snapshot.snapshot_id`
/// （`integer`，改一个数值而不是文本），证明判红不是只对字符串类型生效。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_single_mutated_value_makes_the_checksum_disagree() {
    let admin = admin_config("a_single_mutated_value_makes_the_checksum_disagree");
    with_temp_database(&admin, "readsumneg", |config| async move {
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

            // ---- text 列：末尾加一个字符 ----
            let raw = client
                .query_one(
                    "SELECT md5(t::text) AS __row_checksum, t.* \
                     FROM public.users t WHERE t.id = 'users_00'",
                    &[],
                )
                .await
                .map_err(|e| format!("查 users 失败：{e}"))?;
            let source: String = raw
                .try_get("__row_checksum")
                .map_err(|e| format!("取源侧摘要失败：{e}"))?;
            let mut decoded = openbot_infra::db::tables::users::Row::try_from(&raw)
                .map_err(|e| format!("解 users 失败：{e}"))?;

            // 前提自检：未改动前必须相等，否则"改动后不等"说明不了任何事。
            let sql = reconstruct_checksum_sql(
                openbot_infra::db::tables::users::TABLE_NAME,
                openbot_infra::db::tables::users::COLUMNS.len(),
            );
            let before: String = client
                .query_one(sql.as_str(), &decoded.as_sql_params())
                .await
                .and_then(|row| row.try_get(0))
                .map_err(|e| format!("回送失败：{e}"))?;
            if before != source {
                return Err(format!(
                    "前提自检失败：未改动就已不等（{source} != {before}）"
                ));
            }

            decoded.email.push('x');
            let after: String = client
                .query_one(sql.as_str(), &decoded.as_sql_params())
                .await
                .and_then(|row| row.try_get(0))
                .map_err(|e| format!("回送失败：{e}"))?;
            if after == source {
                return Err("改了 users.email 一个字符，摘要竟然仍相等：比对管线是坏的".to_owned());
            }
            let differing = pinpoint_columns(
                &client,
                openbot_infra::db::tables::users::TABLE_NAME,
                openbot_infra::db::tables::users::COLUMNS,
                &decoded.as_sql_params(),
                &source,
            )
            .await;
            if differing != vec!["email".to_owned()] {
                return Err(format!("逐列定位应当只点名 email，实际 {differing:?}"));
            }

            // ---- integer 列：+1 ----
            let raw = client
                .query_one(
                    "SELECT md5(t::text) AS __row_checksum, t.* \
                     FROM public.computer_snapshot t WHERE t.computer_id = 'computer_snapshot_03'",
                    &[],
                )
                .await
                .map_err(|e| format!("查 computer_snapshot 失败：{e}"))?;
            let source: String = raw
                .try_get("__row_checksum")
                .map_err(|e| format!("取源侧摘要失败：{e}"))?;
            let mut decoded = openbot_infra::db::tables::computer_snapshot::Row::try_from(&raw)
                .map_err(|e| format!("解 computer_snapshot 失败：{e}"))?;
            let sql = reconstruct_checksum_sql(
                openbot_infra::db::tables::computer_snapshot::TABLE_NAME,
                openbot_infra::db::tables::computer_snapshot::COLUMNS.len(),
            );
            let before: String = client
                .query_one(sql.as_str(), &decoded.as_sql_params())
                .await
                .and_then(|row| row.try_get(0))
                .map_err(|e| format!("回送失败：{e}"))?;
            if before != source {
                return Err(format!(
                    "前提自检失败：未改动就已不等（{source} != {before}）"
                ));
            }

            decoded.snapshot_id += 1;
            let after: String = client
                .query_one(sql.as_str(), &decoded.as_sql_params())
                .await
                .and_then(|row| row.try_get(0))
                .map_err(|e| format!("回送失败：{e}"))?;
            if after == source {
                return Err("改了 computer_snapshot.snapshot_id，摘要竟然仍相等".to_owned());
            }
            let differing = pinpoint_columns(
                &client,
                openbot_infra::db::tables::computer_snapshot::TABLE_NAME,
                openbot_infra::db::tables::computer_snapshot::COLUMNS,
                &decoded.as_sql_params(),
                &source,
            )
            .await;
            if differing != vec!["snapshot_id".to_owned()] {
                return Err(format!(
                    "逐列定位应当只点名 snapshot_id，实际 {differing:?}"
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
