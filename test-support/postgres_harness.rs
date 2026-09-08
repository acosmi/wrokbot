// 需要真实 PostgreSQL 的集成测试共用临时库 harness。
//
// 这是 workspace 唯一一份实现；infra/server 测试各自 `include!`，避免两份 harness 漂移却
// 同时保持绿色。每个用例创建随机临时库，结束后 `DROP ... WITH (FORCE)`。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use openbot_infra::db::pool::{self, DatabaseConfig};

pub(crate) const ENV_KEY: &str = "OPENBOT_TEST_DATABASE_URL";

pub(crate) static SEQUENCE: AtomicU32 = AtomicU32::new(0);

pub(crate) fn admin_config(test_name: &str) -> DatabaseConfig {
    let Ok(url) = std::env::var(ENV_KEY) else {
        panic!(
            "{test_name} 需要真实 PostgreSQL，但环境变量 {ENV_KEY} 未设置。\
             默认 `cargo test` 会按 #[ignore] 跳过本用例并打印理由；\
             调用方显式传了 --include-ignored，所以这里不静默放行。\
             设法：OPENBOT_TEST_DATABASE_URL=\"host=… port=… user=… password=… dbname=postgres\""
        );
    };
    url
        .parse::<DatabaseConfig>()
        .unwrap_or_else(|error| panic!("{ENV_KEY} 无法解析：{error}"))
        .with_application_name("openbot-postgres-integration-test")
        .with_max_pool_size(2)
}

pub(crate) fn unique_database_name(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应当晚于 UNIX 纪元")
        .as_nanos();
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("openbot_it_{tag}_{}_{nanos}_{seq}", std::process::id())
}

pub(crate) async fn run_utility(admin: &DatabaseConfig, sql: &str) -> Result<(), String> {
    let pool = pool::connect(admin)
        .await
        .map_err(|error| format!("连接管理库失败：{error}"))?;
    let outcome = async {
        let client = pool
            .get()
            .await
            .map_err(|error| format!("取管理连接失败：{error}"))?;
        client
            .simple_query(sql)
            .await
            .map(|_| ())
            .map_err(|error| format!("执行 `{sql}` 失败：{error}"))
    }
    .await;
    pool.close();
    outcome
}

pub(crate) async fn with_temp_database<F, Fut>(admin: &DatabaseConfig, tag: &str, body: F)
where
    F: FnOnce(DatabaseConfig) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let name = unique_database_name(tag);
    run_utility(admin, &format!("CREATE DATABASE \"{name}\""))
        .await
        .unwrap_or_else(|error| panic!("建临时库 {name} 失败：{error}"));

    let outcome = body(admin.clone().with_dbname(&name)).await;
    let dropped = run_utility(admin, &format!("DROP DATABASE \"{name}\" WITH (FORCE)")).await;

    if let Err(message) = outcome {
        panic!("{message}");
    }
    dropped.unwrap_or_else(|error| panic!("删临时库 {name} 失败：{error}"));
}
