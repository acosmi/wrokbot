//! Native 0028 remote AG-UI interrupt/resume PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0027: &str = include_str!("../../../fixtures/db/schema-0027.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

fn post_0028_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0028.json")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0028_is_exact_expand_only_remote_interrupt_schema() {
    let admin = admin_config("post_0028_is_exact_expand_only_remote_interrupt_schema");
    with_temp_database(&admin, "native0028facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0027_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0027) {
                return Err("0028 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0028_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0028 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0028 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0028 rewrote old column {}.{}",
                            old.name, column.name
                        ));
                    }
                }
            }
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0028").is_some() {
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(post_0028_path(), encoded).map_err(|error| error.to_string())?;
            } else {
                let expected = std::fs::read_to_string(post_0028_path())
                    .map_err(|error| format!("schema-0028 fixture missing: {error}"))?;
                if after != facts(&expected) {
                    return Err("0028 live schema differs from fixture".to_owned());
                }
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
            if ledger != 16 {
                return Err(format!("native ledger expected 16, got {ledger}"));
            }
            if native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::AlreadyApplied
            {
                return Err("0028 ledger replay must be exact".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
