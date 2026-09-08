//! Native 0019 explicit vendor-transport PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0018: &str = include_str!("../../../fixtures/db/schema-0018.json");
const POST_0019: &str = include_str!("../../../fixtures/db/schema-0019.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0019_is_exact_expand_only_transport_identity() {
    let admin = admin_config("post_0019_is_exact_expand_only_transport_identity");
    with_temp_database(&admin, "native0019facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0018_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0018) {
                return Err("0019 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0019_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0019 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0019").is_some() {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/db/schema-0019.json");
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(path, encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            if after != facts(POST_0019) {
                return Err("0019 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0019 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0019 rewrote old column {}.{}",
                            old.name, column.name
                        ));
                    }
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
            if ledger != 7 {
                return Err(format!("native ledger expected 7, got {ledger}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn legacy_null_remains_mcp_and_transport_domain_is_closed() {
    let admin = admin_config("legacy_null_remains_mcp_and_transport_domain_is_closed");
    with_temp_database(&admin, "native0019constraints", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.mcp_servers(id,title,vendor,url,provenance)
                       VALUES('legacy','Legacy','vendor','https://vendor.invalid/mcp','custom');",
                )
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            let legacy: (Option<String>, String) = client
                .query_one(
                    "SELECT transport,coalesce(transport,'mcp')
                       FROM public.mcp_servers WHERE id='legacy'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|row| {
                    Ok((
                        row.try_get(0).map_err(|error| error.to_string())?,
                        row.try_get(1).map_err(|error| error.to_string())?,
                    ))
                })?;
            if legacy != (None, "mcp".to_owned()) {
                return Err("0019 rewrote or reinterpreted the legacy NULL transport".to_owned());
            }
            client
                .execute(
                    "UPDATE public.mcp_servers SET transport='mcp' WHERE id='legacy'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.mcp_servers SET transport='google_drive_rest'
                      WHERE id='legacy'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.mcp_servers SET transport='gated-preview' WHERE id='legacy'",
                    &[],
                )
                .await
                .expect_err("unreviewed transport must fail the named CHECK");
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
