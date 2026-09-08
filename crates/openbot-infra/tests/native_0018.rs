//! Native 0018 MCP credential-generation PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0017: &str = include_str!("../../../fixtures/db/schema-0017.json");
const POST_0018: &str = include_str!("../../../fixtures/db/schema-0018.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0018_is_exact_expand_only_and_credential_generation_is_independent() {
    let admin =
        admin_config("post_0018_is_exact_expand_only_and_credential_generation_is_independent");
    with_temp_database(&admin, "native0018facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0017_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0017) {
                return Err("0018 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0018_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0018 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0018").is_some() {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/db/schema-0018.json");
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(path, encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            if after != facts(POST_0018) {
                return Err("0018 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0018 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0018 rewrote old column {}.{}",
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
            if ledger != 6 {
                return Err(format!("native ledger expected 6, got {ledger}"));
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
async fn legacy_null_means_zero_and_negative_generations_are_rejected() {
    let admin = admin_config("legacy_null_means_zero_and_negative_generations_are_rejected");
    with_temp_database(&admin, "native0018constraints", |config| async move {
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
                    "INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('bot-mcp','Bot','remote_ag_ui','{}');
                     INSERT INTO public.mcp_servers(id,title,vendor,url)
                       VALUES('notes','Notes','notes','https://notes.invalid/mcp');
                     INSERT INTO public.plugin_grants(kind,ref,agent_id)
                       VALUES('mcp','notes/search','bot-mcp');",
                )
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            let legacy: bool = client
                .query_one(
                    "SELECT s.credential_generation IS NULL
                            AND g.credential_generation IS NULL
                       FROM public.mcp_servers s JOIN public.plugin_grants g
                         ON split_part(g.ref,'/',1)=s.id
                      WHERE s.id='notes'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !legacy {
                return Err("0018 rewrote legacy generations instead of preserving NULL".to_owned());
            }
            client
                .execute(
                    "UPDATE public.mcp_servers SET credential_generation=-1 WHERE id='notes'",
                    &[],
                )
                .await
                .expect_err("negative server generation must fail");
            client
                .execute(
                    "UPDATE public.plugin_grants SET credential_generation=-1
                      WHERE ref='notes/search'",
                    &[],
                )
                .await
                .expect_err("negative grant generation must fail");
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
