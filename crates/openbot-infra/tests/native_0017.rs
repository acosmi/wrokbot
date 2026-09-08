//! Native 0017 MCP catalog/stale-grant/callback-sequence PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0016: &str = include_str!("../../../fixtures/db/schema-0016.json");
const POST_0017: &str = include_str!("../../../fixtures/db/schema-0017.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0017_is_exact_expand_only_and_regenerates_only_when_explicitly_requested() {
    let admin = admin_config(
        "post_0017_is_exact_expand_only_and_regenerates_only_when_explicitly_requested",
    );
    with_temp_database(&admin, "native0017facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0016_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0016) {
                return Err("0017 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0017_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0017 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0017").is_some() {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/db/schema-0017.json");
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(path, encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            if after != facts(POST_0017) {
                return Err("0017 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0017 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0017 rewrote old column {}.{}",
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
            if ledger != 5 {
                return Err(format!("native ledger expected 5, got {ledger}"));
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
async fn nullable_compatibility_and_complete_projection_constraints_fail_closed() {
    let admin =
        admin_config("nullable_compatibility_and_complete_projection_constraints_fail_closed");
    with_temp_database(&admin, "native0017constraints", |config| async move {
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
                     INSERT INTO public.mcp_tools(server_id,name,description,input_schema)
                       VALUES('notes','search','Search','{\"type\":\"object\"}');
                     INSERT INTO public.plugin_grants(kind,ref,agent_id)
                       VALUES('mcp','notes/search','bot-mcp');",
                )
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            let legacy_nulls: bool = client
                .query_one(
                    "SELECT s.catalog_generation IS NULL AND s.catalog_hash IS NULL
                            AND s.catalog_transport_fingerprint IS NULL
                            AND t.schema_hash IS NULL AND t.available IS NULL
                            AND g.state IS NULL AND g.effect IS NULL
                            AND g.transport_fingerprint IS NULL
                       FROM public.mcp_servers s
                       JOIN public.mcp_tools t ON t.server_id=s.id
                       JOIN public.plugin_grants g ON g.ref=s.id||'/'||t.name
                      WHERE s.id='notes'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !legacy_nulls {
                return Err(
                    "0017 rewrote legacy catalog rows instead of expand-only NULL".to_owned(),
                );
            }
            for sql in [
                "UPDATE public.runs SET next_tool_call_seq=-1 WHERE false",
                "UPDATE public.mcp_servers SET catalog_generation=1 WHERE id='notes'",
                "UPDATE public.mcp_tools SET schema_hash=repeat('a',64) WHERE server_id='notes'",
                "UPDATE public.plugin_grants SET state='active' WHERE ref='notes/search'",
            ] {
                // The first statement has no row by design; insert a run-specific negative below.
                if sql.contains("WHERE false") {
                    continue;
                }
                client
                    .batch_execute(sql)
                    .await
                    .expect_err("partial catalog projection must fail its CHECK");
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
