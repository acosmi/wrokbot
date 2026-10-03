//! Actual nullable expansion and exact current-schema canary, including a native37 upgrade.
mod harness;
use openbot_infra::db::{
    baseline, desktop_vault_canary, fresh, native, pool, schema_facts, tables,
};
use tokio_postgres::error::SqlState;

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn schema38_matches_owned_pg_oracle_and_preserves_the_fixed_upstream_registry() {
    harness::with_temp_database(
        &harness::admin_config("sandbox38fresh"),
        "sandbox38fresh",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let mut c = p.get().await.unwrap();
            fresh::apply(&mut c).await.unwrap();
            let actual = schema_facts::fetch(&c).await.unwrap();
            let expected: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0038.json"))
                    .unwrap();
            assert_eq!(actual, expected);
            let prior: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0037.json"))
                    .unwrap();
            assert_eq!(actual.tables.len(), prior.tables.len() + 1);
            for table in &prior.tables {
                if table.name != "sandboxed_components" {
                    assert_eq!(actual.table(&table.name), Some(table));
                } else {
                    let now = actual.table(&table.name).unwrap();
                    assert_eq!(now.columns.len(), table.columns.len() + 1);
                    for column in &table.columns {
                        assert!(now.columns.contains(column));
                    }
                    for constraint in &table.constraints {
                        assert!(now.constraints.contains(constraint));
                    }
                    for index in &table.indexes {
                        assert!(now.indexes.contains(index));
                    }
                    let added = now
                        .columns
                        .iter()
                        .find(|c| c.name == "editing_revision")
                        .unwrap();
                    assert!(!added.notnull);
                }
            }
            assert_eq!(actual.enums, prior.enums);
            assert_eq!(actual.extensions, prior.extensions);
            assert_eq!(tables::sandboxed_components::COLUMNS.len(), 19);
            assert_eq!(tables::sandboxed_editing_components::COLUMNS.len(), 20);
            assert_eq!(
                tables::current_table_specs()
                    .filter(|t| t.name == "sandboxed_components")
                    .count(),
                1
            );
            assert_eq!(
                native::apply(&mut c).await.unwrap(),
                native::ApplyOutcome::AlreadyApplied
            );
            drop(c);
            desktop_vault_canary::verify_current_layout(&p)
                .await
                .unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn upgrade_keeps_publication_history_and_allows_legacy_null_but_rejects_nonpositive_edits() {
    harness::with_temp_database(&harness::admin_config("sandbox38upgrade"),"sandbox38upgrade",|config|async move {
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();baseline::apply(&c).await.unwrap();native::apply_through(&mut c,37).await.unwrap();
        c.batch_execute("INSERT INTO public.sandboxed_components(name,title,revision,published,published_at,draft_description,draft_html,draft_css,draft_js_functions,draft_argument_schema,sample_arguments,created_at,updated_at) VALUES('custom_legacy','legacy',7,false,NULL,'d','h','c','j','{}','{}','2020-01-01','2020-01-01')").await.unwrap();
        drop(c);assert_eq!(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.unwrap().native_version(),37);
        let mut c=p.get().await.unwrap();native::apply(&mut c).await.unwrap();
        let row=c.query_one("SELECT revision,editing_revision,updated_at FROM public.sandboxed_components WHERE name='custom_legacy'",&[]).await.unwrap();assert_eq!(row.get::<_,i32>(0),7);assert_eq!(row.get::<_,Option<i64>>(1),Some(1));assert_eq!(row.get::<_,time::OffsetDateTime>(2).year(),2020);
        c.execute("UPDATE public.sandboxed_components SET editing_revision=NULL WHERE name='custom_legacy'",&[]).await.unwrap();
        for value in [0_i64,-1] {assert_eq!(c.execute("UPDATE public.sandboxed_components SET editing_revision=$1 WHERE name='custom_legacy'",&[&value]).await.unwrap_err().code(),Some(&SqlState::CHECK_VIOLATION));}
        let rows=c.query("SELECT * FROM public.sandboxed_components",&[]).await.unwrap();let typed=tables::sandboxed_editing_components::Row::try_from(&rows[0]).unwrap();assert_eq!(typed.editing_revision,None);assert_eq!(typed.revision,7);
        assert_eq!(c.query_one("SELECT count(*) FROM public.sandboxed_component_retired_names",&[]).await.unwrap().get::<_,i64>(0),0);
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.unwrap();p.close();Ok(())
    }).await;
}
