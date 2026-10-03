//! Current preference schema facts, old nullable fields and fixed baseline registry.
mod harness;
use openbot_infra::db::{
    baseline, desktop_vault_canary, fresh, native, pool, schema_facts, tables,
};
use tokio_postgres::error::SqlState;

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn schema40_matches_owned_oracle_and_keeps_native21_baseline() {
    harness::with_temp_database(
        &harness::admin_config("prefs40fresh"),
        "prefs40fresh",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let mut c = p.get().await.unwrap();
            fresh::apply(&mut c).await.unwrap();
            let actual = schema_facts::fetch(&c).await.unwrap();
            let expected: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0040.json"))
                    .unwrap();
            let prior: schema_facts::SchemaFacts =
                serde_json::from_str(include_str!("../../../fixtures/db/schema-0039.json"))
                    .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual.tables.len(), prior.tables.len());
            for old in &prior.tables {
                let now = actual.table(&old.name).unwrap();
                if old.name != "user_ui_preferences" {
                    assert_eq!(old, now);
                } else {
                    assert_eq!(now.columns.len(), old.columns.len() + 1);
                    for col in &old.columns {
                        assert!(now.columns.contains(col));
                    }
                    for constraint in &old.constraints {
                        assert!(now.constraints.contains(constraint));
                    }
                    for index in &old.indexes {
                        assert!(now.indexes.contains(index));
                    }
                    assert!(!now.column("revision").unwrap().notnull);
                }
            }
            assert_eq!(actual.enums, prior.enums);
            assert_eq!(actual.extensions, prior.extensions);
            assert_eq!(tables::user_ui_preferences::COLUMNS.len(), 6);
            assert_eq!(tables::editing_ui_preferences::COLUMNS.len(), 7);
            assert_eq!(
                tables::current_table_specs()
                    .filter(|t| t.name == "user_ui_preferences")
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
async fn upgrade_keeps_values_timestamp_scope_and_nullable_revision() {
    harness::with_temp_database(&harness::admin_config("prefs40upgrade"),"prefs40upgrade",|config|async move {
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        baseline::apply(&c).await.unwrap();native::apply_through(&mut c,39).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email) VALUES('prefs-owner','prefs-owner@example.test');
            INSERT INTO public.user_ui_preferences(deployment_id,tenant_id,actor_user_id,theme,locale,updated_at)
            VALUES('dep','tenant','prefs-owner','dark',NULL,'2020-01-01')").await.unwrap();
        drop(c);assert_eq!(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.unwrap().native_version(),39);
        let mut c=p.get().await.unwrap();native::apply(&mut c).await.unwrap();
        let row=tables::editing_ui_preferences::Row::try_from(&c.query_one("SELECT * FROM public.user_ui_preferences",&[]).await.unwrap()).unwrap();
        assert_eq!(row.theme.as_deref(),Some("dark"));assert_eq!(row.locale,None);assert_eq!(row.updated_at.year(),2020);
        assert_eq!(row.deployment_id,"dep");assert_eq!(row.tenant_id,"tenant");assert_eq!(row.actor_user_id,"prefs-owner");
        assert_eq!(row.revision,Some(1));
        c.execute("UPDATE public.user_ui_preferences SET revision=NULL",&[]).await.unwrap();
        assert_eq!(tables::editing_ui_preferences::Row::try_from(&c.query_one("SELECT * FROM public.user_ui_preferences",&[]).await.unwrap()).unwrap().revision,None);
        for value in [0_i64,-1] {assert_eq!(c.execute("UPDATE public.user_ui_preferences SET revision=$1",&[&value]).await.unwrap_err().code(),Some(&SqlState::CHECK_VIOLATION));}
        c.execute("DELETE FROM public.users WHERE id='prefs-owner'",&[]).await.unwrap();
        assert_eq!(c.query_one("SELECT count(*) FROM public.user_ui_preferences",&[]).await.unwrap().get::<_,i64>(0),0);
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.unwrap();p.close();Ok(())
    }).await;
}
