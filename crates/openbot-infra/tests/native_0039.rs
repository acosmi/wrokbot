//! Actual schema39 fresh/upgrade facts and identity-retirement trigger behavior.
mod harness;
use openbot_infra::db::{
    baseline, desktop_vault_canary, fresh, native, pool, schema_facts, tables,
};
use tokio_postgres::error::SqlState;

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn schema39_matches_owned_oracle_and_retains_the_upstream_skill_registry() {
    harness::with_temp_database(&harness::admin_config("skill39fresh"), "skill39fresh", |config| async move {
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        let actual=schema_facts::fetch(&c).await.unwrap();
        let expected: schema_facts::SchemaFacts=serde_json::from_str(include_str!("../../../fixtures/db/schema-0039.json")).unwrap();
        let prior: schema_facts::SchemaFacts=serde_json::from_str(include_str!("../../../fixtures/db/schema-0038.json")).unwrap();
        assert_eq!(actual,expected);assert_eq!(actual.tables.len(),prior.tables.len()+1);
        for table in &prior.tables {
            let now=actual.table(&table.name).unwrap();
            if table.name!="skills" {assert_eq!(now,table);} else {
                assert_eq!(now.columns.len(),table.columns.len()+1);
                for column in &table.columns {assert!(now.columns.contains(column));}
                for constraint in &table.constraints {assert!(now.constraints.contains(constraint));}
                for index in &table.indexes {assert!(now.indexes.contains(index));}
                let added=now.columns.iter().find(|c|c.name=="revision").unwrap();assert!(!added.notnull);
            }
        }
        assert_eq!(actual.enums,prior.enums);assert_eq!(actual.extensions,prior.extensions);
        assert_eq!(tables::skills::COLUMNS.len(),10);assert_eq!(tables::editing_skills::COLUMNS.len(),11);
        assert_eq!(tables::current_table_specs().filter(|t|t.name=="skills").count(),1);
        assert_eq!(native::apply(&mut c).await.unwrap(),native::ApplyOutcome::AlreadyApplied);
        let row=c.query_one("SELECT t.tgenabled::text,p.proname,n.nspname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace WHERE t.tgrelid='public.skills'::regclass AND t.tgname='skills_retire_deleted_slug' AND NOT t.tgisinternal",&[]).await.unwrap();
        assert_eq!(row.get::<_,String>(0),"O");assert_eq!(row.get::<_,String>(1),"retire_deleted_skill");assert_eq!(row.get::<_,String>(2),"openbot_internal");
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.unwrap();p.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn upgrade_preserves_source_and_nullable_legacy_with_atomic_retirement_overflow() {
    harness::with_temp_database(&harness::admin_config("skill39upgrade"), "skill39upgrade", |config| async move {
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        baseline::apply(&c).await.unwrap();native::apply_through(&mut c,38).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,name,email,created_at,updated_at) VALUES('skill-owner','Owner','skill-owner@example.test','2020-01-01','2020-01-01'); INSERT INTO public.skills(id,slug,owner_user_id,title,summary,instructions,origin,installed_by,created_at,updated_at) VALUES('legacy-skill','legacy-skill','skill-owner','Original','Summary','Original instructions','yours','skill-owner','2020-01-01','2020-01-01')").await.unwrap();
        drop(c);assert_eq!(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.unwrap().native_version(),38);
        let mut c=p.get().await.unwrap();native::apply(&mut c).await.unwrap();
        let row=c.query_one("SELECT * FROM public.skills WHERE slug='legacy-skill'",&[]).await.unwrap();
        let typed=tables::editing_skills::Row::try_from(&row).unwrap();assert_eq!(typed.revision,Some(1));assert_eq!(typed.title,"Original");assert_eq!(typed.instructions,"Original instructions");assert_eq!(typed.updated_at.year(),2020);assert_eq!(typed.owner_user_id.as_deref(),Some("skill-owner"));
        c.execute("UPDATE public.skills SET revision=NULL WHERE slug='legacy-skill'",&[]).await.unwrap();
        for value in [0_i64,-1] {assert_eq!(c.execute("UPDATE public.skills SET revision=$1 WHERE slug='legacy-skill'",&[&value]).await.unwrap_err().code(),Some(&SqlState::CHECK_VIOLATION));}
        let typed=tables::editing_skills::Row::try_from(&c.query_one("SELECT * FROM public.skills",&[]).await.unwrap()).unwrap();assert_eq!(typed.revision,None);
        c.execute("UPDATE public.skills SET revision=$1 WHERE slug='legacy-skill'",&[&i64::MAX]).await.unwrap();
        assert_eq!(c.execute("DELETE FROM public.users WHERE id='skill-owner'",&[]).await.unwrap_err().code(),Some(&SqlState::NUMERIC_VALUE_OUT_OF_RANGE));
        assert_eq!(c.query_one("SELECT (SELECT count(*) FROM public.users WHERE id='skill-owner'),(SELECT count(*) FROM public.skills),(SELECT count(*) FROM public.skill_retired_slugs)",&[]).await.unwrap().get::<_,i64>(0),1);
        assert_eq!(c.query_one("SELECT count(*) FROM public.skills",&[]).await.unwrap().get::<_,i64>(0),1);
        assert_eq!(c.query_one("SELECT count(*) FROM public.skill_retired_slugs",&[]).await.unwrap().get::<_,i64>(0),0);
        c.execute("UPDATE public.skills SET revision=NULL WHERE slug='legacy-skill'",&[]).await.unwrap();
        c.execute("DELETE FROM public.users WHERE id='skill-owner'",&[]).await.unwrap();
        let retired=tables::skill_retired_slugs::Row::try_from(&c.query_one("SELECT * FROM public.skill_retired_slugs",&[]).await.unwrap()).unwrap();assert_eq!(retired.slug,"legacy-skill");assert_eq!(retired.retired_revision,2);
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.unwrap();p.close();Ok(())
    }).await;
}
