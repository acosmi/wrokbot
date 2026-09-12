//! Native 0031 isolated PostgreSQL schema and historical binding lifecycle.
mod harness;
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{NATIVE_0031_TABLES, run_model_selections};
use openbot_infra::db::{baseline, fresh, native, pool, schema_facts};
use time::OffsetDateTime;
use uuid::Uuid;

fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0031.json")
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0031_preserves_all_old_facts_and_fresh_matches_upgrade() {
    let admin = harness::admin_config("native0031_schema");
    harness::with_temp_database(&admin,"model31schema",|config|async move {
        let pool = pool::connect(&config).await.map_err(|e|e.to_string())?;
        let mut c=pool.get().await.map_err(|e|e.to_string())?;
        baseline::apply(&c).await.map_err(|e|e.to_string())?;
        native::apply_through(&mut c,native::NATIVE_0030_VERSION).await.map_err(|e|e.to_string())?;
        let before=schema_facts::fetch(&c).await.map_err(|e|e.to_string())?;
        let prior:SchemaFacts=serde_json::from_str(include_str!("../../../fixtures/db/schema-0030.json")).unwrap();
        assert_eq!(before,prior);
        assert_eq!(native::apply_through(&mut c,native::NATIVE_0031_VERSION).await.unwrap(),native::ApplyOutcome::Applied);
        let after=schema_facts::fetch(&c).await.unwrap();
        assert_eq!(after.enums,before.enums);assert_eq!(after.extensions,before.extensions);assert_eq!(after.functions,before.functions);
        assert_eq!(after.tables.len(),before.tables.len()+1);
        for old in &before.tables { assert_eq!(after.table(&old.name),Some(old)); }
        assert_eq!(NATIVE_0031_TABLES.len(),1);
        let spec=&NATIVE_0031_TABLES[0];let table=after.table(spec.name).unwrap();
        assert_eq!(table.columns.len(),12);assert_eq!(table.indexes.len(),1);
        for (index,(actual,declared)) in table.columns.iter().zip(spec.column_specs).enumerate() {
            assert_eq!(actual.name,spec.columns[index]);assert_eq!(actual.name,declared.name);
            assert_eq!(actual.sql_type,declared.sql_type);assert_eq!(actual.notnull,declared.not_null);
            assert_eq!(actual.ordinal as usize,index+1);
        }
        let fks=c.query("SELECT confrelid::regclass::text,confdeltype::text FROM pg_constraint WHERE conrelid='public.run_model_selections'::regclass AND contype='f'",&[]).await.unwrap();
        assert_eq!(fks.len(),1);assert_eq!(fks[0].get::<_,String>(0),"runs");assert_eq!(fks[0].get::<_,String>(1),"c");
        if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0031").is_some() {
            std::fs::write(fixture(),format!("{}\n",serde_json::to_string_pretty(&after).unwrap())).unwrap();
        } else {let expected:SchemaFacts=serde_json::from_str(&std::fs::read_to_string(fixture()).unwrap()).unwrap();assert_eq!(after,expected);}
        let ledger:i64=c.query_one("SELECT count(*) FROM openbot_internal.schema_migrations",&[]).await.unwrap().get(0);assert_eq!(ledger,19);
        let checksum:String=c.query_one("SELECT checksum FROM openbot_internal.schema_migrations WHERE version=31",&[]).await.unwrap().get(0);assert_eq!(checksum,native::native_0031_checksum());
        assert_eq!(native::apply_through(&mut c,native::NATIVE_0031_VERSION).await.unwrap(),native::ApplyOutcome::AlreadyApplied);
        c.batch_execute("UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=31").await.unwrap();
        assert!(native::apply(&mut c).await.is_err());
        println!("native0031 old_tables={} old_columns={} old_constraints={} unchanged; new_columns=12; ledger=19",before.tables.len(),before.tables.iter().map(|t|t.columns.len()).sum::<usize>(),before.tables.iter().map(|t|t.constraints.len()).sum::<usize>());
        drop(c);pool.close();Ok(())
    }).await;
    harness::with_temp_database(&admin, "model31fresh", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut c = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
        let expected: SchemaFacts =
            serde_json::from_str(&std::fs::read_to_string(fixture()).unwrap()).unwrap();
        assert_eq!(schema_facts::fetch(&c).await.unwrap(), expected);
        drop(c);
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0031_typed_roundtrip_checks_and_only_run_deletion_cascades() {
    let admin = harness::admin_config("native0031_rows");
    harness::with_temp_database(&admin,"model31rows",|config|async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let mut c=pool.get().await.map_err(|e|e.to_string())?;
        fresh::apply(&mut c).await.map_err(|e|e.to_string())?;
        c.batch_execute("INSERT INTO public.users(id,email) VALUES('owner','owner@example.test');
          INSERT INTO public.user_roles(user_id,role) VALUES('owner','user');
          INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,created_at,updated_at) VALUES('thread','tenant','dep','owner','direct_bot','bot','active',now(),now());
          INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,created_at,started_at) VALUES('run','thread','bot','owner',true,'running',1,now(),now());").await.unwrap();
        let row=run_model_selections::Row {run_id:"run".into(),deployment_id:"dep".into(),tenant_id:"tenant".into(),owner_user_id:"owner".into(),auth_generation:7,connection_id:Uuid::from_u128(1),connection_revision:9,secret_id:Uuid::from_u128(2),protocol:"anthropic_messages".into(),endpoint:"https://example.test/v1/messages".into(),model:"model-中文".into(),created_at:OffsetDateTime::UNIX_EPOCH};
        c.execute("INSERT INTO public.run_model_selections VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&row.as_sql_params()).await.unwrap();
        let stored=c.query_one("SELECT * FROM public.run_model_selections WHERE run_id='run'",&[]).await.unwrap();
        let typed=run_model_selections::Row::try_from(&stored).unwrap();assert_eq!(typed,row);
        let checksum:bool=c.query_one("SELECT md5(row(s.*)::text)=md5(ROW($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)::public.run_model_selections::text) FROM public.run_model_selections s WHERE run_id='run'",&typed.as_sql_params()).await.unwrap().get(0);assert!(checksum);
        for mutation in ["auth_generation=-1","connection_revision=0","protocol='gateway'","deployment_id=''","tenant_id=''","owner_user_id=''","endpoint=''","endpoint=repeat('x',2049)","model=''","model=repeat('x',513)"] {
            let error=c.batch_execute(&format!("UPDATE public.run_model_selections SET {mutation} WHERE run_id='run'")).await.unwrap_err();
            assert_eq!(error.code(),Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
        }
        c.batch_execute("DELETE FROM public.user_roles WHERE user_id='owner';DELETE FROM public.users WHERE id='owner';").await.unwrap();
        let retained=c.query_one("SELECT * FROM public.run_model_selections WHERE run_id='run'",&[]).await.unwrap();assert_eq!(run_model_selections::Row::try_from(&retained).unwrap(),row);
        c.batch_execute("DELETE FROM public.runs WHERE run_id='run'").await.unwrap();
        let count:i64=c.query_one("SELECT count(*) FROM public.run_model_selections",&[]).await.unwrap().get(0);assert_eq!(count,0);
        drop(c);pool.close();Ok(())
    }).await;
}
