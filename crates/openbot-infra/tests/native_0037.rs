//! R417's registered physical schema and closed nullable snapshot boundary.
mod harness;
use openbot_infra::db::{desktop_vault_canary, fresh, native, pool, schema_facts};
use tokio_postgres::error::SqlState;

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn latest_fresh_schema_matches_actual_pg_oracle_and_preserves_every_prior_table() {
    harness::with_temp_database(&harness::admin_config("provenance37schema"),"provenance37schema",|config| async move {
        let p=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let mut c=p.get().await.unwrap();
        c.batch_execute("SET default_transaction_isolation='repeatable read'").await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        let actual=schema_facts::fetch(&c).await.unwrap();
        let expected=serde_json::from_str(include_str!("../../../fixtures/db/schema-0037.json")).unwrap();
        assert_eq!(actual,expected);
        let previous: schema_facts::SchemaFacts=serde_json::from_str(include_str!("../../../fixtures/db/schema-0036.json")).unwrap();
        assert_eq!(actual.tables.len(),previous.tables.len());
        for table in &previous.tables {
            if table.name!="memories" {assert_eq!(actual.table(&table.name),Some(table));}
            else {let current=actual.table("memories").unwrap();
                assert_eq!(current.columns.len(),table.columns.len()+2);
                for column in &table.columns {assert!(current.columns.contains(column));}
                for index in &table.indexes {assert!(current.indexes.contains(index));}
                for constraint in &table.constraints {assert!(current.constraints.contains(constraint));}
            }
        }
        assert_eq!(actual.enums,previous.enums);assert_eq!(actual.extensions,previous.extensions);
        let trigger=c.query_one("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='public.memories'::regclass AND tgname='memory_provenance_immutable'",&[]).await.unwrap().get::<_,String>(0);
        assert!(trigger.contains("BEFORE UPDATE"));assert!(trigger.contains("guard_memory_provenance"));
        assert_eq!(native::apply(&mut c).await.unwrap(),native::ApplyOutcome::AlreadyApplied);
        drop(c);desktop_vault_canary::verify_current_layout(&p).await.unwrap();p.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn database_rejects_open_or_mismatched_snapshots_without_backfilling_null() {
    harness::with_temp_database(&harness::admin_config("provenance37shape"),"provenance37shape",|config| async move {
        let p=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let mut c=p.get().await.unwrap();fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email) VALUES ('actor','actor@example.test');
            INSERT INTO public.user_roles(user_id,role) VALUES ('actor','user')").await.unwrap();
        let valid=serde_json::json!({"actorId":"actor","tenantId":"tenant","deploymentId":"deployment","authGeneration":0,"roles":["user"],"scope":{"kind":"user"},"capturedAt":"2020-01-01T00:00:00Z"});
        let mut invalid=vec![serde_json::json!({}),serde_json::json!([])];
        for (key,value) in [("actorId",serde_json::json!("other")),("tenantId",serde_json::json!("other-tenant")),("deploymentId",serde_json::json!("")),("authGeneration",serde_json::json!(-1)),
            ("authGeneration",serde_json::json!(9223372036854775808_u64)),("roles",serde_json::json!(["user","user"])),
            ("scope",serde_json::json!({"kind":"bot","bot_id":"bot"})),("capturedAt",serde_json::json!("tomorrow")),
            ("capturedAt",serde_json::json!("2999-01-01T00:00:00Z")),("capturedAt",serde_json::json!("2020-01-01")),
            ("extra",serde_json::json!(true)),("roles",serde_json::Value::Null)] {
            let mut snapshot=valid.clone();snapshot[key]=value;invalid.push(snapshot);
        }
        let insert="INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,memory_kind,content,sensitivity,origin,created_by,source_authorization_snapshot) VALUES($1,'tenant','actor','user','preference','synthetic','normal','user_action','actor',$2)";
        for (i,snapshot) in invalid.iter().enumerate() {
            let error=c.execute(insert,&[&format!("invalid-{i}"),snapshot]).await.unwrap_err();
            assert_eq!(error.code(),Some(&SqlState::CHECK_VIOLATION));
        }
        c.execute(insert,&[&"valid",&valid]).await.unwrap();
        c.execute(insert,&[&"unknown",&Option::<serde_json::Value>::None]).await.unwrap();
        assert_eq!(c.execute("UPDATE public.memories SET source_authorization_snapshot=$1 WHERE memory_id='unknown'",&[&valid]).await.unwrap_err().code(),Some(&SqlState::CHECK_VIOLATION));
        assert_eq!(c.query_one("SELECT count(*) FROM public.memories",&[]).await.unwrap().get::<_,i64>(0),2);
        drop(c);p.close();Ok(())
    }).await;
}
