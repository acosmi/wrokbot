//! R415 exact production writes on owned PostgreSQL; no equivalent-SQL writer substitute.
mod harness;

use deadpool_postgres::Pool;
use openbot_application::{
    SandboxedComponentAdministration, SandboxedComponentAdministrationError as Error,
    SandboxedComponentDraft,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
    revision::RevisionSnapshot,
};
use openbot_infra::{
    db::{fresh, pool},
    sandboxed_components::PostgresSandboxedComponentAdministration,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn auth(generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("admin"),
        AuthGeneration::new(generation),
        false,
    )
    .with_roles([Role::Admin])
    .build()
}

fn draft(name: &str, expected_revision: Option<i64>, title: &str) -> SandboxedComponentDraft {
    SandboxedComponentDraft {
        expected_revision,
        name: name.to_owned(),
        title: title.to_owned(),
        description: "synthetic description".to_owned(),
        html: format!("<p>{title}</p>"),
        css: String::new(),
        js_functions: String::new(),
        argument_schema: BTreeMap::from([("type".to_owned(), serde_json::json!("object"))]),
        sample_arguments: BTreeMap::new(),
    }
}
async fn setup(p: &Pool) -> PostgresSandboxedComponentAdministration {
    let mut c = p.get().await.unwrap();
    fresh::apply(&mut c).await.unwrap();
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('admin','admin@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('admin','admin')").await.unwrap();
    PostgresSandboxedComponentAdministration::new(
        p.clone(),
        b"synthetic-sandbox-audit-key".to_vec(),
    )
    .unwrap()
}
async fn durable(p: &Pool) -> Value {
    let c = p.get().await.unwrap();
    c.query_one("SELECT jsonb_build_object(
       'source',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY name),'[]') FROM public.sandboxed_components s),
       'governance',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY name),'[]') FROM public.components c),
       'retired',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY name),'[]') FROM public.sandboxed_component_retired_names r),
       'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a))",&[]).await.unwrap().get(0)
}
async fn pool_pids(p: &Pool) -> Vec<i32> {
    let first = p.get().await.unwrap();
    let second = p.get().await.unwrap();
    let mut pids = Vec::new();
    for c in [&first, &second] {
        c.batch_execute("SET default_transaction_isolation='repeatable read'")
            .await
            .unwrap();
        assert_eq!(
            c.query_one("SHOW default_transaction_isolation", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            "repeatable read"
        );
        pids.push(
            c.query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0),
        );
    }
    pids
}
async fn wait_blocked<C: tokio_postgres::GenericClient + Sync>(c: &C, pids: &[i32]) {
    tokio::time::timeout(Duration::from_secs(4),async {
        loop { c.batch_execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
            let waiting:i64=c.query_one("SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0",&[&pids]).await.unwrap().get(0);
            if waiting==pids.len() as i64 { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("actual production writers must reach the owned lock barrier");
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn stale_save_publish_delete_and_create_are_exact_closed_snapshots_without_mutation() {
    harness::with_temp_database(&harness::admin_config("sandboxcasfacts"),"sandboxcasfacts",|config|async move {
        let p=pool::connect(&config).await.unwrap();let port=setup(&p).await;
        let created=port.save_sandboxed_component(&auth(0),&draft("custom_cas",None,"first")).await.unwrap();
        assert_eq!((created.editing_revision,created.revision),(1,0));
        let published=port.publish_sandboxed_component(&auth(0),&created.name,1).await.unwrap();
        assert_eq!((published.editing_revision,published.revision),(2,1));
        let saved=port.save_sandboxed_component(&auth(0),&draft(&created.name,Some(2),"second")).await.unwrap();
        assert_eq!((saved.editing_revision,saved.revision),(3,1));assert_eq!(saved.published_html,created.published_html.or(Some(created.draft_html)));
        let expected=Error::StaleSnapshot(RevisionSnapshot::from_public(3,saved.updated_at,&saved).unwrap());
        let before=durable(&p).await;
        for version in [Some(1),None] {
            assert_eq!(port.save_sandboxed_component(&auth(0),&draft(&saved.name,version,"overwrite")).await.unwrap_err(),expected);
        }
        assert_eq!(port.publish_sandboxed_component(&auth(0),&saved.name,1).await.unwrap_err(),expected);
        assert_eq!(port.delete_sandboxed_component(&auth(0),&saved.name,1).await.unwrap_err(),expected);
        assert_eq!(port.save_sandboxed_component(&auth(0),&draft("custom_missing",Some(1),"missing")).await.unwrap_err(),Error::NotVisible);
        assert_eq!(durable(&p).await,before);
        let wire=serde_json::to_value(match expected {Error::StaleSnapshot(s)=>s,_=>unreachable!()}).unwrap();
        assert_eq!(wire.as_object().unwrap().len(),3);assert_eq!(wire["currentRevision"],3);assert_eq!(wire["currentSha256"].as_str().unwrap().len(),64);
        assert!(time::OffsetDateTime::parse(wire["updatedAt"].as_str().unwrap(),&time::format_description::well_known::Rfc3339).is_ok());
        let c=p.get().await.unwrap();let revisions:Vec<i64>=c.query("SELECT (payload->>'component_editing_revision')::bigint FROM public.audit_events WHERE target_id='custom_cas' ORDER BY (payload->>'component_editing_revision')::bigint",&[]).await.unwrap().iter().map(|r|r.get(0)).collect();assert_eq!(revisions,[1,2,3]);drop(c);p.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn two_waiting_old_version_writers_under_rr_defaults_have_one_success_and_one_current_snapshot()
 {
    harness::with_temp_database(
        &harness::admin_config("sandboxcasrace"),
        "sandboxcasrace",
        |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let port = Arc::new(setup(&p).await);
            port.save_sandboxed_component(&auth(0), &draft("custom_race", None, "initial"))
                .await
                .unwrap();
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config
                .to_pg_config()
                .connect(tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one(
                "SELECT name FROM public.components WHERE name='custom_race' FOR UPDATE",
                &[],
            )
            .await
            .unwrap();
            let left = port.clone();
            let first = tokio::spawn(async move {
                left.save_sandboxed_component(&auth(0), &draft("custom_race", Some(1), "left"))
                    .await
            });
            let right = port.clone();
            let second = tokio::spawn(async move {
                right
                    .save_sandboxed_component(&auth(0), &draft("custom_race", Some(1), "right"))
                    .await
            });
            wait_blocked(&tx, &pids).await;
            tx.commit().await.unwrap();
            let a = first.await.unwrap();
            let b = second.await.unwrap();
            let (won, lost) = match (a, b) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (a, b),
                other => panic!("expected one CAS winner: {other:?}"),
            };
            assert_eq!((won.editing_revision, won.revision), (2, 0));
            assert_eq!(
                lost,
                Error::StaleSnapshot(
                    RevisionSnapshot::from_public(2, won.updated_at, &won).unwrap()
                )
            );
            assert_eq!(
                port.list_sandboxed_components(&auth(0))
                    .await
                    .unwrap()
                    .components,
                [won]
            );
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT count(*) FROM public.audit_events WHERE target_id='custom_race'",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                2
            );
            drop(c);
            drop(barrier);
            task.await.unwrap().unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn two_waiting_new_name_creators_commit_one_initial_version_without_overwrite() {
    harness::with_temp_database(
        &harness::admin_config("sandboxcreate"),
        "sandboxcreate",
        |config| async move {
            let config = config.with_max_pool_size(2);
            let p = pool::connect(&config).await.unwrap();
            let port = Arc::new(setup(&p).await);
            let pids = pool_pids(&p).await;
            let (mut barrier, connection) = config
                .to_pg_config()
                .connect(tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(connection);
            let tx = barrier.transaction().await.unwrap();
            tx.query_one(
                "SELECT id FROM public.users WHERE id='admin' FOR UPDATE",
                &[],
            )
            .await
            .unwrap();
            let left = port.clone();
            let first = tokio::spawn(async move {
                left.save_sandboxed_component(&auth(0), &draft("custom_new", None, "left"))
                    .await
            });
            let right = port.clone();
            let second = tokio::spawn(async move {
                right
                    .save_sandboxed_component(&auth(0), &draft("custom_new", None, "right"))
                    .await
            });
            wait_blocked(&tx, &pids).await;
            tx.commit().await.unwrap();
            let (won, lost) = match (first.await.unwrap(), second.await.unwrap()) {
                (Ok(a), Err(b)) | (Err(b), Ok(a)) => (a, b),
                other => panic!("expected one new-name winner: {other:?}"),
            };
            assert_eq!((won.editing_revision, won.revision), (1, 0));
            assert_eq!(
                lost,
                Error::StaleSnapshot(
                    RevisionSnapshot::from_public(1, won.updated_at, &won).unwrap()
                )
            );
            assert_eq!(
                port.list_sandboxed_components(&auth(0))
                    .await
                    .unwrap()
                    .components,
                [won]
            );
            let c = p.get().await.unwrap();
            assert_eq!(
                c.query_one(
                    "SELECT count(*) FROM public.audit_events WHERE target_id='custom_new'",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                1
            );
            drop(c);
            drop(barrier);
            task.await.unwrap().unwrap();
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn denied_current_admin_precedes_stale_metadata_and_audit_failure_rolls_back_retirement() {
    harness::with_temp_database(&harness::admin_config("sandboxauthority"),"sandboxauthority",|config|async move {
        let p=pool::connect(&config).await.unwrap();let port=setup(&p).await;
        let saved=port.save_sandboxed_component(&auth(0),&draft("custom_authority",None,"initial")).await.unwrap();
        let c=p.get().await.unwrap();c.batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='admin'").await.unwrap();drop(c);
        let before=durable(&p).await;
        assert_eq!(port.save_sandboxed_component(&auth(0),&draft(&saved.name,Some(9),"old")).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.publish_sandboxed_component(&auth(0),&saved.name,9).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.delete_sandboxed_component(&auth(0),&saved.name,9).await.unwrap_err(),Error::NotVisible);
        let c=p.get().await.unwrap();c.batch_execute("DELETE FROM public.user_roles WHERE user_id='admin'").await.unwrap();drop(c);
        assert_eq!(port.save_sandboxed_component(&auth(1),&draft(&saved.name,Some(9),"old")).await.unwrap_err(),Error::NotVisible);
        let c=p.get().await.unwrap();c.batch_execute("INSERT INTO public.user_roles(user_id,role) VALUES('admin','admin'); INSERT INTO public.revoked_access(email,revoked_by) VALUES('admin@example.test','admin')").await.unwrap();drop(c);
        assert_eq!(port.publish_sandboxed_component(&auth(1),&saved.name,9).await.unwrap_err(),Error::NotVisible);
        assert_eq!(durable(&p).await,before);
        let c=p.get().await.unwrap();c.batch_execute("DELETE FROM public.revoked_access; CREATE FUNCTION sandbox_cas_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.target_type='component' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER sandbox_cas_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION sandbox_cas_audit_fault()").await.unwrap();drop(c);
        for result in [port.save_sandboxed_component(&auth(1),&draft(&saved.name,Some(1),"failed")).await.map(|_|()),port.publish_sandboxed_component(&auth(1),&saved.name,1).await.map(|_|()),port.delete_sandboxed_component(&auth(1),&saved.name,1).await] {assert_eq!(result.unwrap_err(),Error::Unavailable);assert_eq!(durable(&p).await,before);}
        p.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn retired_name_refuses_aba_old_save_publish_delete_and_keeps_fresh_other_identity_at_one() {
    harness::with_temp_database(
        &harness::admin_config("sandboxaba"),
        "sandboxaba",
        |config| async move {
            let p = pool::connect(&config).await.unwrap();
            let port = setup(&p).await;
            let old = port
                .save_sandboxed_component(&auth(0), &draft("custom_retired", None, "old"))
                .await
                .unwrap();
            port.delete_sandboxed_component(&auth(0), &old.name, old.editing_revision)
                .await
                .unwrap();
            let before = durable(&p).await;
            assert_eq!(
                port.save_sandboxed_component(&auth(0), &draft(&old.name, None, "new"))
                    .await
                    .unwrap_err(),
                Error::Conflict
            );
            assert_eq!(
                port.save_sandboxed_component(&auth(0), &draft(&old.name, Some(1), "stale"))
                    .await
                    .unwrap_err(),
                Error::Conflict
            );
            assert_eq!(
                port.publish_sandboxed_component(&auth(0), &old.name, 1)
                    .await
                    .unwrap_err(),
                Error::NotVisible
            );
            assert_eq!(
                port.delete_sandboxed_component(&auth(0), &old.name, 1)
                    .await
                    .unwrap_err(),
                Error::NotVisible
            );
            assert_eq!(durable(&p).await, before);
            assert_eq!(before["source"].as_array().unwrap().len(), 0);
            assert_eq!(before["retired"][0]["retired_editing_revision"], 2);
            let other = port
                .save_sandboxed_component(&auth(0), &draft("custom_distinct", None, "new"))
                .await
                .unwrap();
            assert_eq!((other.editing_revision, other.revision), (1, 0));
            p.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn production_null_compatibility_consumes_initial_one_and_preserves_published_revision() {
    harness::with_temp_database(&harness::admin_config("sandboxnull"),"sandboxnull",|config|async move {
        let p=pool::connect(&config).await.unwrap();let port=setup(&p).await;
        port.save_sandboxed_component(&auth(0),&draft("custom_nullable",None,"first")).await.unwrap();
        let c=p.get().await.unwrap();c.execute("UPDATE public.sandboxed_components SET editing_revision=NULL WHERE name='custom_nullable'",&[]).await.unwrap();drop(c);
        let before=port.list_sandboxed_components(&auth(0)).await.unwrap().components.remove(0);assert_eq!((before.editing_revision,before.revision),(1,0));
        let after=port.save_sandboxed_component(&auth(0),&draft(&before.name,Some(1),"next")).await.unwrap();assert_eq!((after.editing_revision,after.revision),(2,0));
        assert_eq!(port.publish_sandboxed_component(&auth(0),&after.name,1).await.unwrap_err(),Error::StaleSnapshot(RevisionSnapshot::from_public(2,after.updated_at,&after).unwrap()));
        let c=p.get().await.unwrap();assert_eq!(c.query_one("SELECT editing_revision FROM public.sandboxed_components WHERE name='custom_nullable'",&[]).await.unwrap().get::<_,Option<i64>>(0),Some(2));drop(c);p.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn same_name_creation_and_deletion_wait_chain_preserves_retirement_in_both_orders() {
    harness::with_temp_database(&harness::admin_config("sandboxdeletecreate"),"sandboxdeletecreate",|config|async move {
        let config=config.with_max_pool_size(2);let p=pool::connect(&config).await.unwrap();let port=Arc::new(setup(&p).await);
        for delete_first in [false,true] {
            let name=if delete_first {"custom_delete_first"} else {"custom_create_first"};
            let original=port.save_sandboxed_component(&auth(0),&draft(name,None,"original")).await.unwrap();let pids=pool_pids(&p).await;
            let (mut barrier,connection)=config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();let connection_task=tokio::spawn(connection);
            let tx=barrier.transaction().await.unwrap();tx.query_one("SELECT name FROM public.components WHERE name=$1 FOR UPDATE",&[&name]).await.unwrap();
            let first_port=port.clone();let first=tokio::spawn(async move {
                if delete_first { first_port.delete_sandboxed_component(&auth(0),name,1).await.map(|()|None) }
                else { first_port.save_sandboxed_component(&auth(0),&draft(name,None,"duplicate")).await.map(Some) }
            });
            let first_pid=tokio::time::timeout(Duration::from_secs(4),async {
                loop {tx.batch_execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
                    if let Some(row)=tx.query_opt("SELECT pid FROM pg_stat_activity WHERE pid=ANY($1) AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0",&[&pids]).await.unwrap() {break row.get::<_,i32>(0);}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("first production request must reach the third connection barrier");
            let second_port=port.clone();let second=tokio::spawn(async move {
                if delete_first { second_port.save_sandboxed_component(&auth(0),&draft(name,None,"duplicate")).await.map(Some) }
                else { second_port.delete_sandboxed_component(&auth(0),name,1).await.map(|()|None) }
            });
            wait_blocked(&tx,&pids).await;
            assert!(pids.contains(&first_pid));tx.commit().await.unwrap();
            let a=first.await.unwrap();let b=second.await.unwrap();
            if delete_first {assert_eq!(a.unwrap(),None);assert_eq!(b.unwrap_err(),Error::Conflict);}
            else {assert_eq!(a.unwrap_err(),Error::StaleSnapshot(RevisionSnapshot::from_public(1,original.updated_at,&original).unwrap()));assert_eq!(b.unwrap(),None);}
            let c=p.get().await.unwrap();assert_eq!(c.query_one("SELECT count(*) FROM public.components WHERE name=$1",&[&name]).await.unwrap().get::<_,i64>(0),0);
            assert_eq!(c.query_one("SELECT count(*) FROM public.sandboxed_components WHERE name=$1",&[&name]).await.unwrap().get::<_,i64>(0),0);
            assert_eq!(c.query_one("SELECT retired_editing_revision FROM public.sandboxed_component_retired_names WHERE name=$1",&[&name]).await.unwrap().get::<_,i64>(0),2);
            assert_eq!(c.query_one("SELECT count(*) FROM public.audit_events WHERE target_id=$1",&[&name]).await.unwrap().get::<_,i64>(0),2);drop(c);
            let before=durable(&p).await;assert_eq!(port.save_sandboxed_component(&auth(0),&draft(name,None,"recreate")).await.unwrap_err(),Error::Conflict);assert_eq!(durable(&p).await,before);
            drop(barrier);connection_task.await.unwrap().unwrap();
        }
        p.close();Ok(())
    }).await;
}
