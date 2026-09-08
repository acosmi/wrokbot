//! PostgreSQL 17 evidence for atomic sandboxed draft/publish/delete governance.

mod harness;

use std::collections::BTreeMap;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    SandboxedComponentAdministration, SandboxedComponentAdministrationError,
    SandboxedComponentDraft,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::sandboxed_components::PostgresSandboxedComponentAdministration;
use serde_json::json;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn sandboxed_lifecycle_is_atomic_published_only_audited_and_namespace_safe() {
    let admin =
        admin_config("sandboxed_lifecycle_is_atomic_published_only_audited_and_namespace_safe");
    with_temp_database(&admin, "sandboxedcomponents", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('sandbox-admin','sandbox-admin@example.test',0);
                     INSERT INTO public.components(
                       name,title,kind,draft_description,published_description,published,
                       published_at,updated_by,created_at,updated_at
                     ) VALUES
                       ('showQuote','Quotation','card','compiled','compiled',true,
                        clock_timestamp(),'the build',clock_timestamp(),clock_timestamp()),
                       ('custom_collision','Compiled collision','card','compiled','compiled',true,
                        clock_timestamp(),'the build',clock_timestamp(),clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("sandbox-deployment"),
                TenantId::new("sandbox-tenant"),
                ActorId::new("sandbox-admin"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::Admin])
            .build();
            let adapter = PostgresSandboxedComponentAdministration::new(
                pool.clone(),
                b"sandboxed-component-audit-key".to_vec(),
            )
            .map_err(|error| error.to_string())?;

            let initial = draft("custom_delivery_eta", "v1", "<p>ETA v1</p>");
            let saved = adapter
                .save_sandboxed_component(&auth, &initial)
                .await
                .map_err(|error| error.to_string())?;
            if saved.name != initial.name
                || saved.revision != 0
                || saved.published
                || saved.authored_by.as_deref() != Some("sandbox-admin")
                || saved.sample_arguments.get("version") != Some(&json!("v1"))
            {
                return Err(format!("initial draft projection drift: {saved:?}"));
            }
            let listed = adapter
                .list_sandboxed_components(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if listed.components != [saved.clone()] {
                return Err(format!("admin list drift: {listed:?}"));
            }
            if !adapter
                .list_published_sandboxed_components(&auth)
                .await
                .map_err(|error| error.to_string())?
                .components
                .is_empty()
            {
                return Err("unpublished draft crossed published projection".to_owned());
            }

            let published_v1 = adapter
                .publish_sandboxed_component(&auth, &initial.name)
                .await
                .map_err(|error| error.to_string())?;
            if published_v1.revision != 1
                || !published_v1.published
                || published_v1.has_unpublished_changes
                || published_v1.published_html.as_deref() != Some(initial.html.as_str())
                || published_v1.published_argument_schema != Some(initial.argument_schema.clone())
            {
                return Err(format!("first publication drift: {published_v1:?}"));
            }
            assert_published_only(&adapter, &auth, &initial, 1).await?;

            let mut metadata_only = initial.clone();
            metadata_only.description = "description v2".to_owned();
            metadata_only.argument_schema.insert("revision".to_owned(), json!(2));
            metadata_only.sample_arguments.insert("version".to_owned(), json!("v2"));
            let metadata_saved = adapter
                .save_sandboxed_component(&auth, &metadata_only)
                .await
                .map_err(|error| error.to_string())?;
            if metadata_saved.revision != 1 || metadata_saved.has_unpublished_changes {
                return Err(format!(
                    "fixed-upstream three-source comparison drift: {metadata_saved:?}"
                ));
            }
            let still_v1 = adapter
                .list_published_sandboxed_components(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if still_v1.components[0].argument_schema != initial.argument_schema {
                return Err("draft argument schema leaked before publication".to_owned());
            }

            let mut source_v2 = metadata_only.clone();
            source_v2.html = "<p>ETA v2</p>".to_owned();
            let source_saved = adapter
                .save_sandboxed_component(&auth, &source_v2)
                .await
                .map_err(|error| error.to_string())?;
            if !source_saved.has_unpublished_changes {
                return Err("changed draft HTML was not reported".to_owned());
            }
            let still_old_source = adapter
                .list_published_sandboxed_components(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if still_old_source.components[0].html != initial.html {
                return Err("draft HTML leaked before second publication".to_owned());
            }
            let published_v2 = adapter
                .publish_sandboxed_component(&auth, &source_v2.name)
                .await
                .map_err(|error| error.to_string())?;
            if published_v2.revision != 2
                || published_v2.has_unpublished_changes
                || published_v2.published_html.as_deref() != Some(source_v2.html.as_str())
            {
                return Err(format!("second publication drift: {published_v2:?}"));
            }
            assert_published_only(&adapter, &auth, &source_v2, 2).await?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.components SET published=false
                      WHERE name='custom_delivery_eta'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if !matches!(
                adapter.list_published_sandboxed_components(&auth).await,
                Err(SandboxedComponentAdministrationError::Corrupt {
                    field: "component_governance"
                })
            ) {
                return Err("published governance mismatch did not fail closed".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "UPDATE public.components SET published=true
                       WHERE name='custom_delivery_eta';
                     UPDATE public.sandboxed_components SET published_css=NULL
                       WHERE name='custom_delivery_eta';",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if !matches!(
                adapter.list_published_sandboxed_components(&auth).await,
                Err(SandboxedComponentAdministrationError::Corrupt {
                    field: "published_css"
                })
            ) {
                return Err("partial published source did not fail closed".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.sandboxed_components SET published_css=$2 WHERE name=$1",
                    &[&source_v2.name, &source_v2.css],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let collision = draft("custom_collision", "collision", "<p>collision</p>");
            if !matches!(
                adapter.save_sandboxed_component(&auth, &collision).await,
                Err(SandboxedComponentAdministrationError::Conflict)
            ) {
                return Err("compiled governance collision was not refused".to_owned());
            }
            if !matches!(
                adapter.delete_sandboxed_component(&auth, "showQuote").await,
                Err(SandboxedComponentAdministrationError::NotVisible)
            ) {
                return Err("compiled component delete was not refused".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION public.reject_sandboxed_component_audit() RETURNS trigger
                       LANGUAGE plpgsql AS $$ BEGIN
                         IF NEW.event_type IN (
                           'component.draft_saved','component.published','component.unpublished'
                         ) THEN
                           RAISE EXCEPTION 'forced sandboxed component audit failure';
                         END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER reject_sandboxed_component_audit
                       BEFORE INSERT ON public.audit_events FOR EACH ROW
                       EXECUTE FUNCTION public.reject_sandboxed_component_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let rollback = draft("custom_rollback", "rollback", "<p>rollback</p>");
            if !matches!(
                adapter.save_sandboxed_component(&auth, &rollback).await,
                Err(SandboxedComponentAdministrationError::Unavailable)
            ) {
                return Err("forced audit failure did not fail draft save".to_owned());
            }
            if !matches!(
                adapter
                    .publish_sandboxed_component(&auth, &source_v2.name)
                    .await,
                Err(SandboxedComponentAdministrationError::Unavailable)
            ) {
                return Err("forced audit failure did not fail publication".to_owned());
            }
            if !matches!(
                adapter
                    .delete_sandboxed_component(&auth, &source_v2.name)
                    .await,
                Err(SandboxedComponentAdministrationError::Unavailable)
            ) {
                return Err("forced audit failure did not fail delete".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rollback_rows: i64 = client
                .query_one(
                    "SELECT
                       (SELECT count(*) FROM public.sandboxed_components
                         WHERE name='custom_rollback')
                       + (SELECT count(*) FROM public.components
                           WHERE name='custom_rollback') AS rows",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get("rows")
                .map_err(|error| error.to_string())?;
            let durable = client
                .query_one(
                    "SELECT s.revision,s.published_html,c.published,
                            (s.published_at=c.published_at) AS same_published_at
                       FROM public.sandboxed_components s
                       JOIN public.components c ON c.name=s.name
                      WHERE s.name='custom_delivery_eta'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if rollback_rows != 0
                || durable
                    .try_get::<_, i32>("revision")
                    .map_err(|error| error.to_string())?
                    != 2
                || durable
                    .try_get::<_, String>("published_html")
                    .map_err(|error| error.to_string())?
                    != source_v2.html
                || !durable
                    .try_get::<_, bool>("published")
                    .map_err(|error| error.to_string())?
                || !durable
                    .try_get::<_, bool>("same_published_at")
                    .map_err(|error| error.to_string())?
            {
                return Err("business rows survived or changed across failed audit".to_owned());
            }
            client
                .batch_execute(
                    "DROP TRIGGER reject_sandboxed_component_audit ON public.audit_events;
                     DROP FUNCTION public.reject_sandboxed_component_audit();
                     INSERT INTO public.components(
                       name,title,kind,draft_description,published_description,published,
                       published_at,updated_by,created_at,updated_at
                     ) VALUES('custom_orphan','Orphan','sandboxed','orphan',NULL,false,NULL,
                              'sandbox-admin',clock_timestamp(),clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            adapter
                .delete_sandboxed_component(&auth, "custom_orphan")
                .await
                .map_err(|error| error.to_string())?;
            adapter
                .delete_sandboxed_component(&auth, &source_v2.name)
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let remaining: i64 = client
                .query_one(
                    "SELECT
                       (SELECT count(*) FROM public.sandboxed_components
                         WHERE name='custom_delivery_eta')
                       + (SELECT count(*) FROM public.components
                           WHERE name IN ('custom_delivery_eta','custom_orphan')) AS rows",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get("rows")
                .map_err(|error| error.to_string())?;
            let audits = client
                .query(
                    "SELECT event_type,payload
                       FROM public.audit_events
                      WHERE target_id='custom_delivery_eta'
                   ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let event_types = audits
                .iter()
                .map(|row| row.try_get::<_, String>("event_type"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            let revisions = audits
                .iter()
                .filter_map(|row| {
                    row.try_get::<_, serde_json::Value>("payload")
                        .ok()
                        .and_then(|value| value.get("component_revision").cloned())
                        .and_then(|value| value.as_u64())
                })
                .collect::<Vec<_>>();
            if remaining != 0
                || event_types
                    != [
                        "component.draft_saved",
                        "component.published",
                        "component.draft_saved",
                        "component.draft_saved",
                        "component.published",
                        "component.unpublished",
                    ]
                || revisions != [1, 2]
                || audits.iter().any(|row| {
                    row.try_get::<_, serde_json::Value>("payload")
                        .ok()
                        .and_then(|value| value.get("component_kind").cloned())
                        != Some(json!("sandboxed"))
                })
            {
                return Err(format!(
                    "delete/audit lifecycle drift: remaining={remaining} events={event_types:?} revisions={revisions:?}"
                ));
            }
            let compiled: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.components
                      WHERE name IN ('showQuote','custom_collision') AND kind='card'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if compiled != 2 {
                return Err("sandboxed surface changed compiled governance".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

fn draft(name: &str, version: &str, html: &str) -> SandboxedComponentDraft {
    SandboxedComponentDraft {
        name: name.to_owned(),
        title: "Delivery ETA".to_owned(),
        description: format!("description {version}"),
        html: html.to_owned(),
        css: "p { color: currentColor; }".to_owned(),
        js_functions: "function draw() { return window.__args; }".to_owned(),
        argument_schema: BTreeMap::from([
            ("type".to_owned(), json!("object")),
            ("version".to_owned(), json!(version)),
        ]),
        sample_arguments: BTreeMap::from([("version".to_owned(), json!(version))]),
    }
}

async fn assert_published_only(
    adapter: &PostgresSandboxedComponentAdministration,
    auth: &openbot_contracts::auth::AuthContext,
    expected: &SandboxedComponentDraft,
    revision: u32,
) -> Result<(), String> {
    let published = adapter
        .list_published_sandboxed_components(auth)
        .await
        .map_err(|error| error.to_string())?;
    if published.components.len() != 1
        || published.components[0].name != expected.name
        || published.components[0].html != expected.html
        || published.components[0].css != expected.css
        || published.components[0].js_functions != expected.js_functions
        || published.components[0].argument_schema != expected.argument_schema
    {
        return Err(format!(
            "published projection revision {revision} drift: {published:?}"
        ));
    }
    let wire = serde_json::to_value(&published).map_err(|error| error.to_string())?;
    if wire.to_string().contains("sampleArguments")
        || wire.to_string().contains("draftHtml")
        || wire.to_string().contains("authoredBy")
    {
        return Err("published wire exposed administrator-only fields".to_owned());
    }
    Ok(())
}
