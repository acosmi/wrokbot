//! PostgreSQL adapter for sandboxed-component draft, publication, and deletion governance.

use std::collections::BTreeMap;

use async_trait::async_trait;
use deadpool_postgres::{Pool, Transaction as PooledTransaction};
use openbot_application::{
    ComponentAdministrationError, ComponentRuntimeScope, GrantedSandboxedComponent,
    GrantedSandboxedComponents, SandboxedComponentAdministration,
    SandboxedComponentAdministrationError, SandboxedComponentDraft,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::components::ComponentDecision;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, PublishedSandboxedComponents, SandboxedComponentRecord,
    SandboxedComponents, is_sandboxed_component_name,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::components::{ComponentGrantFacts, decide_component_grant};
use openbot_domain::vault::SecretBytes;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row, Transaction as PgTransaction};

use crate::component_catalogue::{
    append_sandboxed_component_refusal, commit_component_runtime, component_refusal,
    ensure_runnable_agent,
};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

const SANDBOXED_KIND: &str = "sandboxed";

/// Production PostgreSQL authority for browser-authored component source lifecycle.
pub struct PostgresSandboxedComponentAdministration {
    pool: Pool,
    checkpoint_key: SecretBytes,
}

impl PostgresSandboxedComponentAdministration {
    /// Construct with the deployment's existing domain-separated audit checkpoint key.
    pub fn new(
        pool: Pool,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, SandboxedComponentAdministrationError> {
        if checkpoint_key.is_empty() {
            return Err(SandboxedComponentAdministrationError::Unavailable);
        }
        Ok(Self {
            pool,
            checkpoint_key: SecretBytes::new(checkpoint_key),
        })
    }
}

impl core::fmt::Debug for PostgresSandboxedComponentAdministration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresSandboxedComponentAdministration")
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SandboxedComponentAdministration for PostgresSandboxedComponentAdministration {
    async fn list_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(&record_query("ORDER BY s.title,s.name"), &[])
            .await
            .map_err(query_unavailable)?;
        let components = rows
            .iter()
            .map(decode_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SandboxedComponents { components })
    }

    async fn list_published_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT coalesce(c.name,s.name) AS name,c.kind,
                        c.published AS governance_published,
                        s.published AS source_published,s.published_html,s.published_css,
                        s.published_js_functions,s.published_argument_schema
                   FROM public.components c
              FULL JOIN public.sandboxed_components s ON s.name=c.name
                  WHERE (c.kind='sandboxed' AND c.published=true)
                     OR s.published=true
               ORDER BY coalesce(c.name,s.name)",
                &[],
            )
            .await
            .map_err(query_unavailable)?;
        let components = rows
            .iter()
            .map(decode_published)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PublishedSandboxedComponents { components })
    }

    async fn save_sandboxed_component(
        &self,
        auth: &AuthContext,
        draft: &SandboxedComponentDraft,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        compile_sandbox_schema(&object_value(&draft.argument_schema)).map_err(|_| {
            SandboxedComponentAdministrationError::InvalidInput {
                field: "argument_schema",
            }
        })?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let now = database_now(&transaction).await?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT kind FROM public.components WHERE name=$1 FOR UPDATE",
                &[&draft.name],
            )
            .await
            .map_err(query_unavailable)?
            && row
                .try_get::<_, String>("kind")
                .map_err(|_| corrupt("component_kind"))?
                != SANDBOXED_KIND
        {
            return Err(SandboxedComponentAdministrationError::Conflict);
        }

        let argument_schema = object_value(&draft.argument_schema);
        let sample_arguments = object_value(&draft.sample_arguments);
        transaction
            .execute(
                "INSERT INTO public.sandboxed_components(
                   name,title,draft_description,draft_html,draft_css,draft_js_functions,
                   draft_argument_schema,sample_arguments,revision,published,published_at,
                   authored_by,created_at,updated_at
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,false,NULL,$9,$10,$10)
                 ON CONFLICT(name) DO UPDATE SET
                   title=EXCLUDED.title,draft_description=EXCLUDED.draft_description,
                   draft_html=EXCLUDED.draft_html,draft_css=EXCLUDED.draft_css,
                   draft_js_functions=EXCLUDED.draft_js_functions,
                   draft_argument_schema=EXCLUDED.draft_argument_schema,
                   sample_arguments=EXCLUDED.sample_arguments,authored_by=EXCLUDED.authored_by,
                   updated_at=EXCLUDED.updated_at",
                &[
                    &draft.name,
                    &draft.title,
                    &draft.description,
                    &draft.html,
                    &draft.css,
                    &draft.js_functions,
                    &argument_schema,
                    &sample_arguments,
                    &auth.actor().as_str(),
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;

        let governance = transaction
            .query_opt(
                "INSERT INTO public.components(
                   name,title,kind,draft_description,published_description,published,
                   published_at,updated_by,created_at,updated_at
                 ) VALUES($1,$2,'sandboxed',$3,NULL,false,NULL,$4,$5,$5)
                 ON CONFLICT(name) DO UPDATE SET
                   title=EXCLUDED.title,draft_description=EXCLUDED.draft_description,
                   updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at
                 WHERE components.kind='sandboxed'
                 RETURNING name",
                &[
                    &draft.name,
                    &draft.title,
                    &draft.description,
                    &auth.actor().as_str(),
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if governance.is_none() {
            return Err(SandboxedComponentAdministrationError::Conflict);
        }
        append_sandboxed_audit(
            &transaction,
            auth,
            &draft.name,
            "component.draft_saved",
            None,
            self.checkpoint_key.expose(),
        )
        .await?;
        let row = transaction
            .query_one(&record_query("WHERE s.name=$1"), &[&draft.name])
            .await
            .map_err(query_unavailable)?;
        let record = decode_record(&row)?;
        commit(transaction, "sandboxed_component_save").await?;
        Ok(record)
    }

    async fn publish_sandboxed_component(
        &self,
        auth: &AuthContext,
        component_name: &str,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT s.draft_description,s.draft_html,s.draft_css,s.draft_js_functions,
                        s.draft_argument_schema,s.revision,c.kind
                   FROM public.sandboxed_components s
                   JOIN public.components c ON c.name=s.name
                  WHERE s.name=$1
                  FOR UPDATE OF s,c",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(SandboxedComponentAdministrationError::NotVisible)?;
        if row
            .try_get::<_, String>("kind")
            .map_err(|_| corrupt("component_kind"))?
            != SANDBOXED_KIND
        {
            return Err(SandboxedComponentAdministrationError::NotVisible);
        }
        let revision = row
            .try_get::<_, i32>("revision")
            .map_err(|_| corrupt("revision"))?;
        let next_revision = revision
            .checked_add(1)
            .ok_or(SandboxedComponentAdministrationError::Conflict)?;
        if revision < 0 {
            return Err(corrupt("revision"));
        }
        let now = database_now(&transaction).await?;
        let updated = transaction
            .execute(
                "UPDATE public.sandboxed_components SET
                   published_description=$2,published_html=$3,published_css=$4,
                   published_js_functions=$5,published_argument_schema=$6,published=true,
                   published_at=$7,revision=$8,updated_at=$7
                 WHERE name=$1",
                &[
                    &component_name,
                    &row.try_get::<_, String>("draft_description")
                        .map_err(|_| corrupt("draft_description"))?,
                    &row.try_get::<_, String>("draft_html")
                        .map_err(|_| corrupt("draft_html"))?,
                    &row.try_get::<_, String>("draft_css")
                        .map_err(|_| corrupt("draft_css"))?,
                    &row.try_get::<_, String>("draft_js_functions")
                        .map_err(|_| corrupt("draft_js_functions"))?,
                    &row.try_get::<_, Value>("draft_argument_schema")
                        .map_err(|_| corrupt("draft_argument_schema"))?,
                    &now,
                    &next_revision,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        let governance_updated = transaction
            .execute(
                "UPDATE public.components SET published_description=$2,published=true,
                        published_at=$3,updated_by=$4,updated_at=$3
                  WHERE name=$1 AND kind='sandboxed'",
                &[
                    &component_name,
                    &row.try_get::<_, String>("draft_description")
                        .map_err(|_| corrupt("draft_description"))?,
                    &now,
                    &auth.actor().as_str(),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if updated != 1 || governance_updated != 1 {
            return Err(corrupt("sandboxed_component_publication"));
        }
        append_sandboxed_audit(
            &transaction,
            auth,
            component_name,
            "component.published",
            Some(u64::try_from(next_revision).map_err(|_| corrupt("revision"))?),
            self.checkpoint_key.expose(),
        )
        .await?;
        let row = transaction
            .query_one(&record_query("WHERE s.name=$1"), &[&component_name])
            .await
            .map_err(query_unavailable)?;
        let record = decode_record(&row)?;
        commit(transaction, "sandboxed_component_publish").await?;
        Ok(record)
    }

    async fn delete_sandboxed_component(
        &self,
        auth: &AuthContext,
        component_name: &str,
    ) -> Result<(), SandboxedComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let governance = transaction
            .query_opt(
                "SELECT kind FROM public.components WHERE name=$1 FOR UPDATE",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(SandboxedComponentAdministrationError::NotVisible)?;
        if governance
            .try_get::<_, String>("kind")
            .map_err(|_| corrupt("component_kind"))?
            != SANDBOXED_KIND
        {
            return Err(SandboxedComponentAdministrationError::NotVisible);
        }
        transaction
            .execute(
                "DELETE FROM public.sandboxed_components WHERE name=$1",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?;
        let deleted = transaction
            .execute(
                "DELETE FROM public.components WHERE name=$1 AND kind='sandboxed'",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?;
        if deleted != 1 {
            return Err(corrupt("sandboxed_component_delete"));
        }
        append_sandboxed_audit(
            &transaction,
            auth,
            component_name,
            "component.unpublished",
            None,
            self.checkpoint_key.expose(),
        )
        .await?;
        commit(transaction, "sandboxed_component_delete").await
    }

    async fn list_sandboxed_components_for_agent(
        &self,
        scope: &ComponentRuntimeScope,
    ) -> Result<GrantedSandboxedComponents, SandboxedComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_runnable_agent(&transaction, scope)
            .await
            .map_err(map_component_runtime_error)?;
        let rows = transaction
            .query(
                "SELECT coalesce(c.name,s.name) AS name,c.kind,
                        c.published AS governance_published,c.published_description,
                        s.name AS source_name,s.published AS source_published,
                        s.published_html,s.published_css,s.published_js_functions,
                        s.published_argument_schema,s.revision,
                        (e.agent_id IS NOT NULL) AS withheld_from_agent
                   FROM public.components c
              FULL JOIN public.sandboxed_components s ON s.name=c.name
              LEFT JOIN public.component_exclusions e
                     ON e.component_name=coalesce(c.name,s.name) AND e.agent_id=$1
                  WHERE (c.kind='sandboxed' AND c.published=true)
                     OR s.published=true
               ORDER BY coalesce(c.name,s.name)",
                &[&scope.agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let mut components = Vec::with_capacity(rows.len());
        for row in &rows {
            let definition = decode_granted_sandboxed(row)?;
            if !row
                .try_get::<_, bool>("withheld_from_agent")
                .map_err(|_| corrupt("component_exclusion"))?
            {
                components.push(definition);
            }
        }
        transaction.commit().await.map_err(query_unavailable)?;
        Ok(GrantedSandboxedComponents { components })
    }

    async fn authorize_sandboxed_component(
        &self,
        scope: &ComponentRuntimeScope,
        component_name: &str,
        arguments: &Value,
    ) -> Result<ComponentDecision, SandboxedComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_runnable_agent(&transaction, scope)
            .await
            .map_err(map_component_runtime_error)?;
        transaction
            .query_opt(
                "SELECT name FROM public.components WHERE name=$1 FOR UPDATE",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .query_opt(
                "SELECT name FROM public.sandboxed_components WHERE name=$1 FOR UPDATE",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?;
        let row = transaction
            .query_one(
                "SELECT c.name AS governance_name,c.kind,
                        coalesce(c.published,false) AS governance_published,
                        c.published_description,s.name AS source_name,
                        coalesce(s.published,false) AS source_published,
                        s.published_html,s.published_css,s.published_js_functions,
                        s.published_argument_schema,s.revision,
                        (e.agent_id IS NOT NULL) AS withheld_from_agent
                   FROM (VALUES(1)) AS singleton(value)
              LEFT JOIN public.components c ON c.name=$1
              LEFT JOIN public.sandboxed_components s ON s.name=c.name
              LEFT JOIN public.component_exclusions e
                     ON e.component_name=c.name AND e.agent_id=$2",
                &[&component_name, &scope.agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let governance_name = row
            .try_get::<_, Option<String>>("governance_name")
            .map_err(|_| corrupt("component_governance"))?;
        let kind = row
            .try_get::<_, Option<String>>("kind")
            .map_err(|_| corrupt("component_kind"))?;
        let source_name = row
            .try_get::<_, Option<String>>("source_name")
            .map_err(|_| corrupt("sandboxed_source"))?;
        let owned = governance_name.as_deref() == Some(component_name)
            && kind.as_deref() == Some(SANDBOXED_KIND)
            && source_name.as_deref() == Some(component_name)
            && is_sandboxed_component_name(component_name);
        if kind.as_deref() == Some(SANDBOXED_KIND) && source_name.is_none() {
            return Err(corrupt("sandboxed_source"));
        }
        let governance_published = row
            .try_get::<_, bool>("governance_published")
            .map_err(|_| corrupt("published"))?;
        let source_published = row
            .try_get::<_, bool>("source_published")
            .map_err(|_| corrupt("published"))?;
        if owned && governance_published != source_published {
            return Err(corrupt("component_governance"));
        }
        let published = owned && governance_published && source_published;
        let description = row
            .try_get::<_, Option<String>>("published_description")
            .map_err(|_| corrupt("published_description"))?;
        let facts = ComponentGrantFacts {
            exists: owned,
            published,
            has_published_description: description.is_some(),
            withheld_from_agent: row
                .try_get("withheld_from_agent")
                .map_err(|_| corrupt("component_exclusion"))?,
        };
        if let openbot_domain::components::ComponentGrantDecision::Refused(reason) =
            decide_component_grant(facts)
        {
            let refusal = component_refusal(reason, None).map_err(map_component_runtime_error)?;
            append_sandboxed_component_refusal(
                &transaction,
                scope,
                component_name,
                &refusal,
                self.checkpoint_key.expose(),
            )
            .await
            .map_err(map_component_runtime_error)?;
            commit_component_runtime(transaction, "sandboxed_component_refusal")
                .await
                .map_err(map_component_runtime_error)?;
            return Ok(ComponentDecision::refused(refusal));
        }
        let schema = row
            .try_get::<_, Option<Value>>("published_argument_schema")
            .map_err(|_| corrupt("published_argument_schema"))?
            .ok_or_else(|| corrupt("published_argument_schema"))?;
        required_published(&row, "published_html")?;
        required_published(&row, "published_css")?;
        required_published(&row, "published_js_functions")?;
        let validator = compile_sandbox_schema(&schema)?;
        if !arguments.is_object() || !validator.is_valid(arguments) {
            return Err(SandboxedComponentAdministrationError::InvalidInput {
                field: "component_arguments",
            });
        }
        transaction.commit().await.map_err(query_unavailable)?;
        Ok(ComponentDecision::allowed())
    }
}

fn record_query(suffix: &str) -> String {
    format!(
        "SELECT s.name,s.title,s.draft_description,s.draft_html,s.draft_css,
                s.draft_js_functions,s.draft_argument_schema,s.published_description,
                s.published_html,s.published_css,s.published_js_functions,
                s.published_argument_schema,s.sample_arguments,s.revision,s.published,
                s.published_at,s.authored_by,c.name AS governance_name,c.title AS governance_title,
                c.kind AS governance_kind,c.draft_description AS governance_draft_description,
                c.published_description AS governance_published_description,
                c.published AS governance_published
           FROM public.sandboxed_components s
      LEFT JOIN public.components c ON c.name=s.name {suffix}"
    )
}

fn decode_record(
    row: &Row,
) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
    let name = row
        .try_get::<_, String>("name")
        .map_err(|_| corrupt("component_name"))?;
    let title = row
        .try_get::<_, String>("title")
        .map_err(|_| corrupt("title"))?;
    let draft_description = row
        .try_get::<_, String>("draft_description")
        .map_err(|_| corrupt("draft_description"))?;
    let published_description = row
        .try_get::<_, Option<String>>("published_description")
        .map_err(|_| corrupt("published_description"))?;
    let published = row
        .try_get::<_, bool>("published")
        .map_err(|_| corrupt("published"))?;
    let governance_name = row
        .try_get::<_, Option<String>>("governance_name")
        .map_err(|_| corrupt("component_governance"))?;
    let governance_title = row
        .try_get::<_, Option<String>>("governance_title")
        .map_err(|_| corrupt("component_governance"))?;
    let governance_kind = row
        .try_get::<_, Option<String>>("governance_kind")
        .map_err(|_| corrupt("component_kind"))?;
    let governance_draft = row
        .try_get::<_, Option<String>>("governance_draft_description")
        .map_err(|_| corrupt("component_governance"))?;
    let governance_published_description = row
        .try_get::<_, Option<String>>("governance_published_description")
        .map_err(|_| corrupt("component_governance"))?;
    let governance_published = row
        .try_get::<_, Option<bool>>("governance_published")
        .map_err(|_| corrupt("component_governance"))?;
    if governance_name.as_deref() != Some(name.as_str())
        || governance_title.as_deref() != Some(title.as_str())
        || governance_kind.as_deref() != Some(SANDBOXED_KIND)
        || governance_draft.as_deref() != Some(draft_description.as_str())
        || governance_published_description != published_description
        || governance_published != Some(published)
    {
        return Err(corrupt("component_governance"));
    }
    let draft_html = row
        .try_get::<_, String>("draft_html")
        .map_err(|_| corrupt("draft_html"))?;
    let draft_css = row
        .try_get::<_, String>("draft_css")
        .map_err(|_| corrupt("draft_css"))?;
    let draft_js_functions = row
        .try_get::<_, String>("draft_js_functions")
        .map_err(|_| corrupt("draft_js_functions"))?;
    let published_html = row
        .try_get::<_, Option<String>>("published_html")
        .map_err(|_| corrupt("published_html"))?;
    let published_css = row
        .try_get::<_, Option<String>>("published_css")
        .map_err(|_| corrupt("published_css"))?;
    let published_js_functions = row
        .try_get::<_, Option<String>>("published_js_functions")
        .map_err(|_| corrupt("published_js_functions"))?;
    let revision = row
        .try_get::<_, i32>("revision")
        .map_err(|_| corrupt("revision"))?;
    Ok(SandboxedComponentRecord {
        name,
        title,
        draft_description,
        draft_html: draft_html.clone(),
        draft_css: draft_css.clone(),
        draft_js_functions: draft_js_functions.clone(),
        draft_argument_schema: decode_object(
            row.try_get("draft_argument_schema")
                .map_err(|_| corrupt("draft_argument_schema"))?,
            "draft_argument_schema",
        )?,
        published_html: published_html.clone(),
        published_css: published_css.clone(),
        published_js_functions: published_js_functions.clone(),
        published_argument_schema: row
            .try_get::<_, Option<Value>>("published_argument_schema")
            .map_err(|_| corrupt("published_argument_schema"))?
            .map(|value| decode_object(value, "published_argument_schema"))
            .transpose()?,
        sample_arguments: decode_object(
            row.try_get("sample_arguments")
                .map_err(|_| corrupt("sample_arguments"))?,
            "sample_arguments",
        )?,
        revision: u32::try_from(revision).map_err(|_| corrupt("revision"))?,
        published,
        published_at: row
            .try_get("published_at")
            .map_err(|_| corrupt("published_at"))?,
        authored_by: row
            .try_get("authored_by")
            .map_err(|_| corrupt("authored_by"))?,
        has_unpublished_changes: published
            && (published_html.as_deref() != Some(draft_html.as_str())
                || published_css.as_deref() != Some(draft_css.as_str())
                || published_js_functions.as_deref() != Some(draft_js_functions.as_str())),
    })
}

fn decode_published(
    row: &Row,
) -> Result<PublishedSandboxedComponent, SandboxedComponentAdministrationError> {
    if row
        .try_get::<_, Option<String>>("kind")
        .map_err(|_| corrupt("component_kind"))?
        .as_deref()
        != Some(SANDBOXED_KIND)
        || row
            .try_get::<_, Option<bool>>("governance_published")
            .map_err(|_| corrupt("component_governance"))?
            != Some(true)
        || row
            .try_get::<_, Option<bool>>("source_published")
            .map_err(|_| corrupt("published"))?
            != Some(true)
    {
        return Err(corrupt("component_governance"));
    }
    Ok(PublishedSandboxedComponent {
        name: row.try_get("name").map_err(|_| corrupt("component_name"))?,
        html: required_published(row, "published_html")?,
        css: required_published(row, "published_css")?,
        js_functions: required_published(row, "published_js_functions")?,
        argument_schema: decode_object(
            row.try_get::<_, Option<Value>>("published_argument_schema")
                .map_err(|_| corrupt("published_argument_schema"))?
                .ok_or_else(|| corrupt("published_argument_schema"))?,
            "published_argument_schema",
        )?,
    })
}

fn decode_granted_sandboxed(
    row: &Row,
) -> Result<GrantedSandboxedComponent, SandboxedComponentAdministrationError> {
    let name = row
        .try_get::<_, String>("name")
        .map_err(|_| corrupt("component_name"))?;
    let source_name = row
        .try_get::<_, Option<String>>("source_name")
        .map_err(|_| corrupt("sandboxed_source"))?;
    if !is_sandboxed_component_name(&name)
        || source_name.as_deref() != Some(name.as_str())
        || row
            .try_get::<_, Option<String>>("kind")
            .map_err(|_| corrupt("component_kind"))?
            .as_deref()
            != Some(SANDBOXED_KIND)
        || row
            .try_get::<_, Option<bool>>("governance_published")
            .map_err(|_| corrupt("component_governance"))?
            != Some(true)
        || row
            .try_get::<_, Option<bool>>("source_published")
            .map_err(|_| corrupt("published"))?
            != Some(true)
    {
        return Err(corrupt("component_governance"));
    }
    required_published(row, "published_html")?;
    required_published(row, "published_css")?;
    required_published(row, "published_js_functions")?;
    let description = row
        .try_get::<_, Option<String>>("published_description")
        .map_err(|_| corrupt("published_description"))?
        .ok_or_else(|| corrupt("published_description"))?;
    if description.is_empty()
        || description.len() > 16 * 1024
        || description.as_bytes().contains(&0)
    {
        return Err(corrupt("published_description"));
    }
    let argument_schema = row
        .try_get::<_, Option<Value>>("published_argument_schema")
        .map_err(|_| corrupt("published_argument_schema"))?
        .ok_or_else(|| corrupt("published_argument_schema"))?;
    compile_sandbox_schema(&argument_schema)?;
    let revision = row
        .try_get::<_, Option<i32>>("revision")
        .map_err(|_| corrupt("revision"))?
        .ok_or_else(|| corrupt("revision"))?;
    if revision < 1 {
        return Err(corrupt("revision"));
    }
    Ok(GrantedSandboxedComponent {
        name,
        description,
        argument_schema,
        revision: u32::try_from(revision).map_err(|_| corrupt("revision"))?,
    })
}

fn compile_sandbox_schema(
    schema: &Value,
) -> Result<jsonschema::Validator, SandboxedComponentAdministrationError> {
    if !schema.is_object() || contains_external_schema_reference(schema) {
        return Err(corrupt("published_argument_schema"));
    }
    jsonschema::options()
        .with_pattern_options(
            jsonschema::PatternOptions::regex()
                .size_limit(1024 * 1024)
                .dfa_size_limit(1024 * 1024),
        )
        .build(schema)
        .map_err(|_| corrupt("published_argument_schema"))
}

fn contains_external_schema_reference(schema: &Value) -> bool {
    let mut stack = vec![schema];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                if object
                    .get("$ref")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.starts_with('#'))
                {
                    return true;
                }
                stack.extend(object.values());
            }
            Value::Array(values) => stack.extend(values),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    false
}

fn map_component_runtime_error(
    error: ComponentAdministrationError,
) -> SandboxedComponentAdministrationError {
    match error {
        ComponentAdministrationError::InvalidInput { field }
        | ComponentAdministrationError::Corrupt { field } => {
            SandboxedComponentAdministrationError::Corrupt { field }
        }
        ComponentAdministrationError::NotVisible => {
            SandboxedComponentAdministrationError::NotVisible
        }
        ComponentAdministrationError::Conflict => SandboxedComponentAdministrationError::Conflict,
        ComponentAdministrationError::Unavailable => {
            SandboxedComponentAdministrationError::Unavailable
        }
        ComponentAdministrationError::CommitUnknown => {
            SandboxedComponentAdministrationError::CommitUnknown
        }
    }
}

fn required_published(
    row: &Row,
    field: &'static str,
) -> Result<String, SandboxedComponentAdministrationError> {
    row.try_get::<_, Option<String>>(field)
        .map_err(|_| corrupt(field))?
        .ok_or_else(|| corrupt(field))
}

fn object_value(object: &BTreeMap<String, Value>) -> Value {
    Value::Object(object.clone().into_iter().collect::<Map<_, _>>())
}

fn decode_object(
    value: Value,
    field: &'static str,
) -> Result<BTreeMap<String, Value>, SandboxedComponentAdministrationError> {
    match value {
        Value::Object(object) => Ok(object.into_iter().collect()),
        _ => Err(corrupt(field)),
    }
}

async fn database_now(
    transaction: &PgTransaction<'_>,
) -> Result<OffsetDateTime, SandboxedComponentAdministrationError> {
    transaction
        .query_one("SELECT clock_timestamp() AS now", &[])
        .await
        .map_err(query_unavailable)?
        .try_get("now")
        .map_err(|_| corrupt("database_clock"))
}

async fn append_sandboxed_audit(
    transaction: &PgTransaction<'_>,
    auth: &AuthContext,
    component_name: &str,
    event_type: &'static str,
    revision: Option<u64>,
    checkpoint_key: &[u8],
) -> Result<(), SandboxedComponentAdministrationError> {
    let mut facts = vec![AuditFact::ComponentKind(AuditLabel::new(SANDBOXED_KIND))];
    if let Some(revision) = revision {
        facts.push(AuditFact::ComponentRevision(revision));
    }
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("component"),
        target_id: Some(
            AuditIdentifier::new(component_name.to_owned())
                .map_err(|_| corrupt("component_name"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(infra_unavailable)
}

async fn commit(
    transaction: PooledTransaction<'_>,
    operation: &'static str,
) -> Result<(), SandboxedComponentAdministrationError> {
    transaction.commit().await.map_err(|error| {
        tracing::error!(error = %error, operation, "sandboxed component commit result unknown");
        SandboxedComponentAdministrationError::CommitUnknown
    })
}

fn corrupt(field: &'static str) -> SandboxedComponentAdministrationError {
    SandboxedComponentAdministrationError::Corrupt { field }
}

fn unavailable(error: deadpool_postgres::PoolError) -> SandboxedComponentAdministrationError {
    tracing::error!(error = %error, "sandboxed component database pool unavailable");
    SandboxedComponentAdministrationError::Unavailable
}

fn query_unavailable(error: tokio_postgres::Error) -> SandboxedComponentAdministrationError {
    tracing::error!(error = %error, "sandboxed component query failed");
    SandboxedComponentAdministrationError::Unavailable
}

fn infra_unavailable(error: crate::db::InfraError) -> SandboxedComponentAdministrationError {
    tracing::error!(error = %error, "sandboxed component audit failed");
    SandboxedComponentAdministrationError::Unavailable
}
