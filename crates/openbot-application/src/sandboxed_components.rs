//! Sandboxed component governance use cases and their I/O-free authority port.

use std::collections::BTreeMap;

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::components::{ComponentDecision, ComponentDecisionRefusal};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, PublishedSandboxedComponents, SANDBOXED_COMPONENT_PREFIX,
    SandboxedComponentDeleted, SandboxedComponentRecord, SandboxedComponentResponse,
    SandboxedComponents, SaveSandboxedComponentRequest, is_sandboxed_component_name,
};
use serde_json::Value;

use crate::components::ComponentRuntimeScope;

/// Application/in-process equivalent of the global HTTP request-body boundary.
pub const MAX_SANDBOXED_COMPONENT_DRAFT_BYTES: usize = 1024 * 1024;
const MAX_JSON_NESTING_DEPTH: usize = 128;
const MAX_ACTOR_IDENTIFIER_BYTES: usize = 256;

/// Validated draft passed to persistence; its name is already server-namespaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxedComponentDraft {
    /// Stable `custom_` component identity.
    pub name: String,
    /// Administrator-facing title.
    pub title: String,
    /// Draft model-facing description.
    pub description: String,
    /// Draft authored markup.
    pub html: String,
    /// Draft authored styles.
    pub css: String,
    /// Draft authored JavaScript functions.
    pub js_functions: String,
    /// Draft argument schema.
    pub argument_schema: BTreeMap<String, Value>,
    /// Administrator-only playground arguments.
    pub sample_arguments: BTreeMap<String, Value>,
}

/// One current published sandbox definition granted to a runnable Agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantedSandboxedComponent {
    /// Stable `custom_` provider tool and renderer identity.
    pub name: String,
    /// Current published model-facing description.
    pub description: String,
    /// Current published JSON Schema.
    pub argument_schema: Value,
    /// Current monotonic published revision.
    pub revision: u32,
}

/// Current dynamic sandbox definitions for one runnable Agent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantedSandboxedComponents {
    /// Published, non-withheld definitions in stable name order.
    pub components: Vec<GrantedSandboxedComponent>,
}

/// Stable sandboxed-component failures without SQL text or untrusted source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SandboxedComponentAdministrationError {
    /// A closed request or projection violated its contract.
    #[error("sandboxed_component_invalid_input field={field}")]
    InvalidInput {
        /// Static field only; user source is never reflected.
        field: &'static str,
    },
    /// The named resource is absent or is not owned by the sandboxed surface.
    #[error("sandboxed_component_not_visible")]
    NotVisible,
    /// The operation conflicts with an existing identity or exhausted revision.
    #[error("sandboxed_component_conflict")]
    Conflict,
    /// PostgreSQL or another required local dependency is unavailable.
    #[error("sandboxed_component_unavailable")]
    Unavailable,
    /// A durable row cannot be projected into the closed contract.
    #[error("sandboxed_component_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// A transaction commit result is unknown and requires reconciliation.
    #[error("sandboxed_component_commit_unknown")]
    CommitUnknown,
}

impl SandboxedComponentAdministrationError {
    /// Map to the repository-wide stable application taxonomy.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::Conflict => AppError::RequestConflict {
                resource: "sandboxed_component",
            },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "sandboxed_components",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Authority port for sandboxed source lifecycle; deliberately has no data-function method.
#[async_trait]
pub trait SandboxedComponentAdministration: Send + Sync {
    /// List administrator-editable drafts.
    async fn list_sandboxed_components(
        &self,
        auth: &AuthContext,
    ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError>;

    /// List published source for authenticated runtime presentation.
    async fn list_published_sandboxed_components(
        &self,
        auth: &AuthContext,
    ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError>;

    /// Persist a draft and its shared governance row atomically.
    async fn save_sandboxed_component(
        &self,
        auth: &AuthContext,
        draft: &SandboxedComponentDraft,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError>;

    /// Atomically publish source plus description and increment revision.
    async fn publish_sandboxed_component(
        &self,
        auth: &AuthContext,
        component_name: &str,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError>;

    /// Atomically delete sandboxed source and shared governance.
    async fn delete_sandboxed_component(
        &self,
        auth: &AuthContext,
        component_name: &str,
    ) -> Result<(), SandboxedComponentAdministrationError>;

    /// List current published sandbox definitions granted to one authoritative Agent scope.
    async fn list_sandboxed_components_for_agent(
        &self,
        _scope: &ComponentRuntimeScope,
    ) -> Result<GrantedSandboxedComponents, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }

    /// Recheck publication, withholding, and current schema for one exact provider call.
    async fn authorize_sandboxed_component(
        &self,
        _scope: &ComponentRuntimeScope,
        _component_name: &str,
        _arguments: &Value,
    ) -> Result<ComponentDecision, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }
}

/// Fail-closed default used until the production adapter is injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSandboxedComponentAdministration;

#[async_trait]
impl SandboxedComponentAdministration for NoSandboxedComponentAdministration {
    async fn list_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }

    async fn list_published_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }

    async fn save_sandboxed_component(
        &self,
        _auth: &AuthContext,
        _draft: &SandboxedComponentDraft,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }

    async fn publish_sandboxed_component(
        &self,
        _auth: &AuthContext,
        _component_name: &str,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }

    async fn delete_sandboxed_component(
        &self,
        _auth: &AuthContext,
        _component_name: &str,
    ) -> Result<(), SandboxedComponentAdministrationError> {
        Err(SandboxedComponentAdministrationError::Unavailable)
    }
}

/// List sandboxed drafts after repeating the administrator role check in application.
pub async fn list_sandboxed_components(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
) -> Result<SandboxedComponents, AppError> {
    require_admin(auth)?;
    let components = port
        .list_sandboxed_components(auth)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    for component in &components.components {
        validate_record(component)
            .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    }
    Ok(components)
}

/// List published source; draft and sample fields cannot fit in this return type.
pub async fn list_published_sandboxed_components(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
) -> Result<PublishedSandboxedComponents, AppError> {
    let components = port
        .list_published_sandboxed_components(auth)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    for component in &components.components {
        validate_published(component)
            .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    }
    Ok(components)
}

/// Validate, namespace, and save one sandboxed draft without publishing it.
pub async fn save_sandboxed_component(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
    request: SaveSandboxedComponentRequest,
) -> Result<SandboxedComponentResponse, AppError> {
    require_admin(auth)?;
    let draft =
        validate_draft(request).map_err(SandboxedComponentAdministrationError::into_app_error)?;
    let component = port
        .save_sandboxed_component(auth, &draft)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    validate_record(&component).map_err(SandboxedComponentAdministrationError::into_app_error)?;
    if component.name != draft.name
        || component.title != draft.title
        || component.draft_description != draft.description
        || component.draft_html != draft.html
        || component.draft_css != draft.css
        || component.draft_js_functions != draft.js_functions
        || component.draft_argument_schema != draft.argument_schema
        || component.sample_arguments != draft.sample_arguments
        || component.authored_by.as_deref() != Some(auth.actor().as_str())
    {
        return Err(SandboxedComponentAdministrationError::Corrupt {
            field: "sandboxed_component",
        }
        .into_app_error());
    }
    Ok(SandboxedComponentResponse { component })
}

/// Publish source and description as one application action.
pub async fn publish_sandboxed_component(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
    component_name: String,
) -> Result<SandboxedComponentResponse, AppError> {
    require_admin(auth)?;
    validate_sandboxed_name(&component_name)
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    let component = port
        .publish_sandboxed_component(auth, &component_name)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    validate_record(&component).map_err(SandboxedComponentAdministrationError::into_app_error)?;
    if component.name != component_name
        || !component.published
        || component.published_at.is_none()
        || component.has_unpublished_changes
    {
        return Err(SandboxedComponentAdministrationError::Corrupt {
            field: "sandboxed_component_publication",
        }
        .into_app_error());
    }
    Ok(SandboxedComponentResponse { component })
}

/// Delete only an identity that belongs to the server-owned sandbox namespace.
pub async fn delete_sandboxed_component(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
    component_name: String,
) -> Result<SandboxedComponentDeleted, AppError> {
    require_admin(auth)?;
    validate_sandboxed_name(&component_name)
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    port.delete_sandboxed_component(auth, &component_name)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    Ok(SandboxedComponentDeleted { ok: true })
}

/// Re-authorize one dynamic sandbox renderer against current publication/schema/grant facts.
pub async fn authorize_sandboxed_component(
    port: &dyn SandboxedComponentAdministration,
    auth: &AuthContext,
    component_name: String,
    agent_id: BotId,
    arguments: Value,
) -> Result<ComponentDecision, AppError> {
    validate_sandboxed_name(&component_name)
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    if agent_id.as_str().is_empty()
        || agent_id.as_str().len() > MAX_ACTOR_IDENTIFIER_BYTES
        || agent_id.as_str().as_bytes().contains(&0)
    {
        return Err(
            SandboxedComponentAdministrationError::InvalidInput { field: "agent_id" }
                .into_app_error(),
        );
    }
    let object = arguments
        .as_object()
        .ok_or(SandboxedComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        })
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    let encoded = serde_json::to_vec(&arguments)
        .map_err(|_| SandboxedComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        })
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    if encoded.len() > MAX_SANDBOXED_COMPONENT_DRAFT_BYTES {
        return Err(SandboxedComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        }
        .into_app_error());
    }
    validate_json_object(
        &object
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        "component_arguments",
    )
    .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    let scope = ComponentRuntimeScope {
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        admin: auth.has_role(Role::Admin),
        agent_id,
    };
    let decision = port
        .authorize_sandboxed_component(&scope, &component_name, &arguments)
        .await
        .map_err(SandboxedComponentAdministrationError::into_app_error)?;
    let shape_valid = decision.allowed == decision.refusal.is_none();
    let refusal_valid = decision.refusal.as_ref().is_none_or(|refusal| {
        matches!(
            refusal,
            ComponentDecisionRefusal::UnknownComponent
                | ComponentDecisionRefusal::Unpublished
                | ComponentDecisionRefusal::WithheldFromAgent
        )
    });
    if !shape_valid || !refusal_valid {
        return Err(SandboxedComponentAdministrationError::Corrupt {
            field: "sandboxed_component_decision",
        }
        .into_app_error());
    }
    Ok(decision)
}

fn require_admin(auth: &AuthContext) -> Result<(), AppError> {
    if auth.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(AppError::ForbiddenRole {
            required: Role::Admin,
        })
    }
}

fn validate_draft(
    request: SaveSandboxedComponentRequest,
) -> Result<SandboxedComponentDraft, SandboxedComponentAdministrationError> {
    let encoded = serde_json::to_vec(&request)
        .map_err(|_| SandboxedComponentAdministrationError::InvalidInput { field: "body" })?;
    if encoded.len() > MAX_SANDBOXED_COMPONENT_DRAFT_BYTES {
        return Err(SandboxedComponentAdministrationError::InvalidInput { field: "body" });
    }
    validate_slug(&request.slug)?;
    validate_required_text(&request.title, "title")?;
    for (value, field) in [
        (&request.description, "description"),
        (&request.html, "html"),
        (&request.css, "css"),
        (&request.js_functions, "js_functions"),
    ] {
        validate_source_text(value, field)?;
    }
    validate_json_object(&request.argument_schema, "argument_schema")?;
    validate_json_object(&request.sample_arguments, "sample_arguments")?;
    Ok(SandboxedComponentDraft {
        name: format!("{SANDBOXED_COMPONENT_PREFIX}{}", request.slug),
        title: request.title,
        description: request.description,
        html: request.html,
        css: request.css,
        js_functions: request.js_functions,
        argument_schema: request.argument_schema,
        sample_arguments: request.sample_arguments,
    })
}

fn validate_slug(slug: &str) -> Result<(), SandboxedComponentAdministrationError> {
    if !is_sandboxed_component_name(&format!("{SANDBOXED_COMPONENT_PREFIX}{slug}")) {
        Err(SandboxedComponentAdministrationError::InvalidInput { field: "slug" })
    } else {
        Ok(())
    }
}

fn validate_sandboxed_name(name: &str) -> Result<(), SandboxedComponentAdministrationError> {
    if is_sandboxed_component_name(name) {
        Ok(())
    } else {
        Err(SandboxedComponentAdministrationError::InvalidInput {
            field: "component_name",
        })
    }
}

fn validate_required_text(
    value: &str,
    field: &'static str,
) -> Result<(), SandboxedComponentAdministrationError> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        Err(SandboxedComponentAdministrationError::InvalidInput { field })
    } else {
        Ok(())
    }
}

fn validate_source_text(
    value: &str,
    field: &'static str,
) -> Result<(), SandboxedComponentAdministrationError> {
    if value.as_bytes().contains(&0) {
        Err(SandboxedComponentAdministrationError::InvalidInput { field })
    } else {
        Ok(())
    }
}

fn validate_json_object(
    object: &BTreeMap<String, Value>,
    field: &'static str,
) -> Result<(), SandboxedComponentAdministrationError> {
    let mut stack = object
        .iter()
        .map(|(key, value)| (Some(key.as_str()), value, 1_usize))
        .collect::<Vec<_>>();
    while let Some((key, value, depth)) = stack.pop() {
        if key.is_some_and(|key| key.as_bytes().contains(&0)) || depth > MAX_JSON_NESTING_DEPTH {
            return Err(SandboxedComponentAdministrationError::InvalidInput { field });
        }
        match value {
            Value::String(value) if value.as_bytes().contains(&0) => {
                return Err(SandboxedComponentAdministrationError::InvalidInput { field });
            }
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (None, value, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(
                    values
                        .iter()
                        .map(|(key, value)| (Some(key.as_str()), value, depth + 1)),
                );
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn validate_record(
    record: &SandboxedComponentRecord,
) -> Result<(), SandboxedComponentAdministrationError> {
    validate_sandboxed_name(&record.name).map_err(|_| {
        SandboxedComponentAdministrationError::Corrupt {
            field: "component_name",
        }
    })?;
    validate_required_text(&record.title, "title").map_err(as_corrupt)?;
    for (value, field) in [
        (&record.draft_description, "draft_description"),
        (&record.draft_html, "draft_html"),
        (&record.draft_css, "draft_css"),
        (&record.draft_js_functions, "draft_js_functions"),
    ] {
        validate_source_text(value, field).map_err(as_corrupt)?;
    }
    validate_json_object(&record.draft_argument_schema, "draft_argument_schema")
        .map_err(as_corrupt)?;
    validate_json_object(&record.sample_arguments, "sample_arguments").map_err(as_corrupt)?;
    if let Some(actor) = record.authored_by.as_deref()
        && (actor.is_empty()
            || actor.len() > MAX_ACTOR_IDENTIFIER_BYTES
            || actor.chars().any(char::is_control))
    {
        return Err(SandboxedComponentAdministrationError::Corrupt {
            field: "authored_by",
        });
    }
    if record.published {
        let (Some(html), Some(css), Some(js_functions), Some(argument_schema), Some(_)) = (
            record.published_html.as_deref(),
            record.published_css.as_deref(),
            record.published_js_functions.as_deref(),
            record.published_argument_schema.as_ref(),
            record.published_at,
        ) else {
            return Err(SandboxedComponentAdministrationError::Corrupt {
                field: "published_source",
            });
        };
        for (value, field) in [
            (html, "published_html"),
            (css, "published_css"),
            (js_functions, "published_js_functions"),
        ] {
            validate_source_text(value, field).map_err(as_corrupt)?;
        }
        validate_json_object(argument_schema, "published_argument_schema").map_err(as_corrupt)?;
    }
    let expected_changes = record.published
        && (record.published_html.as_deref() != Some(record.draft_html.as_str())
            || record.published_css.as_deref() != Some(record.draft_css.as_str())
            || record.published_js_functions.as_deref()
                != Some(record.draft_js_functions.as_str()));
    if record.has_unpublished_changes != expected_changes {
        return Err(SandboxedComponentAdministrationError::Corrupt {
            field: "has_unpublished_changes",
        });
    }
    Ok(())
}

fn validate_published(
    component: &PublishedSandboxedComponent,
) -> Result<(), SandboxedComponentAdministrationError> {
    validate_sandboxed_name(&component.name).map_err(|_| {
        SandboxedComponentAdministrationError::Corrupt {
            field: "component_name",
        }
    })?;
    for (value, field) in [
        (&component.html, "published_html"),
        (&component.css, "published_css"),
        (&component.js_functions, "published_js_functions"),
    ] {
        validate_source_text(value, field).map_err(as_corrupt)?;
    }
    validate_json_object(&component.argument_schema, "published_argument_schema")
        .map_err(as_corrupt)
}

fn as_corrupt(
    error: SandboxedComponentAdministrationError,
) -> SandboxedComponentAdministrationError {
    match error {
        SandboxedComponentAdministrationError::InvalidInput { field } => {
            SandboxedComponentAdministrationError::Corrupt { field }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use time::OffsetDateTime;

    fn auth(role: Role) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("deployment"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [role],
            AuthGeneration::new(1),
            false,
        )
    }

    #[test]
    fn fixed_upstream_slug_grammar_is_exact_and_namespaced() {
        for valid in ["ab", "a0", "delivery_eta", &format!("a{}z", "_".repeat(38))] {
            let request = SaveSandboxedComponentRequest {
                slug: valid.to_owned(),
                title: "Title".to_owned(),
                description: String::new(),
                html: String::new(),
                css: String::new(),
                js_functions: String::new(),
                argument_schema: BTreeMap::new(),
                sample_arguments: BTreeMap::new(),
            };
            assert_eq!(
                validate_draft(request).unwrap().name,
                format!("custom_{valid}")
            );
        }
        for invalid in ["a", "A1", "_ab", "ab_", "a-b", "a b"] {
            assert_eq!(
                validate_slug(invalid),
                Err(SandboxedComponentAdministrationError::InvalidInput { field: "slug" })
            );
        }
    }

    #[tokio::test]
    async fn default_port_is_fail_closed_and_non_admin_cannot_reach_it() {
        let user = auth(Role::User);
        assert!(matches!(
            list_sandboxed_components(&NoSandboxedComponentAdministration, &user).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert!(matches!(
            list_published_sandboxed_components(
                &NoSandboxedComponentAdministration,
                &auth(Role::Admin)
            )
            .await,
            Err(AppError::DependencyUnavailable {
                dependency: "sandboxed_components"
            })
        ));
    }

    #[test]
    fn publication_change_flag_preserves_fixed_upstream_three_source_comparison() {
        let record = SandboxedComponentRecord {
            name: "custom_delivery_eta".to_owned(),
            title: "Delivery ETA".to_owned(),
            draft_description: "new description only".to_owned(),
            draft_html: "<p>ETA</p>".to_owned(),
            draft_css: "p{}".to_owned(),
            draft_js_functions: "function draw(){}".to_owned(),
            draft_argument_schema: BTreeMap::new(),
            published_html: Some("<p>ETA</p>".to_owned()),
            published_css: Some("p{}".to_owned()),
            published_js_functions: Some("function draw(){}".to_owned()),
            published_argument_schema: Some(BTreeMap::new()),
            sample_arguments: BTreeMap::new(),
            revision: 1,
            published: true,
            published_at: Some(OffsetDateTime::UNIX_EPOCH),
            authored_by: Some("actor".to_owned()),
            has_unpublished_changes: false,
        };
        assert_eq!(validate_record(&record), Ok(()));
    }

    #[test]
    fn in_process_drafts_share_http_size_depth_and_postgres_nul_boundaries() {
        let oversized = SaveSandboxedComponentRequest {
            slug: "oversized".to_owned(),
            title: "Title".to_owned(),
            description: String::new(),
            html: "x".repeat(MAX_SANDBOXED_COMPONENT_DRAFT_BYTES + 1),
            css: String::new(),
            js_functions: String::new(),
            argument_schema: BTreeMap::new(),
            sample_arguments: BTreeMap::new(),
        };
        assert_eq!(
            validate_draft(oversized),
            Err(SandboxedComponentAdministrationError::InvalidInput { field: "body" })
        );

        let nul = BTreeMap::from([("nested".to_owned(), serde_json::json!({"value":"a\0b"}))]);
        assert_eq!(
            validate_json_object(&nul, "sample_arguments"),
            Err(SandboxedComponentAdministrationError::InvalidInput {
                field: "sample_arguments"
            })
        );

        let mut nested = serde_json::json!(true);
        for _ in 0..MAX_JSON_NESTING_DEPTH {
            nested = serde_json::json!({"next": nested});
        }
        let too_deep = BTreeMap::from([("root".to_owned(), nested)]);
        assert_eq!(
            validate_json_object(&too_deep, "argument_schema"),
            Err(SandboxedComponentAdministrationError::InvalidInput {
                field: "argument_schema"
            })
        );
    }

    #[tokio::test]
    async fn dynamic_authorization_validates_namespace_agent_and_object_before_the_port() {
        let user = auth(Role::User);
        for (name, agent, arguments) in [
            ("showQuote", "agent-1", serde_json::json!({})),
            ("custom_ab", "", serde_json::json!({})),
            ("custom_ab", "agent-1", serde_json::json!([])),
        ] {
            assert!(matches!(
                authorize_sandboxed_component(
                    &NoSandboxedComponentAdministration,
                    &user,
                    name.to_owned(),
                    BotId::new(agent),
                    arguments,
                )
                .await,
                Err(AppError::MalformedPayload { .. })
            ));
        }
        assert!(matches!(
            authorize_sandboxed_component(
                &NoSandboxedComponentAdministration,
                &user,
                "custom_ab".to_owned(),
                BotId::new("agent-1"),
                serde_json::json!({"title":"ok"}),
            )
            .await,
            Err(AppError::DependencyUnavailable {
                dependency: "sandboxed_components"
            })
        ));
    }
}
