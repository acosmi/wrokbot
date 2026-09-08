//! Authenticated compiled-component catalogue reads and additive build announcements.

use std::collections::BTreeSet;

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
#[cfg(test)]
use openbot_contracts::components::ComponentDecisionRefusal;
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME, BOT_ACTIVITY_FUNCTION_NAME,
    COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES, CompiledComponentManifestEntry,
    ComponentApprovalAnswer, ComponentCatalogueAdded, ComponentCatalogueRequest,
    ComponentChoiceAnswer, ComponentDataFunctions, ComponentDecision, ComponentDecisionRequest,
    ComponentFunctionCall, ComponentFunctionCallRequest, ComponentFunctionData,
    ComponentGovernanceMutation, ComponentGovernanceReceipt, ComponentHumanDecisionAnswer,
    ComponentHumanDecisionRequest, ComponentHumanDecisionResolved, ComponentRecord,
    ComponentRecords, GrantedCompiledComponents, MAX_COMPONENT_DESCRIPTION_BYTES,
    PendingComponentHumanDecision, PendingComponentHumanDecisions, RECENT_REFUSALS_FUNCTION_NAME,
    SHOW_ACTIVITY_REPORT_COMPONENT_NAME, compiled_component_manifest,
    component_data_function_manifest, validate_component_human_decision_arguments,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::text::trim_ecmascript;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::tool::args::ToolArguments;

const MAX_RUNTIME_IDENTIFIERS: usize = 1024;
const MAX_RUNTIME_IDENTIFIER_BYTES: usize = 256;
const MAX_HUMAN_DECISION_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_HUMAN_DECISION_ARRAY_ITEMS: usize = 100;
const MAX_HUMAN_DECISION_STRING_BYTES: usize = 16 * 1024;
/// Surface/HITL upper bound; the Agent run deadline may end the wait sooner.
pub const COMPONENT_HUMAN_DECISION_TTL: core::time::Duration =
    core::time::Duration::from_secs(30 * 60);

/// Authority already resolved for one compiled-component runtime request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentRuntimeScope {
    /// Verified tenant, used as the outermost Agent/package boundary.
    pub tenant: TenantId,
    /// Verified current actor.
    pub actor: ActorId,
    /// Whether verified roles include administrator.
    pub admin: bool,
    /// Untrusted Agent target after bounded identifier validation.
    pub agent_id: BotId,
}

/// Authority for one internal surface/HITL request; never serialized by a transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentHumanDecisionScope {
    /// Verified deployment.
    pub deployment: DeploymentId,
    /// Verified tenant.
    pub tenant: TenantId,
    /// Verified actor who owns the waiting run.
    pub actor: ActorId,
    /// Session generation at request time.
    pub auth_generation: openbot_contracts::auth::AuthGeneration,
    /// Whether verified roles include administrator.
    pub admin: bool,
    /// Durable thread from the run lease.
    pub thread_id: ThreadId,
    /// Durable run from the run lease.
    pub run_id: RunId,
    /// Durable Agent from the run lease.
    pub agent_id: BotId,
}

/// Validated request persisted by the component human-decision port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentHumanDecisionDraft {
    /// Server-minted decision identity.
    pub decision_id: String,
    /// Durable provider pairing id.
    pub provider_call_id: String,
    /// Exact decision component.
    pub component_name: String,
    /// Closed, bounded renderer arguments.
    pub arguments: serde_json::Value,
    /// Order-independent canonical arguments digest.
    pub arguments_hash: Sha256Digest,
    /// Bounded wait upper bound.
    pub ttl: core::time::Duration,
}

/// Validated, bounded arguments for one build-owned component data function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentFunctionArguments {
    /// Effective lookback for `botActivity`.
    BotActivity {
        /// Integer days in `1..=90`.
        days: u16,
    },
    /// Effective row cap for `recentRefusals`.
    RecentRefusals {
        /// Integer limit in `1..=50`.
        limit: u16,
    },
}

/// Application-validated call plan; `None` arguments means the function is absent from this build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentFunctionCallPlan {
    /// Stable requested function identity.
    pub function: String,
    /// Bounded function arguments, or `None` for an unknown build function that must be audited.
    pub arguments: Option<ComponentFunctionArguments>,
}

/// Stable component-catalogue failures without SQL values or model/user source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComponentAdministrationError {
    /// Closed manifest/request validation failed.
    #[error("component_invalid_input field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// PostgreSQL or another required local dependency is unavailable.
    #[error("component_unavailable")]
    Unavailable,
    /// A durable row cannot be projected into the closed contract.
    #[error("component_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// The named Agent is absent or not runnable by the verified actor in this tenant.
    #[error("component_agent_not_visible")]
    NotVisible,
    /// An already-resolved decision was answered differently or is no longer pending.
    #[error("component_request_conflict")]
    Conflict,
    /// A catalogue/audit transaction may have committed and must be reconciled.
    #[error("component_commit_unknown")]
    CommitUnknown,
}

impl ComponentAdministrationError {
    /// Map into the stable application error taxonomy.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::Conflict => AppError::RequestConflict {
                resource: "component_human_decision",
            },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "components",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Production port for component governance reads and additive catalogue synchronization.
#[async_trait]
pub trait ComponentAdministration: Send + Sync {
    /// List all durable compiled-component governance records for an authenticated actor.
    async fn list_components(
        &self,
        auth: &AuthContext,
    ) -> Result<ComponentRecords, ComponentAdministrationError>;

    /// Insert missing exact build entries; existing governance rows must remain byte-for-byte owned
    /// by administration.
    async fn sync_catalogue(
        &self,
        auth: &AuthContext,
        entries: &[CompiledComponentManifestEntry],
    ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError>;

    /// Atomically apply one administrator-owned governance change and its audit record.
    async fn update_component_governance(
        &self,
        _auth: &AuthContext,
        _mutation: &ComponentGovernanceMutation,
    ) -> Result<ComponentRecord, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// List the current build's published, non-withheld renderer grants for one runnable Agent.
    async fn list_components_for_agent(
        &self,
        _scope: &ComponentRuntimeScope,
        _renderer_names: &[String],
    ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// Re-authorize one component and all data functions declared by this exact invocation.
    async fn decide_component(
        &self,
        _scope: &ComponentRuntimeScope,
        _component_name: &str,
        _build_has_renderer: bool,
        _functions: &[String],
    ) -> Result<ComponentDecision, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// Repeat every runtime check, execute one bounded data read and append called/failed audit.
    async fn call_component_function(
        &self,
        _scope: &ComponentRuntimeScope,
        _component_name: &str,
        _build_has_renderer: bool,
        _plan: &ComponentFunctionCallPlan,
    ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// Create one pending surface/HITL request and append its requested audit atomically.
    async fn request_component_human_decision(
        &self,
        _scope: &ComponentHumanDecisionScope,
        _draft: &ComponentHumanDecisionDraft,
    ) -> Result<PendingComponentHumanDecision, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// List pending decisions visible to the verified actor.
    async fn list_component_human_decisions(
        &self,
        _auth: &AuthContext,
    ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// Resolve one pending decision with an answer normalized against its stored arguments.
    async fn resolve_component_human_decision(
        &self,
        _auth: &AuthContext,
        _decision_id: &str,
        _answer: &ComponentHumanDecisionAnswer,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    /// Wait for an answer using durable state as the source of truth.
    async fn wait_component_human_decision(
        &self,
        _scope: &ComponentHumanDecisionScope,
        _decision_id: &str,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }
}

/// Fail-closed default for hosts that have not attached component persistence.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoComponentAdministration;

#[async_trait]
impl ComponentAdministration for NoComponentAdministration {
    async fn list_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<ComponentRecords, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }

    async fn sync_catalogue(
        &self,
        _auth: &AuthContext,
        _entries: &[CompiledComponentManifestEntry],
    ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
        Err(ComponentAdministrationError::Unavailable)
    }
}

/// List the authenticated deployment's durable compiled-component governance rows.
pub async fn list_components(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
) -> Result<ComponentRecords, AppError> {
    port.list_components(auth)
        .await
        .map_err(ComponentAdministrationError::into_app_error)
}

/// Validate browser-repeated metadata against the build-owned manifest, then insert only missing
/// rows through the authority port.
pub async fn sync_component_catalogue(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    request: ComponentCatalogueRequest,
) -> Result<ComponentCatalogueAdded, AppError> {
    validate_manifest_entries(&request.components).map_err(|error| error.into_app_error())?;
    port.sync_catalogue(auth, &request.components)
        .await
        .map_err(ComponentAdministrationError::into_app_error)
}

/// Validate and apply one fresh-admin component-governance mutation.
pub async fn update_component_governance(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    mutation: ComponentGovernanceMutation,
) -> Result<ComponentGovernanceReceipt, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    let mutation = normalize_governance_mutation(mutation)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let component = port
        .update_component_governance(auth, &mutation)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_governance_receipt(&mutation, &component)
        .map_err(ComponentAdministrationError::into_app_error)?;
    Ok(ComponentGovernanceReceipt { component })
}

fn normalize_governance_mutation(
    mutation: ComponentGovernanceMutation,
) -> Result<ComponentGovernanceMutation, ComponentAdministrationError> {
    validate_component_name(mutation.component_name())?;
    match mutation {
        ComponentGovernanceMutation::SetAgentGrant {
            component_name,
            agent_id,
            granted,
        } => {
            validate_runtime_identifier(agent_id.as_str(), "agent_id")?;
            Ok(ComponentGovernanceMutation::SetAgentGrant {
                component_name,
                agent_id,
                granted,
            })
        }
        ComponentGovernanceMutation::SetFunctionGrant {
            component_name,
            function,
            granted,
        } => {
            validate_component_name(&function)?;
            if !component_data_function_manifest()
                .iter()
                .any(|entry| entry.name == function)
            {
                return Err(ComponentAdministrationError::InvalidInput { field: "function" });
            }
            Ok(ComponentGovernanceMutation::SetFunctionGrant {
                component_name,
                function,
                granted,
            })
        }
        ComponentGovernanceMutation::SetPublication {
            component_name,
            published,
        } => Ok(ComponentGovernanceMutation::SetPublication {
            component_name,
            published,
        }),
        ComponentGovernanceMutation::SaveDraft {
            component_name,
            description,
        } => {
            let description = trim_ecmascript(&description);
            if description.is_empty()
                || description.len() > MAX_COMPONENT_DESCRIPTION_BYTES
                || description.as_bytes().contains(&0)
            {
                return Err(ComponentAdministrationError::InvalidInput {
                    field: "description",
                });
            }
            Ok(ComponentGovernanceMutation::SaveDraft {
                component_name,
                description: description.to_owned(),
            })
        }
    }
}

fn validate_governance_receipt(
    mutation: &ComponentGovernanceMutation,
    component: &ComponentRecord,
) -> Result<(), ComponentAdministrationError> {
    if component.name != mutation.component_name()
        || component.draft_description.is_empty()
        || component.draft_description.len() > MAX_COMPONENT_DESCRIPTION_BYTES
        || component.draft_description.as_bytes().contains(&0)
        || component.published
            && (component.published_description.is_none() || component.published_at.is_none())
        || component.has_unpublished_changes
            != (component.draft_description
                != component.published_description.as_deref().unwrap_or(""))
    {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_governance_receipt",
        });
    }
    match mutation {
        ComponentGovernanceMutation::SetAgentGrant {
            agent_id, granted, ..
        } if component
            .withheld_from
            .iter()
            .any(|value| value == agent_id.as_str())
            == *granted =>
        {
            Err(ComponentAdministrationError::Corrupt {
                field: "component_agent_grant",
            })
        }
        ComponentGovernanceMutation::SetFunctionGrant {
            function, granted, ..
        } if component.functions.contains(function) != *granted => {
            Err(ComponentAdministrationError::Corrupt {
                field: "component_function_grant",
            })
        }
        ComponentGovernanceMutation::SetPublication { published, .. }
            if component.published != *published
                || *published
                    && (component.published_description.as_deref()
                        != Some(component.draft_description.as_str())
                        || component.has_unpublished_changes) =>
        {
            Err(ComponentAdministrationError::Corrupt {
                field: "component_publication",
            })
        }
        ComponentGovernanceMutation::SaveDraft { description, .. }
            if component.draft_description != *description =>
        {
            Err(ComponentAdministrationError::Corrupt {
                field: "component_draft",
            })
        }
        _ => Ok(()),
    }
}

/// List the current build's actual runtime grants for one current-actor-runnable Agent.
pub async fn list_components_for_agent(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    agent_id: BotId,
) -> Result<GrantedCompiledComponents, AppError> {
    validate_runtime_identifier(agent_id.as_str(), "agent_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    let scope = runtime_scope(auth, agent_id);
    let renderer_names = compiled_component_manifest()
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    let granted = port
        .list_components_for_agent(&scope, &renderer_names)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_granted_components(&granted, &renderer_names)
        .map_err(ComponentAdministrationError::into_app_error)?;
    Ok(granted)
}

/// Re-authorize a component immediately before accepting one renderer tool call.
pub async fn decide_component(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    component_name: String,
    request: ComponentDecisionRequest,
) -> Result<ComponentDecision, AppError> {
    validate_component_name(&component_name)
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_runtime_identifier(request.agent_id.as_str(), "agent_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    let functions = canonicalize_functions(request.functions)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let build_has_renderer = compiled_component_manifest()
        .iter()
        .any(|entry| entry.name == component_name);
    validate_component_function_mapping(&component_name, build_has_renderer, &functions)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let scope = runtime_scope(auth, request.agent_id);
    let decision = port
        .decide_component(&scope, &component_name, build_has_renderer, &functions)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_decision(&decision, &functions)
        .map_err(ComponentAdministrationError::into_app_error)?;
    Ok(decision)
}

/// List the exact build-owned component data-function registry.
#[must_use]
pub fn list_component_data_functions() -> ComponentDataFunctions {
    ComponentDataFunctions {
        functions: component_data_function_manifest(),
    }
}

/// Execute one component-owned read after the authority port repeats every runtime check.
pub async fn call_component_function(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    component_name: String,
    request: ComponentFunctionCallRequest,
) -> Result<ComponentFunctionCall, AppError> {
    validate_component_name(&component_name)
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_runtime_identifier(request.agent_id.as_str(), "agent_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_component_name(&request.function)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let build_has_renderer = compiled_component_manifest()
        .iter()
        .any(|entry| entry.name == component_name);
    if build_has_renderer && !component_accepts_function(&component_name, &request.function) {
        return Err(
            ComponentAdministrationError::InvalidInput { field: "function" }.into_app_error(),
        );
    }
    let ComponentFunctionCallRequest {
        agent_id,
        function,
        args,
    } = request;
    let arguments = normalize_function_arguments(&function, &args)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let plan = ComponentFunctionCallPlan {
        function,
        arguments,
    };
    let scope = runtime_scope(auth, agent_id);
    let result = port
        .call_component_function(&scope, &component_name, build_has_renderer, &plan)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_function_call(&result, &plan).map_err(ComponentAdministrationError::into_app_error)?;
    Ok(result)
}

/// Create and durably await one surface/HITL answer. This internal use case is not an HTTP route.
pub async fn await_component_human_decision(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    request: ComponentHumanDecisionRequest,
) -> Result<ComponentHumanDecisionResolved, AppError> {
    let ComponentHumanDecisionRequest {
        decision_id,
        provider_call_id,
        run_id,
        thread_id,
        agent_id,
        component_name,
        arguments,
    } = request;
    validate_runtime_identifier(&decision_id, "decision_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_provider_call_id(&provider_call_id)
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_runtime_identifier(run_id.as_str(), "run_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_runtime_identifier(thread_id.as_str(), "thread_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_runtime_identifier(agent_id.as_str(), "agent_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_component_human_decision_arguments(&component_name, &arguments)
        .map_err(|_| ComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        })
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_human_decision_argument_bounds(&component_name, &arguments)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let canonical = ToolArguments::new(arguments.clone())
        .map_err(|_| ComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        })
        .map_err(ComponentAdministrationError::into_app_error)?;
    let scope = ComponentHumanDecisionScope {
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        auth_generation: auth.auth_generation(),
        admin: auth.has_role(openbot_contracts::auth::Role::Admin),
        thread_id,
        run_id,
        agent_id,
    };
    let draft = ComponentHumanDecisionDraft {
        decision_id,
        provider_call_id,
        component_name,
        arguments,
        arguments_hash: canonical.canonical_hash(),
        ttl: COMPONENT_HUMAN_DECISION_TTL,
    };
    let pending = port
        .request_component_human_decision(&scope, &draft)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    validate_pending_component_human_decision(&pending, &scope, &draft)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let resolved = port
        .wait_component_human_decision(&scope, &draft.decision_id)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    if resolved.decision_id != draft.decision_id {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_human_decision",
        }
        .into_app_error());
    }
    Ok(resolved)
}

/// List current-actor pending decisions for Web/Desktop presentation.
pub async fn list_pending_component_human_decisions(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
) -> Result<PendingComponentHumanDecisions, AppError> {
    let pending = port
        .list_component_human_decisions(auth)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    if pending.decisions.len() > MAX_RUNTIME_IDENTIFIERS {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_human_decisions",
        }
        .into_app_error());
    }
    for decision in &pending.decisions {
        validate_runtime_identifier(&decision.decision_id, "decision_id")
            .map_err(ComponentAdministrationError::into_app_error)?;
        validate_runtime_identifier(decision.run_id.as_str(), "run_id")
            .map_err(ComponentAdministrationError::into_app_error)?;
        validate_provider_call_id(&decision.provider_call_id)
            .map_err(ComponentAdministrationError::into_app_error)?;
        validate_runtime_identifier(decision.agent_id.as_str(), "agent_id")
            .map_err(ComponentAdministrationError::into_app_error)?;
        validate_component_human_decision_arguments(&decision.component_name, &decision.arguments)
            .map_err(|_| ComponentAdministrationError::Corrupt {
                field: "component_arguments",
            })
            .map_err(ComponentAdministrationError::into_app_error)?;
        validate_human_decision_argument_bounds(&decision.component_name, &decision.arguments)
            .map_err(ComponentAdministrationError::into_app_error)?;
        if decision.expires_at <= decision.requested_at {
            return Err(ComponentAdministrationError::Corrupt {
                field: "component_human_decision_time",
            }
            .into_app_error());
        }
    }
    Ok(pending)
}

/// Normalize and resolve one actor-owned pending decision.
pub async fn resolve_component_human_decision(
    port: &dyn ComponentAdministration,
    auth: &AuthContext,
    decision_id: String,
    answer: ComponentHumanDecisionAnswer,
) -> Result<ComponentHumanDecisionResolved, AppError> {
    validate_runtime_identifier(&decision_id, "decision_id")
        .map_err(ComponentAdministrationError::into_app_error)?;
    let answer = normalize_human_decision_answer(answer)
        .map_err(ComponentAdministrationError::into_app_error)?;
    let resolved = port
        .resolve_component_human_decision(auth, &decision_id, &answer)
        .await
        .map_err(ComponentAdministrationError::into_app_error)?;
    if resolved.decision_id != decision_id || resolved.answer != answer {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_human_decision",
        }
        .into_app_error());
    }
    Ok(resolved)
}

/// Check that every repeated entry is a unique, byte-exact member of this build's manifest.
pub fn validate_manifest_entries(
    entries: &[CompiledComponentManifestEntry],
) -> Result<(), ComponentAdministrationError> {
    let manifest = compiled_component_manifest();
    if entries.len() > manifest.len() {
        return Err(ComponentAdministrationError::InvalidInput {
            field: "components",
        });
    }
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(ComponentAdministrationError::InvalidInput {
                field: "component_name",
            });
        }
        if !manifest.iter().any(|known| known == entry) {
            return Err(ComponentAdministrationError::InvalidInput {
                field: "component_identity",
            });
        }
    }
    Ok(())
}

fn runtime_scope(auth: &AuthContext, agent_id: BotId) -> ComponentRuntimeScope {
    ComponentRuntimeScope {
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        admin: auth.has_role(openbot_contracts::auth::Role::Admin),
        agent_id,
    }
}

fn validate_provider_call_id(value: &str) -> Result<(), ComponentAdministrationError> {
    if value.is_empty() || value.len() > 1024 || value.as_bytes().contains(&0) {
        Err(ComponentAdministrationError::InvalidInput {
            field: "provider_call_id",
        })
    } else {
        Ok(())
    }
}

fn validate_human_decision_argument_bounds(
    component_name: &str,
    arguments: &serde_json::Value,
) -> Result<(), ComponentAdministrationError> {
    if arguments.to_string().len() > MAX_HUMAN_DECISION_ARGUMENT_BYTES {
        return Err(ComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        });
    }
    let object = arguments
        .as_object()
        .ok_or(ComponentAdministrationError::InvalidInput {
            field: "component_arguments",
        })?;
    match component_name {
        ASK_APPROVAL_COMPONENT_NAME => {
            for field in ["title", "summary", "approveLabel", "rejectLabel"] {
                if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                    validate_human_decision_string(value, "component_arguments")?;
                }
            }
            if let Some(details) = object.get("details").and_then(serde_json::Value::as_array) {
                if details.len() > MAX_HUMAN_DECISION_ARRAY_ITEMS {
                    return Err(ComponentAdministrationError::InvalidInput {
                        field: "component_arguments",
                    });
                }
                for detail in details.iter().filter_map(serde_json::Value::as_object) {
                    for field in ["label", "value"] {
                        if let Some(value) = detail.get(field).and_then(serde_json::Value::as_str) {
                            validate_human_decision_string(value, "component_arguments")?;
                        }
                    }
                }
            }
        }
        ASK_CHOICE_COMPONENT_NAME => {
            for field in ["title", "summary"] {
                if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                    validate_human_decision_string(value, "component_arguments")?;
                }
            }
            let options = object
                .get("options")
                .and_then(serde_json::Value::as_array)
                .ok_or(ComponentAdministrationError::InvalidInput {
                    field: "component_arguments",
                })?;
            if options.is_empty() || options.len() > MAX_HUMAN_DECISION_ARRAY_ITEMS {
                return Err(ComponentAdministrationError::InvalidInput {
                    field: "component_arguments",
                });
            }
            let mut ids = BTreeSet::new();
            for option in options.iter().filter_map(serde_json::Value::as_object) {
                let id = option.get("id").and_then(serde_json::Value::as_str).ok_or(
                    ComponentAdministrationError::InvalidInput {
                        field: "component_arguments",
                    },
                )?;
                if id.is_empty() || !ids.insert(id) {
                    return Err(ComponentAdministrationError::InvalidInput {
                        field: "component_arguments",
                    });
                }
                for field in ["id", "label", "description"] {
                    if let Some(value) = option.get(field).and_then(serde_json::Value::as_str) {
                        validate_human_decision_string(value, "component_arguments")?;
                    }
                }
            }
        }
        _ => {
            return Err(ComponentAdministrationError::InvalidInput {
                field: "component_name",
            });
        }
    }
    Ok(())
}

fn validate_human_decision_string(
    value: &str,
    field: &'static str,
) -> Result<(), ComponentAdministrationError> {
    if value.len() > MAX_HUMAN_DECISION_STRING_BYTES || value.as_bytes().contains(&0) {
        Err(ComponentAdministrationError::InvalidInput { field })
    } else {
        Ok(())
    }
}

fn validate_pending_component_human_decision(
    pending: &PendingComponentHumanDecision,
    scope: &ComponentHumanDecisionScope,
    draft: &ComponentHumanDecisionDraft,
) -> Result<(), ComponentAdministrationError> {
    if pending.decision_id != draft.decision_id
        || pending.run_id != scope.run_id
        || pending.provider_call_id != draft.provider_call_id
        || pending.agent_id != scope.agent_id
        || pending.component_name != draft.component_name
        || pending.arguments != draft.arguments
        || pending.expires_at <= pending.requested_at
    {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_human_decision",
        });
    }
    Ok(())
}

fn normalize_human_decision_answer(
    answer: ComponentHumanDecisionAnswer,
) -> Result<ComponentHumanDecisionAnswer, ComponentAdministrationError> {
    match answer {
        ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer { decision, note }) => {
            let note = note
                .map(|note| trim_ecmascript(&note).to_owned())
                .filter(|note| !note.is_empty());
            if note.as_ref().is_some_and(|note| {
                note.len() > COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES || note.as_bytes().contains(&0)
            }) {
                return Err(ComponentAdministrationError::InvalidInput {
                    field: "component_answer",
                });
            }
            Ok(ComponentHumanDecisionAnswer::Approval(
                ComponentApprovalAnswer { decision, note },
            ))
        }
        ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer { choice, label }) => {
            if choice.is_empty() || label.is_empty() {
                return Err(ComponentAdministrationError::InvalidInput {
                    field: "component_answer",
                });
            }
            validate_human_decision_string(&choice, "component_answer")?;
            validate_human_decision_string(&label, "component_answer")?;
            Ok(ComponentHumanDecisionAnswer::Choice(
                ComponentChoiceAnswer { choice, label },
            ))
        }
    }
}

fn canonicalize_functions(
    functions: Vec<String>,
) -> Result<Vec<String>, ComponentAdministrationError> {
    if functions.len() > MAX_RUNTIME_IDENTIFIERS {
        return Err(ComponentAdministrationError::InvalidInput { field: "functions" });
    }
    let mut unique = BTreeSet::new();
    for function in functions {
        validate_component_name(&function)?;
        unique.insert(function);
    }
    Ok(unique.into_iter().collect())
}

fn validate_component_function_mapping(
    component: &str,
    build_has_renderer: bool,
    functions: &[String],
) -> Result<(), ComponentAdministrationError> {
    if !build_has_renderer {
        return Ok(());
    }
    let valid = if component == SHOW_ACTIVITY_REPORT_COMPONENT_NAME {
        functions.len() == 1 && component_accepts_function(component, &functions[0])
    } else {
        functions.is_empty()
    };
    if valid {
        Ok(())
    } else {
        Err(ComponentAdministrationError::InvalidInput { field: "functions" })
    }
}

fn component_accepts_function(component: &str, function: &str) -> bool {
    component == SHOW_ACTIVITY_REPORT_COMPONENT_NAME
        && matches!(
            function,
            BOT_ACTIVITY_FUNCTION_NAME | RECENT_REFUSALS_FUNCTION_NAME
        )
}

fn normalize_function_arguments(
    function: &str,
    args: &serde_json::Value,
) -> Result<Option<ComponentFunctionArguments>, ComponentAdministrationError> {
    let object = match args {
        serde_json::Value::Object(object) => Some(object),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Array(_) => None,
    };
    if let Some(object) = object
        && object
            .keys()
            .any(|key| !matches!(key.as_str(), "days" | "limit"))
    {
        return Err(ComponentAdministrationError::InvalidInput { field: "args" });
    }
    Ok(match function {
        BOT_ACTIVITY_FUNCTION_NAME => Some(ComponentFunctionArguments::BotActivity {
            days: bounded_integer(object.and_then(|args| args.get("days")), 7, 1, 90),
        }),
        RECENT_REFUSALS_FUNCTION_NAME => Some(ComponentFunctionArguments::RecentRefusals {
            limit: bounded_integer(object.and_then(|args| args.get("limit")), 10, 1, 50),
        }),
        _ => None,
    })
}

fn bounded_integer(value: Option<&serde_json::Value>, fallback: u16, min: u16, max: u16) -> u16 {
    let Some(value) = value.and_then(serde_json::Value::as_f64) else {
        return fallback;
    };
    let truncated = value.trunc();
    if truncated <= f64::from(min) {
        min
    } else if truncated >= f64::from(max) {
        max
    } else {
        truncated as u16
    }
}

fn validate_component_name(value: &str) -> Result<(), ComponentAdministrationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Err(ComponentAdministrationError::InvalidInput {
            field: "component_name",
        })
    } else {
        Ok(())
    }
}

fn validate_runtime_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), ComponentAdministrationError> {
    if value.is_empty()
        || value.len() > MAX_RUNTIME_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        Err(ComponentAdministrationError::InvalidInput { field })
    } else {
        Ok(())
    }
}

fn validate_granted_components(
    granted: &GrantedCompiledComponents,
    renderer_names: &[String],
) -> Result<(), ComponentAdministrationError> {
    if granted.components.len() > renderer_names.len() {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_grants",
        });
    }
    let renderers = renderer_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut previous = None::<&str>;
    for component in &granted.components {
        validate_component_name(&component.name).map_err(|_| {
            ComponentAdministrationError::Corrupt {
                field: "component_name",
            }
        })?;
        if !renderers.contains(component.name.as_str())
            || previous.is_some_and(|previous| previous >= component.name.as_str())
            || component.description.is_empty()
            || component.description.len() > MAX_COMPONENT_DESCRIPTION_BYTES
            || component.description.as_bytes().contains(&0)
        {
            return Err(ComponentAdministrationError::Corrupt {
                field: "component_grants",
            });
        }
        previous = Some(&component.name);
    }
    Ok(())
}

fn validate_decision(
    decision: &ComponentDecision,
    functions: &[String],
) -> Result<(), ComponentAdministrationError> {
    if !decision.is_consistent() {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_decision",
        });
    }
    if let Some(function) = decision
        .refusal
        .as_ref()
        .and_then(openbot_contracts::components::ComponentDecisionRefusal::function)
        && functions
            .binary_search_by(|candidate| candidate.as_str().cmp(function))
            .is_err()
    {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_function",
        });
    }
    Ok(())
}

fn validate_function_call(
    result: &ComponentFunctionCall,
    plan: &ComponentFunctionCallPlan,
) -> Result<(), ComponentAdministrationError> {
    if !result.is_consistent() {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_function_call",
        });
    }
    if let Some(function) = result
        .refusal
        .as_ref()
        .and_then(openbot_contracts::components::ComponentDecisionRefusal::function)
        && function != plan.function
    {
        return Err(ComponentAdministrationError::Corrupt {
            field: "component_function",
        });
    }
    match (&result.data, plan.arguments) {
        (
            Some(ComponentFunctionData::BotActivity(_)),
            Some(ComponentFunctionArguments::BotActivity { .. }),
        )
        | (
            Some(ComponentFunctionData::RecentRefusals(_)),
            Some(ComponentFunctionArguments::RecentRefusals { .. }),
        )
        | (None, _) => Ok(()),
        _ => Err(ComponentAdministrationError::Corrupt {
            field: "component_function_data",
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::components::{
        CompiledComponentKind, ComponentRecord, SHOW_QUOTE_COMPONENT_NAME,
    };
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use time::OffsetDateTime;

    use super::*;

    type RuntimeDecisionCall = (ComponentRuntimeScope, String, bool, Vec<String>);

    #[derive(Default)]
    struct FakeComponents {
        syncs: Mutex<Vec<Vec<CompiledComponentManifestEntry>>>,
        mutations: Mutex<Vec<ComponentGovernanceMutation>>,
        runtime_lists: Mutex<Vec<(ComponentRuntimeScope, Vec<String>)>>,
        runtime_decisions: Mutex<Vec<RuntimeDecisionCall>>,
        function_calls: Mutex<
            Vec<(
                ComponentRuntimeScope,
                String,
                bool,
                ComponentFunctionCallPlan,
            )>,
        >,
        human_requests: Mutex<Vec<(ComponentHumanDecisionScope, ComponentHumanDecisionDraft)>>,
        human_resolves: Mutex<Vec<(String, ComponentHumanDecisionAnswer)>>,
    }

    #[async_trait]
    impl ComponentAdministration for FakeComponents {
        async fn list_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<ComponentRecords, ComponentAdministrationError> {
            Ok(ComponentRecords {
                components: vec![ComponentRecord {
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    title: "Quotation".to_owned(),
                    kind: CompiledComponentKind::Card,
                    draft_description: "quote".to_owned(),
                    published_description: Some("quote".to_owned()),
                    published: true,
                    published_at: Some(OffsetDateTime::UNIX_EPOCH),
                    updated_by: Some("the build".to_owned()),
                    updated_at: OffsetDateTime::UNIX_EPOCH,
                    has_unpublished_changes: false,
                    withheld_from: Vec::new(),
                    functions: Vec::new(),
                }],
            })
        }

        async fn sync_catalogue(
            &self,
            _auth: &AuthContext,
            entries: &[CompiledComponentManifestEntry],
        ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
            self.syncs.lock().unwrap().push(entries.to_vec());
            Ok(ComponentCatalogueAdded {
                added: entries.iter().map(|entry| entry.name.clone()).collect(),
            })
        }

        async fn update_component_governance(
            &self,
            _auth: &AuthContext,
            mutation: &ComponentGovernanceMutation,
        ) -> Result<ComponentRecord, ComponentAdministrationError> {
            self.mutations.lock().unwrap().push(mutation.clone());
            let mut record = ComponentRecord {
                name: mutation.component_name().to_owned(),
                title: "Quotation".to_owned(),
                kind: CompiledComponentKind::Card,
                draft_description: "quote".to_owned(),
                published_description: Some("quote".to_owned()),
                published: true,
                published_at: Some(OffsetDateTime::UNIX_EPOCH),
                updated_by: Some("actor".to_owned()),
                updated_at: OffsetDateTime::UNIX_EPOCH,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: Vec::new(),
            };
            match mutation {
                ComponentGovernanceMutation::SetAgentGrant {
                    agent_id, granted, ..
                } if !granted => record.withheld_from.push(agent_id.as_str().to_owned()),
                ComponentGovernanceMutation::SetFunctionGrant {
                    function, granted, ..
                } if *granted => record.functions.push(function.clone()),
                ComponentGovernanceMutation::SetPublication { published, .. } => {
                    record.published = *published;
                }
                ComponentGovernanceMutation::SaveDraft { description, .. } => {
                    record.draft_description = description.clone();
                    record.has_unpublished_changes = true;
                }
                _ => {}
            }
            Ok(record)
        }

        async fn list_components_for_agent(
            &self,
            scope: &ComponentRuntimeScope,
            renderer_names: &[String],
        ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
            self.runtime_lists
                .lock()
                .unwrap()
                .push((scope.clone(), renderer_names.to_vec()));
            Ok(GrantedCompiledComponents {
                components: vec![openbot_contracts::components::GrantedCompiledComponent {
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    description: "published quote".to_owned(),
                }],
            })
        }

        async fn decide_component(
            &self,
            scope: &ComponentRuntimeScope,
            component_name: &str,
            build_has_renderer: bool,
            functions: &[String],
        ) -> Result<ComponentDecision, ComponentAdministrationError> {
            self.runtime_decisions.lock().unwrap().push((
                scope.clone(),
                component_name.to_owned(),
                build_has_renderer,
                functions.to_vec(),
            ));
            if !build_has_renderer {
                return Ok(ComponentDecision::refused(
                    ComponentDecisionRefusal::UnknownComponent,
                ));
            }
            if let Some(function) = functions.iter().find(|name| name.as_str() == "missing") {
                return Ok(ComponentDecision::refused(
                    ComponentDecisionRefusal::FunctionNotGranted {
                        function: function.clone(),
                    },
                ));
            }
            Ok(ComponentDecision::allowed())
        }

        async fn call_component_function(
            &self,
            scope: &ComponentRuntimeScope,
            component_name: &str,
            build_has_renderer: bool,
            plan: &ComponentFunctionCallPlan,
        ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
            self.function_calls.lock().unwrap().push((
                scope.clone(),
                component_name.to_owned(),
                build_has_renderer,
                plan.clone(),
            ));
            match plan.arguments {
                Some(ComponentFunctionArguments::BotActivity { days }) => Ok(
                    ComponentFunctionCall::succeeded(ComponentFunctionData::BotActivity(
                        openbot_contracts::components::BotActivityReport {
                            days,
                            rows: Vec::new(),
                        },
                    )),
                ),
                Some(ComponentFunctionArguments::RecentRefusals { .. }) => Ok(
                    ComponentFunctionCall::succeeded(ComponentFunctionData::RecentRefusals(
                        openbot_contracts::components::RecentRefusalsReport { rows: Vec::new() },
                    )),
                ),
                None => Ok(ComponentFunctionCall::refused(
                    openbot_contracts::components::ComponentDecisionRefusal::FunctionUnavailable {
                        function: plan.function.clone(),
                    },
                )),
            }
        }

        async fn request_component_human_decision(
            &self,
            scope: &ComponentHumanDecisionScope,
            draft: &ComponentHumanDecisionDraft,
        ) -> Result<PendingComponentHumanDecision, ComponentAdministrationError> {
            self.human_requests
                .lock()
                .unwrap()
                .push((scope.clone(), draft.clone()));
            Ok(PendingComponentHumanDecision {
                decision_id: draft.decision_id.clone(),
                run_id: scope.run_id.clone(),
                provider_call_id: draft.provider_call_id.clone(),
                agent_id: scope.agent_id.clone(),
                component_name: draft.component_name.clone(),
                arguments: draft.arguments.clone(),
                requested_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
            })
        }

        async fn list_component_human_decisions(
            &self,
            _auth: &AuthContext,
        ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
            Ok(PendingComponentHumanDecisions::default())
        }

        async fn resolve_component_human_decision(
            &self,
            _auth: &AuthContext,
            decision_id: &str,
            answer: &ComponentHumanDecisionAnswer,
        ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
            self.human_resolves
                .lock()
                .unwrap()
                .push((decision_id.to_owned(), answer.clone()));
            Ok(ComponentHumanDecisionResolved {
                decision_id: decision_id.to_owned(),
                answer: answer.clone(),
                replayed: false,
            })
        }

        async fn wait_component_human_decision(
            &self,
            _scope: &ComponentHumanDecisionScope,
            decision_id: &str,
        ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
            Ok(ComponentHumanDecisionResolved {
                decision_id: decision_id.to_owned(),
                answer: ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                    decision: openbot_contracts::components::ComponentApprovalDecision::Approved,
                    note: None,
                }),
                replayed: false,
            })
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    fn admin_auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("admin"),
            [Role::User, Role::Admin],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn any_authenticated_role_can_list_and_only_exact_manifest_reaches_the_port() {
        let port = FakeComponents::default();
        assert_eq!(
            list_components(&port, &auth())
                .await
                .unwrap()
                .components
                .len(),
            1
        );
        let manifest = compiled_component_manifest();
        let expected = manifest
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            sync_component_catalogue(
                &port,
                &auth(),
                ComponentCatalogueRequest {
                    components: manifest.clone(),
                },
            )
            .await
            .unwrap()
            .added,
            expected
        );
        assert_eq!(port.syncs.lock().unwrap().as_slice(), [manifest]);
    }

    #[tokio::test]
    async fn governance_requires_admin_normalizes_inputs_and_validates_the_authoritative_receipt() {
        let port = FakeComponents::default();
        let mutation = ComponentGovernanceMutation::SaveDraft {
            component_name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
            description: "  edited quote\u{00a0}".to_owned(),
        };
        assert_eq!(
            update_component_governance(&port, &auth(), mutation.clone()).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        );
        assert!(port.mutations.lock().unwrap().is_empty());

        let receipt = update_component_governance(&port, &admin_auth(), mutation)
            .await
            .unwrap();
        assert_eq!(receipt.component.draft_description, "edited quote");
        assert_eq!(port.mutations.lock().unwrap().len(), 1);
        assert_eq!(
            update_component_governance(
                &port,
                &admin_auth(),
                ComponentGovernanceMutation::SetFunctionGrant {
                    component_name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    function: "notShipped".to_owned(),
                    granted: true,
                },
            )
            .await,
            Err(AppError::MalformedPayload { field: "function" })
        );
        assert_eq!(port.mutations.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unknown_tampered_and_duplicate_entries_fail_before_the_port() {
        let port = FakeComponents::default();
        let mut tampered = compiled_component_manifest();
        tampered[0].description.push_str(" attacker");
        let duplicate = vec![
            compiled_component_manifest().remove(0),
            compiled_component_manifest().remove(0),
        ];
        for components in [tampered, duplicate] {
            assert_eq!(
                sync_component_catalogue(&port, &auth(), ComponentCatalogueRequest { components },)
                    .await
                    .unwrap_err()
                    .code()
                    .as_str(),
                "malformed_payload"
            );
        }
        assert!(port.syncs.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn runtime_scope_manifest_and_function_set_are_authoritative_and_bounded() {
        let port = FakeComponents::default();
        let grants = list_components_for_agent(&port, &auth(), BotId::new("agent-one"))
            .await
            .unwrap();
        assert_eq!(grants.components[0].name, SHOW_QUOTE_COMPONENT_NAME);
        {
            let lists = port.runtime_lists.lock().unwrap();
            assert_eq!(lists.len(), 1);
            assert_eq!(lists[0].0.actor.as_str(), "actor");
            assert_eq!(lists[0].0.tenant.as_str(), "tenant");
            assert!(!lists[0].0.admin);
            assert_eq!(lists[0].1.len(), compiled_component_manifest().len());
        }

        let allowed = decide_component(
            &port,
            &auth(),
            SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
            ComponentDecisionRequest {
                agent_id: BotId::new("agent-one"),
                functions: vec![
                    BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                    BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                ],
            },
        )
        .await
        .unwrap();
        assert_eq!(allowed, ComponentDecision::allowed());
        let unknown = decide_component(
            &port,
            &auth(),
            "showStale".to_owned(),
            ComponentDecisionRequest {
                agent_id: BotId::new("agent-one"),
                functions: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            unknown,
            ComponentDecision::refused(ComponentDecisionRefusal::UnknownComponent)
        );
        let decisions = port.runtime_decisions.lock().unwrap();
        assert_eq!(decisions[0].3, [BOT_ACTIVITY_FUNCTION_NAME]);
        assert!(decisions[0].2);
        assert!(!decisions[1].2);
    }

    #[tokio::test]
    async fn malformed_runtime_identifiers_never_reach_authority_port() {
        let port = FakeComponents::default();
        assert!(
            list_components_for_agent(&port, &auth(), BotId::new("\n"))
                .await
                .is_err()
        );
        assert!(
            decide_component(
                &port,
                &auth(),
                "bad/name".to_owned(),
                ComponentDecisionRequest {
                    agent_id: BotId::new("agent-one"),
                    functions: Vec::new(),
                },
            )
            .await
            .is_err()
        );
        assert!(
            decide_component(
                &port,
                &auth(),
                SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                ComponentDecisionRequest {
                    agent_id: BotId::new("agent-one"),
                    functions: vec![BOT_ACTIVITY_FUNCTION_NAME.to_owned()],
                },
            )
            .await
            .is_err()
        );
        assert!(port.runtime_lists.lock().unwrap().is_empty());
        assert!(port.runtime_decisions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn function_registry_arguments_and_result_shape_are_closed_before_and_after_the_port() {
        let port = FakeComponents::default();
        assert_eq!(
            list_component_data_functions()
                .functions
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [BOT_ACTIVITY_FUNCTION_NAME, RECENT_REFUSALS_FUNCTION_NAME]
        );
        let result = call_component_function(
            &port,
            &auth(),
            SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
            ComponentFunctionCallRequest {
                agent_id: BotId::new("agent-one"),
                function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                args: serde_json::json!({"days": 120.9}),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            result.data,
            Some(ComponentFunctionData::BotActivity(
                openbot_contracts::components::BotActivityReport { days: 90, .. }
            ))
        ));
        assert_eq!(
            port.function_calls.lock().unwrap()[0].3.arguments,
            Some(ComponentFunctionArguments::BotActivity { days: 90 })
        );

        let fallback = call_component_function(
            &port,
            &auth(),
            SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
            ComponentFunctionCallRequest {
                agent_id: BotId::new("agent-one"),
                function: RECENT_REFUSALS_FUNCTION_NAME.to_owned(),
                args: serde_json::json!({"days": 30}),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            fallback.data,
            Some(ComponentFunctionData::RecentRefusals(_))
        ));
        assert_eq!(
            port.function_calls.lock().unwrap()[1].3.arguments,
            Some(ComponentFunctionArguments::RecentRefusals { limit: 10 })
        );

        let malformed = call_component_function(
            &port,
            &auth(),
            SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
            ComponentFunctionCallRequest {
                agent_id: BotId::new("agent-one"),
                function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                args: serde_json::json!({"query": "untrusted"}),
            },
        )
        .await;
        assert!(matches!(
            malformed,
            Err(AppError::MalformedPayload { field: "args" })
        ));
        assert_eq!(port.function_calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn human_decision_scope_hash_bounds_and_answer_normalization_precede_the_port() {
        let port = FakeComponents::default();
        let resolved = await_component_human_decision(
            &port,
            &auth(),
            ComponentHumanDecisionRequest {
                decision_id: "decision-1".to_owned(),
                provider_call_id: "provider-call-1".to_owned(),
                run_id: RunId::new("run-1"),
                thread_id: ThreadId::new("thread-1"),
                agent_id: BotId::new("bot-1"),
                component_name: ASK_APPROVAL_COMPONENT_NAME.to_owned(),
                arguments: serde_json::json!({
                    "title":"Refund?",
                    "summary":"The charge was duplicated."
                }),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            resolved.answer,
            ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: openbot_contracts::components::ComponentApprovalDecision::Approved,
                note: None,
            })
        ));
        {
            let requests = port.human_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0.actor.as_str(), "actor");
            assert_eq!(requests[0].0.auth_generation.get(), 1);
            assert_eq!(requests[0].0.agent_id.as_str(), "bot-1");
            assert_eq!(requests[0].1.arguments_hash.to_hex().len(), 64);
        }

        let normalized = resolve_component_human_decision(
            &port,
            &auth(),
            "decision-1".to_owned(),
            ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: openbot_contracts::components::ComponentApprovalDecision::Declined,
                note: Some(" \u{feff}because no ".to_owned()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            normalized.answer,
            ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: openbot_contracts::components::ComponentApprovalDecision::Declined,
                note: Some("because no".to_owned()),
            })
        );

        let duplicate_choice = await_component_human_decision(
            &port,
            &auth(),
            ComponentHumanDecisionRequest {
                decision_id: "decision-2".to_owned(),
                provider_call_id: "provider-call-2".to_owned(),
                run_id: RunId::new("run-1"),
                thread_id: ThreadId::new("thread-1"),
                agent_id: BotId::new("bot-1"),
                component_name: ASK_CHOICE_COMPONENT_NAME.to_owned(),
                arguments: serde_json::json!({
                    "title":"Where?",
                    "options":[
                        {"id":"same","label":"One"},
                        {"id":"same","label":"Two"}
                    ]
                }),
            },
        )
        .await;
        assert!(matches!(
            duplicate_choice,
            Err(AppError::MalformedPayload {
                field: "component_arguments"
            })
        ));
        assert_eq!(port.human_requests.lock().unwrap().len(), 1);
    }
}
