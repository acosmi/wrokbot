//! First-party built-in tool catalog and the narrow ports their executors need.

use core::time::Duration;

use async_trait::async_trait;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, AttemptId, BotId, CapabilityId, CatalogGeneration, DeploymentId, PolicyDecisionId,
    RunId, TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::memory::{MemoryKind, MemorySensitivity};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::tool::metadata::{
    ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    ToolMetadata, ToolName,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ports::MemoryAdministrationError;
use crate::provider::ProviderToolDefinition;
use crate::use_cases::memory::{validate_content, validate_tags};

/// Stable first-party catalog name for the explicit memory tool.
pub const REMEMBER_TOOL_NAME: &str = "remember";
/// Initial first-party catalog generation. It changes whenever schema/metadata semantics change.
pub const BUILTIN_TOOL_CATALOG_GENERATION: u64 = 1;

/// Scope vocabulary exposed to the model. Concrete IDs always come from the active run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberToolScope {
    /// All of the current user's agents.
    User,
    /// The authoritative Bot of the active run.
    Bot,
    /// The authoritative thread of the active run.
    Thread,
}

/// Closed, model-supplied arguments for the explicit `remember` tool.
#[derive(Clone, PartialEq, Eq)]
pub struct RememberToolArguments {
    memory_kind: MemoryKind,
    scope: RememberToolScope,
    content: String,
    tags: Vec<String>,
    sensitivity: MemorySensitivity,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RememberToolWire {
    memory_kind: MemoryKind,
    scope: RememberToolScope,
    content: String,
    tags: Vec<String>,
    sensitivity: MemorySensitivity,
}

impl core::fmt::Debug for RememberToolArguments {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RememberToolArguments")
            .field("memory_kind", &self.memory_kind)
            .field("scope", &self.scope)
            .field("content_bytes", &self.content.len())
            .field("tag_count", &self.tags.len())
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

impl RememberToolArguments {
    /// Memory kind.
    #[must_use]
    pub const fn memory_kind(&self) -> MemoryKind {
        self.memory_kind
    }

    /// Requested scope class; target IDs are never model supplied.
    #[must_use]
    pub const fn scope(&self) -> RememberToolScope {
        self.scope
    }

    /// Validated content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Validated tags.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> MemorySensitivity {
        self.sensitivity
    }
}

/// Parse and apply the same byte/tag limits as the explicit-memory application use case.
pub fn parse_remember_tool_arguments(value: &Value) -> Result<RememberToolArguments, AppError> {
    let wire: RememberToolWire = serde_json::from_value(value.clone())
        .map_err(|_| AppError::MalformedPayload { field: "arguments" })?;
    let mut arguments = RememberToolArguments {
        memory_kind: wire.memory_kind,
        scope: wire.scope,
        content: wire.content,
        tags: wire.tags,
        sensitivity: wire.sensitivity,
    };
    validate_content(&arguments.content)?;
    validate_tags(&arguments.tags)?;
    arguments.tags.sort();
    arguments.tags.dedup();
    Ok(arguments)
}

/// Provider-visible remember definition. The same schema bytes feed [`remember_tool_metadata`].
#[must_use]
pub fn remember_provider_tool() -> ProviderToolDefinition {
    ProviderToolDefinition {
        name: REMEMBER_TOOL_NAME.to_owned(),
        description: "Persist an explicit user-requested preference or sourced fact. Use only when the user asks to remember something.".to_owned(),
        input_schema: remember_schema(),
    }
}

/// Authoritative metadata consumed by the unique tool pipeline.
#[must_use]
pub fn remember_tool_metadata() -> ToolMetadata {
    let schema = remember_schema();
    let schema_bytes = serde_json::to_vec(&schema).expect("static remember schema serializes");
    ToolMetadata {
        name: ToolName::new(REMEMBER_TOOL_NAME).expect("static remember tool name is valid"),
        schema_hash: Sha256Digest::of(&schema_bytes),
        catalog_generation: CatalogGeneration::new(BUILTIN_TOOL_CATALOG_GENERATION),
        effect: EffectClassification::declared(Effect::Write),
        idempotency: Idempotency::NonIdempotent,
        parallel_safe: false,
        timeout: Duration::from_secs(5),
        approval_class: ApprovalClass::NotRequired,
        sandbox: SandboxRequirement::None,
        limits: ToolLimits {
            max_input_bytes: 70 * 1024,
            max_output_bytes: 1024,
            max_model_visible_bytes: 1024,
        },
        resource_locks: Vec::new(),
    }
}

/// Fully authoritative request presented to the remember-tool storage port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberToolMemoryRequest {
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    auth_generation: AuthGeneration,
    run: RunId,
    bot: BotId,
    thread: ThreadId,
    call: ToolCallId,
    attempt: AttemptId,
    decision: PolicyDecisionId,
    capability: CapabilityId,
    args_hash: Sha256Digest,
    schema_hash: Sha256Digest,
    catalog_generation: CatalogGeneration,
    target: openbot_domain::tool::approval::ApprovalTarget,
    arguments: RememberToolArguments,
}

impl RememberToolMemoryRequest {
    /// Derive every effect field from the redeemed execution envelope; model input cannot supply
    /// identities, authority, or an alternate body. Deployment comes from the host assembly.
    pub fn from_execution(
        deployment: DeploymentId,
        call: &crate::tool::ExecutableToolCall,
        proof: &openbot_domain::tool::pipeline::RedeemedCapability,
    ) -> Result<Self, MemoryAdministrationError> {
        if call.metadata().name.as_str() != REMEMBER_TOOL_NAME || call.capability_id() != proof.id()
        {
            return Err(MemoryAdministrationError::Corrupt {
                field: "remember_binding",
            });
        }
        let arguments = parse_remember_tool_arguments(call.arguments().as_value())
            .map_err(|_| MemoryAdministrationError::InvalidInput { field: "arguments" })?;
        Ok(Self {
            deployment,
            tenant: call.tenant().clone(),
            actor: call.actor().actor().clone(),
            auth_generation: call.auth_generation(),
            run: call.run().clone(),
            bot: call.actor().bot().clone(),
            thread: call.thread().clone(),
            call: call.call_id().clone(),
            attempt: call.attempt_id().clone(),
            decision: call.decision_id().clone(),
            capability: proof.id().clone(),
            args_hash: call.arguments().canonical_hash(),
            schema_hash: call.metadata().schema_hash,
            catalog_generation: call.metadata().catalog_generation,
            target: call.target().clone(),
            arguments,
        })
    }

    /// Configured deployment.
    pub const fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }
    /// Original tenant.
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    /// Original actor.
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }
    /// Generation of the original executable call.
    pub const fn auth_generation(&self) -> AuthGeneration {
        self.auth_generation
    }
    /// Original run.
    pub const fn run(&self) -> &RunId {
        &self.run
    }
    /// Original Bot.
    pub const fn bot(&self) -> &BotId {
        &self.bot
    }
    /// Original thread.
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }
    /// Original tool call.
    pub const fn call(&self) -> &ToolCallId {
        &self.call
    }
    /// Original attempt.
    pub const fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
    /// Original decision.
    pub const fn decision(&self) -> &PolicyDecisionId {
        &self.decision
    }
    /// Identity of the consumed capability.
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }
    /// Canonical body binding; not an exportable receipt field.
    pub const fn args_hash(&self) -> &Sha256Digest {
        &self.args_hash
    }
    /// Original catalog schema binding.
    pub const fn schema_hash(&self) -> &Sha256Digest {
        &self.schema_hash
    }
    /// Original catalog generation.
    pub const fn catalog_generation(&self) -> CatalogGeneration {
        self.catalog_generation
    }
    /// Original authoritative target scope.
    pub const fn target(&self) -> &openbot_domain::tool::approval::ApprovalTarget {
        &self.target
    }
    /// Parsed original body.
    pub const fn arguments(&self) -> &RememberToolArguments {
        &self.arguments
    }
}

/// A same-transaction historical business commit, independent of current memory lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedMemoryEffect {
    /// Internal business object originally created.
    pub memory_id: String,
    /// Immutable receipt identity; not returned to the model.
    pub receipt_id: String,
}

/// Storage boundary used only after the complete decision/attempt/capability pipeline.
#[async_trait]
pub trait RememberToolMemory: Send + Sync {
    /// Create one `origin=remember_tool` record and derive fact provenance from the active run.
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<CommittedMemoryEffect, MemoryAdministrationError>;
}

fn remember_schema() -> Value {
    json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{
            "memoryKind":{"type":"string","enum":["preference","fact"]},
            "scope":{"type":"string","enum":["user","bot","thread"]},
            "content":{"type":"string","minLength":1,"maxLength":65536},
            "tags":{
                "type":"array",
                "maxItems":32,
                "items":{"type":"string","minLength":1,"maxLength":64}
            },
            "sensitivity":{"type":"string","enum":["normal","sensitive"],"default":"normal"}
        },
        "required":["memoryKind","scope","content","tags","sensitivity"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_schema_and_metadata_share_one_hash_and_closed_argument_shape() {
        let definition = remember_provider_tool();
        let metadata = remember_tool_metadata();
        assert_eq!(definition.name, REMEMBER_TOOL_NAME);
        assert_eq!(
            metadata.schema_hash,
            Sha256Digest::of(&serde_json::to_vec(&definition.input_schema).unwrap())
        );
        assert_eq!(
            definition.input_schema["required"]
                .as_array()
                .unwrap()
                .len(),
            definition.input_schema["properties"]
                .as_object()
                .unwrap()
                .len(),
            "OpenAI strict=true requires every property to be required"
        );
        let parsed = parse_remember_tool_arguments(&json!({
            "memoryKind":"preference",
            "scope":"user",
            "content":"tea",
            "tags":["drink","drink"],
            "sensitivity":"normal"
        }))
        .unwrap();
        assert_eq!(parsed.tags(), ["drink"]);
        assert_eq!(parsed.sensitivity(), MemorySensitivity::Normal);
        assert!(
            parse_remember_tool_arguments(&json!({
                "memoryKind":"preference",
                "scope":"user",
                "content":"tea",
                "tags":[],
                "sensitivity":"normal",
                "owner":"attacker"
            }))
            .is_err()
        );
    }
}
