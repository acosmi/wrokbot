//! First-party built-in tool catalog and the narrow ports their executors need.

use core::time::Duration;

use async_trait::async_trait;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, CatalogGeneration, RunId, TenantId, ThreadId};
use openbot_contracts::memory::{MemoryKind, MemoryRecord, MemorySensitivity};
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
    /// Deployment tenant.
    pub tenant: TenantId,
    /// Current actor/owner.
    pub actor: ActorId,
    /// Generation revalidated in the memory INSERT transaction.
    pub auth_generation: AuthGeneration,
    /// Active run.
    pub run: RunId,
    /// Active run Bot.
    pub bot: BotId,
    /// Active run thread.
    pub thread: ThreadId,
    /// Validated model arguments without any target ID or provenance field.
    pub arguments: RememberToolArguments,
}

/// Storage boundary used only after the complete decision/attempt/capability pipeline.
#[async_trait]
pub trait RememberToolMemory: Send + Sync {
    /// Create one `origin=remember_tool` record and derive fact provenance from the active run.
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError>;
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
