//! MCP per-user connection DTOs shared by Server, Desktop and Leptos/WASM.

use core::fmt;
use std::sync::Arc;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq as _;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Existing skill slug wire grammar: 2–40 lowercase ASCII letters, digits or internal hyphens.
#[must_use]
pub fn valid_skill_slug(slug: &str) -> bool {
    (2..=40).contains(&slug.len())
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

/// Maximum UTF-8 bytes in one stored skill instruction, shared by management and run snapshots.
pub const MAX_SKILL_INSTRUCTIONS_BYTES: usize = 64 * 1024;

/// Supported confidential-client authentication at MCP token/revocation endpoints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpOAuthClientAuthMethod {
    /// HTTP Basic per RFC 6749 §2.3.1.
    #[default]
    ClientSecretBasic,
    /// Form-body client authentication for providers that explicitly advertise it.
    ClientSecretPost,
}

/// Deployment OAuth client registration. Clone shares, rather than duplicates, the zeroizing
/// client-secret allocation; Debug never renders it.
#[derive(Clone)]
pub struct McpOAuthClientRegistration {
    client_id: String,
    client_secret: Arc<Zeroizing<String>>,
    issuer: String,
    auth_method: McpOAuthClientAuthMethod,
    resource_metadata_url: Option<String>,
}

impl McpOAuthClientRegistration {
    /// Validate the bounded wire fields and move the secret into a zeroizing allocation.
    pub fn new(
        client_id: String,
        client_secret: String,
        issuer: String,
        auth_method: McpOAuthClientAuthMethod,
        resource_metadata_url: Option<String>,
    ) -> Result<Self, McpOAuthClientRegistrationError> {
        Self::with_zeroizing_secret(
            client_id,
            Zeroizing::new(client_secret),
            issuer,
            auth_method,
            resource_metadata_url,
        )
    }

    /// Accept a transient secret allocation from a write-only input. Validation failures erase the
    /// allocation too; successful construction shares this exact allocation without a plain copy.
    pub fn with_zeroizing_secret(
        client_id: String,
        client_secret: Zeroizing<String>,
        issuer: String,
        auth_method: McpOAuthClientAuthMethod,
        resource_metadata_url: Option<String>,
    ) -> Result<Self, McpOAuthClientRegistrationError> {
        if !valid_component(&client_id, 4 * 1024)
            || !valid_component(&client_secret, 16 * 1024)
            || !valid_component(&issuer, 8 * 1024)
            || resource_metadata_url
                .as_ref()
                .is_some_and(|value| !valid_component(value, 8 * 1024))
        {
            return Err(McpOAuthClientRegistrationError);
        }
        Ok(Self {
            client_id,
            client_secret: Arc::new(client_secret),
            issuer,
            auth_method,
            resource_metadata_url,
        })
    }

    /// Registered client id (not a secret).
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Explicit secret exposure only for vault sealing or protocol request construction.
    #[must_use]
    pub fn expose_client_secret(&self) -> &str {
        self.client_secret.as_str()
    }

    /// Authorization-server issuer that this registration is bound to.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Registered token endpoint client-auth method.
    #[must_use]
    pub const fn auth_method(&self) -> McpOAuthClientAuthMethod {
        self.auth_method
    }

    /// Optional administrator-pinned protected-resource metadata URL.
    #[must_use]
    pub fn resource_metadata_url(&self) -> Option<&str> {
        self.resource_metadata_url.as_deref()
    }
}

impl fmt::Debug for McpOAuthClientRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpOAuthClientRegistration")
            .field("client_id_bytes", &self.client_id.len())
            .field("client_secret", &"[redacted]")
            .field("issuer", &"[configured]")
            .field("auth_method", &self.auth_method)
            .field(
                "resource_metadata_url",
                &self.resource_metadata_url.is_some(),
            )
            .finish()
    }
}

impl PartialEq for McpOAuthClientRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.issuer == other.issuer
            && self.auth_method == other.auth_method
            && self.resource_metadata_url == other.resource_metadata_url
            && bool::from(
                self.client_secret
                    .as_bytes()
                    .ct_eq(other.client_secret.as_bytes()),
            )
    }
}

impl Eq for McpOAuthClientRegistration {}

impl Serialize for McpOAuthClientRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            client_id: &'a str,
            client_secret: &'a str,
            issuer: &'a str,
            token_endpoint_auth_method: McpOAuthClientAuthMethod,
            #[serde(skip_serializing_if = "Option::is_none")]
            resource_metadata_url: Option<&'a str>,
        }
        Wire {
            client_id: self.client_id(),
            client_secret: self.expose_client_secret(),
            issuer: self.issuer(),
            token_endpoint_auth_method: self.auth_method,
            resource_metadata_url: self.resource_metadata_url(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpOAuthClientRegistration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            client_id: String,
            #[serde(deserialize_with = "crate::secret_text::deserialize")]
            client_secret: Zeroizing<String>,
            issuer: String,
            #[serde(default)]
            token_endpoint_auth_method: McpOAuthClientAuthMethod,
            #[serde(default)]
            resource_metadata_url: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::with_zeroizing_secret(
            wire.client_id,
            wire.client_secret,
            wire.issuer,
            wire.token_endpoint_auth_method,
            wire.resource_metadata_url,
        )
        .map_err(D::Error::custom)
    }
}

/// Registration contained an empty, oversized or NUL-bearing field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("mcp_oauth_client_registration_invalid")]
pub struct McpOAuthClientRegistrationError;

/// Successful OAuth-client registration acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpOAuthClientRegistered {
    /// Always true for the successful reply variant.
    pub ok: bool,
}

/// Closed catalogue selection shared by Server and Desktop framing. Endpoint and transport are
/// resolved by the application; a renderer may only select the reviewed key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCuratedServerSelection {
    /// Reviewed catalogue key; never an arbitrary endpoint or vendor configuration.
    pub key: String,
}

/// Result of adding or refreshing one reviewed server catalogue entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerMutation {
    /// Stable curated/server id.
    pub server_id: String,
    /// Monotonic catalog generation committed by PostgreSQL.
    pub catalog_generation: u64,
    /// Number of tools currently present in the refreshed server catalogue.
    pub tool_count: u32,
    /// Existing grants suspended because identity/schema/effect no longer matched.
    pub suspended_grants: u32,
}

/// Authentication presentation used by the deployment-wide Plugins administration surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpAdminAuthentication {
    /// Anonymous remote MCP.
    #[serde(rename = "none")]
    None,
    /// One deployment-owned bearer credential.
    #[serde(rename = "deployment-bearer")]
    DeploymentBearer,
    /// Actor-owned OAuth connection backed by a deployment OAuth client.
    #[serde(rename = "user-oauth")]
    UserOAuth,
}

/// Closed effect vocabulary shown by Plugins administration and bound into grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAdminToolEffect {
    /// Read-only data access.
    Read,
    /// Mutating data access.
    Write,
    /// Process or operation execution.
    Execute,
    /// Network side effect.
    Network,
    /// Credential-affecting side effect.
    Credential,
}

/// One compile-time reviewed connector catalogue item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAdminCatalogueEntry {
    /// Stable catalogue key.
    pub key: String,
    /// Human-readable title.
    pub title: String,
    /// Vendor name.
    pub vendor: String,
    /// Short product summary.
    pub summary: String,
    /// Vendor documentation URL.
    pub docs_url: String,
    /// Authentication mode without any credential material.
    pub auth: McpAdminAuthentication,
    /// Whether an administrator must supply an instance hostname.
    pub per_instance: bool,
}

/// One authoritative tool row on the Plugins administration surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAdminTool {
    /// Owning server id.
    pub server_id: String,
    /// Raw vendor tool name.
    pub name: String,
    /// Bounded vendor description.
    pub description: String,
    /// Exact catalogued JSON Schema.
    pub input_schema: serde_json::Value,
    /// Human-readable `<server>/<tool>` grant reference.
    #[serde(rename = "ref")]
    pub reference: String,
    /// First-party effect classification.
    pub effect: McpAdminToolEffect,
    /// Stable Agent ids holding an active, current-generation grant.
    pub granted_to: Vec<String>,
}

/// One configured MCP/Drive server and its current authoritative catalog projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAdminServer {
    /// Stable server id.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Vendor/hostname presentation.
    pub vendor: String,
    /// Configured endpoint; never contains credentials.
    pub url: String,
    /// Reviewed catalogue summary, or empty for custom servers.
    pub summary: String,
    /// Reviewed vendor documentation URL, or empty for custom servers.
    pub docs_url: String,
    /// `first-party` or `custom`.
    pub provenance: String,
    /// Authentication scheme resolved by Rust from transport and credential kind, never guessed
    /// from `has_credential` or a vendor name in the GUI.
    pub authentication: McpAdminAuthentication,
    /// Whether a deployment credential pointer is present.
    pub has_credential: bool,
    /// Last successful catalog refresh.
    pub tools_refreshed_at: Option<OffsetDateTime>,
    /// Stable local error code only; remote response bodies are never projected.
    pub last_error: Option<String>,
    /// Actor id that last added/updated the server.
    pub added_by: Option<String>,
    /// Canonical exact numeric CIDRs explicitly authorized for this custom server.
    pub egress_allow_cidrs: Vec<String>,
    /// Current tools only.
    pub tools: Vec<McpAdminTool>,
}

/// One skill visible to the current actor on the shared Plugins surface.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAdminSkill {
    /// Stable row id.
    pub id: String,
    /// Stable skill slug.
    pub slug: String,
    /// Owner actor, or `None` for a deployment skill.
    pub owner_user_id: Option<String>,
    /// Human-readable title.
    pub title: String,
    /// Short summary.
    pub summary: String,
    /// Instruction body.
    pub instructions: String,
    /// Provenance label.
    pub origin: String,
    /// Actor that installed it, when known.
    pub installed_by: Option<String>,
    /// Stable Agent ids holding a grant.
    pub granted_to: Vec<String>,
}

impl fmt::Debug for McpAdminSkill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAdminSkill")
            .field("id", &self.id)
            .field("slug", &self.slug)
            .field(
                "scope",
                &if self.owner_user_id.is_some() {
                    "personal"
                } else {
                    "deployment"
                },
            )
            .field("title_bytes", &self.title.len())
            .field("summary_bytes", &self.summary.len())
            .field("instructions_bytes", &self.instructions.len())
            .field("origin", &self.origin)
            .field("installed_by_present", &self.installed_by.is_some())
            .field("granted_count", &self.granted_to.len())
            .finish()
    }
}

/// Complete signed-in Plugins page projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAdminPage {
    /// Compile-time reviewed catalogue.
    pub catalogue: Vec<McpAdminCatalogueEntry>,
    /// Always false in v4: shared Bot callback credentials were constructively removed.
    pub bots_may_call_back: bool,
    /// Deployment-wide configured servers.
    pub servers: Vec<McpAdminServer>,
    /// Deployment or actor-visible skills.
    pub skills: Vec<McpAdminSkill>,
    /// Exact configured OAuth callback URI, if this distribution can complete OAuth.
    pub redirect_uri: Option<String>,
}

/// Admin-controlled custom Streamable HTTP server registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpCustomServerRegistration {
    /// Stable lower-case slug.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// HTTPS Streamable HTTP endpoint.
    pub url: String,
    /// Optional deployment-owned bearer credential.
    #[serde(default)]
    pub credential_id: Option<String>,
    /// Exact numeric CIDRs that may override the default private/special-address deny policy.
    #[serde(default)]
    pub egress_allow_cidrs: Vec<String>,
}

/// Successful configured-server deletion acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerRemoved {
    /// Always true for the successful reply variant.
    pub ok: bool,
}

/// Closed plugin grant kind shared by MCP tools and skills.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginGrantKind {
    /// One current MCP tool reference.
    Mcp,
    /// One installed skill slug.
    Skill,
}

/// Create/update request for an actor-owned or deployment-wide skill.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginSkillMutation {
    /// Stable slash-command slug.
    pub slug: String,
    /// Human-readable title.
    pub title: String,
    /// Optional short summary.
    #[serde(default)]
    pub summary: String,
    /// Instructions injected only when the skill is explicitly invoked.
    pub instructions: String,
    /// `true` creates a deployment-owned skill and therefore requires an administrator.
    #[serde(default, rename = "global")]
    pub deployment_wide: bool,
}

impl fmt::Debug for PluginSkillMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSkillMutation")
            .field("slug", &self.slug)
            .field("title_bytes", &self.title.len())
            .field("summary_bytes", &self.summary.len())
            .field("instructions_bytes", &self.instructions.len())
            .field("deployment_wide", &self.deployment_wide)
            .finish()
    }
}

/// Current actor-visible skill list after a successful mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSkills {
    /// Deployment skills plus the actor's own, or all skills for an administrator.
    pub skills: Vec<McpAdminSkill>,
}

/// Grant/revoke request. Actor and role always come from `AuthContext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginGrantMutation {
    /// MCP or skill.
    pub kind: PluginGrantKind,
    /// MCP `<server>/<tool>` reference or skill slug.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Stable target Agent id.
    pub agent_id: String,
}

/// Successful skill removal or grant/revoke acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginMutationAcknowledged {
    /// Always true for the successful reply variant.
    pub ok: bool,
}

impl PluginMutationAcknowledged {
    /// Construct the only successful acknowledgement.
    #[must_use]
    pub const fn success() -> Self {
        Self { ok: true }
    }
}

/// One current MCP tool offered to this actor through one visible Agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedPluginTool {
    /// Stable `<server>/<tool>` grant reference.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Collision-free model-facing name.
    pub tool_name: String,
    /// Bounded catalog description.
    pub description: String,
    /// Exact current catalog schema.
    pub input_schema: serde_json::Value,
}

/// One granted instruction visible to the current actor through one Agent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedPluginSkill {
    /// Stable slash-command slug.
    pub slug: String,
    /// Human-readable title.
    pub title: String,
    /// Short summary.
    pub summary: String,
    /// Bounded instructions.
    pub instructions: String,
}

impl fmt::Debug for GrantedPluginSkill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantedPluginSkill")
            .field("slug", &self.slug)
            .field("title_bytes", &self.title.len())
            .field("summary_bytes", &self.summary.len())
            .field("instructions_bytes", &self.instructions.len())
            .finish()
    }
}

/// Current actor-specific plugins usable through one visible Agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedPlugins {
    /// Current catalog/grant/credential intersection.
    pub tools: Vec<GrantedPluginTool>,
    /// Granted deployment or actor-owned skills.
    pub skills: Vec<GrantedPluginSkill>,
}

impl McpServerRemoved {
    /// Construct the only successful acknowledgement.
    #[must_use]
    pub const fn success() -> Self {
        Self { ok: true }
    }
}

impl McpOAuthClientRegistered {
    /// Construct the only successful acknowledgement.
    #[must_use]
    pub const fn success() -> Self {
        Self { ok: true }
    }
}

fn valid_component(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_registration_transfers_one_secret_allocation_and_keeps_closed_decoding() {
        let secret = Zeroizing::new("allocation-canary".to_owned());
        let address = secret.as_ptr();
        let input = McpOAuthClientRegistration::with_zeroizing_secret(
            "client".to_owned(),
            secret,
            "https://issuer.example".to_owned(),
            McpOAuthClientAuthMethod::ClientSecretBasic,
            None,
        )
        .unwrap();
        assert_eq!(input.expose_client_secret().as_ptr(), address);
        assert_eq!(input.clone().expose_client_secret().as_ptr(), address);
        assert!(!format!("{input:?}").contains("allocation-canary"));
        assert!(serde_json::from_str::<McpOAuthClientRegistration>(r#"{"clientId":"client","clientSecret":"allocation-canary","issuer":"https://issuer.example","role":"admin"}"#).is_err());
    }

    #[test]
    fn oauth_client_wire_round_trips_but_debug_never_contains_the_secret() {
        let raw = r#"{"clientId":"client","clientSecret":"CLIENT-SECRET-CANARY","issuer":"https://issuer.example","tokenEndpointAuthMethod":"client_secret_basic"}"#;
        let registration: McpOAuthClientRegistration = serde_json::from_str(raw).unwrap();
        assert!(!format!("{registration:?}").contains("CLIENT-SECRET-CANARY"));
        let shared = registration.clone();
        drop(registration);
        assert_eq!(shared.expose_client_secret(), "CLIENT-SECRET-CANARY");
        let encoded = serde_json::to_value(&shared).unwrap();
        assert_eq!(encoded["clientSecret"], "CLIENT-SECRET-CANARY");
        assert_eq!(encoded["tokenEndpointAuthMethod"], "client_secret_basic");
    }

    #[test]
    fn empty_or_nul_client_fields_are_rejected() {
        assert!(
            McpOAuthClientRegistration::new(
                String::new(),
                "secret".to_owned(),
                "https://issuer.example".to_owned(),
                McpOAuthClientAuthMethod::ClientSecretBasic,
                None,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<McpOAuthClientRegistration>(
                r#"{"clientId":"client","clientSecret":"bad\u0000secret","issuer":"https://issuer.example"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn custom_server_wire_is_closed_and_private_egress_is_explicit() {
        let registration: McpCustomServerRegistration = serde_json::from_str(
            r#"{"id":"internal-search","title":"Internal search","url":"https://search.internal.example/mcp","egressAllowCidrs":["10.8.0.0/16"]}"#,
        )
        .unwrap();
        assert_eq!(registration.egress_allow_cidrs, ["10.8.0.0/16"]);
        assert!(
            serde_json::from_str::<McpCustomServerRegistration>(
                r#"{"id":"x","title":"X","url":"https://x.example/mcp","host":"10.0.0.1"}"#
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(McpAdminAuthentication::UserOAuth).unwrap(),
            "user-oauth"
        );
    }

    #[test]
    fn skill_and_grant_wire_cannot_smuggle_actor_or_catalog_binding() {
        let skill: PluginSkillMutation = serde_json::from_str(
            r#"{"slug":"standup-notes","title":"Standup notes","instructions":"Summarize decisions.","global":true}"#,
        )
        .unwrap();
        assert!(skill.deployment_wide);
        let skill_debug = format!("{skill:?}");
        assert!(!skill_debug.contains("Standup notes"));
        assert!(!skill_debug.contains("Summarize decisions"));
        let grant: PluginGrantMutation =
            serde_json::from_str(r#"{"kind":"mcp","ref":"notes/search","agentId":"bot-1"}"#)
                .unwrap();
        assert_eq!(grant.kind, PluginGrantKind::Mcp);
        assert_eq!(grant.reference, "notes/search");
        for smuggled in [
            r#"{"slug":"x","title":"X","instructions":"Y","ownerUserId":"admin"}"#,
            r#"{"kind":"mcp","ref":"notes/search","agentId":"bot-1","effect":"read"}"#,
        ] {
            assert!(serde_json::from_str::<serde_json::Value>(smuggled).is_ok());
        }
        assert!(
            serde_json::from_str::<PluginSkillMutation>(
                r#"{"slug":"x","title":"X","instructions":"Y","ownerUserId":"admin"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PluginGrantMutation>(
                r#"{"kind":"mcp","ref":"notes/search","agentId":"bot-1","effect":"read"}"#
            )
            .is_err()
        );
        let projection = GrantedPluginSkill {
            slug: "standup-notes".to_owned(),
            title: "Private title".to_owned(),
            summary: "Private summary".to_owned(),
            instructions: "Private instructions".to_owned(),
        };
        let projection_debug = format!("{projection:?}");
        assert!(!projection_debug.contains("Private title"));
        assert!(!projection_debug.contains("Private summary"));
        assert!(!projection_debug.contains("Private instructions"));
    }
}

/// Closed screen that may receive the browser after an OAuth callback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpOAuthReturnTo {
    /// Personal connected-accounts settings.
    #[default]
    Settings,
    /// Deployment plugin administration detail.
    Admin,
}

/// One actor-owned OAuth connection. Credential identifiers and secrets are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpConnection {
    /// Stable MCP server/catalog identifier.
    pub server_id: String,
    /// Exact scope string returned by the authorization server.
    pub scope: String,
    /// Database-clock connection timestamp.
    pub connected_at: OffsetDateTime,
}

/// Personal connection page payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpConnections {
    /// Stable ids for compile-time reviewed user-OAuth servers enabled by this deployment.
    /// Display metadata is intentionally absent and remains a localized UI concern.
    pub available_server_ids: Vec<String>,
    /// Connections owned by the authenticated actor only.
    pub connections: Vec<McpConnection>,
    /// Exact registered Server callback URI, or `None` when this deployment cannot run OAuth.
    pub redirect_uri: Option<String>,
}

/// Authorization URL created from validated vendor metadata and one-time state/PKCE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpOAuthAuthorization {
    /// URL the browser may deliberately navigate to.
    pub authorization_url: String,
}

/// Vendor-side status after local access has already been tombstoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpVendorRevocationStatus {
    /// Vendor confirmed token revocation.
    Revoked,
    /// Local deny is final, while vendor revocation remains queued for reconciliation.
    Pending,
}

/// Disconnect receipt. It never implies vendor revocation when only local retirement succeeded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpConnectionDisconnected {
    /// Stable server identifier that was disconnected.
    pub server_id: String,
    /// Truthful vendor reconciliation state.
    pub vendor_revocation: McpVendorRevocationStatus,
}

#[cfg(test)]
mod personal_connection_tests {
    use super::*;

    #[test]
    fn personal_connections_wire_is_closed_and_contains_no_server_metadata_or_credentials() {
        let page = McpConnections {
            available_server_ids: vec!["google-drive".to_owned()],
            connections: vec![McpConnection {
                server_id: "google-drive".to_owned(),
                scope: "drive.readonly".to_owned(),
                connected_at: OffsetDateTime::UNIX_EPOCH,
            }],
            redirect_uri: Some("https://app.example.test/api/plugins/oauth/callback".to_owned()),
        };
        assert_eq!(page.available_server_ids, ["google-drive"]);
        assert_eq!(page.connections.len(), 1);
        let encoded = serde_json::to_value(&page).unwrap();
        assert_eq!(
            encoded
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["availableServerIds", "connections", "redirectUri"]
        );
        assert_eq!(
            serde_json::from_value::<McpConnections>(encoded).unwrap(),
            page
        );
        assert!(
            serde_json::from_str::<McpConnections>(
                r#"{"availableServerIds":[],"connections":[],"redirectUri":null,"clientSecret":"forbidden"}"#
            )
            .is_err()
        );
    }
}
