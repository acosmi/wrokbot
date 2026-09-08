//! PostgreSQL MCP catalog generation and stale-grant suspension.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use openbot_application::ProviderToolDefinition;
use openbot_contracts::ids::{ActorId, BotId, CatalogGeneration};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::hash::{CanonicalWriter, Sha256Digest};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::tool::metadata::{Effect, ToolName};
use openbot_domain::vault::{CredentialGeneration, SecretBytes};
use serde_json::Value;
use url::Url;

use crate::google_drive::{
    GOOGLE_DRIVE_API_BASE, GOOGLE_DRIVE_PROVENANCE, GOOGLE_DRIVE_SERVER_ID, GOOGLE_DRIVE_TRANSPORT,
    GOOGLE_DRIVE_VENDOR, google_drive_effect, google_drive_tools,
};
use crate::mcp::{McpBearerToken, McpClientError, McpListedTool, SafeRmcpClient};
use crate::mcp_credentials::PostgresMcpCredentialBroker;
use crate::mcp_egress::parse_stored_mcp_egress;
use crate::net::safe_http::CidrAllowlist;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

const MAX_COMPILED_SCHEMA_CACHE_ENTRIES: usize = 4_096;

/// Catalog refresh/read failure without remote or database payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpCatalogError {
    /// PostgreSQL or RMCP dependency unavailable.
    #[error("mcp_catalog_unavailable")]
    Unavailable,
    /// Server/catalog/grant rows violate the closed schema.
    #[error("mcp_catalog_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Server not found in this deployment.
    #[error("mcp_server_not_visible")]
    NotVisible,
}

/// Current, fully-bound tool available to a Bot.
#[derive(Clone, PartialEq)]
pub struct GrantedMcpTool {
    /// MCP server id.
    pub server_id: String,
    /// Raw vendor tool name.
    pub raw_name: String,
    /// Provider/model-visible collision-free name.
    pub model_name: String,
    /// Vendor description.
    pub description: String,
    /// Exact vendor schema.
    pub input_schema: Value,
    /// Canonical schema hash.
    pub schema_hash: Sha256Digest,
    /// First-party effect classification.
    pub effect: Effect,
    /// Current monotonic catalog generation.
    pub catalog_generation: CatalogGeneration,
    /// Deployment credential generation bound into the current grant identity.
    pub credential_generation: CredentialGeneration,
    /// SafeDialer-validated only when used; Debug never renders it.
    pub endpoint: String,
    /// Per-operation authentication mode proven by the same catalog query.
    pub authentication: McpAuthentication,
    /// Protocol adapter selected by the reviewed server row.
    pub transport: VendorTransportKind,
    /// Exact administrator-authorized CIDRs for this server's SafeDialer operations.
    pub egress_allowlist: CidrAllowlist,
}

/// Closed production vendor transport set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorTransportKind {
    /// Remote MCP Streamable HTTP.
    Mcp,
    /// Google Drive v3 GA REST adapter.
    GoogleDriveRest,
}

impl VendorTransportKind {
    /// Stable PostgreSQL value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::GoogleDriveRest => GOOGLE_DRIVE_TRANSPORT,
        }
    }

    /// Decode PostgreSQL value; legacy callers pass the already-coalesced `mcp` string.
    pub fn parse(value: &str) -> Result<Self, McpCatalogError> {
        parse_transport(value)
    }
}

/// Credential mode currently executable by the production MCP runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpAuthentication {
    /// Server accepts anonymous MCP requests.
    None,
    /// Active deployment-owned `credentials.kind=mcp` bearer.
    DeploymentBearer,
    /// Actor-owned rotating OAuth credential paired with the deployment's registered client.
    UserOAuth,
}

impl core::fmt::Debug for GrantedMcpTool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrantedMcpTool")
            .field("server_id", &self.server_id)
            .field("raw_name", &self.raw_name)
            .field("model_name", &self.model_name)
            .field("description_bytes", &self.description.len())
            .field("schema_hash", &self.schema_hash)
            .field("effect", &self.effect)
            .field("catalog_generation", &self.catalog_generation)
            .field("credential_generation", &self.credential_generation)
            .field("authentication", &self.authentication)
            .field("transport", &self.transport)
            .field("egress_allowlist_entries", &self.egress_allowlist.len())
            .field("endpoint", &"[redacted-origin]")
            .finish()
    }
}

impl GrantedMcpTool {
    /// Provider-neutral definition for built-in or remote AG-UI context.
    #[must_use]
    pub fn provider_definition(&self) -> ProviderToolDefinition {
        ProviderToolDefinition {
            name: self.model_name.clone(),
            description: self.description.clone(),
            input_schema: self.input_schema.clone(),
        }
    }
}

/// Result of one atomic catalog refresh.
#[derive(Clone, Debug, PartialEq)]
pub struct McpCatalogRefresh {
    /// New monotonic generation.
    pub generation: CatalogGeneration,
    /// Current available tools.
    pub tools: Vec<GrantedMcpTool>,
    /// Grants automatically suspended this refresh.
    pub suspended_grants: usize,
}

/// Startup refresh summary. Authenticated/OAuth servers are counted, never contacted without the
/// actor-specific credential path required by the first source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct McpCatalogSweep {
    /// Unauthenticated configured servers refreshed successfully.
    pub refreshed: usize,
    /// Unauthenticated configured servers that remain unavailable/corrupt.
    pub failed: usize,
    /// Credential-backed servers intentionally deferred to the user-OAuth runtime.
    pub authenticated_deferred: usize,
}

/// Unique production catalog store and RMCP refresh adapter.
#[derive(Clone)]
pub struct PostgresMcpCatalog {
    pool: deadpool_postgres::Pool,
    rmcp: SafeRmcpClient,
    checkpoint_key: Arc<SecretBytes>,
    validators: Arc<RwLock<BTreeMap<Sha256Digest, Arc<jsonschema::Validator>>>>,
}

impl PostgresMcpCatalog {
    /// Construct; empty audit key refuses startup.
    pub fn new(
        pool: deadpool_postgres::Pool,
        rmcp: SafeRmcpClient,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, McpCatalogError> {
        if checkpoint_key.is_empty() {
            return Err(McpCatalogError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        Ok(Self {
            pool,
            rmcp,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
            validators: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    /// Validate a model-produced argument object against the exact cached vendor schema. Resolver
    /// features are disabled at the dependency boundary, so external HTTP/file `$ref` cannot turn
    /// schema compilation into an egress side channel.
    pub async fn validate_arguments(
        &self,
        tool: &GrantedMcpTool,
        arguments: &Value,
    ) -> Result<bool, McpCatalogError> {
        if !arguments.is_object() || schema_hash(&tool.input_schema)? != tool.schema_hash {
            return Err(McpCatalogError::Corrupt {
                field: "input_schema",
            });
        }
        let cached = self
            .validators
            .read()
            .map_err(|_| McpCatalogError::Unavailable)?
            .get(&tool.schema_hash)
            .cloned();
        let validator = match cached {
            Some(validator) => validator,
            None => {
                let schema = tool.input_schema.clone();
                let compiled =
                    tokio::task::spawn_blocking(move || compile_schema(&schema).map(Arc::new))
                        .await
                        .map_err(|_| McpCatalogError::Unavailable)?
                        .map_err(|_| McpCatalogError::Corrupt {
                            field: "input_schema",
                        })?;
                let mut validators = self
                    .validators
                    .write()
                    .map_err(|_| McpCatalogError::Unavailable)?;
                if validators.len() >= MAX_COMPILED_SCHEMA_CACHE_ENTRIES {
                    validators.clear();
                }
                validators
                    .entry(tool.schema_hash)
                    .or_insert_with(|| compiled.clone())
                    .clone()
            }
        };
        let arguments = arguments.clone();
        tokio::task::spawn_blocking(move || validator.is_valid(&arguments))
            .await
            .map_err(|_| McpCatalogError::Unavailable)
    }

    /// Refresh anonymous/deployment-bearer MCP plus static Drive REST catalogs at startup. Remote
    /// user-OAuth MCP remains actor-scoped and is deliberately deferred.
    pub async fn refresh_startup_servers(
        &self,
        credentials: &PostgresMcpCredentialBroker,
    ) -> Result<McpCatalogSweep, McpCatalogError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT s.id,s.credential_id,c.kind,c.revoked_at,
                        coalesce(s.transport,'mcp') AS transport
                   FROM public.mcp_servers s
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  ORDER BY s.id",
                &[],
            )
            .await
            .map_err(query_unavailable)?;
        drop(client);
        let mut sweep = McpCatalogSweep::default();
        for row in rows {
            let server_id: String = row
                .try_get("id")
                .map_err(|_| McpCatalogError::Corrupt { field: "server_id" })?;
            let credential_id: Option<uuid::Uuid> =
                row.try_get("credential_id")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "credential_id",
                    })?;
            let kind: Option<crate::db::types::CredentialKind> =
                row.try_get("kind").map_err(|_| McpCatalogError::Corrupt {
                    field: "credential_kind",
                })?;
            let revoked: Option<time::OffsetDateTime> =
                row.try_get("revoked_at")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "revoked_at",
                    })?;
            let transport = parse_transport(
                &row.try_get::<_, String>("transport")
                    .map_err(|_| McpCatalogError::Corrupt { field: "transport" })?,
            )?;
            if transport == VendorTransportKind::GoogleDriveRest {
                match self.refresh(&server_id, None).await {
                    Ok(_) => sweep.refreshed = sweep.refreshed.saturating_add(1),
                    Err(error) => {
                        sweep.failed = sweep.failed.saturating_add(1);
                        tracing::warn!(server_id, code = %error,
                            "Drive REST startup static catalog refresh 失败");
                    }
                }
                continue;
            }
            let bearer = match (credential_id, kind, revoked) {
                (None, None, None) => None,
                (Some(_), Some(crate::db::types::CredentialKind::McpOauthClient), _) => {
                    sweep.authenticated_deferred = sweep.authenticated_deferred.saturating_add(1);
                    continue;
                }
                (Some(_), Some(crate::db::types::CredentialKind::Mcp), None) => {
                    match credentials.bearer_for(&server_id, &ActorId::new("")).await {
                        Ok(Some(bearer)) => Some(bearer),
                        Ok(None) | Err(_) => {
                            sweep.failed = sweep.failed.saturating_add(1);
                            continue;
                        }
                    }
                }
                _ => {
                    sweep.failed = sweep.failed.saturating_add(1);
                    continue;
                }
            };
            match self.refresh(&server_id, bearer).await {
                Ok(_) => sweep.refreshed = sweep.refreshed.saturating_add(1),
                Err(error) => {
                    sweep.failed = sweep.failed.saturating_add(1);
                    tracing::warn!(server_id, code = %error, "MCP startup catalog refresh 失败");
                    if let Ok(client) = self.pool.get().await {
                        let _ = client
                            .execute(
                                "UPDATE public.mcp_servers SET last_error=$2,
                                   updated_at=clock_timestamp() WHERE id=$1",
                                &[&server_id, &error.to_string()],
                            )
                            .await;
                    }
                }
            }
        }
        Ok(sweep)
    }

    /// Real remote listing followed by one catalog/grant/audit transaction.
    pub async fn refresh(
        &self,
        server_id: &str,
        bearer: Option<McpBearerToken>,
    ) -> Result<McpCatalogRefresh, McpCatalogError> {
        validate_component(server_id, "server_id")?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let server = client
            .query_opt(
                "SELECT url,vendor,provenance,coalesce(transport,'mcp') AS transport,
                        coalesce(egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs
                   FROM public.mcp_servers WHERE id=$1",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpCatalogError::NotVisible)?;
        let endpoint: String = server
            .try_get("url")
            .map_err(|_| McpCatalogError::Corrupt { field: "url" })?;
        let vendor: String = server
            .try_get("vendor")
            .map_err(|_| McpCatalogError::Corrupt { field: "vendor" })?;
        let provenance: String =
            server
                .try_get("provenance")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "provenance",
                })?;
        let transport = parse_transport(
            &server
                .try_get::<_, String>("transport")
                .map_err(|_| McpCatalogError::Corrupt { field: "transport" })?,
        )?;
        let egress_allow_cidrs: Vec<String> =
            server
                .try_get("egress_allow_cidrs")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "egress_allow_cidrs",
                })?;
        let egress_allowlist = parse_egress_allowlist(&egress_allow_cidrs)?;
        let transport_digest = transport_fingerprint(
            &endpoint,
            &vendor,
            &provenance,
            transport,
            &egress_allow_cidrs,
        )?;
        let transport_fingerprint_hex = transport_digest.to_hex();
        drop(client);
        let listed = match transport {
            VendorTransportKind::Mcp => self
                .rmcp
                .with_egress_allowlist(egress_allowlist)
                .list_tools(&endpoint, bearer)
                .await
                .map_err(|_| McpCatalogError::Unavailable)?,
            VendorTransportKind::GoogleDriveRest => {
                if server_id != GOOGLE_DRIVE_SERVER_ID
                    || endpoint != GOOGLE_DRIVE_API_BASE
                    || vendor != GOOGLE_DRIVE_VENDOR
                    || provenance != GOOGLE_DRIVE_PROVENANCE
                {
                    return Err(McpCatalogError::Corrupt {
                        field: "transport_identity",
                    });
                }
                google_drive_tools()
            }
        };
        let prepared_server_id = server_id.to_owned();
        let incoming =
            tokio::task::spawn_blocking(move || prepare_listed(&prepared_server_id, listed))
                .await
                .map_err(|_| McpCatalogError::Unavailable)??;

        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let server = transaction
            .query_opt(
                "SELECT coalesce(catalog_generation,0) AS catalog_generation,
                        coalesce(credential_generation,0) AS credential_generation,
                        url,vendor,provenance,coalesce(transport,'mcp') AS transport,
                        coalesce(egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs \
                   FROM public.mcp_servers WHERE id=$1 FOR UPDATE",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpCatalogError::NotVisible)?;
        let old_generation: i64 =
            server
                .try_get("catalog_generation")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "catalog_generation",
                })?;
        let credential_generation: i64 =
            server
                .try_get("credential_generation")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "credential_generation",
                })?;
        let locked_endpoint: String = server
            .try_get("url")
            .map_err(|_| McpCatalogError::Corrupt { field: "url" })?;
        let locked_vendor: String = server
            .try_get("vendor")
            .map_err(|_| McpCatalogError::Corrupt { field: "vendor" })?;
        let locked_provenance: String =
            server
                .try_get("provenance")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "provenance",
                })?;
        let locked_transport = parse_transport(
            &server
                .try_get::<_, String>("transport")
                .map_err(|_| McpCatalogError::Corrupt { field: "transport" })?,
        )?;
        let locked_egress_allow_cidrs: Vec<String> =
            server
                .try_get("egress_allow_cidrs")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "egress_allow_cidrs",
                })?;
        parse_egress_allowlist(&locked_egress_allow_cidrs)?;
        if locked_transport != transport
            || transport_fingerprint(
                &locked_endpoint,
                &locked_vendor,
                &locked_provenance,
                locked_transport,
                &locked_egress_allow_cidrs,
            )? != transport_digest
        {
            return Err(McpCatalogError::Unavailable);
        }
        let generation = old_generation
            .checked_add(1)
            .ok_or(McpCatalogError::Corrupt {
                field: "catalog_generation",
            })?;
        let generation_u64 = u64::try_from(generation).map_err(|_| McpCatalogError::Corrupt {
            field: "catalog_generation",
        })?;
        let now: time::OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| McpCatalogError::Corrupt { field: "clock" })?;
        let existing_rows = transaction
            .query(
                "SELECT name,description,input_schema,created_at,schema_hash,effect, \
                        catalog_generation,first_seen_at,last_seen_at,available \
                   FROM public.mcp_tools WHERE server_id=$1 FOR UPDATE",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
        let mut existing = BTreeMap::new();
        for row in existing_rows {
            let name: String = row
                .try_get("name")
                .map_err(|_| McpCatalogError::Corrupt { field: "tool_name" })?;
            validate_component(&name, "tool_name")?;
            let schema: Value =
                row.try_get("input_schema")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "input_schema",
                    })?;
            let created_at: time::OffsetDateTime =
                row.try_get("created_at")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "created_at",
                    })?;
            let stored_hash: Option<String> =
                row.try_get("schema_hash")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "schema_hash",
                    })?;
            let effect: Option<String> = row
                .try_get("effect")
                .map_err(|_| McpCatalogError::Corrupt { field: "effect" })?;
            let first_seen_at: Option<time::OffsetDateTime> = row
                .try_get("first_seen_at")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "first_seen_at",
                })?;
            let last_seen_at: Option<time::OffsetDateTime> =
                row.try_get("last_seen_at")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "last_seen_at",
                    })?;
            let hash = schema_hash(&schema)?;
            if let Some(stored) = stored_hash
                && Sha256Digest::parse_hex(&stored).ok() != Some(hash)
            {
                return Err(McpCatalogError::Corrupt {
                    field: "schema_hash",
                });
            }
            existing.insert(
                name,
                ExistingTool {
                    schema_hash: hash,
                    effect: parse_effect(effect.as_deref().unwrap_or("execute"))?,
                    first_seen_at: first_seen_at.unwrap_or(created_at),
                    last_seen_at: last_seen_at.unwrap_or(created_at),
                },
            );
        }

        let mut projected = BTreeMap::new();
        for (name, listed) in &incoming {
            let previous = existing.get(name);
            let effect = previous.map_or_else(
                || match transport {
                    VendorTransportKind::Mcp => Effect::Execute,
                    VendorTransportKind::GoogleDriveRest => google_drive_effect(name, true),
                },
                |row| row.effect,
            );
            let first_seen = previous.map_or(now, |row| row.first_seen_at);
            transaction
                .execute(
                    "INSERT INTO public.mcp_tools(
                       server_id,name,description,input_schema,created_at,schema_hash,effect,
                       catalog_generation,first_seen_at,last_seen_at,available
                     ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$5,true)
                     ON CONFLICT(server_id,name) DO UPDATE SET
                       description=excluded.description,input_schema=excluded.input_schema,
                       schema_hash=excluded.schema_hash,effect=coalesce(mcp_tools.effect,excluded.effect),
                       catalog_generation=excluded.catalog_generation,
                       first_seen_at=coalesce(mcp_tools.first_seen_at,excluded.first_seen_at),
                       last_seen_at=excluded.last_seen_at,available=true",
                    &[
                        &server_id,
                        &name,
                        &listed.description,
                        &listed.input_schema,
                        &now,
                        &listed.schema_hash.to_hex(),
                        &effect.as_str(),
                        &generation,
                        &first_seen,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            projected.insert(
                name.clone(),
                ProjectedTool {
                    schema_hash: listed.schema_hash,
                    effect,
                    available: true,
                },
            );
        }
        for (name, old) in &existing {
            if incoming.contains_key(name) {
                continue;
            }
            transaction
                .execute(
                    "UPDATE public.mcp_tools SET
                       schema_hash=$3,effect=$4,catalog_generation=coalesce(catalog_generation,0),
                       first_seen_at=coalesce(first_seen_at,$5),
                       last_seen_at=coalesce(last_seen_at,$6),available=false
                     WHERE server_id=$1 AND name=$2",
                    &[
                        &server_id,
                        &name,
                        &old.schema_hash.to_hex(),
                        &old.effect.as_str(),
                        &old.first_seen_at,
                        &old.last_seen_at,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            projected.insert(
                name.clone(),
                ProjectedTool {
                    schema_hash: old.schema_hash,
                    effect: old.effect,
                    available: false,
                },
            );
        }

        let grant_rows = transaction
            .query(
                "SELECT ref,agent_id,state,catalog_generation,schema_hash,effect, \
                        transport_fingerprint,credential_generation \
                   FROM public.plugin_grants \
                  WHERE kind='mcp' AND split_part(ref,'/',1)=$1 FOR UPDATE",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
        let mut suspended = 0usize;
        for row in grant_rows {
            let reference: String = row
                .try_get("ref")
                .map_err(|_| McpCatalogError::Corrupt { field: "grant_ref" })?;
            let agent_id: String = row
                .try_get("agent_id")
                .map_err(|_| McpCatalogError::Corrupt { field: "agent_id" })?;
            let old_state: Option<String> =
                row.try_get("state").map_err(|_| McpCatalogError::Corrupt {
                    field: "grant_state",
                })?;
            let old_hash: Option<String> =
                row.try_get("schema_hash")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "grant_schema_hash",
                    })?;
            let old_effect: Option<String> =
                row.try_get("effect")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "grant_effect",
                    })?;
            let old_transport: Option<String> =
                row.try_get("transport_fingerprint")
                    .map_err(|_| McpCatalogError::Corrupt {
                        field: "grant_transport_fingerprint",
                    })?;
            let old_credential_generation: Option<i64> = row
                .try_get("credential_generation")
                .map_err(|_| McpCatalogError::Corrupt {
                    field: "grant_credential_generation",
                })?;
            let grant_credential_generation =
                old_credential_generation.unwrap_or(credential_generation);
            if grant_credential_generation < 0 {
                return Err(McpCatalogError::Corrupt {
                    field: "grant_credential_generation",
                });
            }
            let raw_name = reference
                .strip_prefix(&format!("{server_id}/"))
                .filter(|name| !name.is_empty())
                .ok_or(McpCatalogError::Corrupt { field: "grant_ref" })?;
            let tool = projected.get(raw_name).ok_or(McpCatalogError::Corrupt {
                field: "grant_tool",
            })?;
            let unchanged = old_hash.as_deref() == Some(tool.schema_hash.to_hex().as_str())
                && old_effect.as_deref() == Some(tool.effect.as_str())
                && old_transport.as_deref() == Some(transport_fingerprint_hex.as_str())
                && grant_credential_generation == credential_generation;
            let credential_current = grant_credential_generation == credential_generation;
            let new_state = match old_state.as_deref() {
                None if tool.available && credential_current => "active",
                Some("active") if tool.available && unchanged => "active",
                Some("suspended_missing") => "suspended_missing",
                None | Some("active") => "suspended_missing",
                Some(_) => {
                    return Err(McpCatalogError::Corrupt {
                        field: "grant_state",
                    });
                }
            };
            transaction
                .execute(
                    "UPDATE public.plugin_grants SET state=$4,catalog_generation=$5,
                       schema_hash=$6,effect=$7,transport_fingerprint=$8,
                       credential_generation=$9,updated_at=$10
                     WHERE kind='mcp' AND ref=$1 AND agent_id=$2 AND split_part(ref,'/',1)=$3",
                    &[
                        &reference,
                        &agent_id,
                        &server_id,
                        &new_state,
                        &generation,
                        &tool.schema_hash.to_hex(),
                        &tool.effect.as_str(),
                        &transport_fingerprint_hex,
                        &grant_credential_generation,
                        &now,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            if new_state == "suspended_missing" && old_state.as_deref() != Some(new_state) {
                suspended = suspended.saturating_add(1);
                self.append_suspension_audit(
                    &transaction,
                    &reference,
                    &model_name(server_id, raw_name)?,
                    generation_u64,
                )
                .await?;
            }
        }

        let catalog_hash = catalog_hash(&projected);
        transaction
            .execute(
                "UPDATE public.mcp_servers SET catalog_generation=$2,catalog_hash=$3,
                   catalog_transport_fingerprint=$4,tools_refreshed_at=$5,
                   last_error=NULL,updated_at=$5 WHERE id=$1",
                &[
                    &server_id,
                    &generation,
                    &catalog_hash.to_hex(),
                    &transport_fingerprint_hex,
                    &now,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .query_one("SELECT pg_notify('openbot_mcp_catalog','')", &[])
            .await
            .map_err(query_unavailable)?;
        transaction.commit().await.map_err(query_unavailable)?;
        drop(client);

        let tools = self.granted_tools_any(server_id).await?;
        Ok(McpCatalogRefresh {
            generation: CatalogGeneration::new(generation_u64),
            tools,
            suspended_grants: suspended,
        })
    }

    /// Exact currently active tools for one Bot. Actor is included now so per-user credential scope
    /// cannot be forgotten when it lands; the catalog query itself does not expose a credential.
    pub async fn granted_tools(
        &self,
        bot: &BotId,
        actor: &ActorId,
    ) -> Result<Vec<GrantedMcpTool>, McpCatalogError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        self.granted_tools_on_client(&client, bot, actor).await
    }

    /// Same projection on a caller-owned PostgreSQL connection. Context loading uses this to avoid
    /// recursively acquiring a second pool slot while it still reads the run/history snapshot.
    pub(crate) async fn granted_tools_on_client(
        &self,
        client: &tokio_postgres::Client,
        bot: &BotId,
        actor: &ActorId,
    ) -> Result<Vec<GrantedMcpTool>, McpCatalogError> {
        let rows = client
            .query(
                "SELECT s.id AS server_id,s.url,s.vendor,s.provenance,s.credential_id,
                        c.kind AS credential_kind,s.catalog_transport_fingerprint,
                        coalesce(s.credential_generation,0) AS credential_generation,
                        coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.catalog_generation,t.name,t.description,
                        t.input_schema,t.schema_hash,t.effect
                   FROM public.plugin_grants g
                   JOIN public.mcp_tools t ON g.kind='mcp' AND g.ref=t.server_id||'/'||t.name
                   JOIN public.mcp_servers s ON s.id=t.server_id
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE g.agent_id=$1 AND g.state='active' AND t.available=true
                    AND ((coalesce(s.transport,'mcp')='mcp' AND
                          (s.credential_id IS NULL OR
                           (c.kind='mcp' AND c.provider=s.id AND c.revoked_at IS NULL) OR
                           (c.kind='mcp_oauth_client' AND c.provider=s.id
                            AND c.revoked_at IS NULL AND EXISTS(
                              SELECT 1 FROM public.mcp_user_credentials uc
                              JOIN public.credentials u ON u.id=uc.credential_id
                              WHERE uc.server_id=s.id AND uc.user_id=$2
                                AND u.kind='mcp_user_token' AND u.provider=s.id
                                AND u.key_id=$2 AND u.revoked_at IS NULL)))) OR
                         (s.transport='google_drive_rest' AND
                          c.kind='mcp_oauth_client' AND c.provider=s.id
                          AND c.revoked_at IS NULL AND EXISTS(
                            SELECT 1 FROM public.mcp_user_credentials uc
                            JOIN public.credentials u ON u.id=uc.credential_id
                            WHERE uc.server_id=s.id AND uc.user_id=$2
                              AND u.kind='mcp_user_token' AND u.provider=s.id
                              AND u.key_id=$2 AND u.revoked_at IS NULL)))
                    AND s.catalog_generation IS NOT NULL
                    AND g.catalog_generation=s.catalog_generation
                    AND t.catalog_generation=s.catalog_generation
                    AND g.schema_hash=t.schema_hash AND g.effect=t.effect
                    AND g.transport_fingerprint=s.catalog_transport_fingerprint
                    AND g.credential_generation=coalesce(s.credential_generation,0)
                  ORDER BY s.id,t.name",
                &[&bot.as_str(), &actor.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        rows.iter().map(decode_granted).collect()
    }

    /// Current exact binding for one model-visible name and Bot.
    pub async fn binding(
        &self,
        bot: &BotId,
        actor: &ActorId,
        model: &str,
    ) -> Result<GrantedMcpTool, McpCatalogError> {
        self.granted_tools(bot, actor)
            .await?
            .into_iter()
            .find(|tool| tool.model_name == model)
            .ok_or(McpCatalogError::NotVisible)
    }

    /// Current catalog entry by collision-free model name, without granting it to a Bot. This is
    /// only metadata lookup; [`Self::binding`] remains mandatory before policy or execution.
    pub async fn current_tool(&self, model: &str) -> Result<GrantedMcpTool, McpCatalogError> {
        let (server_id, raw_name) = parse_model_name(model)?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT s.id AS server_id,s.url,s.vendor,s.provenance,s.credential_id,
                        c.kind AS credential_kind,s.catalog_transport_fingerprint,
                        coalesce(s.credential_generation,0) AS credential_generation,
                        coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.catalog_generation,t.name,t.description,
                        t.input_schema,t.schema_hash,t.effect
                   FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE s.id=$1 AND t.name=$2 AND t.available=true
                    AND ((coalesce(s.transport,'mcp')='mcp' AND
                          (s.credential_id IS NULL OR
                           (c.kind IN ('mcp','mcp_oauth_client')
                            AND c.provider=s.id AND c.revoked_at IS NULL))) OR
                         (s.transport='google_drive_rest' AND
                          c.kind='mcp_oauth_client' AND c.provider=s.id
                          AND c.revoked_at IS NULL))
                    AND s.catalog_generation IS NOT NULL
                    AND s.catalog_transport_fingerprint IS NOT NULL
                    AND t.catalog_generation=s.catalog_generation",
                &[&server_id, &raw_name],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(McpCatalogError::NotVisible)?;
        decode_granted(&row)
    }

    /// Exact grant projection inside the callback authenticator's existing transaction, avoiding
    /// a second snapshot between run verification and signed tool-set comparison.
    pub(crate) async fn granted_tools_in_transaction(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        bot: &BotId,
        actor: &ActorId,
    ) -> Result<Vec<GrantedMcpTool>, McpCatalogError> {
        let rows = transaction
            .query(
                "SELECT s.id AS server_id,s.url,s.vendor,s.provenance,s.credential_id,
                        c.kind AS credential_kind,s.catalog_transport_fingerprint,
                        coalesce(s.credential_generation,0) AS credential_generation,
                        coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.catalog_generation,t.name,t.description,
                        t.input_schema,t.schema_hash,t.effect
                   FROM public.plugin_grants g
                   JOIN public.mcp_tools t ON g.kind='mcp' AND g.ref=t.server_id||'/'||t.name
                   JOIN public.mcp_servers s ON s.id=t.server_id
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE g.agent_id=$1 AND g.state='active' AND t.available=true
                    AND ((coalesce(s.transport,'mcp')='mcp' AND
                          (s.credential_id IS NULL OR
                           (c.kind='mcp' AND c.provider=s.id AND c.revoked_at IS NULL) OR
                           (c.kind='mcp_oauth_client' AND c.provider=s.id
                            AND c.revoked_at IS NULL AND EXISTS(
                              SELECT 1 FROM public.mcp_user_credentials uc
                              JOIN public.credentials u ON u.id=uc.credential_id
                              WHERE uc.server_id=s.id AND uc.user_id=$2
                                AND u.kind='mcp_user_token' AND u.provider=s.id
                                AND u.key_id=$2 AND u.revoked_at IS NULL)))) OR
                         (s.transport='google_drive_rest' AND
                          c.kind='mcp_oauth_client' AND c.provider=s.id
                          AND c.revoked_at IS NULL AND EXISTS(
                            SELECT 1 FROM public.mcp_user_credentials uc
                            JOIN public.credentials u ON u.id=uc.credential_id
                            WHERE uc.server_id=s.id AND uc.user_id=$2
                              AND u.kind='mcp_user_token' AND u.provider=s.id
                              AND u.key_id=$2 AND u.revoked_at IS NULL)))
                    AND s.catalog_generation IS NOT NULL
                    AND g.catalog_generation=s.catalog_generation
                    AND t.catalog_generation=s.catalog_generation
                    AND g.schema_hash=t.schema_hash AND g.effect=t.effect
                    AND g.transport_fingerprint=s.catalog_transport_fingerprint
                    AND g.credential_generation=coalesce(s.credential_generation,0)
                  ORDER BY s.id,t.name",
                &[&bot.as_str(), &actor.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        rows.iter().map(decode_granted).collect()
    }

    async fn granted_tools_any(
        &self,
        server_id: &str,
    ) -> Result<Vec<GrantedMcpTool>, McpCatalogError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT DISTINCT s.id AS server_id,s.url,s.vendor,s.provenance,s.credential_id,
                        c.kind AS credential_kind,s.catalog_transport_fingerprint,
                        coalesce(s.credential_generation,0) AS credential_generation,
                        coalesce(s.transport,'mcp') AS transport,
                        coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs,
                        s.catalog_generation,t.name,t.description,
                        t.input_schema,t.schema_hash,t.effect
                   FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                   LEFT JOIN public.credentials c ON c.id=s.credential_id
                  WHERE s.id=$1 AND t.available=true AND t.catalog_generation=s.catalog_generation
                    AND ((coalesce(s.transport,'mcp')='mcp' AND
                          (s.credential_id IS NULL OR
                           (c.kind IN ('mcp','mcp_oauth_client')
                            AND c.provider=s.id AND c.revoked_at IS NULL))) OR
                         (s.transport='google_drive_rest' AND
                          (s.credential_id IS NULL OR
                           (c.kind='mcp_oauth_client' AND c.provider=s.id
                            AND c.revoked_at IS NULL))))
                  ORDER BY t.name",
                &[&server_id],
            )
            .await
            .map_err(query_unavailable)?;
        rows.iter().map(decode_granted).collect()
    }

    async fn append_suspension_audit(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        reference: &str,
        tool_name: &str,
        generation: u64,
    ) -> Result<(), McpCatalogError> {
        let (id, created_at) = next_event_coordinates(transaction)
            .await
            .map_err(query_unavailable)?;
        let event = AuditEvent {
            id,
            actor: None,
            event_type: AuditEventType::MCP_TOOL_SUSPENDED_MISSING,
            target_kind: AuditLabel::new("mcp_tool"),
            target_id: Some(
                AuditIdentifier::new(reference)
                    .map_err(|_| McpCatalogError::Corrupt { field: "grant_ref" })?,
            ),
            payload: AuditPayload::from_facts([
                AuditFact::ToolName(
                    AuditIdentifier::new(tool_name)
                        .map_err(|_| McpCatalogError::Corrupt { field: "tool_name" })?,
                ),
                AuditFact::CatalogGeneration(generation),
                AuditFact::ErrorCode(AuditLabel::new("catalog_tool_missing_or_changed")),
            ])
            .map_err(|_| McpCatalogError::Corrupt {
                field: "audit_payload",
            })?,
            created_at,
        };
        append_event_in_transaction(transaction, &event, self.checkpoint_key.expose())
            .await
            .map(|_| ())
            .map_err(query_unavailable)
    }
}

impl core::fmt::Debug for PostgresMcpCatalog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresMcpCatalog")
            .field("rmcp", &self.rmcp)
            .field("checkpoint_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PreparedTool {
    description: String,
    input_schema: Value,
    schema_hash: Sha256Digest,
}

struct ExistingTool {
    schema_hash: Sha256Digest,
    effect: Effect,
    first_seen_at: time::OffsetDateTime,
    last_seen_at: time::OffsetDateTime,
}

struct ProjectedTool {
    schema_hash: Sha256Digest,
    effect: Effect,
    available: bool,
}

fn prepare_listed(
    server_id: &str,
    tools: Vec<McpListedTool>,
) -> Result<BTreeMap<String, PreparedTool>, McpCatalogError> {
    let mut result = BTreeMap::new();
    for tool in tools {
        validate_component(&tool.name, "tool_name")?;
        model_name(server_id, &tool.name)?;
        compile_schema(&tool.input_schema)?;
        let hash = schema_hash(&tool.input_schema)?;
        if result
            .insert(
                tool.name,
                PreparedTool {
                    description: tool.description,
                    input_schema: tool.input_schema,
                    schema_hash: hash,
                },
            )
            .is_some()
        {
            return Err(McpCatalogError::Corrupt { field: "tool_name" });
        }
    }
    Ok(result)
}

fn catalog_hash(tools: &BTreeMap<String, ProjectedTool>) -> Sha256Digest {
    let mut writer = CanonicalWriter::new("openbot:mcp-catalog:v1");
    let count = tools.values().filter(|tool| tool.available).count();
    writer.u64(u64::try_from(count).unwrap_or(u64::MAX));
    for (name, tool) in tools.iter().filter(|(_, tool)| tool.available) {
        writer.bytes(name.as_bytes());
        writer.digest(&tool.schema_hash);
        writer.bytes(tool.effect.as_str().as_bytes());
    }
    writer.digest_of_written()
}

fn schema_hash(schema: &Value) -> Result<Sha256Digest, McpCatalogError> {
    if !schema.is_object() {
        return Err(McpCatalogError::Corrupt {
            field: "input_schema",
        });
    }
    serde_json::to_vec(schema)
        .map(|bytes| Sha256Digest::of(&bytes))
        .map_err(|_| McpCatalogError::Corrupt {
            field: "input_schema",
        })
}

fn compile_schema(schema: &Value) -> Result<jsonschema::Validator, McpCatalogError> {
    // Vendor patterns are untrusted. The linear-time engine deliberately rejects look-around and
    // backreferences instead of allowing catastrophic backtracking in an Agent hot path.
    jsonschema::options()
        .with_pattern_options(
            jsonschema::PatternOptions::regex()
                .size_limit(1024 * 1024)
                .dfa_size_limit(1024 * 1024),
        )
        .build(schema)
        .map_err(|_| McpCatalogError::Corrupt {
            field: "input_schema",
        })
}

fn validate_component(value: &str, field: &'static str) -> Result<(), McpCatalogError> {
    if value.is_empty()
        || value.len() > 64
        || value.contains("__")
        || value.contains('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(McpCatalogError::Corrupt { field });
    }
    Ok(())
}

fn model_name(server: &str, tool: &str) -> Result<String, McpCatalogError> {
    let name = format!("mcp__{server}__{tool}");
    ToolName::new(name.clone()).map_err(|_| McpCatalogError::Corrupt {
        field: "model_tool_name",
    })?;
    Ok(name)
}

fn parse_model_name(model: &str) -> Result<(&str, &str), McpCatalogError> {
    let rest = model
        .strip_prefix("mcp__")
        .ok_or(McpCatalogError::NotVisible)?;
    let (server, tool) = rest.split_once("__").ok_or(McpCatalogError::NotVisible)?;
    validate_component(server, "server_id")?;
    validate_component(tool, "tool_name")?;
    if model_name(server, tool)?.as_str() != model {
        return Err(McpCatalogError::NotVisible);
    }
    Ok((server, tool))
}

fn transport_fingerprint(
    endpoint: &str,
    vendor: &str,
    provenance: &str,
    transport: VendorTransportKind,
    egress_allow_cidrs: &[String],
) -> Result<Sha256Digest, McpCatalogError> {
    if vendor.is_empty()
        || vendor.len() > 256
        || provenance.is_empty()
        || provenance.len() > 256
        || vendor.as_bytes().contains(&0)
        || provenance.as_bytes().contains(&0)
    {
        return Err(McpCatalogError::Corrupt {
            field: "transport_identity",
        });
    }
    let parsed = Url::parse(endpoint).map_err(|_| McpCatalogError::Corrupt { field: "url" })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.cannot_be_a_base()
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(McpCatalogError::Corrupt { field: "url" });
    }
    let mut writer = CanonicalWriter::new("openbot:mcp-transport:v2");
    writer.str(parsed.as_str());
    writer.str(vendor);
    writer.str(provenance);
    writer.str(transport.as_str());
    writer.u64(
        u64::try_from(egress_allow_cidrs.len()).map_err(|_| McpCatalogError::Corrupt {
            field: "egress_allow_cidrs",
        })?,
    );
    for cidr in egress_allow_cidrs {
        writer.str(cidr);
    }
    writer.str(match transport {
        VendorTransportKind::Mcp => "2026-07-28",
        VendorTransportKind::GoogleDriveRest => "drive-v3",
    });
    Ok(writer.digest_of_written())
}

fn parse_effect(value: &str) -> Result<Effect, McpCatalogError> {
    match value {
        "read" => Ok(Effect::Read),
        "write" => Ok(Effect::Write),
        "execute" => Ok(Effect::Execute),
        "network" => Ok(Effect::Network),
        "credential" => Ok(Effect::Credential),
        _ => Err(McpCatalogError::Corrupt { field: "effect" }),
    }
}

fn decode_granted(row: &tokio_postgres::Row) -> Result<GrantedMcpTool, McpCatalogError> {
    let server_id: String = row
        .try_get("server_id")
        .map_err(|_| McpCatalogError::Corrupt { field: "server_id" })?;
    let raw_name: String = row
        .try_get("name")
        .map_err(|_| McpCatalogError::Corrupt { field: "tool_name" })?;
    let description: String = row
        .try_get("description")
        .map_err(|_| McpCatalogError::Corrupt {
            field: "description",
        })?;
    let input_schema: Value =
        row.try_get("input_schema")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "input_schema",
            })?;
    let schema_hash_text: String =
        row.try_get("schema_hash")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "schema_hash",
            })?;
    let effect_text: String = row
        .try_get("effect")
        .map_err(|_| McpCatalogError::Corrupt { field: "effect" })?;
    let generation: i64 =
        row.try_get("catalog_generation")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "catalog_generation",
            })?;
    let credential_generation: i64 =
        row.try_get("credential_generation")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "credential_generation",
            })?;
    let transport = parse_transport(
        &row.try_get::<_, String>("transport")
            .map_err(|_| McpCatalogError::Corrupt { field: "transport" })?,
    )?;
    let egress_allow_cidrs: Vec<String> =
        row.try_get("egress_allow_cidrs")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "egress_allow_cidrs",
            })?;
    let egress_allowlist = parse_egress_allowlist(&egress_allow_cidrs)?;
    let endpoint: String = row
        .try_get("url")
        .map_err(|_| McpCatalogError::Corrupt { field: "url" })?;
    let credential_id: Option<uuid::Uuid> =
        row.try_get("credential_id")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "credential_id",
            })?;
    let credential_kind: Option<crate::db::types::CredentialKind> = row
        .try_get("credential_kind")
        .map_err(|_| McpCatalogError::Corrupt {
            field: "credential_kind",
        })?;
    let vendor: String = row
        .try_get("vendor")
        .map_err(|_| McpCatalogError::Corrupt { field: "vendor" })?;
    let provenance: String = row
        .try_get("provenance")
        .map_err(|_| McpCatalogError::Corrupt {
            field: "provenance",
        })?;
    let stored_transport: String =
        row.try_get("catalog_transport_fingerprint")
            .map_err(|_| McpCatalogError::Corrupt {
                field: "catalog_transport_fingerprint",
            })?;
    validate_component(&server_id, "server_id")?;
    validate_component(&raw_name, "tool_name")?;
    let schema_digest =
        Sha256Digest::parse_hex(&schema_hash_text).map_err(|_| McpCatalogError::Corrupt {
            field: "schema_hash",
        })?;
    if schema_digest != schema_hash(&input_schema)? {
        return Err(McpCatalogError::Corrupt {
            field: "schema_hash",
        });
    }
    if Sha256Digest::parse_hex(&stored_transport).ok()
        != Some(transport_fingerprint(
            &endpoint,
            &vendor,
            &provenance,
            transport,
            &egress_allow_cidrs,
        )?)
    {
        return Err(McpCatalogError::Corrupt {
            field: "catalog_transport_fingerprint",
        });
    }
    let generation = u64::try_from(generation).map_err(|_| McpCatalogError::Corrupt {
        field: "catalog_generation",
    })?;
    let credential_generation =
        u64::try_from(credential_generation).map_err(|_| McpCatalogError::Corrupt {
            field: "credential_generation",
        })?;
    let authentication = match (transport, credential_id, credential_kind) {
        (VendorTransportKind::Mcp, None, None) => McpAuthentication::None,
        (VendorTransportKind::Mcp, Some(_), Some(crate::db::types::CredentialKind::Mcp)) => {
            McpAuthentication::DeploymentBearer
        }
        (
            VendorTransportKind::Mcp | VendorTransportKind::GoogleDriveRest,
            Some(_),
            Some(crate::db::types::CredentialKind::McpOauthClient),
        )
        | (VendorTransportKind::GoogleDriveRest, None, None) => McpAuthentication::UserOAuth,
        _ => {
            return Err(McpCatalogError::Corrupt {
                field: "credential_kind",
            });
        }
    };
    Ok(GrantedMcpTool {
        model_name: model_name(&server_id, &raw_name)?,
        server_id,
        raw_name,
        description,
        input_schema,
        schema_hash: schema_digest,
        effect: parse_effect(&effect_text)?,
        catalog_generation: CatalogGeneration::new(generation),
        credential_generation: CredentialGeneration::new(credential_generation),
        endpoint,
        authentication,
        transport,
        egress_allowlist,
    })
}

fn parse_egress_allowlist(entries: &[String]) -> Result<CidrAllowlist, McpCatalogError> {
    parse_stored_mcp_egress(entries).map_err(|_| McpCatalogError::Corrupt {
        field: "egress_allow_cidrs",
    })
}

fn parse_transport(value: &str) -> Result<VendorTransportKind, McpCatalogError> {
    match value {
        "mcp" => Ok(VendorTransportKind::Mcp),
        GOOGLE_DRIVE_TRANSPORT => Ok(VendorTransportKind::GoogleDriveRest),
        _ => Err(McpCatalogError::Corrupt { field: "transport" }),
    }
}

fn unavailable(error: deadpool_postgres::PoolError) -> McpCatalogError {
    tracing::error!(error = %error, "MCP catalog 获取 PostgreSQL 连接失败");
    McpCatalogError::Unavailable
}

fn query_unavailable(error: impl core::fmt::Display) -> McpCatalogError {
    tracing::error!(error = %error, "MCP catalog PostgreSQL 操作失败");
    McpCatalogError::Unavailable
}

impl From<McpClientError> for McpCatalogError {
    fn from(_: McpClientError) -> Self {
        Self::Unavailable
    }
}
