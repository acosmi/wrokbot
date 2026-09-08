//! Application-owned MCP per-user connection use cases and callback authentication port.

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::mcp::{
    GrantedPlugins, McpAdminPage, McpConnectionDisconnected, McpConnections,
    McpCustomServerRegistration, McpOAuthAuthorization, McpOAuthClientRegistered,
    McpOAuthClientRegistration, McpOAuthReturnTo, McpServerMutation, McpServerRemoved,
    PluginGrantKind, PluginGrantMutation, PluginMutationAcknowledged, PluginSkillMutation,
    PluginSkills,
};
use openbot_domain::vault::SecretBytes;

/// Stable connection-flow failure without remote payload, URL, credential or database values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpConnectionError {
    /// Server/connection is unknown or outside the actor's scope.
    #[error("mcp_connection_not_visible")]
    NotVisible,
    /// Closed input failed validation.
    #[error("mcp_connection_invalid_input field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// Deployment lacks public callback or a registered OAuth client.
    #[error("mcp_connection_conflict resource={resource}")]
    Conflict {
        /// Static resource class only.
        resource: &'static str,
    },
    /// Local dependency is unavailable.
    #[error("mcp_connection_unavailable")]
    Unavailable,
    /// Stored row/secret violates the closed schema.
    #[error("mcp_connection_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Vendor metadata/token/revocation endpoint failed.
    #[error("mcp_connection_vendor_failure")]
    VendorFailure,
    /// A local commit result is unknown and must be reconciled.
    #[error("mcp_connection_commit_unknown")]
    CommitUnknown,
}

impl McpConnectionError {
    /// Map into the stable application error taxonomy.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::NotVisible => AppError::NotVisible,
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Conflict { resource } => AppError::RequestConflict { resource },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "mcp_connections",
            },
            Self::VendorFailure => AppError::VendorFailure {
                vendor: "mcp_oauth",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Production port for authenticated per-user connection operations.
#[async_trait]
pub trait McpConnectionAdministration: Send + Sync {
    /// List only the current actor's connections.
    async fn list_connections(
        &self,
        auth: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError>;

    /// List the signed-in actor's deployment-wide Plugins page projection.
    async fn list_admin_page(
        &self,
        _auth: &AuthContext,
    ) -> Result<McpAdminPage, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Mint one-time state + PKCE and return the validated vendor authorization URL.
    async fn begin_oauth(
        &self,
        auth: &AuthContext,
        server_id: &str,
        return_to: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError>;

    /// Tombstone locally first, then attempt vendor revocation.
    async fn disconnect(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError>;

    /// Validate and atomically register/rotate a deployment OAuth client.
    async fn register_oauth_client(
        &self,
        auth: &AuthContext,
        server_id: &str,
        registration: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError>;

    /// Add one compile-time reviewed catalogue entry. The port, not the caller, owns its endpoint.
    async fn add_curated_server(
        &self,
        _auth: &AuthContext,
        _key: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Register and immediately refresh one custom Streamable HTTP server.
    async fn add_custom_server(
        &self,
        _auth: &AuthContext,
        _registration: &McpCustomServerRegistration,
    ) -> Result<McpServerMutation, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Remove one configured server and its cascading catalog/connection rows.
    async fn remove_server(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
    ) -> Result<McpServerRemoved, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Refresh a configured catalog and atomically suspend stale grants.
    async fn refresh_server(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Create/update one actor/deployment-owned skill and return the actor-visible list.
    async fn save_skill(
        &self,
        _auth: &AuthContext,
        _mutation: &PluginSkillMutation,
    ) -> Result<PluginSkills, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Remove one skill the actor may manage.
    async fn remove_skill(
        &self,
        _auth: &AuthContext,
        _slug: &str,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// Grant/revoke one plugin under current actor and catalog authority.
    async fn set_grant(
        &self,
        _auth: &AuthContext,
        _mutation: &PluginGrantMutation,
        _enabled: bool,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    /// List the current actor-specific plugin set for one visible Agent.
    async fn list_for_agent(
        &self,
        _auth: &AuthContext,
        _agent_id: &openbot_contracts::ids::BotId,
    ) -> Result<GrantedPlugins, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }
}

/// Fail-closed default when production assembly has no MCP connection service.
#[derive(Debug, Default)]
pub struct NoMcpConnectionAdministration;

#[async_trait]
impl McpConnectionAdministration for NoMcpConnectionAdministration {
    async fn list_connections(
        &self,
        _auth: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn begin_oauth(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
        _return_to: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn disconnect(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn register_oauth_client(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
        _registration: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }
}

/// Public callback query. The state is the credential; no browser session is trusted here.
pub struct McpOAuthCallbackInput {
    code: SecretBytes,
    state: SecretBytes,
    issuer: Option<String>,
}

impl McpOAuthCallbackInput {
    /// Move bounded callback values into zeroizing allocations.
    #[must_use]
    pub fn new(code: Vec<u8>, state: Vec<u8>, issuer: Option<String>) -> Self {
        Self {
            code: SecretBytes::new(code),
            state: SecretBytes::new(state),
            issuer,
        }
    }

    /// Expose the authorization code only to the callback coordinator.
    #[must_use]
    pub fn code(&self) -> &[u8] {
        self.code.expose()
    }

    /// Expose opaque state only to the one-time attempt store.
    #[must_use]
    pub fn state(&self) -> &[u8] {
        self.state.expose()
    }

    /// Optional RFC 9207 issuer returned by the authorization server.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }
}

impl core::fmt::Debug for McpOAuthCallbackInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("McpOAuthCallbackInput")
            .field("code", &"<redacted>")
            .field("state", &"<redacted>")
            .field("issuer_present", &self.issuer.is_some())
            .finish()
    }
}

/// Callback result is always an application-owned absolute/relative in-app redirect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpOAuthCallbackOutcome {
    /// Validated redirect destination; never derived from incoming Host or caller URL input.
    pub redirect_to: String,
}

/// Authentication coordinator for the public OAuth callback.
#[async_trait]
pub trait McpOAuthCallback: Send + Sync {
    /// Consume state before validation/network and complete or fail to a uniform redirect.
    async fn complete(&self, input: McpOAuthCallbackInput) -> McpOAuthCallbackOutcome;
}

/// Application use case: list actor-owned connections.
pub async fn list_mcp_connections(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
) -> Result<McpConnections, AppError> {
    port.list_connections(auth)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: read the signed-in actor's Plugins page projection.
pub async fn list_mcp_admin_page(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
) -> Result<McpAdminPage, AppError> {
    port.list_admin_page(auth)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: begin actor-owned OAuth.
pub async fn begin_mcp_oauth(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    server_id: &str,
    return_to: McpOAuthReturnTo,
) -> Result<McpOAuthAuthorization, AppError> {
    port.begin_oauth(auth, server_id, return_to)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: local-first disconnect.
pub async fn disconnect_mcp_connection(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    server_id: &str,
) -> Result<McpConnectionDisconnected, AppError> {
    port.disconnect(auth, server_id)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: admin-only deployment OAuth-client registration.
pub async fn register_mcp_oauth_client(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    server_id: &str,
    registration: &McpOAuthClientRegistration,
) -> Result<McpOAuthClientRegistered, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.register_oauth_client(auth, server_id, registration)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: admin-only add from the reviewed connector catalogue.
pub async fn add_curated_mcp_server(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    key: &str,
) -> Result<McpServerMutation, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.add_curated_server(auth, key)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: admin-only custom Streamable HTTP server registration.
pub async fn add_custom_mcp_server(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    registration: &McpCustomServerRegistration,
) -> Result<McpServerMutation, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.add_custom_server(auth, registration)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: admin-only configured-server removal.
pub async fn remove_mcp_server(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    server_id: &str,
) -> Result<McpServerRemoved, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.remove_server(auth, server_id)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: admin-only server catalog refresh.
pub async fn refresh_mcp_server(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    server_id: &str,
) -> Result<McpServerMutation, AppError> {
    if !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.refresh_server(auth, server_id)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: save an actor-owned skill, or an admin-only deployment skill.
pub async fn save_plugin_skill(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    mutation: &PluginSkillMutation,
) -> Result<PluginSkills, AppError> {
    if mutation.deployment_wide && !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.save_skill(auth, mutation)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: remove one actor/admin-managed skill.
pub async fn remove_plugin_skill(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    slug: &str,
) -> Result<PluginMutationAcknowledged, AppError> {
    port.remove_skill(auth, slug)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: grant a plugin; MCP grants are always administrator-only.
pub async fn grant_plugin(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    mutation: &PluginGrantMutation,
) -> Result<PluginMutationAcknowledged, AppError> {
    if mutation.kind == PluginGrantKind::Mcp && !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.set_grant(auth, mutation, true)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: revoke a plugin; MCP grants are always administrator-only.
pub async fn revoke_plugin(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    mutation: &PluginGrantMutation,
) -> Result<PluginMutationAcknowledged, AppError> {
    if mutation.kind == PluginGrantKind::Mcp && !auth.has_role(Role::Admin) {
        return Err(AppError::ForbiddenRole {
            required: Role::Admin,
        });
    }
    port.set_grant(auth, mutation, false)
        .await
        .map_err(McpConnectionError::into_app_error)
}

/// Application use case: current actor-specific plugins for one visible Agent.
pub async fn list_plugins_for_agent(
    port: &dyn McpConnectionAdministration,
    auth: &AuthContext,
    agent_id: &openbot_contracts::ids::BotId,
) -> Result<GrantedPlugins, AppError> {
    port.list_for_agent(auth, agent_id)
        .await
        .map_err(McpConnectionError::into_app_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::mcp::{McpOAuthClientAuthMethod, McpOAuthClientRegistration};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakePort {
        registrations: AtomicUsize,
        additions: AtomicUsize,
        custom_additions: AtomicUsize,
        removals: AtomicUsize,
        refreshes: AtomicUsize,
        skill_saves: AtomicUsize,
        grant_sets: AtomicUsize,
    }

    #[async_trait]
    impl McpConnectionAdministration for FakePort {
        async fn list_connections(
            &self,
            _auth: &AuthContext,
        ) -> Result<McpConnections, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn begin_oauth(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
            _return_to: McpOAuthReturnTo,
        ) -> Result<McpOAuthAuthorization, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn disconnect(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
        ) -> Result<McpConnectionDisconnected, McpConnectionError> {
            Err(McpConnectionError::Unavailable)
        }

        async fn register_oauth_client(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
            _registration: &McpOAuthClientRegistration,
        ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            Ok(McpOAuthClientRegistered::success())
        }

        async fn add_curated_server(
            &self,
            _auth: &AuthContext,
            key: &str,
        ) -> Result<McpServerMutation, McpConnectionError> {
            self.additions.fetch_add(1, Ordering::SeqCst);
            Ok(McpServerMutation {
                server_id: key.to_owned(),
                catalog_generation: 1,
                tool_count: 4,
                suspended_grants: 0,
            })
        }

        async fn add_custom_server(
            &self,
            _auth: &AuthContext,
            registration: &McpCustomServerRegistration,
        ) -> Result<McpServerMutation, McpConnectionError> {
            self.custom_additions.fetch_add(1, Ordering::SeqCst);
            Ok(McpServerMutation {
                server_id: registration.id.clone(),
                catalog_generation: 1,
                tool_count: 1,
                suspended_grants: 0,
            })
        }

        async fn remove_server(
            &self,
            _auth: &AuthContext,
            _server_id: &str,
        ) -> Result<McpServerRemoved, McpConnectionError> {
            self.removals.fetch_add(1, Ordering::SeqCst);
            Ok(McpServerRemoved::success())
        }

        async fn refresh_server(
            &self,
            _auth: &AuthContext,
            server_id: &str,
        ) -> Result<McpServerMutation, McpConnectionError> {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(McpServerMutation {
                server_id: server_id.to_owned(),
                catalog_generation: 2,
                tool_count: 4,
                suspended_grants: 0,
            })
        }

        async fn save_skill(
            &self,
            _auth: &AuthContext,
            _mutation: &PluginSkillMutation,
        ) -> Result<PluginSkills, McpConnectionError> {
            self.skill_saves.fetch_add(1, Ordering::SeqCst);
            Ok(PluginSkills { skills: Vec::new() })
        }

        async fn set_grant(
            &self,
            _auth: &AuthContext,
            _mutation: &PluginGrantMutation,
            _enabled: bool,
        ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
            self.grant_sets.fetch_add(1, Ordering::SeqCst);
            Ok(PluginMutationAcknowledged::success())
        }
    }

    fn auth(role: Role) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [role],
            AuthGeneration::new(1),
            false,
        )
    }

    fn registration() -> McpOAuthClientRegistration {
        McpOAuthClientRegistration::new(
            "client".to_owned(),
            "secret".to_owned(),
            "https://issuer.example".to_owned(),
            McpOAuthClientAuthMethod::ClientSecretBasic,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn oauth_client_registration_is_admin_gated_before_the_port() {
        let port = FakePort::default();
        assert!(matches!(
            register_mcp_oauth_client(&port, &auth(Role::User), "notes", &registration()).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert_eq!(port.registrations.load(Ordering::SeqCst), 0);
        assert_eq!(
            register_mcp_oauth_client(&port, &auth(Role::Admin), "notes", &registration()).await,
            Ok(McpOAuthClientRegistered::success())
        );
        assert_eq!(port.registrations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn curated_add_and_refresh_are_admin_gated_before_the_port() {
        let port = FakePort::default();
        assert!(matches!(
            add_curated_mcp_server(&port, &auth(Role::User), "google-drive").await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert!(matches!(
            refresh_mcp_server(&port, &auth(Role::User), "google-drive").await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert_eq!(port.additions.load(Ordering::SeqCst), 0);
        assert_eq!(port.refreshes.load(Ordering::SeqCst), 0);
        assert_eq!(
            add_curated_mcp_server(&port, &auth(Role::Admin), "google-drive")
                .await
                .unwrap()
                .tool_count,
            4
        );
        assert_eq!(
            refresh_mcp_server(&port, &auth(Role::Admin), "google-drive")
                .await
                .unwrap()
                .catalog_generation,
            2
        );
        assert_eq!(port.additions.load(Ordering::SeqCst), 1);
        assert_eq!(port.refreshes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn custom_add_and_remove_are_admin_gated_before_the_port() {
        let port = FakePort::default();
        let custom = McpCustomServerRegistration {
            id: "private-notes".to_owned(),
            title: "Private notes".to_owned(),
            url: "https://notes.example/mcp".to_owned(),
            credential_id: None,
            egress_allow_cidrs: vec!["10.0.0.0/8".to_owned()],
        };
        assert!(matches!(
            add_custom_mcp_server(&port, &auth(Role::User), &custom).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert!(matches!(
            remove_mcp_server(&port, &auth(Role::User), "private-notes").await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert_eq!(port.custom_additions.load(Ordering::SeqCst), 0);
        assert_eq!(port.removals.load(Ordering::SeqCst), 0);
        assert_eq!(
            add_custom_mcp_server(&port, &auth(Role::Admin), &custom)
                .await
                .unwrap()
                .tool_count,
            1
        );
        assert_eq!(
            remove_mcp_server(&port, &auth(Role::Admin), "private-notes").await,
            Ok(McpServerRemoved::success())
        );
        assert_eq!(port.custom_additions.load(Ordering::SeqCst), 1);
        assert_eq!(port.removals.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deployment_skills_and_mcp_grants_are_role_gated_before_the_port() {
        let port = FakePort::default();
        let mut skill = PluginSkillMutation {
            slug: "review-notes".to_owned(),
            title: "Review notes".to_owned(),
            summary: "Review".to_owned(),
            instructions: "Review the notes.".to_owned(),
            deployment_wide: true,
        };
        assert!(matches!(
            save_plugin_skill(&port, &auth(Role::User), &skill).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert_eq!(port.skill_saves.load(Ordering::SeqCst), 0);

        skill.deployment_wide = false;
        assert_eq!(
            save_plugin_skill(&port, &auth(Role::User), &skill).await,
            Ok(PluginSkills { skills: Vec::new() })
        );
        assert_eq!(port.skill_saves.load(Ordering::SeqCst), 1);

        let mut grant = PluginGrantMutation {
            kind: PluginGrantKind::Mcp,
            reference: "notes/search".to_owned(),
            agent_id: "agent-one".to_owned(),
        };
        assert!(matches!(
            grant_plugin(&port, &auth(Role::User), &grant).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert!(matches!(
            revoke_plugin(&port, &auth(Role::User), &grant).await,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
        assert_eq!(port.grant_sets.load(Ordering::SeqCst), 0);

        grant.kind = PluginGrantKind::Skill;
        grant.reference = skill.slug;
        assert_eq!(
            grant_plugin(&port, &auth(Role::User), &grant).await,
            Ok(PluginMutationAcknowledged::success())
        );
        assert_eq!(port.grant_sets.load(Ordering::SeqCst), 1);
    }
}
