//! Authority-owned engine role and scope models from v4 §10.1 / §10.6.

use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::ids::{
    ActorId, BotId, ChannelId, CredentialPrincipalId, TenantId, ThreadId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Workspace anchor; Browser profiles may persist, workspace roots never cross this boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceScope {
    /// Channel-owned workspace.
    Channel(ChannelId),
    /// Direct-thread-owned workspace.
    Thread(ThreadId),
}

/// `ProfileScope + WorkspaceScope`; `bot_id` alone is deliberately insufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputerSecurityScope {
    tenant_id: TenantId,
    bot_id: BotId,
    credential_principal_id: CredentialPrincipalId,
    workspace: WorkspaceScope,
}

impl ComputerSecurityScope {
    /// Persistent-profile lock key. Workspace is deliberately absent: one principal's profile
    /// may retain login state across workspaces, but two workspace engines must never own it.
    #[must_use]
    pub fn profile_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        push(&mut hash, b"browser-profile-v1");
        push(&mut hash, self.tenant_id.as_str().as_bytes());
        push(&mut hash, self.bot_id.as_str().as_bytes());
        push(&mut hash, self.credential_principal_id.as_str().as_bytes());
        hash.finalize().into()
    }

    /// Construct the complete browser isolation scope.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        bot_id: BotId,
        credential_principal_id: CredentialPrincipalId,
        workspace: WorkspaceScope,
    ) -> Self {
        Self {
            tenant_id,
            bot_id,
            credential_principal_id,
            workspace,
        }
    }
}

/// Desktop application-window session ID. It is internal and never accepted from renderer input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopWindowSessionId(String);

impl DesktopWindowSessionId {
    /// Construct a bounded non-empty session ID minted by the Rust Desktop host.
    pub fn new(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.contains('\0') {
            return Err(ScopeError::InvalidWindowSessionId);
        }
        Ok(Self(value))
    }
}

/// Temporary Desktop component engine scope; it deliberately has no persistent profile principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentRenderScope {
    tenant_id: TenantId,
    actor_id: ActorId,
    desktop_window_session_id: DesktopWindowSessionId,
}

impl ComponentRenderScope {
    /// Construct one Desktop application-window component scope.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        actor_id: ActorId,
        desktop_window_session_id: DesktopWindowSessionId,
    ) -> Self {
        Self {
            tenant_id,
            actor_id,
            desktop_window_session_id,
        }
    }
}

/// Closed role tag carried in the one-shot boot capability.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineRoleKind {
    /// Browser Computer role.
    BrowserComputer,
    /// Desktop sandboxed component role.
    SandboxedComponent,
}

/// Full authority-owned role. Only its closed tag and opaque scope digest cross into the shim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineRole {
    /// Persistent browser profile + workspace scope.
    BrowserComputer(ComputerSecurityScope),
    /// Temporary per-window component scope.
    SandboxedComponent(ComponentRenderScope),
}

/// Host-authorized actor allowed to receive this engine's screen stream.
///
/// It is never serialized to the engine. The Computer manager must mint it from current authority
/// before launch; subsequent auth-generation changes invalidate the whole attached stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenAudience {
    tenant_id: TenantId,
    actor_id: ActorId,
    auth_generation: AuthGeneration,
}

impl ScreenAudience {
    /// Mint an audience from a verified current authentication context.
    #[must_use]
    pub fn from_auth(auth: &AuthContext) -> Self {
        Self {
            tenant_id: auth.tenant().clone(),
            actor_id: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
        }
    }

    /// Explicit authority-layer constructor for non-HTTP hosts such as the runsc probe.
    #[must_use]
    pub fn new(tenant_id: TenantId, actor_id: ActorId, auth_generation: AuthGeneration) -> Self {
        Self {
            tenant_id,
            actor_id,
            auth_generation,
        }
    }

    /// Audience tenant.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Audience actor.
    #[must_use]
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// Auth generation current when the host authorized the stream.
    #[must_use]
    pub const fn auth_generation(&self) -> AuthGeneration {
        self.auth_generation
    }
}

impl EngineRole {
    /// Closed wire tag.
    #[must_use]
    pub const fn kind(&self) -> EngineRoleKind {
        match self {
            Self::BrowserComputer(_) => EngineRoleKind::BrowserComputer,
            Self::SandboxedComponent(_) => EngineRoleKind::SandboxedComponent,
        }
    }

    /// Opaque deterministic digest used for partition naming without exposing actor/tenant IDs.
    #[must_use]
    pub fn scope_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        match self {
            Self::BrowserComputer(scope) => {
                push(&mut hash, b"browser-computer-v1");
                push(&mut hash, scope.tenant_id.as_str().as_bytes());
                push(&mut hash, scope.bot_id.as_str().as_bytes());
                push(&mut hash, scope.credential_principal_id.as_str().as_bytes());
                match &scope.workspace {
                    WorkspaceScope::Channel(id) => {
                        push(&mut hash, b"channel");
                        push(&mut hash, id.as_str().as_bytes());
                    }
                    WorkspaceScope::Thread(id) => {
                        push(&mut hash, b"thread");
                        push(&mut hash, id.as_str().as_bytes());
                    }
                }
            }
            Self::SandboxedComponent(scope) => {
                push(&mut hash, b"sandboxed-component-v1");
                push(&mut hash, scope.tenant_id.as_str().as_bytes());
                push(&mut hash, scope.actor_id.as_str().as_bytes());
                push(&mut hash, scope.desktop_window_session_id.0.as_bytes());
            }
        }
        hash.finalize().into()
    }

    /// Tenant axis retained only in the Rust authority layer.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::BrowserComputer(scope) => &scope.tenant_id,
            Self::SandboxedComponent(scope) => &scope.tenant_id,
        }
    }

    /// Component role is additionally actor-bound; browser access is authorized by its manager.
    #[must_use]
    pub fn component_actor_id(&self) -> Option<&ActorId> {
        match self {
            Self::BrowserComputer(_) => None,
            Self::SandboxedComponent(scope) => Some(&scope.actor_id),
        }
    }
}

/// Scope construction failures.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    /// Desktop window session ID was empty, over 256 bytes, or contained NUL.
    #[error("engine_window_session_id_invalid")]
    InvalidWindowSessionId,
}

fn push(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{
        ActorId, BotId, ChannelId, CredentialPrincipalId, TenantId, ThreadId,
    };

    use super::{
        ComponentRenderScope, ComputerSecurityScope, DesktopWindowSessionId, EngineRole,
        WorkspaceScope,
    };

    #[test]
    fn profile_key_ignores_workspace_but_binds_each_profile_axis() {
        let scope = |tenant: &str, bot: &str, principal: &str, channel: &str| {
            ComputerSecurityScope::new(
                TenantId::new(tenant),
                BotId::new(bot),
                CredentialPrincipalId::new(principal),
                WorkspaceScope::Channel(ChannelId::new(channel)),
            )
        };
        let first = scope("tenant", "bot", "principal", "first");
        let other_workspace = scope("tenant", "bot", "principal", "second");
        assert_eq!(first.profile_digest(), other_workspace.profile_digest());
        assert_ne!(
            EngineRole::BrowserComputer(first.clone()).scope_digest(),
            EngineRole::BrowserComputer(other_workspace).scope_digest()
        );
        for changed in [
            scope("other", "bot", "principal", "first"),
            scope("tenant", "other", "principal", "first"),
            scope("tenant", "bot", "other", "first"),
        ] {
            assert_ne!(first.profile_digest(), changed.profile_digest());
        }
    }

    #[test]
    fn every_scope_axis_changes_the_opaque_partition_digest() {
        let browser = |tenant: &str, bot: &str, principal: &str, workspace: WorkspaceScope| {
            EngineRole::BrowserComputer(ComputerSecurityScope::new(
                TenantId::new(tenant),
                BotId::new(bot),
                CredentialPrincipalId::new(principal),
                workspace,
            ))
            .scope_digest()
        };
        let baseline = browser(
            "tenant-a",
            "bot-a",
            "principal-a",
            WorkspaceScope::Channel(ChannelId::new("channel-a")),
        );
        for changed in [
            browser(
                "tenant-b",
                "bot-a",
                "principal-a",
                WorkspaceScope::Channel(ChannelId::new("channel-a")),
            ),
            browser(
                "tenant-a",
                "bot-b",
                "principal-a",
                WorkspaceScope::Channel(ChannelId::new("channel-a")),
            ),
            browser(
                "tenant-a",
                "bot-a",
                "principal-b",
                WorkspaceScope::Channel(ChannelId::new("channel-a")),
            ),
            browser(
                "tenant-a",
                "bot-a",
                "principal-a",
                WorkspaceScope::Thread(ThreadId::new("channel-a")),
            ),
        ] {
            assert_ne!(baseline, changed);
        }
    }

    #[test]
    fn component_digest_binds_window_actor_and_tenant() {
        let role = EngineRole::SandboxedComponent(ComponentRenderScope::new(
            TenantId::new("tenant-a"),
            ActorId::new("actor-a"),
            DesktopWindowSessionId::new("window-a").expect("session"),
        ));
        let changed = EngineRole::SandboxedComponent(ComponentRenderScope::new(
            TenantId::new("tenant-a"),
            ActorId::new("actor-a"),
            DesktopWindowSessionId::new("window-b").expect("session"),
        ));
        assert_ne!(role.scope_digest(), changed.scope_digest());
    }
}
