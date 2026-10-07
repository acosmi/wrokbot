//! Disposable Plugins state used only by the explicitly opted-in GUI fixture binary.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openbot_application::{McpConnectionAdministration, McpConnectionError};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_contracts::mcp::*;
use serde_json::json;

#[derive(Clone)]
pub(super) struct PluginsFixture {
    base: super::FixtureConnections,
    inner: Arc<Mutex<Rows>>,
    next_mode: Arc<AtomicU8>,
    home_skills: Option<HomeSkillsScope>,
}

#[derive(Clone)]
struct HomeSkillsScope {
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    auth_generation: AuthGeneration,
    agent: BotId,
}

struct Rows {
    servers: BTreeMap<String, McpAdminServer>,
    revision: u64,
    operations: Vec<serde_json::Value>,
    connected: Vec<McpConnection>,
}

impl PluginsFixture {
    pub(super) fn new(base: super::FixtureConnections) -> Self {
        let drive = server(
            "google-drive",
            "Google Drive",
            McpAdminAuthentication::UserOAuth,
        );
        Self {
            base,
            inner: Arc::new(Mutex::new(Rows {
                servers: BTreeMap::from([(drive.id.clone(), drive)]),
                revision: 1,
                operations: Vec::new(),
                connected: Vec::new(),
            })),
            next_mode: Arc::new(AtomicU8::new(0)),
            home_skills: None,
        }
    }

    // Synthetic Home QA data, enabled only by the Memory/fixed startup opt-in.
    pub(super) fn with_home_skills(mut self, auth: &AuthContext) -> Self {
        self.home_skills = Some(HomeSkillsScope {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            agent: BotId::new("fixture-owned-public"), // Operations Guide.
        });
        self
    }

    pub(super) fn control(&self, mode: u8) -> bool {
        if mode > 3 {
            return false;
        }
        self.next_mode.store(mode, Ordering::SeqCst);
        true
    }

    pub(super) fn proof(&self) -> serde_json::Value {
        let rows = self.inner.lock().expect("fixture state");
        json!({"revision": rows.revision, "serverCount": rows.servers.len(), "operations": rows.operations})
    }

    async fn before(&self, auth: &AuthContext) -> Result<u8, McpConnectionError> {
        self.base.ensure_actor(auth)?;
        if !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        let mode = self.next_mode.swap(0, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(if mode == 3 {
            1000
        } else {
            80
        }))
        .await;
        if mode == 1 {
            return Err(McpConnectionError::Unavailable);
        }
        Ok(mode)
    }

    fn after(
        &self,
        mode: u8,
        operation: &'static str,
        id: &str,
    ) -> Result<u64, McpConnectionError> {
        let mut rows = self
            .inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?;
        rows.revision += 1;
        rows.operations
            .push(json!({"operation": operation,"serverId": id}));
        if mode == 2 {
            Err(McpConnectionError::CommitUnknown)
        } else {
            Ok(rows.revision)
        }
    }
}

fn server(id: &str, title: &str, authentication: McpAdminAuthentication) -> McpAdminServer {
    McpAdminServer {
        id: id.to_owned(),
        title: title.to_owned(),
        vendor: "Fixture vendor".to_owned(),
        url: format!("https://{}.example.test/mcp", id),
        summary: "Deterministic fixture connector".to_owned(),
        docs_url: "https://example.test/docs".to_owned(),
        provenance: if id == "google-drive" {
            "first-party"
        } else {
            "custom"
        }
        .to_owned(),
        authentication,
        has_credential: authentication != McpAdminAuthentication::None,
        tools_refreshed_at: None,
        last_error: None,
        added_by: None,
        egress_allow_cidrs: Vec::new(),
        tools: ["read_notes", "update_notes"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| McpAdminTool {
                server_id: id.to_owned(),
                name: name.to_owned(),
                description: format!("Fixture {name}"),
                input_schema: json!({"type":"object","properties":{}}),
                reference: format!("{id}/{name}"),
                effect: if index == 0 {
                    McpAdminToolEffect::Read
                } else {
                    McpAdminToolEffect::Write
                },
                granted_to: Vec::new(),
            })
            .collect(),
    }
}

#[async_trait]
impl McpConnectionAdministration for PluginsFixture {
    async fn list_for_agent(
        &self,
        auth: &AuthContext,
        agent_id: &BotId,
    ) -> Result<GrantedPlugins, McpConnectionError> {
        let scope = self
            .home_skills
            .as_ref()
            .ok_or(McpConnectionError::Unavailable)?;
        if auth.deployment() != &scope.deployment
            || auth.tenant() != &scope.tenant
            || auth.actor() != &scope.actor
            || auth.auth_generation() != scope.auth_generation
            || !auth.has_role(Role::User)
            || agent_id != &scope.agent
        {
            return Err(McpConnectionError::NotVisible);
        }
        Ok(GrantedPlugins {
            tools: Vec::new(),
            skills: vec![
                GrantedPluginSkill {
                    slug: "review-note".to_owned(),
                    title: "Review note".to_owned(),
                    summary: "Synthetic Home QA selection".to_owned(),
                    instructions: "Fixture-only: review the supplied note; no external calls."
                        .to_owned(),
                },
                GrantedPluginSkill {
                    slug: "check-list".to_owned(),
                    title: "Check list".to_owned(),
                    summary: "Synthetic Home QA order check".to_owned(),
                    instructions:
                        "Fixture-only: preserve the supplied checklist order; no external calls."
                            .to_owned(),
                },
            ],
        })
    }

    async fn list_admin_page(
        &self,
        auth: &AuthContext,
    ) -> Result<McpAdminPage, McpConnectionError> {
        self.base.ensure_actor(auth)?;
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let rows = self
            .inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?;
        Ok(McpAdminPage {
            catalogue: vec![McpAdminCatalogueEntry {
                key: "google-drive".to_owned(),
                title: "Google Drive".to_owned(),
                vendor: "Google".to_owned(),
                summary: "Personal files".to_owned(),
                docs_url: "https://example.test/docs".to_owned(),
                auth: McpAdminAuthentication::UserOAuth,
                per_instance: false,
            }],
            bots_may_call_back: false,
            servers: rows.servers.values().cloned().collect(),
            skills: Vec::new(),
            redirect_uri: Some(self.base.redirect_uri.clone()),
        })
    }

    async fn list_connections(
        &self,
        auth: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError> {
        let mut page = self.base.list_connections(auth).await?;
        let rows = self
            .inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?;
        page.available_server_ids = rows
            .servers
            .values()
            .filter(|row| row.authentication == McpAdminAuthentication::UserOAuth)
            .map(|row| row.id.clone())
            .collect();
        page.connections.extend(rows.connected.clone());
        page.connections
            .retain(|connection| rows.servers.contains_key(&connection.server_id));
        page.connections
            .sort_by(|left, right| left.server_id.cmp(&right.server_id));
        page.connections
            .dedup_by(|left, right| left.server_id == right.server_id);
        Ok(page)
    }

    async fn begin_oauth(
        &self,
        auth: &AuthContext,
        id: &str,
        return_to: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError> {
        self.base.ensure_actor(auth)?;
        if return_to == McpOAuthReturnTo::Settings {
            return self.base.begin_oauth(auth, id, return_to).await;
        }
        let mut rows = self
            .inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?;
        if !rows.servers.get(id).is_some_and(|row| {
            row.authentication == McpAdminAuthentication::UserOAuth && row.has_credential
        }) {
            return Err(McpConnectionError::NotVisible);
        }
        rows.connected.retain(|row| row.server_id != id);
        rows.connected.push(McpConnection {
            server_id: id.to_owned(),
            scope: "fixture.read".to_owned(),
            connected_at: self.base.connected_at,
        });
        Ok(McpOAuthAuthorization {
            authorization_url: format!("/admin/plugins/{id}?connected={id}"),
        })
    }

    async fn disconnect(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError> {
        self.base.ensure_actor(auth)?;
        let removed = {
            let mut rows = self
                .inner
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?;
            let count = rows.connected.len();
            rows.connected.retain(|row| row.server_id != id);
            count != rows.connected.len()
        };
        let base = self.base.disconnect(auth, id).await;
        if removed {
            Ok(McpConnectionDisconnected {
                server_id: id.to_owned(),
                vendor_revocation: McpVendorRevocationStatus::Pending,
            })
        } else {
            base
        }
    }

    async fn add_curated_server(
        &self,
        auth: &AuthContext,
        key: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        let mode = self.before(auth).await?;
        if key != "google-drive" {
            return Err(McpConnectionError::NotVisible);
        }
        let mut row = server(key, "Google Drive", McpAdminAuthentication::UserOAuth);
        row.has_credential = false;
        self.inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?
            .servers
            .insert(key.to_owned(), row);
        let revision = self.after(mode, "add", key)?;
        Ok(McpServerMutation {
            server_id: key.to_owned(),
            catalog_generation: revision,
            tool_count: 2,
            suspended_grants: 0,
        })
    }

    async fn add_custom_server(
        &self,
        auth: &AuthContext,
        registration: &McpCustomServerRegistration,
    ) -> Result<McpServerMutation, McpConnectionError> {
        let mode = self.before(auth).await?;
        let mut row = server(
            &registration.id,
            &registration.title,
            if registration.credential_id.is_some() {
                McpAdminAuthentication::DeploymentBearer
            } else {
                McpAdminAuthentication::None
            },
        );
        row.url.clone_from(&registration.url);
        row.egress_allow_cidrs
            .clone_from(&registration.egress_allow_cidrs);
        self.inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?
            .servers
            .insert(row.id.clone(), row);
        let revision = self.after(mode, "custom", &registration.id)?;
        Ok(McpServerMutation {
            server_id: registration.id.clone(),
            catalog_generation: revision,
            tool_count: 2,
            suspended_grants: 0,
        })
    }

    async fn register_oauth_client(
        &self,
        auth: &AuthContext,
        id: &str,
        _registration: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
        let mode = self.before(auth).await?;
        {
            let mut rows = self
                .inner
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?;
            let row = rows
                .servers
                .get_mut(id)
                .ok_or(McpConnectionError::NotVisible)?;
            row.authentication = McpAdminAuthentication::UserOAuth;
            row.has_credential = true;
        }
        self.after(mode, "oauth-client", id)?;
        Ok(McpOAuthClientRegistered { ok: true })
    }

    async fn refresh_server(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<McpServerMutation, McpConnectionError> {
        let mode = self.before(auth).await?;
        if !self
            .inner
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?
            .servers
            .contains_key(id)
        {
            return Err(McpConnectionError::NotVisible);
        }
        let revision = self.after(mode, "refresh", id)?;
        Ok(McpServerMutation {
            server_id: id.to_owned(),
            catalog_generation: revision,
            tool_count: 2,
            suspended_grants: 0,
        })
    }

    async fn remove_server(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<McpServerRemoved, McpConnectionError> {
        let mode = self.before(auth).await?;
        {
            let mut rows = self
                .inner
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?;
            if rows.servers.remove(id).is_none() {
                return Err(McpConnectionError::NotVisible);
            }
            rows.connected
                .retain(|connection| connection.server_id != id);
        }
        if id == "google-drive" {
            self.base
                .connection
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?
                .take();
        }
        self.after(mode, "remove", id)?;
        Ok(McpServerRemoved { ok: true })
    }

    async fn set_grant(
        &self,
        auth: &AuthContext,
        mutation: &PluginGrantMutation,
        enabled: bool,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        let mode = self.before(auth).await?;
        if mutation.kind != PluginGrantKind::Mcp {
            return Err(McpConnectionError::NotVisible);
        }
        let (id, name) = mutation
            .reference
            .split_once('/')
            .ok_or(McpConnectionError::NotVisible)?;
        {
            let mut rows = self
                .inner
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?;
            let tool = rows
                .servers
                .get_mut(id)
                .and_then(|server| server.tools.iter_mut().find(|tool| tool.name == name))
                .ok_or(McpConnectionError::NotVisible)?;
            tool.granted_to.retain(|agent| agent != &mutation.agent_id);
            if enabled {
                tool.granted_to.push(mutation.agent_id.clone());
            }
        }
        self.after(mode, if enabled { "grant" } else { "revoke" }, id)?;
        Ok(PluginMutationAcknowledged { ok: true })
    }
}

#[cfg(test)]
mod home_skills_tests {
    use super::*;

    fn auth(
        deployment: &str,
        tenant: &str,
        actor: &str,
        generation: u64,
        roles: &[Role],
    ) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new(deployment),
            TenantId::new(tenant),
            ActorId::new(actor),
            roles.iter().copied(),
            AuthGeneration::new(generation),
            false,
        )
    }

    fn fixed_auth(roles: &[Role]) -> AuthContext {
        auth(
            super::super::FIXTURE_DEPLOYMENT,
            super::super::FIXTURE_TENANT,
            super::super::FIXTURE_ACTOR,
            1,
            roles,
        )
    }

    fn fixture() -> PluginsFixture {
        PluginsFixture::new(super::super::FixtureConnections::new(
            ActorId::new(super::super::FIXTURE_ACTOR),
            39015,
            time::OffsetDateTime::UNIX_EPOCH,
        ))
    }

    #[tokio::test]
    async fn home_skills_default_remains_unavailable_for_fixed_and_foreign_callers() {
        let fixture = fixture();
        for caller in [
            fixed_auth(&[Role::User, Role::Admin]),
            auth("other-deployment", "other-tenant", "other-actor", 2, &[]),
        ] {
            for agent in ["fixture-owned-public", "fixture-owned-private"] {
                assert!(matches!(
                    fixture.list_for_agent(&caller, &BotId::new(agent)).await,
                    Err(McpConnectionError::Unavailable)
                ));
            }
        }
    }

    #[tokio::test]
    async fn home_skills_opt_in_returns_only_ordered_synthetic_skills_to_the_full_scope() {
        let fixture = fixture().with_home_skills(&fixed_auth(&[Role::User, Role::Admin]));
        let agent = BotId::new("fixture-owned-public");
        for caller in [
            fixed_auth(&[Role::User]),
            fixed_auth(&[Role::User, Role::Admin]),
        ] {
            let mut granted = fixture.list_for_agent(&caller, &agent).await.unwrap();
            assert!(granted.tools.is_empty());
            assert_eq!(
                granted
                    .skills
                    .iter()
                    .map(|skill| skill.slug.as_str())
                    .collect::<Vec<_>>(),
                ["review-note", "check-list"]
            );
            assert!(granted.skills.iter().all(|skill| {
                skill.summary.starts_with("Synthetic ")
                    && skill.instructions.starts_with("Fixture-only: ")
                    && skill.instructions.ends_with("no external calls.")
            }));
            // A caller-owned reply cannot mutate later grants or manufacture a tool grant.
            granted.skills.clear();
            assert_eq!(
                fixture
                    .list_for_agent(&caller, &agent)
                    .await
                    .unwrap()
                    .skills
                    .len(),
                2
            );
        }
    }

    #[tokio::test]
    async fn home_skills_opt_in_rejects_each_foreign_scope_dimension_and_non_user_role() {
        let fixture = fixture().with_home_skills(&fixed_auth(&[Role::User, Role::Admin]));
        let agent = BotId::new("fixture-owned-public");
        for caller in [
            auth(
                "foreign",
                super::super::FIXTURE_TENANT,
                super::super::FIXTURE_ACTOR,
                1,
                &[Role::User],
            ),
            auth(
                super::super::FIXTURE_DEPLOYMENT,
                "foreign",
                super::super::FIXTURE_ACTOR,
                1,
                &[Role::User],
            ),
            auth(
                super::super::FIXTURE_DEPLOYMENT,
                super::super::FIXTURE_TENANT,
                "foreign",
                1,
                &[Role::User],
            ),
            auth(
                super::super::FIXTURE_DEPLOYMENT,
                super::super::FIXTURE_TENANT,
                super::super::FIXTURE_ACTOR,
                2,
                &[Role::User],
            ),
            fixed_auth(&[Role::Admin]),
            fixed_auth(&[]),
        ] {
            assert!(matches!(
                fixture.list_for_agent(&caller, &agent).await,
                Err(McpConnectionError::NotVisible)
            ));
        }
    }

    #[tokio::test]
    async fn home_skills_opt_in_rejects_every_agent_except_operations_guide() {
        let caller = fixed_auth(&[Role::User]);
        let fixture = fixture().with_home_skills(&caller);
        for agent in [
            "fixture-owned-private",
            "fixture-system-public",
            "missing-agent",
            "Fixture-owned-public",
        ] {
            assert!(matches!(
                fixture.list_for_agent(&caller, &BotId::new(agent)).await,
                Err(McpConnectionError::NotVisible)
            ));
        }
    }
}
