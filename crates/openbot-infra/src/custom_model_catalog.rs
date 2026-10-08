//! Current-owner custom catalogue observations in one original read-only RC transaction.
//!
//! Schema validation precedes the final joint statement. Its full Host result and any
//! produced tail survive page failures until the original ROLLBACK is acknowledged.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use async_trait::async_trait;
use openbot_application::custom_model_catalog::{
    CurrentCustomModelCatalogPage, CustomModelCatalogError as Error, CustomModelCatalogInventory,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::custom_model_catalog::{
    CUSTOM_MODEL_CATALOG_PAGE_SIZE, CustomModelCatalogEntry, CustomModelCatalogPage,
    CustomModelCatalogPageRequest,
};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::model_connections::{CustomModelProtocol, ModelConnectionSource};
use openbot_contracts::request_binding::{
    CustomModelCatalogHostObservation, CustomModelCatalogHostTailWitness,
    CustomModelCatalogHostTarget, CustomModelCatalogSessionFacts, HostRequestBindingError,
    HostRequestBindingKind, RequestBindingIssuer,
};
use openbot_domain::identity::roles::resolve_effective_role;
use time::OffsetDateTime;
use tokio_postgres::types::FromSql;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::auth::single_user::desktop_local::{DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL};
use crate::auth::single_user::{SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL};
use crate::db::desktop_vault_canary::VerifiedDesktopCustomModelCatalogProvenance;
use crate::db::native;
use crate::db::pool::DatabasePool;

/// One concrete Pool, namespace and independently enrolled original Host issuer.
pub struct PostgresCustomModelCatalogInventory {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    authority: Arc<()>,
    issuer: OnceLock<RequestBindingIssuer>,
    desktop_provenance: OnceLock<VerifiedDesktopCustomModelCatalogProvenance>,
}

impl PostgresCustomModelCatalogInventory {
    /// Validate only namespace configuration; construction performs no I/O or effects.
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, Error> {
        if !identifier(deployment.as_str()) || !identifier(tenant.as_str()) {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            authority: Arc::new(()),
            issuer: OnceLock::new(),
            desktop_provenance: OnceLock::new(),
        })
    }

    /// Trusted composition compares the original manager as well as both namespace keys.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && &self.deployment == deployment
            && &self.tenant == tenant
    }

    /// A generic implementation of the target port does not enroll a different repository.
    #[must_use]
    pub fn matches_host_target(
        &self,
        target: &dyn CustomModelCatalogHostTarget,
        auth: &AuthContext,
    ) -> bool {
        self.scope(auth).is_ok()
            && target.matches_authority(&self.authority)
            && target.matches_auth(auth)
    }

    /// Startup-only, exactly once; an ended or previously enrolled issuer is not replaced.
    pub fn enroll_host_issuer(
        &self,
        issuer: &RequestBindingIssuer,
    ) -> Result<(), HostRequestBindingError> {
        if self.pool.is_closed() || !issuer.observation().is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.issuer
            .set(issuer.clone())
            .map_err(|_| HostRequestBindingError::NotCurrent)
    }

    /// Adopt only the opaque proof minted by the actual verified database owner.
    pub fn adopt_desktop_provenance(
        &self,
        provenance: VerifiedDesktopCustomModelCatalogProvenance,
    ) -> Result<(), HostRequestBindingError> {
        if self.pool.is_closed()
            || !provenance.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.desktop_provenance
            .set(provenance)
            .map_err(|_| HostRequestBindingError::NotCurrent)
    }

    fn scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !identifier(auth.actor().as_str())
            || !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            return Err(Error::NotVisible);
        }
        Ok(())
    }

    async fn observe(
        &self,
        tx: &Transaction<'_>,
        current: &CurrentRequest<'_>,
        cursor: Option<Uuid>,
        deadline: Instant,
    ) -> Result<ObservedPage, Error> {
        let milliseconds = deadline
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining.as_millis().min(5_000))
            .filter(|remaining| *remaining > 0)
            .ok_or(Error::Unavailable)?;
        bounded(
            deadline,
            tx.batch_execute(&format!(
                "SET LOCAL statement_timeout='{milliseconds}ms'; SET LOCAL lock_timeout='{milliseconds}ms'"
            )),
        )
        .await?;
        bounded(
            deadline,
            native::validate_custom_model_catalog_in_transaction(tx),
        )
        .await?;
        current.check_attachment(deadline)?;
        let epoch = current.host.server_session_epoch();
        let lookup = epoch.as_ref().map(|epoch| epoch.lookup_id());
        // This is the final SQL statement. No independently refreshed actor/session or
        // per-owner mapping query may replace this joint READ COMMITTED observation.
        let rows = bounded(
            deadline,
            tx.query(
                current_sql(current.host.kind() == HostRequestBindingKind::DesktopWindow),
                &[
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &current.auth.actor().as_str(),
                    &lookup,
                    &cursor,
                ],
            ),
        )
        .await?;
        let row = rows.first().ok_or(Error::Unavailable)?;
        // Keep this entire Result, including the original tail when successful, even
        // when the following page decoder rejects the 101st row or global mapping.
        let host = current
            .decode_current_host(row, deadline)
            .and_then(|session| {
                current
                    .host
                    .witness(current.auth, session, deadline)
                    .map_err(host_error)
            });
        let page = decode_page(&rows);
        Ok(ObservedPage { host, page })
    }
}

#[async_trait]
impl CustomModelCatalogInventory for PostgresCustomModelCatalogInventory {
    async fn list_current(
        &self,
        auth: &AuthContext,
        request: &CustomModelCatalogPageRequest,
        deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, Error> {
        self.scope(auth)?;
        if !request.is_valid() {
            return Err(Error::InvalidCursor);
        }
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        let cursor = request
            .cursor
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| Error::InvalidCursor)?;
        let target = OriginalInvocation {
            authority: &self.authority,
            auth,
        };
        let current = CurrentRequest::borrow(self, auth, &target, deadline)?;
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| Error::Unavailable)?;
        let transaction = client
            .begin_read_committed_read_only()
            .await
            .map_err(|_| Error::Unavailable)?;
        let observed = self
            .observe(transaction.as_transaction(), &current, cursor, deadline)
            .await;
        // GuardedTransaction records actual ACK (or the original unproven/late state)
        // before returning. A pure Host failure never converts known ACK into unknown.
        transaction
            .rollback()
            .await
            .map_err(|_| Error::Unavailable)?;
        // End this original checkout while its acknowledged disposition is known,
        // before any later pure Host/page rejection. Retained Auth may still refer
        // indirectly to the existing Host/Pool; this is not physical driver closure.
        drop(client);
        let observed = observed?;
        let tail = observed.host?;
        current.check_attachment(deadline)?;
        tail.verify_current(auth, deadline).map_err(host_error)?;
        let page = observed.page?;
        CurrentCustomModelCatalogPage::from_rollback_acknowledged_observation(
            page,
            auth.clone(),
            deadline,
            tail,
        )
    }
}

struct ObservedPage {
    host: Result<Box<dyn CustomModelCatalogHostTailWitness>, Error>,
    page: Result<CustomModelCatalogPage, Error>,
}

struct OriginalInvocation<'a> {
    authority: &'a Arc<()>,
    auth: &'a AuthContext,
}

impl CustomModelCatalogHostTarget for OriginalInvocation<'_> {
    fn matches_authority(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(self.authority, authority)
    }

    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.auth == auth
            && self
                .auth
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(original, current)| {
                    original.identity().same_binding(current.identity())
                })
    }
}

/// Borrowing the guard keeps its original inputs, not an owner/window lifetime lease.
struct CurrentRequest<'a> {
    repository: &'a PostgresCustomModelCatalogInventory,
    auth: &'a AuthContext,
    issuer: &'a RequestBindingIssuer,
    host: CustomModelCatalogHostObservation<'a>,
}

impl<'a> CurrentRequest<'a> {
    fn borrow(
        repository: &'a PostgresCustomModelCatalogInventory,
        auth: &'a AuthContext,
        target: &'a dyn CustomModelCatalogHostTarget,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let issuer = repository.issuer.get().ok_or(Error::Unavailable)?;
        let binding = auth.request_binding().ok_or(Error::NotVisible)?;
        if !issuer.observation().is_current() || !issuer.owns_identity(binding.identity()) {
            return Err(Error::NotVisible);
        }
        let host = binding
            .borrow_custom_model_catalog_host_before(auth, target, deadline)
            .map_err(host_error)?;
        let request = Self {
            repository,
            auth,
            issuer,
            host,
        };
        request.check_attachment(deadline)?;
        if request.host.kind() == HostRequestBindingKind::DesktopWindow
            && repository.desktop_provenance.get().is_none()
        {
            return Err(Error::Unavailable);
        }
        Ok(request)
    }

    fn check_attachment(&self, deadline: Instant) -> Result<(), Error> {
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        let binding = self.auth.request_binding().ok_or(Error::NotVisible)?;
        if !self.issuer.observation().is_current()
            || !self.issuer.owns_identity(self.host.identity())
            || self.host.kind() != binding.kind()
            || !self.host.identity().same_binding(binding.identity())
        {
            return Err(Error::NotVisible);
        }
        Ok(())
    }

    fn decode_current_host(
        &self,
        row: &Row,
        deadline: Instant,
    ) -> Result<Option<CustomModelCatalogSessionFacts>, Error> {
        let actor: Option<String> = column(row, "current_actor")?;
        let raw_generation: Option<i64> = column(row, "current_generation")?;
        let generation = raw_generation
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(Error::NotVisible)?;
        if actor.as_deref() != Some(self.auth.actor().as_str())
            || generation != self.auth.auth_generation().get()
            || column::<bool>(row, "denied")?
        {
            return Err(Error::NotVisible);
        }
        let roles: Vec<String> = column(row, "current_roles")?;
        let parsed = roles
            .iter()
            .map(|role| role.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::NotVisible)?;
        let session = match self.host.kind() {
            HostRequestBindingKind::ServerSession => {
                if self.auth.is_single_user() {
                    return Err(Error::NotVisible);
                }
                let epoch = self.host.server_session_epoch().ok_or(Error::NotVisible)?;
                let (
                    Some(id),
                    Some(user),
                    Some(token),
                    Some(created),
                    Some(updated),
                    Some(expires),
                    Some(issued),
                ) = (
                    column::<Option<String>>(row, "session_id")?,
                    column::<Option<String>>(row, "session_user")?,
                    column::<Option<String>>(row, "session_token")?,
                    column::<Option<OffsetDateTime>>(row, "session_created")?,
                    column::<Option<OffsetDateTime>>(row, "session_updated")?,
                    column::<Option<OffsetDateTime>>(row, "session_expires")?,
                    column::<Option<i64>>(row, "session_generation")?,
                )
                else {
                    return Err(Error::NotVisible);
                };
                if !epoch.matches_raw_row(&id, &user, &token, created, issued)
                    || Some(issued) != raw_generation
                {
                    return Err(Error::NotVisible);
                }
                let role = resolve_effective_role(parsed).map_err(|_| Error::NotVisible)?;
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    false,
                )
                .with_role(role)
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                Some(CustomModelCatalogSessionFacts {
                    created_at: created,
                    updated_at: updated,
                    expires_at: expires,
                    observed_wall: OffsetDateTime::now_utc(),
                    observed_monotonic: Instant::now(),
                })
            }
            HostRequestBindingKind::ServerSingleUserOwner
            | HostRequestBindingKind::DesktopWindow => {
                if !self.auth.is_single_user()
                    || self.host.server_session_epoch().is_some()
                    || roles.as_slice() != ["admin"]
                {
                    return Err(Error::NotVisible);
                }
                let (actor, email) = if self.host.kind() == HostRequestBindingKind::DesktopWindow {
                    (DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL)
                } else {
                    (SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL)
                };
                if self.auth.actor().as_str() != actor
                    || column::<Option<String>>(row, "current_email")?.as_deref() != Some(email)
                {
                    return Err(Error::NotVisible);
                }
                if self.host.kind() == HostRequestBindingKind::DesktopWindow
                    && !self
                        .repository
                        .desktop_provenance
                        .get()
                        .ok_or(Error::Unavailable)?
                        .matches_current_row(row)
                        .map_err(|_| Error::Unavailable)?
                {
                    return Err(Error::NotVisible);
                }
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    true,
                )
                .with_roles([Role::Admin, Role::User])
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                None
            }
        };
        self.check_attachment(deadline)?;
        Ok(session)
    }
}

fn decode_page(rows: &[Row]) -> Result<CustomModelCatalogPage, Error> {
    if rows.is_empty() || rows.len() > CUSTOM_MODEL_CATALOG_PAGE_SIZE + 1 {
        return Err(Error::Unavailable);
    }
    let mut models = Vec::with_capacity(rows.len());
    for row in rows {
        if !column::<bool>(row, "mapping_healthy")? || column::<bool>(row, "page_invalid")? {
            return Err(Error::Unavailable);
        }
        let Some(id) = column::<Option<Uuid>>(row, "page_connection_id")? else {
            if rows.len() != 1 {
                return Err(Error::Unavailable);
            }
            continue;
        };
        let connection_id = id.to_string();
        let protocol = match required::<String>(row, "page_protocol")?.as_str() {
            "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
            "openai_responses" => CustomModelProtocol::OpenaiResponses,
            "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
            _ => return Err(Error::Unavailable),
        };
        let name = required::<String>(row, "page_name")?;
        let endpoint = required::<String>(row, "page_endpoint")?;
        let model = required::<String>(row, "page_model")?;
        let connection_revision = required::<i64>(row, "page_connection_revision")?;
        if !crate::model_connections::readonly_configuration_valid(
            &name,
            protocol,
            &endpoint,
            &model,
            Some(connection_revision),
        ) {
            return Err(Error::Unavailable);
        }
        let entry = CustomModelCatalogEntry {
            source: ModelConnectionSource::Custom,
            connection_id,
            connection_revision,
            model_id: required(row, "page_model_id")?,
            catalog_revision: required(row, "page_catalog_revision")?,
            name,
            protocol,
            model,
            enabled: required(row, "page_enabled")?,
        };
        if !entry.is_valid()
            || models.last().is_some_and(|last: &CustomModelCatalogEntry| {
                last.connection_id >= entry.connection_id
            })
        {
            return Err(Error::Unavailable);
        }
        models.push(entry);
    }
    // Even the actual 101st definition, including its private endpoint, has now passed
    // Rust validation. Only after that complete validation may it become a lookahead.
    let next_cursor = if models.len() > CUSTOM_MODEL_CATALOG_PAGE_SIZE {
        models.truncate(CUSTOM_MODEL_CATALOG_PAGE_SIZE);
        models.last().map(|entry| entry.connection_id.clone())
    } else {
        None
    };
    let page = CustomModelCatalogPage {
        models,
        next_cursor,
    };
    if !page.is_valid() {
        return Err(Error::Unavailable);
    }
    Ok(page)
}

fn column<T: for<'a> FromSql<'a>>(row: &Row, name: &str) -> Result<T, Error> {
    row.try_get(name).map_err(|_| Error::Unavailable)
}

fn required<T: for<'a> FromSql<'a>>(row: &Row, name: &str) -> Result<T, Error> {
    column::<Option<T>>(row, name)?.ok_or(Error::Unavailable)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn host_error(error: HostRequestBindingError) -> Error {
    match error {
        HostRequestBindingError::Missing | HostRequestBindingError::NotCurrent => Error::NotVisible,
        HostRequestBindingError::Unavailable => Error::Unavailable,
    }
}

async fn bounded<T, E>(
    deadline: Instant,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| Error::Unavailable)?;
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    result.map_err(|_| Error::Unavailable)
}

fn current_sql(desktop: bool) -> &'static str {
    static SERVER: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let slot = if desktop { &DESKTOP } else { &SERVER };
    slot.get_or_init(|| {
        let (canary_columns, canary_join) = if desktop {
            (
                ",pcs.system_identifier::text AS catalog_database_system_identifier,
                 d.oid AS catalog_database_oid,
                 CASE WHEN octet_length(dc.dataset_id)=32 THEN dc.dataset_id END AS catalog_canary_dataset,
                 CASE WHEN octet_length(dc.deployment_id) BETWEEN 1 AND 512 THEN dc.deployment_id END AS catalog_canary_deployment,
                 CASE WHEN octet_length(dc.tenant_id) BETWEEN 1 AND 512 THEN dc.tenant_id END AS catalog_canary_tenant,
                 CASE WHEN octet_length(dc.key_id)=32 THEN dc.key_id END AS catalog_canary_key,
                 dc.key_version AS catalog_canary_key_version,dc.canary_schema AS catalog_canary_schema,
                 CASE WHEN octet_length(dc.encrypted_canary) BETWEEN 1 AND 4096 THEN dc.encrypted_canary END AS catalog_canary_encrypted",
                " LEFT JOIN pg_catalog.pg_control_system() pcs ON true
                  LEFT JOIN pg_catalog.pg_database d ON d.datname=current_database()
                  LEFT JOIN openbot_internal.desktop_vault_canaries dc
                    ON dc.deployment_id=$1 AND dc.tenant_id=$2 AND dc.key_version=1",
            )
        } else { ("", "") };
        format!(r#"/* custom_model_catalog_current_joint_observation */
          WITH mapping_health AS MATERIALIZED (
            SELECT NOT EXISTS (
              SELECT 1 FROM public.model_connections m
              FULL OUTER JOIN public.custom_model_catalogs c ON c.connection_id=m.id
              WHERE m.id IS NULL OR c.connection_id IS NULL
                OR c.catalog_revision<=0 OR m.revision<=0
                OR ROW(c.connection_id,c.deployment_id,c.tenant_id,c.owner_user_id,
                       c.model_id,c.protocol,c.endpoint,c.model,c.enabled,c.retired)
                   IS DISTINCT FROM
                   ROW(m.id,m.deployment_id,m.tenant_id,m.owner_user_id,
                       'custom:'::text||m.id::text,m.protocol,m.endpoint,m.model,m.enabled,m.deleted_at IS NOT NULL)
            ) AS mapping_healthy
          ), page AS MATERIALIZED (
            SELECT m.id AS connection_id,m.revision AS connection_revision,
              CASE WHEN octet_length(m.name) BETWEEN 1 AND 100 THEN m.name END AS name,
              CASE WHEN m.protocol IN ('openai_chat_completions','openai_responses','anthropic_messages') THEN m.protocol END AS protocol,
              CASE WHEN octet_length(m.endpoint) BETWEEN 1 AND 2048 THEN m.endpoint END AS endpoint,
              CASE WHEN octet_length(m.model) BETWEEN 1 AND 512 THEN m.model END AS model,
              m.enabled,
              CASE WHEN octet_length(c.model_id)=43 THEN c.model_id END AS model_id,
              c.catalog_revision,
              NOT coalesce(octet_length(m.name) BETWEEN 1 AND 100
                AND octet_length(m.endpoint) BETWEEN 1 AND 2048
                AND octet_length(m.model) BETWEEN 1 AND 512
                AND octet_length(c.model_id)=43
                AND m.protocol IN ('openai_chat_completions','openai_responses','anthropic_messages')
                AND m.revision>0 AND c.catalog_revision>0,false) AS invalid_row
            FROM public.model_connections m
            LEFT JOIN public.custom_model_catalogs c ON c.connection_id=m.id
            WHERE m.deployment_id=$1 AND m.tenant_id=$2 AND m.owner_user_id=$3
              AND m.deleted_at IS NULL AND c.retired=false
              AND ($5::uuid IS NULL OR m.id>$5::uuid)
            ORDER BY m.id LIMIT 101
          )
          SELECT CASE WHEN octet_length(u.id) BETWEEN 1 AND 512 THEN u.id END AS current_actor,
            u.auth_generation AS current_generation,
            CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS current_email,
            EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied,
            ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles,
            CASE WHEN octet_length(s.id) BETWEEN 1 AND 512 THEN s.id END AS session_id,
            CASE WHEN octet_length(s.user_id) BETWEEN 1 AND 512 THEN s.user_id END AS session_user,
            CASE WHEN octet_length(s.token) BETWEEN 1 AND 512 THEN s.token END AS session_token,
            s.created_at AS session_created,s.updated_at AS session_updated,
            s.expires_at AS session_expires,s.auth_generation AS session_generation,
            h.mapping_healthy,p.connection_id AS page_connection_id,
            p.connection_revision AS page_connection_revision,p.name AS page_name,
            p.protocol AS page_protocol,p.endpoint AS page_endpoint,p.model AS page_model,
            p.enabled AS page_enabled,p.model_id AS page_model_id,p.catalog_revision AS page_catalog_revision,
            coalesce(p.invalid_row,false) AS page_invalid
            {canary_columns}
          FROM (SELECT 1) anchor CROSS JOIN mapping_health h
          LEFT JOIN public.users u ON u.id=$3
          LEFT JOIN public.sessions s ON s.id=$4::text AND s.user_id=u.id
          LEFT JOIN page p ON true
          {canary_join}
          ORDER BY p.connection_id"#)
    }).as_str()
}
