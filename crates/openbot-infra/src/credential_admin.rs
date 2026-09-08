//! Atomic write-only credential administration on the existing Vault/credentials table. Creation,
//! reference replacement, local retirement and typed audit share one PostgreSQL transaction.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openbot_application::credential_admin::{
    CredentialAdministration, CredentialAdministrationError as Error,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::credential_admin::{
    CREDENTIAL_PAGE_SIZE, CredentialExternalRevocation, CredentialPage, CredentialPageRequest,
    CredentialRecordKind, CredentialRevoked, CredentialStatus, CredentialWrite, CredentialWritten,
    ManualCredentialKind,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::db::types::CredentialKind;
use crate::mcp_connections::PostgresMcpConnections;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::vault::CredentialRecordVault;

const PUBLIC_COLUMNS: &str = "id,kind,provider,key_id,CASE WHEN octet_length(metadata::text)<=65536 THEN metadata ELSE NULL END AS metadata,revoked_at,created_at";
const ADMIN_METADATA: &str = "_openbot_credential_admin";

/// One deployment-owned credential administration boundary; callers cannot choose its scope.
pub struct PostgresCredentialAdministration {
    pool: deadpool_postgres::Pool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: SecretBytes,
    mcp: Arc<PostgresMcpConnections>,
    model_reference: Option<openbot_contracts::credential_admin::CredentialModelReference>,
}

impl PostgresCredentialAdministration {
    /// Use the same pool, Vault and MCP retirement coordinator as the application assembly.
    pub fn new(
        pool: deadpool_postgres::Pool,
        vault: CredentialRecordVault,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
        mcp: Arc<PostgresMcpConnections>,
    ) -> Result<Self, Error> {
        if audit_key.expose().len() < 32
            || deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
        {
            return Err(Error::InvalidInput {
                field: "credential_admin_configuration",
            });
        }
        Ok(Self {
            pool,
            vault,
            deployment,
            tenant,
            audit_key,
            mcp,
            model_reference: None,
        })
    }

    /// Publish the existing default model's non-secret lookup reference for configuration UI.
    pub fn with_model_reference(mut self, provider: String, key_id: String) -> Result<Self, Error> {
        if provider.is_empty()
            || provider.len() > 256
            || key_id.is_empty()
            || key_id.len() > 1024
            || provider.chars().any(char::is_control)
            || key_id.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput {
                field: "model_reference",
            });
        }
        self.model_reference = Some(
            openbot_contracts::credential_admin::CredentialModelReference { provider, key_id },
        );
        Ok(self)
    }

    fn scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !auth.has_role(Role::Admin)
        {
            return Err(Error::NotVisible);
        }
        Ok(())
    }

    async fn write(
        &self,
        auth: &AuthContext,
        previous: Option<Uuid>,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, Error> {
        self.scope(auth)?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        current_admin(&tx, auth).await?;

        // Lock the server before its credential, matching MCP registration/rotation lock order.
        if input.kind() == ManualCredentialKind::Mcp {
            tx.query(
                "SELECT id FROM public.mcp_servers WHERE id=$1 FOR UPDATE",
                &[&input.provider()],
            )
            .await
            .map_err(unavailable)?;
        }
        let old = if let Some(id) = previous {
            let row = tx
                .query_opt(
                    &format!(
                        "SELECT {PUBLIC_COLUMNS} FROM public.credentials WHERE id=$1 FOR UPDATE"
                    ),
                    &[&id],
                )
                .await
                .map_err(unavailable)?
                .ok_or(Error::NotVisible)?;
            let kind: CredentialKind = row.try_get("kind").map_err(|_| corrupt("kind"))?;
            let provider: String = row.try_get("provider").map_err(|_| corrupt("provider"))?;
            let revoked: Option<OffsetDateTime> = row
                .try_get("revoked_at")
                .map_err(|_| corrupt("revoked_at"))?;
            if kind != storage_kind(input.kind())
                || provider != input.provider()
                || revoked.is_some()
            {
                return Err(Error::Conflict);
            }
            Some(row)
        } else {
            None
        };

        let id = Uuid::now_v7();
        let kind = storage_kind(input.kind());
        let secret = SecretBytes::new(input.expose_plaintext().as_bytes().to_vec());
        let consumer = consumer(input.kind(), input.provider());
        let encrypted = self
            .vault
            .seal(
                &id,
                secret_kind(input.kind()),
                SecretPrincipal::Deployment,
                consumer.clone(),
                &secret,
            )
            .map_err(|_| corrupt("vault_seal"))?;
        let metadata = json!({ (ADMIN_METADATA): {"version":1,"userMetadata":input.metadata()} });
        let now: OffsetDateTime = tx
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        let row = tx.query_one(
            &format!("INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7) RETURNING {PUBLIC_COLUMNS},encrypted_value"),
            &[&id, &kind, &input.provider(), &encrypted, &input.key_id(), &metadata, &now]).await.map_err(unavailable)?;
        // A trigger/disk-side mutation must not activate an unreadable replacement.
        let stored: String = row
            .try_get("encrypted_value")
            .map_err(|_| corrupt("encrypted_value"))?;
        let verified = self
            .vault
            .open(
                &id,
                secret_kind(input.kind()),
                SecretPrincipal::Deployment,
                consumer,
                &stored,
            )
            .map_err(|_| corrupt("vault_readback"))?
            .into_secret();
        if !secret.ct_eq(&verified) {
            return Err(corrupt("vault_readback"));
        }

        if let (Some(previous), Some(old)) = (previous, old.as_ref()) {
            invalidate_mcp_references(&tx, previous, Some(id), input.provider(), kind, now).await?;
            tx.execute("UPDATE public.credentials SET revoked_at=$2,updated_at=$2,metadata=metadata || jsonb_build_object('revocation_status','operator_required','revocation_reason','credential_rotated','operator_required_at',$2::timestamptz) WHERE id=$1 AND revoked_at IS NULL", &[&previous,&now]).await.map_err(unavailable)?;
            self.audit(
                &tx,
                auth.actor(),
                AuditEventType::CREDENTIAL_ROTATED,
                id,
                kind,
                input.provider(),
                input.key_id(),
                Some(previous),
            )
            .await?;
            let _ = old;
        } else {
            self.audit(
                &tx,
                auth.actor(),
                AuditEventType::CREDENTIAL_CREATED,
                id,
                kind,
                input.provider(),
                input.key_id(),
                None,
            )
            .await?;
        }
        let status = project(&row)?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(CredentialWritten { credential: status })
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        tx: &Transaction<'_>,
        actor: &ActorId,
        event_type: AuditEventType,
        id: Uuid,
        kind: CredentialKind,
        provider: &str,
        key_id: &str,
        previous: Option<Uuid>,
    ) -> Result<(), Error> {
        let mut facts = vec![
            AuditFact::CredentialKind(AuditLabel::new(kind_label(kind))),
            AuditFact::CredentialProvider(identifier(provider)?),
        ];
        if key_id.len() <= AuditIdentifier::MAX_BYTES {
            facts.push(AuditFact::CredentialKeyReference(identifier(key_id)?));
        } else {
            facts.push(AuditFact::CredentialKeyReferenceHash(Sha256Digest::of(
                key_id.as_bytes(),
            )));
            facts.push(AuditFact::CredentialKeyReferenceBytes(key_id.len() as u64));
        }
        if let Some(previous) = previous {
            facts.push(AuditFact::PreviousCredential(identifier(
                &previous.to_string(),
            )?));
        }
        if event_type == AuditEventType::CREDENTIAL_REVOKED {
            facts.push(AuditFact::VendorRevoked(false));
        }
        let (event_id, created_at) = next_event_coordinates(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let event = AuditEvent {
            id: event_id,
            actor: Some(actor.clone()),
            event_type,
            target_kind: AuditLabel::new("credential"),
            target_id: Some(identifier(&id.to_string())?),
            payload: AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?,
            created_at,
        };
        append_event_in_transaction(tx, &event, self.audit_key.expose())
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}

impl std::fmt::Debug for PostgresCredentialAdministration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresCredentialAdministration")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CredentialAdministration for PostgresCredentialAdministration {
    async fn list(
        &self,
        auth: &AuthContext,
        request: &CredentialPageRequest,
    ) -> Result<CredentialPage, Error> {
        self.scope(auth)?;
        let cursor = request.cursor.as_deref().map(parse_cursor).transpose()?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        current_admin(&tx, auth).await?;
        let limit = i64::try_from(CREDENTIAL_PAGE_SIZE + 1).map_err(|_| corrupt("page_size"))?;
        let rows = if let Some(cursor) = cursor {
            tx.query(&format!("SELECT {PUBLIC_COLUMNS} FROM public.credentials WHERE (created_at,id)>($1,$2) ORDER BY created_at,id LIMIT $3"), &[&cursor.created_at,&cursor.id,&limit]).await
        } else {
            tx.query(&format!("SELECT {PUBLIC_COLUMNS} FROM public.credentials ORDER BY created_at,id LIMIT $1"), &[&limit]).await
        }.map_err(unavailable)?;
        let more = rows.len() > CREDENTIAL_PAGE_SIZE;
        let credentials = rows
            .iter()
            .take(CREDENTIAL_PAGE_SIZE)
            .map(project)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if more {
            let row = &rows[CREDENTIAL_PAGE_SIZE - 1];
            Some(encode_cursor(&PageCursor {
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| corrupt("created_at"))?,
                id: row.try_get("id").map_err(|_| corrupt("id"))?,
            })?)
        } else {
            None
        };
        tx.commit().await.map_err(unavailable)?;
        Ok(CredentialPage {
            credentials,
            next_cursor,
            model_reference: self.model_reference.clone(),
        })
    }

    async fn create(
        &self,
        auth: &AuthContext,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, Error> {
        self.write(auth, None, input).await
    }
    async fn rotate(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, Error> {
        self.write(auth, Some(parse_id(id)?), input).await
    }

    async fn revoke(&self, auth: &AuthContext, id: &str) -> Result<CredentialRevoked, Error> {
        self.scope(auth)?;
        let id = parse_id(id)?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        current_admin(&tx, auth).await?;
        let hint = tx
            .query_opt(
                "SELECT kind,provider FROM public.credentials WHERE id=$1",
                &[&id],
            )
            .await
            .map_err(unavailable)?
            .ok_or(Error::NotVisible)?;
        let hint_kind: CredentialKind = hint.try_get("kind").map_err(|_| corrupt("kind"))?;
        let provider: String = hint.try_get("provider").map_err(|_| corrupt("provider"))?;
        if matches!(
            hint_kind,
            CredentialKind::Mcp | CredentialKind::McpOauthClient | CredentialKind::McpUserToken
        ) {
            tx.query(
                "SELECT id FROM public.mcp_servers WHERE id=$1 FOR UPDATE",
                &[&provider],
            )
            .await
            .map_err(unavailable)?;
        }
        let row = tx
            .query_opt(
                &format!("SELECT {PUBLIC_COLUMNS} FROM public.credentials WHERE id=$1 FOR UPDATE"),
                &[&id],
            )
            .await
            .map_err(unavailable)?
            .ok_or(Error::NotVisible)?;
        let kind: CredentialKind = row.try_get("kind").map_err(|_| corrupt("kind"))?;
        let key_id: String = row.try_get("key_id").map_err(|_| corrupt("key_id"))?;
        if kind != hint_kind
            || row
                .try_get::<_, String>("provider")
                .map_err(|_| corrupt("provider"))?
                != provider
        {
            return Err(Error::Conflict);
        }
        if let Some(revoked_at) = row
            .try_get::<_, Option<OffsetDateTime>>("revoked_at")
            .map_err(|_| corrupt("revoked_at"))?
        {
            let external_revocation = project(&row)?.external_revocation;
            tx.commit().await.map_err(unavailable)?;
            return Ok(CredentialRevoked {
                id: id.to_string(),
                revoked_at,
                external_revocation,
            });
        }
        let now: OffsetDateTime = tx
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        // Managed OAuth retirement owns the exact actor/client snapshot and the existing
        // reconciler; generic metadata cannot substitute a consent or redirect context.
        let extra = self
            .mcp
            .prepare_admin_credential_retirement(&tx, auth, id, kind, &provider, &key_id, now)
            .await
            .map_err(|_| Error::Unavailable)?;
        let external_revocation =
            if extra.get("revocation_status").and_then(Value::as_str) == Some("pending") {
                CredentialExternalRevocation::Pending
            } else {
                CredentialExternalRevocation::OperatorRequired
            };
        tx.execute("UPDATE public.credentials SET revoked_at=$2,updated_at=$2,metadata=metadata || $3::jsonb WHERE id=$1 AND revoked_at IS NULL", &[&id,&now,&extra]).await.map_err(unavailable)?;
        invalidate_mcp_references(&tx, id, None, &provider, kind, now).await?;
        self.audit(
            &tx,
            auth.actor(),
            AuditEventType::CREDENTIAL_REVOKED,
            id,
            kind,
            &provider,
            &key_id,
            None,
        )
        .await?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(CredentialRevoked {
            id: id.to_string(),
            revoked_at: now,
            external_revocation,
        })
    }
}

async fn current_admin(tx: &Transaction<'_>, auth: &AuthContext) -> Result<(), Error> {
    let generation = i64::try_from(auth.auth_generation().get()).map_err(|_| Error::NotVisible)?;
    let row = tx.query_opt("SELECT coalesce(u.auth_generation,0)=$2 AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role='admin') AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)) AS allowed FROM public.users u WHERE u.id=$1 FOR SHARE OF u", &[&auth.actor().as_str(),&generation]).await.map_err(unavailable)?;
    if !row
        .as_ref()
        .is_some_and(|r| r.try_get::<_, bool>("allowed").unwrap_or(false))
    {
        return Err(Error::NotVisible);
    }
    Ok(())
}

async fn invalidate_mcp_references(
    tx: &Transaction<'_>,
    old: Uuid,
    replacement: Option<Uuid>,
    provider: &str,
    kind: CredentialKind,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let rows = tx.query("SELECT id,coalesce(credential_generation,0) AS generation FROM public.mcp_servers WHERE credential_id=$1 FOR UPDATE", &[&old]).await.map_err(unavailable)?;
    for row in rows {
        let server: String = row.try_get("id").map_err(|_| corrupt("server_id"))?;
        if server != provider
            || !matches!(kind, CredentialKind::Mcp | CredentialKind::McpOauthClient)
        {
            return Err(corrupt("credential_reference"));
        }
        let old_generation: i64 = row
            .try_get("generation")
            .map_err(|_| corrupt("credential_generation"))?;
        let generation = old_generation
            .checked_add(1)
            .ok_or_else(|| corrupt("credential_generation"))?;
        tx.execute("UPDATE public.plugin_grants SET state='suspended_missing',credential_generation=coalesce(credential_generation,$2),updated_at=$3 WHERE kind='mcp' AND split_part(ref,'/',1)=$1", &[&server,&old_generation,&now]).await.map_err(unavailable)?;
        // A retired bearer remains an unusable pointer; NULL would silently enable anonymous use.
        tx.execute("UPDATE public.mcp_servers SET credential_id=coalesce($2,credential_id),credential_generation=$3,catalog_generation=CASE WHEN catalog_generation IS NULL THEN NULL ELSE catalog_generation+1 END,last_error='credential_changed_requires_regrant',updated_at=$4 WHERE id=$1", &[&server,&replacement,&generation,&now]).await.map_err(unavailable)?;
    }
    Ok(())
}

fn project(row: &Row) -> Result<CredentialStatus, Error> {
    let kind: CredentialKind = row.try_get("kind").map_err(|_| corrupt("kind"))?;
    let stored: Value = row.try_get("metadata").map_err(|_| corrupt("metadata"))?;
    let revoked_at: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(|_| corrupt("revoked_at"))?;
    let external_revocation = if revoked_at.is_none() {
        CredentialExternalRevocation::NotRequested
    } else {
        match stored.get("revocation_status").and_then(Value::as_str) {
            Some("pending" | "revoking") => CredentialExternalRevocation::Pending,
            Some("revoked") => CredentialExternalRevocation::Revoked,
            _ => CredentialExternalRevocation::OperatorRequired,
        }
    };
    let metadata = if let Some(admin) = stored.get(ADMIN_METADATA) {
        if admin.get("version") != Some(&json!(1)) {
            return Err(corrupt("metadata_version"));
        }
        admin
            .get("userMetadata")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| corrupt("user_metadata"))?
    } else {
        let mut public = stored
            .as_object()
            .cloned()
            .ok_or_else(|| corrupt("metadata"))?;
        public.retain(|key, _| {
            !key.starts_with("revocation_")
                && !key.starts_with("operator_")
                && !key.starts_with("_openbot_")
                && key != "server_removal_revocation"
                && key != "credential_revocation"
        });
        Value::Object(public)
    };
    Ok(CredentialStatus {
        id: row
            .try_get::<_, Uuid>("id")
            .map_err(|_| corrupt("id"))?
            .to_string(),
        kind: record_kind(kind),
        provider: row.try_get("provider").map_err(|_| corrupt("provider"))?,
        key_id: row.try_get("key_id").map_err(|_| corrupt("key_id"))?,
        metadata,
        revoked_at,
        created_at: row
            .try_get("created_at")
            .map_err(|_| corrupt("created_at"))?,
        external_revocation,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageCursor {
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    id: Uuid,
}
fn encode_cursor(cursor: &PageCursor) -> Result<String, Error> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor).map_err(|_| corrupt("cursor"))?))
}
fn parse_cursor(value: &str) -> Result<PageCursor, Error> {
    let invalid = || Error::InvalidInput { field: "cursor" };
    if value.is_empty() || value.len() > 512 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
    let cursor: PageCursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if encode_cursor(&cursor)? != value {
        return Err(invalid());
    }
    Ok(cursor)
}
fn parse_id(value: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(value).map_err(|_| Error::InvalidInput {
        field: "credential_id",
    })
}
fn identifier(value: &str) -> Result<AuditIdentifier, Error> {
    AuditIdentifier::new(value).map_err(|_| corrupt("audit_identifier"))
}
fn unavailable(_: tokio_postgres::Error) -> Error {
    Error::Unavailable
}
fn corrupt(field: &'static str) -> Error {
    Error::Corrupt { field }
}
fn storage_kind(kind: ManualCredentialKind) -> CredentialKind {
    match kind {
        ManualCredentialKind::Model => CredentialKind::Model,
        ManualCredentialKind::Connector => CredentialKind::Connector,
        ManualCredentialKind::Mcp => CredentialKind::Mcp,
    }
}
fn secret_kind(kind: ManualCredentialKind) -> SecretKind {
    match kind {
        ManualCredentialKind::Model => SecretKind::Model,
        ManualCredentialKind::Connector => SecretKind::Connector,
        ManualCredentialKind::Mcp => SecretKind::Mcp,
    }
}
fn consumer(kind: ManualCredentialKind, provider: &str) -> SecretPrincipal {
    if kind == ManualCredentialKind::Mcp {
        SecretPrincipal::Service(ServiceId::new(provider))
    } else {
        SecretPrincipal::Deployment
    }
}
fn kind_label(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Model => "model",
        CredentialKind::Connector => "connector",
        CredentialKind::Agent => "agent",
        CredentialKind::Mcp => "mcp",
        CredentialKind::McpOauthClient => "mcp_oauth_client",
        CredentialKind::McpUserToken => "mcp_user_token",
    }
}
fn record_kind(kind: CredentialKind) -> CredentialRecordKind {
    match kind {
        CredentialKind::Model => CredentialRecordKind::Model,
        CredentialKind::Connector => CredentialRecordKind::Connector,
        CredentialKind::Agent => CredentialRecordKind::Agent,
        CredentialKind::Mcp => CredentialRecordKind::Mcp,
        CredentialKind::McpOauthClient => CredentialRecordKind::McpOauthClient,
        CredentialKind::McpUserToken => CredentialRecordKind::McpUserToken,
    }
}
