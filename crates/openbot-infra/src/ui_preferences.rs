//! Authoritative, actor-scoped UI preference CAS and audit in one PostgreSQL transaction.

use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use async_trait::async_trait;
use openbot_application::{UiPreferenceAdministration, UiPreferenceAdministrationError as Error};
use openbot_contracts::{
    auth::{AuthContext, Role},
    ids::{DeploymentId, TenantId},
    ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences},
};
use openbot_domain::{
    audit::{
        event::{AuditEvent, AuditEventType},
        payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload},
    },
    vault::SecretBytes,
};
use std::sync::Arc;
use tokio_postgres::{IsolationLevel, Row, Transaction};

const LOCK_SEED: i64 = 0x5549_5052_4546_3031;
const COLUMNS: &str = "theme,locale,coalesce(revision,1)::bigint AS revision,updated_at";

/// One configured host scope; Desktop and Server share this authoritative editing port.
#[derive(Clone)]
pub struct PostgresUiPreferenceAdministration {
    pool: deadpool_postgres::Pool,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: Arc<SecretBytes>,
}

impl PostgresUiPreferenceAdministration {
    /// Bind existing PostgreSQL and audit infrastructure without performing I/O.
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
    ) -> Result<Self, Error> {
        if deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
            || audit_key.expose().len() < 32
        {
            return Err(Error::InvalidInput {
                field: "ui_preference_configuration",
            });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            audit_key: Arc::new(audit_key),
        })
    }

    fn scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            return Err(Error::NotVisible);
        }
        Ok(())
    }

    async fn authority(&self, tx: &Transaction<'_>, auth: &AuthContext) -> Result<(), Error> {
        // Authority subqueries run AFTER a possible user lock wait in a new RC statement.
        tx.query_opt(
            "SELECT id FROM public.users WHERE id=$1 FOR SHARE",
            &[&auth.actor().as_str()],
        )
        .await
        .map_err(unavailable)?
        .ok_or(Error::NotVisible)?;
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| Error::Corrupt {
                field: "auth_generation",
            })?;
        let current: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM public.users u WHERE u.id=$1
             AND coalesce(u.auth_generation,0)=$2
             AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id)
             AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)))",
                &[&auth.actor().as_str(), &generation],
            )
            .await
            .map_err(unavailable)?
            .try_get(0)
            .map_err(|_| Error::Corrupt {
                field: "actor_authority",
            })?;
        if current {
            Ok(())
        } else {
            Err(Error::NotVisible)
        }
    }

    async fn row(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        lock: bool,
    ) -> Result<Option<UiPreferences>, Error> {
        let suffix = if lock { " FOR UPDATE" } else { "" };
        tx.query_opt(
            &format!(
                "SELECT {COLUMNS} FROM public.user_ui_preferences
            WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3{suffix}"
            ),
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &auth.actor().as_str(),
            ],
        )
        .await
        .map_err(unavailable)?
        .as_ref()
        .map(decode)
        .transpose()
    }

    async fn audit(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        revision: i64,
    ) -> Result<(), Error> {
        let revision = u64::try_from(revision).map_err(|_| Error::Corrupt { field: "revision" })?;
        let payload = AuditPayload::from_facts([
            AuditFact::ConfigurationChange(AuditLabel::new("ui_preferences_saved")),
            AuditFact::UiPreferencesRevision(revision),
        ])
        .map_err(|_| Error::Corrupt {
            field: "audit_payload",
        })?;
        let (id, created_at) = next_event_coordinates(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(auth.actor().clone()),
            event_type: AuditEventType::parse("configuration.changed").ok_or(Error::Corrupt {
                field: "audit_event",
            })?,
            target_kind: AuditLabel::new("ui_preferences"),
            target_id: Some(AuditIdentifier::new(auth.actor().as_str()).map_err(|_| {
                Error::Corrupt {
                    field: "audit_target",
                }
            })?),
            payload,
            created_at,
        };
        append_event_in_transaction(tx, &event, self.audit_key.expose())
            .await
            .map(|_| ())
            .map_err(|_| Error::Unavailable)
    }
}

#[async_trait]
impl UiPreferenceAdministration for PostgresUiPreferenceAdministration {
    async fn get(&self, auth: &AuthContext) -> Result<UiPreferences, Error> {
        self.scope(auth)?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        tx.batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(unavailable)?;
        self.authority(&tx, auth).await?;
        let preferences = self.row(&tx, auth, false).await?.unwrap_or_default();
        // A missing row remains absent. Neither defaults nor reads mint a revision or audit.
        tx.commit().await.map_err(unavailable)?;
        Ok(preferences)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, Error> {
        self.scope(auth)?;
        if update.is_empty() {
            return Err(Error::InvalidInput { field: "body" });
        }
        if update.expected_revision.is_some_and(|v| v <= 0) {
            return Err(Error::InvalidInput {
                field: "expected_revision",
            });
        }
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        tx.batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(unavailable)?;
        self.authority(&tx, auth).await?;
        // A closed JSON tuple has unambiguous boundaries for the three authoritative keys.
        let identity = serde_json::to_string(&(
            self.deployment.as_str(),
            self.tenant.as_str(),
            auth.actor().as_str(),
        ))
        .map_err(|_| Error::Corrupt { field: "scope" })?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,$2))",
            &[&identity, &LOCK_SEED],
        )
        .await
        .map_err(unavailable)?;
        let theme = update.theme.map(UiTheme::as_str);
        let locale = update.locale.map(UiLocale::as_str);
        let saved = if let Some(current) = self.row(&tx, auth, true).await? {
            let revision = current
                .revision
                .ok_or(Error::Corrupt { field: "revision" })?;
            if update.expected_revision != Some(revision) {
                return Err(stale(current)?);
            }
            let next = revision
                .checked_add(1)
                .ok_or(Error::Corrupt { field: "revision" })?;
            let row=tx.query_one(&format!("UPDATE public.user_ui_preferences SET
                theme=coalesce($4,theme),locale=coalesce($5,locale),revision=$6,updated_at=clock_timestamp()
                WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3 RETURNING {COLUMNS}"),
                &[&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str(),&theme,&locale,&next])
                .await.map_err(unavailable)?;
            decode(&row)?
        } else {
            if update.expected_revision.is_some() {
                return Err(Error::NotVisible);
            }
            let row = tx
                .query_opt(
                    &format!(
                        "INSERT INTO public.user_ui_preferences
                (deployment_id,tenant_id,actor_user_id,theme,locale,revision,updated_at)
                VALUES($1,$2,$3,$4,$5,1,clock_timestamp())
                ON CONFLICT (deployment_id,tenant_id,actor_user_id) DO NOTHING RETURNING {COLUMNS}"
                    ),
                    &[
                        &self.deployment.as_str(),
                        &self.tenant.as_str(),
                        &auth.actor().as_str(),
                        &theme,
                        &locale,
                    ],
                )
                .await
                .map_err(unavailable)?;
            if let Some(row) = row {
                decode(&row)?
            } else {
                // A competing writer outside this port can win the unique key. New RC read,
                // never an upsert, obtains its committed metadata without another write.
                let current = self.row(&tx, auth, true).await?.ok_or(Error::NotVisible)?;
                return Err(stale(current)?);
            }
        };
        self.audit(
            &tx,
            auth,
            saved.revision.ok_or(Error::Corrupt { field: "revision" })?,
        )
        .await?;
        tx.commit().await.map_err(|error| {
            tracing::warn!(error=%error,"UI preferences commit result unknown");
            Error::CommitUnknown
        })?;
        Ok(saved)
    }
}

fn stale(current: UiPreferences) -> Result<Error, Error> {
    current
        .revision_snapshot()
        .map(Error::StaleSnapshot)
        .map_err(|_| Error::Corrupt {
            field: "revision_snapshot",
        })
}

fn decode(row: &Row) -> Result<UiPreferences, Error> {
    let theme = row
        .try_get::<_, Option<String>>("theme")
        .map_err(|_| Error::Corrupt { field: "theme" })?
        .map(|v| match v.as_str() {
            "system" => Ok(UiTheme::System),
            "light" => Ok(UiTheme::Light),
            "dark" => Ok(UiTheme::Dark),
            _ => Err(Error::Corrupt { field: "theme" }),
        })
        .transpose()?;
    let locale = row
        .try_get::<_, Option<String>>("locale")
        .map_err(|_| Error::Corrupt { field: "locale" })?
        .map(|v| match v.as_str() {
            "en" => Ok(UiLocale::En),
            "zh-CN" => Ok(UiLocale::ZhCn),
            _ => Err(Error::Corrupt { field: "locale" }),
        })
        .transpose()?;
    let revision: i64 = row
        .try_get("revision")
        .map_err(|_| Error::Corrupt { field: "revision" })?;
    let updated_at: time::OffsetDateTime =
        row.try_get("updated_at").map_err(|_| Error::Corrupt {
            field: "updated_at",
        })?;
    if (theme.is_none() && locale.is_none()) || revision <= 0 {
        return Err(Error::Corrupt { field: "row" });
    }
    let preferences = UiPreferences {
        theme,
        locale,
        revision: Some(revision),
        updated_at: Some(updated_at),
    };
    preferences
        .revision_snapshot()
        .map_err(|_| Error::Corrupt {
            field: "revision_snapshot",
        })?;
    Ok(preferences)
}

fn unavailable(error: tokio_postgres::Error) -> Error {
    tracing::warn!(error=%error,"UI preferences PostgreSQL operation unavailable");
    Error::Unavailable
}
