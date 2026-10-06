//! 原 Host attachment 和同一原事务的新 RC 当前观察。这里不调用另开事务的 verify_current。

use std::future::Future;
use std::time::Instant;

use openbot_application::approval_preferences::RememberPreferenceRepositoryError as Error;
use openbot_contracts::approval_preferences::RememberPreferenceKey;
use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingKind, RememberPreferenceHostObservation,
    RememberPreferenceHostTailWitness, RememberPreferenceHostTarget,
    RememberPreferenceSessionFacts, RequestBindingIssuer,
};
use openbot_domain::identity::roles::resolve_effective_role;
use time::OffsetDateTime;
use tokio_postgres::types::{FromSql, ToSql};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::{PostgresRememberPreferenceRepository, authority_sql};
use crate::auth::single_user::desktop_local::{DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL};
use crate::auth::single_user::{SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL};

pub(super) fn host_error(error: HostRequestBindingError) -> Error {
    match error {
        HostRequestBindingError::Missing | HostRequestBindingError::NotCurrent => Error::NotVisible,
        HostRequestBindingError::Unavailable => Error::Unavailable,
    }
}

/// 每个 await 共用这个入口绝对期限；不会刷新预算或回显底层错误。
pub(super) async fn bounded<T, E>(
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

/// 构造只借实际已登记发行点和实际 Host guard，不保活它的 owner/window lease。
pub(super) struct CurrentRequest<'a> {
    repository: &'a PostgresRememberPreferenceRepository,
    auth: &'a AuthContext,
    issuer: &'a RequestBindingIssuer,
    host: RememberPreferenceHostObservation<'a>,
}

impl<'a> CurrentRequest<'a> {
    pub(super) fn borrow(
        repository: &'a PostgresRememberPreferenceRepository,
        auth: &'a AuthContext,
        target: &'a dyn RememberPreferenceHostTarget,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let issuer = repository.issuer.get().ok_or(Error::Unavailable)?;
        let binding = auth.request_binding().ok_or(Error::NotVisible)?;
        if !issuer.owns_identity(binding.identity()) || !issuer.observation().is_current() {
            return Err(Error::NotVisible);
        }
        let host = binding
            .borrow_remember_preference_host_before(auth, target, deadline)
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

    /// actor 的允许等待先完成，再由后续 observe 另发 statement 重读全部交集。
    pub(super) async fn lock_actor(
        &self,
        tx: &Transaction<'_>,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.check_attachment(deadline)?;
        required(
            tx,
            deadline,
            authority_sql::LOCK_ACTOR,
            &[&self.auth.actor().as_str()],
        )
        .await
    }

    /// 新 statement 的 Host 行、actor 代际/角色/deny、Bot 与 Thread 来源共同解码。
    pub(super) async fn observe(
        &self,
        tx: &Transaction<'_>,
        key: &RememberPreferenceKey,
        deadline: Instant,
    ) -> Result<CurrentSnapshot, Error> {
        self.check_attachment(deadline)?;
        let epoch = self.host.server_session_epoch();
        let lookup = epoch.as_ref().map(|epoch| epoch.lookup_id());
        let desktop = self.host.kind() == HostRequestBindingKind::DesktopWindow;
        let row = bounded(
            deadline,
            tx.query_one(
                authority_sql::current(desktop),
                &[
                    &key.deployment_id().as_str(),
                    &key.tenant_id().as_str(),
                    &key.actor_id().as_str(),
                    &key.bot_id().as_str(),
                    &key.target_kind(),
                    &key.target_id(),
                    &lookup,
                ],
            ),
        )
        .await?;
        self.check_attachment(deadline)?;
        if !column::<bool>(&row, "source_visible")? {
            return Err(Error::NotVisible);
        }
        let session = self.decode_current_host(&row, deadline)?;
        let source = SourceRows::decode(&row, key)?;
        let witness = self
            .host
            .witness(self.auth, session, deadline)
            .map_err(host_error)?;
        self.check_attachment(deadline)?;
        witness
            .verify_current(self.auth, deadline)
            .map_err(host_error)?;
        Ok(CurrentSnapshot { source, witness })
    }

    fn decode_current_host(
        &self,
        row: &Row,
        deadline: Instant,
    ) -> Result<Option<RememberPreferenceSessionFacts>, Error> {
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
                // SessionLifetimePolicy 留在真实 producer；仅将同一 statement 的实际时间交给它。
                Some(RememberPreferenceSessionFacts {
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
                let (actor, email) = match self.host.kind() {
                    HostRequestBindingKind::ServerSingleUserOwner => {
                        (SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL)
                    }
                    HostRequestBindingKind::DesktopWindow => {
                        (DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL)
                    }
                    HostRequestBindingKind::ServerSession => unreachable!("session handled above"),
                };
                if self.auth.actor().as_str() != actor
                    || column::<Option<String>>(row, "current_email")?.as_deref() != Some(email)
                {
                    return Err(Error::NotVisible);
                }
                if self.host.kind() == HostRequestBindingKind::DesktopWindow {
                    let proof = self
                        .repository
                        .desktop_provenance
                        .get()
                        .ok_or(Error::Unavailable)?;
                    if !proof
                        .matches_current_row(row)
                        .map_err(|_| Error::Unavailable)?
                    {
                        return Err(Error::NotVisible);
                    }
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

    /// 来源共享锁一律 NOWAIT。许可的 actor/key/row/audit 等待后不再取得任何反向来源锁。
    pub(super) async fn lock_sources(
        &self,
        tx: &Transaction<'_>,
        key: &RememberPreferenceKey,
        source: &SourceRows,
        deadline: Instant,
    ) -> Result<(), Error> {
        required(
            tx,
            deadline,
            authority_sql::LOCK_BOT,
            &[&key.bot_id().as_str()],
        )
        .await?;
        required(
            tx,
            deadline,
            authority_sql::LOCK_PROFILE,
            &[&key.bot_id().as_str()],
        )
        .await?;
        if let Some(package) = source.bot_package {
            required(tx, deadline, authority_sql::LOCK_PACKAGE, &[&package]).await?;
        }
        if let Some(thread) = &source.thread {
            required(
                tx,
                deadline,
                authority_sql::LOCK_THREAD,
                &[
                    &thread.id.as_str(),
                    &key.deployment_id().as_str(),
                    &key.tenant_id().as_str(),
                ],
            )
            .await?;
            match thread.kind.as_str() {
                "direct_bot" => {
                    required(
                        tx,
                        deadline,
                        authority_sql::LOCK_THREAD_MEMBER,
                        &[&thread.id.as_str(), &key.actor_id().as_str()],
                    )
                    .await?;
                }
                "channel" => {
                    required(
                        tx,
                        deadline,
                        authority_sql::LOCK_CHANNEL,
                        &[&thread.anchor.as_str()],
                    )
                    .await?;
                    required(
                        tx,
                        deadline,
                        authority_sql::LOCK_CHANNEL_MEMBER,
                        &[&thread.anchor.as_str(), &key.actor_id().as_str()],
                    )
                    .await?;
                    required(
                        tx,
                        deadline,
                        authority_sql::LOCK_CHANNEL_BOT,
                        &[&thread.anchor.as_str(), &key.bot_id().as_str()],
                    )
                    .await?;
                    if let Some(package) = thread.channel_package {
                        required(tx, deadline, authority_sql::LOCK_PACKAGE, &[&package]).await?;
                    }
                }
                _ => return Err(Error::NotVisible),
            }
        }
        Ok(())
    }
}

pub(super) struct CurrentSnapshot {
    pub(super) source: SourceRows,
    witness: Box<dyn RememberPreferenceHostTailWitness>,
}

impl CurrentSnapshot {
    pub(super) fn verify_tail(&self, auth: &AuthContext, deadline: Instant) -> Result<(), Error> {
        self.witness
            .verify_current(auth, deadline)
            .map_err(host_error)
    }

    pub(super) fn require_same(&self, locked: &SourceRows) -> Result<(), Error> {
        if &self.source == locked {
            Ok(())
        } else {
            Err(Error::NotVisible)
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SourceRows {
    bot_package: Option<Uuid>,
    thread: Option<ThreadRows>,
}

#[derive(Clone, PartialEq, Eq)]
struct ThreadRows {
    id: String,
    kind: String,
    anchor: String,
    channel_package: Option<Uuid>,
}

impl SourceRows {
    fn decode(row: &Row, key: &RememberPreferenceKey) -> Result<Self, Error> {
        let id: Option<String> = column(row, "source_thread")?;
        let kind: Option<String> = column(row, "source_kind")?;
        let anchor: Option<String> = column(row, "source_anchor")?;
        let channel_package: Option<Uuid> = column(row, "channel_package")?;
        let thread = if key.target_kind() == "memory_thread" {
            let (Some(id), Some(kind), Some(anchor)) = (id, kind, anchor) else {
                return Err(Error::NotVisible);
            };
            if id != key.target_id()
                || !is_valid_artifact_identity(&anchor)
                || !matches!(kind.as_str(), "direct_bot" | "channel")
                || (kind == "direct_bot" && anchor != key.bot_id().as_str())
            {
                return Err(Error::NotVisible);
            }
            Some(ThreadRows {
                id,
                kind,
                anchor,
                channel_package,
            })
        } else {
            if id.is_some() || kind.is_some() || anchor.is_some() || channel_package.is_some() {
                return Err(Error::Corrupt {
                    field: "source_scope",
                });
            }
            None
        };
        Ok(Self {
            bot_package: column(row, "bot_package")?,
            thread,
        })
    }
}

async fn required(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &'static str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<(), Error> {
    bounded(deadline, tx.query_opt(sql, parameters))
        .await?
        .ok_or(Error::NotVisible)?;
    Ok(())
}

fn column<T: for<'a> FromSql<'a>>(row: &Row, name: &'static str) -> Result<T, Error> {
    row.try_get(name)
        .map_err(|_| Error::Corrupt { field: name })
}
