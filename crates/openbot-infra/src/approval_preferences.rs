//! remember 批准偏好的内部 PostgreSQL 持久地基。
//!
//! 每次调用从入口计原绝对五秒，使用自己的实际 Pool、原 RC 事务、真实 Host 来源和完整
//! 当前权限。偏好只增加策略输入；本模块不开放用户保存 route、AppCommand 或执行能力。

mod authority_sql;
mod current;

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::approval_preferences::{
    RememberPreferenceRepository, RememberPreferenceRepositoryError as Error,
};
use openbot_contracts::approval_preferences::{
    RememberPreference, RememberPreferenceKey, RememberPreferenceRecordError,
    RememberPreferenceRevision, RememberPreferenceState, RememberPreferenceTarget,
    StoredRememberPreference,
};
use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingError, RememberPreferenceHostTarget, RequestBindingIssuer,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::SecretBytes;
use time::OffsetDateTime;
use tokio_postgres::types::FromSql;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::db::approval_preference_schema;
use crate::db::desktop_vault_canary::VerifiedDesktopRememberPreferenceProvenance;
use crate::db::pool::{DatabasePool, TransactionOwnerError};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use current::{CurrentRequest, bounded};

const BUDGET: Duration = Duration::from_secs(5);

/// 同实际 Pool、namespace 与已登记真实 Host 的内部 repository。
///
/// 构造和 enrollment 不取得数据库连接，不声明可用性；每次操作重新读取实际存储和权限。
pub struct PostgresRememberPreferenceRepository {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    authority: Arc<()>,
    audit_key: SecretBytes,
    issuer: OnceLock<RequestBindingIssuer>,
    desktop_provenance: OnceLock<VerifiedDesktopRememberPreferenceProvenance>,
}

impl fmt::Debug for PostgresRememberPreferenceRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresRememberPreferenceRepository(<bound>)")
    }
}

impl PostgresRememberPreferenceRepository {
    /// 受信组合根以实际 Pool 和审计 key 构造；不产生 Ready 或任何当前授权结论。
    ///
    /// # Errors
    /// namespace 或审计 key 不满足内部边界时返回不含输入原文的封闭错误。
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        checkpoint_key: SecretBytes,
    ) -> Result<Self, Error> {
        if !is_valid_artifact_identity(deployment.as_str()) {
            return Err(Error::InvalidInput {
                field: "deployment",
            });
        }
        if !is_valid_artifact_identity(tenant.as_str()) {
            return Err(Error::InvalidInput { field: "tenant" });
        }
        if checkpoint_key.expose().len() < 32 {
            return Err(Error::InvalidInput { field: "audit_key" });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            authority: Arc::new(()),
            audit_key: checkpoint_key,
            issuer: OnceLock::new(),
            desktop_provenance: OnceLock::new(),
        })
    }

    /// 仅接收由实际 verified canary 和匹配 Local DB owner 派生的封闭原件，一次采用。
    ///
    /// # Errors
    /// 原 Pool/namespace 不核同或已有采用时拒绝，不从安装字符串生成替代 provenance。
    pub fn adopt_desktop_provenance(
        &self,
        provenance: VerifiedDesktopRememberPreferenceProvenance,
    ) -> Result<(), HostRequestBindingError> {
        if !provenance.matches_pool_scope(&self.pool, &self.deployment, &self.tenant) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.desktop_provenance
            .set(provenance)
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// 比较同一个实际 immutable Manager 与 namespace，供真实组合根的一次安装使用。
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

    /// 真实 producer 安装其原发行点，一次 enrollment；之后仍逐调用检查原 attachment。
    ///
    /// # Errors
    /// 原 owner 已关闭或已经登记时拒绝；Clone issuer 不拥有生命周期 lease。
    pub fn enroll_host_issuer(
        &self,
        issuer: &RequestBindingIssuer,
    ) -> Result<(), HostRequestBindingError> {
        if !issuer.observation().is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.issuer
            .set(issuer.clone())
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// 原 Host guard 比较这个具体 repository 调用与原 Auth facts/binding；bool 本身不授予权限。
    #[must_use]
    pub fn matches_host_target(
        &self,
        target: &dyn RememberPreferenceHostTarget,
        auth: &AuthContext,
    ) -> bool {
        self.scope(auth).is_ok()
            && target.matches_authority(&self.authority)
            && target.matches_auth(auth)
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

    fn key(
        &self,
        auth: &AuthContext,
        bot: &BotId,
        target: RememberPreferenceTarget,
    ) -> Result<RememberPreferenceKey, Error> {
        self.scope(auth)?;
        RememberPreferenceKey::new(
            self.deployment.clone(),
            self.tenant.clone(),
            auth.actor().clone(),
            bot.clone(),
            target,
        )
        .map_err(|error| match error {
            RememberPreferenceRecordError::InvalidIdentity(field) => Error::InvalidInput { field },
            _ => Error::InvalidInput { field: "target" },
        })
    }

    async fn execute(
        &self,
        auth: &AuthContext,
        key: &RememberPreferenceKey,
        write: Option<WriteIntent>,
        deadline: Instant,
    ) -> Result<RememberPreferenceState, Error> {
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
        // 真实 PG17/UTF8/8192、0043 prefix 和表形状；与随后原事务共用同一原 client/deadline。
        // BEGIN 尚未取得时失败走默认永久退役，不能宣称已有事务的正常 ROLLBACK ACK。
        bounded(
            deadline,
            approval_preference_schema::verify(client.as_client()),
        )
        .await?;
        let transaction = client.begin_read_committed().await.map_err(owner_error)?;
        let result = self
            .operate(
                transaction.as_transaction(),
                &current,
                auth,
                key,
                write,
                deadline,
            )
            .await;
        match result {
            Ok(state) if write.is_some() => {
                // operate 的最后一步是新 RC full intersection + 同原 Host 的同步尾证。
                transaction.commit().await.map_err(owner_error)?;
                Ok(state)
            }
            result => {
                // read、409、业务/SQL错误都等原 ROLLBACK ACK；失败/晚 ACK 不能输出正常结果。
                transaction.rollback().await.map_err(owner_error)?;
                result
            }
        }
    }

    async fn operate(
        &self,
        tx: &Transaction<'_>,
        current: &CurrentRequest<'_>,
        auth: &AuthContext,
        key: &RememberPreferenceKey,
        write: Option<WriteIntent>,
        deadline: Instant,
    ) -> Result<RememberPreferenceState, Error> {
        current.lock_actor(tx, deadline).await?;
        let initial = current.observe(tx, key, deadline).await?;
        current
            .lock_sources(tx, key, &initial.source, deadline)
            .await?;
        let locked = current.observe(tx, key, deadline).await?;
        locked.require_same(&initial.source)?;
        let source = locked.source.clone();
        bounded(
            deadline,
            tx.query_one(
                authority_sql::LOCK_KEY,
                &[
                    &key.deployment_id().as_str(),
                    &key.tenant_id().as_str(),
                    &key.actor_id().as_str(),
                    &key.bot_id().as_str(),
                    &key.target_kind(),
                    &key.target_id(),
                    &authority_sql::KEY_LOCK_SEED,
                ],
            ),
        )
        .await?;
        let after_key = current.observe(tx, key, deadline).await?;
        after_key.require_same(&source)?;
        let row = bounded(
            deadline,
            tx.query_opt(
                authority_sql::row_for_update(),
                &[
                    &key.deployment_id().as_str(),
                    &key.tenant_id().as_str(),
                    &key.actor_id().as_str(),
                    &key.bot_id().as_str(),
                    &key.target_kind(),
                    &key.target_id(),
                ],
            ),
        )
        .await?;
        let after_row = current.observe(tx, key, deadline).await?;
        after_row.require_same(&source)?;
        let stored = row.as_ref().map(|row| decode(row, key)).transpose()?;
        let Some(write) = write else {
            after_row.verify_tail(auth, deadline)?;
            return Ok(stored.map_or(
                RememberPreferenceState::Absent,
                RememberPreferenceState::Stored,
            ));
        };
        match (&stored, write.expected) {
            (None, Some(_)) => return Err(Error::NotVisible),
            (Some(existing), expected) if expected != Some(existing.revision()) => {
                return Err(Error::Conflict {
                    snapshot: existing.revision_snapshot().map_err(|_| Error::Corrupt {
                        field: "revision_snapshot",
                    })?,
                });
            }
            _ => {}
        }
        let updated = self
            .mutate(tx, key, stored.as_ref(), write, deadline)
            .await?;
        let payload = AuditPayload::from_facts([
            AuditFact::ConfigurationChange(AuditLabel::new("approval_preference_saved")),
            AuditFact::ApprovalPreferenceRevision(updated.revision()),
        ])
        .map_err(|_| Error::Corrupt {
            field: "audit_payload",
        })?;
        // audit coordinate 自身取得原 chain 锁并可能等待；后面仍只发新 RC 观察，不反向加锁。
        let (id, created_at) = bounded(deadline, next_event_coordinates(tx)).await?;
        let after_audit_lock = current.observe(tx, key, deadline).await?;
        after_audit_lock.require_same(&source)?;
        let event = AuditEvent {
            id,
            actor: Some(auth.actor().clone()),
            event_type: AuditEventType::parse("configuration.changed").ok_or(Error::Corrupt {
                field: "audit_event",
            })?,
            target_kind: AuditLabel::new("approval_preference"),
            target_id: Some(
                AuditIdentifier::new(updated.id()).map_err(|_| Error::Corrupt {
                    field: "audit_target",
                })?,
            ),
            payload,
            created_at,
        };
        bounded(
            deadline,
            append_event_in_transaction(tx, &event, self.audit_key.expose()),
        )
        .await?;
        let final_current = current.observe(tx, key, deadline).await?;
        final_current.require_same(&source)?;
        final_current.verify_tail(auth, deadline)?;
        Ok(RememberPreferenceState::Stored(updated))
    }

    async fn mutate(
        &self,
        tx: &Transaction<'_>,
        key: &RememberPreferenceKey,
        old: Option<&StoredRememberPreference>,
        write: WriteIntent,
        deadline: Instant,
    ) -> Result<StoredRememberPreference, Error> {
        let row = match old {
            None => {
                // 只在确认缺行且 None 创建时取得新 ID；read/Absent/409 不铸造 ID 或写行。
                let id = Uuid::now_v7();
                bounded(
                    deadline,
                    tx.query_one(
                        authority_sql::insert(),
                        &[
                            &key.deployment_id().as_str(),
                            &key.tenant_id().as_str(),
                            &key.actor_id().as_str(),
                            &key.bot_id().as_str(),
                            &key.target_kind(),
                            &key.target_id(),
                            &id,
                            &write.preference.as_storage(),
                        ],
                    ),
                )
                .await?
            }
            Some(old) => {
                let next = old
                    .revision()
                    .checked_next()
                    .map_err(|_| Error::Unavailable)?;
                bounded(
                    deadline,
                    tx.query_opt(
                        authority_sql::update(),
                        &[
                            &key.deployment_id().as_str(),
                            &key.tenant_id().as_str(),
                            &key.actor_id().as_str(),
                            &key.bot_id().as_str(),
                            &key.target_kind(),
                            &key.target_id(),
                            &old.revision().get(),
                            &write.preference.as_storage(),
                            &next.get(),
                        ],
                    ),
                )
                .await?
                .ok_or(Error::Unavailable)?
            }
        };
        let stored = decode(&row, key)?;
        let expected_revision = old
            .map_or(Ok(RememberPreferenceRevision::first()), |old| {
                old.revision().checked_next()
            })
            .map_err(|_| Error::Unavailable)?;
        if stored.preference() != write.preference
            || stored.revision() != expected_revision
            || old.is_some_and(|old| {
                old.id() != stored.id() || old.created_at() != stored.created_at()
            })
            || (old.is_none() && stored.created_at() != stored.updated_at())
        {
            return Err(Error::Corrupt {
                field: "mutation_result",
            });
        }
        Ok(stored)
    }
}

#[async_trait]
impl RememberPreferenceRepository for PostgresRememberPreferenceRepository {
    async fn read(
        &self,
        auth: &AuthContext,
        bot: &BotId,
        target: RememberPreferenceTarget,
    ) -> Result<RememberPreferenceState, Error> {
        let deadline = Instant::now() + BUDGET;
        let key = self.key(auth, bot, target)?;
        self.execute(auth, &key, None, deadline).await
    }

    async fn write(
        &self,
        auth: &AuthContext,
        bot: &BotId,
        target: RememberPreferenceTarget,
        preference: RememberPreference,
        expected_revision: Option<i64>,
    ) -> Result<StoredRememberPreference, Error> {
        let deadline = Instant::now() + BUDGET;
        let expected = expected_revision
            .map(RememberPreferenceRevision::new)
            .transpose()
            .map_err(|_| Error::InvalidInput {
                field: "expected_revision",
            })?;
        let key = self.key(auth, bot, target)?;
        match self
            .execute(
                auth,
                &key,
                Some(WriteIntent {
                    preference,
                    expected,
                }),
                deadline,
            )
            .await?
        {
            RememberPreferenceState::Stored(stored) => Ok(stored),
            RememberPreferenceState::Absent => Err(Error::Corrupt {
                field: "mutation_result",
            }),
        }
    }
}

#[derive(Clone, Copy)]
struct WriteIntent {
    preference: RememberPreference,
    expected: Option<RememberPreferenceRevision>,
}

struct OriginalInvocation<'a> {
    authority: &'a Arc<()>,
    auth: &'a AuthContext,
}

impl RememberPreferenceHostTarget for OriginalInvocation<'_> {
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

fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::CommitUnknown => Error::CommitUnknown,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        TransactionOwnerError::AlreadyStarted
        | TransactionOwnerError::DeadlineExceeded
        | TransactionOwnerError::BeginUnavailable
        | TransactionOwnerError::RollbackUnproven => Error::Unavailable,
    }
}

fn decode(row: &Row, expected: &RememberPreferenceKey) -> Result<StoredRememberPreference, Error> {
    let id: Uuid = column(row, "preference_id")?;
    let key = RememberPreferenceKey::from_stored(
        DeploymentId::new(column::<String>(row, "deployment_id")?),
        TenantId::new(column::<String>(row, "tenant_id")?),
        ActorId::new(column::<String>(row, "actor_id")?),
        BotId::new(column::<String>(row, "bot_id")?),
        &column::<String>(row, "target_kind")?,
        column::<String>(row, "target_id")?,
    )
    .map_err(record_error)?;
    if &key != expected
        || column::<String>(row, "tool_name")? != "remember"
        || column::<String>(row, "effect")? != "write"
    {
        return Err(Error::Corrupt {
            field: "complete_key",
        });
    }
    StoredRememberPreference::from_stored(
        &id.to_string(),
        key,
        &column::<String>(row, "preference")?,
        column(row, "revision")?,
        column::<OffsetDateTime>(row, "created_at")?,
        column::<OffsetDateTime>(row, "updated_at")?,
    )
    .map_err(record_error)
}

fn column<T: for<'a> FromSql<'a>>(row: &Row, name: &'static str) -> Result<T, Error> {
    row.try_get(name)
        .map_err(|_| Error::Corrupt { field: name })
}

fn record_error(error: RememberPreferenceRecordError) -> Error {
    let field = match error {
        RememberPreferenceRecordError::InvalidIdentity(field) => field,
        RememberPreferenceRecordError::InvalidTarget => "target_kind",
        RememberPreferenceRecordError::InvalidId => "preference_id",
        RememberPreferenceRecordError::InvalidPreference => "preference",
        RememberPreferenceRecordError::InvalidRevision => "revision",
        RememberPreferenceRecordError::InvalidTimestamp => "timestamp",
        RememberPreferenceRecordError::RevisionOverflow => return Error::Unavailable,
    };
    Error::Corrupt { field }
}
