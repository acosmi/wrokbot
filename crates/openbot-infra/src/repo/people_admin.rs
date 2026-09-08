//! `PeopleAdministration` 的 PostgreSQL 原子适配器。

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use deadpool_postgres::{GenericClient, Pool};
use openbot_application::{
    OwnedCredentialRetirementError, OwnedCredentialRetirer, PeopleAdministration,
    PeoplePageRequest, PeoplePortError,
};
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::error::IdentityConflictReason;
use openbot_contracts::ids::ActorId;
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::identity::email::NormalizedEmail;
use openbot_domain::identity::revocation::{
    AccessChangeEffect, AccessChangeRejection, AccessChangeRequest, RestoreStep, RevocationStep,
    authorize_access_change,
};
use openbot_domain::identity::roles::{
    AdminFloor, RoleChangeEffect, RoleChangeRejection, RoleChangeRequest, RoleStatement,
    authorize_role_change,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::InfraError;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

pub(crate) const PEOPLE_CHANGE_LOCK_KEY: i64 = 0x4f50_454e_5045_4f31; // `OPENPEO1`

const PERSON_SELECT: &str = "\
SELECT u.id,u.email,u.name,u.image,
       coalesce(bool_or(ur.role='admin'),false) AS is_admin,
       coalesce(bool_or(ur.role='user'),false) AS is_user,
       coalesce(array_agg(distinct a.provider_id ORDER BY a.provider_id) FILTER (WHERE a.provider_id IS NOT NULL), '{}') AS providers,
       max(s.created_at) AS last_signed_in_at,
       coalesce(bool_or(ra.email IS NOT NULL),false) AS revoked,
       coalesce(u.auth_generation,0) AS auth_generation
FROM public.users u
LEFT JOIN public.user_roles ur ON ur.user_id=u.id
LEFT JOIN public.accounts a ON a.user_id=u.id
LEFT JOIN public.sessions s ON s.user_id=u.id
LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email)";

/// PostgreSQL people/auth 原子适配器。
#[derive(Clone)]
pub struct PostgresPeopleAdministration {
    pool: Pool,
    floor: Option<AdminFloor>,
    checkpoint_key: std::sync::Arc<[u8]>,
    owned_credential_retirer: Option<std::sync::Arc<dyn OwnedCredentialRetirer>>,
}

impl PostgresPeopleAdministration {
    /// 构造；checkpoint key 为空直接拒绝，避免 acting 事务无法写 audit。
    pub fn new(
        pool: Pool,
        floor: Option<AdminFloor>,
        checkpoint_key: impl Into<Vec<u8>>,
    ) -> Result<Self, InfraError> {
        let checkpoint_key = checkpoint_key.into();
        if checkpoint_key.is_empty() {
            return Err(InfraError::repository_invariant(
                "audit_checkpoint_key_empty",
            ));
        }
        Ok(Self {
            pool,
            floor,
            checkpoint_key: checkpoint_key.into(),
            owned_credential_retirer: None,
        })
    }

    /// 注入人员移除后的个人凭据退役端口。
    ///
    /// 退役在 people deny/session/generation 事务提交后运行；失败不会撤销已经生效的人员移除，
    /// 重试同一 access revoke 会再次调用该幂等端口，以便恢复上一次未完成的第二阶段。
    #[must_use]
    pub fn with_owned_credential_retirer(
        mut self,
        retirer: std::sync::Arc<dyn OwnedCredentialRetirer>,
    ) -> Self {
        self.owned_credential_retirer = Some(retirer);
        self
    }
}

impl core::fmt::Debug for PostgresPeopleAdministration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresPeopleAdministration")
            .field(
                "configured_admins",
                &self.floor.as_ref().map(AdminFloor::len),
            )
            .field(
                "owned_credential_retirement",
                &self.owned_credential_retirer.is_some(),
            )
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PeopleAdministration for PostgresPeopleAdministration {
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        let client = self.pool.get().await.map_err(log_unavailable)?;
        let person = find_person(&client, actor, self.floor.as_ref())
            .await
            .map_err(port_error)?
            .ok_or(PeoplePortError::Corrupt { field: "actor" })?;
        Ok(CurrentUser {
            id: person.person.id,
            email: person.person.email,
            name: person.person.name,
            image: person.person.image,
            role: person.person.role,
        })
    }

    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError> {
        let client = self.pool.get().await.map_err(log_unavailable)?;
        list_people(&client, request, self.floor.as_ref())
            .await
            .map_err(port_error)
    }

    async fn change_role(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        desired: Role,
    ) -> Result<Person, PeoplePortError> {
        let mut client = self.pool.get().await.map_err(log_unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| port_error(InfraError::query("开始 people role 事务", error)))?;
        lock_people(&transaction).await.map_err(port_error)?;
        let before = find_person(&transaction, subject, self.floor.as_ref())
            .await
            .map_err(port_error)?
            .ok_or(PeoplePortError::NotFound)?;
        let email = NormalizedEmail::normalize(&before.person.email)
            .map_err(|_| PeoplePortError::Corrupt { field: "email" })?;
        let other_effective_admins = other_effective_admins(&transaction, subject)
            .await
            .map_err(port_error)?;
        let request = RoleChangeRequest {
            actor,
            subject,
            subject_email: &email,
            subject_role: before.person.role,
            desired_role: desired,
            other_effective_admins,
        };
        let effect =
            authorize_role_change(self.floor.as_ref(), &request).map_err(role_rejection)?;
        if let RoleChangeEffect::Change(plan) = effect {
            apply_role_plan(&transaction, &plan)
                .await
                .map_err(port_error)?;
            advance_generation(&transaction, subject, None)
                .await
                .map_err(port_error)?;
            append_people_audit(
                &transaction,
                actor,
                subject,
                AuditEventType::parse("person.role_changed").expect("catalog 含 role event"),
                AuditPayload::from_facts([
                    AuditFact::PreviousRole(AuditLabel::new(before.person.role.as_str())),
                    AuditFact::NewRole(AuditLabel::new(desired.as_str())),
                ])
                .expect("两个不同字段不会重复"),
                &self.checkpoint_key,
            )
            .await
            .map_err(port_error)?;
        }
        let after = find_person(&transaction, subject, self.floor.as_ref())
            .await
            .map_err(port_error)?
            .ok_or(PeoplePortError::Corrupt { field: "person" })?;
        transaction
            .commit()
            .await
            .map_err(|error| port_error(InfraError::query("提交 people role 事务", error)))?;
        Ok(after.person)
    }

    async fn change_access(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        revoked: bool,
    ) -> Result<Person, PeoplePortError> {
        let mut client = self.pool.get().await.map_err(log_unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| port_error(InfraError::query("开始 people access 事务", error)))?;
        lock_people(&transaction).await.map_err(port_error)?;
        let before = find_person(&transaction, subject, self.floor.as_ref())
            .await
            .map_err(port_error)?
            .ok_or(PeoplePortError::NotFound)?;
        let email = NormalizedEmail::normalize(&before.person.email)
            .map_err(|_| PeoplePortError::Corrupt { field: "email" })?;
        let request = AccessChangeRequest {
            actor,
            subject,
            subject_email: &email,
            subject_role: before.person.role,
            subject_revoked: before.person.revoked,
            desired_revoked: revoked,
            other_effective_admins: other_effective_admins(&transaction, subject)
                .await
                .map_err(port_error)?,
            current_generation: AuthGeneration::new(before.auth_generation),
        };
        match authorize_access_change(self.floor.as_ref(), &request).map_err(access_rejection)? {
            AccessChangeEffect::Unchanged => {}
            AccessChangeEffect::Revoke(plan) => {
                for step in plan.steps() {
                    match step {
                        RevocationStep::DenyAddress { email, revoked_by } => {
                            transaction
                                .execute(
                                    "INSERT INTO public.revoked_access(email,revoked_at,revoked_by) \
                                     VALUES($1,clock_timestamp(),$2) ON CONFLICT(email) DO NOTHING",
                                    &[&email.as_str(), &revoked_by.as_str()],
                                )
                                .await
                                .map_err(|error| {
                                    port_error(InfraError::query("写 revoked_access", error))
                                })?;
                        }
                        RevocationStep::TerminateSessions { subject } => {
                            transaction
                                .execute(
                                    "DELETE FROM public.sessions WHERE user_id=$1",
                                    &[&subject.as_str()],
                                )
                                .await
                                .map_err(|error| {
                                    port_error(InfraError::query("终止 subject sessions", error))
                                })?;
                        }
                        RevocationStep::AdvanceAuthGeneration { subject, to } => {
                            advance_generation(&transaction, subject, Some(to.get()))
                                .await
                                .map_err(port_error)?;
                        }
                    }
                }
                append_people_audit(
                    &transaction,
                    actor,
                    subject,
                    AuditEventType::parse("person.access_revoked")
                        .expect("catalog 含 revoke event"),
                    AuditPayload::from_facts([AuditFact::AccessRevoked(true)])
                        .expect("单字段 payload 合法"),
                    &self.checkpoint_key,
                )
                .await
                .map_err(port_error)?;
            }
            AccessChangeEffect::Restore(plan) => {
                for step in plan.steps() {
                    match step {
                        RestoreStep::AllowAddress { email } => {
                            transaction
                                .execute(
                                    "DELETE FROM public.revoked_access WHERE email=$1",
                                    &[&email.as_str()],
                                )
                                .await
                                .map_err(|error| {
                                    port_error(InfraError::query("恢复 subject access", error))
                                })?;
                        }
                    }
                }
                append_people_audit(
                    &transaction,
                    actor,
                    subject,
                    AuditEventType::parse("person.access_restored")
                        .expect("catalog 含 restore event"),
                    AuditPayload::from_facts([AuditFact::AccessRevoked(false)])
                        .expect("单字段 payload 合法"),
                    &self.checkpoint_key,
                )
                .await
                .map_err(port_error)?;
            }
        }
        let after = find_person(&transaction, subject, self.floor.as_ref())
            .await
            .map_err(port_error)?
            .ok_or(PeoplePortError::Corrupt { field: "person" })?;
        transaction
            .commit()
            .await
            .map_err(|error| port_error(InfraError::query("提交 people access 事务", error)))?;
        if revoked && let Some(retirer) = &self.owned_credential_retirer {
            retirer
                .retire_owned_credentials(subject, actor)
                .await
                .map_err(|error| {
                    tracing::error!(code = %error, "people 已移除，个人 credential 第二阶段退役失败");
                    match error {
                        OwnedCredentialRetirementError::Unavailable => PeoplePortError::Unavailable,
                        OwnedCredentialRetirementError::Corrupt { field } => {
                            PeoplePortError::Corrupt { field }
                        }
                    }
                })?;
        }
        Ok(after.person)
    }
}

pub(crate) async fn lock_people(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&PEOPLE_CHANGE_LOCK_KEY],
        )
        .await
        .map(|_| ())
        .map_err(|error| InfraError::query("获取 people change 锁", error))
}

pub(crate) async fn apply_role_plan(
    transaction: &tokio_postgres::Transaction<'_>,
    plan: &openbot_domain::identity::roles::RoleAssignmentPlan,
) -> Result<(), InfraError> {
    for statement in plan.statements() {
        match statement {
            RoleStatement::DeleteAllRolesExcept { keep } => {
                let keep = db_role(keep);
                transaction
                    .execute(
                        "DELETE FROM public.user_roles WHERE user_id=$1 AND role<>$2",
                        &[&plan.subject().as_str(), &keep],
                    )
                    .await
                    .map_err(|error| InfraError::query("删除 subject 旧角色", error))?;
            }
            RoleStatement::UpsertRole { role } => {
                let role = db_role(role);
                transaction
                    .execute(
                        "INSERT INTO public.user_roles(user_id,role,created_at) \
                         VALUES($1,$2,clock_timestamp()) ON CONFLICT(user_id,role) DO NOTHING",
                        &[&plan.subject().as_str(), &role],
                    )
                    .await
                    .map_err(|error| InfraError::query("写 subject 目标角色", error))?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn advance_generation(
    transaction: &tokio_postgres::Transaction<'_>,
    subject: &ActorId,
    expected_next: Option<u64>,
) -> Result<u64, InfraError> {
    let row = transaction
        .query_one(
            "UPDATE public.users \
             SET auth_generation=coalesce(auth_generation,0)+1, updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING auth_generation",
            &[&subject.as_str()],
        )
        .await
        .map_err(|error| InfraError::query("递增 subject auth generation", error))?;
    let value: i64 = row
        .try_get(0)
        .map_err(|error| crate::db::RowDecodeError::column("users", "auth_generation", error))?;
    let value = u64::try_from(value)
        .map_err(|_| InfraError::repository_invariant("auth_generation_negative"))?;
    if expected_next.is_some_and(|expected| expected != value) {
        return Err(InfraError::repository_invariant(
            "auth_generation_snapshot_mismatch",
        ));
    }
    Ok(value)
}

async fn other_effective_admins<C: GenericClient + Sync>(
    client: &C,
    subject: &ActorId,
) -> Result<usize, InfraError> {
    let count: i64 = client
        .query_one(
            "SELECT count(distinct u.id)::bigint \
             FROM public.users u JOIN public.user_roles ur ON ur.user_id=u.id AND ur.role='admin' \
             LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email) \
             WHERE u.id<>$1 AND ra.email IS NULL",
            &[&subject.as_str()],
        )
        .await
        .map_err(|error| InfraError::query("统计其他有效 admin", error))?
        .try_get(0)
        .map_err(|error| crate::db::RowDecodeError::column("user_roles", "count", error))?;
    usize::try_from(count).map_err(|_| InfraError::repository_invariant("admin_count_negative"))
}

async fn append_people_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorId,
    subject: &ActorId,
    event_type: AuditEventType,
    payload: AuditPayload,
    key: &[u8],
) -> Result<(), InfraError> {
    let (id, created_at) = next_event_coordinates(transaction).await?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type,
        target_kind: AuditLabel::new("person"),
        target_id: Some(
            AuditIdentifier::new(subject.as_str())
                .map_err(|_| InfraError::repository_invariant("person_id_not_audit_identifier"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, key)
        .await
        .map(|_| ())
}

async fn find_person<C: GenericClient + Sync>(
    client: &C,
    id: &ActorId,
    floor: Option<&AdminFloor>,
) -> Result<Option<PersonRecord>, InfraError> {
    let sql = person_by_id_sql();
    let row = client
        .query_opt(&sql, &[&id.as_str()])
        .await
        .map_err(|error| InfraError::query("按 id 读取 person aggregate", error))?;
    row.as_ref()
        .map(|row| person_from_row(row, floor))
        .transpose()
}

fn person_by_id_sql() -> String {
    format!("{PERSON_SELECT} WHERE u.id=$1 GROUP BY u.id")
}

async fn list_people<C: GenericClient + Sync>(
    client: &C,
    request: PeoplePageRequest,
    floor: Option<&AdminFloor>,
) -> Result<PeoplePage, InfraError> {
    let pattern = request.search.as_deref().map(like_pattern);
    let cursor = request.cursor.as_deref().and_then(decode_cursor);
    let has_cursor = cursor.is_some();
    let cursor_at = cursor.as_ref().and_then(|cursor| cursor.last_signed_in_at);
    let cursor_email = cursor.as_ref().map(|cursor| cursor.email.as_str());
    let limit = i64::from(request.limit) + 1;
    let sql = format!(
        "WITH people AS ({PERSON_SELECT} GROUP BY u.id) \
         SELECT * FROM people \
         WHERE ($1::text IS NULL OR email ILIKE $1 ESCAPE '\\' \
                OR coalesce(name,'') ILIKE $1 ESCAPE '\\') \
           AND (NOT $2::boolean \
                OR (last_signed_in_at IS NULL AND ($3::timestamptz IS NOT NULL OR email>$4)) \
                OR (last_signed_in_at IS NOT NULL AND $3::timestamptz IS NOT NULL AND \
                    (last_signed_in_at<$3 OR (last_signed_in_at=$3 AND email>$4)))) \
         ORDER BY last_signed_in_at DESC NULLS LAST,email LIMIT $5"
    );
    let rows = client
        .query(
            &sql,
            &[&pattern, &has_cursor, &cursor_at, &cursor_email, &limit],
        )
        .await
        .map_err(|error| InfraError::query("列出 people aggregate", error))?;
    let mut people = rows
        .iter()
        .map(|row| person_from_row(row, floor).map(|record| record.person))
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = people.len() > request.limit as usize;
    people.truncate(request.limit as usize);
    let next_cursor = if has_more {
        people.last().map(encode_cursor).transpose()?
    } else {
        None
    };
    Ok(PeoplePage {
        people,
        next_cursor,
    })
}

struct PersonRecord {
    person: Person,
    auth_generation: u64,
}

fn person_from_row(
    row: &tokio_postgres::Row,
    floor: Option<&AdminFloor>,
) -> Result<PersonRecord, InfraError> {
    let id: String = get(row, "id")?;
    let email: String = get(row, "email")?;
    let name = get(row, "name")?;
    let image = get(row, "image")?;
    let is_admin: bool = get(row, "is_admin")?;
    let _is_user: bool = get(row, "is_user")?;
    let providers: Vec<Option<String>> = get(row, "providers")?;
    let providers = providers
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| InfraError::repository_invariant("provider_array_contains_null"))?;
    let last_signed_in_at = get(row, "last_signed_in_at")?;
    let revoked = get(row, "revoked")?;
    let generation: i64 = get(row, "auth_generation")?;
    let auth_generation = u64::try_from(generation)
        .map_err(|_| InfraError::repository_invariant("auth_generation_negative"))?;
    let normalized = NormalizedEmail::normalize(&email)
        .map_err(|_| InfraError::repository_invariant("person_email_invalid"))?;
    Ok(PersonRecord {
        person: Person {
            id: ActorId::new(id),
            email,
            name,
            image,
            role: if is_admin { Role::Admin } else { Role::User },
            providers,
            last_signed_in_at,
            revoked,
            configured_admin: floor.is_some_and(|floor| floor.contains(&normalized)),
        },
        auth_generation,
    })
}

fn get<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    column: &'static str,
) -> Result<T, InfraError> {
    row.try_get(column).map_err(|error| {
        crate::db::RowDecodeError::column("(person aggregate)", column, error).into()
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeopleCursor {
    #[serde(with = "time::serde::rfc3339::option")]
    last_signed_in_at: Option<OffsetDateTime>,
    email: String,
}

fn decode_cursor(raw: &str) -> Option<PeopleCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn encode_cursor(person: &Person) -> Result<String, InfraError> {
    let bytes = serde_json::to_vec(&PeopleCursor {
        last_signed_in_at: person.last_signed_in_at,
        email: person.email.clone(),
    })
    .map_err(|_| InfraError::repository_invariant("people_cursor_encode_failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn like_pattern(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('%');
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped.push('%');
    escaped
}

fn db_role(role: Role) -> crate::db::types::Role {
    match role {
        Role::Admin => crate::db::types::Role::Admin,
        Role::User => crate::db::types::Role::User,
    }
}

fn role_rejection(error: RoleChangeRejection) -> PeoplePortError {
    PeoplePortError::IdentityConflict {
        reason: match error {
            RoleChangeRejection::ConfiguredAdmin => IdentityConflictReason::RoleConfiguredAdmin,
            RoleChangeRejection::SelfDemotion => IdentityConflictReason::RoleSelfDemotion,
            RoleChangeRejection::LastAdmin => IdentityConflictReason::RoleLastAdmin,
        },
    }
}

fn access_rejection(error: AccessChangeRejection) -> PeoplePortError {
    PeoplePortError::IdentityConflict {
        reason: match error {
            AccessChangeRejection::ConfiguredAdmin => IdentityConflictReason::AccessConfiguredAdmin,
            AccessChangeRejection::SelfRevocation => IdentityConflictReason::AccessSelfRevocation,
            AccessChangeRejection::LastAdmin => IdentityConflictReason::AccessLastAdmin,
        },
    }
}

fn log_unavailable(error: deadpool_postgres::PoolError) -> PeoplePortError {
    tracing::error!(error = %error, "people adapter 获取连接失败");
    PeoplePortError::Unavailable
}

fn port_error(error: InfraError) -> PeoplePortError {
    tracing::error!(error = %error, "people adapter 失败");
    match error {
        InfraError::RowDecode(_) | InfraError::RepositoryInvariant { .. } => {
            PeoplePortError::Corrupt { field: "people" }
        }
        InfraError::Connect { .. }
        | InfraError::Query { .. }
        | InfraError::IncompatibleDatabase(_)
        | InfraError::NativeMigration(_) => PeoplePortError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定上游 `PeopleStore.find()` 的复杂度判据：按 id 的过滤必须在聚合前进入 SQL，
    /// 不能退回 `list().find(...)` 或先构造 deployment-wide CTE 再在 Rust 里筛。
    #[test]
    fn finding_one_person_is_id_bounded_before_aggregation() {
        let sql = person_by_id_sql();
        assert_eq!(sql.matches("WHERE u.id=$1").count(), 1);
        assert_eq!(sql.matches("GROUP BY u.id").count(), 1);
        assert!(
            sql.find("WHERE u.id=$1") < sql.find("GROUP BY u.id"),
            "主键谓词必须在 person 聚合之前：{sql}",
        );
        assert!(
            !sql.contains("WITH people AS") && !sql.contains("SELECT * FROM people"),
            "point lookup 不得复用 deployment-wide list 查询：{sql}",
        );

        // 正向对照：列表生产 SQL 确实使用 `WITH people AS`；上面的零命中不是拼错关键字。
        let list_sql =
            format!("WITH people AS ({PERSON_SELECT} GROUP BY u.id) SELECT * FROM people");
        assert!(list_sql.contains("WITH people AS"));
        assert!(list_sql.contains("SELECT * FROM people"));
    }
}
