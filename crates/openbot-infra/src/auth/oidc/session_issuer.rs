//! 已验证 OIDC identity → PostgreSQL user/account/group/session 的唯一原子签发面。
//!
//! 明文 session token 先在内存铸造，但只有事务完成 user/account、撤权、floor、membership、
//! generation、keyed-hash session 与 audit 后才返回调用方。任何一步失败都会 rollback；调用方拿
//! 不到 token。账号按 `(provider_id, sub)` 锚定并要求存量 issuer 精确相等；新 provider 可按
//! 已验证规范 email 链接既有人，兑现上游“同一人一周 Entra、下一周 Okta”语义。

use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use deadpool_postgres::Pool;
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, ChannelId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::identity::email::NormalizedEmail;
use openbot_domain::identity::groups::{
    ChannelAudience, ChannelAudienceBinding, DeploymentMode, EffectivePrincipal,
    MembershipProvisioningPlan, project_membership,
};
use openbot_domain::identity::revocation::{DenyListAnswer, SignInPath, screen_sign_in};
use openbot_domain::identity::roles::{
    AdminFloor, AdminFloorDecision, apply_admin_floor, plan_set_role, resolve_effective_role,
    seed_role,
};
use openbot_domain::identity::session::{
    SessionHashKey, SessionLifetimePolicy, SessionToken, SessionTokenHash, authenticate,
};
use openbot_domain::vault::SecretBytes;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use super::claims::VerifiedIdentity;
use super::email::{EmailDomain, domain_of};
use super::provider::{OidcProviderConfig, ProviderKind, ProviderOrigin};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::repo::people_admin::{advance_generation, apply_role_plan, lock_people};

const SESSION_TOKEN_BYTES: usize = 32;
const MAX_USER_AGENT_BYTES: usize = 512;
const MAX_IP_BYTES: usize = 64;

/// 登录签发失败；不带 email/sub/token/数据库原值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionIssueError {
    #[error("oidc_session_dependency_unavailable")]
    DependencyUnavailable,
    #[error("oidc_session_access_revoked")]
    AccessRevoked,
    #[error("oidc_session_identity_conflict")]
    IdentityConflict,
    #[error("oidc_session_state_corrupt")]
    Corrupt,
    #[error("oidc_session_random_unavailable")]
    RandomUnavailable,
}

/// 协议层已经完成密码学与协议校验后，交给统一 session 事务的最小身份事实。
pub(crate) struct FederatedIdentity {
    issuer: String,
    subject: String,
    email: String,
    groups: std::collections::BTreeSet<openbot_domain::identity::groups::GroupName>,
    group_normalization: openbot_domain::identity::groups::GroupNormalization,
}

impl FederatedIdentity {
    fn from_oidc(identity: &VerifiedIdentity) -> Self {
        Self {
            issuer: identity.issuer().as_str().to_owned(),
            subject: identity.subject().as_str().to_owned(),
            email: identity.email().to_owned(),
            groups: identity.groups().clone(),
            group_normalization: identity.group_normalization(),
        }
    }

    /// 只给同 crate 的 SAML verifier：调用点必须先完成签名覆盖与全部 profile 判定。
    #[cfg(feature = "server-sso")]
    pub(crate) fn from_verified_saml(
        issuer: String,
        subject: String,
        email: String,
        groups: std::collections::BTreeSet<openbot_domain::identity::groups::GroupName>,
        group_normalization: openbot_domain::identity::groups::GroupNormalization,
    ) -> Self {
        Self {
            issuer,
            subject,
            email,
            groups,
            group_normalization,
        }
    }

    #[cfg(all(test, feature = "server-sso"))]
    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    #[cfg(all(test, feature = "server-sso"))]
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }
}

/// 协议无关的 provider 绑定；字段不公开，只有已验证配置 adapter 能构造。
pub(crate) struct FederatedProvider {
    id: super::provider::ProviderId,
    issuer: String,
    origin: ProviderOrigin,
    domains: std::collections::BTreeSet<EmailDomain>,
    scoped_subject_prefix: Option<&'static str>,
}

impl FederatedProvider {
    fn from_oidc(provider: &OidcProviderConfig) -> Self {
        Self {
            id: provider.id().clone(),
            issuer: provider.issuer().as_str().to_owned(),
            origin: provider.origin(),
            domains: provider.domains().clone(),
            scoped_subject_prefix: matches!(
                provider.kind(),
                ProviderKind::Entra { tenants, .. } if tenants.is_tenant_independent()
            )
            .then_some("entra1_"),
        }
    }

    #[cfg(feature = "server-sso")]
    pub(crate) fn verified_saml(
        id: super::provider::ProviderId,
        issuer: String,
        domains: std::collections::BTreeSet<EmailDomain>,
    ) -> Self {
        Self {
            id,
            issuer,
            origin: ProviderOrigin::DynamicallyRegistered,
            domains,
            scoped_subject_prefix: Some("saml1_"),
        }
    }
}

/// 明文 bearer cookie；不 Clone/Serialize，Debug 永远打码。
pub struct SessionCookieValue(SecretBytes);

impl SessionCookieValue {
    #[must_use]
    pub fn expose(&self) -> &str {
        core::str::from_utf8(self.0.expose()).expect("session token 只由 base64url ASCII 编码构造")
    }
}

impl core::fmt::Debug for SessionCookieValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SessionCookieValue([REDACTED])")
    }
}

/// commit 后可交给 HTTP 层的签发结果。
pub struct IssuedSession {
    token: SessionCookieValue,
    actor: ActorId,
    email: NormalizedEmail,
    expires_at: OffsetDateTime,
    path: SignInPath,
}

impl IssuedSession {
    #[must_use]
    pub const fn token(&self) -> &SessionCookieValue {
        &self.token
    }

    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }

    #[must_use]
    pub const fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    #[must_use]
    pub const fn path(&self) -> SignInPath {
        self.path
    }
}

impl core::fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssuedSession")
            .field("token", &self.token)
            .field("actor", &self.actor)
            .field("email", &self.email)
            .field("expires_at", &self.expires_at)
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Clone)]
pub struct PostgresOidcSessionIssuer {
    pool: Pool,
    hash_key: Arc<SecretBytes>,
    lifetime: SessionLifetimePolicy,
    floor: AdminFloor,
    checkpoint_key: Arc<SecretBytes>,
}

impl PostgresOidcSessionIssuer {
    pub fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        lifetime: SessionLifetimePolicy,
        floor: AdminFloor,
        checkpoint_key: impl Into<Vec<u8>>,
    ) -> Result<Self, SessionIssueError> {
        let hash_key = hash_key.into();
        let checkpoint_key = checkpoint_key.into();
        if hash_key.is_empty() || checkpoint_key.is_empty() {
            return Err(SessionIssueError::Corrupt);
        }
        Ok(Self {
            pool,
            hash_key: Arc::new(SecretBytes::new(hash_key)),
            lifetime,
            floor,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
        })
    }

    /// 在一个事务里 provision/refresh 并签发；commit 后才返回明文 token。
    pub async fn issue(
        &self,
        identity: &VerifiedIdentity,
        provider: &OidcProviderConfig,
        now: OffsetDateTime,
        peer_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<IssuedSession, SessionIssueError> {
        let identity = FederatedIdentity::from_oidc(identity);
        let provider = FederatedProvider::from_oidc(provider);
        self.issue_federated(&identity, &provider, now, peer_ip, user_agent)
            .await
    }

    pub(crate) async fn issue_federated(
        &self,
        identity: &FederatedIdentity,
        provider: &FederatedProvider,
        now: OffsetDateTime,
        peer_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<IssuedSession, SessionIssueError> {
        if identity.issuer != provider.issuer {
            return Err(SessionIssueError::IdentityConflict);
        }
        if provider.origin == ProviderOrigin::DynamicallyRegistered {
            let domain = domain_of(&identity.email).ok_or(SessionIssueError::IdentityConflict)?;
            if !provider.domains.contains(&domain) {
                return Err(SessionIssueError::IdentityConflict);
            }
        }
        let incoming_email =
            NormalizedEmail::normalize(&identity.email).map_err(|_| SessionIssueError::Corrupt)?;
        let token = generate_token()?;
        let token_hash = SessionTokenHash::compute(
            SessionToken::new(token.expose().as_bytes()),
            SessionHashKey::new(self.hash_key.expose()),
        )
        .to_column_value();

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        lock_people(&transaction)
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;

        let provider_id = provider.id.as_str();
        let account_subject = account_subject_key(identity, provider);
        let subject = account_subject.as_str();
        let issuer = identity.issuer.as_str();
        let account_row = transaction
            .query_opt(
                "SELECT a.user_id,a.issuer,u.email,u.groups,coalesce(u.auth_generation,0) AS auth_generation \
                 FROM public.accounts a JOIN public.users u ON u.id=a.user_id \
                 WHERE a.provider_id=$1 AND a.account_id=$2 FOR UPDATE OF a,u",
                &[&provider_id, &subject],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;

        let (actor, stored_email, mut generation, path, is_new_user, needs_account) =
            match account_row {
                Some(row) => {
                    let stored_issuer: Option<String> = get(&row, "issuer")?;
                    if stored_issuer.as_deref() != Some(issuer) {
                        return Err(SessionIssueError::IdentityConflict);
                    }
                    let actor = ActorId::new(get::<String>(&row, "user_id")?);
                    let email = NormalizedEmail::normalize(&get::<String>(&row, "email")?)
                        .map_err(|_| SessionIssueError::Corrupt)?;
                    let generation = generation_from_row(&row)?;
                    (
                        actor,
                        email,
                        generation,
                        SignInPath::ReturningAccount,
                        false,
                        false,
                    )
                }
                None => {
                    let rows = transaction
                        .query(
                            "SELECT id,email,groups,coalesce(auth_generation,0) AS auth_generation \
                             FROM public.users WHERE lower(email)=$1 FOR UPDATE",
                            &[&incoming_email.as_str()],
                        )
                        .await
                        .map_err(|_| SessionIssueError::DependencyUnavailable)?;
                    if rows.len() > 1 {
                        return Err(SessionIssueError::IdentityConflict);
                    }
                    match rows.first() {
                        Some(row) => (
                            ActorId::new(get::<String>(row, "id")?),
                            NormalizedEmail::normalize(&get::<String>(row, "email")?)
                                .map_err(|_| SessionIssueError::Corrupt)?,
                            generation_from_row(row)?,
                            SignInPath::ReturningAccount,
                            false,
                            true,
                        ),
                        None => (
                            ActorId::new(Uuid::now_v7().to_string()),
                            incoming_email.clone(),
                            AuthGeneration::new(0),
                            SignInPath::NewAccount,
                            true,
                            true,
                        ),
                    }
                }
            };

        let revoked = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM public.revoked_access \
                 WHERE lower(email)=$1 OR lower(email)=$2)",
                &[&incoming_email.as_str(), &stored_email.as_str()],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?
            .try_get::<_, bool>(0)
            .map_err(|_| SessionIssueError::Corrupt)?;
        if revoked {
            append_session_audit(
                &transaction,
                None,
                Some(&actor),
                "session.refused",
                AuditPayload::from_facts([AuditFact::ErrorCode(AuditLabel::new(
                    "identity_access_revoked",
                ))])
                .map_err(|_| SessionIssueError::Corrupt)?,
                self.checkpoint_key.expose(),
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
            return Err(SessionIssueError::AccessRevoked);
        }
        let cleared = screen_sign_in(DenyListAnswer::not_listed(incoming_email.clone()), path)
            .map_err(|_| SessionIssueError::AccessRevoked)?;

        if is_new_user {
            let empty_groups: Vec<String> = Vec::new();
            transaction
                .execute(
                    "INSERT INTO public.users(id,email,name,image,email_verified,groups,created_at,updated_at,auth_generation) \
                     VALUES($1,$2,NULL,NULL,true,$3,$4,$4,0)",
                    &[&actor.as_str(), &incoming_email.as_str(), &empty_groups, &now],
                )
                .await
                .map_err(|_| SessionIssueError::IdentityConflict)?;
        }

        let mut authorization_changed = false;
        if !is_new_user && stored_email != incoming_email {
            let conflict = transaction
                .query_opt(
                    "SELECT id FROM public.users WHERE lower(email)=$1 AND id<>$2 FOR UPDATE",
                    &[&incoming_email.as_str(), &actor.as_str()],
                )
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
            if conflict.is_some() {
                return Err(SessionIssueError::IdentityConflict);
            }
            transaction
                .execute(
                    "UPDATE public.users SET email=$2,email_verified=true,updated_at=$3 WHERE id=$1",
                    &[&actor.as_str(), &incoming_email.as_str(), &now],
                )
                .await
                .map_err(|_| SessionIssueError::IdentityConflict)?;
            authorization_changed = true;
        }

        if needs_account {
            let account_row_id = Uuid::now_v7().to_string();
            transaction
                .execute(
                    "INSERT INTO public.accounts( \
                       id,account_id,provider_id,user_id,access_token,refresh_token,id_token, \
                       access_token_expires_at,refresh_token_expires_at,scope,password,created_at,updated_at,issuer) \
                     VALUES($1,$2,$3,$4,NULL,NULL,NULL,NULL,NULL,NULL,NULL,$5,$5,$6)",
                    &[
                        &account_row_id,
                        &subject,
                        &provider_id,
                        &actor.as_str(),
                        &now,
                        &issuer,
                    ],
                )
                .await
                .map_err(|_| SessionIssueError::IdentityConflict)?;
        }

        let role_rows = transaction
            .query(
                "SELECT role::text AS role FROM public.user_roles WHERE user_id=$1 ORDER BY role",
                &[&actor.as_str()],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        let current_role = role_rows
            .iter()
            .map(|row| {
                get::<String>(row, "role")
                    .and_then(|raw| Role::from_str(&raw).map_err(|_| SessionIssueError::Corrupt))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let current_role = resolve_effective_role(current_role);

        let mut floor_granted = false;
        if is_new_user {
            let target = seed_role(&self.floor, &incoming_email);
            floor_granted = target == Role::Admin;
            apply_role_plan(&transaction, &plan_set_role(&actor, target))
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        } else {
            match apply_admin_floor(Some(&self.floor), &actor, &incoming_email, current_role) {
                AdminFloorDecision::NotOnFloor => {
                    current_role.map_err(|_| SessionIssueError::Corrupt)?;
                }
                AdminFloorDecision::AlreadyAdmin(plan) => {
                    apply_role_plan(&transaction, &plan)
                        .await
                        .map_err(|_| SessionIssueError::DependencyUnavailable)?;
                }
                AdminFloorDecision::Granted(plan) => {
                    apply_role_plan(&transaction, &plan)
                        .await
                        .map_err(|_| SessionIssueError::DependencyUnavailable)?;
                    floor_granted = true;
                    authorization_changed = true;
                }
            }
        }

        let groups: Vec<String> = identity
            .groups
            .iter()
            .map(|group| group.as_str().to_owned())
            .collect();
        transaction
            .execute(
                "UPDATE public.users SET groups=$2,updated_at=$3 WHERE id=$1",
                &[&actor.as_str(), &groups, &now],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;

        let channels = load_channel_audiences(&transaction).await?;
        let principal = EffectivePrincipal::from_cleared(
            &cleared,
            actor.clone(),
            DeploymentMode::MultiUser,
            identity.groups.clone(),
            identity.group_normalization,
        );
        let projected = project_membership(&principal, &channels);
        let existing_rows = transaction
            .query(
                "SELECT channel_id FROM public.channel_memberships WHERE user_id=$1 FOR UPDATE",
                &[&actor.as_str()],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        let existing = MembershipProvisioningPlan::from_materialized(
            existing_rows
                .iter()
                .map(|row| get::<String>(row, "channel_id").map(ChannelId::new))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let settlement = projected.diff(&existing).settle(generation);
        for channel in settlement.revoked() {
            transaction
                .execute(
                    "DELETE FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2",
                    &[&channel.as_str(), &actor.as_str()],
                )
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        }
        for channel in settlement.granted() {
            transaction
                .execute(
                    "INSERT INTO public.channel_memberships(channel_id,user_id,created_at) \
                     VALUES($1,$2,$3) ON CONFLICT(channel_id,user_id) DO NOTHING",
                    &[&channel.as_str(), &actor.as_str(), &now],
                )
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        }
        if !settlement.revoked().is_empty() {
            authorization_changed = true;
        }

        if authorization_changed {
            let expected = generation.next();
            if expected == generation || expected.get() > i64::MAX as u64 {
                return Err(SessionIssueError::Corrupt);
            }
            let advanced = advance_generation(&transaction, &actor, Some(expected.get()))
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
            generation = AuthGeneration::new(advanced);
            transaction
                .execute(
                    "DELETE FROM public.sessions WHERE user_id=$1",
                    &[&actor.as_str()],
                )
                .await
                .map_err(|_| SessionIssueError::DependencyUnavailable)?;
        }

        let minted = authenticate(&cleared, generation, now);
        let expires_at = now + self.lifetime.absolute();
        let session_id = Uuid::now_v7().to_string();
        let generation_i64 = i64::try_from(minted.state().generation().get())
            .map_err(|_| SessionIssueError::Corrupt)?;
        let ip = bounded_optional(peer_ip, MAX_IP_BYTES);
        let user_agent = bounded_optional(user_agent, MAX_USER_AGENT_BYTES);
        transaction
            .execute(
                "INSERT INTO public.sessions( \
                   id,user_id,token,expires_at,ip_address,user_agent,created_at,updated_at,auth_generation) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8)",
                &[
                    &session_id,
                    &actor.as_str(),
                    &token_hash,
                    &expires_at,
                    &ip,
                    &user_agent,
                    &now,
                    &generation_i64,
                ],
            )
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;

        if floor_granted {
            append_session_audit(
                &transaction,
                Some(&actor),
                Some(&actor),
                "person.admin_by_configuration",
                AuditPayload::empty(),
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        append_session_audit(
            &transaction,
            Some(&actor),
            Some(&actor),
            "session.signed_in",
            AuditPayload::empty(),
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| SessionIssueError::DependencyUnavailable)?;

        Ok(IssuedSession {
            token,
            actor,
            email: incoming_email,
            expires_at,
            path: minted.path(),
        })
    }
}

impl core::fmt::Debug for PostgresOidcSessionIssuer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresOidcSessionIssuer")
            .field("hash_key", &"[REDACTED]")
            .field("lifetime", &self.lifetime)
            .field("configured_admins", &self.floor.len())
            .field("checkpoint_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

async fn load_channel_audiences(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<Vec<ChannelAudienceBinding>, SessionIssueError> {
    let rows = transaction
        .query(
            "SELECT id,allowed_groups FROM public.channels ORDER BY id FOR SHARE",
            &[],
        )
        .await
        .map_err(|_| SessionIssueError::DependencyUnavailable)?;
    rows.iter()
        .map(|row| {
            let id = ChannelId::new(get::<String>(row, "id")?);
            let raw: Vec<Option<String>> = get(row, "allowed_groups")?;
            let groups = raw
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(SessionIssueError::Corrupt)?;
            let audience =
                ChannelAudience::parse(groups).map_err(|_| SessionIssueError::Corrupt)?;
            Ok(ChannelAudienceBinding::new(id, audience))
        })
        .collect()
}

async fn append_session_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: Option<&ActorId>,
    target: Option<&ActorId>,
    event_type: &'static str,
    payload: AuditPayload,
    key: &[u8],
) -> Result<(), SessionIssueError> {
    let event_type = AuditEventType::parse(event_type).ok_or(SessionIssueError::Corrupt)?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(|_| SessionIssueError::DependencyUnavailable)?;
    let target_id = target
        .map(|id| AuditIdentifier::new(id.as_str()).map_err(|_| SessionIssueError::Corrupt))
        .transpose()?;
    let event = AuditEvent {
        id,
        actor: actor.cloned(),
        event_type,
        target_kind: AuditLabel::new("person"),
        target_id,
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, key)
        .await
        .map(|_| ())
        .map_err(|_| SessionIssueError::DependencyUnavailable)
}

fn generate_token() -> Result<SessionCookieValue, SessionIssueError> {
    let mut bytes = [0u8; SESSION_TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| SessionIssueError::RandomUnavailable)?;
    Ok(SessionCookieValue(SecretBytes::new(
        URL_SAFE_NO_PAD.encode(bytes).into_bytes(),
    )))
}

fn account_subject_key(identity: &FederatedIdentity, provider: &FederatedProvider) -> String {
    let Some(prefix) = provider.scoped_subject_prefix else {
        return identity.subject.clone();
    };
    let issuer = identity.issuer.as_bytes();
    let subject = identity.subject.as_bytes();
    let mut framed = Vec::with_capacity(16 + issuer.len() + subject.len());
    framed.extend_from_slice(&(issuer.len() as u64).to_be_bytes());
    framed.extend_from_slice(issuer);
    framed.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    framed.extend_from_slice(subject);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(Sha256::digest(framed)))
}

fn bounded_optional(value: Option<&str>, max_bytes: usize) -> Option<String> {
    value
        .filter(|value| {
            !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn generation_from_row(row: &Row) -> Result<AuthGeneration, SessionIssueError> {
    let raw: i64 = get(row, "auth_generation")?;
    u64::try_from(raw)
        .map(AuthGeneration::new)
        .map_err(|_| SessionIssueError::Corrupt)
}

fn get<'row, T>(row: &'row Row, column: &'static str) -> Result<T, SessionIssueError>
where
    T: tokio_postgres::types::FromSql<'row>,
{
    row.try_get(column).map_err(|_| SessionIssueError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_and_issuer_debug_never_print_the_token_or_keys() {
        let token = SessionCookieValue(SecretBytes::new(b"top-secret-session-token".to_vec()));
        assert_eq!(format!("{token:?}"), "SessionCookieValue([REDACTED])");
        assert!(!format!("{token:?}").contains(token.expose()));
    }

    #[test]
    fn hostile_peer_metadata_is_dropped_not_truncated_into_a_different_value() {
        assert_eq!(
            bounded_optional(Some("127.0.0.1"), MAX_IP_BYTES).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(bounded_optional(Some("line\nbreak"), MAX_IP_BYTES), None);
        assert_eq!(
            bounded_optional(Some(&"x".repeat(MAX_IP_BYTES + 1)), MAX_IP_BYTES),
            None
        );
    }
}
