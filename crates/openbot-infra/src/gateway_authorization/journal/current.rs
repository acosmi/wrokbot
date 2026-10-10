//! Original current Host borrow and actual actor/session observations.

use super::{
    Error, GatewayAuthorizationJournal, Kind, OperationGate, host_error, observation_error,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::request_binding::{
    GatewayAuthorizationHostObservation, GatewayAuthorizationHostTailWitness,
    GatewayAuthorizationSessionFacts, HostRequestBindingKind,
};
use openbot_domain::identity::roles::resolve_effective_role;
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction, types::FromSql};

pub(super) async fn borrow_current<'a>(
    journal: &'a GatewayAuthorizationJournal,
    auth: &'a AuthContext,
    gate: &'a OperationGate<'_>,
) -> Result<GatewayAuthorizationHostObservation<'a>, Error> {
    gate.check()?;
    journal.check_scope(auth)?;
    if !std::ptr::eq(journal, gate.journal) || gate.auth != auth {
        return Err(Error::new(Kind::Refused));
    }
    let issuer = journal
        .issuer
        .get()
        .ok_or_else(|| Error::new(Kind::Unavailable))?;
    let binding = auth
        .request_binding()
        .ok_or_else(|| Error::new(Kind::Refused))?;
    if !issuer.observation().is_current() || !issuer.owns_identity(binding.identity()) {
        return Err(Error::new(Kind::Refused));
    }
    let observation = binding
        .borrow_gateway_authorization_host_before(auth, gate, gate.deadline().into_std())
        .map_err(host_error)?;
    check_attachment(journal, auth, &observation, gate)?;
    Ok(observation)
}

fn check_attachment(
    journal: &GatewayAuthorizationJournal,
    auth: &AuthContext,
    observation: &GatewayAuthorizationHostObservation<'_>,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    gate.check()?;
    let issuer = journal
        .issuer
        .get()
        .ok_or_else(|| Error::new(Kind::Unavailable))?;
    let binding = auth
        .request_binding()
        .ok_or_else(|| Error::new(Kind::Refused))?;
    if !issuer.observation().is_current()
        || !issuer.owns_identity(observation.identity())
        || !binding.identity().same_binding(observation.identity())
        || binding.kind() != observation.kind()
        || !matches!(
            observation.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::ServerSingleUserOwner
        )
    {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}

const ACTOR_SELECT: &str = r"SELECT
  CASE WHEN octet_length(u.id) BETWEEN 1 AND 512 THEN u.id END AS current_actor,
  u.auth_generation AS current_generation,
  CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS current_email,
  EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied,
  ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles,
  CASE WHEN octet_length(s.id) BETWEEN 1 AND 512 THEN s.id END AS session_id,
  CASE WHEN octet_length(s.user_id) BETWEEN 1 AND 512 THEN s.user_id END AS session_user,
  CASE WHEN octet_length(s.token) BETWEEN 1 AND 512 THEN s.token END AS session_token,
  s.created_at AS session_created,s.updated_at AS session_updated,
  s.expires_at AS session_expires,s.auth_generation AS session_generation
  FROM public.users u LEFT JOIN public.sessions s ON s.id=$2::text AND s.user_id=u.id
  WHERE u.id=$1::text";
const ACTOR_SHARE: &str = r"SELECT
  CASE WHEN octet_length(u.id) BETWEEN 1 AND 512 THEN u.id END AS current_actor,
  u.auth_generation AS current_generation,
  CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS current_email,
  EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied,
  ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles,
  CASE WHEN octet_length(s.id) BETWEEN 1 AND 512 THEN s.id END AS session_id,
  CASE WHEN octet_length(s.user_id) BETWEEN 1 AND 512 THEN s.user_id END AS session_user,
  CASE WHEN octet_length(s.token) BETWEEN 1 AND 512 THEN s.token END AS session_token,
  s.created_at AS session_created,s.updated_at AS session_updated,
  s.expires_at AS session_expires,s.auth_generation AS session_generation
  FROM public.users u LEFT JOIN public.sessions s ON s.id=$2::text AND s.user_id=u.id
  WHERE u.id=$1::text FOR SHARE OF u";

pub(super) async fn lock_actor(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    observation: &GatewayAuthorizationHostObservation<'_>,
    gate: &OperationGate<'_>,
) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, Error> {
    actor_on(tx, auth, observation, gate, ACTOR_SHARE).await
}
pub(super) async fn observe_actor(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    observation: &GatewayAuthorizationHostObservation<'_>,
    gate: &OperationGate<'_>,
) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, Error> {
    actor_on(tx, auth, observation, gate, ACTOR_SELECT).await
}
async fn actor_on(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    observation: &GatewayAuthorizationHostObservation<'_>,
    gate: &OperationGate<'_>,
    sql: &'static str,
) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, Error> {
    check_attachment(gate.journal, auth, observation, gate)?;
    let epoch = observation.server_session_epoch();
    let lookup = epoch.as_ref().map(|value| value.lookup_id());
    let row = gate
        .io(
            tx.query_opt(sql, &[&auth.actor().as_str(), &lookup]),
            observation_error,
        )
        .await?
        .ok_or_else(|| Error::new(Kind::Refused))?;
    let session = decode_actor(&row, auth, observation, gate)?;
    let tail = observation
        .witness(auth, session, gate.deadline().into_std())
        .map_err(host_error)?;
    verify_tail(tail.as_ref(), auth, gate)?;
    Ok(tail)
}

fn column<T: for<'a> FromSql<'a>>(row: &Row, name: &str) -> Result<T, Error> {
    row.try_get(name).map_err(observation_error)
}
fn decode_actor(
    row: &Row,
    auth: &AuthContext,
    observation: &GatewayAuthorizationHostObservation<'_>,
    gate: &OperationGate<'_>,
) -> Result<Option<GatewayAuthorizationSessionFacts>, Error> {
    check_attachment(gate.journal, auth, observation, gate)?;
    let actor: Option<String> = column(row, "current_actor")?;
    let raw_generation: i64 = column(row, "current_generation")?;
    let generation = u64::try_from(raw_generation).map_err(|_| Error::new(Kind::Refused))?;
    if actor.as_deref() != Some(auth.actor().as_str())
        || generation != auth.auth_generation().get()
        || column::<bool>(row, "denied")?
    {
        return Err(Error::new(Kind::Refused));
    }
    let roles: Vec<String> = column(row, "current_roles")?;
    let parsed = roles
        .iter()
        .map(|v| v.parse::<Role>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::new(Kind::Refused))?;
    match observation.kind() {
        HostRequestBindingKind::ServerSession => {
            if auth.is_single_user() {
                return Err(Error::new(Kind::Refused));
            }
            let epoch = observation
                .server_session_epoch()
                .ok_or_else(|| Error::new(Kind::Refused))?;
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
                return Err(Error::new(Kind::Refused));
            };
            if issued != raw_generation
                || !epoch.matches_raw_row(&id, &user, &token, created, issued)
            {
                return Err(Error::new(Kind::Refused));
            }
            let role = resolve_effective_role(parsed).map_err(|_| Error::new(Kind::Refused))?;
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                false,
            )
            .with_role(role)
            .build();
            if current != *auth {
                return Err(Error::new(Kind::Refused));
            }
            let sample = gate.check()?;
            // SQL persistence uses microseconds, while this observation retains the
            // exact original clock sample for the original Host lifetime witness.
            let nanos = i128::from(sample.wall.timestamp())
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(i128::from(sample.wall.timestamp_subsec_nanos())))
                .ok_or_else(|| Error::new(Kind::Deadline))?;
            let observed_wall = OffsetDateTime::from_unix_timestamp_nanos(nanos)
                .map_err(|_| Error::new(Kind::Deadline))?;
            Ok(Some(GatewayAuthorizationSessionFacts {
                created_at: created,
                updated_at: updated,
                expires_at: expires,
                observed_wall,
                observed_monotonic: sample.mono.into_std(),
            }))
        }
        HostRequestBindingKind::ServerSingleUserOwner => {
            if !auth.is_single_user()
                || observation.server_session_epoch().is_some()
                || roles.as_slice() != ["admin"]
                || auth.actor().as_str() != crate::auth::single_user::SINGLE_USER_ACTOR_ID
                || column::<Option<String>>(row, "current_email")?.as_deref()
                    != Some(crate::auth::single_user::SINGLE_USER_EMAIL)
            {
                return Err(Error::new(Kind::Refused));
            }
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                true,
            )
            .with_roles([Role::Admin, Role::User])
            .build();
            if current != *auth {
                return Err(Error::new(Kind::Refused));
            }
            Ok(None)
        }
        HostRequestBindingKind::DesktopWindow => Err(Error::new(Kind::Refused)),
    }
}
pub(super) fn verify_tail(
    witness: &dyn GatewayAuthorizationHostTailWitness,
    auth: &AuthContext,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    gate.check()?;
    witness
        .verify_current(auth, gate.deadline().into_std())
        .map_err(host_error)?;
    gate.check()?;
    Ok(())
}
