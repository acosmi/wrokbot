//! Shared current-actor fence for Memory transactions. People authorization changes update the
//! same user row/generation; holding SHARE until transaction end orders reads/writes before them.

use openbot_application::MemoryAdministrationError;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::ActorId;
use tokio_postgres::Transaction;

pub(super) async fn lock_actor(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    auth_generation: AuthGeneration,
) -> Result<(), MemoryAdministrationError> {
    lock_actor_with_mode(transaction, actor, auth_generation, false).await
}

/// Order a write-control revocation after already admitted GUI writes and before later writes.
pub(super) async fn lock_actor_for_control(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    auth_generation: AuthGeneration,
) -> Result<(), MemoryAdministrationError> {
    lock_actor_with_mode(transaction, actor, auth_generation, true).await
}

async fn lock_actor_with_mode(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    auth_generation: AuthGeneration,
    exclusive: bool,
) -> Result<(), MemoryAdministrationError> {
    let generation =
        i64::try_from(auth_generation.get()).map_err(|_| MemoryAdministrationError::NotVisible)?;
    let current = transaction
        .query_opt(
            &format!(
                "SELECT u.id FROM public.users u
              WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                WHERE ra.email=lower(u.email))
              {} OF u",
                if exclusive { "FOR UPDATE" } else { "FOR SHARE" }
            ),
            &[&actor.as_str(), &generation],
        )
        .await
        .map_err(|error| super::unavailable("验证 memory actor 失败", error))?;
    current
        .map(|_| ())
        .ok_or(MemoryAdministrationError::NotVisible)
}
