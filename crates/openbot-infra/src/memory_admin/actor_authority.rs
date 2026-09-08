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
    let generation =
        i64::try_from(auth_generation.get()).map_err(|_| MemoryAdministrationError::NotVisible)?;
    let current = transaction
        .query_opt(
            "SELECT u.id FROM public.users u
              WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                WHERE ra.email=lower(u.email))
              FOR SHARE OF u",
            &[&actor.as_str(), &generation],
        )
        .await
        .map_err(|error| super::unavailable("验证 memory actor 失败", error))?;
    current
        .map(|_| ())
        .ok_or(MemoryAdministrationError::NotVisible)
}
