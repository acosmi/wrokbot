//! Thread ID 的唯一生产 issuer；CSPRNG 在 infra，布局在 WASM-safe contracts。

use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{DeploymentId, ThreadId};

/// OS CSPRNG 不可用；不携带平台错误文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("thread_id_random_unavailable")]
pub struct ThreadIdMintError;

/// 以 OS CSPRNG 填满 UUID entropy，再由唯一 contracts 布局器铸造 UUIDv8。
///
/// # Errors
///
/// OS 随机源不可用时 fail-closed，不退化到时间戳/计数器。
pub fn mint_thread_id(deployment: &DeploymentId) -> Result<ThreadId, ThreadIdMintError> {
    let mut entropy = [0_u8; 16];
    getrandom::fill(&mut entropy).map_err(|_| ThreadIdMintError)?;
    Ok(ThreadIdentity::new(deployment).mint_from_entropy(entropy))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn production_issuer_is_fresh_and_every_id_is_owned_by_the_deployment() {
        let deployment = DeploymentId::new("deployment-production");
        let identity = ThreadIdentity::new(&deployment);
        let minted: BTreeSet<_> = (0..1_000)
            .map(|_| mint_thread_id(&deployment).unwrap())
            .inspect(|thread| assert!(identity.owns(thread)))
            .map(ThreadId::into_inner)
            .collect();
        assert_eq!(minted.len(), 1_000);
    }
}
