//! Explicit transport facts for integration fixtures; no production bypass or header-derived peer.

use std::net::{Ipv4Addr, SocketAddr};

use axum::extract::ConnectInfo;
use openbot_server::ServerState;
use openbot_server::config::transport::TrustedTransportPolicy;
use openbot_server::config::{EnvMap, ServerConfig};

pub(super) fn loopback_policy() -> TrustedTransportPolicy {
    ServerConfig::from_env_map(&EnvMap::new())
        .expect("empty fixture configuration")
        .transport_policy(true)
}

/// `oneshot` has no accepted socket. The fixture supplies that missing fact outside the real
/// router so the normal transport gate still executes before authentication and application code.
/// Real TCP fixtures instead use `into_make_service_with_connect_info` on their listener.
#[allow(dead_code)] // The real-socket fixture shares only loopback_policy.
pub(super) fn loopback_router(state: ServerState) -> axum::Router {
    openbot_server::router(state).layer(axum::Extension(ConnectInfo(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        40_000,
    )))))
}
