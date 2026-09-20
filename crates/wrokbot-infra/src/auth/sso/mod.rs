//! deployment-owned 动态 OIDC/SAML：配置、加密存储、路由与协议入口。

pub mod config;
mod ephemeral;
mod saml;
mod service;
mod store;
mod vault;

pub use config::{
    RegisterIdentityProviderInput, RegisteredIdentityProvider, SsoConfigError, SsoProtocol,
};
pub use saml::SamlStart;
pub use service::{DynamicSsoError, DynamicSsoService, DynamicSsoStart, SsoRouteReceipt};
