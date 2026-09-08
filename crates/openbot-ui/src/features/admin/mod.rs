//! Administrator-only product surfaces.

pub mod audit;
pub mod boundaries;
pub mod credentials;
pub mod home;
pub mod identity_providers;
pub mod people;
pub mod playground;
pub mod plugins;
pub mod shell;

pub use audit::AdminAuditPage;
pub use boundaries::AdminBoundariesPage;
pub use credentials::AdminCredentialsPage;
pub use home::AdminHomePage;
pub use identity_providers::AdminIdentityProvidersPage;
pub use people::AdminPeoplePage;
pub use playground::SandboxPlaygroundPage;
pub use plugins::AdminPluginsPage;
pub use shell::AdminShell;
