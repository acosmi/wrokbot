//! Tenant Package 文件加载与 PostgreSQL 同步适配器。

mod loader;
mod postgres;

pub use loader::{MAX_TENANT_PACKAGE_FILE_BYTES, TenantPackageLoadError, load_tenant_package};
pub use postgres::PostgresTenantPackageSynchronizer;
