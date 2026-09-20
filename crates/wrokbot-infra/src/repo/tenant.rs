//! tenant package repository。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `deployment_packages` repository。
    DeploymentPackageRepo,
    table = deployment_packages,
    order_by = "\"id\"",
    find = find_by_id(id: &uuid::Uuid) where "\"id\" = $1"
);
