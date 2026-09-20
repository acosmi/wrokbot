//! computer policy/snapshot repositories。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `action_policy` repository。
    ActionPolicyRepo,
    table = action_policy,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

define_table_repo!(
    /// `computer_snapshot` repository。
    SnapshotRepo,
    table = computer_snapshot,
    order_by = "\"computer_id\"",
    find = find_by_computer_id(computer_id: &str) where "\"computer_id\" = $1"
);
