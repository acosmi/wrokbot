//! Intelligence 一次性导入 cursor repository（v3 §20.3）。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `intelligence_import_cursors` repository；不进入最终运行请求路径。
    ImportCursorRepo,
    table = intelligence_import_cursors,
    order_by = "\"bundle_id\", \"aggregate_kind\"",
    find = find_by_key(bundle_id: &str, aggregate_kind: &str) where "\"bundle_id\" = $1 AND \"aggregate_kind\" = $2"
);
