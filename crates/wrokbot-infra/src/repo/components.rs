//! compiled/sandboxed component 表的类型化 PostgreSQL repositories。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `components` repository。
    ComponentRepo,
    table = components,
    order_by = "\"name\"",
    find = find_by_name(name: &str) where "\"name\" = $1"
);

define_table_repo!(
    /// `component_exclusions` repository。
    ComponentExclusionRepo,
    table = component_exclusions,
    order_by = "\"component_name\", \"agent_id\"",
    find = find_by_key(component_name: &str, agent_id: &str) where "\"component_name\" = $1 AND \"agent_id\" = $2"
);

define_table_repo!(
    /// `component_functions` repository。
    ComponentFunctionRepo,
    table = component_functions,
    order_by = "\"component_name\", \"function_name\"",
    find = find_by_key(component_name: &str, function_name: &str) where "\"component_name\" = $1 AND \"function_name\" = $2"
);

define_table_repo!(
    /// `sandboxed_components` repository。
    SandboxedComponentRepo,
    table = sandboxed_components,
    order_by = "\"name\"",
    find = find_by_name(name: &str) where "\"name\" = $1"
);
