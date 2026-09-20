//! use case —— 每个文件一个用例，一个用例一条编排。
//!
//! G1 从下面两个起步；W-3a people 与 W-3b tool 编排分别在 `people` / [`crate::tool`]：
//!
//! | 用例 | 标注 | parity 出处 |
//! | --- | --- | --- |
//! | [`list_visible_channels`] | parity | `server/src/routes/channels/routes.ts::list`（ledger `api-channels-list-get`） |
//! | [`health`] | 新增 | 上游无对应路由；它是 typed 边界的最小活性证据 |
//! | [`mint_thread_id`] / [`get_thread_status`] | parity + §4.1 替代 | 固定上游 `thread-routes.test.ts`，R64 |
//! | [`begin_thread_run`] / [`subscribe_thread_events`] | 新增 native control plane | §4.3，R65 |
//! | [`remember_memory`] / [`list_memories`] / [`correct_memory`] / [`mutate_memory`] / [`recall_memories`] | 新增 explicit memory backend | §4.3，R66 |
//!
//! 用例是**函数**不是结构体：它们没有需要跨调用保存的状态，依赖由参数传入（port 的
//! 引用 + `AuthContext`）。做成 struct 只会让「这次调用用了哪些依赖」从签名里消失。

pub mod agents;
pub mod audit;
pub mod channels_create;
pub mod health;
pub mod list_visible_channels;
pub mod memory;
pub mod people;
pub mod policy;
pub mod routing;
pub mod thread;

pub use agents::{
    create_agent, delete_agent, duplicate_agent, get_visible_agent, list_visible_agents,
    set_agent_hidden, test_agent_connection, update_agent,
};
pub use audit::{DEFAULT_AUDIT_PAGE, MAX_AUDIT_PAGE, list_audit_events};
pub use channels_create::create_channel;
pub use health::{DEFAULT_HEARTBEAT_PERIOD, health, health_stream};
pub use list_visible_channels::{DEFAULT_CHANNEL_PAGE, get_visible_channel, list_visible_channels};
pub use memory::{
    DEFAULT_MEMORY_PAGE, MAX_MEMORY_CONTENT_BYTES, MAX_MEMORY_QUERY_BYTES, MAX_MEMORY_TAG_BYTES,
    MAX_MEMORY_TAGS, correct_memory, get_memory_control, list_memories, mutate_memory,
    recall_memories, remember_memory, update_memory_control,
};
pub use people::{
    DEFAULT_PEOPLE_PAGE, MAX_PEOPLE_PAGE, admin_status, change_person_access, change_person_role,
    current_user, list_people,
};
pub use policy::{get_action_policy, set_action_policy};
pub use routing::{MAX_ROUTING_CANDIDATES, route_channel_message};
pub use thread::{
    begin_thread_run, cancel_thread_run, get_thread_conversation, get_thread_history,
    get_thread_status, mint_thread_id, subscribe_channel_activity, subscribe_thread_events,
};
