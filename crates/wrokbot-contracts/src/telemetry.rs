//! 关联字段与脱敏（v3 §16.4）。
//!
//! §16.4 逐字给出统一关联字段清单：
//!
//! ```text
//! deployment_id / tenant_id / request_id / actor_id / bot_id
//! channel_id / thread_id / run_id / tool_call_id
//! computer_id / generation / policy_decision_id
//! mcp_server_id / transport / release_sha
//! ```
//!
//! 并规定：「高基数 actor/thread 不进入 metrics label，只进入受控 trace/log。」
//!
//! 本模块提供三样东西：[`CorrelationFields`]（字段载体）、[`METRICS_LABEL_ALLOWLIST`]
//! （metrics label 白名单）与 [`Redacted`]（脱敏包装）。

use core::fmt;

use serde::Serialize;

use crate::ids::{
    ActorId, BotId, ChannelId, ComputerGeneration, ComputerId, DeploymentId, PolicyDecisionId,
    RunId, TenantId, ThreadId, ToolCallId,
};

/// 传输面。
///
/// 封闭 enum 而不是 `String`：`transport` 是**允许进 metrics label** 的字段
/// （见 [`METRICS_LABEL_ALLOWLIST`]），而 metrics label 的基数必须有界。自由字符串
/// 标签是 Prometheus 上最经典的一类事故 —— 一次带 request id 的 label 就能把时间序列
/// 数量炸到内存耗尽。封闭 enum 让「基数有界」成为构造性事实。
///
/// 新增传输面必须同 PR 扩这个 enum，那正是我们想要的复核点。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Axum HTTP 请求（§5.2）。
    Http,
    /// HTTP Server-Sent Events 流。
    Sse,
    /// WebSocket（含 screencast viewer，§12.4）。
    #[serde(rename = "websocket")]
    WebSocket,
    /// Unix domain socket（engine 控制面，§11.2）。
    Uds,
    /// Windows 命名管道（engine 控制面在 Windows 上的对偶，§11.2）。
    NamedPipe,
    /// Tauri typed in-process 调用（§0.2 Desktop 直连）。
    InProcess,
}

impl Transport {
    /// 稳定的 label 取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sse => "sse",
            Self::WebSocket => "websocket",
            Self::Uds => "uds",
            Self::NamedPipe => "named_pipe",
            Self::InProcess => "in_process",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// §16.4 的统一关联字段。
///
/// 全部 `Option`：一次 HTTP 探活没有 `thread_id`，一次后台 run 没有 `request_id`，
/// 强制填充只会得到一堆假值。序列化时省略 `None`，日志里不出现空键。
///
/// # 为什么只 `Serialize` 不 `Deserialize`
///
/// 它是**出方向**的投影：Rust 把已知的身份写进 trace/log。反方向（从外部字节读回一组
/// 关联字段）没有合法用例，而一旦开了口，它就会变成 [`crate::auth::AuthContext`] 的
/// 影子入口 —— 调用方把 `actor_id` 塞进关联字段，下游某处再拿它当身份用。
///
/// # `request_id` / `mcp_server_id` / `release_sha` 为什么是 `String`
///
/// §5.3 把**核心 ID** 的集合固定为十五个，这三项不在其中。在这里铸造第 16、17 个
/// 核心 ID newtype 等于擅自扩张一份被方案定死的清单（repository contract §4「parity 与新增必须
/// 分开标注」）。它们此刻只是关联字段的载体，等到有 ledger 条目要求它们成为一等 ID 时
/// 再升格。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CorrelationFields {
    /// 部署。低基数，可进 metrics label。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<DeploymentId>,
    /// 租户。低基数，可进 metrics label。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    /// 单次请求。**每次请求都不同 = 无界基数**，只进 trace/log。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 行动者。§16.4 点名的高基数字段，只进 trace/log。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
    /// bot。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_id: Option<BotId>,
    /// channel。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<ChannelId>,
    /// 线程。§16.4 点名的高基数字段，只进 trace/log。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<ThreadId>,
    /// run。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// 工具调用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<ToolCallId>,
    /// computer。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_id: Option<ComputerId>,
    /// computer 代际。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<ComputerGeneration>,
    /// policy 裁决。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision_id: Option<PolicyDecisionId>,
    /// MCP server。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server_id: Option<String>,
    /// 传输面。低基数，可进 metrics label。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    /// 发行物 commit。低基数（一个进程生命周期内恒定），可进 metrics label。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_sha: Option<String>,
}

/// 允许作为 metrics label 的关联字段名 —— **白名单，default-deny**。
///
/// §16.4 只逐字点名了 `actor` / `thread` 两个高基数字段不得进 label，但用黑名单表达这条
/// 规则是错的：黑名单在「新增了一个同样高基数的字段而没人想起来加进去」时静默失效。
/// 白名单的失效方向相反 —— 新字段默认进不了 label，要进必须有人显式论证它的基数上界。
///
/// 当前四项的基数论证：
///
/// - `deployment_id`：一次部署一个值。
/// - `tenant_id`：租户数量由计费与 provisioning 有界约束，且它是 scope 判定的最外层，
///   缺了它 metrics 无法按租户切分。
/// - `transport`：[`Transport`] 是封闭 enum，基数 = 变体数。
/// - `release_sha`：一个进程生命周期内恒定，滚动升级期间最多并存两三个值。
///
/// 被排除的全部其余字段里，`request_id` / `run_id` / `tool_call_id` / `thread_id` /
/// `actor_id` 是显式无界的；`bot_id` / `channel_id` / `computer_id` / `generation` /
/// `policy_decision_id` / `mcp_server_id` 虽然「看起来有界」，但它们的上界由用户行为
/// 决定而不是由部署决定 —— 「看起来有界」不是基数论证。
pub const METRICS_LABEL_ALLOWLIST: &[&str] =
    &["deployment_id", "tenant_id", "transport", "release_sha"];

/// 判断某个关联字段名是否可以作为 metrics label。
///
/// 调用点应当用它而不是自己 `contains` —— 单点收口才能在将来把白名单换成更严格的
/// 结构（例如编译期集合）时不遗漏调用方。
#[must_use]
pub fn is_allowed_metrics_label(field: &str) -> bool {
    METRICS_LABEL_ALLOWLIST.contains(&field)
}

/// [`Redacted`] 在 `Debug` / `Display` 下输出的固定占位。
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// 脱敏包装。
///
/// §17.2 条 8：「secret 不进模型、GUI state、browser event、普通日志、trace、screen URL。」
/// 大多数泄漏不是有人存心 `println!` 了一个密钥，而是某个包含密钥字段的结构体被
/// `#[derive(Debug)]` 之后随手 `tracing::debug!(?config)` 出去了。
///
/// 本类型把「不能打印」变成类型属性：`Debug` 与 `Display` 都只输出
/// [`REDACTED_PLACEHOLDER`]，取值必须显式调用 [`Redacted::expose`] —— 那一行在 review 和
/// grep 里都是可见的。
///
/// 刻意**不**实现的三样：
///
/// - `Serialize` / `Deserialize`：能序列化就能顺着任何 DTO 流出去，等于没包。
/// - `PartialEq`：用它比较密钥会得到一个非常数时间的比较；常数时间比较不属于本 crate
///   的职责，所以这里不提供一个看起来能用的错误工具。
/// - `Deref`：自动解引用会让 `format!("{}", secret)` 在某些语境下悄悄绕过包装。
#[derive(Clone)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// 包装一个敏感值。
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// **显式**取出敏感值的引用。
    ///
    /// 名字是 `expose` 不是 `get`：调用点读起来就是一句「我在此处暴露一个密钥」。
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;

    /// 把每个字段都填满，用来机械地取出 [`CorrelationFields`] 的真实字段名集合。
    fn fully_populated() -> CorrelationFields {
        CorrelationFields {
            deployment_id: Some(DeploymentId::new("dep-1")),
            tenant_id: Some(TenantId::new("tenant-1")),
            request_id: Some("req-1".to_owned()),
            actor_id: Some(ActorId::new("actor-1")),
            bot_id: Some(BotId::new("bot-1")),
            channel_id: Some(ChannelId::new("channel-1")),
            thread_id: Some(ThreadId::new("thread-1")),
            run_id: Some(RunId::new("run-1")),
            tool_call_id: Some(ToolCallId::new("tc-1")),
            computer_id: Some(ComputerId::new("computer-1")),
            generation: Some(ComputerGeneration::new(3)),
            policy_decision_id: Some(PolicyDecisionId::new("pd-1")),
            mcp_server_id: Some("mcp-1".to_owned()),
            transport: Some(Transport::Http),
            release_sha: Some("891df72".to_owned()),
        }
    }

    fn field_names() -> BTreeSet<String> {
        let value = serde_json::to_value(fully_populated()).unwrap();
        match value {
            Value::Object(map) => map.keys().cloned().collect(),
            other => panic!("CorrelationFields 必须序列化成对象，实际是 {other:?}"),
        }
    }

    /// §16.4 逐字点名的十五个关联字段一个不少、一个不多。
    #[test]
    fn correlation_fields_match_plan_section_16_4_exactly() {
        let expected: BTreeSet<String> = [
            "deployment_id",
            "tenant_id",
            "request_id",
            "actor_id",
            "bot_id",
            "channel_id",
            "thread_id",
            "run_id",
            "tool_call_id",
            "computer_id",
            "generation",
            "policy_decision_id",
            "mcp_server_id",
            "transport",
            "release_sha",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(field_names(), expected);
        assert_eq!(expected.len(), 15);
    }

    /// **负向**：§16.4 点名的两个高基数字段不在 metrics label 白名单里。
    #[test]
    fn high_cardinality_fields_are_not_metrics_labels() {
        assert!(
            !is_allowed_metrics_label("actor_id"),
            "§16.4：高基数 actor 不进 metrics label"
        );
        assert!(
            !is_allowed_metrics_label("thread_id"),
            "§16.4：高基数 thread 不进 metrics label"
        );
        // 同族的无界字段一并排除。
        assert!(!is_allowed_metrics_label("request_id"));
        assert!(!is_allowed_metrics_label("run_id"));
        assert!(!is_allowed_metrics_label("tool_call_id"));
    }

    /// **正向对照**：白名单不是空数组 —— 确实允许的字段在里面。
    ///
    /// 没有这一条，上面那条测试在「`METRICS_LABEL_ALLOWLIST` 是 `&[]`」的世界里同样通过，
    /// 什么都证明不了。
    #[test]
    fn allowlist_actually_permits_the_low_cardinality_fields() {
        assert!(is_allowed_metrics_label("transport"));
        assert!(is_allowed_metrics_label("deployment_id"));
        assert!(is_allowed_metrics_label("tenant_id"));
        assert!(is_allowed_metrics_label("release_sha"));
        assert_eq!(METRICS_LABEL_ALLOWLIST.len(), 4);
    }

    /// 白名单里的每个名字都必须是 [`CorrelationFields`] 的真实字段。
    ///
    /// 否则白名单可以在字段改名后继续「允许」一个已经不存在的字段，而所有断言照绿。
    #[test]
    fn every_allowlisted_name_is_a_real_correlation_field() {
        let names = field_names();
        for label in METRICS_LABEL_ALLOWLIST {
            assert!(
                names.contains(*label),
                "白名单项 {label} 不是 CorrelationFields 的字段"
            );
        }
    }

    #[test]
    fn correlation_fields_omit_none_and_never_emit_empty_keys() {
        let json = serde_json::to_string(&CorrelationFields::default()).unwrap();
        assert_eq!(json, "{}");

        let partial = CorrelationFields {
            transport: Some(Transport::WebSocket),
            ..CorrelationFields::default()
        };
        assert_eq!(
            serde_json::to_string(&partial).unwrap(),
            r#"{"transport":"websocket"}"#
        );
    }

    /// 脱敏：`Debug` 不得泄漏内容。
    #[test]
    fn redacted_debug_does_not_leak_the_value() {
        let secret = Redacted::new("hunter2");
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert_eq!(format!("{secret:?}"), REDACTED_PLACEHOLDER);
        assert!(!format!("{secret}").contains("hunter2"));
        assert_eq!(format!("{secret}"), REDACTED_PLACEHOLDER);

        // 包在结构体里、被 derive(Debug) 一起打印时同样不泄漏 —— 那才是真实的泄漏形态：
        // 没人会存心打印密钥，泄漏都发生在 `tracing::debug!(?config)` 这一行上。
        //
        // 两个字段只经 derive(Debug) 读取，而 dead-code 分析刻意忽略 derive 出来的 Debug，
        // 于是这里必然报 dead_code。这正是本测试要复现的形态，不能靠"给字段加个读取"绕开。
        #[expect(dead_code)]
        #[derive(Debug)]
        struct Config {
            url: &'static str,
            key: Redacted<&'static str>,
        }
        let rendered = format!(
            "{:?}",
            Config {
                url: "https://example.invalid",
                key: Redacted::new("hunter2"),
            }
        );
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert!(rendered.contains("https://example.invalid"), "{rendered}");
    }

    /// **正向对照**：同一个值不包装时**确实**会被打印出来。
    ///
    /// 没有这一条，上面那条测试在「`hunter2` 这个字符串根本无法出现在任何 Debug 输出里」
    /// 的世界里同样通过。
    #[test]
    fn unwrapped_value_really_does_leak() {
        assert!(format!("{:?}", "hunter2").contains("hunter2"));
    }

    #[test]
    fn expose_returns_the_original_value() {
        let secret = Redacted::new(String::from("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(Redacted::new(42_u32).expose(), &42);
    }

    #[test]
    fn transport_labels_are_stable() {
        assert_eq!(Transport::Http.as_str(), "http");
        assert_eq!(Transport::Sse.as_str(), "sse");
        assert_eq!(Transport::WebSocket.as_str(), "websocket");
        assert_eq!(Transport::Uds.as_str(), "uds");
        assert_eq!(Transport::NamedPipe.as_str(), "named_pipe");
        assert_eq!(Transport::InProcess.as_str(), "in_process");
        assert_eq!(Transport::NamedPipe.to_string(), "named_pipe");
        assert_eq!(
            serde_json::to_string(&Transport::InProcess).unwrap(),
            r#""in_process""#
        );
    }
}
