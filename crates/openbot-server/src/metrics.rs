//! metrics —— §16.4「Server 暴露 Prometheus metrics」在 transport 侧的落点。
//!
//! # 门面 + exporter 两层，零 phone-home 由构造保证
//!
//! 本模块的记录路径只调 `metrics` **门面**：`histogram!` / `gauge!` 在没有安装 recorder
//! 时是彻底的 no-op，不分配、不建连、不知道 exporter 是谁。exporter
//! （`metrics-exporter-prometheus`）只在 [`install_recorder`] 里出现一次，而它由宿主
//! **显式调用**——与 [`crate::telemetry::init`] 同一条纪律（库不替宿主装全局单例）。
//!
//! exporter 的 `default-features = false` 是仓根钉死的：默认 feature 会带进
//! `http-listener`（自己起一个监听端口）与 `push-gateway`（主动往外推）。两者分别撞
//! parity 条目 `metrics-get` 的「不另开监听端口」与 §16.4 的「零 phone-home」。
//! **本 crate 因此没有任何主动外发行为**：指标只在有人 `GET /metrics` 时被渲染出去。
//!
//! # label 基数：白名单 + 一份本地台账，两边都不在 = 判红
//!
//! §16.4 逐字：「高基数 actor/thread 不进入 metrics label，只进入受控 trace/log。」
//! `openbot_contracts::telemetry::METRICS_LABEL_ALLOWLIST` 是**关联字段**那一侧的白名单
//! （四项：`deployment_id` / `tenant_id` / `transport` / `release_sha`）。
//!
//! 但 HTTP 指标天然还有两个维度 —— `method` 与 `status` —— 它们根本不是 §16.4 那份
//! 十五项关联字段里的名字，白名单对它们无话可说。照抄
//! `openbot_application::service::TRACE_ONLY_SPAN_FIELDS` 的手法把这件事做成可判定的：
//!
//! [`HTTP_METRIC_LABELS`] 里的每一项，**要么**在 `METRICS_LABEL_ALLOWLIST` 里（关联字段，
//! 已有基数论证），**要么**在 [`TRANSPORT_INTRINSIC_LABELS`] 里（传输面固有维度，基数论证
//! 写在下面）。两边都不在 = 有人加了 label 却没做基数论证，`every_http_label_has_a_cardinality_verdict`
//! 当场判红。再加一条：[`TRANSPORT_INTRINSIC_LABELS`] 里的名字**不得**与十五个关联字段
//! 重名（`transport_intrinsic_labels_never_shadow_a_correlation_field`），否则就能用
//! "它是固有维度"这句话把一个被白名单拒掉的关联字段偷渡进来。
//!
//! # `method` 的基数是**被守住的**，不是天然有界的
//!
//! HTTP 方法在协议上是一个自由 token：`hyper` 会把 `FOOBAR1` / `FOOBAR2` 原样解析成
//! `Method` 的扩展变体。直接拿 `Method::as_str()` 当 label，对端就能用一串随机方法名
//! 把时间序列数量炸掉 —— 这正是 `Transport` 那条注释点名的经典事故。所以
//! [`method_label`] 返回 `&'static str`：命中已知方法给静态名，否则一律
//! [`METHOD_OTHER`]。**基数有界因此是类型上的事实，不是一句祈祷。**
//!
//! # `route` 只认 `MatchedPath`
//!
//! 绝不记原始 `uri().path()`。Axum `MatchedPath` 来自路由表静态 pattern；未匹配统一写
//! [`ROUTE_UNMATCHED`]。因此对端发明再多 path 也只有一个 unmatched series。
//!
//! # 没有 active connections
//!
//! §16.4 点名了它，但**本 crate 从不拥有监听 socket** —— `Router` 由宿主二进制交给
//! hyper/axum-server 去 accept。这里能诚实测到的是**在飞请求数**
//! （[`HTTP_REQUESTS_IN_FLIGHT`]），那是另一件事，所以它用了另一个名字。
//! 把在飞请求数改名叫 connections 就是造假，不做。

use core::time::Duration;

use http::{Method, StatusCode};
use metrics::{gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use openbot_contracts::telemetry::Transport;

pub use metrics_exporter_prometheus::BuildError;

/// 请求耗时直方图（秒）。
///
/// **它同时就是 status 计数器**：Prometheus 直方图自带 `_count` 系列，按 `status` label
/// 切开就是每个状态码的请求数。另立一个 `..._requests_total` 计数器只会得到同一份数据的
/// 第二个真源 —— 两个数对不上的时候没人说得清该信哪个。
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "openbot_http_request_duration_seconds";

/// 在飞请求数（不是连接数，见模块文档）。
pub const HTTP_REQUESTS_IN_FLIGHT: &str = "openbot_http_requests_in_flight";

/// 传输面 label 名（关联字段，在 `METRICS_LABEL_ALLOWLIST` 里）。
pub const LABEL_TRANSPORT: &str = "transport";

/// HTTP 方法 label 名（传输面固有维度）。
pub const LABEL_METHOD: &str = "method";

/// HTTP 状态码 label 名（传输面固有维度）。
pub const LABEL_STATUS: &str = "status";

/// Axum 匹配后的静态 route pattern label 名。
pub const LABEL_ROUTE: &str = "route";

/// 未匹配路由统一桶；从不使用对端控制的原始 path。
pub const ROUTE_UNMATCHED: &str = "unmatched";

/// 未知 HTTP 方法的兜底 label 取值。见模块文档〈`method` 的基数是被守住的〉。
pub const METHOD_OTHER: &str = "other";

/// 本模块**实际打上去**的 label 名全集 —— 台账。
///
/// `http_labels_are_exactly_the_declared_ledger` 拿真实渲染出来的 Prometheus 文本反解出
/// label 名，与它逐项比对：多打一个或少打一个都判红。
pub const HTTP_METRIC_LABELS: &[&str] = &[LABEL_TRANSPORT, LABEL_METHOD, LABEL_STATUS, LABEL_ROUTE];

/// 传输面**固有维度**——不是 §16.4 的关联字段，所以白名单对它们无话可说。
///
/// 逐项基数论证：
///
/// - `method`：由 [`method_label`] 收敛到 9 个已知方法 + [`METHOD_OTHER`]，共 **10** 个
///   取值，`&'static str` 保证不会有第 11 个。
/// - `status`：取值只能来自本进程自己产出的状态码 —— §15.3 的 `HTTP_STATUS_DOMAIN`
///   加上 transport 自己会产的 404 与 413。对端无法让我们发明新状态码。
/// - `route`：Axum 路由表静态 pattern + 唯一 `unmatched`，不是原始 URL path。
pub const TRANSPORT_INTRINSIC_LABELS: &[&str] = &[LABEL_METHOD, LABEL_STATUS, LABEL_ROUTE];

/// 已知 HTTP 方法的静态 label 取值。
///
/// 命中给静态名，未命中给 [`METHOD_OTHER`]。返回 `&'static str` 不是风格 —— 它是
/// 「基数有界」这件事的类型层证据（见模块文档）。
#[must_use]
pub fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => METHOD_OTHER,
    }
}

/// 在飞请求 +1，返回一个到期自动 -1 的守卫。
///
/// 用守卫而不是"进来加、出去减"两行：中间件里的 `next.run(...)` 可以 panic、可以被
/// 取消（客户端断开时整个 future 被 drop），两种情形下"出去减"那一行都不会执行，
/// 于是 gauge 只涨不落 —— 一个永远在爬的在飞数比没有这个指标更糟。`Drop` 是唯一
/// 在这两种情形下都跑的地方。
#[must_use]
pub fn track_in_flight() -> InFlightGuard {
    gauge!(HTTP_REQUESTS_IN_FLIGHT, LABEL_TRANSPORT => Transport::Http.as_str()).increment(1.0);
    InFlightGuard(())
}

/// [`track_in_flight`] 的守卫，`Drop` 时把在飞数减回去。
#[derive(Debug)]
pub struct InFlightGuard(());

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        gauge!(HTTP_REQUESTS_IN_FLIGHT, LABEL_TRANSPORT => Transport::Http.as_str()).decrement(1.0);
    }
}

/// 记一次请求的耗时与状态。
pub fn record_http_request(method: &Method, status: StatusCode, elapsed: Duration, route: &str) {
    histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        LABEL_TRANSPORT => Transport::Http.as_str(),
        LABEL_METHOD => method_label(method),
        LABEL_STATUS => status.as_u16().to_string(),
        LABEL_ROUTE => route.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

/// 渲染 Prometheus 文本的句柄。
///
/// 它是 `/metrics` 路由的唯一数据来源。`ServerBuilder` 不给句柄时那条路由 fail-closed
/// 回 503，而不是回一段空文本 —— 空文本与"这个副本真的一个指标都没有"不可区分。
#[derive(Clone)]
pub struct MetricsHandle(PrometheusHandle);

impl MetricsHandle {
    /// 包装一个已建好的 exporter 句柄。
    ///
    /// 给自己定制过 bucket 的宿主用；常规路径是 [`install_recorder`]。
    #[must_use]
    pub const fn new(handle: PrometheusHandle) -> Self {
        Self(handle)
    }

    /// 渲染当前快照（Prometheus 文本曝露格式）。
    #[must_use]
    pub fn render(&self) -> String {
        self.0.render()
    }
}

impl core::fmt::Debug for MetricsHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 不打印句柄内容：那是整份指标快照，进日志既无用又可能很大。
        f.write_str("MetricsHandle")
    }
}

/// 把 Prometheus recorder 装成进程全局，返回渲染句柄。
///
/// **只有宿主二进制该调它，而且只调一次**，理由与 [`crate::telemetry::init`] 逐字相同。
/// 本 crate 内部零调用点（由 `library_never_installs_a_global_recorder` 钉住）。
///
/// 它**不监听任何端口、不连接任何地址**：`PrometheusBuilder` 在
/// `default-features = false` 下只会 `build_recorder`，`/metrics` 由本仓自己的 Axum 路由
/// 渲染（parity 条目 `metrics-get`）。
///
/// # Errors
///
/// recorder 构建失败或全局 recorder 已被装过时返回 [`BuildError`]。已装过是**错误而不是
/// 静默覆盖**：谁在给这个进程记指标是宿主必须知道的事。
pub fn install_recorder() -> Result<MetricsHandle, BuildError> {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)?;
    Ok(MetricsHandle::new(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::telemetry::{
        CorrelationFields, METRICS_LABEL_ALLOWLIST, is_allowed_metrics_label,
    };
    use std::collections::BTreeSet;

    /// 十五个关联字段的真实名字集合（机械取出，不手抄）。
    fn correlation_field_names() -> BTreeSet<String> {
        let populated = CorrelationFields {
            deployment_id: Some(openbot_contracts::ids::DeploymentId::new("d")),
            tenant_id: Some(openbot_contracts::ids::TenantId::new("t")),
            request_id: Some("r".to_owned()),
            actor_id: Some(openbot_contracts::ids::ActorId::new("a")),
            bot_id: Some(openbot_contracts::ids::BotId::new("b")),
            channel_id: Some(openbot_contracts::ids::ChannelId::new("c")),
            thread_id: Some(openbot_contracts::ids::ThreadId::new("th")),
            run_id: Some(openbot_contracts::ids::RunId::new("run")),
            tool_call_id: Some(openbot_contracts::ids::ToolCallId::new("tc")),
            computer_id: Some(openbot_contracts::ids::ComputerId::new("cm")),
            generation: Some(openbot_contracts::ids::ComputerGeneration::new(1)),
            policy_decision_id: Some(openbot_contracts::ids::PolicyDecisionId::new("pd")),
            mcp_server_id: Some("mcp".to_owned()),
            transport: Some(Transport::Http),
            release_sha: Some("sha".to_owned()),
        };
        match serde_json::to_value(populated).expect("可序列化") {
            serde_json::Value::Object(map) => map.keys().cloned().collect(),
            other => panic!("CorrelationFields 必须序列化成对象，实际是 {other:?}"),
        }
    }

    /// **每个 label 都必须有基数裁决**：要么在白名单里，要么被显式登记为传输面固有维度。
    /// 两边都不在 = 有人加了 label 却没论证基数。
    #[test]
    fn every_http_label_has_a_cardinality_verdict() {
        for label in HTTP_METRIC_LABELS {
            let allowlisted = is_allowed_metrics_label(label);
            let intrinsic = TRANSPORT_INTRINSIC_LABELS.contains(label);
            assert!(
                allowlisted != intrinsic,
                "label {label} 必须恰好落在一边：白名单（关联字段，有基数论证）或传输面固有维度"
            );
        }
    }

    /// 正向对照：白名单**确实**允许我在用的那个关联字段，而且它非空。
    ///
    /// 没有这一条，上面那条在「`is_allowed_metrics_label` 恒 false」的世界里会把
    /// `transport` 也判成"固有维度"，于是白名单形同虚设却全绿。
    #[test]
    fn allowlist_actually_permits_the_transport_label() {
        assert!(is_allowed_metrics_label(LABEL_TRANSPORT));
        assert!(!METRICS_LABEL_ALLOWLIST.is_empty());
        assert!(METRICS_LABEL_ALLOWLIST.contains(&LABEL_TRANSPORT));
    }

    /// **负向**：§16.4 点名的高基数字段一个都没被我打上去。
    ///
    /// 正向对照在同一条里（`transport` 确实在我的 label 集合里），否则本断言在
    /// 「`HTTP_METRIC_LABELS` 是空数组」的世界里同样通过。
    #[test]
    fn high_cardinality_correlation_fields_are_never_labels() {
        for forbidden in [
            "actor_id",
            "thread_id",
            "request_id",
            "run_id",
            "tool_call_id",
        ] {
            assert!(
                !HTTP_METRIC_LABELS.contains(&forbidden),
                "{forbidden} 是 §16.4 点名的高基数字段，不得作为 metrics label"
            );
            assert!(!is_allowed_metrics_label(forbidden));
        }
        assert!(HTTP_METRIC_LABELS.contains(&LABEL_TRANSPORT));
    }

    /// 固有维度不得与十五个关联字段重名。
    ///
    /// 否则"它是传输面固有维度"这句话就成了把被白名单拒掉的关联字段偷渡进来的后门。
    #[test]
    fn transport_intrinsic_labels_never_shadow_a_correlation_field() {
        let correlation = correlation_field_names();
        for label in TRANSPORT_INTRINSIC_LABELS {
            assert!(
                !correlation.contains(*label),
                "{label} 与关联字段重名 —— 它的基数裁决必须走白名单，不能走固有维度这条路"
            );
        }
        // 正向对照：这个集合确实非空且确实装着关联字段（否则上面在空集合上恒真）。
        assert_eq!(correlation.len(), 15);
        assert!(correlation.contains(LABEL_TRANSPORT));
    }

    /// 未知方法收敛到 `other`，已知方法给自己的静态名。
    #[test]
    fn unknown_methods_collapse_to_a_single_bucket() {
        // 负向：对端可以发明任意方法 token，但它们只能落进一个桶。
        let hostile: Vec<Method> = (0..50)
            .map(|i| Method::from_bytes(format!("FOOBAR{i}").as_bytes()).expect("合法 token"))
            .collect();
        let buckets: BTreeSet<&'static str> = hostile.iter().map(method_label).collect();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets.into_iter().next(), Some(METHOD_OTHER));

        // 正向对照：已知方法**没有**被折叠掉，否则上一条在"所有方法都是 other"的
        // 世界里同样通过，而那样的 label 一点用都没有。
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::POST), "POST");
        assert_ne!(method_label(&Method::GET), method_label(&Method::POST));
        assert_ne!(method_label(&Method::GET), METHOD_OTHER);
    }

    /// 已知方法的取值集合是 10 个（9 个标准方法 + `other`），基数论证的机械形式。
    #[test]
    fn method_label_domain_is_ten_values() {
        let standard = [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::CONNECT,
        ];
        let mut domain: BTreeSet<&'static str> = standard.iter().map(method_label).collect();
        assert_eq!(domain.len(), 9, "九个标准方法必须各占一个桶");
        domain.insert(METHOD_OTHER);
        assert_eq!(domain.len(), 10);
    }

    /// 在飞守卫真的会把 gauge 减回去 —— 包括 panic 路径。
    ///
    /// 判据是**渲染出来的文本**，不是"我调用了 decrement"：后者在守卫压根没实现 `Drop`
    /// 的世界里也能写出来。
    #[test]
    fn in_flight_guard_decrements_even_on_panic() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let outcome = std::panic::catch_unwind(|| {
                let _guard = track_in_flight();
                panic!("handler 炸了");
            });
            assert!(outcome.is_err());
        });
        let rendered = handle.render();
        assert!(
            rendered.contains(HTTP_REQUESTS_IN_FLIGHT),
            "gauge 没出现在快照里：{rendered}"
        );
        // 正向对照 + 负向断言合一：出现了这个指标，而且值回到了 0。
        assert!(
            rendered.contains(&format!(
                "{HTTP_REQUESTS_IN_FLIGHT}{{transport=\"http\"}} 0"
            )),
            "在飞数没有减回 0：{rendered}"
        );
    }

    /// 没装 recorder 时，记录路径是彻底的 no-op（零 phone-home 的构造证据）。
    ///
    /// 它跑在没有 local recorder 的作用域里：不 panic、不阻塞、什么都不发生。
    #[test]
    fn recording_without_a_recorder_is_a_noop() {
        let guard = track_in_flight();
        record_http_request(
            &Method::GET,
            StatusCode::OK,
            Duration::from_millis(1),
            "/health",
        );
        drop(guard);
    }

    /// 本 crate 不在任何地方自动装全局 recorder —— 与
    /// `telemetry::library_never_installs_a_global_subscriber` 同一条纪律。
    ///
    /// 机械判据靠源码文本，因为"没有人调它"没法在运行期观察到。
    #[test]
    fn library_never_installs_a_global_recorder() {
        const SOURCES: [(&str, &str); 9] = [
            ("lib.rs", include_str!("lib.rs")),
            ("auth.rs", include_str!("auth.rs")),
            ("error.rs", include_str!("error.rs")),
            ("limits.rs", include_str!("limits.rs")),
            ("readiness.rs", include_str!("readiness.rs")),
            ("telemetry.rs", include_str!("telemetry.rs")),
            ("http/mod.rs", include_str!("http/mod.rs")),
            ("http/channels.rs", include_str!("http/channels.rs")),
            ("http/metrics.rs", include_str!("http/metrics.rs")),
        ];
        for (name, source) in SOURCES {
            assert!(
                !source.contains("set_global_recorder"),
                "{name} 里出现了 set_global_recorder —— 库不得替宿主装全局 recorder"
            );
            // exporter 自带的两条外发/监听能力也不许在别处冒出来（§16.4 零 phone-home
            // + 台账「不另开监听端口」）。
            assert!(!source.contains("with_http_listener"), "{name}");
            assert!(!source.contains("with_push_gateway"), "{name}");
        }
        // 正向对照：本文件**确实**有那个调用（否则上面在"全仓根本没有这个函数"的
        // 世界里同样通过）。
        assert!(include_str!("metrics.rs").contains("set_global_recorder"));
    }
}
