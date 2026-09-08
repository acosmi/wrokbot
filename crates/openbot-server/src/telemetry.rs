//! tracing —— 请求 span、`request_id` 消毒、subscriber 构造器（v3 §16.4）。
//!
//! G1 判据第四条逐字：「tracing/metrics/redaction 从首个 vertical slice 生效」。本模块是
//! 其中 tracing 与 redaction 那两半在 transport 侧的落点。**metrics 尚未落地**，见 crate
//! 文档〈还没有的东西〉。
//!
//! # 零 phone-home
//!
//! §16.4 逐字：「Rust 版删掉 runtime 后没有任何第一方外发遥测端点，OTel exporter 只在
//! 管理员显式配置 collector 地址时才建连」。本模块**没有任何网络出口**：它只往调用方给
//! 的 `Write` 里写字节。`opentelemetry` 也刻意不在依赖图里 —— 配置面是 G2（§15.4），
//! 此刻引入只会得到一个零调用点的依赖。
//!
//! # 库不自动装全局 subscriber
//!
//! [`init`] 是**显式调用**的，本 crate 没有任何路径会自己调它（`router` 不会、handler
//! 不会）。理由很实在：全局 subscriber 一个进程只能装一次，库替宿主装了，宿主就再也装
//! 不上自己的了 —— 而 Desktop 与 Server 共用同一份 core，日志去向必须由二进制决定。
//! 需要组合而不是接管的宿主用 [`subscriber`] 拿到 `Subscriber` 自行处置。
//!
//! # `request_id` 当不可信输入处理
//!
//! 它可以来自请求头（跨服务串联链路时有用），而请求头是对端完全控制的字节。原样记进
//! 日志有两个具体后果：换行符能伪造整条日志记录（日志注入），超长值能把日志写爆。所以
//! [`sanitize_request_id`] 是一道**白名单**：ASCII 字母数字加 `-` `_`，长度 1..=64。
//! 不合格就当没有，铸造一个新的 UUIDv7 —— **不截断、不清洗后使用**，因为"把攻击者的
//! 字符串洗一洗再用"仍然是在用攻击者的字符串。

use axum::extract::MatchedPath;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderMap, HeaderName, HeaderValue};
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

/// 承载 request id 的请求头 / 响应头名。
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// 接受的 request id 最大长度（字符）。
///
/// 64 = 一个 UUID（36）加上调用方前缀还有余量，同时远小于任何会把日志行撑坏的长度。
pub const MAX_REQUEST_ID_LEN: usize = 64;

/// 请求 span 的名字。
///
/// 它与 [`trace_request`] 里 `info_span!` 的字面量必须一致；
/// `request_span_name_matches_the_constant` 用捕获到的真实 span 名比对它。
pub const REQUEST_SPAN_NAME: &str = "http.request";

/// span 上 actor 身份字段的名字。[`crate::auth::Authenticated`] 往这里写。
pub const ACTOR_ID_FIELD: &str = "actor_id";

/// 静态路由 pattern span 字段。
pub const HTTP_ROUTE_FIELD: &str = "http.route";

/// [`trace_request`] 在请求 span 上记录的字段名全集。
///
/// 与 `openbot_application::service::APPLICATION_SPAN_FIELDS` 同样是**台账**：
/// `request_span_fields_are_exactly_the_declared_ledger` 拿捕获到的真实字段集与它逐项
/// 比对，多记一个或少记一个都判红。加字段就必须来改这里，而改这里会立刻撞上
/// 「这个字段的基数论证在哪」这个问题。
///
/// 逐项理由（§16.4「高基数 actor/thread 不进入 metrics label，只进入受控 trace/log」）：
///
/// - `request_id`：**每次请求都不同 = 无界基数**，只进 trace/log。它在 §16.4 的关联字段
///   清单里。
/// - `http.method`：值域是 HTTP 方法，有界。
/// - `http.status_code`：值域是状态码，有界。
/// - `actor_id`：§16.4 点名的高基数字段，只进 trace/log。
///
/// route 只来自 `MatchedPath`；request/actor 仍只进 trace，不进 metrics。
pub const REQUEST_SPAN_FIELDS: &[&str] = &[
    "request_id",
    "http.method",
    "http.status_code",
    HTTP_ROUTE_FIELD,
    ACTOR_ID_FIELD,
];

/// 消毒 request id：合格就借出原值，不合格返回 `None`。
///
/// 判据是**白名单**：长度 1..=[`MAX_REQUEST_ID_LEN`]，且每个字节都是 ASCII 字母数字或
/// `-` / `_`。这一集合刚好覆盖 UUID、ULID、以及常见的 `<service>-<id>` 前缀形态，同时
/// 排除掉换行、控制字符、空格、引号与任何非 ASCII 字节。
#[must_use]
pub fn sanitize_request_id(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    raw.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        .then_some(raw)
}

/// 取本次请求的 request id：头部合格就沿用，否则铸造一个 UUIDv7。
///
/// 沿用而不是永远新铸，是因为跨服务链路需要同一个 id 串起来；铸造而不是原样接受，
/// 是因为那个头是对端控制的。两者的接缝就是 [`sanitize_request_id`]。
#[must_use]
pub fn resolve_request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_request_id)
        .map_or_else(|| Uuid::now_v7().to_string(), ToOwned::to_owned)
}

/// 请求级 span 中间件。
///
/// 装在 router 的**最外层**（见 [`crate::http::router`]），所以：
///
/// - 413（超出 [`crate::limits::REQUEST_BODY_LIMIT_BYTES`]）与 404 也被记进 span；
/// - `AuthResolver` 在这个 span 里跑，于是 [`crate::auth::Authenticated`] 的
///   `Span::current().record(actor_id, …)` 落在这条记录上；
/// - `openbot-application` 的 `application.execute` span 是它的子 span，`request_id`
///   经 span 父子关系自然继承，不必逐层手传。
///
/// # 为什么 span 里只有 route pattern
///
/// 不记 `uri().path()`；只读 Axum `MatchedPath` 静态 pattern，未匹配写 `unmatched`。
pub async fn trace_request(request: Request, next: Next) -> Response {
    let request_id = resolve_request_id(request.headers());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or(crate::metrics::ROUTE_UNMATCHED, MatchedPath::as_str);
    let span = tracing::info_span!(
        "http.request",
        request_id = %request_id,
        http.method = %request.method(),
        http.status_code = tracing::field::Empty,
        http.route = %route,
        actor_id = tracing::field::Empty,
    );

    let mut response = {
        use tracing::Instrument as _;
        next.run(request).instrument(span.clone()).await
    };
    span.record("http.status_code", response.status().as_u16());

    // 把**消毒后**的 id 回给调用方：运维报障时能直接给出这一个值。回的是我们认可的
    // 那个字符串，不是对端送来的原值 —— 原值不合格时它已经被换成新铸的 UUID 了。
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    response
}

/// 日志格式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// 人读格式，给开发与 Desktop 本地 ring buffer。
    Text,
    /// 一行一个 JSON 对象，给容器化 Server（§16.1 的 OCI image）。
    Json,
}

/// 默认过滤指令 —— 没有 `RUST_LOG` 时用它。
///
/// `info` 而不是 `debug`：§17.2 条 8「secret 不进普通日志」，而 debug 级别是第三方库
/// 最可能打出请求细节的地方。要更吵由运维显式开。
pub const DEFAULT_FILTER_DIRECTIVE: &str = "info";

/// 组装一个 `Subscriber`，写到调用方给的 writer。
///
/// # 过滤器来自 `RUST_LOG`
///
/// 刻意用生态惯例 `RUST_LOG`，而不是发明一个 `OPENBOT_LOG`：§15.4 已经把 `OPENBOT_*`
/// 变量做了 preserve / rename / remove 三档裁决，往那份清单里加一个没有 ledger 条目的
/// 新变量是擅自扩张（repository contract §4「parity 与新增必须分开标注」）。`RUST_LOG` 不属于
/// 那份清单，也不需要"被 remove 的变量出现即启动报错"那条规则兜着。
///
/// 解析不了（写错了指令）时回落到 [`DEFAULT_FILTER_DIRECTIVE`]，不 panic：一个拼错的
/// 日志过滤器不该让服务起不来。
pub fn subscriber<W>(format: LogFormat, make_writer: W) -> Box<dyn Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER_DIRECTIVE));
    subscriber_with_filter(format, make_writer, filter)
}

fn subscriber_with_filter<W>(
    format: LogFormat,
    make_writer: W,
    filter: EnvFilter,
) -> Box<dyn Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(make_writer);
    match format {
        LogFormat::Text => Box::new(builder.finish()),
        LogFormat::Json => Box::new(builder.json().finish()),
    }
}

/// 把 [`subscriber`] 装成进程全局默认，写到 stderr。
///
/// **只有宿主二进制该调它，而且只调一次。** 本 crate 内部零调用点（由
/// `library_never_installs_a_global_subscriber` 钉住）。
///
/// # Errors
///
/// 已经装过全局 subscriber 时返回 `SetGlobalDefaultError`。这是**错误而不是静默覆盖**：
/// 谁在给这个进程记日志是宿主必须知道的事。
pub fn init(format: LogFormat) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(subscriber(format, std::io::stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// 收进内存的 writer，用来实测两种格式的**字节**。
    #[derive(Clone, Default)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl BufferWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().expect("writer 锁不会中毒").clone())
                .expect("日志是 UTF-8")
        }
    }

    impl io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("writer 锁不会中毒")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // -----------------------------------------------------------------------
    // request id 消毒
    // -----------------------------------------------------------------------

    /// 正向：合格的 id 原样沿用。
    ///
    /// 没有这一条，下面那组"非法值被拒"的断言在
    /// 「`sanitize_request_id` 恒返回 `None`」的世界里全部通过。
    #[test]
    fn well_formed_request_ids_are_kept_verbatim() {
        assert_eq!(sanitize_request_id("abc123"), Some("abc123"));
        assert_eq!(
            sanitize_request_id("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"),
            Some("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
        );
        assert_eq!(
            sanitize_request_id("edge_gateway-42"),
            Some("edge_gateway-42")
        );
        // 恰好等于上限的长度必须通过 —— 边界不是"接近上限就拒"。
        let exact = "a".repeat(MAX_REQUEST_ID_LEN);
        assert_eq!(sanitize_request_id(&exact), Some(exact.as_str()));
    }

    /// 负向：注入面上的每一类都被拒。
    #[test]
    fn hostile_request_ids_are_rejected_not_sanitized() {
        // 日志注入：换行能伪造一整条记录。
        assert_eq!(sanitize_request_id("a\nlevel=INFO fake=1"), None);
        assert_eq!(sanitize_request_id("a\r\nb"), None);
        // 控制字符与 ANSI 转义。
        assert_eq!(sanitize_request_id("a\u{1b}[31m"), None);
        assert_eq!(sanitize_request_id("a\0b"), None);
        // JSON 结构字符 —— JSON 格式下能把一行日志拆成两个对象。
        assert_eq!(sanitize_request_id(r#"a","x":"y"#), None);
        // 空格与非 ASCII。
        assert_eq!(sanitize_request_id("a b"), None);
        assert_eq!(sanitize_request_id("中文"), None);
        // 长度两端。
        assert_eq!(sanitize_request_id(""), None);
        assert_eq!(
            sanitize_request_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)),
            None
        );
    }

    #[test]
    fn resolve_mints_a_fresh_id_when_the_header_is_absent_or_hostile() {
        let empty = HeaderMap::new();
        let minted = resolve_request_id(&empty);
        assert_eq!(
            sanitize_request_id(&minted),
            Some(minted.as_str()),
            "铸造出来的 id 必须自己也过得了消毒 —— 否则它自己就是注入面"
        );

        let mut hostile = HeaderMap::new();
        hostile.insert(
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_static("bad value with spaces"),
        );
        let replaced = resolve_request_id(&hostile);
        assert_ne!(replaced, "bad value with spaces");
        assert!(sanitize_request_id(&replaced).is_some());

        // 正向对照：合格的头确实被沿用（否则上面两条在"永远重铸"的世界里也通过）。
        let mut good = HeaderMap::new();
        good.insert(
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_static("upstream-req-7"),
        );
        assert_eq!(resolve_request_id(&good), "upstream-req-7");
    }

    /// 两次铸造不撞号。
    #[test]
    fn minted_ids_are_distinct() {
        let headers = HeaderMap::new();
        assert_ne!(resolve_request_id(&headers), resolve_request_id(&headers));
    }

    // -----------------------------------------------------------------------
    // subscriber
    // -----------------------------------------------------------------------

    /// 两种格式确实产出**不同**的字节，且 JSON 那种真的是 JSON。
    ///
    /// 只断言"能跑通"是没用的：那在两个分支返回同一个 subscriber 的世界里同样成立。
    #[test]
    fn text_and_json_formats_differ_and_json_parses() {
        let text_sink = BufferWriter::default();
        tracing::subscriber::with_default(
            subscriber_with_filter(
                LogFormat::Text,
                text_sink.clone(),
                EnvFilter::new(DEFAULT_FILTER_DIRECTIVE),
            ),
            || {
                tracing::info!(marker = "openbot-format-probe", "hello");
            },
        );
        let text = text_sink.contents();
        assert!(text.contains("openbot-format-probe"), "{text}");
        assert!(
            serde_json::from_str::<serde_json::Value>(text.trim()).is_err(),
            "Text 格式不该是 JSON，否则两个分支没区别：{text}"
        );

        let json_sink = BufferWriter::default();
        tracing::subscriber::with_default(
            subscriber_with_filter(
                LogFormat::Json,
                json_sink.clone(),
                EnvFilter::new(DEFAULT_FILTER_DIRECTIVE),
            ),
            || {
                tracing::info!(marker = "openbot-format-probe", "hello");
            },
        );
        let json = json_sink.contents();
        let parsed: serde_json::Value =
            serde_json::from_str(json.trim()).unwrap_or_else(|e| panic!("{json} 不是 JSON：{e}"));
        assert_eq!(parsed["fields"]["marker"], "openbot-format-probe");
        assert_ne!(text, json);
    }

    /// 本 crate 不在任何地方自动装全局 subscriber。
    ///
    /// 机械判据：`init` 的调用点只有它自己的定义与测试。这条断言靠源码文本，
    /// 因为"没有人调它"没法在运行期观察到。
    #[test]
    fn library_never_installs_a_global_subscriber() {
        const SOURCES: [(&str, &str); 10] = [
            ("lib.rs", include_str!("lib.rs")),
            ("auth.rs", include_str!("auth.rs")),
            ("error.rs", include_str!("error.rs")),
            ("limits.rs", include_str!("limits.rs")),
            ("readiness.rs", include_str!("readiness.rs")),
            ("http/mod.rs", include_str!("http/mod.rs")),
            ("http/channels.rs", include_str!("http/channels.rs")),
            ("http/health.rs", include_str!("http/health.rs")),
            ("http/metrics.rs", include_str!("http/metrics.rs")),
            ("metrics.rs", include_str!("metrics.rs")),
        ];
        for (name, source) in SOURCES {
            assert!(
                !source.contains("set_global_default"),
                "{name} 里出现了 set_global_default —— 库不得替宿主装全局 subscriber"
            );
        }
        // 正向对照：本文件**确实**有那个调用（否则上面在"全仓根本没有这个函数"的
        // 世界里同样通过）。
        assert!(include_str!("telemetry.rs").contains("set_global_default"));
    }
}
