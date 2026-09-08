//! `GET /metrics` —— parity ledger `metrics-get`（`label: 新增`，`T-API-0148`）。
//!
//! 台账原文把落点钉成 `openbot-server::http::metrics (GET /metrics)`，本模块逐字兑现。
//!
//! # 为什么是本进程的一条路由，而不是第二个监听端口
//!
//! 台账 `notes` 逐字：「**不另开监听端口** —— 第二个监听端口是一块没经过评审的网络面」。
//! `metrics-exporter-prometheus` 自带的 `http-listener` 能自己起一个服务，那条路会绕过
//! 本 crate 的全部 transport 约束（[`crate::limits`] 的体积上限、[`crate::telemetry`] 的
//! 请求 span、以及 G2 要加的 method/origin 判定），所以仓根把它的 `default-features`
//! 关掉了（见 `Cargo.toml` 注释）。
//!
//! # 访问控制：与 API 共用 session
//!
//! handler 签名要求 [`crate::auth::Authenticated`]；未登录 401。没有第二枚 metrics token，
//! 因而 session 撤权/代际变化会与其它 API 同时生效。
//!
//! # 没装 recorder 时 fail-closed
//!
//! 宿主没调 [`crate::metrics::install_recorder`]、也没把句柄交给 `ServerBuilder` 时，
//! 这条路由回 **503**，不回一段空文本。空文本与"这个副本真的一个请求都没处理过"
//! 逐字节不可分，而后者是合法状态 —— 把两者渲染成同一个响应，就等于让"指标没接上"
//! 这件事永远没人发现。

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{StatusCode, header};
use openbot_contracts::error::AppError;

use crate::auth::Authenticated;
use crate::error::HttpError;
use crate::http::ServerState;

/// Prometheus 文本曝露格式的 content type。
///
/// `version=0.0.4` 是 Prometheus 文本格式的版本号，抓取端按它决定解析器。写死是对的：
/// 它是格式契约，不是可配置项。
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `GET /metrics` —— 渲染当前指标快照。
///
/// # Errors
///
/// 宿主没有交出渲染句柄时返回 503 `dependency_unavailable`（见模块文档〈fail-closed〉）。
pub async fn render(
    State(state): State<ServerState>,
    Authenticated(_auth): Authenticated,
) -> Result<Response, HttpError> {
    let Some(handle) = state.metrics_handle() else {
        tracing::warn!("GET /metrics 但宿主没有安装 metrics recorder —— fail-closed 回 503");
        return Err(AppError::DependencyUnavailable {
            dependency: "metrics_recorder",
        }
        .into());
    };

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        handle.render(),
    )
        .into_response())
}
