//! `GET /health` 与 `GET /readiness` —— 运维面（v3 §16.1）。
//!
//! # 两条路由的身份不同
//!
//! | 路由 | 台账 | 语义 |
//! | --- | --- | --- |
//! | `/health` | parity `health-get`（`migration_rule: preserve`，上游返回 `{status:"ok"}`） | **存活**：进程还在应答。恒 200，不碰数据库、不碰 application |
//! | `/readiness` | **新增** `readiness-get`（`T-API-0147`） | **就绪**：声明过的依赖判据此刻各是什么状态 |
//!
//! 拆成两条是 §16.1 的要求（台账 `notes` 原文：「Rust 版按 §16.1 拆 health/readiness，
//! /health 语义不变」）。拆开的价值在于它们的失败含义完全不同：`/health` 红 = 把这个
//! 进程杀掉重启；`/readiness` 红 = 别往它身上导流量，但别杀它（它可能正等着数据库回来）。
//! 合成一条会让编排器在两种情形下做同一件错事。
//!
//! # 两条都不经认证
//!
//! `/health` 是 parity 决定的（台账标 `public`）。`/readiness` 是本轮的裁决：编排器的
//! 探针没有 session，要求认证等于让这条路由对它真正的消费者不可用。代价是任何人都能看到
//! 一个布尔式的就绪状态 —— 所以响应体里**只有聚合状态，没有依赖明细**：依赖名会泄漏部署
//! 拓扑（`openbot_contracts::command::HealthReport` 为同一理由拒绝在探活应答里列依赖）。
//! 哪一项没就绪、哪一项没验证，只进 `warn!` 日志。
//!
//! # `/readiness` 的三态
//!
//! `ready`(200) / `unverified`(**503**) / `not_ready`(503)，语义、优先级与那条 503 裁决的
//! 代价论证见 [`crate::readiness`] 模块文档。这里只强调一件事：**`unverified` 一路呈现到
//! 响应体**，不折叠成 ready 也不折叠成 `not_ready`。`openbot-infra` 已经用类型把
//! 「账本表不存在 ⇒ 无法验证」这一态承载好了，transport 把它压成布尔就等于把那套设计
//! 作废。后两态同状态码，所以**区分只落在 body 的 `status` 字段与 `warn!` 日志上**，
//! 测试也相应地断言 body 而不只断言状态码。

use axum::Json;
use axum::extract::State;
use http::StatusCode;
use serde::Serialize;

use crate::http::ServerState;
use crate::readiness::{ReadinessStatus, ReadinessVerdict, aggregate};

/// `/health` 的稳定取值。上游返回 `{status:"ok"}`，parity 保留。
pub const HEALTH_OK: &str = "ok";

/// `/health` 的响应体。
///
/// 刻意**不**复用 `openbot_contracts::command::HealthReport`：那是 `AppCommand::Health`
/// 的跨边界应答（`{"ok":true}`），而这条路由的线上形状由 parity 台账固定成
/// `{"status":"ok"}`。两个形状撞在一个类型上，改任何一边都会悄悄破掉另一边。
#[derive(Debug, Serialize)]
pub struct HealthBody {
    /// 恒 [`HEALTH_OK`]。
    pub status: &'static str,
}

/// `GET /health` —— 存活探针。
///
/// 没有任何参数：**它连 `ServerState` 都不取**。这不是省事，是判据 —— 一个拿不到 state
/// 的 handler 在构造上就不可能去碰数据库、application 或认证。台账写着「错误码：无（恒
/// 200）」，而"恒 200"最可靠的兑现方式是让它无从失败。
pub async fn health() -> Json<HealthBody> {
    Json(HealthBody { status: HEALTH_OK })
}

/// `/readiness` 的响应体。**只有聚合状态**，见模块文档。
#[derive(Debug, Serialize)]
pub struct ReadinessBody {
    /// 三态之一。
    pub status: ReadinessStatus,
    /// 仅非 loopback 明文 HTTP 为 true；安全档位省略该字段以保持最小响应。
    #[serde(skip_serializing_if = "is_false")]
    pub insecure_transport: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// `GET /readiness` —— 就绪探针。
///
/// 逐条跑完**全部**已声明判据再聚合，不在第一条判红时短路：运维需要一次就看到所有出问题
/// 的依赖，而不是修一条重启一次再发现下一条。
pub async fn readiness(State(state): State<ServerState>) -> (StatusCode, Json<ReadinessBody>) {
    let probes = state.readiness_probes();

    if probes.is_empty() {
        // fail-closed：一条判据都没声明的进程说不出自己 ready（§16.1「未配置独立
        // Supervisor + runsc 时 readiness 失败，不能静默退回共享 browser」—— 判据是
        // "没配置"，不是"配了但坏了"）。
        tracing::warn!("readiness 没有任何已声明判据 —— 按 fail-closed 判为 not_ready");
    }

    let mut verdicts = Vec::with_capacity(probes.len());
    for probe in probes {
        let verdict = probe.check().await;
        match verdict {
            ReadinessVerdict::Ready => {}
            ReadinessVerdict::NotReady => {
                tracing::warn!(dependency = probe.dependency(), "readiness 判据判红");
            }
            ReadinessVerdict::Unverified => {
                // 这一条就是"三态别被压成布尔"的可观察面：运维在日志里看得见
                // **哪一项本轮没有被验证过**，而不是只看到一个绿色的 ready。
                tracing::warn!(
                    dependency = probe.dependency(),
                    "readiness 判据本轮无法验证 —— 既未通过也未失败"
                );
            }
        }
        verdicts.push(verdict);
    }

    let status = aggregate(verdicts);
    // fail-closed 兜底：`ReadinessStatus::http_status` 的值域是 {200, 503}，两者都是合法
    // 状态码（`readiness_statuses_are_valid_http_codes` 钉住），所以这条 `unwrap_or`
    // 不可达；真要不可达变可达，宁可回 503 也不回 200。
    let code =
        StatusCode::from_u16(status.http_status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    (
        code,
        Json(ReadinessBody {
            status,
            insecure_transport: state.insecure_transport(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个状态码都能翻译成合法 `StatusCode` —— 上面那条 `unwrap_or` 兜底不可达。
    #[test]
    fn readiness_statuses_are_valid_http_codes() {
        for status in [
            ReadinessStatus::Ready,
            ReadinessStatus::Unverified,
            ReadinessStatus::NotReady,
        ] {
            let code = StatusCode::from_u16(status.http_status())
                .unwrap_or_else(|_| panic!("{status:?} 的状态码不合法"));
            assert_eq!(code.as_u16(), status.http_status());
        }
    }

    /// `/health` 的线上形状是 parity 台账里那一个，不是 contracts 的 `HealthReport`。
    #[test]
    fn health_body_matches_the_upstream_wire_shape() {
        let json = serde_json::to_string(&HealthBody { status: HEALTH_OK }).expect("可序列化");
        assert_eq!(json, r#"{"status":"ok"}"#);
        // 负向对照：它**不是** `AppCommand::Health` 的应答形状。
        assert_ne!(json, r#"{"ok":true}"#);
    }

    /// 三态各自的线上形状。
    #[test]
    fn readiness_body_renders_all_three_states() {
        let render = |status| {
            serde_json::to_string(&ReadinessBody {
                status,
                insecure_transport: false,
            })
            .expect("可序列化")
        };
        assert_eq!(render(ReadinessStatus::Ready), r#"{"status":"ready"}"#);
        assert_eq!(
            render(ReadinessStatus::Unverified),
            r#"{"status":"unverified"}"#
        );
        assert_eq!(
            render(ReadinessStatus::NotReady),
            r#"{"status":"not_ready"}"#
        );
        assert_eq!(
            serde_json::to_string(&ReadinessBody {
                status: ReadinessStatus::Ready,
                insecure_transport: true,
            })
            .unwrap(),
            r#"{"status":"ready","insecure_transport":true}"#,
        );
    }
}
