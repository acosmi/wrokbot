//! `openbot-testkit` —— 测试与闸门工具：golden trace、fault injection、fake provider、xtask。
//!
//! # 所有权边界（v3 §5.1 / §19.3 / §21）
//!
//! 负责：
//!
//! - golden trace 的录制、回放与比对（v3 §21.1 parity / §21.2 Agent-Protocol）；
//!   shadow Agent 只重放录制的 provider stream，**不执行 live tool**（v3 §20.1）。
//! - fault injection 与 fake provider：让 retry / cancel / budget / stall 这些路径在没有真实
//!   厂商端点的情况下也能被确定性覆盖。
//! - golden 截图工具面（设计系统文档 §10.4）；当前库面只提供无第三方依赖的 RGBA8
//!   像素比较核心，不解码 PNG、不截图、不生成 diff 图，也不冒充完整 golden gate。
//! - **xtask**：仓库闸门驱动器，落在本 crate 的 bin target `src/bin/xtask.rs`，
//!   `required-features = ["xtask"]`。v3 §5.1 的 crate 表里本 crate 的职责原文就含 "xtask"，
//!   所以这是方案内既定归属，不是本轮新增的第 11 个 crate。
//!
//! 明确**不**负责：
//!
//! - 进入任何发行物。本 crate 是开发期工具，`publish = false`，不被十个业务 crate 依赖。
//! - 实现业务规则或绕开 `openbot-application`：测试也必须穿过 `ApplicationService`（v3 §5.2
//!   逐字把"测试"与 Axum、Tauri、迁移工具并列为只做认证 / framing / 限制 / 错误映射的一方）。
//! - 替代 CI：`xtask ci` 只是把 v3 §16.3 的固定清单按顺序跑一遍，不新增也不删减判据。
//!
//! # 当前落地面
//!
//! | target | 内容 | 出处 |
//! | --- | --- | --- |
//! | [`golden`] | 已解码 RGBA8 的阈值、比例、8×8 差异块与显式 mask 比较核心 | GUI v2 §10.4 |
//! | `src/bin/xtask.rs` | 仓库闸门驱动器（含PNG-only `golden check-manifest/compare/verify`） | §19.3 / §24 G0/G6 |
//! | `tests/transport_parity.rs` | **G1 判据第 2 条**的执行面：同一个 `ApplicationService` 经 Axum HTTP 与 in-process 两条 transport，结果一致 | §24 G1 / §5.2 |
//!
//! PNG解码、deterministic diff图、manifest/mask/matrix fail-closed gate已落；Web CDP/desktop xcap
//! 截图、固定Linux容器/fonts与245张正式基线仍未落。golden trace、fault injection与fake provider继续
//! 按各自闸门逐步实施。
//!
//! ## 为什么对拍装置落在 `tests/` 而不是库面
//!
//! 它是一份**集成测试**，不是可复用工具：夹具（内存 `ChannelReader`、固定身份、
//! 命令→路由台账）只对那一条判据有意义。把它们提到库面就得给每一样起一个公开名字、
//! 定一份公开契约，而在下一个消费者出现之前，那份契约没有任何人在验证。
//!
//! 更实在的一条：库面一旦公开这些夹具，业务 crate 就可能反向依赖 testkit —— 而本 crate
//! 「不进任何发行物」正是靠"没人依赖它"成立的。
//!
//! ## dev-dependencies 的方向
//!
//! `tests/transport_parity.rs` 依赖 `openbot-application` / `-contracts` / `-server` /
//! `-desktop` 四个业务 crate，全部只在 `[dev-dependencies]` 里。所以依赖箭头是
//! **testkit → 业务 crate**，且只在 `cargo test` 时存在；`cargo build --workspace` 的
//! 依赖图里，本 crate 与它们零关系。

pub mod golden;

#[cfg(test)]
mod fixtures;
