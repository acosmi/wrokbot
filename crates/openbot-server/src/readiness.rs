//! readiness —— **三态**，因为"没验证过"和"验证通过"不是同一件事（v3 §16.1）。
//!
//! # 为什么不是布尔
//!
//! §14.1 的迁移边界判定天生是三态：账本 `drizzle.__drizzle_migrations` 有 ≥ 13 条 →
//! 确认迁到 `0012`；条目不足 → 确定的不兼容；**账本表根本不存在** → 无法验证。第三态是
//! 刻意的：13 条 migration 里 `0003` 是纯数据迁移，跑没跑过在 schema 上不留痕迹，而账本
//! 缺失时**不能用数据形状去猜**（§28.1 R24 记着上一版基于 `accounts.issuer IS NULL` 的
//! 判据是错的 —— 上游注释写明该列 deliberately 可空，滚动发布期旧 replica 会插不带该列
//! 的行，于是 NULL 在健康库上合法，fail-closed 会拒绝一个好库）。
//!
//! `openbot-infra` 已经用类型把这三态承载好了。**如果 transport 这一层把它压成布尔，
//! 前面那套设计就白做了** —— 那正是 repository contract 反复点名的形态：跳过自己却报 ok 的检查
//! 不是闸门。所以 [`ReadinessVerdict`] 也是三态，而且 [`ReadinessStatus`] 把第三态一路
//! 呈现到 HTTP 响应体里。
//!
//! # 三态各自的处置
//!
//! | 判定 | 聚合后的状态 | HTTP | 日志 |
//! | --- | --- | --- | --- |
//! | [`ReadinessVerdict::Ready`] | 该项 ok | —— | 不记 |
//! | [`ReadinessVerdict::NotReady`] | [`ReadinessStatus::NotReady`] | 503 | `warn!` |
//! | [`ReadinessVerdict::Unverified`] | [`ReadinessStatus::Unverified`] | **503** | `warn!` |
//!
//! # `Unverified` 走 503（2026-08-22 裁决）
//!
//! 判据是**两种误判的代价不对称**：
//!
//! - `unverified → 200`：一个跳过了数据迁移的库**静默接流量**。以 `0003`
//!   （`backfill_account_issuer`，13 条里唯一的纯数据迁移）为例，后果是同一身份被
//!   Better Auth 重复建账 —— 数据层面的身份污染，事后极难清理，而且**没有任何人会看见**：
//!   只看状态码的编排器读到的是 ready。
//! - `unverified → 503`：副本起不来。后果**响亮、立刻、第一次冒烟就撞上**。
//!
//! 叠加 repository contract §5 条 3「空 / 坏 / 未知 policy fail-closed」——`Unverifiable` 就是
//! 「未知」。
//!
//! 代价随之落到状态码上：`Unverified` 与 `NotReady` **同码**，所以「三态可见」这件事的
//! 兑现全部落在 body 的 `status` 字段与 `warn!` 日志上。测试相应地断言 body，不只断言
//! 状态码（`readiness_renders_three_pairwise_distinct_outcomes` 比的是三个 body）。
//!
//! ## 接线层随之背上的义务 —— 读到这里的人请务必看完
//!
//! **新装的库由本项目 Rust baseline 建成，不会有 drizzle 账本。** 如果接线层原样把
//! "账本表不存在"映射成 [`ReadinessVerdict::Unverified`]，一套全新安装将**永远不会
//! ready** —— 而且症状会诱使人去改状态码。
//!
//! **正确的解法不是把 503 放宽回 200。** 状态码那条判据保护的是"有历史数据、但没跑过
//! 迁移"这个致命情形，放宽它等于把上面那条不对称的代价论证整个作废。正确的解法是：
//! **接线层要知道"这个库是我自己刚建的、没有历史数据要回填"，从而映射成
//! [`ReadinessVerdict::Ready`]。** 判据必须是本项目自己留下的痕迹（例如 Rust baseline
//! 建库时写下的 schema 版本记录），而**不是**"账本表不存在就当新库" —— 后者与
//! "一个删掉了账本表的旧库"逐字节不可分，那正是 §28.1 R24 已经推翻过一次的猜法。
//!
//! 一句话给 G2 接线的人：**看到新装不 ready，去补"这是新库"的证据，别去改状态码。**
//!
//! # 零探针 = not ready，这是 fail-closed
//!
//! 一个**一条依赖都没声明**的 Server 说不出自己 ready。§16.1 逐字：「multi-user
//! production 未配置独立 Supervisor + runsc 时 readiness 失败，不能静默退回共享 browser」
//! —— 判据是"没配置"，不是"配了但坏了"。所以 [`ServerBuilder`](crate::http::ServerBuilder)
//! 不注册任何探针时 `/readiness` 返回 503，由
//! `readiness_with_no_probes_is_not_ready` 配正向对照钉住。
//!
//! # 判据 port 与二进制接线
//!
//! library 只定义 port；W-4 `main.rs` 把
//! `openbot_infra::db::compat` 的 `DataMigrationVerdict` **逐态**映射过来：
//!
//! ```text
//! DataMigrationVerdict::Applied      -> ReadinessVerdict::Ready
//! DataMigrationVerdict::Incomplete   -> ReadinessVerdict::NotReady
//! DataMigrationVerdict::Unverifiable -> ReadinessVerdict::Unverified
//! ```
//!
//! [`FnReadinessProbe`] 就是给这段映射用的：接线层写一个闭包，不必为每个依赖定义一个
//! 类型。**三态到三态，一一对应** —— 中间没有任何一步能把 `Unverifiable` 合并掉。

use core::future::Future;

use async_trait::async_trait;
use serde::Serialize;

/// 一次依赖检查的判定。**三态**，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadinessVerdict {
    /// 验证过，可服务。
    Ready,
    /// 验证过，不可服务。这是**确定的**不兼容或故障。
    NotReady,
    /// **没能验证**。既不是通过也不是失败 —— 判据本轮拿不到证据。
    ///
    /// 实现绝不能拿它当"大概没事"用：它的唯一正确来源是"我确实没法知道"
    /// （例如迁移账本表不存在）。用它掩盖一次超时或一次查询失败，就是把故障
    /// 洗成"未验证"。
    Unverified,
}

/// 一次依赖检查。
///
/// `dependency()` 返回 `&'static str` 而不是 `String`：依赖名会进日志，而数据库/上游
/// 返回的原值是不可信数据 —— 这条限制在类型层面堵死"把运行期字符串当依赖名"的路，
/// 与 `openbot_application::ports::PortError` 的同一决定一致。
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    /// 依赖的静态名。**只进受控日志，绝不进 HTTP 响应体**（依赖明细泄漏部署拓扑）。
    fn dependency(&self) -> &'static str;

    /// 此刻的判定。
    async fn check(&self) -> ReadinessVerdict;
}

/// 由闭包提供判定的探针 —— 接线层的默认工具。
///
/// 存在的理由：迁移账本、连接池、Supervisor、runsc 这些检查各自只有一行逻辑，为每一个
/// 定义一个类型只会得到一堆一次性 struct。闭包让**那一行映射**成为代码里最显眼的东西：
///
/// ```ignore
/// FnReadinessProbe::new(MIGRATION_LEDGER_DEPENDENCY, || async {
///     match compat::data_migration_verdict(&pool).await {
///         DataMigrationVerdict::Applied => ReadinessVerdict::Ready,
///         DataMigrationVerdict::Incomplete => ReadinessVerdict::NotReady,
///         DataMigrationVerdict::Unverifiable => ReadinessVerdict::Unverified,
///     }
/// })
/// ```
///
/// 穷举 match 是这里的重点：`DataMigrationVerdict` 新增变体会让接线层当场编译失败，
/// 而不是悄悄落进某个 `_ =>` 分支。
pub struct FnReadinessProbe<F> {
    dependency: &'static str,
    check: F,
}

impl<F> FnReadinessProbe<F> {
    /// 用一个异步闭包造探针。
    pub const fn new(dependency: &'static str, check: F) -> Self {
        Self { dependency, check }
    }
}

#[async_trait]
impl<F, Fut> ReadinessProbe for FnReadinessProbe<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = ReadinessVerdict> + Send,
{
    fn dependency(&self) -> &'static str {
        self.dependency
    }

    async fn check(&self) -> ReadinessVerdict {
        (self.check)().await
    }
}

/// 迁移账本这一项的依赖名。
///
/// 常量而不是各处手写字面量：它同时出现在接线层的探针注册与运维的日志检索里，
/// 两处漂移会让"grep 不到"看起来像"没发生过"。
///
/// # 注册这一项的人必须先读模块文档〈接线层随之背上的义务〉
///
/// 一句话版本：**新装的库没有 drizzle 账本**。把"账本表不存在"原样映射成
/// [`ReadinessVerdict::Unverified`] 会让全新安装永远不 ready（`Unverified` 是 503）。
/// 解法是给接线层补上"这是本项目自己刚建的新库"的**正面证据**并映射成
/// [`ReadinessVerdict::Ready`]，**不是**把状态码放宽 —— 那会作废掉
/// 「跳过迁移的旧库静默接流量」这条保护。
pub const MIGRATION_LEDGER_DEPENDENCY: &str = "database_migration_ledger";

/// 聚合后的 readiness 状态 —— **就是 HTTP 响应体里那个 `status`**。
///
/// 封闭 enum + `snake_case`：取值是契约，编排器与运维脚本会按它做判断。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    /// 每一项都验证通过，且**至少声明了一项**。
    Ready,
    /// 没有任何一项判红，但**有项目没能验证**。
    ///
    /// 它与 [`Self::NotReady`] 同状态码（503，fail-closed），但**线上取值不同** ——
    /// 运维看 body 就知道这是"没能验证"而不是"确定坏了"，两者的处置完全不同：
    /// 前者去补证据，后者去修依赖。见模块文档〈`Unverified` 走 503〉。
    Unverified,
    /// 有项目判红，或**一项都没声明**。
    NotReady,
}

impl ReadinessStatus {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unverified => "unverified",
            Self::NotReady => "not_ready",
        }
    }

    /// 对应的 HTTP 状态码。
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Ready => 200,
            // `Unverified` 与 `NotReady` 同码是**有意的**（2026-08-22 裁决，见模块文档
            // 的代价论证）：repository contract §5 条 3「空 / 坏 / 未知 fail-closed」，而未验证
            // 就是未知。三态的**区分**因此全部落在 `as_str()` 与 `warn!` 上。
            Self::Unverified | Self::NotReady => 503,
        }
    }
}

/// 依 fail-closed 优先级聚合：`NotReady` > `Unverified` > `Ready`。
///
/// 顺序是判据不是偏好 —— 一项红加一项未验证必须是红，反过来则会让一次确定的不兼容
/// 被一次"没验证"盖过去。零项直接 [`ReadinessStatus::NotReady`]，理由见模块文档。
#[must_use]
pub fn aggregate(verdicts: impl IntoIterator<Item = ReadinessVerdict>) -> ReadinessStatus {
    let mut seen_any = false;
    let mut seen_unverified = false;
    for verdict in verdicts {
        seen_any = true;
        match verdict {
            ReadinessVerdict::NotReady => return ReadinessStatus::NotReady,
            ReadinessVerdict::Unverified => seen_unverified = true,
            ReadinessVerdict::Ready => {}
        }
    }
    if !seen_any {
        return ReadinessStatus::NotReady;
    }
    if seen_unverified {
        ReadinessStatus::Unverified
    } else {
        ReadinessStatus::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_probe_at_all_is_not_ready() {
        assert_eq!(aggregate(Vec::new()), ReadinessStatus::NotReady);
        // 正向对照：同一个函数在**有**一项通过时确实给 Ready ——
        // 否则上一条在"aggregate 恒 NotReady"的世界里同样通过。
        assert_eq!(aggregate([ReadinessVerdict::Ready]), ReadinessStatus::Ready);
    }

    /// fail-closed 优先级：红压过未验证，未验证压过通过。
    #[test]
    fn not_ready_dominates_unverified_which_dominates_ready() {
        assert_eq!(
            aggregate([ReadinessVerdict::Ready, ReadinessVerdict::Unverified]),
            ReadinessStatus::Unverified
        );
        assert_eq!(
            aggregate([ReadinessVerdict::Unverified, ReadinessVerdict::NotReady]),
            ReadinessStatus::NotReady
        );
        assert_eq!(
            aggregate([ReadinessVerdict::NotReady, ReadinessVerdict::Unverified]),
            ReadinessStatus::NotReady
        );
        assert_eq!(
            aggregate([ReadinessVerdict::Ready, ReadinessVerdict::Ready]),
            ReadinessStatus::Ready
        );
    }

    /// 三个状态的**线上取值**两两不同。
    ///
    /// 刻意不比状态码：`Unverified` 与 `NotReady` 同为 503（2026-08-22 裁决），所以
    /// 「三态可分」这件事的唯一承载面就是 `as_str()`。这条是"`Unverified` 没被折叠成
    /// 别的东西"的最小机械判据：只要有人把它的 `as_str` 改成 `"ready"` 或 `"not_ready"`、
    /// 或者把 enum 合成两态，这里当场红。
    #[test]
    fn three_statuses_are_pairwise_distinct_on_the_wire() {
        let all = [
            ReadinessStatus::Ready,
            ReadinessStatus::Unverified,
            ReadinessStatus::NotReady,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str(), "线上取值撞了");
            }
        }
        assert_eq!(ReadinessStatus::Ready.as_str(), "ready");
        assert_eq!(ReadinessStatus::Unverified.as_str(), "unverified");
        assert_eq!(ReadinessStatus::NotReady.as_str(), "not_ready");
    }

    /// `Unverified` fail-closed 到 503（2026-08-22 裁决），但仍**不等于**"确定坏了"。
    ///
    /// 状态码不再区分这两态，所以区分必须落在线上取值上 —— 这条把那个位移钉住：
    /// 谁把 `as_str` 合并掉（让 `unverified` 与 `not_ready` 同名），这里当场红。
    #[test]
    fn unverified_fails_closed_yet_stays_distinguishable_from_a_hard_failure() {
        assert_eq!(
            ReadinessStatus::Unverified.http_status(),
            503,
            "未知即 fail-closed（repository contract §5 条 3）"
        );
        assert_eq!(ReadinessStatus::NotReady.http_status(), 503);
        // 同码，但两态在 body 里必须分得开。
        assert_ne!(
            ReadinessStatus::Unverified.as_str(),
            ReadinessStatus::NotReady.as_str()
        );
        assert_ne!(
            ReadinessStatus::Unverified.as_str(),
            ReadinessStatus::Ready.as_str()
        );
        // 正向对照：唯一一个真正声称"能接流量"的状态确实是 200，
        // 否则本条在"所有状态都是 503"的世界里同样通过。
        assert_eq!(ReadinessStatus::Ready.http_status(), 200);
    }

    #[tokio::test]
    async fn fn_probe_forwards_all_three_verdicts() {
        for expected in [
            ReadinessVerdict::Ready,
            ReadinessVerdict::NotReady,
            ReadinessVerdict::Unverified,
        ] {
            let probe =
                FnReadinessProbe::new(MIGRATION_LEDGER_DEPENDENCY, move || async move { expected });
            assert_eq!(probe.dependency(), MIGRATION_LEDGER_DEPENDENCY);
            assert_eq!(probe.check().await, expected);
        }
    }
}
