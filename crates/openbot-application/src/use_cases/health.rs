//! `Health` 用例 —— 最小只读用例：一个 `execute` 应答 + 一条 `subscribe` 心跳流。
//!
//! 它在 G1 的作用不是"探活"这个功能本身，而是**证明两个入口都通了**：`execute` 与
//! `subscribe` 各自有一条不依赖任何 port 的路径，于是「transport 接错了」与「数据库没起来」
//! 在排障时是两个可分辨的事实。

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use futures_core::Stream;
use openbot_contracts::command::{AppEvent, HealthReport};
use tokio::time::{Interval, MissedTickBehavior, interval};

use crate::service::AppEventStream;

/// 心跳默认间隔。
///
/// 30 秒是**新增**取值不是 parity：上游没有 `SubscriptionRequest::Health` 这条链路
/// （`AppEvent` 与订阅面整体是本次重写引入的 typed 边界）。定这个数的依据是它要同时满足
/// 两件事：比常见的反向代理空闲超时（60 s）短，以免流被中间设备掐断；又不至于密到让
/// 一条静默连接产生可观的流量。真要改它是一次产品决定，需要 ledger 条目。
pub const DEFAULT_HEARTBEAT_PERIOD: Duration = Duration::from_secs(30);

/// 探活应答。
///
/// # 它回答的是哪个问题
///
/// `ok: true` 的含义精确到一句话：**这个进程接下了一条 typed 命令并跑完了一个 use case**。
/// 它**不**代表数据库、vault、browser engine 可用 —— 那是 readiness，属于
/// `openbot-server` 的 `/readyz` 与 §16.4 的 metrics。
///
/// 这个区分是刻意的，也是 contracts 里 [`HealthReport`] 只有一个布尔的理由：把依赖明细
/// 放进公开应答会顺带泄漏部署拓扑。反过来说，本函数**永远不会返回 `ok: false`** ——
/// 一个能返回 false 的探活意味着进程还活着却自认不可服务，那种状态该由 readiness 表达，
/// 不该由一条已经成功执行的命令表达。由 `health_is_not_a_readiness_probe` 钉住。
#[must_use]
pub fn health() -> HealthReport {
    HealthReport { ok: true }
}

/// 心跳订阅流。
///
/// `seq` 从 0 开始单调递增，供 viewer 判断是否丢帧。
///
/// # 为什么不 spawn 任务
///
/// 见 [`AppEventStream`] 的类型文档：流自己就是生产者，调用方 drop 掉它工作立即停止。
/// 换成「spawn 一个任务往 channel 里塞」的写法，取消就变成一件要靠运行时纪律保证的事。
#[must_use]
pub fn health_stream(period: Duration) -> AppEventStream {
    Box::pin(HeartbeatStream::new(period))
}

/// [`health_stream`] 的流实现。
struct HeartbeatStream {
    interval: Interval,
    seq: u64,
}

impl HeartbeatStream {
    fn new(period: Duration) -> Self {
        // `tokio::time::interval` 对零周期是 panic 不是报错。一个订阅参数把服务打 panic
        // 是最坏的结果，所以这里取 1 ns 下限：语义上「尽可能快」，而调用方本来也不该
        // 传零。刻意不返回 Result —— 让每个 transport 去处理一条它永远不该构造出来的
        // 错误分支，只会得到一堆各自不同的处理方式。
        let period = period.max(Duration::from_nanos(1));
        let mut interval = interval(period);
        // 默认的 `Burst` 会在消费者慢下来之后一次性补发全部欠下的 tick。心跳要的是
        // 「现在还活着」，不是把过去补齐 —— 补发只会在链路刚恢复时再压一波流量上去。
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self { interval, seq: 0 }
    }
}

impl Stream for HeartbeatStream {
    type Item = AppEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.interval.poll_tick(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                let seq = self.seq;
                // 饱和而不是回绕：回绕会让 seq 重新变成 0，而 viewer 判丢帧靠的正是
                // 「seq 只增不减」。饱和的最坏结果是停在 MAX（viewer 看到不再前进），
                // 回绕的最坏结果是 viewer 认为自己丢了 2^64 帧。
                // 到顶需要以 30 s 一拍连续跑约 1.75e13 年，实践中不可达。
                self.seq = self.seq.saturating_add(1);
                Poll::Ready(Some(AppEvent::Heartbeat { seq }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 探活不是 readiness：它只报告「命令跑通了」。
    ///
    /// 正向对照：`HealthReport` 这个类型**能**表达 false —— 所以本条断言不是在
    /// 「这个字段只有一种取值」的世界里成立的。
    #[test]
    fn health_is_not_a_readiness_probe() {
        assert!(health().ok);
        assert!(!HealthReport { ok: false }.ok);
    }

    /// 心跳流首拍立即到达，且 `seq` 从 0 单调递增。
    ///
    /// 用 1 ms 周期而不是默认的 30 s：这里没有任何「必须在 X 毫秒内完成」的上界断言，
    /// 所以它不是一条与时钟赛跑的测试 —— 慢机器上只是多等几毫秒，不会翻。
    #[test]
    fn heartbeat_stream_is_monotonic_from_zero() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("构建当前线程运行时");
        runtime.block_on(async {
            let mut stream = health_stream(Duration::from_millis(1));
            let mut seen = Vec::new();
            for _ in 0..3 {
                seen.push(next(&mut stream).await);
            }
            assert_eq!(
                seen,
                vec![
                    AppEvent::Heartbeat { seq: 0 },
                    AppEvent::Heartbeat { seq: 1 },
                    AppEvent::Heartbeat { seq: 2 },
                ]
            );
        });
    }

    /// 零周期不 panic —— 见 [`HeartbeatStream::new`] 的下限说明。
    #[test]
    fn zero_period_is_clamped_instead_of_panicking() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("构建当前线程运行时");
        runtime.block_on(async {
            let mut stream = health_stream(Duration::ZERO);
            assert_eq!(next(&mut stream).await, AppEvent::Heartbeat { seq: 0 });
        });
    }

    /// 从流里取下一项。
    ///
    /// 手写而不是用 `futures::StreamExt::next`：本 crate 只依赖 `futures-core`
    /// （`Stream` trait 本身），把整个 `futures-util` 拉进来只为一个测试辅助函数不划算。
    async fn next(stream: &mut AppEventStream) -> AppEvent {
        core::future::poll_fn(|cx| stream.as_mut().poll_next(cx))
            .await
            .expect("心跳流是无限流，不会终止")
    }
}
