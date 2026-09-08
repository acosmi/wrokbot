//! 限速**判定**（v3 §6.2 末段「按 IP/email hash 限速，避免组织枚举和 callback flood」）。
//!
//! # 这里只有判定，没有存储
//!
//! [`RateLimitPolicy::evaluate`] 是纯函数：给定「上一次的计数状态」「策略」「此刻」，
//! 回答放不放行以及新的计数状态。**计数存在哪、按什么 key 分桶、多久淘汰，都不在这里** ——
//! 那是一张有淘汰策略、可能跨进程共享的表，属于调用方。
//!
//! 这条切分不是洁癖：把存储也塞进来，这个模块就需要一个时钟、一把锁和一个后台清扫器，
//! 而它现在**一个都不需要**，于是它的每条测试都是确定性的。
//!
//! # key 的哈希也不在这里
//!
//! §6.2 说的是「IP / email **hash**」。本模块不选哈希算法也不做哈希：`openbot-infra` 的
//! 这一层没有 crypto 依赖，而「用哪种摘要、加不加盐」是与 vault 同级的部署决定。调用方
//! 拿摘要当 key 去查它自己的表，查出来的 [`RateLimitCounter`] 才进这里。
//!
//! # 固定窗口，以及它已知的那条弱点
//!
//! 实现是固定窗口计数器。它有一条众所周知的性质：**跨窗口边界可以在瞬间放行 2×N 次**
//! （上一窗口末尾 N 次 + 新窗口开头 N 次）。这里接受它，理由是本限速面要挡的是
//! 「逐个域名枚举一个组织的 SSO 配置」与「回调洪水」，两者都以分钟计、以量取胜，
//! 2× 的瞬时突发不改变结论；而滑动窗口要么多存一圈时间戳（把存储面变复杂），要么引入
//! 浮点衰减（把判定变成不易复算的东西）。
//!
//! **把它写下来是因为它是一次选择而不是疏忽** —— 由
//! `the_fixed_window_boundary_burst_is_a_known_and_measured_property` 实测钉住，将来谁要
//! 改成滑动窗口，那条测试会告诉他改动确实生效了。

use time::{Duration, OffsetDateTime};

/// 一个分桶的计数状态。由调用方持久化，由 [`RateLimitPolicy::evaluate`] 演进。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitCounter {
    window_started_at: OffsetDateTime,
    count: u32,
}

impl RateLimitCounter {
    /// PostgreSQL adapter 从自己写下的两字段状态水合；不接受自由 JSON 穿越 crate 边界。
    #[must_use]
    pub(crate) const fn restore(window_started_at: OffsetDateTime, count: u32) -> Self {
        Self {
            window_started_at,
            count,
        }
    }

    /// 当前窗口的起点。
    #[must_use]
    pub const fn window_started_at(&self) -> OffsetDateTime {
        self.window_started_at
    }

    /// 当前窗口内已计入的次数（**含**被拒的那些）。
    ///
    /// 被拒也计数是刻意的：不计数的话，一个已经超限的调用方可以无限次敲门而窗口永不
    /// 推进 —— 限速器变成了一个只在「刚好没超限」时才生效的东西。
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }
}

/// 一次判定的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    allowed: bool,
    counter: RateLimitCounter,
}

impl RateLimitDecision {
    /// 这次是否放行。
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    /// 演进后的计数状态。调用方必须把它写回自己的表，否则限速器不前进。
    #[must_use]
    pub const fn counter(&self) -> RateLimitCounter {
        self.counter
    }
}

/// 限速策略：一个窗口内最多几次。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitPolicy {
    max_per_window: u32,
    window: Duration,
}

impl RateLimitPolicy {
    /// 建一条策略。
    ///
    /// `max_per_window == 0` 表示**全拒**，这是一个合法且有用的取值（把某条通道临时关死），
    /// 不当成配置错误。窗口为零或负时同样全拒 —— 见 [`Self::evaluate`] 里的理由。
    #[must_use]
    pub const fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
        }
    }

    /// 窗口内额度。
    #[must_use]
    pub const fn max_per_window(&self) -> u32 {
        self.max_per_window
    }

    /// 窗口长度。
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// 判定这一次放不放行，并给出演进后的计数。
    ///
    /// `prior` 为 `None` 表示这个桶此前没有记录（新 key，或已被调用方淘汰）。
    ///
    /// # 时间倒流按「开新窗口」处理
    ///
    /// `now < prior.window_started_at` 时（时钟回拨、多机时钟不齐、调用方传错）本函数
    /// 开一个新窗口，而不是把差值当成 0 继续用旧计数。理由是另一条选择更糟：沿用旧窗口
    /// 会让一次时钟回拨把额度**永久**冻结在已用满的状态上。开新窗口最多多放行一个窗口的量，
    /// 是两害相权里可恢复的那一个。
    ///
    /// 窗口长度非正时恒拒：那意味着「每 0 秒最多 N 次」，没有任何有意义的放行语义，
    /// 按 repository contract §5 条 3「空 / 坏 / 未知 fail-closed」处理。
    #[must_use]
    pub fn evaluate(
        &self,
        prior: Option<RateLimitCounter>,
        now: OffsetDateTime,
    ) -> RateLimitDecision {
        if self.window <= Duration::ZERO {
            return RateLimitDecision {
                allowed: false,
                counter: RateLimitCounter {
                    window_started_at: now,
                    count: self.max_per_window.saturating_add(1),
                },
            };
        }

        let same_window = prior.filter(|prior| {
            now >= prior.window_started_at && now - prior.window_started_at < self.window
        });

        let (window_started_at, used) = match same_window {
            Some(prior) => (prior.window_started_at, prior.count),
            None => (now, 0),
        };

        let count = used.saturating_add(1);
        RateLimitDecision {
            allowed: count <= self.max_per_window,
            counter: RateLimitCounter {
                window_started_at,
                count,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitCounter, RateLimitPolicy};
    use time::{Duration, OffsetDateTime};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn policy() -> RateLimitPolicy {
        RateLimitPolicy::new(3, Duration::minutes(1))
    }

    /// 正向 + 负向：额度内放行，超出即拒。
    #[test]
    fn requests_inside_the_budget_pass_and_the_next_one_does_not() {
        let policy = policy();
        let mut counter: Option<RateLimitCounter> = None;

        for expected_count in 1..=3 {
            let decision = policy.evaluate(counter, t0());
            assert!(decision.allowed(), "第 {expected_count} 次应当放行");
            assert_eq!(decision.counter().count(), expected_count);
            counter = Some(decision.counter());
        }

        let denied = policy.evaluate(counter, t0());
        assert!(!denied.allowed(), "第 4 次应当被拒");
        assert_eq!(denied.counter().count(), 4, "被拒也要计数");
    }

    /// 被拒的请求继续推高计数 —— 否则超限方可以无限敲门而窗口永不推进。
    #[test]
    fn denied_requests_still_advance_the_counter() {
        let policy = RateLimitPolicy::new(1, Duration::minutes(1));
        let first = policy.evaluate(None, t0());
        assert!(first.allowed());

        let mut counter = first.counter();
        for expected in 2..=5 {
            let decision = policy.evaluate(Some(counter), t0());
            assert!(!decision.allowed());
            assert_eq!(decision.counter().count(), expected);
            counter = decision.counter();
        }
    }

    /// 窗口滚过之后额度恢复，窗口起点也跟着推进。
    #[test]
    fn a_new_window_restores_the_budget() {
        let policy = policy();
        let exhausted = RateLimitCounter {
            window_started_at: t0(),
            count: 99,
        };

        // 负向：窗口内仍然拒。
        assert!(
            !policy
                .evaluate(Some(exhausted), t0() + Duration::seconds(59))
                .allowed()
        );

        // 正向：正好一个窗口之后放行，并且开了新窗口。
        let renewed = policy.evaluate(Some(exhausted), t0() + Duration::seconds(60));
        assert!(renewed.allowed());
        assert_eq!(renewed.counter().count(), 1);
        assert_eq!(
            renewed.counter().window_started_at(),
            t0() + Duration::seconds(60)
        );
    }

    /// 固定窗口边界上的 2×N 突发：一条**已知**性质的实测记录。
    ///
    /// 顺带钉住另一条容易想当然的性质：**窗口锚在本窗口的第一次请求上，不是墙钟网格上**。
    /// 本测试第一版就栽在这里 —— 从 `None` 起步、在 `t0+59s` 发第一次请求，窗口是从
    /// `t0+59s` 才开始算的，`t0+60s` 根本没跨过边界。
    #[test]
    fn the_fixed_window_boundary_burst_is_a_known_and_measured_property() {
        let policy = policy();

        // 窗口在 t0 开启（**锚在第一次请求上，不是墙钟网格**），末尾 59 秒处用满 3 次。
        let mut counter = Some(RateLimitCounter {
            window_started_at: t0(),
            count: 0,
        });
        let late = t0() + Duration::seconds(59);
        for _ in 0..3 {
            let d = policy.evaluate(counter, late);
            assert!(d.allowed());
            counter = Some(d.counter());
        }
        assert_eq!(
            counter.unwrap().window_started_at(),
            t0(),
            "窗口起点不随窗口内的请求推进"
        );

        // 跨过边界后立刻又能用 3 次 —— 一秒内合计 6 次。
        let mut allowed_after_boundary = 0;
        let just_after = t0() + Duration::seconds(60);
        for _ in 0..3 {
            let d = policy.evaluate(counter, just_after);
            if d.allowed() {
                allowed_after_boundary += 1;
            }
            counter = Some(d.counter());
        }
        assert_eq!(
            allowed_after_boundary, 3,
            "固定窗口在边界上确实允许 2×N —— 换成滑动窗口时这条会变"
        );

        // 正向对照：第 7 次仍然被拒，说明限速器本身是生效的。
        assert!(!policy.evaluate(counter, just_after).allowed());
    }

    /// 时钟回拨开新窗口，不把额度永久冻死。
    #[test]
    fn a_backwards_clock_opens_a_new_window_instead_of_freezing_the_budget() {
        let policy = policy();
        let exhausted = RateLimitCounter {
            window_started_at: t0(),
            count: 99,
        };

        let rewound = policy.evaluate(Some(exhausted), t0() - Duration::hours(1));
        assert!(rewound.allowed(), "时钟回拨不该把额度永久冻结");
        assert_eq!(rewound.counter().count(), 1);
        assert_eq!(
            rewound.counter().window_started_at(),
            t0() - Duration::hours(1)
        );
    }

    /// 退化配置 fail-closed，且**只有**退化配置才恒拒。
    #[test]
    fn degenerate_policies_fail_closed() {
        // 零额度：全拒。
        let zero = RateLimitPolicy::new(0, Duration::minutes(1));
        assert!(!zero.evaluate(None, t0()).allowed());

        // 零窗口 / 负窗口：全拒。
        assert!(
            !RateLimitPolicy::new(10, Duration::ZERO)
                .evaluate(None, t0())
                .allowed()
        );
        assert!(
            !RateLimitPolicy::new(10, Duration::seconds(-1))
                .evaluate(None, t0())
                .allowed()
        );

        // 正向对照：正常配置照常放行 —— 否则以上三条在「恒拒」的世界里同样通过。
        assert!(
            RateLimitPolicy::new(10, Duration::minutes(1))
                .evaluate(None, t0())
                .allowed()
        );
    }

    /// 计数溢出不回绕成「又有额度了」。
    #[test]
    fn the_counter_saturates_instead_of_wrapping() {
        let policy = policy();
        let maxed = RateLimitCounter {
            window_started_at: t0(),
            count: u32::MAX,
        };
        let decision = policy.evaluate(Some(maxed), t0());
        assert!(!decision.allowed());
        assert_eq!(decision.counter().count(), u32::MAX);
    }
}
