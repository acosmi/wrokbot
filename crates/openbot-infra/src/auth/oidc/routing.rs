//! email domain routing 与它的**统一响应**（v3 §6.2 条 2 + 末段）。
//!
//! # 「统一响应」被做成类型上跑不掉的东西
//!
//! §6.2 末段：「email routing 的成功/失败使用统一响应并按 IP/email hash 限速，避免组织枚举
//! 和 callback flood」。把它写成一条纪律（「记得两个分支返回同样的东西」）是没有用的：
//! 那正是 review 最容易放过、重构最容易破坏的一类约束。
//!
//! 这里的构造是：离开服务端的那个类型 [`UniformRoutingResponse`] 是一个**零大小类型**。
//! 它没有字段，因此**装不下任何一个比特**，成功与失败在它上面不可区分不是因为两处都写对了，
//! 而是因为没有地方可以写错。由 `the_uniform_response_is_a_zero_sized_type` 用
//! `size_of` 实测钉住（配一条正向对照，证明这不是「所有类型都是零大小」）。
//!
//! 服务端自己要用的判定放在 [`EmailRoutingOutcome::next_provider`]，它与响应是两个字段，
//! 不是同一个值的两种视图。
//!
//! # 限速在分支之前，计数在两条分支上完全一致
//!
//! 限速判定跑在「查得到 / 查不到」之前，并且**无论查得到与否都推进同一个计数**。
//! 这条比它看起来重要：如果只对未命中计数，那么**计数器本身就是那个 oracle** ——
//! 攻击者只要观察限速什么时候开始生效，就能区分「这个域名有企业 SSO」和「没有」。
//! 由 `the_counter_advances_identically_on_both_branches` 钉住。
//!
//! # 本模块解决不了的那一半
//!
//! 响应**内容**统一了，但真实部署里还有两条侧信道不在这一层：
//!
//! 1. **时序**。命中时要多做一次注册表查表，理论上可测。本模块不做常数时间处理（查表是
//!    `BTreeMap`，域名长度本身就影响耗时），这是已知非目标。
//! 2. **后续跳转**。一个「命中就 302 到 IdP、未命中就停在原页」的部署，会把这里精心统一的
//!    响应立刻再泄露一次。正确做法是两条分支都回同一个页面，跳转由后续一步凭不透明票据
//!    发起 —— 那是 transport / GUI 层的形态决定，本模块只能把它写在这里提醒。

use time::OffsetDateTime;

use super::email::domain_of;
use super::provider::{ProviderId, ProviderRegistry};
use super::ratelimit::{RateLimitCounter, RateLimitPolicy};

/// email routing 离开服务端时的**唯一**形状。
///
/// 零大小类型 —— 见模块文档。它刻意**没有**构造参数：想在里面塞一个「是否命中」的
/// 布尔值，得先改这个类型的定义，而那是一次会被 review 看见的改动。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UniformRoutingResponse;

impl UniformRoutingResponse {
    /// 稳定 code。命中、未命中、被限速三条路径**共用**这一个。
    ///
    /// 它不是错误码也不是文案，而是「这次 routing 请求已被受理」这一个事实的标识符；
    /// 本地化由 GUI 侧按 code 查表（v3 §4a / §15.3）。
    pub const CODE: &'static str = "oidc_routing_accepted";

    /// 稳定 code。
    #[must_use]
    pub const fn code(self) -> &'static str {
        Self::CODE
    }
}

/// 一次 email routing 的完整结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailRoutingOutcome {
    response: UniformRoutingResponse,
    next: Option<ProviderId>,
    counter: RateLimitCounter,
}

impl EmailRoutingOutcome {
    /// 能离开服务端的那一半。
    #[must_use]
    pub const fn response(&self) -> UniformRoutingResponse {
        self.response
    }

    /// 服务端接下来该拿哪个 provider 发起登录。
    ///
    /// `None` 覆盖三种互不区分的情形：email 不成形、域名没有对应 provider、这次被限速。
    /// **这个值绝不能出现在应答里**（出现了，上面那个零大小类型就白设计了）。
    #[must_use]
    pub const fn next_provider(&self) -> Option<&ProviderId> {
        self.next.as_ref()
    }

    /// 演进后的限速计数，调用方写回自己的表。
    #[must_use]
    pub const fn counter(&self) -> RateLimitCounter {
        self.counter
    }
}

/// 按 email 域名把一次登录路由到某个 provider。
///
/// 顺序是**先限速、后查表**：见模块文档里那条「计数器本身就是 oracle」的理由。
///
/// `prior` 是调用方按 IP / email 摘要分桶取出的上一次计数（没有就传 `None`）。
/// 本函数不知道也不需要知道分桶用的是什么 key —— 摘要与存储都在调用方
/// （见 [`super::ratelimit`] 的模块文档）。
#[must_use]
pub fn route_email(
    registry: &ProviderRegistry,
    email: &str,
    policy: RateLimitPolicy,
    prior: Option<RateLimitCounter>,
    now: OffsetDateTime,
) -> EmailRoutingOutcome {
    let decision = policy.evaluate(prior, now);

    let next = if decision.allowed() {
        domain_of(email)
            .and_then(|domain| registry.by_domain(&domain))
            .map(|config| config.id().clone())
    } else {
        None
    };

    EmailRoutingOutcome {
        response: UniformRoutingResponse,
        next,
        counter: decision.counter(),
    }
}

#[cfg(test)]
mod tests {
    use super::{EmailRoutingOutcome, UniformRoutingResponse, route_email};
    use crate::auth::oidc::provider::fixtures::three_providers;
    use crate::auth::oidc::provider::{ProviderId, ProviderRegistry};
    use crate::auth::oidc::ratelimit::{RateLimitCounter, RateLimitPolicy};
    use time::{Duration, OffsetDateTime};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn generous() -> RateLimitPolicy {
        RateLimitPolicy::new(100, Duration::minutes(1))
    }

    fn run(
        registry: &ProviderRegistry,
        email: &str,
        policy: RateLimitPolicy,
        prior: Option<RateLimitCounter>,
    ) -> EmailRoutingOutcome {
        route_email(registry, email, policy, prior, t0())
    }

    /// 统一响应是零大小类型：它装不下任何一个比特。
    ///
    /// 正向对照证明这不是「所有类型都是零大小」—— 一个真的能携带信息的类型不是零大小。
    #[test]
    fn the_uniform_response_is_a_zero_sized_type() {
        assert_eq!(
            core::mem::size_of::<UniformRoutingResponse>(),
            0,
            "统一响应一旦有字段，成功与失败就可以在它上面被区分"
        );
        assert!(
            core::mem::size_of::<Option<ProviderId>>() > 0,
            "正向对照：能携带信息的类型不是零大小"
        );
        assert!(core::mem::size_of::<bool>() > 0);
    }

    /// 命中、未命中、email 不成形、被限速 —— 四条路径的可观测输出逐字相同。
    #[test]
    fn every_routing_path_produces_the_same_observable_response() {
        let registry = three_providers();

        let matched = run(&registry, "someone@acme.example", generous(), None);
        let unmatched = run(&registry, "someone@nobody.example", generous(), None);
        let malformed = run(&registry, "not-an-email", generous(), None);
        let throttled = run(
            &registry,
            "someone@acme.example",
            RateLimitPolicy::new(0, Duration::minutes(1)),
            None,
        );

        let responses = [
            matched.response(),
            unmatched.response(),
            malformed.response(),
            throttled.response(),
        ];
        for response in responses {
            assert_eq!(response, responses[0]);
            assert_eq!(response.code(), UniformRoutingResponse::CODE);
        }

        // 服务端内部的判定确实有区别 —— 否则上面那条在「routing 压根没实现」的世界里
        // 同样通过。
        assert_eq!(
            matched.next_provider(),
            Some(&ProviderId::parse("okta").unwrap())
        );
        assert_eq!(unmatched.next_provider(), None);
        assert_eq!(malformed.next_provider(), None);
        assert_eq!(throttled.next_provider(), None);
    }

    /// 三家 provider 各自按自己的域名命中。
    #[test]
    fn each_configured_provider_is_reachable_by_its_own_domain() {
        let registry = three_providers();
        for (email, expected) in [
            ("someone@gmail.example", "google"),
            ("someone@contoso.example", "microsoft"),
            ("someone@acme.example", "okta"),
        ] {
            assert_eq!(
                run(&registry, email, generous(), None).next_provider(),
                Some(&ProviderId::parse(expected).unwrap()),
                "{email} 应当路由到 {expected}"
            );
        }
    }

    /// 域名比对大小写不敏感（`EmailDomain` 已规范化），但不接受相近写法。
    #[test]
    fn routing_is_case_insensitive_but_not_fuzzy() {
        let registry = three_providers();
        let okta = ProviderId::parse("okta").unwrap();

        assert_eq!(
            run(&registry, "Someone@ACME.Example", generous(), None).next_provider(),
            Some(&okta)
        );
        // 负向：子域、上级域、拼写相近的域名都不命中。
        for email in [
            "someone@sub.acme.example",
            "someone@example",
            "someone@acme.example.evil",
            "someone@acrne.example",
        ] {
            assert_eq!(
                run(&registry, email, generous(), None).next_provider(),
                None,
                "{email} 不该命中"
            );
        }
    }

    /// 被限速时即使域名命中也不放行 —— 限速器不可被「反正查得到」绕过。
    #[test]
    fn a_throttled_request_does_not_route_even_on_a_matching_domain() {
        let registry = three_providers();
        let policy = RateLimitPolicy::new(1, Duration::minutes(1));

        let first = run(&registry, "someone@acme.example", policy, None);
        assert!(
            first.next_provider().is_some(),
            "正向对照：额度内的同一封 email 是命中的"
        );

        let second = run(
            &registry,
            "someone@acme.example",
            policy,
            Some(first.counter()),
        );
        assert_eq!(second.next_provider(), None, "超限后不得继续路由");
        assert_eq!(second.response(), first.response());
    }

    /// 计数在「命中」与「未命中」两条分支上完全一致。
    ///
    /// 这是把「计数器本身」这条 oracle 关掉的判据：如果只对未命中计数，攻击者观察限速
    /// 何时开始生效就能区分两类域名。
    #[test]
    fn the_counter_advances_identically_on_both_branches() {
        let registry = three_providers();
        let policy = generous();

        let mut hit: Option<RateLimitCounter> = None;
        let mut miss: Option<RateLimitCounter> = None;
        for _ in 0..5 {
            let h = run(&registry, "someone@acme.example", policy, hit);
            let m = run(&registry, "someone@nobody.example", policy, miss);
            assert_eq!(
                h.counter(),
                m.counter(),
                "两条分支的计数必须逐字段相同，否则计数器就是 oracle"
            );
            hit = Some(h.counter());
            miss = Some(m.counter());
        }
        assert_eq!(hit.unwrap().count(), 5);

        // 不成形的 email 也走同一条计数路径 —— 否则它就是第三种可被区分的输入。
        let malformed = run(&registry, "garbage", policy, hit);
        let matched = run(&registry, "someone@acme.example", policy, hit);
        assert_eq!(malformed.counter(), matched.counter());
    }

    /// 空注册表下每封 email 的结果都一样，且仍然计数。
    #[test]
    fn an_empty_registry_still_answers_uniformly_and_still_counts() {
        let empty = ProviderRegistry::default();
        assert!(empty.is_empty());

        let a = run(&empty, "someone@acme.example", generous(), None);
        let b = run(&empty, "someone@nobody.example", generous(), None);
        assert_eq!(a.response(), b.response());
        assert_eq!(a.next_provider(), None);
        assert_eq!(b.next_provider(), None);
        assert_eq!(a.counter().count(), 1);
    }
}
