//! 公共传输的安全档位 —— session cookie 的 `Secure` 属性由它单点决定（v3 §6.3）。
//!
//! # 判据只有一条：`OPENBOT_PUBLIC_URL` 是不是 `https`
//!
//! v3 §6.3 逐字：「`Secure` 当且仅当 `OPENBOT_PUBLIC_URL` 是 `https` 时设置」。**不另设开关。**
//!
//! 不设开关这件事本身是裁决，理由是"开关"在这里必然是错的：
//!
//! - 一个允许"明文也强制 `Secure`"的开关，会造出一个**浏览器根本不会回传**的 cookie ——
//!   症状是"登录之后又回到登录页"，而配置看起来完全正确。上游 CHANGELOG 修过的
//!   「plain HTTP 真实地址上无法开始会话」正是这个形态。
//! - 一个允许"HTTPS 下不加 `Secure`"的开关，是把一个纯粹的降级做成了可配置项。
//!
//! 于是 `Secure` 不是策略，是**对当前 scheme 的事实陈述**。
//!
//! # 非 loopback 的明文部署：仍可登录，但会被点名
//!
//! 同样出自 §6.3：上游 `repository contract` 写的是"把 TLS 放在前面"而不是"拒绝 HTTP"，
//! 所以这里**不拒绝启动**。代价用另外两件事兑现：启动日志告警，以及 `/health` readiness
//! 附带 `insecure_transport: true`。
//!
//! 这两件事都不是可选的 —— 一个既不加 `Secure`、又什么都不说的部署，
//! 在运维看来与一个 HTTPS 部署逐字节相同。
//!
//! # 为什么是四态而不是布尔
//!
//! "要不要加 `Secure`"和"要不要点亮 `insecure_transport`"是**两个不同的问题**，
//! 它们的答案在 loopback 明文这一档上分叉：不加 `Secure`（浏览器不会回传），
//! 但也不点亮告警（本机开发是正常形态，把它点亮等于训练所有人忽略这盏灯）。
//!
//! 把它压成一个布尔，必然有一档被折进另一档 —— 而被折掉的那一档就是"真实暴露的明文部署"
//! 与"开发机"分不开的那一刻。
//!
//! | 档位 | `Secure` | `insecure_transport` | 启动告警 |
//! | --- | --- | --- | --- |
//! | [`PublicTransport::Https`] | ✅ | ❌ | 无 |
//! | [`PublicTransport::LoopbackHttp`] | ❌ | ❌ | 无 |
//! | [`PublicTransport::PublicHttp`] | ❌ | ✅ | 有 |
//! | [`PublicTransport::Unconfigured`] | ❌ | ❌ | 有 |
//!
//! # `Unconfigured` 为什么不点亮 `insecure_transport`
//!
//! 没配公共地址的部署，就是 v3 §6.1 那个"无 IdP + `OPENBOT_SINGLE_USER=true`"的本机形态，
//! 而那一档的暴露面由**绑定地址**管住（`openbot_infra::auth::config::single_user_binding_verdict`），
//! 不由这里管。`insecure_transport` 说的是"有人的 session cookie 正在网络上裸奔"，
//! 而这一档我们并不知道有没有网络 —— 把"不知道"渲染成"有问题"，与渲染成"没问题"
//! 一样是在编造。所以它走**告警**（说出"你没配公共地址"这个事实），不走那面旗。
//!
//! 这一档仍然要有话说，因此 [`PublicTransport::startup_warning`] 对它返回 `Some`。

use crate::config::address::{DeploymentAddress, Scheme};

/// 这个部署的公共传输长什么样。四态，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicTransport {
    /// `OPENBOT_PUBLIC_URL` 是 `https`。
    Https,
    /// `OPENBOT_PUBLIC_URL` 是 `http`，且 host 只能从本机到达。
    LoopbackHttp,
    /// `OPENBOT_PUBLIC_URL` 是 `http`，host 不是 loopback。**明文会话正在网络上跑。**
    PublicHttp,
    /// 没有配 `OPENBOT_PUBLIC_URL`。
    Unconfigured,
}

impl PublicTransport {
    /// 由公共地址判定档位。**纯函数**，除入参外不看任何东西。
    #[must_use]
    pub fn classify(public_url: Option<&DeploymentAddress>) -> Self {
        match public_url {
            None => Self::Unconfigured,
            Some(address) => match address.scheme() {
                Scheme::Https => Self::Https,
                Scheme::Http if address.is_loopback() => Self::LoopbackHttp,
                Scheme::Http => Self::PublicHttp,
            },
        }
    }

    /// session cookie 要不要带 `Secure`。
    ///
    /// **只有 [`PublicTransport::Https`] 为真** —— 在别的档位上加 `Secure`，
    /// 得到的是一个浏览器不肯回传的 cookie，症状是登录后回到登录页。
    #[must_use]
    pub const fn cookie_secure(self) -> bool {
        matches!(self, Self::Https)
    }

    /// `/health` readiness 要不要附 `insecure_transport: true`（v3 §6.3）。
    #[must_use]
    pub const fn insecure_transport(self) -> bool {
        matches!(self, Self::PublicHttp)
    }

    /// 启动日志要不要说点什么，以及说什么。
    ///
    /// 返回 `&'static str` 而不是拼好的串：文案里不能出现任何配置值
    /// （理由同 [`crate::config::error`] 模块文档 —— 它会进日志）。
    #[must_use]
    pub const fn startup_warning(self) -> Option<&'static str> {
        match self {
            Self::Https | Self::LoopbackHttp => None,
            Self::PublicHttp => Some(
                "OPENBOT_PUBLIC_URL 是明文 http 且不是 loopback：session cookie 不会带 Secure，\
                 会话凭据将以明文经过网络。请在前面放 TLS。",
            ),
            Self::Unconfigured => Some(
                "未配置 OPENBOT_PUBLIC_URL：本部署没有对外公共地址，OAuth 回调与连接器授权\
                 无法生成 redirect URI。若这是本机单用户部署，请确认绑定在 loopback 上。",
            ),
        }
    }

    /// 稳定的线上取值，供 readiness 响应体与日志使用。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::LoopbackHttp => "loopback_http",
            Self::PublicHttp => "public_http",
            Self::Unconfigured => "unconfigured",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(raw: &str) -> DeploymentAddress {
        DeploymentAddress::parse(raw).expect("测试地址必须合法")
    }

    /// 任务点名的三种情形：https / loopback http / 非 loopback http。
    ///
    /// 三条一起断言，因为它们互为对照：任何一个"恒返回同一档"的实现都会在这里红。
    #[test]
    fn the_three_shapes_land_in_three_different_places() {
        assert_eq!(
            PublicTransport::classify(Some(&address("https://openbot.example.com"))),
            PublicTransport::Https
        );
        assert_eq!(
            PublicTransport::classify(Some(&address("http://localhost:3001"))),
            PublicTransport::LoopbackHttp
        );
        assert_eq!(
            PublicTransport::classify(Some(&address("http://openbot.example.com"))),
            PublicTransport::PublicHttp
        );
        // 第四档：没配。
        assert_eq!(
            PublicTransport::classify(None),
            PublicTransport::Unconfigured
        );
    }

    /// `Secure` 当且仅当 https。
    #[test]
    fn secure_is_set_exactly_when_the_scheme_is_https() {
        assert!(PublicTransport::Https.cookie_secure());
        // 负向：其余三档都不加 —— 加了就是一个浏览器不肯回传的 cookie。
        assert!(!PublicTransport::LoopbackHttp.cookie_secure());
        assert!(!PublicTransport::PublicHttp.cookie_secure());
        assert!(!PublicTransport::Unconfigured.cookie_secure());
    }

    /// `insecure_transport` 只在"真实暴露的明文"那一档点亮。
    #[test]
    fn only_a_genuinely_exposed_plaintext_deployment_raises_the_flag() {
        assert!(PublicTransport::PublicHttp.insecure_transport());
        // 负向对照三条。loopback 那条是本组的重点：把它也点亮，
        // 这盏灯就会在每台开发机上常亮，从而在真出事那天没人看。
        assert!(!PublicTransport::Https.insecure_transport());
        assert!(!PublicTransport::LoopbackHttp.insecure_transport());
        assert!(!PublicTransport::Unconfigured.insecure_transport());
    }

    /// 两档有话说，两档没有 —— 且说的话里不含任何配置值。
    #[test]
    fn warnings_exist_exactly_where_they_are_earned() {
        assert!(PublicTransport::Https.startup_warning().is_none());
        assert!(PublicTransport::LoopbackHttp.startup_warning().is_none());

        let exposed = PublicTransport::PublicHttp
            .startup_warning()
            .expect("暴露的明文部署必须被点名");
        assert!(exposed.contains("Secure"), "{exposed}");

        let unconfigured = PublicTransport::Unconfigured
            .startup_warning()
            .expect("没配公共地址也要说出来");
        assert!(
            unconfigured.contains("OPENBOT_PUBLIC_URL"),
            "{unconfigured}"
        );
    }

    /// 四个线上取值两两不同 —— 折叠掉任何一档，这里当场红。
    #[test]
    fn four_states_are_pairwise_distinct_on_the_wire() {
        let all = [
            PublicTransport::Https,
            PublicTransport::LoopbackHttp,
            PublicTransport::PublicHttp,
            PublicTransport::Unconfigured,
        ];
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                assert_ne!(left.as_str(), right.as_str(), "线上取值撞了");
            }
        }
    }

    /// 两个问题确实是两个问题：存在一档 `Secure` 与 `insecure_transport` **同时为假**。
    ///
    /// 这条把"能不能压成布尔"钉死：如果能，那么 `insecure = !secure` 恒成立，
    /// 而 loopback 明文这一档正是反例。
    #[test]
    fn the_two_questions_cannot_be_collapsed_into_one_boolean() {
        let loopback = PublicTransport::LoopbackHttp;
        assert!(!loopback.cookie_secure());
        assert!(!loopback.insecure_transport());
        // 正向对照：确实存在一档两者相反，否则上一条在"两个函数恒返回 false"
        // 的世界里同样通过。
        assert!(PublicTransport::Https.cookie_secure());
        assert!(PublicTransport::PublicHttp.insecure_transport());
    }
}
