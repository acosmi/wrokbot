//! 部署地址 —— 一个**只回答两个问题**的窄 URL 类型。
//!
//! 那两个问题是：
//!
//! 1. scheme 是不是 `https`（v3 §6.3：session cookie 的 `Secure` 属性当且仅当它是）；
//! 2. host 是不是 loopback（同上：非 loopback 的 plain HTTP 才需要告警与
//!    `insecure_transport: true`）。
//!
//! # 为什么不引第三方 URL 解析器
//!
//! `openbot-server` 的 `Cargo.toml` 里没有 `url`，而依赖清单不在本轮的可动文件里。
//! 兄弟 crate `openbot-infra` 有 `url`（OIDC 那条链路需要真正的 WHATWG 解析器），
//! 所以 `OKTA_OAUTH_ISSUER` 那种"必须和上游 `new URL()` 逐字符同判"的地方在那边用真解析器。
//! 这里要回答的两个问题窄到不需要它，硬拉一个依赖进来只会多一条供应链条目。
//!
//! **这不是"两份 URL 解析实现"** —— 两边解析的是不同变量、回答的是不同问题。真要统一，
//! 正确做法是给本 crate 的清单加 `url`，那是集成层的一次显式决定。
//!
//! # 与上游的**已知偏差**，交付时请一并看
//!
//! | 变量 | 上游 | 这里 | 为什么 |
//! | --- | --- | --- | --- |
//! | `OPENBOT_PUBLIC_URL` | `optional()`，**完全不校验** | 必须是绝对 `http`/`https` URL | 它现在要回答"cookie 要不要 `Secure`"（v3 §6.3）。一个解析不了的值回答不了这个问题，而 fail-closed 的方向是拒绝启动，不是"当作不安全"—— 后者会让一个写错了的 `https` 地址静默降级成明文会话 |
//! | `AGENT_COMPUTER_URL` / `COMPUTER_SUPERVISOR_URL` | `new URL()`，任意 scheme | 只收 `http`/`https` | 它们是 HTTP 客户端的 base URL；`ftp://` 能通过上游那一关，然后在第一次请求时才炸 |
//!
//! 两条都写进交付报告，判据以上游实测为准、偏差以本文档为准。

use core::fmt;

use openbot_domain::text::trim_ecmascript;

/// 地址的 scheme。**只有两个**，因为本类型只服务 HTTP(S) 端点。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    /// 明文。
    Http,
    /// TLS。**这是 `Secure` cookie 的唯一判据**（v3 §6.3）。
    Https,
}

impl Scheme {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// 地址解析失败的形态。
///
/// 只有一个变体，因为调用方对这三种情形的反应完全相同（报一条
/// [`crate::config::error::Expectation::AbsoluteHttpUrl`]）。分成三个变体只会让每个调用点
/// 多一次没有意义的 `match`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressParseError;

/// 一个已经验证过的部署地址。
///
/// 持有**规范化之后**的原串（尾斜杠已剥），因为它要和 IdP 处登记的 redirect URI 逐字符
/// 比对（v3 §6.2 条 3）—— 重新拼装一遍 URL 会引入大小写、默认端口、路径归一化三种漂移。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentAddress {
    text: String,
    scheme: Scheme,
    host: String,
}

impl DeploymentAddress {
    /// 解析一个绝对 `http` / `https` URL。
    ///
    /// 入参会先 `trim` 再剥尾斜杠 —— 与上游 `optional()` + `.replace(/\/+$/, "")` 同序。
    ///
    /// # Errors
    ///
    /// 缺 scheme、scheme 不是 `http`/`https`、或 host 为空时返回 [`AddressParseError`]。
    pub fn parse(raw: &str) -> Result<Self, AddressParseError> {
        let text = crate::config::env::strip_trailing_slashes(trim_ecmascript(raw));

        let (scheme_text, rest) = text.split_once("://").ok_or(AddressParseError)?;
        let scheme = match scheme_text.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(AddressParseError),
        };

        // authority 到第一个 `/` `?` `#` 为止。三个都要看：`https://x?a=1` 是合法 URL，
        // 只找 `/` 会把 `x?a=1` 整个当成 host。
        let authority = rest
            .find(['/', '?', '#'])
            .map_or(rest, |index| &rest[..index]);

        // userinfo 剥到**最后**一个 `@`：口令里出现 `@` 是合法的，从第一个切会把
        // 口令的后半段当成 host。
        let host_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, after)| after);

        let host = if let Some(stripped) = host_port.strip_prefix('[') {
            // IPv6 字面量。`]` 之后的东西只能是 `:port`，这里不需要它。
            stripped.split_once(']').ok_or(AddressParseError)?.0
        } else {
            host_port.split(':').next().unwrap_or_default()
        };

        if host.is_empty() {
            return Err(AddressParseError);
        }

        Ok(Self {
            text: text.to_owned(),
            scheme,
            host: host.to_ascii_lowercase(),
        })
    }

    /// 规范化之后的原串（无尾斜杠）。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// scheme。
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// 小写化的 host，不含端口，IPv6 不含方括号。
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// host 是不是 loopback。见 [`is_loopback_host`]。
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        is_loopback_host(&self.host)
    }
}

impl fmt::Display for DeploymentAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// 这个 host 是不是只能从本机到达。
///
/// # 收哪些，为什么
///
/// - `localhost` 与任何 `*.localhost`：RFC 6761 §6.3 把整个 `.localhost` 保留给 loopback，
///   而 `http://api.localhost:3001` 是真实存在的本地开发形状。
/// - `127.0.0.0/8` 全段：`127.0.0.1` 之外还有人用 `127.0.0.2` 做多实例区分。
/// - `::1` 与它的展开写法 `0:0:0:0:0:0:0:1`。
///
/// # 判错的代价是不对称的，所以宽在哪一侧要说清
///
/// 这个判据的唯一用途是决定要不要点亮 `insecure_transport`（v3 §6.3）。
///
/// - **误判成 loopback**（该告警没告警）：一个真实暴露的明文部署不吭声。
/// - **误判成非 loopback**（不该告警却告警）：每个开发机的启动日志都多一行噪音，
///   而噪音会训练人忽略它 —— 于是第一种代价照样会发生。
///
/// 所以这里收得**窄而准**：只收上面三类确定属于本机的形态，不做 DNS 解析
/// （启动期解析 DNS 会让配置校验依赖网络），也不猜 `10.0.0.0/8` 之类的私网
/// —— 私网**不是** loopback，一个绑在公司内网明文地址上的部署确实应该被点名。
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    if host == "::1" || host == "0:0:0:0:0:0:0:1" {
        return true;
    }
    is_ipv4_loopback(&host)
}

/// `127.0.0.0/8` 的点分四段判定。
fn is_ipv4_loopback(host: &str) -> bool {
    let mut octets = host.split('.');
    let Some(first) = octets.next().and_then(|part| part.parse::<u8>().ok()) else {
        return false;
    };
    if first != 127 {
        return false;
    }
    let mut count = 1;
    for part in octets {
        if part.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
    }
    count == 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// scheme 与 host 抽得对 —— 三种典型形状。
    #[test]
    fn parses_scheme_and_host() {
        let https = DeploymentAddress::parse("https://openbot.example.com/api/").expect("合法");
        assert_eq!(https.scheme(), Scheme::Https);
        assert_eq!(https.host(), "openbot.example.com");
        // 尾斜杠在解析时就剥掉了，之后没有第二个地方会再剥一次。
        assert_eq!(https.as_str(), "https://openbot.example.com/api");

        let with_port = DeploymentAddress::parse("http://localhost:3001").expect("合法");
        assert_eq!(with_port.scheme(), Scheme::Http);
        assert_eq!(with_port.host(), "localhost");

        let ipv6 = DeploymentAddress::parse("http://[::1]:3001/x").expect("合法");
        assert_eq!(ipv6.host(), "::1");
        assert!(ipv6.is_loopback());
    }

    /// host 大小写归一，scheme 大小写也归一。
    #[test]
    fn case_is_normalised_on_both_halves() {
        let address = DeploymentAddress::parse("HTTPS://OpenBot.Example.COM").expect("合法");
        assert_eq!(address.scheme(), Scheme::Https);
        assert_eq!(address.host(), "openbot.example.com");
        // 原串**不**归一：它要和厂商处登记的 redirect URI 逐字符比对，
        // 我们无权替操作员改写它。
        assert_eq!(address.as_str(), "HTTPS://OpenBot.Example.COM");
    }

    /// userinfo 里的 `@` 不能把 host 切错。
    #[test]
    fn userinfo_is_stripped_from_the_last_at_sign() {
        let address =
            DeploymentAddress::parse("https://user:p@ss@internal.test:8443/x").expect("合法");
        assert_eq!(address.host(), "internal.test");
    }

    /// 查询串直接跟在 authority 后面时不能被当成 host 的一部分。
    #[test]
    fn a_query_string_terminates_the_authority() {
        let address = DeploymentAddress::parse("https://openbot.test?a=1").expect("合法");
        assert_eq!(address.host(), "openbot.test");
    }

    /// 拒绝的三类 —— 并配"合法值确实通过"的正向对照。
    #[test]
    fn refuses_what_it_cannot_answer_questions_about() {
        for bad in [
            "not a URL",
            "openbot.example.com",
            "ftp://openbot.example.com",
            "https://",
            "://openbot.test",
            "",
            "\u{0085}https://openbot.test\u{0085}",
        ] {
            assert_eq!(
                DeploymentAddress::parse(bad),
                Err(AddressParseError),
                "{bad:?} 不该被接受"
            );
        }
        // 正向对照：否则一个恒 Err 的解析器也能过上面全部。
        assert!(DeploymentAddress::parse("http://localhost:3001").is_ok());
        assert!(DeploymentAddress::parse("https://openbot.example.com").is_ok());
    }

    /// loopback 判据：收的三类都收，不该收的一律不收。
    #[test]
    fn loopback_is_narrow_and_precise() {
        for loopback in [
            "localhost",
            "LOCALHOST",
            "api.localhost",
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
            "::1",
            "0:0:0:0:0:0:0:1",
        ] {
            assert!(is_loopback_host(loopback), "{loopback} 应判 loopback");
        }

        // 负向：私网不是 loopback —— 一个绑在公司内网明文地址上的部署确实要被点名。
        for exposed in [
            "openbot.example.com",
            "10.0.0.1",
            "192.168.1.10",
            "172.16.0.1",
            "128.0.0.1",
            "127.0.0",
            "127.0.0.1.evil.test",
            "notlocalhost",
            "localhost.evil.test",
            "",
        ] {
            assert!(!is_loopback_host(exposed), "{exposed} 不该判 loopback");
        }
    }
}
