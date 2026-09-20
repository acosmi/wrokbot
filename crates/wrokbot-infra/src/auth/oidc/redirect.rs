//! 精确 redirect URI（v3 §6.2 条 3 的「精确 redirect URI」那一项）。
//!
//! # 裁决：比对是**原始字符串逐字节相等**，规范化发生在**登记时**
//!
//! 两种可选形态：(a) 收到时先 URL 规范化再比对；(b) 登记时强制规范形、收到时逐字节比对。
//! 本模块选 (b)，三条理由：
//!
//! 1. **规范化是一个必须与 IdP 逐位一致的函数**。RFC 6749 §3.1.2.2 与 OAuth 2.1 草案
//!    §4.1.2.1 都写明授权服务器用 *simple string comparison*。Google / Entra / Okta 照此
//!    实现。我们如果规范化后再比，就会**接受一批 IdP 本来会拒绝的值** —— 我们这一侧的
//!    检查因此严格弱于 IdP 那一侧，等于白做。反过来它还引入一个新的分歧面：两个实现的
//!    规范化差一点，那一点就是绕过。
//! 2. **「同一个 URI 的两种拼法」应当在配置期消失，而不是在登录期被和稀泥**。
//!    [`CanonicalRedirectUri::parse`] 要求 `Url::parse(raw).to_string() == raw`，于是
//!    `https://host:443/cb`（`url` crate 会丢掉默认端口）、`https://HOST/cb`（host 会被
//!    小写化）之类的写法**根本登记不进来**，管理员当场拿到
//!    [`OidcError::RedirectUriNotCanonical`]。
//! 3. **逐字节比对的残余风险是「误拒」而不是「误放」**，而误拒有名字、可当场定位。
//!
//! 三个点名的绕过形态各自的结论：
//!
//! | 形态 | 结论 |
//! | --- | --- |
//! | `https://host/cb` vs `https://host/cb/` | **两个不同的 URI**，RFC 3986 §6.2.2.3 的规范化既不加也不删末尾斜杠。两者都可以各自登记，互不匹配。没有绕过面，只有「登记哪个就必须回调哪个」。 |
//! | `https://host:443/cb` | 登记阶段直接拒（`to_string()` 会丢掉 `:443`，往返不等）。就算它出现在回调里，也与登记值不逐字节相等，一样拒。 |
//! | `https://HOST/cb` | 同上，`url` crate 会把 host 小写化，往返不等，登记阶段拒。 |
//!
//! # 一处必须点名的上游陷阱
//!
//! `openidconnect` 的 `new_url_type!` 宏（`openidconnect-4.0.1/src/macros.rs`）生成的
//! `PartialEq` 比的是 `self.1`，也就是**构造时传入的原始字符串**，而不是解析后的 `Url`。
//! 于是 `RedirectUrl::new("https://h:443/cb")` 与
//! `RedirectUrl::from_url(Url::parse("https://h:443/cb"))` 是**两个不相等的值**（后者存的是
//! `Url::to_string()` 的规范形）。同一个 URI 因构造函数不同而不等 —— 把 redirect URI 的
//! 相等性押在这个类型上是不安全的，所以本模块自己持有 `String` 并只用它比对。
//! 该行为由 `openidconnect_redirect_url_equality_depends_on_the_constructor` 钉住。

use url::Url;

use super::error::OidcError;

/// 只允许 `https`。多用户 Server 的默认档。
pub const HTTPS_ONLY: &[&str] = &["https"];

/// 允许 `https` 与 `http`。
///
/// 存在的理由是 v3 §6.3 的既有裁决：上游 `repository contract` 写的是「把 TLS 放在前面」
/// 而不是「拒绝 HTTP」，且 CHANGELOG 修过「plain HTTP 真实地址上无法开始会话」，所以
/// **非 loopback 的 plain HTTP 部署仍可登录**，代价是启动日志告警 + `/health` 带
/// `insecure_transport: true`。把 scheme 集合做成参数而不是常量，是因为它是**部署形态**，
/// 写死在协议层就等于把一条产品裁决藏进一个没人能改的地方。
pub const HTTPS_OR_HTTP: &[&str] = &["https", "http"];

/// 一个已登记的、规范形的 redirect URI。
///
/// 不变量（由 [`Self::parse`] 建立，之后无法被破坏 —— 字段私有且没有 setter）：
///
/// - `Url::parse(inner)` 成功且 `to_string()` 与 `inner` 逐字节相等；
/// - scheme 在登记时给定的允许集内；
/// - 有 host；不是 `cannot-be-a-base` URL；
/// - 无 fragment（RFC 6749 §3.1.2 明禁）；无 userinfo。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalRedirectUri(String);

impl CanonicalRedirectUri {
    /// 登记一个 redirect URI。
    ///
    /// # Errors
    ///
    /// - [`OidcError::RedirectUriNotCanonical`]：解析失败，或往返后与原串不等；
    /// - [`OidcError::RedirectUriSchemeNotAllowed`]：scheme 不在 `allowed_schemes` 内；
    /// - [`OidcError::RedirectUriNotBare`]：带 fragment 或 userinfo，或没有 host。
    pub fn parse(raw: &str, allowed_schemes: &[&str]) -> Result<Self, OidcError> {
        let url = Url::parse(raw).map_err(|_| OidcError::RedirectUriNotCanonical)?;

        if url.cannot_be_a_base() || url.host_str().is_none() {
            return Err(OidcError::RedirectUriNotBare);
        }
        if !allowed_schemes.contains(&url.scheme()) {
            return Err(OidcError::RedirectUriSchemeNotAllowed);
        }
        if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
            return Err(OidcError::RedirectUriNotBare);
        }
        // 规范形闸门：只有「写下来的那一串」本身就是 `url` crate 的规范输出，逐字节比对
        // 才既是充分的又是必要的。这一条挡掉的是 `:443`、大写 host、`%2F` 之类的异写。
        if url.as_str() != raw {
            return Err(OidcError::RedirectUriNotCanonical);
        }

        Ok(Self(raw.to_owned()))
    }

    /// 登记值本身。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 与回调实际到达的 redirect URI 做**逐字节**比对。
    ///
    /// # Errors
    ///
    /// 不相等时返回 [`OidcError::RedirectUriMismatch`]。
    pub fn assert_exact_match(&self, received: &str) -> Result<(), OidcError> {
        if self.0 == received {
            Ok(())
        } else {
            Err(OidcError::RedirectUriMismatch)
        }
    }

    /// 交给 `openidconnect` 构造授权请求时用的形态。
    ///
    /// 走 `RedirectUrl::new`（保留原串）而不是 `from_url`（存规范形），这样 wire 上出现的
    /// 字节与登记值、与 [`Self::assert_exact_match`] 比的那一串是**同一串**。见模块文档
    /// 里那条构造函数陷阱。
    ///
    /// # Errors
    ///
    /// 实际不可能失败（不变量保证 `Url::parse` 成功），但仍以 `Result` 返回而不是
    /// `expect`：一个「不可能」的 `panic` 在认证路径上是拒绝服务面。
    pub fn to_openidconnect(&self) -> Result<openidconnect::RedirectUrl, OidcError> {
        openidconnect::RedirectUrl::new(self.0.clone())
            .map_err(|_| OidcError::RedirectUriNotCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalRedirectUri, HTTPS_ONLY, HTTPS_OR_HTTP};
    use crate::auth::oidc::error::OidcError;
    use url::Url;

    /// 正向：规范形的 https 回调登记得进，并且只匹配它自己。
    #[test]
    fn a_canonical_https_callback_registers_and_matches_itself() {
        let uri = CanonicalRedirectUri::parse("https://app.example.com/auth/callback", HTTPS_ONLY)
            .expect("规范形应当登记成功");
        assert_eq!(uri.as_str(), "https://app.example.com/auth/callback");
        assert_eq!(
            uri.assert_exact_match("https://app.example.com/auth/callback"),
            Ok(())
        );
    }

    /// 负向：默认端口的显式写法**登记不进来**。
    ///
    /// 正向对照就在同一条里 —— 去掉 `:443` 的同一个 URI 登记得进。没有这个对照，
    /// 本断言在「`parse` 恒返回 Err」的世界里同样通过。
    #[test]
    fn the_explicit_default_port_spelling_cannot_be_registered() {
        assert_eq!(
            CanonicalRedirectUri::parse("https://app.example.com:443/auth/callback", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotCanonical)
        );
        assert!(
            CanonicalRedirectUri::parse("https://app.example.com/auth/callback", HTTPS_ONLY)
                .is_ok(),
            "正向对照：同一个 URI 的规范写法必须登记得进"
        );
        // 非默认端口是规范形的一部分，必须登记得进 —— 否则上一条其实是在拒绝所有端口。
        assert!(
            CanonicalRedirectUri::parse("https://app.example.com:8443/auth/callback", HTTPS_ONLY)
                .is_ok()
        );
    }

    /// 负向：大写 host 登记不进（`url` 会小写化，往返不等）。
    #[test]
    fn an_uppercase_host_cannot_be_registered() {
        assert_eq!(
            CanonicalRedirectUri::parse("https://APP.example.com/cb", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotCanonical)
        );
        assert!(CanonicalRedirectUri::parse("https://app.example.com/cb", HTTPS_ONLY).is_ok());
    }

    /// 末尾斜杠是**两个不同的 URI**：各自登记得进，互不匹配。
    ///
    /// 这正是选「逐字节相等」的代价与收益同时出现的地方：没有静默的互相接受。
    #[test]
    fn trailing_slash_is_a_different_uri_in_both_directions() {
        let no_slash = CanonicalRedirectUri::parse("https://app.example.com/cb", HTTPS_ONLY)
            .expect("无斜杠形态可登记");
        let with_slash = CanonicalRedirectUri::parse("https://app.example.com/cb/", HTTPS_ONLY)
            .expect("带斜杠形态同样可登记");

        assert_eq!(
            no_slash.assert_exact_match("https://app.example.com/cb/"),
            Err(OidcError::RedirectUriMismatch)
        );
        assert_eq!(
            with_slash.assert_exact_match("https://app.example.com/cb"),
            Err(OidcError::RedirectUriMismatch)
        );
        // 正向对照：各自匹配自己。
        assert_eq!(
            no_slash.assert_exact_match("https://app.example.com/cb"),
            Ok(())
        );
        assert_eq!(
            with_slash.assert_exact_match("https://app.example.com/cb/"),
            Ok(())
        );
    }

    /// 逐字节比对不会被端口 / 大小写的异写绕过。
    #[test]
    fn exact_match_refuses_alternate_spellings_of_the_same_url() {
        let uri = CanonicalRedirectUri::parse("https://app.example.com/cb", HTTPS_ONLY).unwrap();
        for spelling in [
            "https://app.example.com:443/cb",
            "https://APP.example.com/cb",
            "https://app.example.com/cb?x=1",
            "https://app.example.com/CB",
            "http://app.example.com/cb",
        ] {
            assert_eq!(
                uri.assert_exact_match(spelling),
                Err(OidcError::RedirectUriMismatch),
                "{spelling} 不该匹配"
            );
        }
        assert_eq!(uri.assert_exact_match("https://app.example.com/cb"), Ok(()));
    }

    /// scheme 允许集是参数：默认档拒 `http`，§6.3 的宽松档接受它。
    #[test]
    fn the_allowed_scheme_set_is_a_parameter_not_a_constant() {
        assert_eq!(
            CanonicalRedirectUri::parse("http://box.internal/cb", HTTPS_ONLY),
            Err(OidcError::RedirectUriSchemeNotAllowed)
        );
        assert!(CanonicalRedirectUri::parse("http://box.internal/cb", HTTPS_OR_HTTP).is_ok());
        // 两档都不接受别的 scheme。
        assert_eq!(
            CanonicalRedirectUri::parse("ftp://box.internal/cb", HTTPS_OR_HTTP),
            Err(OidcError::RedirectUriSchemeNotAllowed)
        );
    }

    /// fragment / userinfo / 无 host 一律拒；query 允许（RFC 6749 §3.1.2 明确允许）。
    #[test]
    fn fragment_userinfo_and_hostless_uris_are_refused_but_query_is_allowed() {
        assert_eq!(
            CanonicalRedirectUri::parse("https://app.example.com/cb#frag", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotBare)
        );
        assert_eq!(
            CanonicalRedirectUri::parse("https://user@app.example.com/cb", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotBare)
        );
        assert_eq!(
            CanonicalRedirectUri::parse("mailto:someone@example.com", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotBare)
        );
        // 正向对照：query 是允许的，所以上面三条不是「什么都拒」。
        assert!(
            CanonicalRedirectUri::parse("https://app.example.com/cb?tenant=acme", HTTPS_ONLY)
                .is_ok()
        );
    }

    /// 完全不是 URL 的输入落 `RedirectUriNotCanonical`。
    #[test]
    fn garbage_is_refused() {
        assert_eq!(
            CanonicalRedirectUri::parse("not a url", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotCanonical)
        );
        assert_eq!(
            CanonicalRedirectUri::parse("", HTTPS_ONLY),
            Err(OidcError::RedirectUriNotCanonical)
        );
    }

    /// 上游陷阱的实测记录：`openidconnect::RedirectUrl` 的相等性取决于用了哪个构造函数。
    ///
    /// 负向（两个构造函数对同一个非规范串给出不相等的值）+ 正向（对规范串给出相等的值）。
    /// 后者证明这不是「`RedirectUrl` 恒不等」，而正是「原串 vs 规范形」的差异。
    #[test]
    fn openidconnect_redirect_url_equality_depends_on_the_constructor() {
        use openidconnect::RedirectUrl;

        let raw = "https://app.example.com:443/cb";
        let via_new = RedirectUrl::new(raw.to_owned()).unwrap();
        let via_from_url = RedirectUrl::from_url(Url::parse(raw).unwrap());
        assert_ne!(
            via_new, via_from_url,
            "同一个 URI 因构造函数不同而不等 —— 这就是不能把相等性押在该类型上的理由"
        );

        let canonical = "https://app.example.com/cb";
        assert_eq!(
            RedirectUrl::new(canonical.to_owned()).unwrap(),
            RedirectUrl::from_url(Url::parse(canonical).unwrap()),
            "正向对照：规范串上两个构造函数一致"
        );
    }

    /// 交给 `openidconnect` 的形态保留原串。
    #[test]
    fn the_openidconnect_form_carries_the_registered_bytes() {
        let uri = CanonicalRedirectUri::parse("https://app.example.com/cb", HTTPS_ONLY).unwrap();
        let as_oidc = uri.to_openidconnect().unwrap();
        assert_eq!(as_oidc.as_str(), uri.as_str());
    }
}
