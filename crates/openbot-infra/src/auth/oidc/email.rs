//! email domain routing 需要的**窄**类型。
//!
//! # 边界：这里只做「路由键」，不做「身份」
//!
//! v3 §6.2 条 8 要求删除用户时「以**规范化 email** 写入 `revoked_access`」，条 6 的
//! `INITIAL_ADMIN_EMAILS` 也按 email 认人。那个规范化是**身份**判定，属于
//! `openbot_domain::identity`，不在本模块 —— 一个部署里只能有一份 email 规范化规则，
//! 两份就等于两种「同一个人」的定义。
//!
//! 本模块只回答一个窄得多的问题：**这封 email 该被路由到哪个 provider**。为此只需要域名
//! 那一半。local-part 在这里连读都不读（除了确认它非空），因为把 local-part 的规范化也
//! 抄一份进来，就是在制造上面说的那份重复。
//!
//! > 集成待办：[`EmailDomain`] 与 `domain_of` 将来要与
//! > `openbot_domain::identity::email` 的规范化合并 —— 合并方向是**本模块调用领域层**，
//! > 而不是领域层来读这里。
//!
//! # 为什么域名只收 ASCII
//!
//! [`EmailDomain::parse`] 拒绝任何非 ASCII 字节，IDN 必须由调用方先转成 punycode。
//! 理由不是省事：Unicode 里存在大量与 ASCII 视觉等价的码位（同形异义字），而 routing 的
//! 输出是**「这个人属于哪个组织」**。允许两串肉眼相同、字节不同的域名各自注册，等于给
//! 组织冒充开一道门 —— 而这道门的受害者在界面上看不出任何异常。

use super::error::OidcError;

/// 一个规范化的 email 域名，可以直接当路由键比对。
///
/// 不变量（由 [`Self::parse`] 建立）：全小写 ASCII；非空；不含 `@`、空白与控制字符；
/// 不以 `.` 或 `-` 开头或结尾；不含连续 `.`。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailDomain(String);

impl EmailDomain {
    /// 解析并规范化一个域名。
    ///
    /// # Errors
    ///
    /// 任一不变量不满足时返回 [`OidcError::DomainMalformed`]。**不**做「尽量修一修」的
    /// 宽容解析：一个被悄悄修正过的域名会让管理员登记的东西和实际生效的东西不是一回事。
    pub fn parse(raw: &str) -> Result<Self, OidcError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || !trimmed.is_ascii() {
            return Err(OidcError::DomainMalformed);
        }
        let lowered = trimmed.to_ascii_lowercase();

        let shape_ok = lowered
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !shape_ok {
            return Err(OidcError::DomainMalformed);
        }
        if lowered.starts_with('.')
            || lowered.ends_with('.')
            || lowered.starts_with('-')
            || lowered.ends_with('-')
            || lowered.contains("..")
        {
            return Err(OidcError::DomainMalformed);
        }

        Ok(Self(lowered))
    }

    /// 规范化后的域名。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 从一封 email 里取出路由键。
///
/// 在最后一个 `@` 处切分（RFC 5321 的 local-part 允许带引号的 `@`，取最后一个是实践中
/// 唯一不会把合法地址切错的做法），要求两侧都非空，然后把右侧交给 [`EmailDomain::parse`]。
///
/// # 只剥两端空白，绝不剥内部空白
///
/// 整串首尾的空白会被去掉（登录框里粘贴地址时带上的那种，语义无歧义）；**切分之后
/// 两侧一律不再 trim**，任一侧含空白即判不成形。
///
/// 这条不是洁癖，是一次实测出来的缺陷修复：[`EmailDomain::parse`] 自己会 trim（那是给
/// **管理员登记域名**用的便利），于是 `someone@ acme.example` 一度被静默路由到
/// `acme.example`。**给配置输入的宽容一旦作用到协议数据上，就变成了一处解析分歧** ——
/// 而分歧的两侧（我们和 IdP）会对「这是谁」给出不同答案。由
/// `whitespace_next_to_the_at_sign_does_not_route` 钉住。
///
/// 返回 `Option` 而不是 `Result`：调用方（routing）对「这封 email 根本不成形」与
/// 「成形但没有对应 provider」必须给出**同一个**回答（见 `routing` 模块的统一响应），
/// 所以在这一层就不该产生一个可区分的错误值。
#[must_use]
pub fn domain_of(email: &str) -> Option<EmailDomain> {
    let trimmed = email.trim();
    let (local, domain) = trimmed.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    if local.chars().any(char::is_whitespace) || domain.chars().any(char::is_whitespace) {
        return None;
    }
    EmailDomain::parse(domain).ok()
}

/// 一个 claim 值是否够格当 email 地址用。
///
/// 判据逐字照搬上游 `server/src/auth/index.ts::mapEntraProfile` 里的 `claim` 闭包：
/// `typeof value === "string" && value.includes("@")`。它刻意宽松 —— 上游注释说明这条链
/// 存在的理由是 Entra 常常只在 `upn` 或 `preferred_username` 里给出地址，而 OIDC 规范
/// **并不保证** `preferred_username` 是一个地址，所以「含 `@`」就是能拿到的全部保证。
///
/// 收紧它是一次**产品**决定而不是实现细节：收紧的那一刻，一批今天能登录的人会开始被拒。
#[must_use]
pub fn claim_looks_like_an_address(value: &str) -> bool {
    value.contains('@')
}

#[cfg(test)]
mod tests {
    use super::{EmailDomain, claim_looks_like_an_address, domain_of};
    use crate::auth::oidc::error::OidcError;

    /// 正向：常见写法归一到同一个键。
    #[test]
    fn domains_normalise_to_one_routing_key() {
        let expected = EmailDomain::parse("acme.example").unwrap();
        for raw in ["acme.example", "ACME.Example", "  Acme.EXAMPLE  "] {
            assert_eq!(EmailDomain::parse(raw).as_ref(), Ok(&expected), "{raw}");
        }
        assert_eq!(expected.as_str(), "acme.example");
    }

    /// 负向：坏形态一律拒，不做「尽量修一修」。
    #[test]
    fn malformed_domains_are_refused() {
        for raw in [
            "",
            "   ",
            "acme example",        // 空白
            "acme@example",        // 带 @
            ".acme.example",       // 前导点
            "acme.example.",       // 末尾点
            "-acme.example",       // 前导连字符
            "acme.example-",       // 末尾连字符
            "acme..example",       // 连续点
            "acme_example",        // 下划线不是域名字符
            "acme.example/path",   // 斜杠
            "acme.exam\u{0000}le", // 控制字符
        ] {
            assert_eq!(
                EmailDomain::parse(raw),
                Err(OidcError::DomainMalformed),
                "{raw:?} 应当被拒"
            );
        }
    }

    /// 负向：同形异义的非 ASCII 域名不得注册。
    ///
    /// 正向对照紧跟其后 —— punycode 形态是被接受的，所以这条不是「凡是像域名的都拒」。
    #[test]
    fn confusable_unicode_domains_are_refused_but_punycode_is_accepted() {
        // U+0430 CYRILLIC SMALL LETTER A，与 ASCII 'a' 视觉等价。
        let confusable = "\u{0430}cme.example";
        assert_ne!(confusable, "acme.example");
        assert_eq!(
            EmailDomain::parse(confusable),
            Err(OidcError::DomainMalformed)
        );

        assert!(EmailDomain::parse("xn--80ak6aa92e.example").is_ok());
    }

    /// 正向 + 负向：从 email 取路由键。
    #[test]
    fn the_routing_key_comes_from_the_last_at_sign() {
        assert_eq!(
            domain_of("Someone@ACME.example"),
            Some(EmailDomain::parse("acme.example").unwrap())
        );
        // 带引号 local-part 里的 @ 不该把切分点带偏。
        assert_eq!(
            domain_of("\"weird@local\"@acme.example"),
            Some(EmailDomain::parse("acme.example").unwrap())
        );

        // 负向：不成形的一律拿不到键。
        for raw in ["", "no-at-sign", "@acme.example", "someone@"] {
            assert_eq!(domain_of(raw), None, "{raw:?} 不该产出路由键");
        }
    }

    /// `@` 两侧的空白不得被静默吸收。
    ///
    /// 这条是一次实测缺陷的回归闸门：`EmailDomain::parse` 自己会 trim，早先的
    /// `domain_of` 因此把 `someone@ acme.example` 路由到了 `acme.example`。
    #[test]
    fn whitespace_next_to_the_at_sign_does_not_route() {
        for raw in [
            "someone@ acme.example",
            "someone @acme.example",
            "someone@acme.example ", // 这一个应当**通过**（两端空白允许剥）
        ] {
            let routed = domain_of(raw).is_some();
            let expected = raw == "someone@acme.example ";
            assert_eq!(routed, expected, "{raw:?}");
        }

        // 正向对照：内部无空白的同一地址照常路由 —— 否则上面在「什么都不路由」的
        // 世界里同样通过。
        assert_eq!(
            domain_of("  someone@acme.example  "),
            Some(EmailDomain::parse("acme.example").unwrap())
        );
    }

    /// claim 判据与上游逐字一致：宽松到只要求含 `@`。
    #[test]
    fn the_claim_predicate_matches_upstream_exactly() {
        // 正向：真地址与 Entra 的 UPN 形态都算数。
        assert!(claim_looks_like_an_address("someone@acme.example"));
        assert!(claim_looks_like_an_address(
            "someone_acme.example#EXT#@acme.onmicrosoft.example"
        ));
        // 负向：不含 @ 的显示名 / 用户名不算。
        assert!(!claim_looks_like_an_address("someone"));
        assert!(!claim_looks_like_an_address(""));
        assert!(!claim_looks_like_an_address("Some One"));
    }
}
