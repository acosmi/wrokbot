//! provider 模型与注册表（v3 §6.2 条 1 / 2 / 9）。
//!
//! # 三家的差异落在类型上，不落在 `if`
//!
//! §6.2 条 1 要求 Google、Microsoft Entra、Okta 可**同时**配置。它们真正的差异只有一处：
//! **issuer 由谁决定**，也就是「一个管理员能不能把这个 provider 指向他挑的主机」。
//! [`ProviderKind`] 把它写成三个变体，[`ProviderKind::issuer_trust`] 把它收敛成一个可判定
//! 的答案：
//!
//! - [`ProviderKind::Google`] —— issuer 是常量 [`GOOGLE_ISSUER`]，变体里**没有 issuer 字段**。
//!   管理员改不动它不是因为有一条校验，而是因为没有那个字段可填。
//! - [`ProviderKind::Entra`] —— authority 只接受固定 Microsoft host 上的官方四类取值，并额外
//!   带一份 [`EntraTenantPolicy`]；这是唯一一个 `tid` claim 有意义的变体。
//! - [`ProviderKind::DeploymentOwned`] —— Okta 与一切动态注册的 provider，整个 issuer 由
//!   管理员给出。上游 `repository contract` 的 `OKTA_OAUTH_ISSUER` 示例
//!   `https://example.okta.com/oauth2/default` 说明了为什么它必须走 discovery：**每个客户
//!   自己的 issuer，还带路径段**，端点无法预先知道。
//!
//! # provider 的身份是 `(id, issuer)`，不是 `id`
//!
//! 上游 `server/src/db/schema/core.ts` 在 `accounts.issuer` 列上写明了理由：「`providerId`
//! alone stopped being enough once a deployment can register more than one OIDC provider: two
//! companies' Okta tenants are both "okta" and are not the same directory.」本模块因此把
//! issuer 放进 [`OidcProviderConfig`] 的必填面，而不是当成可推导的细节。
//!
//! # provider 归部署，不归登记它的管理员（§6.2 条 9）
//!
//! 上游 `server/src/auth/identity-provider-store.ts` 记录了这条的来历：Better Auth 的 SSO
//! 插件把登记者的 `userId` 盖在行上，再用 `providers.filter(p => p.userId === session.user.id)`
//! 回答列表 —— 于是第二个管理员看到空列表、重复登记了同一个 provider，而**最初那位管理员
//! 离职时把公司的登录一起带走了**（行随他的用户行级联删除）。
//!
//! 本模块的对应构造：[`OidcProviderConfig::registered_by`] 存在，但**没有任何查找路径读它**。
//! 由 `a_provider_whose_registrant_is_gone_is_still_routable` 钉住 —— 那条测试把登记者置空
//! 之后仍要求 routing 命中。
//!
//! # 这里没有 client secret
//!
//! [`OidcProviderConfig`] 里**没有**存放 client secret 的字段。同样照搬上游那条设计：
//! `identity-provider-store.ts` 的 `RegisteredIdentityProvider` 注释写「no projection that
//! includes them can be safe to send to a browser, so the shape that leaves this module cannot
//! express them」。secret 由 vault 模块（不在本轮）解密后，在**单次调用**里以参数形式交给
//! 需要它的那一个函数，不进任何长寿命结构 —— v3 §17.2 条 8「secret 不进模型、GUI state、
//! browser event、普通日志、trace」。

use std::collections::{BTreeMap, BTreeSet};

use openidconnect::{ClientId, IssuerUrl};

use super::email::EmailDomain;
use super::error::OidcError;
use super::redirect::CanonicalRedirectUri;

/// Google 的 issuer identifier。
///
/// 证据：`openidconnect-4.0.1/examples/google.rs` 里
/// `IssuerUrl::new("https://accounts.google.com".to_string())`，以及上游
/// `server/src/db/schema/core.ts` 在 `accounts.issuer` 的注释里举的同一个值。
///
/// **没有末尾斜杠**，这不是笔误 —— 见 [`parse_issuer`] 对 `url` crate 序列化行为的说明。
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// 一个 provider 在本部署内的稳定标识。
///
/// 形态被刻意收紧到 `[a-z0-9][a-z0-9_-]{0,63}`：这个值会出现在 URL 路径、结构化日志字段、
/// audit 查询桶和 pre-auth 面的应答里。允许自由文本等于在这四个地方各开一处注入面，而
/// 收紧它的代价只是管理员改个名字。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    /// 解析一个 provider ID。
    ///
    /// # Errors
    ///
    /// 形态不合时返回 [`OidcError::ProviderIdMalformed`]。**不**做大小写归一化：
    /// 归一化会让 `Okta` 与 `okta` 变成同一个 provider，而管理员在两处看到的字面量不同，
    /// 「我删掉的到底是哪一个」就没有答案了。
    pub fn parse(raw: &str) -> Result<Self, OidcError> {
        if raw.is_empty() || raw.len() > 64 {
            return Err(OidcError::ProviderIdMalformed);
        }
        let mut chars = raw.chars();
        let first = chars.next().ok_or(OidcError::ProviderIdMalformed)?;
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(OidcError::ProviderIdMalformed);
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
            return Err(OidcError::ProviderIdMalformed);
        }
        Ok(Self(raw.to_owned()))
    }

    /// 标识本身。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// issuer 由谁决定 —— [`ProviderKind`] 的三个变体收敛出的那条判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssuerTrust {
    /// issuer 是本模块钉死的常量，管理员无法改动。
    Pinned,
    /// issuer 由管理员输入，必须先过 [`parse_issuer`] 的闸门，出网仍受 safe dialer 约束。
    AdministratorSupplied,
}

/// Entra 的 `tid`（租户）策略。
///
/// §6.2 条 5 要求 Entra 的 email 解析链「仍需 verified issuer/tenant policy」—— 也就是说
/// 那条宽松的 `email → upn → preferred_username` 回退**不豁免**租户校验。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntraTenantPolicy {
    /// 不额外限制 `tid`（issuer 已经把范围钉死在单租户 authority 上时的正常档）。
    IssuerScoped,
    /// `common` / `organizations` 的 tenant-independent metadata。
    ///
    /// `tid` 必须是 canonical GUID；`allow_personal=false` 另外拒绝 Microsoft consumer tenant。
    TenantIndependent {
        /// `common=true`，`organizations=false`。
        allow_personal: bool,
    },
    /// `tid` 必须落在这个集合内。
    ///
    /// 多租户 authority（Entra 的 `common` / `organizations`）下这是**唯一**的边界：
    /// 那种 authority 的 token 由登录者自己的租户签发，不校验 `tid` 等于接受全世界。
    AllowList(BTreeSet<String>),
}

impl EntraTenantPolicy {
    /// `tid` 是否被接受。
    ///
    /// `None` 表示 token 里没有 `tid` claim：[`Self::AllowList`] 档下**拒绝**（拿不到租户
    /// 就无法证明它在名单里），[`Self::IssuerScoped`] 档下接受（边界由 issuer 承担）。
    #[must_use]
    pub fn accepts(&self, tid: Option<&str>) -> bool {
        match self {
            Self::IssuerScoped => true,
            Self::AllowList(allowed) => tid.is_some_and(|t| allowed.contains(t)),
            Self::TenantIndependent { allow_personal } => tid.is_some_and(|tenant| {
                let Ok(parsed) = uuid::Uuid::parse_str(tenant) else {
                    return false;
                };
                let canonical = parsed.hyphenated().to_string();
                canonical == tenant && (*allow_personal || tenant != MICROSOFT_CONSUMER_TENANT_ID)
            }),
        }
    }

    #[must_use]
    pub const fn is_tenant_independent(&self) -> bool {
        matches!(self, Self::TenantIndependent { .. })
    }
}

/// Microsoft personal accounts 的固定 tenant GUID（官方 ID token claims reference）。
pub const MICROSOFT_CONSUMER_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// provider 的种类。见模块文档。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderKind {
    /// Google。issuer 恒为 [`GOOGLE_ISSUER`]。
    Google,
    /// Microsoft Entra。
    ///
    /// authority/issuer 由环境配置 adapter 按固定 Microsoft host 与官方 tenant 形态构造；
    /// 本变体不把任意管理员 URL 当成 Entra。
    Entra {
        /// 用来拉 discovery 的 authority（可能是 `common` / `organizations`）。
        authority: IssuerUrl,
        /// 该租户的 issuer。
        issuer: IssuerUrl,
        /// `tid` 策略。
        tenants: EntraTenantPolicy,
    },
    /// Okta 与一切动态注册的 deployment-owned provider。
    DeploymentOwned {
        /// 管理员给出的 issuer，可带路径段。
        issuer: IssuerUrl,
    },
}

impl ProviderKind {
    /// 该 provider 的 issuer。
    ///
    /// # Panics
    ///
    /// 不会 —— [`GOOGLE_ISSUER`] 是常量且由 `google_issuer_constant_parses` 实测可解析。
    #[must_use]
    pub fn issuer(&self) -> IssuerUrl {
        match self {
            Self::Google => IssuerUrl::new(GOOGLE_ISSUER.to_owned())
                .unwrap_or_else(|_| unreachable!("GOOGLE_ISSUER 由测试实测可解析")),
            Self::Entra { issuer, .. } | Self::DeploymentOwned { issuer } => issuer.clone(),
        }
    }

    /// discovery authority。普通 OIDC 与 token issuer 相同；tenant-independent Entra 不同。
    #[must_use]
    pub fn discovery_issuer(&self) -> IssuerUrl {
        match self {
            Self::Entra { authority, .. } => authority.clone(),
            Self::Google | Self::DeploymentOwned { .. } => self.issuer(),
        }
    }

    /// issuer 由谁决定。
    #[must_use]
    pub const fn issuer_trust(&self) -> IssuerTrust {
        match self {
            Self::Google => IssuerTrust::Pinned,
            Self::Entra { .. } | Self::DeploymentOwned { .. } => IssuerTrust::AdministratorSupplied,
        }
    }

    /// Entra 的租户策略；其余变体没有这个概念。
    #[must_use]
    pub const fn entra_tenants(&self) -> Option<&EntraTenantPolicy> {
        match self {
            Self::Entra { tenants, .. } => Some(tenants),
            Self::Google | Self::DeploymentOwned { .. } => None,
        }
    }
}

/// provider 是怎么进到这个部署里的。
///
/// 它与 [`ProviderKind`] 是**两条正交的轴**：`ProviderKind` 决定 issuer 可不可信，
/// `ProviderOrigin` 决定它能不能出现在 pre-auth 面上（§6.2「pre-auth surface 只公开
/// 环境配置的 provider ID」）。把两者混成一个枚举会让「动态注册一个叫 google 的 provider」
/// 这种情形无处安放。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderOrigin {
    /// 由部署的环境配置声明（上游的 `GOOGLE_OAUTH_*` / `MICROSOFT_OAUTH_*` / `OKTA_OAUTH_*`）。
    EnvironmentConfigured,
    /// 由管理员在运行期动态注册（§6.2 条 2）。
    DynamicallyRegistered,
}

/// 一个 OIDC provider 的配置。**不含 client secret**，见模块文档。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcProviderConfig {
    id: ProviderId,
    kind: ProviderKind,
    origin: ProviderOrigin,
    client_id: ClientId,
    redirect_uri: CanonicalRedirectUri,
    domains: BTreeSet<EmailDomain>,
    registered_by: Option<String>,
}

impl OidcProviderConfig {
    /// 组装一份配置。
    ///
    /// `registered_by` 是**记录**不是**权限**：它只回答「当初是谁登记的」，任何查找路径
    /// 都不读它（§6.2 条 9）。类型上写成 `Option<String>` 是因为登记者可以离开，而
    /// provider 必须留下 —— `None` 是一个正常的稳态，不是缺失数据。
    ///
    /// > 集成待办：`registered_by` 将来换成 `openbot_contracts::ids::ActorId`。
    #[must_use]
    pub fn new(
        id: ProviderId,
        kind: ProviderKind,
        origin: ProviderOrigin,
        client_id: ClientId,
        redirect_uri: CanonicalRedirectUri,
        domains: BTreeSet<EmailDomain>,
        registered_by: Option<String>,
    ) -> Self {
        Self {
            id,
            kind,
            origin,
            client_id,
            redirect_uri,
            domains,
            registered_by,
        }
    }

    /// provider 标识。
    #[must_use]
    pub const fn id(&self) -> &ProviderId {
        &self.id
    }

    /// 种类。
    #[must_use]
    pub const fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    /// 来源（决定 pre-auth 可见性）。
    #[must_use]
    pub const fn origin(&self) -> ProviderOrigin {
        self.origin
    }

    /// 该 provider 的 issuer。
    #[must_use]
    pub fn issuer(&self) -> IssuerUrl {
        self.kind.issuer()
    }

    /// 用来拉 `.well-known` 的 authority。
    #[must_use]
    pub fn discovery_issuer(&self) -> IssuerUrl {
        self.kind.discovery_issuer()
    }

    pub(crate) fn with_entra_token_issuer(&self, issuer: IssuerUrl) -> Result<Self, OidcError> {
        let ProviderKind::Entra {
            authority, tenants, ..
        } = &self.kind
        else {
            return Err(OidcError::IdTokenRejected);
        };
        Ok(Self {
            id: self.id.clone(),
            kind: ProviderKind::Entra {
                authority: authority.clone(),
                issuer,
                tenants: tenants.clone(),
            },
            origin: self.origin,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            domains: self.domains.clone(),
            registered_by: self.registered_by.clone(),
        })
    }

    /// OAuth client id。
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// 登记的精确 redirect URI。
    #[must_use]
    pub const fn redirect_uri(&self) -> &CanonicalRedirectUri {
        &self.redirect_uri
    }

    /// 路由到这里的 email 域名集合。
    #[must_use]
    pub const fn domains(&self) -> &BTreeSet<EmailDomain> {
        &self.domains
    }

    /// 当初是谁登记的。**没有任何查找路径读它。**
    #[must_use]
    pub fn registered_by(&self) -> Option<&str> {
        self.registered_by.as_deref()
    }
}

/// 解析并校验一个管理员给出的 issuer。
///
/// # 闸门
///
/// - scheme 必须是 `https`；
/// - 必须有 host，不能是 `cannot-be-a-base`；
/// - 不得带 query、fragment 或 userinfo。
///
/// 这三条**必须由我们自己做**：`openidconnect::IssuerUrl` 的文档写它是「URL using the
/// `https` scheme with no query or fragment component」，但 `new_url_type!` 宏
/// （`openidconnect-4.0.1/src/macros.rs`）生成的 `new` 只有一句 `url::Url::parse(&url)?`,
/// 一个 scheme 都不检查。由 `openidconnect_issuer_url_does_not_enforce_its_documented_shape`
/// 实测钉住。
///
/// # 为什么**不**做 redirect URI 那样的「往返规范形」闸门
///
/// `url` crate 对特殊 scheme 会把空路径序列化成 `/`，于是
/// `Url::parse("https://accounts.google.com").as_str()` 得到的是
/// `"https://accounts.google.com/"` —— 带了一条 issuer identifier 本身没有的斜杠。
/// 而 issuer 必须与 ID token 的 `iss` claim 逐字节相等（`openidconnect` 的验证器比的就是
/// 原串）。所以在这里套往返闸门会把 Google 的正确 issuer 判成非法。
/// 由 `the_url_crate_adds_a_trailing_slash_which_is_why_issuers_skip_the_roundtrip_gate` 实测。
///
/// # Errors
///
/// - [`OidcError::IssuerNotHttps`]：scheme 不是 `https`；
/// - [`OidcError::IssuerNotBare`]：无 host / 带 query / fragment / userinfo。
pub fn parse_issuer(raw: &str) -> Result<IssuerUrl, OidcError> {
    let issuer = IssuerUrl::new(raw.to_owned()).map_err(|_| OidcError::IssuerNotBare)?;
    let url = issuer.url();

    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(OidcError::IssuerNotBare);
    }
    if url.scheme() != "https" {
        return Err(OidcError::IssuerNotHttps);
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(OidcError::IssuerNotBare);
    }
    Ok(issuer)
}

/// 本部署已注册的全部 OIDC provider。
///
/// 建表时就把「同一个域名被两个 provider 抢注」和「同一个 ID 登记两次」判死，而不是留到
/// 查询时按遍历顺序碰运气 —— routing 的输出是一次权限判定，让它的答案取决于插入顺序，
/// 等于让一个新管理员靠抢注域名把别人的用户接管过来。
#[derive(Clone, Debug, Default)]
pub struct ProviderRegistry {
    by_id: BTreeMap<ProviderId, OidcProviderConfig>,
    by_domain: BTreeMap<EmailDomain, ProviderId>,
}

impl ProviderRegistry {
    /// 从一组配置建表。
    ///
    /// # Errors
    ///
    /// - [`OidcError::ProviderIdConflict`]：同一个 ID 出现两次；
    /// - [`OidcError::DomainConflict`]：同一个域名被两个 provider 声明。
    pub fn build(configs: impl IntoIterator<Item = OidcProviderConfig>) -> Result<Self, OidcError> {
        let mut by_id: BTreeMap<ProviderId, OidcProviderConfig> = BTreeMap::new();
        let mut by_domain: BTreeMap<EmailDomain, ProviderId> = BTreeMap::new();

        for config in configs {
            for domain in config.domains() {
                if by_domain.contains_key(domain) {
                    return Err(OidcError::DomainConflict);
                }
                by_domain.insert(domain.clone(), config.id().clone());
            }
            if by_id.insert(config.id().clone(), config).is_some() {
                return Err(OidcError::ProviderIdConflict);
            }
        }

        Ok(Self { by_id, by_domain })
    }

    /// 按 ID 取。
    #[must_use]
    pub fn by_id(&self, id: &ProviderId) -> Option<&OidcProviderConfig> {
        self.by_id.get(id)
    }

    /// 按 email 域名取。**不读 [`OidcProviderConfig::registered_by`]**（§6.2 条 9）。
    #[must_use]
    pub fn by_domain(&self, domain: &EmailDomain) -> Option<&OidcProviderConfig> {
        self.by_domain.get(domain).and_then(|id| self.by_id.get(id))
    }

    /// 全部 provider，按 ID 升序。
    pub fn iter(&self) -> impl Iterator<Item = &OidcProviderConfig> {
        self.by_id.values()
    }

    /// provider 数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否一个 provider 都没有。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
pub(super) mod fixtures {
    //! 测试夹具。`pub(super)` 让同一 oidc 模块树里的兄弟模块复用，不出 crate。

    use super::{
        EntraTenantPolicy, OidcProviderConfig, ProviderId, ProviderKind, ProviderOrigin,
        ProviderRegistry,
    };
    use crate::auth::oidc::email::EmailDomain;
    use crate::auth::oidc::redirect::{CanonicalRedirectUri, HTTPS_ONLY};
    use openidconnect::ClientId;
    use std::collections::BTreeSet;

    /// 造一份配置。
    pub fn config(
        id: &str,
        kind: ProviderKind,
        origin: ProviderOrigin,
        domains: &[&str],
    ) -> OidcProviderConfig {
        OidcProviderConfig::new(
            ProviderId::parse(id).expect("夹具的 ID 必须合法"),
            kind,
            origin,
            ClientId::new(format!("{id}-client")),
            CanonicalRedirectUri::parse("https://app.example.com/auth/callback", HTTPS_ONLY)
                .expect("夹具的 redirect URI 必须合法"),
            domains
                .iter()
                .map(|d| EmailDomain::parse(d).expect("夹具的域名必须合法"))
                .collect::<BTreeSet<_>>(),
            Some("actor-admin".to_owned()),
        )
    }

    /// Okta 形态的 kind（带路径段的 issuer）。
    pub fn okta_kind(issuer: &str) -> ProviderKind {
        ProviderKind::DeploymentOwned {
            issuer: super::parse_issuer(issuer).expect("夹具 issuer 必须合法"),
        }
    }

    /// Entra 形态的 kind。
    pub fn entra_kind(issuer: &str, tenants: EntraTenantPolicy) -> ProviderKind {
        let issuer = super::parse_issuer(issuer).expect("夹具 issuer 必须合法");
        ProviderKind::Entra {
            authority: issuer.clone(),
            issuer,
            tenants,
        }
    }

    /// 三家同时配置的注册表（§6.2 条 1）。
    pub fn three_providers() -> ProviderRegistry {
        ProviderRegistry::build([
            config(
                "google",
                ProviderKind::Google,
                ProviderOrigin::EnvironmentConfigured,
                &["gmail.example"],
            ),
            config(
                "microsoft",
                entra_kind(
                    "https://login.example-entra.test/11111111-2222-3333-4444-555555555555/v2.0",
                    EntraTenantPolicy::IssuerScoped,
                ),
                ProviderOrigin::EnvironmentConfigured,
                &["contoso.example"],
            ),
            config(
                "okta",
                okta_kind("https://example.okta-test.invalid/oauth2/default"),
                ProviderOrigin::EnvironmentConfigured,
                &["acme.example"],
            ),
        ])
        .expect("三家互不冲突")
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{config, entra_kind, okta_kind, three_providers};
    use super::{
        EntraTenantPolicy, GOOGLE_ISSUER, IssuerTrust, ProviderId, ProviderKind, ProviderOrigin,
        ProviderRegistry, parse_issuer,
    };
    use crate::auth::oidc::email::EmailDomain;
    use crate::auth::oidc::error::OidcError;
    use openidconnect::IssuerUrl;
    use std::collections::BTreeSet;
    use url::Url;

    /// [`GOOGLE_ISSUER`] 确实可解析成 [`IssuerUrl`] —— [`ProviderKind::issuer`] 的
    /// `unreachable!` 靠这条兑现。
    #[test]
    fn google_issuer_constant_parses() {
        let issuer = IssuerUrl::new(GOOGLE_ISSUER.to_owned()).expect("常量必须可解析");
        assert_eq!(issuer.as_str(), "https://accounts.google.com");
        assert_eq!(ProviderKind::Google.issuer(), issuer);
    }

    /// 三家同时配置，且 issuer 信任度按种类分档。
    #[test]
    fn all_three_providers_coexist_with_distinct_issuer_trust() {
        let registry = three_providers();
        assert_eq!(registry.len(), 3);

        let google = registry
            .by_id(&ProviderId::parse("google").unwrap())
            .unwrap();
        let microsoft = registry
            .by_id(&ProviderId::parse("microsoft").unwrap())
            .unwrap();
        let okta = registry.by_id(&ProviderId::parse("okta").unwrap()).unwrap();

        assert_eq!(google.kind().issuer_trust(), IssuerTrust::Pinned);
        assert_eq!(
            microsoft.kind().issuer_trust(),
            IssuerTrust::AdministratorSupplied
        );
        assert_eq!(
            okta.kind().issuer_trust(),
            IssuerTrust::AdministratorSupplied
        );

        // Okta 的 issuer 带路径段 —— 这正是它必须走 discovery 的理由。
        assert_eq!(
            okta.issuer().as_str(),
            "https://example.okta-test.invalid/oauth2/default"
        );
        // 只有 Entra 有租户策略。
        assert!(google.kind().entra_tenants().is_none());
        assert!(okta.kind().entra_tenants().is_none());
        assert!(microsoft.kind().entra_tenants().is_some());
    }

    /// Google 变体在**类型上**没有 issuer 字段：管理员无处填入别的主机。
    ///
    /// 断言方式是行为等价的：无论怎么构造 `ProviderKind::Google`，`issuer()` 恒为常量。
    #[test]
    fn the_google_variant_carries_no_administrator_supplied_issuer() {
        assert_eq!(ProviderKind::Google.issuer().as_str(), GOOGLE_ISSUER);
        // 正向对照：另外两个变体确实会把管理员给的值原样带出来 —— 否则上一条在
        //「issuer() 恒返回常量」的世界里同样通过。
        assert_eq!(
            okta_kind("https://example.okta-test.invalid/oauth2/default")
                .issuer()
                .as_str(),
            "https://example.okta-test.invalid/oauth2/default"
        );
    }

    /// 上游行为实测：`IssuerUrl::new` 不执行它文档里声称的形态约束。
    ///
    /// 这条既是证据记录，也是 [`parse_issuer`] 存在的理由。
    #[test]
    fn openidconnect_issuer_url_does_not_enforce_its_documented_shape() {
        // 文档说「https scheme with no query or fragment」，实测三样都放行。
        assert!(IssuerUrl::new("http://plain.example".to_owned()).is_ok());
        assert!(IssuerUrl::new("https://idp.example?x=1".to_owned()).is_ok());
        assert!(IssuerUrl::new("https://idp.example#frag".to_owned()).is_ok());

        // 我们自己的闸门把三样都拒掉。
        assert_eq!(
            parse_issuer("http://plain.example"),
            Err(OidcError::IssuerNotHttps)
        );
        assert_eq!(
            parse_issuer("https://idp.example?x=1"),
            Err(OidcError::IssuerNotBare)
        );
        assert_eq!(
            parse_issuer("https://idp.example#frag"),
            Err(OidcError::IssuerNotBare)
        );
        assert_eq!(
            parse_issuer("https://user@idp.example"),
            Err(OidcError::IssuerNotBare)
        );
        assert_eq!(
            parse_issuer("mailto:someone@example.com"),
            Err(OidcError::IssuerNotBare)
        );

        // 正向对照：合法 issuer（含带路径段的 Okta 形态）照常通过。
        assert!(parse_issuer(GOOGLE_ISSUER).is_ok());
        assert!(parse_issuer("https://example.okta-test.invalid/oauth2/default").is_ok());
    }

    /// `url` crate 会给空路径补一条 `/`，所以 issuer 不能套 redirect URI 那种往返闸门。
    #[test]
    fn the_url_crate_adds_a_trailing_slash_which_is_why_issuers_skip_the_roundtrip_gate() {
        let parsed = Url::parse(GOOGLE_ISSUER).unwrap();
        assert_eq!(
            parsed.as_str(),
            "https://accounts.google.com/",
            "url crate 补了斜杠；套往返闸门会把 Google 的正确 issuer 判非法"
        );
        assert_ne!(parsed.as_str(), GOOGLE_ISSUER);

        // 而 `IssuerUrl` 保留原串 —— 与 `iss` claim 逐字节比对靠的就是这一点。
        assert_eq!(
            IssuerUrl::new(GOOGLE_ISSUER.to_owned()).unwrap().as_str(),
            GOOGLE_ISSUER
        );
    }

    /// 域名抢注 fail-closed。
    #[test]
    fn two_providers_claiming_one_domain_is_refused() {
        let result = ProviderRegistry::build([
            config(
                "okta",
                okta_kind("https://a.okta-test.invalid/oauth2/default"),
                ProviderOrigin::EnvironmentConfigured,
                &["acme.example"],
            ),
            config(
                "acme-sso",
                okta_kind("https://b.okta-test.invalid/oauth2/default"),
                ProviderOrigin::DynamicallyRegistered,
                &["acme.example"],
            ),
        ]);
        assert_eq!(result.unwrap_err(), OidcError::DomainConflict);

        // 正向对照：换成不同域名就建得起来。
        assert!(
            ProviderRegistry::build([
                config(
                    "okta",
                    okta_kind("https://a.okta-test.invalid/oauth2/default"),
                    ProviderOrigin::EnvironmentConfigured,
                    &["acme.example"],
                ),
                config(
                    "acme-sso",
                    okta_kind("https://b.okta-test.invalid/oauth2/default"),
                    ProviderOrigin::DynamicallyRegistered,
                    &["other.example"],
                ),
            ])
            .is_ok()
        );
    }

    /// 同 ID 登记两次 fail-closed，不静默覆盖。
    #[test]
    fn a_duplicate_provider_id_is_refused_not_overwritten() {
        let result = ProviderRegistry::build([
            config(
                "okta",
                okta_kind("https://a.okta-test.invalid/oauth2/default"),
                ProviderOrigin::EnvironmentConfigured,
                &["acme.example"],
            ),
            config(
                "okta",
                okta_kind("https://evil.okta-test.invalid/oauth2/default"),
                ProviderOrigin::DynamicallyRegistered,
                &["other.example"],
            ),
        ]);
        assert_eq!(result.unwrap_err(), OidcError::ProviderIdConflict);
    }

    /// §6.2 条 9：登记者离开后 provider 仍然可路由。
    ///
    /// 上游的失效模式是行随登记者的用户行级联删除 —— 这里的对应断言是「查找路径不读
    /// `registered_by`」，用 `None` 与 `Some` 两种登记者各建一次表、要求结果相同来证明。
    #[test]
    fn a_provider_whose_registrant_is_gone_is_still_routable() {
        let domain = EmailDomain::parse("acme.example").unwrap();

        let with_registrant = config(
            "okta",
            okta_kind("https://example.okta-test.invalid/oauth2/default"),
            ProviderOrigin::DynamicallyRegistered,
            &["acme.example"],
        );
        assert_eq!(with_registrant.registered_by(), Some("actor-admin"));

        let mut orphaned = with_registrant.clone();
        orphaned.registered_by = None;

        let a = ProviderRegistry::build([with_registrant]).unwrap();
        let b = ProviderRegistry::build([orphaned]).unwrap();

        let via_a = a.by_domain(&domain).expect("有登记者时可路由");
        let via_b = b.by_domain(&domain).expect("登记者离开后仍必须可路由");
        assert_eq!(via_a.id(), via_b.id());
        assert_eq!(via_a.issuer(), via_b.issuer());
        assert_eq!(via_b.registered_by(), None);
    }

    /// provider ID 形态闸门：正负各一组。
    #[test]
    fn provider_ids_are_shape_checked() {
        for good in ["google", "okta", "acme-sso", "sso_2", "a", &"x".repeat(64)] {
            assert!(ProviderId::parse(good).is_ok(), "{good} 应当合法");
        }
        for bad in [
            "",
            "Google",   // 大写不做归一，直接拒
            "-leading", // 首字符必须是字母或数字
            "_leading",
            "has space",
            "has/slash",
            "emoji\u{1F600}",
            &"x".repeat(65),
        ] {
            assert_eq!(
                ProviderId::parse(bad),
                Err(OidcError::ProviderIdMalformed),
                "{bad:?} 应当被拒"
            );
        }
    }

    /// Entra 租户策略：名单档缺 `tid` 拒、名单外拒、名单内接受；issuer 档一律接受。
    #[test]
    fn the_entra_tenant_policy_is_fail_closed_only_in_the_allow_list_mode() {
        let allowed: BTreeSet<String> = ["tenant-a".to_owned()].into_iter().collect();
        let list = EntraTenantPolicy::AllowList(allowed);

        assert!(list.accepts(Some("tenant-a")), "名单内必须接受");
        assert!(!list.accepts(Some("tenant-b")), "名单外必须拒绝");
        assert!(!list.accepts(None), "拿不到 tid 就无法证明它在名单里");

        // 正向对照：issuer 档不额外限制，所以「恒拒」不是本函数的行为。
        let scoped = EntraTenantPolicy::IssuerScoped;
        assert!(scoped.accepts(Some("tenant-b")));
        assert!(scoped.accepts(None));

        // 该策略只挂在 Entra 变体上。
        assert_eq!(
            entra_kind(
                "https://idp.example/tenant/v2.0",
                EntraTenantPolicy::IssuerScoped
            )
            .entra_tenants(),
            Some(&EntraTenantPolicy::IssuerScoped)
        );
    }
}
