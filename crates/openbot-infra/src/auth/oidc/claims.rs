//! ID token 校验与 Entra 的地址解析（v3 §6.2 条 3 的后半 + 条 5）。
//!
//! # 签名 / `iss` / `aud` / 时间窗 / `nonce` 交给库，租户与地址留给我们
//!
//! 这五项由 `openidconnect` 的 `IdTokenVerifier` 执行 —— 它按 OpenID Connect Core §3.1.3.7
//! 逐条走，而且有一处我们照抄不来的严谨：`JwtClaimsVerifier::verified_payload` 的注释写明
//! 「We must *not* trust the 'kid' or 'alg' fields present in the JOSE header, as an attacker
//! could manipulate these」，算法只从**我们给定的 allowlist** 里选。自己重写一遍只会得到
//! 一个更差的实现。
//!
//! 留在本模块的是两条库不知道的判定：
//!
//! 1. **租户策略**（[`super::provider::EntraTenantPolicy`]）—— `tid` 不是标准 claim，
//!    库不认识它；
//! 2. **地址解析**（[`resolve_directory_email`]）—— `email → upn → preferred_username`
//!    这条链是 Entra 特有的现实妥协，见下。
//!
//! # 算法 allowlist 由**我们**钉，不由 IdP 也不由 token 说了算
//!
//! [`DEFAULT_ID_TOKEN_SIGNING_ALGS`] 只有 RS256（也正是 `JwtClaimsVerifier::new` 的默认值）。
//! 刻意**不**从 discovery 文档的 `id_token_signing_alg_values_supported` 推导：那等于让被
//! 验证的一方决定用什么强度验证自己。也刻意不用库的 `allow_any_alg()`。
//!
//! # Entra 的 `email → upn → preferred_username`
//!
//! 上游 `server/src/auth/index.ts::mapEntraProfile` 的注释解释了这条链的来历：Entra 只在
//! profile 带 email 属性时才发 `email`，而多租户应用（默认 tenant `common`）下，外部用户的
//! token 由他们自己的租户签发，**不继承本应用的 optional claim 配置**，于是 `email` 常常
//! 根本不来。而这个部署对一个人的**每一条授权判定都以地址为键**（`INITIAL_ADMIN_EMAILS`、
//! role、deny list、People 页），地址缺失不是外观问题。
//!
//! 三个都拿不到时**拒绝登录**，逐字照搬上游那条裁决：「being refused is a far better answer
//! than being quietly admitted as somebody the deployment cannot recognise」。
//!
//! 判据是「值里含 `@`」（上游 `claim` 闭包：`typeof value === "string" && value.includes("@")`）。
//! 它宽松得刺眼，但收紧它是一次**产品**决定 —— OIDC 规范并不保证 `preferred_username` 是
//! 地址，收紧的那一刻，一批今天能登录的人会开始被拒。见 [`super::email::claim_looks_like_an_address`]。
//!
//! W-7b 的固定 `samael` 图已经把 `chrono` 变成直接依赖；生产协调器因此改用
//! [`build_verifier_at`]，把本次 callback 的 `OffsetDateTime` 精确注入 ID-token verifier。
//! [`build_verifier`] 仍保留给需要系统时钟的通用调用点与既有测试，不再把依赖缺口写成事实。

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use openidconnect::core::{
    CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AdditionalClaims, ClientSecret, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeySet, Nonce,
    SubjectIdentifier,
};

use super::email::claim_looks_like_an_address;
use super::error::OidcError;
use super::provider::{OidcProviderConfig, ProviderKind};
use openbot_domain::identity::groups::{
    GroupName, GroupNormalization, IdpGroupMapping, resolve_group_claims,
};

const MAX_VERIFIED_CLAIMS_BYTES: usize = 256 * 1024;

/// 本模块接受的 ID token 签名算法。
///
/// 只有 RS256 —— Google / Entra / Okta 的默认值，也是 OpenID Connect Core §3.1.3.7 条 7 说的
/// 「SHOULD be the default of RS256」。要加别的算法是一次显式决定：把它写进调用点的参数，
/// 而不是改这个常量。
pub const DEFAULT_ID_TOKEN_SIGNING_ALGS: &[CoreJwsSigningAlgorithm] =
    &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256];

/// 标准 claim 之外，目录型 IdP 会带的两个。
///
/// 只收这两个而不是一张 `Map<String, Value>`：把整份 token 的未知 claim 都留下来，等于给
/// 下游一个「随手读一个没验证过语义的字段」的诱惑，而每一个这样的读法都是一次隐式契约。
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct DirectoryClaims {
    /// Entra 的 User Principal Name。目录自己对这个账号的称呼。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upn: Option<String>,
    /// Entra 的租户标识。[`super::provider::EntraTenantPolicy`] 的判定对象。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
}

impl AdditionalClaims for DirectoryClaims {}

/// 带 [`DirectoryClaims`] 的 ID token claims。
pub type DirectoryIdTokenClaims = IdTokenClaims<DirectoryClaims, CoreGenderClaim>;

/// 带 [`DirectoryClaims`] 的 ID token。
pub type DirectoryIdToken = IdToken<
    DirectoryClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// 一次成功校验之后，能用来建立身份的最小事实集。
///
/// 刻意**不**把整份 claims 带出去：带出去下游就会开始读别的字段，而那些字段没有经过本模块
/// 的任何判定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    issuer: IssuerUrl,
    subject: SubjectIdentifier,
    email: String,
    groups: BTreeSet<GroupName>,
    group_normalization: GroupNormalization,
    group_claim_present: bool,
}

impl VerifiedIdentity {
    /// 签发这份 token 的 issuer（已由验证器逐字节比对过）。
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    /// `sub` claim —— IdP 内部对这个账号的不变标识。
    #[must_use]
    pub const fn subject(&self) -> &SubjectIdentifier {
        &self.subject
    }

    /// 解析出来的地址。
    ///
    /// **它还不是规范化 email**：规范化是 `openbot_domain::identity` 的判定，这里只保证
    /// 它是三条 claim 里第一个含 `@` 的那个值。
    ///
    /// > 集成待办：交给 `openbot_domain::identity::email` 规范化后再用于任何授权判定。
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// 已按该 provider 显式规则规范化的 groups；无 mapping 时为空。
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<GroupName> {
        &self.groups
    }

    #[must_use]
    pub const fn group_normalization(&self) -> GroupNormalization {
        self.group_normalization
    }

    /// mapping 路径在 token 中是否存在；与“存在但空数组”分开。
    #[must_use]
    pub const fn group_claim_present(&self) -> bool {
        self.group_claim_present
    }
}

/// 组一个 ID token 验证器。
///
/// `client_secret` 为 `Some` 时走 confidential client（这是接受 HS256 之类共享密钥算法的
/// **前提**：库对 public client 直接拒绝对称签名，理由写在 `JwtClaimsVerifier::verified_payload`
/// 里 ——「anyone can forge a JWT with a valid signature」）。
///
/// 返回的验证器用**系统时钟**判 `exp` / `iat`，理由见模块文档。
#[must_use]
pub fn build_verifier<'a>(
    provider: &OidcProviderConfig,
    client_secret: Option<&ClientSecret>,
    keys: JsonWebKeySet<CoreJsonWebKey>,
    allowed_algs: &[CoreJwsSigningAlgorithm],
) -> CoreIdTokenVerifier<'a> {
    let client_id = provider.client_id().clone();
    let issuer = provider.issuer();

    let verifier = match client_secret {
        Some(secret) => {
            CoreIdTokenVerifier::new_confidential_client(client_id, secret.clone(), issuer, keys)
        }
        None => CoreIdTokenVerifier::new_public_client(client_id, issuer, keys),
    };

    // `alg: none` 即使被误列进来也不放行：一个没有签名的 ID token 不是「弱」，是「没有」。
    let algs: Vec<CoreJwsSigningAlgorithm> = allowed_algs
        .iter()
        .filter(|alg| !matches!(alg, CoreJwsSigningAlgorithm::None))
        .cloned()
        .collect();

    verifier.set_allowed_algs(algs)
}

/// 用调用方时钟构造 verifier；生产 callback 使用，避免 exp/iat 判定偷偷另读一次墙钟。
pub fn build_verifier_at<'a>(
    provider: &OidcProviderConfig,
    client_secret: Option<&ClientSecret>,
    keys: JsonWebKeySet<CoreJsonWebKey>,
    allowed_algs: &[CoreJwsSigningAlgorithm],
    now: time::OffsetDateTime,
) -> Result<CoreIdTokenVerifier<'a>, OidcError> {
    let now = chrono::DateTime::from_timestamp(now.unix_timestamp(), now.nanosecond())
        .ok_or(OidcError::IdTokenRejected)?;
    Ok(build_verifier(provider, client_secret, keys, allowed_algs).set_time_fn(move || now))
}

/// 用一个已建好的验证器校验 ID token，并收敛出 [`VerifiedIdentity`]。
///
/// 判定顺序：解析 → 库的五项校验 → 租户策略 → 地址解析。租户在地址之前，因为「你不属于
/// 这个部署认的租户」比「你的地址取不到」是更外层的拒绝理由。
///
/// # Errors
///
/// - [`OidcError::IdTokenMalformed`]：不是一个能解开的 JWT；
/// - [`OidcError::IdTokenRejected`]：签名 / `iss` / `aud` / 时间窗 / `nonce` 有一项不过
///   （**五项共用一个码**，见该变体的文档：分开回答等于给攻击者一台逐项试错的仪器）；
/// - [`OidcError::TenantNotAllowed`]：`tid` 不在该 provider 的允许集内；
/// - [`OidcError::EmailClaimMissing`]：`email` / `upn` / `preferred_username` 都拿不到地址。
pub fn verify_with(
    raw_id_token: &str,
    verifier: &CoreIdTokenVerifier<'_>,
    provider: &OidcProviderConfig,
    nonce: &Nonce,
) -> Result<VerifiedIdentity, OidcError> {
    verify_with_group_mapping(raw_id_token, verifier, provider, nonce, None)
}

/// 在标准 token 验证成功后，于**同一份已签名 payload**上解析 provider 专属 group mapping。
pub fn verify_with_group_mapping(
    raw_id_token: &str,
    verifier: &CoreIdTokenVerifier<'_>,
    provider: &OidcProviderConfig,
    nonce: &Nonce,
    group_mapping: Option<&IdpGroupMapping>,
) -> Result<VerifiedIdentity, OidcError> {
    let token: DirectoryIdToken = raw_id_token
        .parse()
        .map_err(|_| OidcError::IdTokenMalformed)?;

    let claims = token
        .claims(verifier, nonce)
        .map_err(|_| OidcError::IdTokenRejected)?;

    if let ProviderKind::Entra { tenants, .. } = provider.kind()
        && !tenants.accepts(claims.additional_claims().tid.as_deref())
    {
        return Err(OidcError::TenantNotAllowed);
    }

    let email = resolve_directory_email(claims)?;

    let (groups, group_normalization, group_claim_present) = match group_mapping {
        None => (BTreeSet::new(), GroupNormalization::Exact, false),
        Some(mapping) => {
            if mapping.provider().as_str() != provider.id().as_str() {
                return Err(OidcError::GroupMappingMismatch);
            }
            let payload = verified_payload_json(raw_id_token)?;
            let resolved = resolve_group_claims(&payload, mapping)
                .map_err(|_| OidcError::GroupClaimRejected)?;
            (
                resolved.groups().clone(),
                mapping.normalization(),
                resolved.claim_present(),
            )
        }
    };

    Ok(VerifiedIdentity {
        issuer: claims.issuer().clone(),
        subject: claims.subject().clone(),
        email,
        groups,
        group_normalization,
        group_claim_present,
    })
}

fn verified_payload_json(raw_id_token: &str) -> Result<serde_json::Value, OidcError> {
    let mut segments = raw_id_token.split('.');
    let _header = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    let payload = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    let _signature = segments.next().ok_or(OidcError::IdTokenMalformed)?;
    if segments.next().is_some() || payload.len() > MAX_VERIFIED_CLAIMS_BYTES * 2 {
        return Err(OidcError::IdTokenMalformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| OidcError::IdTokenMalformed)?;
    if decoded.len() > MAX_VERIFIED_CLAIMS_BYTES {
        return Err(OidcError::IdTokenMalformed);
    }
    serde_json::from_slice(&decoded).map_err(|_| OidcError::IdTokenMalformed)
}

#[derive(Deserialize)]
struct EntraIssuerClaims {
    iss: String,
    tid: String,
}

/// 按 Microsoft tenant-independent metadata 规则，把不可信 `iss/tid` 先收敛成一个候选
/// concrete issuer；随后必须用该 issuer 构造 verifier 对**同一原始 JWT**验签。
pub(crate) fn validate_entra_token_issuer(
    raw_id_token: &str,
    provider: &OidcProviderConfig,
    signing_key_issuer: &str,
) -> Result<IssuerUrl, OidcError> {
    let ProviderKind::Entra { tenants, .. } = provider.kind() else {
        return Err(OidcError::IdTokenRejected);
    };
    let claims: EntraIssuerClaims = serde_json::from_value(verified_payload_json(raw_id_token)?)
        .map_err(|_| OidcError::IdTokenRejected)?;
    if !tenants.accepts(Some(&claims.tid)) {
        return Err(OidcError::TenantNotAllowed);
    }
    let parsed_tid = uuid::Uuid::parse_str(&claims.tid).map_err(|_| OidcError::IdTokenRejected)?;
    if parsed_tid.hyphenated().to_string() != claims.tid {
        return Err(OidcError::IdTokenRejected);
    }

    let expected = substitute_tenant_template(provider.issuer().as_str(), &claims.tid)
        .unwrap_or_else(|| provider.issuer().as_str().to_owned());
    if expected != claims.iss {
        return Err(OidcError::IdTokenRejected);
    }
    let key_expected = substitute_tenant_template(signing_key_issuer, &claims.tid)
        .unwrap_or_else(|| signing_key_issuer.to_owned());
    if key_expected != claims.iss {
        return Err(OidcError::IdTokenRejected);
    }
    super::provider::parse_issuer(&claims.iss).map_err(|_| OidcError::IdTokenRejected)
}

fn substitute_tenant_template(template: &str, tenant: &str) -> Option<String> {
    let lower = template.to_ascii_lowercase();
    for marker in ["{tenantid}", "%7btenantid%7d"] {
        if let Some(start) = lower.find(marker) {
            let end = start + marker.len();
            let mut replaced = String::with_capacity(template.len() - marker.len() + tenant.len());
            replaced.push_str(&template[..start]);
            replaced.push_str(tenant);
            replaced.push_str(&template[end..]);
            return Some(replaced);
        }
    }
    None
}

/// [`build_verifier`] + [`verify_with`] 的便利组合。
///
/// 用系统时钟判 `exp` / `iat`（模块文档解释了为什么这里注入不了时钟）。
///
/// # Errors
///
/// 同 [`verify_with`]。
pub fn verify_id_token(
    raw_id_token: &str,
    provider: &OidcProviderConfig,
    client_secret: Option<&ClientSecret>,
    keys: JsonWebKeySet<CoreJsonWebKey>,
    nonce: &Nonce,
    allowed_algs: &[CoreJwsSigningAlgorithm],
) -> Result<VerifiedIdentity, OidcError> {
    let verifier = build_verifier(provider, client_secret, keys, allowed_algs);
    verify_with(raw_id_token, &verifier, provider, nonce)
}

/// 按 `email → upn → preferred_username` 取地址。
///
/// 语义逐条对齐上游 `server/src/auth/index.ts::mapEntraProfile`：每个候选都要「是字符串
/// 且含 `@`」才算数，顺序固定，三个都不算数就失败。
///
/// # Errors
///
/// 三条 claim 都给不出含 `@` 的值时返回 [`OidcError::EmailClaimMissing`]。
pub fn resolve_directory_email(claims: &DirectoryIdTokenClaims) -> Result<String, OidcError> {
    let candidates = [
        claims.email().map(|value| value.as_str()),
        claims.additional_claims().upn.as_deref(),
        claims.preferred_username().map(|value| value.as_str()),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|value| claim_looks_like_an_address(value))
        .map(ToOwned::to_owned)
        .ok_or(OidcError::EmailClaimMissing)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_ID_TOKEN_SIGNING_ALGS, DirectoryClaims, DirectoryIdToken, DirectoryIdTokenClaims,
        build_verifier, resolve_directory_email, verify_with, verify_with_group_mapping,
    };
    use crate::auth::oidc::error::OidcError;
    use crate::auth::oidc::provider::fixtures::{config, entra_kind, okta_kind};
    use crate::auth::oidc::provider::{
        EntraTenantPolicy, OidcProviderConfig, ProviderKind, ProviderOrigin,
    };
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use openbot_domain::identity::groups::{
        GroupClaimPath, GroupNormalization, IdentityProviderId, IdpGroupMapping,
    };
    use openidconnect::core::{CoreHmacKey, CoreIdTokenVerifier, CoreJwsSigningAlgorithm};
    use openidconnect::{ClientSecret, JsonWebKeySet, Nonce};
    use sha2::Sha256;
    use std::collections::BTreeSet;

    const ISSUER: &str = "https://example.okta-test.invalid/oauth2/default";
    const SECRET: &str = "a-shared-client-secret-for-tests";
    /// 远未到期（2286 年）。
    const FAR_FUTURE: i64 = 9_999_999_999;
    /// 早已过期（2001 年）。
    const LONG_PAST: i64 = 1_000_000_000;
    /// 测试用「此刻」（2027 年前后），介于两者之间。
    const NOW: i64 = 1_800_000_000;

    fn okta_provider() -> OidcProviderConfig {
        config(
            "okta",
            okta_kind(ISSUER),
            ProviderOrigin::EnvironmentConfigured,
            &["acme.example"],
        )
    }

    fn entra_provider(tenants: EntraTenantPolicy) -> OidcProviderConfig {
        config(
            "microsoft",
            entra_kind(ISSUER, tenants),
            ProviderOrigin::EnvironmentConfigured,
            &["contoso.example"],
        )
    }

    /// 用 serde 造 claims，从而**不必命名** `chrono::DateTime<Utc>`（它不在依赖面上）。
    fn claims_json(
        issuer: &str,
        audience: &str,
        exp: i64,
        nonce: Option<&str>,
        extra: &str,
    ) -> String {
        let nonce_field = nonce.map_or(String::new(), |n| format!(r#""nonce":"{n}","#));
        format!(
            r#"{{"iss":"{issuer}","aud":["{audience}"],"exp":{exp},"iat":{NOW},"sub":"subject-1",{nonce_field}{extra}}}"#
        )
    }

    fn parse_claims(json: &str) -> DirectoryIdTokenClaims {
        serde_json::from_str(json).expect("夹具 claims 必须可解析")
    }

    /// 用 HS256 签一份 ID token。
    ///
    /// 走对称算法是因为它让整条验证链（签名 + `iss` + `aud` + 时间窗 + `nonce`）在**不引入
    /// 任何密钥材料夹具**的前提下真实跑起来；库对 public client 拒绝对称签名，所以这些用例
    /// 必然走 confidential client 分支。
    fn sign(claims: &DirectoryIdTokenClaims) -> String {
        let key = CoreHmacKey::new(SECRET);
        DirectoryIdToken::new(
            claims.clone(),
            &key,
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
        .expect("签名不该失败")
        .to_string()
    }

    /// 保留任意 provider claim 的 HS256 JWT；`DirectoryIdToken::new` 会先把未知字段过滤掉，
    /// 因而不能用来测试动态 group path。
    fn sign_raw(claims_json: &str) -> String {
        let header = super::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = super::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = super::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{signature}")
    }

    /// 一个把「此刻」钉死在 `NOW` 的验证器 —— 时间来自一份 `exp == NOW` 的 claims，
    /// 于是无需命名 `DateTime<Utc>` 就能拿到那个类型的值。
    fn verifier_at_now(provider: &OidcProviderConfig) -> CoreIdTokenVerifier<'static> {
        let anchor = parse_claims(&claims_json(ISSUER, "okta-client", NOW, None, r#""x":1"#));
        let now = anchor.expiration();
        build_verifier(
            provider,
            Some(&ClientSecret::new(SECRET.to_owned())),
            JsonWebKeySet::new(Vec::new()),
            &[CoreJwsSigningAlgorithm::HmacSha256],
        )
        .set_time_fn(move || now)
    }

    fn good_claims() -> DirectoryIdTokenClaims {
        parse_claims(&claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example""#,
        ))
    }

    /// 正向对照（本文件里所有负向断言都靠它）：一份好 token 是被接受的。
    #[test]
    fn a_good_token_is_accepted() {
        let provider = okta_provider();
        let identity = verify_with(
            &sign(&good_claims()),
            &verifier_at_now(&provider),
            &provider,
            &Nonce::new("nonce-1".to_owned()),
        )
        .expect("好 token 必须被接受");

        assert_eq!(identity.email(), "someone@acme.example");
        assert_eq!(identity.subject().as_str(), "subject-1");
        assert_eq!(identity.issuer().as_str(), ISSUER);
        assert!(identity.groups().is_empty());
        assert!(!identity.group_claim_present());
    }

    #[test]
    fn groups_are_resolved_only_after_token_verification_with_the_bound_mapping() {
        let provider = okta_provider();
        let claims = claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example","resource_access":{"roles":[" Finance ","Risk","Finance"]}"#,
        );
        let raw = sign_raw(&claims);
        let mapping = IdpGroupMapping::new(
            IdentityProviderId::new("okta"),
            GroupClaimPath::from_dotted("resource_access.roles").unwrap(),
            GroupNormalization::TrimLowercase,
        );
        let identity = verify_with_group_mapping(
            &raw,
            &verifier_at_now(&provider),
            &provider,
            &Nonce::new("nonce-1".to_owned()),
            Some(&mapping),
        )
        .unwrap();
        let groups: Vec<&str> = identity
            .groups()
            .iter()
            .map(|group| group.as_str())
            .collect();
        assert_eq!(groups, vec!["finance", "risk"]);
        assert_eq!(
            identity.group_normalization(),
            GroupNormalization::TrimLowercase
        );
        assert!(identity.group_claim_present());

        let wrong_provider = IdpGroupMapping::new(
            IdentityProviderId::new("another-provider"),
            GroupClaimPath::from_dotted("resource_access.roles").unwrap(),
            GroupNormalization::Exact,
        );
        assert_eq!(
            verify_with_group_mapping(
                &raw,
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned()),
                Some(&wrong_provider),
            ),
            Err(OidcError::GroupMappingMismatch)
        );
    }

    #[test]
    fn a_bad_group_shape_rejects_the_login_instead_of_inventing_memberships() {
        let provider = okta_provider();
        let raw = sign_raw(&claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example","groups":["risk",42]"#,
        ));
        let mapping = IdpGroupMapping::new(
            IdentityProviderId::new("okta"),
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::Exact,
        );
        assert_eq!(
            verify_with_group_mapping(
                &raw,
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned()),
                Some(&mapping),
            ),
            Err(OidcError::GroupClaimRejected)
        );
    }

    #[test]
    fn entra_tenant_template_binds_tid_token_issuer_and_signing_key_issuer_exactly() {
        let authority = crate::auth::oidc::provider::parse_issuer(
            "https://login.microsoftonline.com/common/v2.0",
        )
        .unwrap();
        let template = crate::auth::oidc::provider::parse_issuer(
            "https://login.microsoftonline.com/{tenantid}/v2.0",
        )
        .unwrap();
        let provider = OidcProviderConfig::new(
            crate::auth::oidc::ProviderId::parse("microsoft").unwrap(),
            ProviderKind::Entra {
                authority,
                issuer: template,
                tenants: EntraTenantPolicy::TenantIndependent {
                    allow_personal: true,
                },
            },
            ProviderOrigin::EnvironmentConfigured,
            openidconnect::ClientId::new("microsoft-client".to_owned()),
            crate::auth::oidc::CanonicalRedirectUri::parse(
                "https://app.example.com/auth/callback",
                crate::auth::oidc::redirect::HTTPS_ONLY,
            )
            .unwrap(),
            BTreeSet::new(),
            None,
        );
        let tid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let issuer = format!("https://login.microsoftonline.com/{tid}/v2.0");
        let raw = sign_raw(&claims_json(
            &issuer,
            "microsoft-client",
            FAR_FUTURE,
            Some("nonce-1"),
            &format!(r#""email":"person@example.com","tid":"{tid}""#),
        ));
        let concrete = super::validate_entra_token_issuer(
            &raw,
            &provider,
            "https://login.microsoftonline.com/{tenantid}/v2.0",
        )
        .unwrap();
        assert_eq!(concrete.as_str(), issuer);

        for bad_key_issuer in [
            "https://login.microsoftonline.com/ffffffff-ffff-4fff-8fff-ffffffffffff/v2.0",
            "https://evil.example/{tenantid}/v2.0",
            "",
        ] {
            assert_eq!(
                super::validate_entra_token_issuer(&raw, &provider, bad_key_issuer),
                Err(OidcError::IdTokenRejected)
            );
        }
    }

    #[test]
    fn entra_tenant_independent_policy_rejects_noncanonical_and_personal_when_organizations_only() {
        let organizations = EntraTenantPolicy::TenantIndependent {
            allow_personal: false,
        };
        assert!(organizations.accepts(Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")));
        assert!(!organizations.accepts(Some(crate::auth::oidc::MICROSOFT_CONSUMER_TENANT_ID)));
        assert!(!organizations.accepts(Some("not-a-guid")));
        assert!(!organizations.accepts(Some("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")));
        assert!(!organizations.accepts(None));
    }

    /// 负向：签名被换过的 token 被拒。
    #[test]
    fn a_token_signed_with_another_secret_is_rejected() {
        let provider = okta_provider();
        let forged = DirectoryIdToken::new(
            good_claims(),
            &CoreHmacKey::new("a-different-secret-entirely"),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
        .unwrap()
        .to_string();

        assert_eq!(
            verify_with(
                &forged,
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .err(),
            Some(OidcError::IdTokenRejected)
        );
    }

    /// 负向：`iss` / `aud` / `nonce` / `exp` 各错一项都被拒；四项共用一个码。
    #[test]
    fn issuer_audience_nonce_and_expiry_are_each_enforced() {
        let provider = okta_provider();
        let verifier = verifier_at_now(&provider);
        let right_nonce = Nonce::new("nonce-1".to_owned());

        // iss 不对。
        let wrong_issuer = sign(&parse_claims(&claims_json(
            "https://evil.example",
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example""#,
        )));
        assert_eq!(
            verify_with(&wrong_issuer, &verifier, &provider, &right_nonce).err(),
            Some(OidcError::IdTokenRejected)
        );

        // aud 不对。
        let wrong_audience = sign(&parse_claims(&claims_json(
            ISSUER,
            "someone-elses-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example""#,
        )));
        assert_eq!(
            verify_with(&wrong_audience, &verifier, &provider, &right_nonce).err(),
            Some(OidcError::IdTokenRejected)
        );

        // nonce 不对。
        assert_eq!(
            verify_with(
                &sign(&good_claims()),
                &verifier,
                &provider,
                &Nonce::new("someone-elses-nonce".to_owned())
            )
            .err(),
            Some(OidcError::IdTokenRejected)
        );

        // nonce 缺失（`impl NonceVerifier for &Nonce` 对缺失 claim 也判错）。
        let no_nonce = sign(&parse_claims(&claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            None,
            r#""email":"someone@acme.example""#,
        )));
        assert_eq!(
            verify_with(&no_nonce, &verifier, &provider, &right_nonce).err(),
            Some(OidcError::IdTokenRejected)
        );

        // 已过期。
        let expired = sign(&parse_claims(&claims_json(
            ISSUER,
            "okta-client",
            LONG_PAST,
            Some("nonce-1"),
            r#""email":"someone@acme.example""#,
        )));
        assert_eq!(
            verify_with(&expired, &verifier, &provider, &right_nonce).err(),
            Some(OidcError::IdTokenRejected)
        );

        // 正向对照：同一个 verifier 仍然接受那份好 token。
        assert!(verify_with(&sign(&good_claims()), &verifier, &provider, &right_nonce).is_ok());
    }

    /// 负向：算法 allowlist 之外的签名被拒 —— 默认档只认 RS256。
    #[test]
    fn an_algorithm_outside_the_allowlist_is_rejected() {
        let provider = okta_provider();
        let anchor = parse_claims(&claims_json(ISSUER, "okta-client", NOW, None, r#""x":1"#));
        let now = anchor.expiration();

        let rs256_only = build_verifier(
            &provider,
            Some(&ClientSecret::new(SECRET.to_owned())),
            JsonWebKeySet::new(Vec::new()),
            DEFAULT_ID_TOKEN_SIGNING_ALGS,
        )
        .set_time_fn(move || now);

        assert_eq!(
            verify_with(
                &sign(&good_claims()),
                &rs256_only,
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .err(),
            Some(OidcError::IdTokenRejected),
            "HS256 不在默认 allowlist 里"
        );

        // 正向对照：显式允许 HS256 之后同一份 token 就过了 —— 证明上一条拒的是算法，
        // 不是别的什么。
        assert!(
            verify_with(
                &sign(&good_claims()),
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .is_ok()
        );
    }

    /// `alg: none` 即使被误列进 allowlist 也不放行。
    #[test]
    fn the_none_algorithm_is_filtered_out_of_the_allowlist() {
        let provider = okta_provider();
        let anchor = parse_claims(&claims_json(ISSUER, "okta-client", NOW, None, r#""x":1"#));
        let now = anchor.expiration();

        // 只把 `None` 放进来：过滤之后 allowlist 为空，任何签名算法都不匹配。
        let only_none = build_verifier(
            &provider,
            Some(&ClientSecret::new(SECRET.to_owned())),
            JsonWebKeySet::new(Vec::new()),
            &[CoreJwsSigningAlgorithm::None],
        )
        .set_time_fn(move || now);

        assert_eq!(
            verify_with(
                &sign(&good_claims()),
                &only_none,
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .err(),
            Some(OidcError::IdTokenRejected)
        );
    }

    /// 负向：解不开的字符串落 `IdTokenMalformed`，与「解得开但不过」是两个码。
    #[test]
    fn garbage_is_malformed_not_merely_rejected() {
        let provider = okta_provider();
        let verifier = verifier_at_now(&provider);
        let nonce = Nonce::new("nonce-1".to_owned());

        for garbage in ["", "not-a-jwt", "a.b", "a.b.c.d"] {
            assert_eq!(
                verify_with(garbage, &verifier, &provider, &nonce).err(),
                Some(OidcError::IdTokenMalformed),
                "{garbage:?}"
            );
        }
        assert_ne!(
            OidcError::IdTokenMalformed.code(),
            OidcError::IdTokenRejected.code()
        );
    }

    /// Entra 地址链：`email → upn → preferred_username`，顺序与「含 `@`」判据都照搬上游。
    #[test]
    fn the_entra_email_chain_follows_upstream_order_and_predicate() {
        // 三个都在时取 email。
        let all_three = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""email":"first@acme.example","upn":"second@acme.example","preferred_username":"third@acme.example""#,
        ));
        assert_eq!(
            resolve_directory_email(&all_three).unwrap(),
            "first@acme.example"
        );

        // 缺 email 时取 upn。
        let no_email = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""upn":"second@acme.example","preferred_username":"third@acme.example""#,
        ));
        assert_eq!(
            resolve_directory_email(&no_email).unwrap(),
            "second@acme.example"
        );

        // 只剩 preferred_username。
        let only_pu = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""preferred_username":"third@acme.example""#,
        ));
        assert_eq!(
            resolve_directory_email(&only_pu).unwrap(),
            "third@acme.example"
        );
    }

    /// 不含 `@` 的候选被跳过，而不是被采纳 —— 上游 `claim` 闭包的逐字语义。
    #[test]
    fn a_candidate_without_an_at_sign_is_skipped_not_taken() {
        // `email` 是个显示名（无 `@`），链条应当继续走到 `upn`。
        let display_name_email = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""email":"Some One","upn":"real@acme.example""#,
        ));
        assert_eq!(
            resolve_directory_email(&display_name_email).unwrap(),
            "real@acme.example"
        );

        // 三个都不含 `@` => 拒绝登录（上游：返回空对象让 Better Auth 拒登）。
        let none_usable = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""email":"Some One","upn":"DOMAIN\\someone","preferred_username":"someone""#,
        ));
        assert_eq!(
            resolve_directory_email(&none_usable),
            Err(OidcError::EmailClaimMissing)
        );

        // 三个 claim 全缺同样拒。
        let nothing = parse_claims(&claims_json(ISSUER, "c", FAR_FUTURE, None, r#""x":1"#));
        assert_eq!(
            resolve_directory_email(&nothing),
            Err(OidcError::EmailClaimMissing)
        );
    }

    /// 地址取不到时**整次登录**失败，而不是拿一个空地址往下走。
    #[test]
    fn a_token_without_any_usable_address_fails_the_whole_sign_in() {
        let provider = okta_provider();
        let no_address = sign(&parse_claims(&claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""preferred_username":"someone""#,
        )));
        assert_eq!(
            verify_with(
                &no_address,
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .err(),
            Some(OidcError::EmailClaimMissing)
        );
    }

    /// §6.2 条 5：宽松的地址链**不豁免**租户策略。
    #[test]
    fn the_relaxed_email_chain_does_not_exempt_the_tenant_policy() {
        let allowed: BTreeSet<String> = ["tenant-a".to_owned()].into_iter().collect();
        let provider = entra_provider(EntraTenantPolicy::AllowList(allowed));
        let nonce = Nonce::new("nonce-1".to_owned());

        // 名单外的租户：地址明明取得到，仍然拒。
        let wrong_tenant = sign(&parse_claims(&claims_json(
            ISSUER,
            "microsoft-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""upn":"someone@contoso.example","tid":"tenant-b""#,
        )));
        assert_eq!(
            verify_with(
                &wrong_tenant,
                &verifier_at_now(&provider),
                &provider,
                &nonce
            )
            .err(),
            Some(OidcError::TenantNotAllowed)
        );

        // 缺 `tid`：名单档拿不到租户就无法证明它在名单里，同样拒。
        let no_tid = sign(&parse_claims(&claims_json(
            ISSUER,
            "microsoft-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""upn":"someone@contoso.example""#,
        )));
        assert_eq!(
            verify_with(&no_tid, &verifier_at_now(&provider), &provider, &nonce).err(),
            Some(OidcError::TenantNotAllowed)
        );

        // 正向对照：名单内的租户通过，且地址来自 `upn`（`email` 根本没来）。
        let right_tenant = sign(&parse_claims(&claims_json(
            ISSUER,
            "microsoft-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""upn":"someone@contoso.example","tid":"tenant-a""#,
        )));
        let identity = verify_with(
            &right_tenant,
            &verifier_at_now(&provider),
            &provider,
            &nonce,
        )
        .expect("名单内的租户必须通过");
        assert_eq!(identity.email(), "someone@contoso.example");
    }

    /// 非 Entra 的 provider 不受租户策略约束（它们的边界由 issuer 承担）。
    #[test]
    fn a_non_entra_provider_ignores_the_tid_claim() {
        let provider = okta_provider();
        let with_stray_tid = sign(&parse_claims(&claims_json(
            ISSUER,
            "okta-client",
            FAR_FUTURE,
            Some("nonce-1"),
            r#""email":"someone@acme.example","tid":"whatever""#,
        )));
        assert!(
            verify_with(
                &with_stray_tid,
                &verifier_at_now(&provider),
                &provider,
                &Nonce::new("nonce-1".to_owned())
            )
            .is_ok()
        );
    }

    /// `DirectoryClaims` 只认 `upn` / `tid`，别的未知 claim 不会被顺手带出来。
    #[test]
    fn additional_claims_are_narrow_by_construction() {
        let claims = parse_claims(&claims_json(
            ISSUER,
            "c",
            FAR_FUTURE,
            None,
            r#""upn":"a@b.example","tid":"t","groups":["admins"],"roles":["owner"]"#,
        ));
        assert_eq!(
            claims.additional_claims(),
            &DirectoryClaims {
                upn: Some("a@b.example".to_owned()),
                tid: Some("t".to_owned()),
            }
        );
    }
}
