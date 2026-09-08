//! OIDC 失败的稳定 code。
//!
//! # 为什么是「码」而不是「消息」
//!
//! v3 §15.3 把错误契约钉在 code / status / audit 类型上，文案可本地化且不进 domain /
//! application。本模块产出的每个失败都只是一个静态标识符：它进日志、进 audit、进
//! 前端的本地化表查一次，**永远不进用户界面当句子**。
//!
//! 更硬的一条理由在认证面尤其成立：错误里带上「IdP 回了什么」就等于把一段**不可信的
//! 远端字节**接进日志与告警管道（同 [`openbot_application::ports::PortError`] 的取舍：
//! 那里也刻意只留 `&'static str`）。所以本枚举的每个变体都**没有字段** —— 不是懒，是
//! 结构上让「把 IdP 的响应体拼进错误」这件事写不出来。需要细节时由产生错误的那一处
//! 自己 `tracing` 出去，那是受控 trace，不是契约。
//!
//! # 变体与 code 是同一处声明
//!
//! 本文件底部的 `oidc_errors!` 宏一次性生成 enum、`#[error(...)]`、[`OidcError::code`] 与
//! [`OidcError::ALL`]。这不是为了少打字：一个枚举同时维护「变体表」和「码表」两份清单
//! 时，两份清单**恒有一天会不等**，而不等的那一天没有任何编译期信号。单点声明把这条
//! 失效模式直接消掉，`code_matches_display` 与 `all_covers_every_variant` 两条测试再从
//! 两个方向把它钉住。

/// 由单一声明表同时生成 [`OidcError`] 的变体、`Display`、[`OidcError::code`] 与
/// [`OidcError::ALL`]。
///
/// 宏只在本模块内使用（不 `#[macro_export]`）：它是这一个枚举的实现细节，不是给别处
/// 复用的工具。
macro_rules! oidc_errors {
    ($( $(#[$meta:meta])* $variant:ident => $code:literal , )+) => {
        /// OIDC 协议层的失败。封闭 enum，全部变体无字段。
        ///
        /// 「无字段」是契约的一部分，见模块文档。想加带值的变体前先回答：那个值来自
        /// IdP 吗？来自 IdP 就不能进错误。
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
        pub enum OidcError {
            $(
                $(#[$meta])*
                #[error($code)]
                $variant,
            )+
        }

        impl OidcError {
            /// 全部变体。顺序即声明序。
            ///
            /// 它由宏生成，所以**不可能**漏登记一个变体 —— 这正是它存在的理由：
            /// 手写的「全变体清单」是一份注定漂移的抄件。
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// 稳定 code。
            ///
            /// 它是**标识符**不是文案：不随 locale 变化，不进本地化表（v3 §4a / §15.3
            /// 的分工是「code 穿越边界，文案在 GUI 侧查表」）。改动任一 code 都是一次
            /// 对外契约变更。
            #[must_use]
            pub const fn code(self) -> &'static str {
                match self {
                    $( Self::$variant => $code, )+
                }
            }
        }
    };
}

oidc_errors![
    // ---- 出网（由注入的 dialer 承担，本模块只解释它的结果）-------------------
    /// 注入的 dialer 说这次取不到：连不上、超时、被 egress 策略拒绝。
    ///
    /// 刻意不区分「连不上」与「被策略拒绝」：区分它就等于把内网可达性做成一个
    /// 可被探测的信道（v3 §6.2 要求 pre-auth 面不泄露组织拓扑，同一条理由在这里
    /// 对内网拓扑成立）。
    TransportUnavailable => "oidc_transport_unavailable",
    /// 元数据端点回了非 200。
    MetadataStatusNotOk => "oidc_metadata_status_not_ok",
    /// 元数据端点回的 `Content-Type` 不是 JSON。
    MetadataContentTypeInvalid => "oidc_metadata_content_type_invalid",
    /// 响应体超过调用方给定的字节上限（v3 §6.2「大小/时间上限」的大小那一半）。
    MetadataTooLarge => "oidc_metadata_too_large",
    /// 响应体不是一份能解开的 OIDC 元数据 / JWKS 文档。
    MetadataMalformed => "oidc_metadata_malformed",
    /// discovery 给出的 authorization/token/JWKS endpoint 不是可接受的 HTTPS 绝对 URL。
    MetadataEndpointRejected => "oidc_metadata_endpoint_rejected",

    // ---- issuer ------------------------------------------------------------
    /// issuer 不是 `https`。
    ///
    /// 必须由我们自己拒：`openidconnect::IssuerUrl::new` 的文档说它是「URL using the
    /// `https` scheme with no query or fragment component」，但 `new_url_type!` 宏
    /// 生成的构造函数只做 `url::Url::parse`，**一个 scheme 都不检查**。
    IssuerNotHttps => "oidc_issuer_not_https",
    /// issuer 带了 query 或 fragment，或带了 userinfo。理由同 [`Self::IssuerNotHttps`]。
    IssuerNotBare => "oidc_issuer_not_bare",
    /// 元数据文档自报的 `issuer` 与我们请求的那个不是同一个。
    ///
    /// 这是 discovery 唯一的身份锚：没有这条，任何能应答 `.well-known` 的主机都能
    /// 冒充任意 issuer。
    IssuerMismatch => "oidc_issuer_mismatch",

    // ---- JWKS --------------------------------------------------------------
    /// 本地缓存与本次拉取都没有这个 `kid`。
    JwksKeyNotFound => "oidc_jwks_key_not_found",
    /// `kid` 未命中，但距上次拉取还在冷却窗内，本次**不**再打向 IdP。
    ///
    /// 没有这条，一个伪造 `kid` 的请求就是一次打向 IdP 的放大攻击。
    JwksRefreshRateLimited => "oidc_jwks_refresh_rate_limited",

    // ---- redirect URI ------------------------------------------------------
    /// 登记的 redirect URI 不是规范形（见 `redirect` 模块的裁决）。
    RedirectUriNotCanonical => "oidc_redirect_uri_not_canonical",
    /// redirect URI 的 scheme 不在允许集内。
    RedirectUriSchemeNotAllowed => "oidc_redirect_uri_scheme_not_allowed",
    /// redirect URI 带 fragment / userinfo —— RFC 6749 §3.1.2 明禁 fragment。
    RedirectUriNotBare => "oidc_redirect_uri_not_bare",
    /// 回调带来的 redirect URI 与本次登录尝试登记的那个**不是逐字节相同**。
    RedirectUriMismatch => "oidc_redirect_uri_mismatch",

    // ---- PKCE --------------------------------------------------------------
    /// `code_challenge_method` 不是 `S256`。`plain` 落在这里。
    PkceMethodNotS256 => "oidc_pkce_method_not_s256",

    // ---- 一次登录尝试 --------------------------------------------------------
    /// 回调带来的 `state` 不对应任何在飞的登录尝试。
    ///
    /// 「不存在」与「已被用掉」共用这一个码是刻意的：区分它们会告诉攻击者他猜中了
    /// 一个真实存在过的 `state`。
    AttemptUnknown => "oidc_attempt_unknown",
    /// 登录尝试已过期。
    AttemptExpired => "oidc_attempt_expired",
    /// 回调声称的 provider 与登录尝试发起时锁定的那个不一致。
    AttemptProviderMismatch => "oidc_attempt_provider_mismatch",
    /// 在飞登录尝试已达容量上限，本次不再登记。
    ///
    /// 存在的理由是 §6.2 点名的 callback flood：一个只增不减的在飞表就是内存耗尽面。
    AttemptStoreFull => "oidc_attempt_store_full",

    // ---- authorization code / token endpoint -----------------------------
    /// discovery 文档没有 token endpoint，无法完成 Authorization Code flow。
    TokenEndpointMissing => "oidc_token_endpoint_missing",
    /// token request 形态、HTTP 交换或 OAuth 错误响应有一项失败。
    ///
    /// 不把 IdP 的 error_description 带出：它是不可信远端字节，也会成为 callback oracle。
    TokenExchangeRejected => "oidc_token_exchange_rejected",
    /// IdP 返回了限流/5xx 或无法解析的 token/JWKS 响应；属于上游 vendor failure。
    ProviderResponseInvalid => "oidc_provider_response_invalid",
    /// token response 没有 ID token；access token 不能替代身份断言。
    IdTokenMissing => "oidc_id_token_missing",

    // ---- ID token ----------------------------------------------------------
    /// ID token 不是一个能解开的 JWT。
    IdTokenMalformed => "oidc_id_token_malformed",
    /// ID token 的签名、`iss`、`aud`、时间窗或 `nonce` 有一项不过。
    ///
    /// 五项共用一个码：把「签名坏」与「aud 不对」分开回答，等于给攻击者一台
    /// 逐项试错的仪器。运维需要的区分度由产生它的那一处 `tracing` 提供。
    IdTokenRejected => "oidc_id_token_rejected",
    /// Entra：`email` / `upn` / `preferred_username` 三个 claim 都没给出可用地址。
    ///
    /// 照搬上游 `server/src/auth/index.ts::mapEntraProfile` 的语义 —— 它返回空对象让
    /// 登录被拒，注释里写明「被拒远好于作为一个部署认不出的人被悄悄放进来」。
    EmailClaimMissing => "oidc_email_claim_missing",
    /// ID token 的 `tid`（Entra 租户）不在该 provider 允许的租户集内。
    TenantNotAllowed => "oidc_tenant_not_allowed",
    /// `MICROSOFT_OAUTH_TENANT_ID` 不是 common/organizations/consumers/canonical GUID。
    EntraTenantMalformed => "oidc_entra_tenant_malformed",
    /// 调用方把 A provider 的 group mapping 用在 B provider 的已验证 token 上。
    GroupMappingMismatch => "oidc_group_mapping_mismatch",
    /// 已验证 token 的 group claim 路径/形状不符合该 provider 的显式 mapping。
    GroupClaimRejected => "oidc_group_claim_rejected",

    // ---- provider 注册 ------------------------------------------------------
    /// 引用了一个未注册的 provider。
    ProviderUnknown => "oidc_provider_unknown",
    /// provider ID 不符合形态约束。
    ProviderIdMalformed => "oidc_provider_id_malformed",
    /// 同一个 provider ID 被登记了两次。
    ///
    /// fail-closed 而不是「后者覆盖前者」：`BTreeMap::insert` 的静默覆盖会让一份配置里
    /// 真正生效的是哪一条，取决于遍历顺序。
    ProviderIdConflict => "oidc_provider_id_conflict",
    /// 登记的 email domain 不是一个可比对的规范域名。
    DomainMalformed => "oidc_domain_malformed",
    /// 两个 provider 抢同一个 email domain。
    ///
    /// fail-closed：不「后者覆盖前者」。routing 是一次权限判定，让它的答案取决于
    /// 注册顺序，等于让一个新管理员靠抢注域名把别人的用户接管过来。
    DomainConflict => "oidc_domain_conflict",
];

#[cfg(test)]
mod tests {
    use super::OidcError;
    use std::collections::BTreeSet;

    /// `Display`（由 `#[error(...)]` 生成）与 [`OidcError::code`] 必须逐字相同。
    ///
    /// 两者都由同一次宏展开产出，本测试钉住的是「将来有人手工改了其中一处」。
    #[test]
    fn code_matches_display() {
        for err in OidcError::ALL {
            assert_eq!(
                err.to_string(),
                err.code(),
                "{err:?} 的 Display 与 code 漂移了"
            );
        }
    }

    /// 码互不相同 —— 重复码会让两种不同失败在 audit 里落进同一个桶。
    #[test]
    fn codes_are_unique() {
        let codes: BTreeSet<&str> = OidcError::ALL.iter().map(|e| e.code()).collect();
        assert_eq!(
            codes.len(),
            OidcError::ALL.len(),
            "ALL 里存在重复 code：{codes:?}"
        );
    }

    /// 每个码都以 `oidc_` 打头且只含 `[a-z0-9_]`。
    ///
    /// 这条不是洁癖：稳定 code 会被 GUI 侧当本地化表的键、被 audit 当查询桶，
    /// 一个带空格或大写的码会在两边各自以不同方式坏掉。
    #[test]
    fn codes_are_snake_case_and_namespaced() {
        for err in OidcError::ALL {
            let code = err.code();
            assert!(code.starts_with("oidc_"), "{code} 缺少命名空间前缀");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code} 含非法字符"
            );
            // 负向对照的正面：确认这条断言不是恒真的 —— 一个确实非法的码会被判出来。
            assert!(!code.contains(' '));
        }
    }

    /// 上一条的**负向对照**：同一套判据作用在一个坏码上必须失败。
    ///
    /// 没有这条，`codes_are_snake_case_and_namespaced` 在「判据恒真」的世界里同样通过。
    #[test]
    fn the_shape_predicate_actually_rejects_a_bad_code() {
        let bad = "OIDC Bad Code";
        assert!(!bad.starts_with("oidc_"));
        assert!(
            !bad.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
    }

    /// [`OidcError::ALL`] 覆盖每个变体。
    ///
    /// 由宏生成本来就保证了这点，本测试守的是「将来有人把 enum 从宏里拆出来手写」：
    /// 那一刻这条穷尽 `match` 会因为少了新变体而**编译失败**，而不是静默漏掉。
    #[test]
    fn all_covers_every_variant() {
        // 穷尽 match：新增变体而忘了它，这里编译不过。
        fn tag(err: OidcError) -> u8 {
            match err {
                OidcError::TransportUnavailable => 0,
                OidcError::MetadataStatusNotOk => 1,
                OidcError::MetadataContentTypeInvalid => 2,
                OidcError::MetadataTooLarge => 3,
                OidcError::MetadataMalformed => 4,
                OidcError::IssuerNotHttps => 5,
                OidcError::IssuerNotBare => 6,
                OidcError::IssuerMismatch => 7,
                OidcError::JwksKeyNotFound => 8,
                OidcError::JwksRefreshRateLimited => 9,
                OidcError::RedirectUriNotCanonical => 10,
                OidcError::RedirectUriSchemeNotAllowed => 11,
                OidcError::RedirectUriNotBare => 12,
                OidcError::RedirectUriMismatch => 13,
                OidcError::PkceMethodNotS256 => 14,
                OidcError::AttemptUnknown => 15,
                OidcError::AttemptExpired => 16,
                OidcError::AttemptProviderMismatch => 17,
                OidcError::AttemptStoreFull => 18,
                OidcError::IdTokenMalformed => 19,
                OidcError::IdTokenRejected => 20,
                OidcError::EmailClaimMissing => 21,
                OidcError::TenantNotAllowed => 22,
                OidcError::ProviderUnknown => 23,
                OidcError::ProviderIdMalformed => 24,
                OidcError::ProviderIdConflict => 25,
                OidcError::DomainMalformed => 26,
                OidcError::DomainConflict => 27,
                OidcError::TokenEndpointMissing => 28,
                OidcError::TokenExchangeRejected => 29,
                OidcError::ProviderResponseInvalid => 30,
                OidcError::IdTokenMissing => 31,
                OidcError::GroupMappingMismatch => 32,
                OidcError::GroupClaimRejected => 33,
                OidcError::MetadataEndpointRejected => 34,
                OidcError::EntraTenantMalformed => 35,
            }
        }

        let tags: BTreeSet<u8> = OidcError::ALL.iter().copied().map(tag).collect();
        assert_eq!(
            tags.len(),
            OidcError::ALL.len(),
            "ALL 与穷尽 match 的变体集合不等"
        );
    }
}
