//! JWKS 缓存与轮转（v3 §6.2 条 3 的「JWKS rotation」）。
//!
//! # 轮转与限速是同一条要求的两半
//!
//! IdP 会换签名密钥，所以看到一个本地没有的 `kid` 时必须能重新拉一次 JWKS —— 这是
//! 「rotation」那一半。但**只有这一半就是一个放大攻击面**：任何人只要拿一个 `kid` 随手
//! 编造的 JWT 打过来，就能让我们向 IdP 打一发请求，而伪造 `kid` 的成本是零。
//!
//! 所以 [`JwksCache::key_set_for`] 的判定是两级的：先查缓存，未命中再问冷却窗
//! （[`JwksRefreshPolicy`]）。冷却窗内的未命中直接落 [`OidcError::JwksRefreshRateLimited`]，
//! **不出网**。
//!
//! # 拉取失败也要记时刻
//!
//! [`JwksCache::last_fetch_at`] 在**发起**拉取时就被写上，与成功失败无关。这一条容易写反：
//! 只在成功时记时刻，那么一个正在故障的 IdP 会让每一次伪造 `kid` 的请求都真的打出去 ——
//! 放大攻击在 IdP 最脆弱的时候恰好完全失效。代价是 IdP 短暂抖动期间，合法的新 `kid` 也要
//! 等一个冷却窗才能被接纳；这是可恢复的一侧。由
//! `a_failed_fetch_still_starts_the_cooldown` 钉住。
//!
//! # 这里不验签
//!
//! 本模块只负责「把正确的 keyset 交出来」。签名校验、`iss` / `aud` / 时间窗 / `nonce`
//! 全在 [`super::claims`]，由 `openidconnect` 的 `IdTokenVerifier` 执行。

use std::collections::{BTreeMap, BTreeSet};

use openidconnect::core::{CoreJsonWebKey, CoreProviderMetadata};
use openidconnect::{JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl};
use time::{Duration, OffsetDateTime};
use url::Url;

use super::discovery::FetchBudget;
use super::error::OidcError;
use super::transport::{JSON_ESSENCES, MetadataTransport};

/// JWKS 重拉的冷却策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwksRefreshPolicy {
    cooldown: Duration,
}

impl JwksRefreshPolicy {
    /// 建一条策略。
    ///
    /// `cooldown` 非正表示**不限速**。这是一个刻意保留的取值（本机开发、集成测试），
    /// 但它不是默认值 —— 默认值由调用方显式给出，本模块不替部署做这个决定。
    #[must_use]
    pub const fn new(cooldown: Duration) -> Self {
        Self { cooldown }
    }

    /// 冷却窗长度。
    #[must_use]
    pub const fn cooldown(&self) -> Duration {
        self.cooldown
    }

    /// 距上次拉取 `last_fetch_at` 之后，此刻是否允许再拉。
    ///
    /// `None` 表示从没拉过 —— 允许。
    ///
    /// 时钟回拨（`now < last_fetch_at`）按**仍在冷却窗内**处理，与
    /// [`super::ratelimit::RateLimitPolicy::evaluate`] 的取舍相反，因为两者的失效代价不同：
    /// 限速器冻死额度会挡住合法登录（不可接受），而 JWKS 多等一个冷却窗只是让一次密钥
    /// 轮转晚一点被认出来（可恢复），而放宽它换来的是一个可被时钟操纵触发的放大面。
    #[must_use]
    pub fn allows_refresh(
        &self,
        last_fetch_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> bool {
        let Some(last) = last_fetch_at else {
            return true;
        };
        if self.cooldown <= Duration::ZERO {
            return true;
        }
        now >= last && now - last >= self.cooldown
    }
}

/// 一个 provider 的 JWKS 本地缓存。
#[derive(Debug)]
pub struct JwksCache {
    jwks_uri: JsonWebKeySetUrl,
    keys: JsonWebKeySet<CoreJsonWebKey>,
    last_fetch_at: Option<OffsetDateTime>,
    /// Microsoft tenant-independent JWKS 的 per-key issuer；普通 IdP 为空。
    key_issuers: BTreeMap<String, String>,
}

impl JwksCache {
    /// 建一个空缓存。
    #[must_use]
    pub fn new(jwks_uri: JsonWebKeySetUrl) -> Self {
        Self {
            jwks_uri,
            keys: JsonWebKeySet::new(Vec::new()),
            last_fetch_at: None,
            key_issuers: BTreeMap::new(),
        }
    }

    /// 从一份已取回的 discovery 文档建缓存（只取 `jwks_uri`，不拉密钥）。
    #[must_use]
    pub fn from_metadata(metadata: &CoreProviderMetadata) -> Self {
        Self::new(metadata.jwks_uri().clone())
    }

    /// JWKS 端点。
    #[must_use]
    pub const fn jwks_uri(&self) -> &JsonWebKeySetUrl {
        &self.jwks_uri
    }

    /// 上一次**发起**拉取的时刻（无论成败）。
    #[must_use]
    pub const fn last_fetch_at(&self) -> Option<OffsetDateTime> {
        self.last_fetch_at
    }

    /// 当前缓存的密钥数。
    #[must_use]
    pub fn cached_key_count(&self) -> usize {
        self.keys.keys().len()
    }

    /// 缓存里有没有这个 `kid`。
    ///
    /// `kid` 为 `None` 时判据退化成「缓存非空」：一个不带 `kid` 的 JWT 无法定向查找，
    /// 选哪把密钥由 `openidconnect` 的验证器按算法决定，我们这一层只需保证它有得选。
    #[must_use]
    pub fn contains(&self, kid: Option<&JsonWebKeyId>) -> bool {
        match kid {
            None => !self.keys.keys().is_empty(),
            Some(kid) => self
                .keys
                .keys()
                .iter()
                .any(|key| key.key_id().is_some_and(|id| id == kid)),
        }
    }

    /// 选中 key 自带的 issuer（Microsoft tenant-independent metadata 的额外硬闸门）。
    #[must_use]
    pub fn key_issuer(&self, kid: &JsonWebKeyId) -> Option<&str> {
        self.key_issuers.get(kid.as_str()).map(String::as_str)
    }

    /// 取一份能覆盖 `kid` 的 keyset，必要且被允许时重新拉取。
    ///
    /// 判定顺序：命中缓存 → 直接返回，**不出网**；未命中 → 问冷却窗；允许则拉一次并
    /// 重新判定，仍不命中就 [`OidcError::JwksKeyNotFound`]。
    ///
    /// # Errors
    ///
    /// - [`OidcError::JwksRefreshRateLimited`]：未命中且仍在冷却窗内；
    /// - [`OidcError::JwksKeyNotFound`]：拉过之后仍然没有这个 `kid`；
    /// - [`OidcError::TransportUnavailable`] / `Metadata*`：拉取本身失败（判据见
    ///   [`super::transport::MetadataResponse::into_json_body`]）。
    pub async fn key_set_for(
        &mut self,
        kid: Option<&JsonWebKeyId>,
        transport: &dyn MetadataTransport,
        budget: FetchBudget,
        policy: JwksRefreshPolicy,
        now: OffsetDateTime,
    ) -> Result<&JsonWebKeySet<CoreJsonWebKey>, OidcError> {
        if self.contains(kid) {
            return Ok(&self.keys);
        }
        if !policy.allows_refresh(self.last_fetch_at, now) {
            return Err(OidcError::JwksRefreshRateLimited);
        }

        self.refresh(transport, budget, now).await?;

        if self.contains(kid) {
            Ok(&self.keys)
        } else {
            Err(OidcError::JwksKeyNotFound)
        }
    }

    /// 无条件拉一次 JWKS 并替换缓存。
    ///
    /// **不问冷却窗** —— 冷却窗是 [`Self::key_set_for`] 的判据。这个函数留给「管理员手动
    /// 触发一次刷新」这类有人为授权的路径；它仍然会推进 [`Self::last_fetch_at`]。
    ///
    /// # Errors
    ///
    /// 拉取或解析失败时返回对应的稳定 code；失败时**保留**原有缓存 —— 一次网络抖动不该
    /// 让所有在飞的登录立刻失去可用密钥。
    pub async fn refresh(
        &mut self,
        transport: &dyn MetadataTransport,
        budget: FetchBudget,
        now: OffsetDateTime,
    ) -> Result<(), OidcError> {
        // 先记时刻：失败也算用掉一次机会，见模块文档。
        self.last_fetch_at = Some(now);

        let url = Url::parse(self.jwks_uri.as_str()).map_err(|_| OidcError::MetadataMalformed)?;
        let request = budget.request(url);
        let response = transport.get(&request).await?;
        let body = response.into_json_body(&request, JSON_ESSENCES)?;

        let fetched: JsonWebKeySet<CoreJsonWebKey> =
            serde_json::from_slice(&body).map_err(|_| OidcError::MetadataMalformed)?;
        let key_issuers = parse_key_issuers(&body)?;
        self.keys = fetched;
        self.key_issuers = key_issuers;
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct RawJwksIssuerProjection {
    keys: Vec<RawJwkIssuerProjection>,
}

#[derive(serde::Deserialize)]
struct RawJwkIssuerProjection {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
}

fn parse_key_issuers(body: &[u8]) -> Result<BTreeMap<String, String>, OidcError> {
    let raw: RawJwksIssuerProjection =
        serde_json::from_slice(body).map_err(|_| OidcError::MetadataMalformed)?;
    let mut seen = BTreeSet::new();
    let mut issuers = BTreeMap::new();
    for key in raw.keys {
        let Some(kid) = key.kid else {
            continue;
        };
        if kid.is_empty() || kid.len() > 256 || kid.chars().any(char::is_control) {
            return Err(OidcError::MetadataMalformed);
        }
        if !seen.insert(kid.clone()) {
            return Err(OidcError::MetadataMalformed);
        }
        if let Some(issuer) = key.issuer {
            if issuer.is_empty() || issuer.len() > 2048 || issuer.chars().any(char::is_control) {
                return Err(OidcError::MetadataMalformed);
            }
            issuers.insert(kid, issuer);
        }
    }
    Ok(issuers)
}

#[cfg(test)]
pub(super) mod fixtures {
    //! JWKS 夹具。

    use openidconnect::core::CoreJsonWebKey;
    use openidconnect::{JsonWebKeyId, JsonWebKeySet};

    /// 造一把带 `kid` 的 RSA 公钥（值本身不用于验签，只用于查表）。
    ///
    /// 用 `CoreJsonWebKey::new_rsa` 而不是手写 JSON：模数与指数的 base64url 编码由库自己
    /// 产出，测试就不会因为抄错一个字符而失败在与被测判据无关的地方。
    #[must_use]
    pub fn rsa_key(kid: &str) -> CoreJsonWebKey {
        CoreJsonWebKey::new_rsa(
            vec![0xAB; 256],
            vec![0x01, 0x00, 0x01],
            Some(JsonWebKeyId::new(kid.to_owned())),
        )
    }

    /// 把若干把密钥序列化成一份 JWKS 文档。
    #[must_use]
    pub fn jwks_document(kids: &[&str]) -> String {
        let set = JsonWebKeySet::new(kids.iter().copied().map(rsa_key).collect());
        serde_json::to_string(&set).expect("JWKS 序列化不会失败")
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::jwks_document;
    use super::{JwksCache, JwksRefreshPolicy};
    use crate::auth::oidc::discovery::FetchBudget;
    use crate::auth::oidc::error::OidcError;
    use crate::auth::oidc::transport::MetadataResponse;
    use crate::auth::oidc::transport::fake::FakeTransport;
    use openidconnect::{JsonWebKeyId, JsonWebKeySetUrl};
    use time::{Duration, OffsetDateTime};

    const JWKS_URI: &str = "https://example.okta-test.invalid/oauth2/default/v1/keys";

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn budget() -> FetchBudget {
        FetchBudget::new(64 * 1024, core::time::Duration::from_secs(5))
    }

    fn new_cache() -> JwksCache {
        JwksCache::new(JsonWebKeySetUrl::new(JWKS_URI.to_owned()).unwrap())
    }

    fn kid(value: &str) -> JsonWebKeyId {
        JsonWebKeyId::new(value.to_owned())
    }

    fn policy() -> JwksRefreshPolicy {
        JwksRefreshPolicy::new(Duration::minutes(5))
    }

    /// 冷启动：第一次查任何 `kid` 都会拉一次。
    #[tokio::test]
    async fn a_cold_cache_fetches_once() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));

        let mut cache = new_cache();
        assert_eq!(cache.cached_key_count(), 0);

        let keys = cache
            .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
            .await
            .expect("冷启动必须拉得到");
        assert_eq!(keys.keys().len(), 1);
        assert_eq!(transport.calls_for(JWKS_URI), 1);
    }

    #[tokio::test]
    async fn per_key_issuer_is_preserved_for_entra_and_duplicate_kid_is_rejected() {
        let mut document: serde_json::Value =
            serde_json::from_str(&jwks_document(&["key-a"])).unwrap();
        document["keys"][0]["issuer"] = serde_json::Value::String(
            "https://login.microsoftonline.com/{tenantid}/v2.0".to_owned(),
        );
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &serde_json::to_string(&document).unwrap());
        let mut cache = new_cache();
        cache
            .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
            .await
            .unwrap();
        assert_eq!(
            cache.key_issuer(&kid("key-a")),
            Some("https://login.microsoftonline.com/{tenantid}/v2.0")
        );

        let duplicated = serde_json::json!({
            "keys": [document["keys"][0].clone(), document["keys"][0].clone()]
        });
        let duplicate_transport = FakeTransport::new();
        duplicate_transport.push_json(JWKS_URI, &serde_json::to_string(&duplicated).unwrap());
        let mut duplicate_cache = new_cache();
        assert_eq!(
            duplicate_cache
                .refresh(&duplicate_transport, budget(), t0())
                .await,
            Err(OidcError::MetadataMalformed)
        );
    }

    /// 命中缓存不出网 —— 这是限速之外的第一道，也是最重要的一道减压。
    #[tokio::test]
    async fn a_cached_kid_never_touches_the_network_again() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));

        let mut cache = new_cache();
        for _ in 0..10 {
            cache
                .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
                .await
                .expect("命中缓存必须成功");
        }
        assert_eq!(
            transport.calls_for(JWKS_URI),
            1,
            "命中缓存的十次查询只应有第一次出网"
        );
    }

    /// 轮转：新 `kid` 触发重拉，拉回来就认；这是「rotation」那一半。
    #[tokio::test]
    async fn an_unknown_kid_triggers_a_refresh_that_picks_up_the_rotated_key() {
        let transport = FakeTransport::new();
        // 第一次只有 key-a；之后 key-a + key-b（最后一个应答会重复）。
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));
        transport.push_json(JWKS_URI, &jwks_document(&["key-a", "key-b"]));

        let mut cache = new_cache();
        cache
            .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
            .await
            .unwrap();
        assert!(!cache.contains(Some(&kid("key-b"))));

        // 冷却窗过后，未命中的 key-b 触发第二次拉取并被接纳。
        let later = t0() + Duration::minutes(5);
        let keys = cache
            .key_set_for(Some(&kid("key-b")), &transport, budget(), policy(), later)
            .await
            .expect("轮转后的新密钥必须能被拉回来");
        assert_eq!(keys.keys().len(), 2);
        assert_eq!(transport.calls_for(JWKS_URI), 2);
        assert!(cache.contains(Some(&kid("key-a"))), "旧密钥不该被挤掉");
    }

    /// 限速：冷却窗内的未命中**不出网**，直接落稳定 code。
    ///
    /// 这条与上一条是同一枚硬币的两面 —— 缺了限速，一个伪造 `kid` 的请求就是一次打向
    /// IdP 的放大攻击。
    #[tokio::test]
    async fn a_forged_kid_inside_the_cooldown_does_not_reach_the_idp() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));

        let mut cache = new_cache();
        cache
            .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
            .await
            .unwrap();
        assert_eq!(transport.calls_for(JWKS_URI), 1);

        // 一百次伪造 kid，全部落在冷却窗内。
        for i in 0..100 {
            let forged = kid(&format!("forged-{i}"));
            let now = t0() + Duration::seconds(i);
            assert_eq!(
                cache
                    .key_set_for(Some(&forged), &transport, budget(), policy(), now)
                    .await
                    .err(),
                Some(OidcError::JwksRefreshRateLimited)
            );
        }
        assert_eq!(
            transport.calls_for(JWKS_URI),
            1,
            "一百次伪造 kid 不得产生哪怕一次出网"
        );

        // 正向对照：冷却窗外确实会再拉一次 —— 否则上面的「1 次」在「永不拉取」的世界里
        // 同样成立。
        let after = t0() + Duration::minutes(5);
        assert_eq!(
            cache
                .key_set_for(
                    Some(&kid("still-forged")),
                    &transport,
                    budget(),
                    policy(),
                    after
                )
                .await
                .err(),
            Some(OidcError::JwksKeyNotFound),
            "拉过之后仍然没有这个 kid，应当是 KeyNotFound 而不是限速"
        );
        assert_eq!(transport.calls_for(JWKS_URI), 2);
    }

    /// 「拉过之后仍无此 `kid`」与「被限速」是两个不同的码。
    ///
    /// 区分它们对**运维**有意义（前者说明确实没这把密钥，后者说明我们主动没去问），
    /// 而两者都不对调用方泄露任何 IdP 侧信息。
    #[tokio::test]
    async fn rate_limited_and_key_not_found_are_distinct_codes() {
        assert_ne!(
            OidcError::JwksRefreshRateLimited.code(),
            OidcError::JwksKeyNotFound.code()
        );
    }

    /// 拉取失败同样开启冷却窗。
    #[tokio::test]
    async fn a_failed_fetch_still_starts_the_cooldown() {
        let transport = FakeTransport::new(); // 什么都没排 => 恒 TransportUnavailable
        let mut cache = new_cache();

        assert_eq!(
            cache
                .key_set_for(Some(&kid("key-a")), &transport, budget(), policy(), t0())
                .await
                .err(),
            Some(OidcError::TransportUnavailable)
        );
        assert_eq!(cache.last_fetch_at(), Some(t0()), "失败也要记时刻");

        // 紧接着的重试落在冷却窗内，不再出网。
        assert_eq!(
            cache
                .key_set_for(
                    Some(&kid("key-a")),
                    &transport,
                    budget(),
                    policy(),
                    t0() + Duration::seconds(1)
                )
                .await
                .err(),
            Some(OidcError::JwksRefreshRateLimited)
        );
        assert_eq!(
            transport.calls_for(JWKS_URI),
            1,
            "IdP 故障期间不得变成不限速重试"
        );
    }

    /// 拉取失败保留原有缓存 —— 一次抖动不该让在飞登录全部失效。
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_previous_keys() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));
        transport.push(
            JWKS_URI,
            Ok(MetadataResponse::new(
                503,
                Some("application/json".to_owned()),
                b"{}".to_vec(),
            )),
        );

        let mut cache = new_cache();
        cache.refresh(&transport, budget(), t0()).await.unwrap();
        assert_eq!(cache.cached_key_count(), 1);

        assert_eq!(
            cache
                .refresh(&transport, budget(), t0() + Duration::minutes(10))
                .await
                .err(),
            Some(OidcError::MetadataStatusNotOk)
        );
        assert_eq!(cache.cached_key_count(), 1, "失败不得清空缓存");
        assert!(cache.contains(Some(&kid("key-a"))));
    }

    /// 冷却窗判据本身：正负各一组，含时钟回拨。
    #[test]
    fn the_cooldown_predicate_is_fail_closed_on_a_backwards_clock() {
        let policy = policy();

        // 从没拉过 => 允许。
        assert!(policy.allows_refresh(None, t0()));
        // 窗内 => 不允许。
        assert!(!policy.allows_refresh(Some(t0()), t0() + Duration::minutes(4)));
        // 正好一个窗 => 允许。
        assert!(policy.allows_refresh(Some(t0()), t0() + Duration::minutes(5)));
        // 时钟回拨 => 不允许（与限速器的取舍相反，理由见文档）。
        assert!(!policy.allows_refresh(Some(t0()), t0() - Duration::hours(1)));

        // 冷却窗非正 => 不限速（开发档）。
        let open = JwksRefreshPolicy::new(Duration::ZERO);
        assert!(open.allows_refresh(Some(t0()), t0()));
        assert!(open.allows_refresh(Some(t0()), t0() - Duration::hours(1)));
    }

    /// 不带 `kid` 的 token：缓存非空即命中，缓存为空才拉。
    #[tokio::test]
    async fn a_token_without_a_kid_uses_whatever_is_cached() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, &jwks_document(&["key-a"]));

        let mut cache = new_cache();
        assert!(!cache.contains(None), "空缓存下 None 不算命中");

        cache
            .key_set_for(None, &transport, budget(), policy(), t0())
            .await
            .expect("空缓存 + 无 kid 应当触发一次拉取");
        assert_eq!(transport.calls_for(JWKS_URI), 1);

        assert!(cache.contains(None));
        cache
            .key_set_for(None, &transport, budget(), policy(), t0())
            .await
            .unwrap();
        assert_eq!(transport.calls_for(JWKS_URI), 1, "非空缓存下不再出网");
    }

    /// 坏 JWKS 文档落 `MetadataMalformed`，并且不污染缓存。
    #[tokio::test]
    async fn a_malformed_jwks_document_is_refused() {
        let transport = FakeTransport::new();
        transport.push_json(JWKS_URI, "{ not json");

        let mut cache = new_cache();
        assert_eq!(
            cache.refresh(&transport, budget(), t0()).await.err(),
            Some(OidcError::MetadataMalformed)
        );
        assert_eq!(cache.cached_key_count(), 0);

        // 正向对照：合格文档收得进。
        let good = FakeTransport::new();
        good.push_json(JWKS_URI, &jwks_document(&["key-a"]));
        let mut cache2 = new_cache();
        assert_eq!(cache2.refresh(&good, budget(), t0()).await, Ok(()));
        assert_eq!(cache2.cached_key_count(), 1);
    }
}
