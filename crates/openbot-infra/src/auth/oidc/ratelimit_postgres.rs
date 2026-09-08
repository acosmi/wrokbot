//! OIDC pre-auth 的 PostgreSQL/HMAC 跨 replica 限速存储。

use std::sync::Arc;

use deadpool_postgres::Pool;
use hmac::{Hmac, Mac};
use openbot_contracts::ids::TenantId;
use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use super::ratelimit::{RateLimitDecision, RateLimitPolicy};

type HmacSha256 = Hmac<Sha256>;
const STORAGE_VERSION: u8 = 1;
const MAX_BUCKET_KEY_BYTES: usize = 1024;

/// 分桶名字是封闭枚举，调用方不能把用户输入变成 identifier 前缀。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OidcRateLimitBucket {
    LoginStartIp,
    CallbackIp,
    EmailRouteIp,
    EmailRouteEmail,
}

impl OidcRateLimitBucket {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginStartIp => "login_start_ip",
            Self::CallbackIp => "callback_ip",
            Self::EmailRouteIp => "email_route_ip",
            Self::EmailRouteEmail => "email_route_email",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PostgresRateLimitError {
    #[error("oidc_rate_limit_dependency_unavailable")]
    DependencyUnavailable,
    #[error("oidc_rate_limit_state_corrupt")]
    Corrupt,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCounter {
    version: u8,
    window_started_at: i64,
    count: u32,
}

#[derive(Clone)]
pub struct PostgresOidcRateLimiter {
    pool: Pool,
    hash_key: Arc<SecretBytes>,
    tenant_scope: String,
}

impl PostgresOidcRateLimiter {
    pub fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        tenant: &TenantId,
    ) -> Result<Self, PostgresRateLimitError> {
        let hash_key = hash_key.into();
        if hash_key.is_empty() {
            return Err(PostgresRateLimitError::Corrupt);
        }
        let tenant_scope = hex(&Sha256::digest(
            [
                b"openbot-oidc-rate-tenant-v1\0".as_slice(),
                tenant.as_str().as_bytes(),
            ]
            .concat(),
        ));
        Ok(Self {
            pool,
            hash_key: Arc::new(SecretBytes::new(hash_key)),
            tenant_scope,
        })
    }

    /// 原始 IP/email 只进入 HMAC，不落库、不进错误/Debug。
    pub async fn evaluate(
        &self,
        bucket: OidcRateLimitBucket,
        raw_key: &str,
        policy: RateLimitPolicy,
        now: OffsetDateTime,
    ) -> Result<RateLimitDecision, PostgresRateLimitError> {
        let key_bytes = raw_key.as_bytes();
        if key_bytes.is_empty() || key_bytes.len() > MAX_BUCKET_KEY_BYTES {
            return Err(PostgresRateLimitError::Corrupt);
        }
        let (id, lock_key) = self.bucket_id(bucket, key_bytes)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        // 每次最多清 100 个过期 bucket，避免无限增长，也不给一次请求无界清扫工作量。
        transaction
            .execute(
                "DELETE FROM public.verifications WHERE id IN ( \
                   SELECT id FROM public.verifications \
                   WHERE identifier='oidc-rate-limit' AND expires_at <= $1 LIMIT 100)",
                &[&now],
            )
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        let prior = transaction
            .query_opt(
                "SELECT value FROM public.verifications WHERE id=$1 FOR UPDATE",
                &[&id],
            )
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?
            .map(|row| -> Result<_, PostgresRateLimitError> {
                let value: String = row
                    .try_get(0)
                    .map_err(|_| PostgresRateLimitError::Corrupt)?;
                let stored: StoredCounter =
                    serde_json::from_str(&value).map_err(|_| PostgresRateLimitError::Corrupt)?;
                if stored.version != STORAGE_VERSION {
                    return Err(PostgresRateLimitError::Corrupt);
                }
                let started = OffsetDateTime::from_unix_timestamp(stored.window_started_at)
                    .map_err(|_| PostgresRateLimitError::Corrupt)?;
                Ok(super::ratelimit::RateLimitCounter::restore(
                    started,
                    stored.count,
                ))
            })
            .transpose()?;
        let decision = policy.evaluate(prior, now);
        let counter = decision.counter();
        let value = serde_json::to_string(&StoredCounter {
            version: STORAGE_VERSION,
            window_started_at: counter.window_started_at().unix_timestamp(),
            count: counter.count(),
        })
        .map_err(|_| PostgresRateLimitError::Corrupt)?;
        let expiry = counter.window_started_at()
            + if policy.window() > Duration::ZERO {
                policy.window()
            } else {
                Duration::seconds(1)
            };
        transaction
            .execute(
                "INSERT INTO public.verifications(id,identifier,value,expires_at,created_at,updated_at) \
                 VALUES($1,'oidc-rate-limit',$2,$3,$4,$4) \
                 ON CONFLICT(id) DO UPDATE SET value=excluded.value,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
                &[&id, &value, &expiry, &now],
            )
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PostgresRateLimitError::DependencyUnavailable)?;
        Ok(decision)
    }

    fn bucket_id(
        &self,
        bucket: OidcRateLimitBucket,
        raw_key: &[u8],
    ) -> Result<(String, i64), PostgresRateLimitError> {
        let mut mac = HmacSha256::new_from_slice(self.hash_key.expose())
            .map_err(|_| PostgresRateLimitError::Corrupt)?;
        mac.update(b"openbot-oidc-rate-bucket-v1\0");
        mac.update(self.tenant_scope.as_bytes());
        mac.update(b"\0");
        mac.update(bucket.as_str().as_bytes());
        mac.update(b"\0");
        mac.update(raw_key);
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        let mut lock = [0u8; 8];
        lock.copy_from_slice(&digest[..8]);
        Ok((
            format!(
                "oidc-rate:{}:{}:{}",
                self.tenant_scope,
                bucket.as_str(),
                hex(&digest)
            ),
            i64::from_be_bytes(lock),
        ))
    }
}

impl core::fmt::Debug for PostgresOidcRateLimiter {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresOidcRateLimiter")
            .field("hash_key", &"[REDACTED]")
            .field("tenant_scope", &self.tenant_scope)
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_bucket_id_never_contain_the_raw_ip_or_email() {
        // bucket_id 本身需 pool，故只钉 HMAC 容器 Debug；真库测试再查 value/id。
        let error = PostgresRateLimitError::DependencyUnavailable;
        assert!(!format!("{error:?}").contains("person@example.com"));
        assert_ne!(
            OidcRateLimitBucket::EmailRouteEmail.as_str(),
            OidcRateLimitBucket::EmailRouteIp.as_str()
        );
    }
}
