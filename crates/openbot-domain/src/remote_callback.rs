//! Remote AG-UI callback credential and signed run-assertion invariants.
//!
//! This module is deterministic: entropy and database time are caller-supplied. PostgreSQL and the
//! OS CSPRNG remain infra effects, while token shape, domain separation, canonical tool-set binding,
//! HMAC verification and expiry are pure and independently testable.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::audit::hash::{CanonicalWriter, Sha256Digest};
use crate::vault::SecretBytes;

/// Human-recognisable prefix for a per-Agent callback credential.
pub const CALLBACK_TOKEN_PREFIX: &str = "obot_agt_";
/// Entropy bytes in a callback token.
pub const CALLBACK_TOKEN_BYTES: usize = 32;
/// Exact callback token string length (`prefix + base64url-no-pad(32 bytes)`).
pub const CALLBACK_TOKEN_LENGTH: usize = CALLBACK_TOKEN_PREFIX.len() + 43;
/// Run assertion lifetime required by the first source.
pub const RUN_ASSERTION_TTL_MILLIS: i64 = 10 * 60 * 1000;
/// Assertion use/domain label; distinct from session/OAuth signatures.
pub const RUN_ASSERTION_LABEL: &str = "openbot:agent-run";
/// Current signed payload version.
pub const RUN_ASSERTION_VERSION: &str = "openbot.remote-run.v1";
/// Maximum signed assertion bytes accepted at the boundary.
pub const MAX_RUN_ASSERTION_BYTES: usize = 16 * 1024;
/// Maximum tools bound into one assertion.
pub const MAX_REMOTE_TOOLS: usize = 256;
/// Maximum UTF-8 bytes in one remote tool name.
pub const MAX_REMOTE_TOOL_NAME_BYTES: usize = 512;

type HmacSha256 = Hmac<Sha256>;

/// Pure callback token/assertion validation failure; contains no presented secret or payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteCallbackCredentialError {
    /// Token entropy or textual shape is invalid.
    #[error("remote_callback_token_invalid")]
    InvalidToken,
    /// Tool set is too large, contains an invalid name, or has a length overflow.
    #[error("remote_callback_tool_set_invalid")]
    InvalidToolSet,
    /// Signing key is empty.
    #[error("remote_callback_signing_key_invalid")]
    InvalidSigningKey,
    /// Assertion syntax, signature, payload schema, scope, or lifetime is invalid.
    #[error("remote_callback_assertion_invalid")]
    InvalidAssertion,
}

/// Render 32 caller-supplied CSPRNG bytes into the fixed callback-token wire shape.
#[must_use]
pub fn callback_token_from_entropy(entropy: [u8; CALLBACK_TOKEN_BYTES]) -> String {
    let mut token = String::with_capacity(CALLBACK_TOKEN_LENGTH);
    token.push_str(CALLBACK_TOKEN_PREFIX);
    URL_SAFE_NO_PAD.encode_string(entropy, &mut token);
    token
}

/// Cheap exact shape validation before a database lookup.
#[must_use]
pub fn looks_like_callback_token(value: &str) -> bool {
    if value.len() != CALLBACK_TOKEN_LENGTH || !value.starts_with(CALLBACK_TOKEN_PREFIX) {
        return false;
    }
    let mut decoded = [0_u8; CALLBACK_TOKEN_BYTES];
    URL_SAFE_NO_PAD
        .decode_slice(
            &value.as_bytes()[CALLBACK_TOKEN_PREFIX.len()..],
            &mut decoded,
        )
        .is_ok_and(|written| written == CALLBACK_TOKEN_BYTES)
}

/// SHA-256 value stored in PostgreSQL instead of the usable callback credential.
pub fn callback_token_hash(value: &str) -> Result<Sha256Digest, RemoteCallbackCredentialError> {
    if !looks_like_callback_token(value) {
        return Err(RemoteCallbackCredentialError::InvalidToken);
    }
    Ok(Sha256Digest::of(value.as_bytes()))
}

/// Compare stored/computed callback-token hashes without a prefix timing oracle.
#[must_use]
pub fn same_callback_token_hash(left: &Sha256Digest, right: &Sha256Digest) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

/// Canonical set of tools the deployment actually offered to one remote run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteToolSet {
    names: BTreeSet<String>,
    digest: Sha256Digest,
}

impl RemoteToolSet {
    /// Validate, sort, deduplicate, and length-frame tool names before hashing.
    pub fn new<I, S>(names: I) -> Result<Self, RemoteCallbackCredentialError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let names = names.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        if names.len() > MAX_REMOTE_TOOLS
            || names.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_REMOTE_TOOL_NAME_BYTES
                    || name.as_bytes().contains(&0)
            })
        {
            return Err(RemoteCallbackCredentialError::InvalidToolSet);
        }
        let mut writer = CanonicalWriter::new("openbot:remote-tool-set:v1");
        writer.u64(
            u64::try_from(names.len())
                .map_err(|_| RemoteCallbackCredentialError::InvalidToolSet)?,
        );
        for name in &names {
            writer.bytes(name.as_bytes());
        }
        let digest = writer.digest_of_written();
        Ok(Self { names, digest })
    }

    /// Empty, explicitly deny-all tool set.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(std::iter::empty::<String>()).expect("empty tool set is valid")
    }

    /// Whether the exact callback tool was offered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Canonical whole-set digest bound into the assertion.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Stable sorted names for protocol projection.
    #[must_use]
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }
}

/// Authoritative scope to sign for one remote run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRunScope {
    /// Deployment bound by the signing key and payload.
    pub deployment: DeploymentId,
    /// Tenant bound by the payload.
    pub tenant: TenantId,
    /// Remote Bot receiving the assertion.
    pub bot: BotId,
    /// Session-resolved actor on whose behalf the run executes.
    pub actor: ActorId,
    /// Durable run id.
    pub run: RunId,
}

/// Verified signed run claims. No constructor is public other than verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteRun {
    scope: RemoteRunScope,
    tools: Sha256Digest,
    issued_at_millis: i64,
    expires_at_millis: i64,
}

impl VerifiedRemoteRun {
    /// Verified scope.
    #[must_use]
    pub const fn scope(&self) -> &RemoteRunScope {
        &self.scope
    }

    /// Verified canonical tool-set digest.
    #[must_use]
    pub const fn tool_set_digest(&self) -> Sha256Digest {
        self.tools
    }

    /// Database-issued Unix milliseconds.
    #[must_use]
    pub const fn issued_at_millis(&self) -> i64 {
        self.issued_at_millis
    }

    /// Exact ten-minute expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedRemoteRun {
    version: String,
    deployment_id: String,
    tenant_id: String,
    bot_id: String,
    actor_id: String,
    run_id: String,
    tool_set_hash: String,
    #[serde(rename = "iat")]
    issued_at_millis: i64,
    #[serde(rename = "exp")]
    expires_at_millis: i64,
}

/// HMAC signer/verifier holding only domain-separated run-signing material.
pub struct RemoteRunAssertionSigner {
    key: SecretBytes,
}

impl RemoteRunAssertionSigner {
    /// Derive the run-only signing key from the current deployment master.
    pub fn new(master: Vec<u8>) -> Result<Self, RemoteCallbackCredentialError> {
        if master.is_empty() {
            return Err(RemoteCallbackCredentialError::InvalidSigningKey);
        }
        let mut derivation = HmacSha256::new_from_slice(&master)
            .map_err(|_| RemoteCallbackCredentialError::InvalidSigningKey)?;
        derivation.update(RUN_ASSERTION_LABEL.as_bytes());
        let key = derivation.finalize().into_bytes().to_vec();
        drop(SecretBytes::new(master));
        Ok(Self {
            key: SecretBytes::new(key),
        })
    }

    /// Sign a run for exactly ten minutes from caller-supplied database time.
    pub fn mint(
        &self,
        scope: RemoteRunScope,
        tools: &RemoteToolSet,
        issued_at_millis: i64,
    ) -> Result<String, RemoteCallbackCredentialError> {
        validate_scope(&scope)?;
        if issued_at_millis < 0 {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
        let expires_at_millis = issued_at_millis
            .checked_add(RUN_ASSERTION_TTL_MILLIS)
            .ok_or(RemoteCallbackCredentialError::InvalidAssertion)?;
        let payload = SignedRemoteRun {
            version: RUN_ASSERTION_VERSION.to_owned(),
            deployment_id: scope.deployment.as_str().to_owned(),
            tenant_id: scope.tenant.as_str().to_owned(),
            bot_id: scope.bot.as_str().to_owned(),
            actor_id: scope.actor.as_str().to_owned(),
            run_id: scope.run.as_str().to_owned(),
            tool_set_hash: tools.digest().to_hex(),
            issued_at_millis,
            expires_at_millis,
        };
        let payload = serde_json::to_vec(&payload)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        let value = URL_SAFE_NO_PAD.encode(payload);
        let signature = self.sign(value.as_bytes())?;
        let signed = format!("{value}.{}", URL_SAFE_NO_PAD.encode(signature));
        if signed.len() > MAX_RUN_ASSERTION_BYTES {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
        Ok(signed)
    }

    /// Verify signature, strict payload schema, exact lifetime, scope shape, and database time.
    pub fn verify(
        &self,
        signed: &str,
        now_millis: i64,
    ) -> Result<VerifiedRemoteRun, RemoteCallbackCredentialError> {
        if signed.is_empty()
            || signed.len() > MAX_RUN_ASSERTION_BYTES
            || signed.as_bytes().contains(&0)
            || now_millis < 0
        {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
        let (value, encoded_signature) = signed
            .split_once('.')
            .filter(|(value, signature)| {
                !value.is_empty() && !signature.is_empty() && !signature.contains('.')
            })
            .ok_or(RemoteCallbackCredentialError::InvalidAssertion)?;
        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        if signature.len() != 32 {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
        let mut verifier = HmacSha256::new_from_slice(self.key.expose())
            .map_err(|_| RemoteCallbackCredentialError::InvalidSigningKey)?;
        verifier.update(value.as_bytes());
        verifier
            .verify_slice(&signature)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        let payload = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        let payload: SignedRemoteRun = serde_json::from_slice(&payload)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        let tools = Sha256Digest::parse_hex(&payload.tool_set_hash)
            .map_err(|_| RemoteCallbackCredentialError::InvalidAssertion)?;
        let scope = RemoteRunScope {
            deployment: DeploymentId::new(payload.deployment_id),
            tenant: TenantId::new(payload.tenant_id),
            bot: BotId::new(payload.bot_id),
            actor: ActorId::new(payload.actor_id),
            run: RunId::new(payload.run_id),
        };
        validate_scope(&scope)?;
        if payload.version != RUN_ASSERTION_VERSION
            || payload.issued_at_millis < 0
            || payload
                .issued_at_millis
                .checked_add(RUN_ASSERTION_TTL_MILLIS)
                != Some(payload.expires_at_millis)
            || now_millis < payload.issued_at_millis
            || now_millis >= payload.expires_at_millis
        {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
        Ok(VerifiedRemoteRun {
            scope,
            tools,
            issued_at_millis: payload.issued_at_millis,
            expires_at_millis: payload.expires_at_millis,
        })
    }

    fn sign(&self, value: &[u8]) -> Result<[u8; 32], RemoteCallbackCredentialError> {
        let mut signer = HmacSha256::new_from_slice(self.key.expose())
            .map_err(|_| RemoteCallbackCredentialError::InvalidSigningKey)?;
        signer.update(value);
        Ok(signer.finalize().into_bytes().into())
    }
}

impl core::fmt::Debug for RemoteRunAssertionSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteRunAssertionSigner")
            .field("key", &"[redacted]")
            .finish()
    }
}

fn validate_scope(scope: &RemoteRunScope) -> Result<(), RemoteCallbackCredentialError> {
    for value in [
        scope.deployment.as_str(),
        scope.tenant.as_str(),
        scope.bot.as_str(),
        scope.actor.as_str(),
        scope.run.as_str(),
    ] {
        if value.is_empty() || value.len() > 4096 || value.as_bytes().contains(&0) {
            return Err(RemoteCallbackCredentialError::InvalidAssertion);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RemoteRunScope {
        RemoteRunScope {
            deployment: DeploymentId::new("deployment-a"),
            tenant: TenantId::new("tenant-a"),
            bot: BotId::new("agent-a"),
            actor: ActorId::new("actor-a"),
            run: RunId::new("run-a"),
        }
    }

    #[test]
    fn callback_tokens_are_exactly_shaped_unique_and_hash_only_themselves() {
        let first = callback_token_from_entropy([1; CALLBACK_TOKEN_BYTES]);
        let second = callback_token_from_entropy([2; CALLBACK_TOKEN_BYTES]);
        assert!(looks_like_callback_token(&first));
        assert!(looks_like_callback_token(&second));
        assert_ne!(first, second);
        assert_eq!(first.len(), CALLBACK_TOKEN_LENGTH);
        assert_eq!(callback_token_hash(&first), callback_token_hash(&first));
        assert_ne!(callback_token_hash(&first), callback_token_hash(&second));
        for invalid in [
            "Bearer hunter2",
            "obot_agt_",
            "obot_agt_not-a-32-byte-token",
        ] {
            assert!(!looks_like_callback_token(invalid));
            assert_eq!(
                callback_token_hash(invalid),
                Err(RemoteCallbackCredentialError::InvalidToken)
            );
        }
    }

    #[test]
    fn tool_set_is_order_independent_duplicate_free_and_length_framed() {
        let first = RemoteToolSet::new(["mcp__a__bc", "mcp__ab__c", "mcp__a__bc"]).unwrap();
        let second = RemoteToolSet::new(["mcp__ab__c", "mcp__a__bc"]).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("mcp__a__bc"));
        assert!(!first.contains("mcp__a__b"));
        assert_eq!(
            first.names().collect::<Vec<_>>(),
            ["mcp__a__bc", "mcp__ab__c"]
        );
        assert_ne!(
            first.digest(),
            RemoteToolSet::new(["mcp__a__b", "cmcp__ab__c"])
                .unwrap()
                .digest()
        );
        assert_eq!(
            RemoteToolSet::new([""]),
            Err(RemoteCallbackCredentialError::InvalidToolSet)
        );
    }

    #[test]
    fn assertion_round_trip_binds_scope_tool_set_and_exact_ten_minute_lifetime() {
        let signer = RemoteRunAssertionSigner::new(b"deployment-master".to_vec()).unwrap();
        let tools = RemoteToolSet::new(["mcp__drive__search"]).unwrap();
        let signed = signer.mint(scope(), &tools, 1_000).unwrap();
        let verified = signer.verify(&signed, 1_001).unwrap();
        assert_eq!(verified.scope(), &scope());
        assert_eq!(verified.tool_set_digest(), tools.digest());
        assert_eq!(verified.issued_at_millis(), 1_000);
        assert_eq!(verified.expires_at_millis(), 601_000);
        assert!(signer.verify(&signed, 600_999).is_ok());
        assert_eq!(
            signer.verify(&signed, 601_000),
            Err(RemoteCallbackCredentialError::InvalidAssertion)
        );
    }

    #[test]
    fn signed_wire_matches_the_pinned_node_hmac_and_base64url_algorithm() {
        const NODE_VECTOR: &str = "eyJ2ZXJzaW9uIjoib3BlbmJvdC5yZW1vdGUtcnVuLnYxIiwiZGVwbG95bWVudElkIjoiZGVwbG95bWVudC1hIiwidGVuYW50SWQiOiJ0ZW5hbnQtYSIsImJvdElkIjoiYWdlbnQtYSIsImFjdG9ySWQiOiJhY3Rvci1hIiwicnVuSWQiOiJydW4tYSIsInRvb2xTZXRIYXNoIjoiYmU0NmIzMDg3ODFjYzJkOGYzNTNhODVjNTdkNTI3YzQwMDY2ODg3M2Q2Y2U0ZmFiNjQ0NTdhYTU2OTg1MjYyNiIsImlhdCI6MTAwMCwiZXhwIjo2MDEwMDB9.WZnvhRmDQyCxFUmSZHlSLtT1tEV0ku_PuJO5iC-FhZw";
        let signer = RemoteRunAssertionSigner::new(b"deployment-master".to_vec()).unwrap();
        assert_eq!(
            signer.mint(scope(), &RemoteToolSet::empty(), 1_000),
            Ok(NODE_VECTOR.to_owned())
        );
        assert_eq!(signer.verify(NODE_VECTOR, 1_001).unwrap().scope(), &scope());
    }

    #[test]
    fn assertion_rejects_wrong_key_tampering_future_time_and_malformed_input() {
        let signer = RemoteRunAssertionSigner::new(b"deployment-master".to_vec()).unwrap();
        let wrong = RemoteRunAssertionSigner::new(b"another-master".to_vec()).unwrap();
        let signed = signer
            .mint(scope(), &RemoteToolSet::empty(), 1_000)
            .unwrap();
        assert_eq!(
            wrong.verify(&signed, 1_001),
            Err(RemoteCallbackCredentialError::InvalidAssertion)
        );
        let (value, signature) = signed.split_once('.').unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).unwrap()).unwrap();
        payload["botId"] = serde_json::Value::String("agent-b".to_owned());
        let forged = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
            signature
        );
        assert_eq!(
            signer.verify(&forged, 1_001),
            Err(RemoteCallbackCredentialError::InvalidAssertion)
        );
        assert_eq!(
            signer.verify(&signed, 999),
            Err(RemoteCallbackCredentialError::InvalidAssertion)
        );
        for malformed in ["", "not-signed", ".", "a.b.c", "a.bad!"] {
            assert_eq!(
                signer.verify(malformed, 1_001),
                Err(RemoteCallbackCredentialError::InvalidAssertion)
            );
        }
    }
}
