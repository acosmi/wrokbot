//! Bounded backup recovery-metadata wrapping using the Vault AES-256-GCM boundary.
//!
//! Domain layer only: caller supplies the 32-byte recovery key, 12-byte nonce, and metadata.
//! This is not an archive format, RestoreAuthorized, or V5-BACKUP-01 close.

use serde::{Deserialize, Serialize};

use crate::vault::aead::{aes_gcm_decrypt, aes_gcm_encrypt};
use crate::vault::{
    ApplicationKeyPurpose, KeyVersion, NONCE_BYTES, Nonce, SecretBytes, TAG_BYTES, VaultError,
    derive_application_key,
};

const AAD_PREFIX: &[u8] = b"openbot.backup.aad.recovery-wrap.v1\x00";
const RECOVERY_SCHEMA: &str = "openbot.backup.recovery.v1";
const ENVELOPE_SCHEMA: &str = "openbot-backup-recovery-wrap";
const ENVELOPE_SCHEMA_VERSION: u64 = 1;
const METADATA_MAX_BYTES: usize = 4096;
/// Canonical JSON bytes with empty nonce and ciphertext, including field names and punctuation.
const ENVELOPE_FIXED_WIRE_BYTES: usize = 86;
const ENVELOPE_MAX_BYTES: usize =
    ENVELOPE_FIXED_WIRE_BYTES + NONCE_BYTES * 2 + (METADATA_MAX_BYTES + TAG_BYTES) * 2;

/// Closed identity used only to form recovery-wrap AAD.
#[derive(Clone)]
pub struct BackupRecoveryBinding {
    bundle_id: String,
    dataset: String,
    key_id: String,
    key_version: KeyVersion,
}

impl BackupRecoveryBinding {
    /// Bind bundle, closed recovery schema, dataset, key id, and key version.
    pub fn new(
        bundle_id: impl Into<String>,
        dataset: impl Into<String>,
        key_id: impl Into<String>,
        key_version: KeyVersion,
    ) -> Result<Self, VaultError> {
        let binding = Self {
            bundle_id: bundle_id.into(),
            dataset: dataset.into(),
            key_id: key_id.into(),
            key_version,
        };
        if !valid_identity(&binding.bundle_id)
            || !valid_identity(&binding.dataset)
            || !valid_hex_id(&binding.key_id)
        {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(binding)
    }

    pub(super) fn aad(&self) -> Vec<u8> {
        let mut aad = AAD_PREFIX.to_vec();
        for field in [
            self.bundle_id.as_bytes(),
            RECOVERY_SCHEMA.as_bytes(),
            self.dataset.as_bytes(),
            self.key_id.as_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u64).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad.extend_from_slice(&u64::from(self.key_version.get()).to_be_bytes());
        aad
    }
}

impl core::fmt::Debug for BackupRecoveryBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRecoveryBinding(<redacted-identities>)")
    }
}

/// Strict canonical JSON envelope for one recovery-metadata wrap.
pub struct BackupRecoveryEnvelope {
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireEnvelope {
    schema: String,
    schema_version: u64,
    nonce: String,
    ciphertext: String,
}

impl BackupRecoveryEnvelope {
    /// Parse a strict, bounded, lowercase-hex recovery envelope.
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        if value.len() > ENVELOPE_MAX_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        let wire: WireEnvelope =
            serde_json::from_str(value).map_err(|_| VaultError::EnvelopeInvalid)?;
        if wire.schema != ENVELOPE_SCHEMA || wire.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(VaultError::EnvelopeInvalid);
        }
        let nonce = decode_hex(&wire.nonce)?;
        let ciphertext = decode_hex(&wire.ciphertext)?;
        if nonce.len() != NONCE_BYTES || ciphertext.len() < TAG_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(Self {
            nonce: Nonce::from_slice(&nonce)?,
            ciphertext,
        })
    }

    /// Serialize the unique closed field order.
    #[must_use]
    pub fn to_column_value(&self) -> String {
        format!(
            "{{\"schema\":\"{ENVELOPE_SCHEMA}\",\"schemaVersion\":{ENVELOPE_SCHEMA_VERSION},\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            encode_hex(self.nonce.as_bytes()),
            encode_hex(&self.ciphertext)
        )
    }
}

impl core::fmt::Debug for BackupRecoveryEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRecoveryEnvelope(<redacted>)")
    }
}

/// Seal bounded recovery metadata under the domain-derived wrap key.
pub fn seal_backup_recovery_wrap(
    recovery_key: &SecretBytes,
    binding: &BackupRecoveryBinding,
    nonce: Nonce,
    metadata: &[u8],
) -> Result<BackupRecoveryEnvelope, VaultError> {
    if metadata.is_empty() || metadata.len() > METADATA_MAX_BYTES {
        return Err(VaultError::PlaintextTooLarge);
    }
    let key = derive_application_key(recovery_key, ApplicationKeyPurpose::BackupRecoveryWrap)?;
    let ciphertext = aes_gcm_encrypt(key.expose(), nonce, &binding.aad(), metadata)?;
    Ok(BackupRecoveryEnvelope { nonce, ciphertext })
}

/// Open recovery metadata only after AEAD authentication succeeds.
pub fn open_backup_recovery_wrap(
    recovery_key: &SecretBytes,
    binding: &BackupRecoveryBinding,
    envelope: &BackupRecoveryEnvelope,
) -> Result<SecretBytes, VaultError> {
    let key = derive_application_key(recovery_key, ApplicationKeyPurpose::BackupRecoveryWrap)?;
    let plaintext = aes_gcm_decrypt(
        key.expose(),
        envelope.nonce,
        &binding.aad(),
        &envelope.ciphertext,
    )?;
    if plaintext.is_empty() || plaintext.len() > METADATA_MAX_BYTES {
        return Err(VaultError::Decrypt);
    }
    Ok(SecretBytes::new(plaintext))
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identity(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|ch| ch == '\0' || ch.is_control())
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

pub(super) fn decode_hex(value: &str) -> Result<Vec<u8>, VaultError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultError::EnvelopeInvalid);
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(VaultError::EnvelopeInvalid);
    }
    for pair in pairs {
        decoded.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(decoded)
}

fn nibble(byte: u8) -> Result<u8, VaultError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(VaultError::EnvelopeInvalid),
    }
}

#[cfg(test)]
mod capacity_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> BackupRecoveryBinding {
        BackupRecoveryBinding::new(
            "bundle-one",
            "dataset-one",
            "aa".repeat(16),
            KeyVersion::new(1),
        )
        .unwrap()
    }

    fn recovery_key() -> SecretBytes {
        SecretBytes::new(vec![0x11; 32])
    }

    fn nonce() -> Nonce {
        Nonce::from_array([0x22; NONCE_BYTES])
    }

    #[test]
    fn round_trip_authenticates_metadata_and_redacts_debug() {
        let metadata = b"vault-key-id=aa;version=1";
        let envelope =
            seal_backup_recovery_wrap(&recovery_key(), &binding(), nonce(), metadata).unwrap();
        let wire = envelope.to_column_value();
        assert!(!wire.contains("vault-key-id"));
        let parsed = BackupRecoveryEnvelope::parse(&wire).unwrap();
        let opened = open_backup_recovery_wrap(&recovery_key(), &binding(), &parsed).unwrap();
        assert_eq!(opened.expose(), metadata);
        assert!(!format!("{envelope:?}").contains("vault-key-id"));
        assert!(!format!("{:?}", binding()).contains("bundle-one"));
    }

    #[test]
    fn truncated_ciphertext_does_not_yield_plaintext() {
        let envelope = seal_backup_recovery_wrap(
            &recovery_key(),
            &binding(),
            nonce(),
            b"vault-key-id=aa;version=1",
        )
        .unwrap();
        let mut truncated = envelope.ciphertext.clone();
        truncated.pop();
        let broken = BackupRecoveryEnvelope {
            nonce: envelope.nonce,
            ciphertext: truncated,
        };
        assert!(matches!(
            open_backup_recovery_wrap(&recovery_key(), &binding(), &broken),
            Err(VaultError::CiphertextTooShort | VaultError::Decrypt)
        ));
    }

    #[test]
    fn wrong_aad_or_key_is_rejected() {
        let envelope = seal_backup_recovery_wrap(
            &recovery_key(),
            &binding(),
            nonce(),
            b"vault-key-id=aa;version=1",
        )
        .unwrap();
        let other = BackupRecoveryBinding::new(
            "bundle-two",
            "dataset-one",
            "aa".repeat(16),
            KeyVersion::new(1),
        )
        .unwrap();
        assert!(matches!(
            open_backup_recovery_wrap(&recovery_key(), &other, &envelope),
            Err(VaultError::Decrypt)
        ));
        let wrong_version = BackupRecoveryBinding::new(
            "bundle-one",
            "dataset-one",
            "aa".repeat(16),
            KeyVersion::new(2),
        )
        .unwrap();
        assert!(matches!(
            open_backup_recovery_wrap(&recovery_key(), &wrong_version, &envelope),
            Err(VaultError::Decrypt)
        ));
        let wrong_key = SecretBytes::new(vec![0x33; 32]);
        assert!(matches!(
            open_backup_recovery_wrap(&wrong_key, &binding(), &envelope),
            Err(VaultError::Decrypt)
        ));
    }

    #[test]
    fn empty_or_oversize_metadata_is_rejected() {
        assert!(matches!(
            seal_backup_recovery_wrap(&recovery_key(), &binding(), nonce(), b""),
            Err(VaultError::PlaintextTooLarge)
        ));
        let huge = vec![0x41; METADATA_MAX_BYTES + 1];
        assert!(matches!(
            seal_backup_recovery_wrap(&recovery_key(), &binding(), nonce(), &huge),
            Err(VaultError::PlaintextTooLarge)
        ));
    }
}
