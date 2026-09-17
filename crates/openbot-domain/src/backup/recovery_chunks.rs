//! Ordered backup recovery chunks with sequence, total length, and inventory digest in AAD.
//!
//! One in-flight chunk: the assembler only opens the next sequence. Reorder, truncate,
//! and cross-bundle ciphertext do not yield assembled plaintext.

use serde::{Deserialize, Serialize};

use super::recovery_wrap::{BackupRecoveryBinding, decode_hex, encode_hex};
use crate::audit::hash::Sha256Digest;
use crate::vault::aead::{aes_gcm_decrypt, aes_gcm_encrypt};
use crate::vault::{
    ApplicationKeyPurpose, NONCE_BYTES, Nonce, SecretBytes, TAG_BYTES, VaultError,
    derive_application_key,
};

const CHUNK_AAD_PREFIX: &[u8] = b"openbot.backup.aad.recovery-chunk.v1\x00";
const ENVELOPE_SCHEMA: &str = "openbot-backup-recovery-chunk";
const ENVELOPE_SCHEMA_VERSION: u64 = 1;
const ENVELOPE_MAX_BYTES: usize = 8 * 1024 * 1024 + 4096;
const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: u32 = 32;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;

/// Closed per-chunk identity: 037 binding plus sequence, count, total length, inventory digest.
pub struct BackupRecoveryChunkSpec {
    binding: BackupRecoveryBinding,
    sequence: u32,
    chunk_count: u32,
    total_bytes: u64,
    inventory_digest: Sha256Digest,
}

impl BackupRecoveryChunkSpec {
    /// Construct one chunk's authenticated identity.
    pub fn new(
        binding: BackupRecoveryBinding,
        sequence: u32,
        chunk_count: u32,
        total_bytes: u64,
        inventory_digest: Sha256Digest,
    ) -> Result<Self, VaultError> {
        if chunk_count == 0
            || chunk_count > MAX_CHUNKS
            || sequence >= chunk_count
            || total_bytes == 0
            || total_bytes > MAX_TOTAL_BYTES
        {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(Self {
            binding,
            sequence,
            chunk_count,
            total_bytes,
            inventory_digest,
        })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = CHUNK_AAD_PREFIX.to_vec();
        aad.extend_from_slice(&self.binding.aad());
        aad.extend_from_slice(&u64::from(self.sequence).to_be_bytes());
        aad.extend_from_slice(&u64::from(self.chunk_count).to_be_bytes());
        aad.extend_from_slice(&self.total_bytes.to_be_bytes());
        aad.extend_from_slice(self.inventory_digest.as_bytes());
        aad
    }
}

impl core::fmt::Debug for BackupRecoveryChunkSpec {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRecoveryChunkSpec(<redacted>)")
    }
}

/// Strict canonical JSON envelope for one recovery chunk.
pub struct BackupRecoveryChunkEnvelope {
    sequence: u32,
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireChunkEnvelope {
    schema: String,
    schema_version: u64,
    sequence: u64,
    nonce: String,
    ciphertext: String,
}

impl BackupRecoveryChunkEnvelope {
    /// Parse a bounded chunk envelope. Sequence in JSON is a locator only.
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        if value.len() > ENVELOPE_MAX_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        let wire: WireChunkEnvelope =
            serde_json::from_str(value).map_err(|_| VaultError::EnvelopeInvalid)?;
        if wire.schema != ENVELOPE_SCHEMA || wire.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(VaultError::EnvelopeInvalid);
        }
        if wire.sequence > u64::from(u32::MAX) {
            return Err(VaultError::EnvelopeInvalid);
        }
        let nonce = decode_hex(&wire.nonce)?;
        let ciphertext = decode_hex(&wire.ciphertext)?;
        if nonce.len() != NONCE_BYTES || ciphertext.len() < TAG_BYTES {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(Self {
            sequence: u32::try_from(wire.sequence).map_err(|_| VaultError::EnvelopeInvalid)?,
            nonce: Nonce::from_slice(&nonce)?,
            ciphertext,
        })
    }

    /// Serialize the unique closed field order.
    #[must_use]
    pub fn to_column_value(&self) -> String {
        format!(
            "{{\"schema\":\"{ENVELOPE_SCHEMA}\",\"schemaVersion\":{ENVELOPE_SCHEMA_VERSION},\"sequence\":{},\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            self.sequence,
            encode_hex(self.nonce.as_bytes()),
            encode_hex(&self.ciphertext)
        )
    }
}

impl core::fmt::Debug for BackupRecoveryChunkEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRecoveryChunkEnvelope(<redacted>)")
    }
}

/// Seal one chunk. Caller supplies nonce; uniqueness is an infra obligation.
pub fn seal_backup_recovery_chunk(
    recovery_key: &SecretBytes,
    spec: &BackupRecoveryChunkSpec,
    nonce: Nonce,
    plaintext: &[u8],
) -> Result<BackupRecoveryChunkEnvelope, VaultError> {
    if plaintext.is_empty() || plaintext.len() > MAX_CHUNK_BYTES {
        return Err(VaultError::PlaintextTooLarge);
    }
    if u64::try_from(plaintext.len()).unwrap_or(u64::MAX) > spec.total_bytes {
        return Err(VaultError::PlaintextTooLarge);
    }
    let key = derive_application_key(recovery_key, ApplicationKeyPurpose::BackupRecoveryWrap)?;
    let ciphertext = aes_gcm_encrypt(key.expose(), nonce, &spec.aad(), plaintext)?;
    Ok(BackupRecoveryChunkEnvelope {
        sequence: spec.sequence,
        nonce,
        ciphertext,
    })
}

/// Open one chunk against the caller-supplied spec. Envelope sequence must match spec.
pub fn open_backup_recovery_chunk(
    recovery_key: &SecretBytes,
    spec: &BackupRecoveryChunkSpec,
    envelope: &BackupRecoveryChunkEnvelope,
) -> Result<SecretBytes, VaultError> {
    if envelope.sequence != spec.sequence {
        return Err(VaultError::EnvelopeInvalid);
    }
    let key = derive_application_key(recovery_key, ApplicationKeyPurpose::BackupRecoveryWrap)?;
    let plaintext = aes_gcm_decrypt(
        key.expose(),
        envelope.nonce,
        &spec.aad(),
        &envelope.ciphertext,
    )?;
    if plaintext.is_empty() || plaintext.len() > MAX_CHUNK_BYTES {
        return Err(VaultError::Decrypt);
    }
    Ok(SecretBytes::new(plaintext))
}

/// Sequential assembler: only the next sequence is accepted; finish yields plaintext only when complete.
pub struct BackupRecoveryChunkStream {
    binding: BackupRecoveryBinding,
    chunk_count: u32,
    total_bytes: u64,
    inventory_digest: Sha256Digest,
    next_sequence: u32,
    accumulated: zeroize::Zeroizing<Vec<u8>>,
}

impl BackupRecoveryChunkStream {
    /// Begin an ordered assembly. No plaintext is available until [`Self::finish`].
    pub fn begin(
        binding: BackupRecoveryBinding,
        chunk_count: u32,
        total_bytes: u64,
        inventory_digest: Sha256Digest,
    ) -> Result<Self, VaultError> {
        if chunk_count == 0
            || chunk_count > MAX_CHUNKS
            || total_bytes == 0
            || total_bytes > MAX_TOTAL_BYTES
        {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(Self {
            binding,
            chunk_count,
            total_bytes,
            inventory_digest,
            next_sequence: 0,
            accumulated: zeroize::Zeroizing::new(Vec::new()),
        })
    }

    /// Open and append exactly the next chunk. On failure the assembler is unchanged.
    pub fn accept(
        &mut self,
        recovery_key: &SecretBytes,
        envelope: &BackupRecoveryChunkEnvelope,
    ) -> Result<(), VaultError> {
        if self.next_sequence >= self.chunk_count {
            return Err(VaultError::EnvelopeInvalid);
        }
        let spec = BackupRecoveryChunkSpec::new(
            self.binding.clone(),
            self.next_sequence,
            self.chunk_count,
            self.total_bytes,
            self.inventory_digest,
        )?;
        let opened = open_backup_recovery_chunk(recovery_key, &spec, envelope)?;
        let piece = opened.expose();
        let added = u64::try_from(piece.len()).map_err(|_| VaultError::EnvelopeInvalid)?;
        let have = u64::try_from(self.accumulated.len()).map_err(|_| VaultError::EnvelopeInvalid)?;
        let next_len = have.checked_add(added).ok_or(VaultError::EnvelopeInvalid)?;
        if next_len > self.total_bytes {
            return Err(VaultError::EnvelopeInvalid);
        }
        if self.next_sequence + 1 == self.chunk_count && next_len != self.total_bytes {
            return Err(VaultError::EnvelopeInvalid);
        }
        self.accumulated.extend_from_slice(piece);
        self.next_sequence += 1;
        Ok(())
    }

    /// Release assembled plaintext only when every chunk was accepted and the total matches.
    pub fn finish(self) -> Result<SecretBytes, VaultError> {
        if self.next_sequence != self.chunk_count
            || u64::try_from(self.accumulated.len()).unwrap_or(u64::MAX) != self.total_bytes
        {
            return Err(VaultError::EnvelopeInvalid);
        }
        Ok(SecretBytes::new(self.accumulated.to_vec()))
    }
}

impl core::fmt::Debug for BackupRecoveryChunkStream {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRecoveryChunkStream(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KeyVersion;

    fn binding() -> BackupRecoveryBinding {
        BackupRecoveryBinding::new(
            "bundle-one",
            "dataset-one",
            "aa".repeat(16),
            KeyVersion::new(1),
        )
        .unwrap()
    }

    fn other_binding() -> BackupRecoveryBinding {
        BackupRecoveryBinding::new(
            "bundle-two",
            "dataset-one",
            "aa".repeat(16),
            KeyVersion::new(1),
        )
        .unwrap()
    }

    fn recovery_key() -> SecretBytes {
        SecretBytes::new(vec![0x11; 32])
    }

    fn digest() -> Sha256Digest {
        Sha256Digest::of(b"terminal-inventory")
    }

    fn spec(sequence: u32) -> BackupRecoveryChunkSpec {
        BackupRecoveryChunkSpec::new(binding(), sequence, 2, 8, digest()).unwrap()
    }

    fn nonce(tag: u8) -> Nonce {
        Nonce::from_array([tag; NONCE_BYTES])
    }

    #[test]
    fn two_chunks_round_trip_in_order() {
        let first = seal_backup_recovery_chunk(&recovery_key(), &spec(0), nonce(1), b"abcd").unwrap();
        let second =
            seal_backup_recovery_chunk(&recovery_key(), &spec(1), nonce(2), b"efgh").unwrap();
        let mut stream =
            BackupRecoveryChunkStream::begin(binding(), 2, 8, digest()).unwrap();
        stream.accept(&recovery_key(), &first).unwrap();
        stream.accept(&recovery_key(), &second).unwrap();
        let assembled = stream.finish().unwrap();
        assert_eq!(assembled.expose(), b"abcdefgh");
        assert!(!format!("{first:?}").contains("abcd"));
    }

    #[test]
    fn reorder_does_not_assemble() {
        let first = seal_backup_recovery_chunk(&recovery_key(), &spec(0), nonce(1), b"abcd").unwrap();
        let second =
            seal_backup_recovery_chunk(&recovery_key(), &spec(1), nonce(2), b"efgh").unwrap();
        let mut stream =
            BackupRecoveryChunkStream::begin(binding(), 2, 8, digest()).unwrap();
        assert!(matches!(
            stream.accept(&recovery_key(), &second),
            Err(VaultError::EnvelopeInvalid | VaultError::Decrypt)
        ));
        stream.accept(&recovery_key(), &first).unwrap();
        assert!(matches!(stream.finish(), Err(VaultError::EnvelopeInvalid)));
    }

    #[test]
    fn truncated_stream_does_not_yield_plaintext() {
        let first = seal_backup_recovery_chunk(&recovery_key(), &spec(0), nonce(1), b"abcd").unwrap();
        let mut stream =
            BackupRecoveryChunkStream::begin(binding(), 2, 8, digest()).unwrap();
        stream.accept(&recovery_key(), &first).unwrap();
        assert!(matches!(stream.finish(), Err(VaultError::EnvelopeInvalid)));
    }

    #[test]
    fn truncated_ciphertext_does_not_open() {
        let envelope =
            seal_backup_recovery_chunk(&recovery_key(), &spec(0), nonce(1), b"abcd").unwrap();
        let mut ciphertext = envelope.ciphertext.clone();
        ciphertext.pop();
        let broken = BackupRecoveryChunkEnvelope {
            sequence: envelope.sequence,
            nonce: envelope.nonce,
            ciphertext,
        };
        assert!(matches!(
            open_backup_recovery_chunk(&recovery_key(), &spec(0), &broken),
            Err(VaultError::CiphertextTooShort | VaultError::Decrypt)
        ));
    }

    #[test]
    fn cross_bundle_chunk_does_not_open() {
        let envelope =
            seal_backup_recovery_chunk(&recovery_key(), &spec(0), nonce(1), b"abcd").unwrap();
        let foreign = BackupRecoveryChunkSpec::new(other_binding(), 0, 2, 8, digest()).unwrap();
        assert!(matches!(
            open_backup_recovery_chunk(&recovery_key(), &foreign, &envelope),
            Err(VaultError::Decrypt)
        ));
    }
}
