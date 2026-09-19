use crate::vault::{KeyVersion, NONCE_BYTES, Nonce, SecretBytes, VaultError};

use super::{
    BackupRecoveryBinding, BackupRecoveryEnvelope, open_backup_recovery_wrap,
    seal_backup_recovery_wrap,
};

const MAX_METADATA_BYTES: usize = 4096;
const MAX_CANONICAL_ENVELOPE_BYTES: usize = 8334;
const SECRET_MARKER: &str = "capacity-secret-042";

fn binding() -> BackupRecoveryBinding {
    BackupRecoveryBinding::new(
        "bundle-capacity-042",
        "dataset-capacity-042",
        "c4".repeat(16),
        KeyVersion::new(42),
    )
    .unwrap()
}

fn recovery_key() -> SecretBytes {
    SecretBytes::new((0x20u8..0x40).collect())
}

fn nonce(tag: u8) -> Nonce {
    Nonce::from_array([tag; NONCE_BYTES])
}

fn metadata_with_len(len: usize) -> Vec<u8> {
    let mut metadata = format!("{SECRET_MARKER}:").into_bytes();
    metadata.resize(len, 0x5a);
    metadata
}

#[test]
fn maximum_metadata_seals_to_8334_bytes_and_round_trips_exactly() {
    let metadata = metadata_with_len(MAX_METADATA_BYTES);
    let key = recovery_key();
    let binding = binding();
    let envelope = seal_backup_recovery_wrap(&key, &binding, nonce(0x41), &metadata).unwrap();
    let column = envelope.to_column_value();

    assert_eq!(column.len(), MAX_CANONICAL_ENVELOPE_BYTES);
    let parsed = BackupRecoveryEnvelope::parse(&column).unwrap();
    let opened = open_backup_recovery_wrap(&key, &binding, &parsed).unwrap();
    assert_eq!(opened.expose(), metadata.as_slice());
}

#[test]
fn metadata_one_byte_over_the_public_limit_is_still_rejected_without_plaintext() {
    let metadata = metadata_with_len(MAX_METADATA_BYTES + 1);
    let result = seal_backup_recovery_wrap(&recovery_key(), &binding(), nonce(0x42), &metadata);
    let debug = format!("{result:?}");

    assert!(matches!(result, Err(VaultError::PlaintextTooLarge)));
    assert!(!debug.contains(SECRET_MARKER));
}

#[test]
fn maximum_envelope_plus_one_whitespace_byte_is_rejected_before_json_acceptance() {
    let metadata = metadata_with_len(MAX_METADATA_BYTES);
    let envelope =
        seal_backup_recovery_wrap(&recovery_key(), &binding(), nonce(0x43), &metadata).unwrap();
    let mut oversized = envelope.to_column_value();
    assert_eq!(oversized.len(), MAX_CANONICAL_ENVELOPE_BYTES);
    oversized.push(' ');
    assert_eq!(oversized.len(), MAX_CANONICAL_ENVELOPE_BYTES + 1);

    let result = BackupRecoveryEnvelope::parse(&oversized);
    let debug = format!("{result:?}");
    assert!(matches!(result, Err(VaultError::EnvelopeInvalid)));
    assert!(!debug.contains(SECRET_MARKER));
}

#[test]
fn maximum_envelope_ciphertext_tampering_fails_aead_without_plaintext() {
    let metadata = metadata_with_len(MAX_METADATA_BYTES);
    let key = recovery_key();
    let binding = binding();
    let envelope = seal_backup_recovery_wrap(&key, &binding, nonce(0x44), &metadata).unwrap();
    let mut tampered = envelope.to_column_value().into_bytes();
    assert_eq!(tampered.len(), MAX_CANONICAL_ENVELOPE_BYTES);

    let ciphertext_last = tampered.len() - 3;
    tampered[ciphertext_last] = if tampered[ciphertext_last] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let tampered = String::from_utf8(tampered).unwrap();
    let parsed = BackupRecoveryEnvelope::parse(&tampered).unwrap();
    let result = open_backup_recovery_wrap(&key, &binding, &parsed);
    let debug = format!("{result:?}");

    assert!(matches!(result, Err(VaultError::Decrypt)));
    assert!(!debug.contains(SECRET_MARKER));
}
