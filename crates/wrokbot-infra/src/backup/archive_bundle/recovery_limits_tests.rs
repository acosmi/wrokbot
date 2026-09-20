use wrokbot_domain::audit::hash::Sha256Digest;
use wrokbot_domain::backup::{
    BackupRecoveryBinding, BackupRecoveryChunkSpec, seal_backup_recovery_chunk,
    seal_backup_recovery_wrap,
};
use wrokbot_domain::vault::{KeyVersion, NONCE_BYTES, Nonce, SecretBytes};

use super::{
    ArchiveBundleBounds, read_archive_bundle, unpack_archive_bundle, write_archive_bundle,
};

const MAX_METADATA_BYTES: usize = 4096;
const MAX_CANONICAL_ENVELOPE_BYTES: usize = 8334;

fn nonce(tag: u8) -> Nonce {
    Nonce::from_array([tag; NONCE_BYTES])
}

#[test]
fn maximum_wrap_flows_through_archive_write_read_and_authenticated_unpack() {
    let key = SecretBytes::new((0x40u8..0x60).collect());
    let binding = BackupRecoveryBinding::new(
        "bundle-recovery-limits-042",
        "dataset-recovery-limits-042",
        "d5".repeat(16),
        KeyVersion::new(42),
    )
    .unwrap();
    let digest = Sha256Digest::of(b"recovery limits inventory 042");

    let mut expected_wrap = b"maximum-wrap-secret-042:".to_vec();
    expected_wrap.resize(MAX_METADATA_BYTES, 0x6d);
    let expected_chunk = b"small authenticated archive chunk 042".to_vec();

    let wrap = seal_backup_recovery_wrap(&key, &binding, nonce(0x61), &expected_wrap)
        .unwrap()
        .to_column_value();
    assert_eq!(wrap.len(), MAX_CANONICAL_ENVELOPE_BYTES);

    let chunk_spec = BackupRecoveryChunkSpec::new(
        binding.clone(),
        0,
        1,
        u64::try_from(expected_chunk.len()).unwrap(),
        digest,
    )
    .unwrap();
    let chunk = seal_backup_recovery_chunk(&key, &chunk_spec, nonce(0x62), &expected_chunk)
        .unwrap()
        .to_column_value();

    let bounds = ArchiveBundleBounds::standard();
    let mut archive = Vec::new();
    write_archive_bundle(digest, &wrap, &[chunk], bounds, &mut archive).unwrap();
    let contents = read_archive_bundle(&mut archive.as_slice(), bounds, digest).unwrap();
    let unpacked = unpack_archive_bundle(
        &contents,
        &key,
        &binding,
        1,
        u64::try_from(expected_chunk.len()).unwrap(),
    )
    .unwrap();

    assert_eq!(unpacked.wrap_plaintext().expose(), expected_wrap.as_slice());
    assert_eq!(
        unpacked.chunks_plaintext().expose(),
        expected_chunk.as_slice()
    );
}
