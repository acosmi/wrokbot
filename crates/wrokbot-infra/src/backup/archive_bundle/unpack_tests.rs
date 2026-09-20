use wrokbot_domain::audit::hash::Sha256Digest;
use wrokbot_domain::backup::{
    BackupRecoveryBinding, BackupRecoveryChunkSpec, seal_backup_recovery_chunk,
    seal_backup_recovery_wrap,
};
use wrokbot_domain::vault::{KeyVersion, NONCE_BYTES, Nonce, SecretBytes};

use super::{
    ArchiveBundleBounds, ArchiveBundleContents, ArchiveBundleFault, UnpackedArchiveBundle,
    read_archive_bundle, unpack_archive_bundle, write_archive_bundle,
};

const WRAP_PLAINTEXT: &[u8] = b"opaque recovery metadata: wrap-secret-040";
const CHUNK_PARTS: [&[u8]; 3] = [
    b"first authenticated chunk/",
    b"second authenticated chunk/",
    b"last authenticated chunk: chunk-secret-040",
];

struct Fixture {
    key: SecretBytes,
    binding: BackupRecoveryBinding,
    digest: Sha256Digest,
    wrap_wire: String,
    chunk_wires: Vec<String>,
    archive_bytes: Vec<u8>,
    contents: ArchiveBundleContents,
    chunks_plaintext: Vec<u8>,
}

fn binding(
    bundle_id: &str,
    dataset: &str,
    key_id_byte: &str,
    key_version: u32,
) -> BackupRecoveryBinding {
    BackupRecoveryBinding::new(
        bundle_id,
        dataset,
        key_id_byte.repeat(32 / key_id_byte.len()),
        KeyVersion::new(key_version),
    )
    .unwrap()
}

fn nonce(tag: u8) -> Nonce {
    Nonce::from_array([tag; NONCE_BYTES])
}

fn fixture() -> Fixture {
    let key = SecretBytes::new((0u8..32).collect());
    let binding = binding("bundle-040", "dataset-040", "a1", 7);
    let digest = Sha256Digest::of(b"terminal inventory for V6-PR-040");
    let chunks_plaintext = CHUNK_PARTS.concat();
    let chunk_count = u32::try_from(CHUNK_PARTS.len()).unwrap();
    let total_bytes = u64::try_from(chunks_plaintext.len()).unwrap();

    // Every seal under this fixture key has a distinct nonce: 0x40 for the wrap,
    // then 0x51..=0x53 for the three chunks.
    let wrap_wire = seal_backup_recovery_wrap(&key, &binding, nonce(0x40), WRAP_PLAINTEXT)
        .unwrap()
        .to_column_value();
    let chunk_wires = CHUNK_PARTS
        .iter()
        .enumerate()
        .map(|(sequence, plaintext)| {
            let spec = BackupRecoveryChunkSpec::new(
                binding.clone(),
                u32::try_from(sequence).unwrap(),
                chunk_count,
                total_bytes,
                digest,
            )
            .unwrap();
            seal_backup_recovery_chunk(
                &key,
                &spec,
                nonce(0x51 + u8::try_from(sequence).unwrap()),
                plaintext,
            )
            .unwrap()
            .to_column_value()
        })
        .collect::<Vec<_>>();

    let bounds = ArchiveBundleBounds::standard();
    let mut archive_bytes = Vec::new();
    write_archive_bundle(digest, &wrap_wire, &chunk_wires, bounds, &mut archive_bytes).unwrap();
    let contents = read_archive_bundle(&mut archive_bytes.as_slice(), bounds, digest).unwrap();

    Fixture {
        key,
        binding,
        digest,
        wrap_wire,
        chunk_wires,
        archive_bytes,
        contents,
        chunks_plaintext,
    }
}

fn corrupt_ciphertext(wire: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(wire).unwrap();
    let ciphertext = value["ciphertext"].as_str().unwrap();
    let replacement = if ciphertext.ends_with('0') { '1' } else { '0' };
    let mut corrupted = ciphertext[..ciphertext.len() - 1].to_owned();
    corrupted.push(replacement);
    value["ciphertext"] = serde_json::Value::String(corrupted);
    serde_json::to_string(&value).unwrap()
}

fn with_parts(
    fixture: &Fixture,
    wrap_envelope: String,
    chunk_envelopes: Vec<String>,
) -> ArchiveBundleContents {
    ArchiveBundleContents {
        inventory_digest: fixture.digest,
        wrap_envelope,
        chunk_envelopes,
    }
}

fn total_bytes(fixture: &Fixture) -> u64 {
    u64::try_from(fixture.chunks_plaintext.len()).unwrap()
}

fn assert_failure_redacts(
    result: Result<UnpackedArchiveBundle, ArchiveBundleFault>,
    expected: ArchiveBundleFault,
) {
    let rendered = format!("{result:?}");
    assert_eq!(result.err(), Some(expected));
    assert!(!rendered.contains("wrap-secret-040"));
    assert!(!rendered.contains("chunk-secret-040"));
}

#[test]
fn real_seal_write_read_unpack_chain_returns_exact_multichunk_bytes_and_redacts_debug() {
    let fixture = fixture();

    assert!(
        !fixture
            .archive_bytes
            .windows(WRAP_PLAINTEXT.len())
            .any(|window| window == WRAP_PLAINTEXT)
    );
    assert!(
        !fixture
            .archive_bytes
            .windows(fixture.chunks_plaintext.len())
            .any(|window| window == fixture.chunks_plaintext.as_slice())
    );

    let unpacked = unpack_archive_bundle(
        &fixture.contents,
        &fixture.key,
        &fixture.binding,
        u32::try_from(CHUNK_PARTS.len()).unwrap(),
        total_bytes(&fixture),
    )
    .unwrap();

    assert_eq!(unpacked.wrap_plaintext().expose(), WRAP_PLAINTEXT);
    assert_eq!(
        unpacked.chunks_plaintext().expose(),
        fixture.chunks_plaintext.as_slice()
    );
    let debug = format!("{unpacked:?}");
    assert!(!debug.contains("wrap-secret-040"));
    assert!(!debug.contains("chunk-secret-040"));
    assert_eq!(debug, "UnpackedArchiveBundle(<redacted-plaintext>)");
}

#[test]
fn wrap_authentication_damage_and_wrong_recovery_key_return_no_plaintext() {
    let fixture = fixture();
    let corrupted = with_parts(
        &fixture,
        corrupt_ciphertext(&fixture.wrap_wire),
        fixture.chunk_wires.clone(),
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &corrupted,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::WrapOpenFailed,
    );

    let wrong_key = SecretBytes::new(vec![0xee; 32]);
    assert_failure_redacts(
        unpack_archive_bundle(
            &fixture.contents,
            &wrong_key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::WrapOpenFailed,
    );
}

#[test]
fn damaged_last_chunk_fails_after_valid_earlier_chunks_without_a_result() {
    let fixture = fixture();
    let mut chunks = fixture.chunk_wires.clone();
    chunks[2] = corrupt_ciphertext(&chunks[2]);
    let contents = with_parts(&fixture, fixture.wrap_wire.clone(), chunks);

    assert_failure_redacts(
        unpack_archive_bundle(
            &contents,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn foreign_bundle_last_chunk_is_rejected_after_an_authentic_prefix() {
    let fixture = fixture();
    let foreign_binding = binding("bundle-foreign", "dataset-040", "a1", 7);
    let spec =
        BackupRecoveryChunkSpec::new(foreign_binding, 2, 3, total_bytes(&fixture), fixture.digest)
            .unwrap();
    let foreign_last = seal_backup_recovery_chunk(&fixture.key, &spec, nonce(0x70), CHUNK_PARTS[2])
        .unwrap()
        .to_column_value();
    let contents = with_parts(
        &fixture,
        fixture.wrap_wire.clone(),
        vec![
            fixture.chunk_wires[0].clone(),
            fixture.chunk_wires[1].clone(),
            foreign_last,
        ],
    );

    assert_failure_redacts(
        unpack_archive_bundle(
            &contents,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn bundle_dataset_key_id_and_key_version_bindings_are_authenticated() {
    let fixture = fixture();
    let alternatives = [
        binding("bundle-foreign", "dataset-040", "a1", 7),
        binding("bundle-040", "dataset-foreign", "a1", 7),
        binding("bundle-040", "dataset-040", "b2", 7),
        binding("bundle-040", "dataset-040", "a1", 8),
    ];

    for other in alternatives {
        assert_failure_redacts(
            unpack_archive_bundle(
                &fixture.contents,
                &fixture.key,
                &other,
                3,
                total_bytes(&fixture),
            ),
            ArchiveBundleFault::WrapOpenFailed,
        );
    }
}

#[test]
fn inventory_digest_is_authenticated_by_every_chunk() {
    let fixture = fixture();
    let foreign_digest = Sha256Digest::of(b"different terminal inventory");
    let mut archive = Vec::new();
    write_archive_bundle(
        foreign_digest,
        &fixture.wrap_wire,
        &fixture.chunk_wires,
        ArchiveBundleBounds::standard(),
        &mut archive,
    )
    .unwrap();
    let contents = read_archive_bundle(
        &mut archive.as_slice(),
        ArchiveBundleBounds::standard(),
        foreign_digest,
    )
    .unwrap();

    assert_failure_redacts(
        unpack_archive_bundle(
            &contents,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn reordered_duplicated_and_missing_chunks_never_assemble() {
    let fixture = fixture();

    let reordered = with_parts(
        &fixture,
        fixture.wrap_wire.clone(),
        vec![
            fixture.chunk_wires[1].clone(),
            fixture.chunk_wires[0].clone(),
            fixture.chunk_wires[2].clone(),
        ],
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &reordered,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );

    let duplicated = with_parts(
        &fixture,
        fixture.wrap_wire.clone(),
        vec![
            fixture.chunk_wires[0].clone(),
            fixture.chunk_wires[0].clone(),
            fixture.chunk_wires[2].clone(),
        ],
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &duplicated,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );

    let missing = with_parts(
        &fixture,
        fixture.wrap_wire.clone(),
        fixture.chunk_wires[..2].to_vec(),
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &missing,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkCountMismatch,
    );
}

#[test]
fn expected_count_and_total_mismatches_are_rejected() {
    let fixture = fixture();
    let count_precedes_parse = with_parts(
        &fixture,
        "not wrap json".to_owned(),
        fixture.chunk_wires[..2].to_vec(),
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &count_precedes_parse,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkCountMismatch,
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &fixture.contents,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture) + 1,
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn authenticated_chunks_with_a_declared_total_one_byte_too_large_fail_at_the_last_chunk() {
    let fixture = fixture();
    let declared_total = total_bytes(&fixture) + 1;
    let chunks = CHUNK_PARTS
        .iter()
        .enumerate()
        .map(|(sequence, plaintext)| {
            let spec = BackupRecoveryChunkSpec::new(
                fixture.binding.clone(),
                u32::try_from(sequence).unwrap(),
                3,
                declared_total,
                fixture.digest,
            )
            .unwrap();
            seal_backup_recovery_chunk(
                &fixture.key,
                &spec,
                nonce(0x80 + u8::try_from(sequence).unwrap()),
                plaintext,
            )
            .unwrap()
            .to_column_value()
        })
        .collect();
    let contents = with_parts(&fixture, fixture.wrap_wire.clone(), chunks);

    assert_failure_redacts(
        unpack_archive_bundle(&contents, &fixture.key, &fixture.binding, 3, declared_total),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn wrap_open_precedes_chunk_parse_and_chunks_are_parsed_then_opened_one_at_a_time() {
    let fixture = fixture();

    let wrap_failure_first = with_parts(
        &fixture,
        corrupt_ciphertext(&fixture.wrap_wire),
        vec!["not chunk json".to_owned(); 3],
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &wrap_failure_first,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::WrapOpenFailed,
    );

    let mut chunks = fixture.chunk_wires.clone();
    chunks[0] = corrupt_ciphertext(&chunks[0]);
    chunks[1] = "not chunk json".to_owned();
    let first_chunk_auth_failure = with_parts(&fixture, fixture.wrap_wire.clone(), chunks);
    assert_failure_redacts(
        unpack_archive_bundle(
            &first_chunk_auth_failure,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkOpenFailed,
    );
}

#[test]
fn stream_hard_limits_precede_wrap_and_chunk_parsing() {
    let fixture = fixture();
    let too_many = ArchiveBundleContents {
        inventory_digest: fixture.digest,
        wrap_envelope: "not wrap json".to_owned(),
        chunk_envelopes: vec!["not chunk json".to_owned(); 33],
    };
    assert_failure_redacts(
        unpack_archive_bundle(
            &too_many,
            &fixture.key,
            &fixture.binding,
            33,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkAssemblyFailed,
    );

    let too_large = ArchiveBundleContents {
        inventory_digest: fixture.digest,
        wrap_envelope: "not wrap json".to_owned(),
        chunk_envelopes: vec!["not chunk json".to_owned()],
    };
    assert_failure_redacts(
        unpack_archive_bundle(
            &too_large,
            &fixture.key,
            &fixture.binding,
            1,
            4 * 1024 * 1024 + 1,
        ),
        ArchiveBundleFault::ChunkAssemblyFailed,
    );

    let zero_total = ArchiveBundleContents {
        inventory_digest: fixture.digest,
        wrap_envelope: "not wrap json".to_owned(),
        chunk_envelopes: vec!["not chunk json".to_owned()],
    };
    assert_failure_redacts(
        unpack_archive_bundle(&zero_total, &fixture.key, &fixture.binding, 1, 0),
        ArchiveBundleFault::ChunkAssemblyFailed,
    );
}

#[test]
fn complete_and_truncated_envelope_json_are_classified_before_authentication() {
    let fixture = fixture();

    let mut bad_wrap: serde_json::Value = serde_json::from_str(&fixture.wrap_wire).unwrap();
    bad_wrap["unexpected"] = serde_json::Value::Bool(true);
    let complete_bad_wrap = with_parts(
        &fixture,
        serde_json::to_string(&bad_wrap).unwrap(),
        fixture.chunk_wires.clone(),
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &complete_bad_wrap,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::WrapParseFailed,
    );

    let truncated_wrap = with_parts(
        &fixture,
        fixture.wrap_wire[..fixture.wrap_wire.len() - 1].to_owned(),
        fixture.chunk_wires.clone(),
    );
    assert_failure_redacts(
        unpack_archive_bundle(
            &truncated_wrap,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::WrapParseFailed,
    );

    let mut bad_chunk: serde_json::Value = serde_json::from_str(&fixture.chunk_wires[0]).unwrap();
    bad_chunk["unexpected"] = serde_json::Value::Bool(true);
    let mut chunks = fixture.chunk_wires.clone();
    chunks[0] = serde_json::to_string(&bad_chunk).unwrap();
    let complete_bad_chunk = with_parts(&fixture, fixture.wrap_wire.clone(), chunks);
    assert_failure_redacts(
        unpack_archive_bundle(
            &complete_bad_chunk,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkParseFailed,
    );

    let mut chunks = fixture.chunk_wires.clone();
    chunks[0].pop();
    let truncated_chunk = with_parts(&fixture, fixture.wrap_wire.clone(), chunks);
    assert_failure_redacts(
        unpack_archive_bundle(
            &truncated_chunk,
            &fixture.key,
            &fixture.binding,
            3,
            total_bytes(&fixture),
        ),
        ArchiveBundleFault::ChunkParseFailed,
    );
}

#[test]
fn complete_structural_and_truncated_archive_json_are_rejected_by_public_read() {
    let fixture = fixture();
    let mut structurally_bad: serde_json::Value =
        serde_json::from_slice(&fixture.archive_bytes).unwrap();
    structurally_bad["unexpected"] = serde_json::Value::Bool(true);
    let complete = serde_json::to_vec(&structurally_bad).unwrap();
    assert_eq!(
        read_archive_bundle(
            &mut complete.as_slice(),
            ArchiveBundleBounds::standard(),
            fixture.digest,
        )
        .unwrap_err(),
        ArchiveBundleFault::ParseFailed
    );

    let mut truncated = fixture.archive_bytes.clone();
    truncated.pop();
    assert_eq!(
        read_archive_bundle(
            &mut truncated.as_slice(),
            ArchiveBundleBounds::standard(),
            fixture.digest,
        )
        .unwrap_err(),
        ArchiveBundleFault::ParseFailed
    );
}
