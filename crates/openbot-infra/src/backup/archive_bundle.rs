//! 有界 archive bundle 写出与读入（§14.4 / R344 / V6-PR-039）。
//!
//! Archive bundle 是 037 recovery-wrap + 038 recovery-chunks 的序列化容器。
//! 本模块只做有界 JSON 序列化/反序列化，不打开 AEAD（调用方用 037/038 API 打开），
//! 不做 PG/WAL 恢复、原子切换、staging coordinator 集成、RestoreAuthorized、A6 或 0031。

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use openbot_domain::audit::hash::Sha256Digest;

/// Archive bundle 有界配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveBundleBounds {
    max_total_bytes: usize,
    max_chunks: usize,
}

impl ArchiveBundleBounds {
    /// 产品默认：总 8MiB、最多 32 块。
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_total_bytes: 8 * 1024 * 1024,
            max_chunks: 32,
        }
    }

    /// 更紧的测试边界。
    #[must_use]
    pub fn try_new(max_total_bytes: usize, max_chunks: usize) -> Option<Self> {
        if max_total_bytes == 0 || max_chunks == 0 {
            return None;
        }
        Some(Self {
            max_total_bytes,
            max_chunks,
        })
    }
}

/// Archive bundle 失败分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveBundleFault {
    /// Schema 不匹配。
    SchemaInvalid,
    /// 总字节超限。
    TotalBytesExceeded,
    /// 块数超限。
    ChunkCountExceeded,
    /// Inventory digest 不符。
    InventoryDigestMismatch,
    /// JSON 解析失败。
    ParseFailed,
    /// I/O 写入失败。
    WriteFailed,
    /// I/O 读取失败。
    ReadFailed,
    /// Wrap envelope 缺失。
    WrapMissing,
    /// Chunk envelopes 为空。
    ChunksEmpty,
}

const ARCHIVE_SCHEMA: &str = "openbot-backup-archive";
const ARCHIVE_SCHEMA_VERSION: u64 = 1;

/// Strict canonical JSON wire format.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireArchiveBundle {
    schema: String,
    schema_version: u64,
    inventory_digest: String,
    wrap_envelope: String,
    chunk_envelopes: Vec<String>,
}

/// 读入结果：持有 digest + wrap column value + chunk column values。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveBundleContents {
    inventory_digest: Sha256Digest,
    wrap_envelope: String,
    chunk_envelopes: Vec<String>,
}

impl ArchiveBundleContents {
    /// Inventory digest。
    #[must_use]
    pub fn inventory_digest(&self) -> Sha256Digest {
        self.inventory_digest
    }

    /// Recovery wrap envelope column value (JSON string)。
    #[must_use]
    pub fn wrap_envelope(&self) -> &str {
        &self.wrap_envelope
    }

    /// Chunk envelope column values (JSON strings)。
    #[must_use]
    pub fn chunk_envelopes(&self) -> &[String] {
        &self.chunk_envelopes
    }
}

/// 将 inventory digest、recovery wrap envelope 和 chunk envelopes 写入 archive bundle。
///
/// 写入固定 schema `openbot-backup-archive` / version 1 的 JSON。
/// 总输出字节受 bounds 限制。
pub fn write_archive_bundle(
    inventory_digest: Sha256Digest,
    wrap_envelope: &str,
    chunk_envelopes: &[String],
    bounds: ArchiveBundleBounds,
    output: &mut dyn Write,
) -> Result<u64, ArchiveBundleFault> {
    if wrap_envelope.is_empty() {
        return Err(ArchiveBundleFault::WrapMissing);
    }
    if chunk_envelopes.is_empty() {
        return Err(ArchiveBundleFault::ChunksEmpty);
    }
    if chunk_envelopes.len() > bounds.max_chunks {
        return Err(ArchiveBundleFault::ChunkCountExceeded);
    }
    let wire = WireArchiveBundle {
        schema: ARCHIVE_SCHEMA.to_owned(),
        schema_version: ARCHIVE_SCHEMA_VERSION,
        inventory_digest: hex_encode(inventory_digest.as_bytes()),
        wrap_envelope: wrap_envelope.to_owned(),
        chunk_envelopes: chunk_envelopes.to_vec(),
    };
    let serialized =
        serde_json::to_vec(&wire).map_err(|_| ArchiveBundleFault::WriteFailed)?;
    if serialized.len() > bounds.max_total_bytes {
        return Err(ArchiveBundleFault::TotalBytesExceeded);
    }
    output
        .write_all(&serialized)
        .map_err(|_| ArchiveBundleFault::WriteFailed)?;
    Ok(u64::try_from(serialized.len()).unwrap_or(u64::MAX))
}

/// 从 archive bundle 读入并校验 schema/version/inventory digest。
///
/// 返回 [`ArchiveBundleContents`] 持有 wrap 和 chunk envelope column values。
/// 调用方用 037/038 API 逐条打开 AEAD。
pub fn read_archive_bundle(
    input: &mut dyn Read,
    bounds: ArchiveBundleBounds,
    expected_digest: Sha256Digest,
) -> Result<ArchiveBundleContents, ArchiveBundleFault> {
    let mut buffer = Vec::new();
    let read_limit = u64::try_from(bounds.max_total_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let bytes_read = input
        .take(read_limit)
        .read_to_end(&mut buffer)
        .map_err(|_| ArchiveBundleFault::ReadFailed)?;
    if bytes_read > bounds.max_total_bytes {
        return Err(ArchiveBundleFault::TotalBytesExceeded);
    }
    let wire: WireArchiveBundle =
        serde_json::from_slice(&buffer).map_err(|_| ArchiveBundleFault::ParseFailed)?;
    if wire.schema != ARCHIVE_SCHEMA || wire.schema_version != ARCHIVE_SCHEMA_VERSION {
        return Err(ArchiveBundleFault::SchemaInvalid);
    }
    if wire.wrap_envelope.is_empty() {
        return Err(ArchiveBundleFault::WrapMissing);
    }
    if wire.chunk_envelopes.is_empty() {
        return Err(ArchiveBundleFault::ChunksEmpty);
    }
    if wire.chunk_envelopes.len() > bounds.max_chunks {
        return Err(ArchiveBundleFault::ChunkCountExceeded);
    }
    let digest_bytes = hex_decode(&wire.inventory_digest)
        .map_err(|_| ArchiveBundleFault::ParseFailed)?;
    if digest_bytes.len() != 32 {
        return Err(ArchiveBundleFault::ParseFailed);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest_bytes);
    let parsed_digest = Sha256Digest::from_bytes(arr);
    if parsed_digest != expected_digest {
        return Err(ArchiveBundleFault::InventoryDigestMismatch);
    }
    Ok(ArchiveBundleContents {
        inventory_digest: parsed_digest,
        wrap_envelope: wire.wrap_envelope,
        chunk_envelopes: wire.chunk_envelopes,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i]).map_err(|_| ())?;
        let lo = nibble(bytes[i + 1]).map_err(|_| ())?;
        decoded.push((hi << 4) | lo);
        i += 2;
    }
    Ok(decoded)
}

fn nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_digest() -> Sha256Digest {
        Sha256Digest::of(b"test-inventory-data")
    }

    fn sample_wrap() -> String {
        r#"{"schema":"openbot-backup-recovery-wrap","schemaVersion":1,"nonce":"aabbccddeeff00112233aabb","ciphertext":"deadbeef0102030405060708091011121314151617181920"}"#.to_owned()
    }

    fn sample_chunks() -> Vec<String> {
        vec![
            r#"{"schema":"openbot-backup-recovery-chunk","schemaVersion":1,"sequence":0,"nonce":"112233445566778899aabbcc","ciphertext":"cafe0102030405060708091011121314151617181920"}"#.to_owned(),
            r#"{"schema":"openbot-backup-recovery-chunk","schemaVersion":1,"sequence":1,"nonce":"aabbccddeeff112233445566","ciphertext":"babe0102030405060708091011121314151617181920"}"#.to_owned(),
        ]
    }

    #[test]
    fn round_trip() {
        let digest = sample_digest();
        let wrap = sample_wrap();
        let chunks = sample_chunks();
        let bounds = ArchiveBundleBounds::standard();

        let mut buffer = Vec::new();
        let written =
            write_archive_bundle(digest, &wrap, &chunks, bounds, &mut buffer).unwrap();
        assert_eq!(written, buffer.len() as u64);
        assert!(written > 0);

        let contents =
            read_archive_bundle(&mut buffer.as_slice(), bounds, digest).unwrap();
        assert_eq!(contents.inventory_digest(), digest);
        assert_eq!(contents.wrap_envelope(), wrap);
        assert_eq!(contents.chunk_envelopes(), chunks.as_slice());
    }

    #[test]
    fn wrong_digest_rejected() {
        let digest = sample_digest();
        let wrong_digest = Sha256Digest::of(b"wrong-data");
        let bounds = ArchiveBundleBounds::standard();

        let mut buffer = Vec::new();
        write_archive_bundle(digest, &sample_wrap(), &sample_chunks(), bounds, &mut buffer)
            .unwrap();

        let result = read_archive_bundle(&mut buffer.as_slice(), bounds, wrong_digest);
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::InventoryDigestMismatch);
    }

    #[test]
    fn total_bytes_exceeded_on_write() {
        let bounds = ArchiveBundleBounds::try_new(10, 32).unwrap();
        let mut buffer = Vec::new();
        let result = write_archive_bundle(
            sample_digest(),
            &sample_wrap(),
            &sample_chunks(),
            bounds,
            &mut buffer,
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::TotalBytesExceeded);
    }

    #[test]
    fn total_bytes_exceeded_on_read() {
        let digest = sample_digest();
        let bounds_big = ArchiveBundleBounds::standard();
        let bounds_small = ArchiveBundleBounds::try_new(10, 32).unwrap();

        let mut buffer = Vec::new();
        write_archive_bundle(digest, &sample_wrap(), &sample_chunks(), bounds_big, &mut buffer)
            .unwrap();

        let result = read_archive_bundle(&mut buffer.as_slice(), bounds_small, digest);
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::TotalBytesExceeded);
    }

    #[test]
    fn chunk_count_exceeded() {
        let bounds = ArchiveBundleBounds::try_new(8 * 1024 * 1024, 1).unwrap();
        let mut buffer = Vec::new();
        let result = write_archive_bundle(
            sample_digest(),
            &sample_wrap(),
            &sample_chunks(),
            bounds,
            &mut buffer,
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::ChunkCountExceeded);
    }

    #[test]
    fn schema_mismatch_rejected() {
        let bad_json = r#"{"schema":"wrong-schema","schemaVersion":1,"inventoryDigest":"aa","wrapEnvelope":"w","chunkEnvelopes":["c"]}"#;
        let bounds = ArchiveBundleBounds::standard();
        let result = read_archive_bundle(
            &mut bad_json.as_bytes(),
            bounds,
            sample_digest(),
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::SchemaInvalid);
    }

    #[test]
    fn truncated_json_rejected() {
        let truncated = r#"{"schema":"openbot-backup-archive","schemaVer"#;
        let bounds = ArchiveBundleBounds::standard();
        let result = read_archive_bundle(
            &mut truncated.as_bytes(),
            bounds,
            sample_digest(),
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::ParseFailed);
    }

    #[test]
    fn empty_wrap_rejected() {
        let mut buffer = Vec::new();
        let result = write_archive_bundle(
            sample_digest(),
            "",
            &sample_chunks(),
            ArchiveBundleBounds::standard(),
            &mut buffer,
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::WrapMissing);
    }

    #[test]
    fn empty_chunks_rejected() {
        let mut buffer = Vec::new();
        let result = write_archive_bundle(
            sample_digest(),
            &sample_wrap(),
            &[],
            ArchiveBundleBounds::standard(),
            &mut buffer,
        );
        assert_eq!(result.unwrap_err(), ArchiveBundleFault::ChunksEmpty);
    }
}
