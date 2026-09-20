use std::io::{self, Read, Write};

use wrokbot_domain::audit::hash::Sha256Digest;

use super::{ArchiveBundleBounds, ArchiveBundleFault, read_archive_bundle, write_archive_bundle};

const STANDARD_BYTES: usize = 8 * 1024 * 1024;
const STANDARD_CHUNKS: usize = 32;

fn digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0xab; 32])
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
}

impl Write for RecordingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

struct PrefixThenFailWriter {
    remaining: usize,
    bytes: Vec<u8>,
    writes: usize,
}

impl Write for PrefixThenFailWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.remaining == 0 {
            return Err(io::Error::other("injected writer failure"));
        }
        let accepted = buffer.len().min(self.remaining);
        self.bytes.extend_from_slice(&buffer[..accepted]);
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReadProbe {
    bytes: Vec<u8>,
    offset: usize,
}

impl Read for ReadProbe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let available = self.bytes.len().saturating_sub(self.offset);
        let count = available.min(buffer.len());
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn assert_exact_boundary(wrap: &str, chunks: &[String], expected: &[u8]) {
    let exact_bounds = ArchiveBundleBounds::try_new(expected.len(), chunks.len()).unwrap();
    let mut output = Vec::new();
    let written = write_archive_bundle(digest(), wrap, chunks, exact_bounds, &mut output).unwrap();
    assert_eq!(written, u64::try_from(expected.len()).unwrap());
    assert_eq!(output, expected);

    let tight_bounds = ArchiveBundleBounds::try_new(expected.len() - 1, chunks.len()).unwrap();
    let mut untouched = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(digest(), wrap, chunks, tight_bounds, &mut untouched).unwrap_err(),
        ArchiveBundleFault::TotalBytesExceeded
    );
    assert_eq!(untouched.writes, 0);
    assert_eq!(untouched.flushes, 0);
    assert!(untouched.bytes.is_empty());
}

#[test]
fn bounds_can_only_tighten_the_standard_limits() {
    assert!(ArchiveBundleBounds::try_new(0, 1).is_none());
    assert!(ArchiveBundleBounds::try_new(1, 0).is_none());
    assert!(ArchiveBundleBounds::try_new(0, 0).is_none());

    assert!(ArchiveBundleBounds::try_new(1, 1).is_some());
    assert_eq!(
        ArchiveBundleBounds::try_new(STANDARD_BYTES, STANDARD_CHUNKS),
        Some(ArchiveBundleBounds::standard())
    );

    assert!(ArchiveBundleBounds::try_new(STANDARD_BYTES + 1, STANDARD_CHUNKS).is_none());
    assert!(ArchiveBundleBounds::try_new(STANDARD_BYTES, STANDARD_CHUNKS + 1).is_none());
    assert!(ArchiveBundleBounds::try_new(usize::MAX, STANDARD_CHUNKS).is_none());
    assert!(ArchiveBundleBounds::try_new(STANDARD_BYTES, usize::MAX).is_none());
    assert!(ArchiveBundleBounds::try_new(usize::MAX, usize::MAX).is_none());
}

#[test]
fn exact_json_bytes_and_field_order_succeed_only_at_the_exact_bound() {
    let expected = format!(
        r#"{{"schema":"openbot-backup-archive","schemaVersion":1,"inventoryDigest":"{}","wrapEnvelope":"wrap","chunkEnvelopes":["chunk"]}}"#,
        "ab".repeat(32)
    );
    assert_exact_boundary("wrap", &["chunk".to_owned()], expected.as_bytes());
}

#[test]
fn escaped_and_unicode_values_use_their_exact_encoded_byte_boundary() {
    let wrap = "\"\\\n\t\0雪🦀";
    let chunks = vec!["\u{0008}\r中文".to_owned()];
    let expected = format!(
        r#"{{"schema":"openbot-backup-archive","schemaVersion":1,"inventoryDigest":"{}","wrapEnvelope":"\"\\\n\t\u0000雪🦀","chunkEnvelopes":["\b\r中文"]}}"#,
        "ab".repeat(32)
    );
    assert_exact_boundary(wrap, &chunks, expected.as_bytes());
}

#[test]
fn large_wrap_and_multiple_large_chunks_are_rejected_before_output() {
    let mut wrap_writer = RecordingWriter::default();
    let large_wrap = "w".repeat(STANDARD_BYTES + 1);
    assert_eq!(
        write_archive_bundle(
            digest(),
            &large_wrap,
            &["chunk".to_owned()],
            ArchiveBundleBounds::standard(),
            &mut wrap_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::TotalBytesExceeded
    );
    assert_eq!((wrap_writer.writes, wrap_writer.flushes), (0, 0));
    assert!(wrap_writer.bytes.is_empty());

    let large_chunk = "c".repeat(STANDARD_BYTES / 2 + 1);
    let chunks = vec![large_chunk.clone(), large_chunk];
    let mut chunks_writer = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(
            digest(),
            "wrap",
            &chunks,
            ArchiveBundleBounds::standard(),
            &mut chunks_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::TotalBytesExceeded
    );
    assert_eq!((chunks_writer.writes, chunks_writer.flushes), (0, 0));
    assert!(chunks_writer.bytes.is_empty());
}

#[test]
fn empty_and_chunk_count_errors_keep_their_priority_without_output() {
    let thirty_three = vec!["x".to_owned(); STANDARD_CHUNKS + 1];

    let mut empty_wrap_writer = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(
            digest(),
            "",
            &thirty_three,
            ArchiveBundleBounds::standard(),
            &mut empty_wrap_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::WrapMissing
    );
    assert_eq!(
        (empty_wrap_writer.writes, empty_wrap_writer.flushes),
        (0, 0)
    );

    let mut empty_chunks_writer = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(
            digest(),
            "wrap",
            &[],
            ArchiveBundleBounds::standard(),
            &mut empty_chunks_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::ChunksEmpty
    );
    assert_eq!(
        (empty_chunks_writer.writes, empty_chunks_writer.flushes),
        (0, 0)
    );

    let mut too_many_writer = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(
            digest(),
            "wrap",
            &thirty_three,
            ArchiveBundleBounds::standard(),
            &mut too_many_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::ChunkCountExceeded
    );
    assert_eq!((too_many_writer.writes, too_many_writer.flushes), (0, 0));

    let mut tightened_writer = RecordingWriter::default();
    assert_eq!(
        write_archive_bundle(
            digest(),
            "wrap",
            &["first".to_owned(), "second".to_owned()],
            ArchiveBundleBounds::try_new(STANDARD_BYTES, 1).unwrap(),
            &mut tightened_writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::ChunkCountExceeded
    );
    assert_eq!((tightened_writer.writes, tightened_writer.flushes), (0, 0));
}

#[test]
fn output_io_failure_remains_write_failed_after_a_real_prefix() {
    let expected = format!(
        r#"{{"schema":"openbot-backup-archive","schemaVersion":1,"inventoryDigest":"{}","wrapEnvelope":"wrap","chunkEnvelopes":["chunk"]}}"#,
        "ab".repeat(32)
    );
    let mut writer = PrefixThenFailWriter {
        remaining: 17,
        bytes: Vec::new(),
        writes: 0,
    };

    assert_eq!(
        write_archive_bundle(
            digest(),
            "wrap",
            &["chunk".to_owned()],
            ArchiveBundleBounds::standard(),
            &mut writer,
        )
        .unwrap_err(),
        ArchiveBundleFault::WriteFailed
    );
    assert!(writer.writes >= 2);
    assert!(!writer.bytes.is_empty());
    assert!(writer.bytes.len() < expected.len());
    assert!(expected.as_bytes().starts_with(&writer.bytes));
}

#[test]
fn read_stops_after_max_plus_one_bytes_and_preserves_the_budget_error() {
    let bounds = ArchiveBundleBounds::try_new(10, 1).unwrap();
    let mut reader = ReadProbe {
        bytes: vec![b'x'; 100],
        offset: 0,
    };

    assert_eq!(
        read_archive_bundle(&mut reader, bounds, digest()).unwrap_err(),
        ArchiveBundleFault::TotalBytesExceeded
    );
    assert_eq!(reader.offset, 11);
}
