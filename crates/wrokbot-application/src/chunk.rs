//! Provider token delta → durable semantic chunk 的纯 accumulator（v3 §4.3 条 7）。

use core::time::Duration;
use std::time::Instant;

/// 一个 pending chunk 最长等待时间。
pub const SEMANTIC_CHUNK_MAX_DELAY: Duration = Duration::from_millis(50);
/// 一个 durable semantic chunk 的 UTF-8 字节上限。
pub const SEMANTIC_CHUNK_MAX_BYTES: usize = 8 * 1024;

/// 按 50ms 或 8KiB 上限合并文本 delta；不做 Unicode normalization。
#[derive(Debug, Default)]
pub struct SemanticChunkAccumulator {
    pending: String,
    started_at: Option<Instant>,
}

impl SemanticChunkAccumulator {
    /// 空 accumulator。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: String::new(),
            started_at: None,
        }
    }

    /// 推入一段完整 UTF-8 delta，返回本次达到时间/大小上限而应持久化的 chunks。
    ///
    /// 调用方仍须在 [`Self::next_deadline`] 到达时调用 [`Self::flush_due`]；没有后台任务的
    /// 纯结构不能自行醒来。
    pub fn push(&mut self, delta: &str, now: Instant) -> Vec<String> {
        let mut ready = Vec::new();
        if let Some(chunk) = self.flush_due(now) {
            ready.push(chunk);
        }
        let mut remaining = delta;
        while !remaining.is_empty() {
            if self.pending.is_empty() {
                self.started_at = Some(now);
            }
            let capacity = SEMANTIC_CHUNK_MAX_BYTES - self.pending.len();
            let first_scalar = remaining.chars().next().map_or(0, char::len_utf8);
            if capacity < first_scalar {
                ready.push(self.take_pending());
                continue;
            }
            let take = prefix_boundary(remaining, capacity);
            self.pending.push_str(&remaining[..take]);
            remaining = &remaining[take..];
            if self.pending.len() == SEMANTIC_CHUNK_MAX_BYTES {
                ready.push(self.take_pending());
            }
        }
        ready
    }

    /// 到 50ms 边界时取出 pending；未到或为空返回 `None`。
    pub fn flush_due(&mut self, now: Instant) -> Option<String> {
        let due = self.started_at.is_some_and(|started| {
            now.saturating_duration_since(started) >= SEMANTIC_CHUNK_MAX_DELAY
        });
        due.then(|| self.take_pending())
    }

    /// provider/run 收口时取出最后一个不满上限的 chunk。
    pub fn finish(&mut self) -> Option<String> {
        (!self.pending.is_empty()).then(|| self.take_pending())
    }

    /// 当前 pending 字节数。
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    /// pending 的最迟 flush 时刻；空时为 `None`。
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.started_at
            .and_then(|started| started.checked_add(SEMANTIC_CHUNK_MAX_DELAY))
    }

    fn take_pending(&mut self) -> String {
        self.started_at = None;
        core::mem::take(&mut self.pending)
    }
}

fn prefix_boundary(value: &str, max_bytes: usize) -> usize {
    if value.len() <= max_bytes {
        return value.len();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifty_milliseconds_is_the_closed_flush_boundary() {
        let start = Instant::now();
        let mut accumulator = SemanticChunkAccumulator::new();
        assert!(accumulator.push("hello", start).is_empty());
        assert_eq!(
            accumulator.flush_due(start + Duration::from_millis(49)),
            None
        );
        assert_eq!(
            accumulator.flush_due(start + Duration::from_millis(50)),
            Some("hello".to_owned())
        );
    }

    #[test]
    fn eight_kib_is_a_byte_limit_and_the_remainder_stays_pending() {
        let input = "a".repeat(SEMANTIC_CHUNK_MAX_BYTES + 1);
        let mut accumulator = SemanticChunkAccumulator::new();
        let ready = accumulator.push(&input, Instant::now());
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), SEMANTIC_CHUNK_MAX_BYTES);
        assert_eq!(accumulator.pending_bytes(), 1);
        assert_eq!(ready[0].clone() + &accumulator.finish().unwrap(), input);
    }

    #[test]
    fn utf8_is_never_split_inside_a_scalar_and_bytes_round_trip() {
        let input = "🦀".repeat(SEMANTIC_CHUNK_MAX_BYTES / 4 + 3);
        let mut accumulator = SemanticChunkAccumulator::new();
        let mut chunks = accumulator.push(&input, Instant::now());
        chunks.extend(accumulator.finish());
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.len() <= SEMANTIC_CHUNK_MAX_BYTES)
        );
        assert_eq!(chunks.concat(), input);

        let mut mixed = SemanticChunkAccumulator::new();
        let mut chunks = mixed.push(
            &("a".repeat(SEMANTIC_CHUNK_MAX_BYTES - 1) + "🦀"),
            Instant::now(),
        );
        chunks.extend(mixed.finish());
        assert_eq!(chunks[0].len(), SEMANTIC_CHUNK_MAX_BYTES - 1);
        assert_eq!(chunks[1], "🦀");
    }

    #[test]
    fn an_overdue_pending_chunk_flushes_before_the_next_delta() {
        let start = Instant::now();
        let mut accumulator = SemanticChunkAccumulator::new();
        assert!(accumulator.push("first", start).is_empty());
        assert_eq!(
            accumulator.push("second", start + SEMANTIC_CHUNK_MAX_DELAY),
            vec!["first".to_owned()]
        );
        assert_eq!(accumulator.finish(), Some("second".to_owned()));
    }

    #[test]
    fn empty_input_and_empty_finish_never_create_phantom_events() {
        let mut accumulator = SemanticChunkAccumulator::new();
        assert!(accumulator.push("", Instant::now()).is_empty());
        assert_eq!(accumulator.finish(), None);
        assert_eq!(accumulator.next_deadline(), None);
    }
}
