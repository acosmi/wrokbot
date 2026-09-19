//! Message-owner-scoped Markdown memoization. No transcript data is kept in a process-global cache.

use super::parser::{
    MAX_MARKDOWN_BYTES, MAX_MARKDOWN_EVENTS, MarkdownBlock, MarkdownLimit, ParsedMarkdown,
    limited_document, parse_document,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Maximum retained source/structural bytes across this cache owner; not a process RSS claim.
pub const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum distinct message identities retained by one owner.
pub const MAX_CACHE_MESSAGES: usize = 32;

/// One structurally keyed block. Unchanged blocks keep their Arc and their mounted view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoBlock {
    /// Parsed block shared with the current view.
    pub block: Arc<MarkdownBlock>,
    /// Whether this update reused an existing block.
    pub reused: bool,
    index: usize,
    fingerprint: [u8; 32],
    structural_bytes: usize,
}

impl MemoBlock {
    /// DOM identity is local to one message component, never an authorization or public identifier.
    pub fn view_key(&self) -> (usize, [u8; 32]) {
        (self.index, self.fingerprint)
    }

    fn new(index: usize, block: Arc<MarkdownBlock>) -> Self {
        // This formatting is in-memory only; untrusted transcript content is never logged.
        let structural = format!("{block:?}");
        Self {
            block,
            reused: false,
            index,
            fingerprint: Sha256::digest(structural.as_bytes()).into(),
            structural_bytes: structural.len(),
        }
    }
}

struct CachedMessage {
    source: String,
    blocks: Vec<MemoBlock>,
    starts: Vec<usize>,
    event_starts: Vec<usize>,
    event_count: usize,
    needs_full_context: bool,
    touched: u64,
    cost: usize,
}

/// A cache held by its rendering owner and released on message/channel teardown.
#[derive(Default)]
pub struct StreamingMemoStore {
    messages: HashMap<String, CachedMessage>,
    retained_bytes: usize,
    clock: u64,
    last_parsed_bytes: usize,
}

impl StreamingMemoStore {
    /// Construct an empty independent cache owner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evict exactly this owner's message.
    pub fn clear_message(&mut self, message_id: &str) {
        if let Some(message) = self.messages.remove(message_id) {
            self.retained_bytes -= message.cost;
        }
    }

    /// Release all transcript content held by this owner.
    pub fn clear_all(&mut self) {
        self.messages.clear();
        self.retained_bytes = 0;
    }

    /// Bytes actually passed to the parser by the most recent update, for deterministic budget tests.
    pub fn last_parsed_bytes(&self) -> usize {
        self.last_parsed_bytes
    }

    /// Retained source plus structural representation bytes charged to this cache's budget.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Number of cached message identities.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Parse only the open tail on an ordinary append. Reference-sensitive and raw-HTML documents
    /// are reparsed with their full context; structurally unchanged views are still reused.
    pub fn process_stream(&mut self, message_id: &str, text: &str) -> Vec<MemoBlock> {
        let Some(clock) = self.clock.checked_add(1) else {
            self.clear_all();
            self.clock = 0;
            return self.process_stream(message_id, text);
        };
        self.clock = clock;
        let previous = self.messages.remove(message_id);
        if let Some(previous) = previous.as_ref() {
            self.retained_bytes -= previous.cost;
        }
        let mut document = None;
        self.last_parsed_bytes = text.len();
        if let Some(previous) = previous.as_ref() {
            if text == previous.source {
                self.last_parsed_bytes = 0;
                document = Some(ParsedMarkdown {
                    blocks: previous
                        .blocks
                        .iter()
                        .map(|entry| Arc::clone(&entry.block))
                        .collect(),
                    starts: previous.starts.clone(),
                    event_starts: previous.event_starts.clone(),
                    event_count: previous.event_count,
                    needs_full_context: previous.needs_full_context,
                });
            } else if text.len() <= MAX_MARKDOWN_BYTES
                && text.starts_with(&previous.source)
                && !previous.needs_full_context
                && !text[previous.source.len()..].contains('[')
                && previous.blocks.len() >= 3
            {
                // Keeping two final blocks open also covers setext headings, lists and tables that
                // can absorb the immediately preceding block while a line is still arriving.
                let prefix_count = previous.blocks.len() - 2;
                let start = previous.starts[prefix_count];
                let prefix_events = previous.event_starts[prefix_count];
                let tail = parse_document(&text[start..]);
                if !tail.needs_full_context
                    && prefix_events + tail.event_count <= MAX_MARKDOWN_EVENTS
                {
                    let mut blocks = previous.blocks[..prefix_count]
                        .iter()
                        .map(|entry| Arc::clone(&entry.block))
                        .collect::<Vec<_>>();
                    blocks.extend(tail.blocks);
                    let mut starts = previous.starts[..prefix_count].to_vec();
                    starts.extend(tail.starts.into_iter().map(|offset| offset + start));
                    let mut event_starts = previous.event_starts[..prefix_count].to_vec();
                    event_starts.extend(
                        tail.event_starts
                            .into_iter()
                            .map(|count| count + prefix_events),
                    );
                    document = Some(ParsedMarkdown {
                        blocks,
                        starts,
                        event_starts,
                        event_count: prefix_events + tail.event_count,
                        needs_full_context: false,
                    });
                    self.last_parsed_bytes = text.len() - start;
                } else if prefix_events + tail.event_count > MAX_MARKDOWN_EVENTS {
                    document = Some(limited_document(text, MarkdownLimit::Events));
                }
            }
        }
        let document = document.unwrap_or_else(|| parse_document(text));
        let blocks = document
            .blocks
            .into_iter()
            .enumerate()
            .map(|(index, block)| {
                if let Some(old) = previous.as_ref().and_then(|old| old.blocks.get(index))
                    && old.block == block
                {
                    let mut reused = old.clone();
                    reused.reused = true;
                    reused
                } else {
                    MemoBlock::new(index, block)
                }
            })
            .collect::<Vec<_>>();
        let cost = text.len().saturating_add(message_id.len()).saturating_add(
            blocks
                .iter()
                .map(|entry| entry.structural_bytes)
                .sum::<usize>(),
        );
        // Large source bodies are displayed as bounded previews and never retained in this cache.
        if text.len() <= MAX_MARKDOWN_BYTES && message_id.len() <= 4096 && cost <= MAX_CACHE_BYTES {
            while self.messages.len() >= MAX_CACHE_MESSAGES
                || self.retained_bytes + cost > MAX_CACHE_BYTES
            {
                let Some(oldest) = self
                    .messages
                    .iter()
                    .min_by_key(|(_, entry)| entry.touched)
                    .map(|(id, _)| id.clone())
                else {
                    break;
                };
                self.clear_message(&oldest);
            }
            self.retained_bytes += cost;
            self.messages.insert(
                message_id.to_owned(),
                CachedMessage {
                    source: text.to_owned(),
                    blocks: blocks.clone(),
                    starts: document.starts,
                    event_starts: document.event_starts,
                    event_count: document.event_count,
                    needs_full_context: document.needs_full_context,
                    touched: clock,
                    cost,
                },
            );
        }
        blocks
    }
}
