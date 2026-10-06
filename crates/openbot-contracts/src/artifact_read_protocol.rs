//! Closed public read controls. A locator or control reply carries no byte authority.

use serde::{Deserialize, Serialize};

/// Open one memory-only reader for a current-visible artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenArtifactRead {
    /// Artifact selector; the trusted producer resolves all ownership and physical facts.
    pub artifact_id: String,
}

/// Select the next original sequential block, without a path, range or seek.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadArtifactReadBlock {
    /// A Rust-minted memory locator, never a replacement for the original host binding.
    pub handle_id: String,
    /// Starts at zero and advances only after the original accepted acknowledgment.
    pub sequence: u32,
}

/// Acknowledge only a block that actually reached the controlled transport handoff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcknowledgeArtifactReadBlock {
    /// Original reader locator; another current session cannot take ownership of it.
    pub handle_id: String,
    /// The exact handed-off block sequence, or the last already accepted acknowledgment.
    pub sequence: u32,
}

/// Stop one original reader without changing its artifact record or retention.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloseArtifactRead {
    /// The original memory-only reader locator.
    pub handle_id: String,
}

/// Actual prepared record facts. These fields are not a reusable read grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReadOpened {
    /// Rust-minted locator whose original session/window remains separately checked.
    pub handle_id: String,
    /// Canonical UUIDv7 of the actual prepared record.
    pub artifact_id: String,
    /// Whole digest verified on the original retained descriptor.
    pub sha256: String,
    /// Exact logical length of that same original object.
    pub byte_length: u64,
    /// Actual remaining monotonic lifetime, at most 600000 milliseconds.
    pub remaining_millis: u32,
}

/// Control metadata for a matched original pending block; no byte payload is serialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReadChunkDescriptor {
    /// The original reader locator.
    pub handle_id: String,
    /// The one original block selected for delivery.
    pub sequence: u32,
    /// Actual prefix length, bounded by the retained initialized 4 MiB allocation.
    pub byte_length: u32,
    /// True only after a real sequential zero read and actual per-reader closure.
    pub eof: bool,
}

/// An ephemeral read acknowledgment; it is neither a save receipt nor retry permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReadAcknowledged {
    /// The original reader locator.
    pub handle_id: String,
    /// The same accepted original block sequence, including response-loss ACK retries.
    pub sequence: u32,
}

/// Success is produced only after this reader's real worker, FD and allocation end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReadClosed {
    /// The original reader locator; no artifact state change is implied.
    pub handle_id: String,
}

/// A handle locator accepts its one canonical lower-hyphenated UUIDv7 representation.
/// Validation does not establish existence, current authority or operation ownership.
#[must_use]
pub fn is_canonical_artifact_read_handle(value: &str) -> bool {
    crate::artifacts::canonical_artifact_uuid_v7(value).is_some_and(|canonical| canonical == value)
}

#[cfg(test)]
#[path = "artifact_read_protocol_tests.rs"]
mod tests;
