//! Closed on-disk representation for the PostgreSQL server startup journal.

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StartupJournalPhase {
    SpawnEntered,
    ChildObserved,
    Ready,
    StopEntered,
    ExitConfirmed,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct StartupJournalRecord {
    pub(super) schema: String,
    pub(super) schema_version: u64,
    pub(super) instance_id: String,
    pub(super) data_dir_name: String,
    pub(super) data_dir_device: u64,
    pub(super) data_dir_inode: u64,
    pub(super) attempt_id: String,
    pub(super) start_evidence_sha256: String,
    pub(super) owner_observation: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(super) child_observation: Option<String>,
    pub(super) phase: StartupJournalPhase,
}

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}
