//! Closed on-disk representation for PostgreSQL version and initdb helper journals.

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperKind {
    VersionPostgres,
    VersionInitdb,
    VersionPgCtl,
    Initdb,
}

impl HelperKind {
    pub(super) const fn next(self) -> Option<Self> {
        match self {
            Self::VersionPostgres => Some(Self::VersionInitdb),
            Self::VersionInitdb => Some(Self::VersionPgCtl),
            Self::VersionPgCtl => Some(Self::Initdb),
            Self::Initdb => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HelperJournalPhase {
    SpawnEntered,
    ChildObserved,
    ExitConfirmed,
    HelpersComplete,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct HelperJournalRecord {
    pub(super) schema: String,
    pub(super) schema_version: u64,
    pub(super) instance_id: String,
    pub(super) data_dir_name: String,
    pub(super) data_dir_device: u64,
    pub(super) data_dir_inode: u64,
    pub(super) attempt_id: String,
    pub(super) start_evidence_sha256: String,
    pub(super) owner_observation: String,
    pub(super) helper_kind: HelperKind,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(super) child_observation: Option<String>,
    pub(super) phase: HelperJournalPhase,
}

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}
