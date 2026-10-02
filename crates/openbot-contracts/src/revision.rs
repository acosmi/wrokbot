//! Closed configuration revision conflict snapshot shared by authenticated transports.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// Current committed metadata of a configuration object. It grants no write authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireSnapshot", into = "WireSnapshot")]
pub struct RevisionSnapshot {
    revision: i64,
    digest: [u8; 32],
    updated_at: OffsetDateTime,
}

impl RevisionSnapshot {
    /// Hash only the object's public, committed representation, never credential bytes.
    pub fn from_public<T: Serialize>(
        revision: i64,
        updated_at: OffsetDateTime,
        value: &T,
    ) -> Result<Self, serde_json::Error> {
        use serde::ser::Error as _;
        if revision <= 0 {
            return Err(serde_json::Error::custom("invalid_revision_snapshot"));
        }
        updated_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| serde_json::Error::custom("invalid_revision_snapshot"))?;
        let mut public = serde_json::to_value(value)?;
        public.sort_all_objects();
        let canonical = serde_json::to_vec(&public)?;
        Ok(Self {
            revision,
            digest: Sha256::digest(canonical).into(),
            updated_at,
        })
    }

    /// Monotonic revision of the current committed object.
    #[must_use]
    pub const fn current_revision(self) -> i64 {
        self.revision
    }

    /// Database-clock time of that committed revision.
    #[must_use]
    pub const fn updated_at(self) -> OffsetDateTime {
        self.updated_at
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSnapshot {
    current_revision: i64,
    current_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl From<RevisionSnapshot> for WireSnapshot {
    fn from(snapshot: RevisionSnapshot) -> Self {
        use core::fmt::Write;
        let mut digest = String::with_capacity(64);
        for byte in snapshot.digest {
            write!(&mut digest, "{byte:02x}").expect("string write");
        }
        Self {
            current_revision: snapshot.revision,
            current_sha256: digest,
            updated_at: snapshot.updated_at,
        }
    }
}

impl TryFrom<WireSnapshot> for RevisionSnapshot {
    type Error = &'static str;
    fn try_from(wire: WireSnapshot) -> Result<Self, Self::Error> {
        if wire.current_revision <= 0 || wire.current_sha256.len() != 64 {
            return Err("invalid_revision_snapshot");
        }
        let mut digest = [0; 32];
        for (index, bytes) in wire
            .current_sha256
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
        {
            let digit = |b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            digest[index] = digit(bytes[0]).ok_or("invalid_revision_snapshot")? * 16
                + digit(bytes[1]).ok_or("invalid_revision_snapshot")?;
        }
        Ok(Self {
            revision: wire.current_revision,
            digest,
            updated_at: wire.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_is_independent_of_nested_object_insertion_order() {
        let left: serde_json::Value =
            serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":[{"y":2,"x":1}]}"#).unwrap();
        let right: serde_json::Value =
            serde_json::from_str(r#"{"a":[{"x":1,"y":2}],"z":{"a":1,"b":2}}"#).unwrap();
        let at = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            RevisionSnapshot::from_public(1, at, &left).unwrap(),
            RevisionSnapshot::from_public(1, at, &right).unwrap()
        );
    }

    #[test]
    fn closed_snapshot_has_only_current_revision_digest_and_rfc3339_time() {
        let time = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let value = serde_json::json!({"name":"public configuration", "revision":2});
        assert!(RevisionSnapshot::from_public(0, time, &value).is_err());
        assert!(RevisionSnapshot::from_public(-1, time, &value).is_err());
        let snapshot = RevisionSnapshot::from_public(2, time, &value).unwrap();
        let wire = serde_json::to_value(snapshot).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 3);
        assert_eq!(wire["currentRevision"], 2);
        assert_eq!(wire["updatedAt"], "2023-11-14T22:13:20Z");
        assert_eq!(wire["currentSha256"].as_str().unwrap().len(), 64);
        assert_eq!(
            serde_json::from_value::<RevisionSnapshot>(wire.clone()).unwrap(),
            snapshot
        );
        for mutation in [
            serde_json::json!({"currentRevision":0}),
            serde_json::json!({"currentSha256":"A".repeat(64)}),
            serde_json::json!({"extra":"secret"}),
        ] {
            let mut bad = wire.clone();
            for (key, value) in mutation.as_object().unwrap() {
                bad[key] = value.clone();
            }
            assert!(serde_json::from_value::<RevisionSnapshot>(bad).is_err());
        }
    }
}
