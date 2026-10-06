use super::*;
use crate::command::{AppCommand, AppReply};
use serde_json::json;

const ARTIFACT: &str = "0199d763-f300-7000-8000-000000000001";
const HANDLE: &str = "0199d763-f300-7000-8000-000000000002";

#[test]
fn public_artifact_read_control_wire_is_closed_and_contains_no_byte_authority() {
    let commands = [
        (
            AppCommand::OpenArtifactRead(OpenArtifactRead {
                artifact_id: ARTIFACT.into(),
            }),
            json!({"kind":"open_artifact_read","artifactId":ARTIFACT}),
        ),
        (
            AppCommand::ReadArtifactReadBlock(ReadArtifactReadBlock {
                handle_id: HANDLE.into(),
                sequence: 0,
            }),
            json!({"kind":"read_artifact_read_block","handleId":HANDLE,"sequence":0}),
        ),
        (
            AppCommand::AcknowledgeArtifactReadBlock(AcknowledgeArtifactReadBlock {
                handle_id: HANDLE.into(),
                sequence: 1,
            }),
            json!({"kind":"acknowledge_artifact_read_block","handleId":HANDLE,"sequence":1}),
        ),
        (
            AppCommand::CloseArtifactRead(CloseArtifactRead {
                handle_id: HANDLE.into(),
            }),
            json!({"kind":"close_artifact_read","handleId":HANDLE}),
        ),
    ];
    for (command, golden) in commands {
        assert_eq!(serde_json::to_value(&command).unwrap(), golden);
        assert_eq!(
            serde_json::from_value::<AppCommand>(golden.clone()).unwrap(),
            command
        );
        for key in [
            "path",
            "actorId",
            "sessionId",
            "windowId",
            "datasetId",
            "expectedSha256",
            "range",
        ] {
            let mut extra = golden.clone();
            extra[key] = json!("untrusted authority");
            assert!(
                serde_json::from_value::<AppCommand>(extra).is_err(),
                "{key}"
            );
        }
    }
    let replies = [
        (
            AppReply::ArtifactReadOpened(ArtifactReadOpened {
                handle_id: HANDLE.into(),
                artifact_id: ARTIFACT.into(),
                sha256: "a".repeat(64),
                byte_length: 5,
                remaining_millis: 599_999,
            }),
            json!({"kind":"artifact_read_opened","handleId":HANDLE,"artifactId":ARTIFACT,
                "sha256":"a".repeat(64),"byteLength":5,"remainingMillis":599999}),
        ),
        (
            AppReply::ArtifactReadChunkDescriptor(ArtifactReadChunkDescriptor {
                handle_id: HANDLE.into(),
                sequence: 0,
                byte_length: 5,
                eof: false,
            }),
            json!({"kind":"artifact_read_chunk_descriptor","handleId":HANDLE,
                "sequence":0,"byteLength":5,"eof":false}),
        ),
        (
            AppReply::ArtifactReadAcknowledged(ArtifactReadAcknowledged {
                handle_id: HANDLE.into(),
                sequence: 0,
            }),
            json!({"kind":"artifact_read_acknowledged","handleId":HANDLE,"sequence":0}),
        ),
        (
            AppReply::ArtifactReadClosed(ArtifactReadClosed {
                handle_id: HANDLE.into(),
            }),
            json!({"kind":"artifact_read_closed","handleId":HANDLE}),
        ),
    ];
    for (reply, golden) in replies {
        assert_eq!(serde_json::to_value(&reply).unwrap(), golden);
        assert_eq!(
            serde_json::from_value::<AppReply>(golden.clone()).unwrap(),
            reply
        );
        for key in [
            "bytes",
            "path",
            "token",
            "actorId",
            "replay",
            "notCommitted",
        ] {
            let mut extra = golden.clone();
            extra[key] = json!("not a control fact");
            assert!(serde_json::from_value::<AppReply>(extra).is_err(), "{key}");
        }
    }
}

#[test]
fn public_artifact_read_selectors_reject_duplicate_and_unbounded_sequences() {
    assert!(is_canonical_artifact_read_handle(HANDLE));
    for malformed in [
        HANDLE.to_uppercase(),
        HANDLE.replace('-', ""),
        format!("{HANDLE}\0"),
        format!("{HANDLE}/next"),
        "../../private".into(),
        "0199d763-f300-4000-8000-000000000002".into(),
    ] {
        assert!(!is_canonical_artifact_read_handle(&malformed));
    }
    // A memory locator's format alone proves neither existence nor its original host.
    assert!(is_canonical_artifact_read_handle(ARTIFACT));
    for kind in [
        "read_artifact_read_block",
        "acknowledge_artifact_read_block",
    ] {
        for sequence in [
            json!(-1),
            json!(4294967296_u64),
            json!(1.0),
            json!("0"),
            json!(null),
        ] {
            assert!(
                serde_json::from_value::<AppCommand>(json!({
                    "kind":kind,"handleId":HANDLE,"sequence":sequence,
                }))
                .is_err()
            );
        }
        for sequence in [0, u32::MAX] {
            assert!(
                serde_json::from_value::<AppCommand>(json!({
                    "kind":kind,"handleId":HANDLE,"sequence":sequence,
                }))
                .is_ok()
            );
        }
        let duplicate = format!(
            "{{\"kind\":\"{kind}\",\"handleId\":\"{HANDLE}\",\"sequence\":0,\"sequence\":1}}"
        );
        assert!(serde_json::from_str::<AppCommand>(&duplicate).is_err());
    }
    let duplicate_handle =
        format!("{{\"handleId\":\"{HANDLE}\",\"handleId\":\"{ARTIFACT}\",\"sequence\":0}}");
    assert!(serde_json::from_str::<ReadArtifactReadBlock>(&duplicate_handle).is_err());
    assert!(serde_json::from_value::<ReadArtifactReadBlock>(json!({"handleId":HANDLE})).is_err());
    assert!(
        serde_json::from_value::<OpenArtifactRead>(
            json!({"artifactId":ARTIFACT,"handleId":HANDLE})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<CloseArtifactRead>(json!({"handleId":HANDLE,"sequence":0}))
            .is_err()
    );
}
