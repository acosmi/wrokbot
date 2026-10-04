use openbot_contracts::artifacts::{
    GetSourceRunArtifactIds, SourceRunArtifactIds, is_valid_artifact_identity,
};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::ids::{RunId, ThreadId};
use serde_json::json;

#[test]
fn source_run_id_dtos_keep_closed_exact_identity_and_no_byte_fields() {
    let input = GetSourceRunArtifactIds {
        source_thread_id: ThreadId::new("source/thread%成果"),
        source_run_id: RunId::new(" run:é/原件 "),
    };
    let wire = json!({"sourceThreadId":"source/thread%成果","sourceRunId":" run:é/原件 "});
    assert_eq!(serde_json::to_value(&input).unwrap(), wire);
    assert_eq!(serde_json::from_value::<GetSourceRunArtifactIds>(wire.clone()).unwrap(), input);
    for field in ["authority", "ownerActorId", "path", "body", "pool", "sessionId", "handle"] {
        let mut invalid = wire.clone();
        invalid[field] = json!("untrusted");
        assert!(serde_json::from_value::<GetSourceRunArtifactIds>(invalid).is_err(), "{field}");
    }
    for id in ["x", " ", "成果/%é", &"x".repeat(512)] {
        assert!(is_valid_artifact_identity(id));
    }
    for id in ["", "a\0b", "a\n", "a\u{7f}", "a\u{85}", &"x".repeat(513), &"é".repeat(257)] {
        assert!(!is_valid_artifact_identity(id));
    }
    let ids = SourceRunArtifactIds {
        source_thread_id: input.source_thread_id.clone(),
        source_run_id: input.source_run_id.clone(),
        artifact_ids: vec!["01900000-0000-7000-8000-000000000010".to_owned()],
    };
    let reply = serde_json::to_value(&ids).unwrap();
    assert_eq!(reply.as_object().unwrap().len(), 3);
    assert_eq!(reply["artifactIds"], json!(ids.artifact_ids));
    for field in ["body", "sha256", "byteLength", "status", "readHandle", "authority"] {
        let mut invalid = reply.clone();
        invalid[field] = json!("untrusted");
        assert!(serde_json::from_value::<SourceRunArtifactIds>(invalid).is_err(), "{field}");
    }
    let command = AppCommand::GetSourceRunArtifactIds(input);
    let command_wire = serde_json::to_value(&command).unwrap();
    assert_eq!(command_wire["kind"], "get_source_run_artifact_ids");
    assert_eq!(serde_json::from_value::<AppCommand>(command_wire.clone()).unwrap(), command);
    let mut injected = command_wire;
    injected["ownerActorId"] = json!("untrusted");
    assert!(serde_json::from_value::<AppCommand>(injected).is_err());
    let typed = AppReply::SourceRunArtifactIds(ids);
    let typed_wire = serde_json::to_value(&typed).unwrap();
    assert_eq!(typed_wire["kind"], "source_run_artifact_ids");
    assert_eq!(serde_json::from_value::<AppReply>(typed_wire).unwrap(), typed);
}
