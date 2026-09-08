//! Comprehensive integration tests for AG-UI 0.0.57 official event fixture.
//!
//! Validates:
//! 1. Exact set equality between fixture event types and `openbot_agent::agui::AGUI_EVENT_TYPES` (33 events).
//! 2. Clean decoding of all lifecycle runs in `official-event-family.jsonl` by `AguiDecoder`.
//! 3. Isolated individual validation of each of the 33 official event types.
//! 4. Provenance metadata and hash integrity across all vendored schema files.
//! 5. Official wire compatibility for `RunAgentInput` serialization and resume representation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use openbot_agent::agui::{
    AGUI_EVENT_TYPES, AGUI_SCHEMA_VERSION, AguiDecoder, AguiEvent, AguiRole,
    encode_run_agent_input, encode_run_agent_input_with_resume,
};
use openbot_application::{
    ProviderMessage, ProviderMessageRole, ProviderRemoteResume, ProviderRemoteResumeEntry,
    ProviderRemoteResumeStatus, ProviderToolCall, ProviderToolDefinition,
};
use openbot_domain::audit::hash::Sha256Digest;
use serde_json::{Value, json};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn read_fixture_lines() -> Vec<String> {
    let fixture_path = workspace_root().join("fixtures/agui/official-event-family.jsonl");
    let content = fs::read_to_string(&fixture_path)
        .unwrap_or_else(|err| panic!("failed to read fixture at {:?}: {}", fixture_path, err));
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn test_official_fixture_event_types_exact_match() {
    let lines = read_fixture_lines();
    assert!(
        !lines.is_empty(),
        "official-event-family.jsonl must not be empty"
    );

    let mut fixture_types = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let value: Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("line {} is not valid JSON: {}", idx + 1, err));
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("line {} missing string 'type' field", idx + 1));
        fixture_types.insert(event_type.to_owned());
    }

    let schema = fs::read_to_string(workspace_root().join("fixtures/agui/schema-0.0.57/events.ts"))
        .expect("fixed official event schema");
    let body = schema
        .split_once("export enum EventType {")
        .expect("official enum")
        .1
        .split_once("\n}")
        .expect("enum end")
        .0;
    let official_types: BTreeSet<String> = body
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once('=')?;
            let value = value.trim().trim_end_matches(',').trim_matches('"');
            assert_eq!(name.trim(), value, "official enum literal identity");
            Some(value.to_owned())
        })
        .collect();
    let expected_types: BTreeSet<String> = AGUI_EVENT_TYPES.iter().map(|&s| s.to_owned()).collect();
    assert_eq!(
        official_types, fixture_types,
        "official schema and fixture type sets"
    );
    assert_eq!(
        official_types, expected_types,
        "official schema and Rust type sets"
    );

    assert_eq!(
        fixture_types.len(),
        33,
        "fixture must contain exactly 33 distinct event types"
    );
    assert_eq!(
        expected_types.len(),
        33,
        "AGUI_EVENT_TYPES must contain exactly 33 distinct event types"
    );

    let missing: Vec<_> = expected_types.difference(&fixture_types).collect();
    let unexpected: Vec<_> = fixture_types.difference(&expected_types).collect();

    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "Event types mismatch: missing={:?}, unexpected={:?}",
        missing,
        unexpected
    );
}

#[test]
fn test_official_fixture_runs_decode_successfully() {
    let lines = read_fixture_lines();

    // Group lines into runs based on RUN_STARTED occurrences
    let mut runs: Vec<Vec<String>> = Vec::new();
    let mut current_run: Vec<String> = Vec::new();

    for line in lines {
        let value: Value = serde_json::from_str(&line).expect("valid JSON");
        if value.get("type").and_then(Value::as_str) == Some("RUN_STARTED")
            && !current_run.is_empty()
        {
            runs.push(current_run);
            current_run = Vec::new();
        }
        current_run.push(line);
    }
    if !current_run.is_empty() {
        runs.push(current_run);
    }

    assert_eq!(
        runs.len(),
        3,
        "expected 3 structured lifecycle runs in official fixture"
    );

    // --- Run 1: Full success lifecycle with 31 non-error event types ---
    {
        let run1_lines = &runs[0];
        let first: Value = serde_json::from_str(&run1_lines[0]).expect("valid JSON");
        let thread_id = first["threadId"].as_str().expect("threadId");
        let run_id = first["runId"].as_str().expect("runId");

        let mut decoder = AguiDecoder::new(thread_id, run_id, json!({})).unwrap();
        let mut total_events = Vec::new();

        for (idx, line) in run1_lines.iter().enumerate() {
            let events = decoder.ingest(line).unwrap_or_else(|err| {
                panic!(
                    "Run 1 line {} failed ingest: {:?} (raw: {})",
                    idx + 1,
                    err,
                    line
                )
            });
            total_events.extend(events);
        }

        let finish_events = decoder.finish().expect("Run 1 finish() must succeed");
        total_events.extend(finish_events);

        // Verify state snapshot & delta were applied
        assert_eq!(decoder.state()["items_processed"], 2);
        assert_eq!(decoder.state()["stage_completed"], true);

        // Verify activity snapshot & delta
        let activity = decoder
            .activity("act-plan-001")
            .expect("act-plan-001 must exist");
        assert_eq!(activity["progress"], 100);

        // Verify messages snapshot
        assert_eq!(decoder.messages().len(), 2);
        assert_eq!(decoder.messages()[0]["role"], "user");
        assert_eq!(decoder.messages()[1]["role"], "assistant");

        // Verify terminal was RunFinished
        assert!(
            total_events.contains(&AguiEvent::RunFinished),
            "Run 1 must include RunFinished event"
        );
    }

    // --- Run 2: Error run ---
    {
        let run2_lines = &runs[1];
        let first: Value = serde_json::from_str(&run2_lines[0]).expect("valid JSON");
        let thread_id = first["threadId"].as_str().expect("threadId");
        let run_id = first["runId"].as_str().expect("runId");

        let mut decoder = AguiDecoder::new(thread_id, run_id, json!({})).unwrap();
        let mut total_events = Vec::new();

        for (idx, line) in run2_lines.iter().enumerate() {
            let events = decoder.ingest(line).unwrap_or_else(|err| {
                panic!(
                    "Run 2 line {} failed ingest: {:?} (raw: {})",
                    idx + 1,
                    err,
                    line
                )
            });
            total_events.extend(events);
        }

        let finish_events = decoder
            .finish()
            .expect("Run 2 finish() must succeed after RUN_ERROR");
        total_events.extend(finish_events);

        assert!(
            total_events
                .iter()
                .any(|ev| matches!(ev, AguiEvent::RunError { .. })),
            "Run 2 must decode RunError"
        );
    }

    // --- Run 3: Interruption run ---
    {
        let run3_lines = &runs[2];
        let first: Value = serde_json::from_str(&run3_lines[0]).expect("valid JSON");
        let thread_id = first["threadId"].as_str().expect("threadId");
        let run_id = first["runId"].as_str().expect("runId");

        let mut decoder = AguiDecoder::new(thread_id, run_id, json!({})).unwrap();
        let mut total_events = Vec::new();

        for (idx, line) in run3_lines.iter().enumerate() {
            let events = decoder.ingest(line).unwrap_or_else(|err| {
                panic!(
                    "Run 3 line {} failed ingest: {:?} (raw: {})",
                    idx + 1,
                    err,
                    line
                )
            });
            total_events.extend(events);
        }

        let finish_events = decoder
            .finish()
            .expect("Run 3 finish() must succeed after interrupt");
        total_events.extend(finish_events);

        assert!(
            total_events.iter().any(|ev| matches!(ev, AguiEvent::RunInterrupted { interrupts } if !interrupts.is_empty())),
            "Run 3 must decode RunInterrupted"
        );
    }
}

#[test]
fn test_official_fixture_all_33_events_individually() {
    let lines = read_fixture_lines();
    let mut sample_by_type: BTreeMap<String, Value> = BTreeMap::new();
    for line in &lines {
        let val: Value = serde_json::from_str(line).unwrap();
        let t = val["type"].as_str().unwrap().to_owned();
        sample_by_type.entry(t).or_insert(val);
    }

    assert_eq!(sample_by_type.len(), 33);

    // 1. RUN_STARTED
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        let ev = d
            .ingest(
                &json!({
                    "type": "RUN_STARTED",
                    "threadId": "t",
                    "runId": "r"
                })
                .to_string(),
            )
            .unwrap();
        assert_eq!(ev, vec![AguiEvent::RunStarted]);
    }

    // 2. STEP_STARTED & 3. STEP_FINISHED
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(&json!({"type": "STEP_STARTED", "stepName": "init"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::StepStarted {
                name: "init".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "STEP_FINISHED", "stepName": "init"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::StepFinished {
                name: "init".to_owned()
            }]
        );
    }

    // 4. TEXT_MESSAGE_START & 5. TEXT_MESSAGE_CONTENT & 6. TEXT_MESSAGE_END
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(
                &json!({"type": "TEXT_MESSAGE_START", "messageId": "m1", "role": "assistant"})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::TextStarted {
                id: "m1".to_owned(),
                role: AguiRole::Assistant,
                name: None
            }]
        );
        let ev = d
            .ingest(
                &json!({"type": "TEXT_MESSAGE_CONTENT", "messageId": "m1", "delta": "hi"})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::TextDelta {
                id: "m1".to_owned(),
                delta: "hi".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "TEXT_MESSAGE_END", "messageId": "m1"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::TextEnded {
                id: "m1".to_owned()
            }]
        );
    }

    // 7. TEXT_MESSAGE_CHUNK
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "TEXT_MESSAGE_CHUNK", "messageId": "c1", "role": "user", "delta": "hello"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![
                AguiEvent::TextStarted {
                    id: "c1".to_owned(),
                    role: AguiRole::User,
                    name: None
                },
                AguiEvent::TextDelta {
                    id: "c1".to_owned(),
                    delta: "hello".to_owned()
                }
            ]
        );
        let ev = d
            .ingest(&json!({"type": "TEXT_MESSAGE_CHUNK", "delta": ""}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::TextEnded {
                id: "c1".to_owned()
            }]
        );
    }

    // 8. TOOL_CALL_START & 9. TOOL_CALL_ARGS & 10. TOOL_CALL_END & 11. TOOL_CALL_RESULT
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(
                &json!({"type": "TOOL_CALL_START", "toolCallId": "tc1", "toolCallName": "calc"})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ToolStarted {
                id: "tc1".to_owned(),
                name: "calc".to_owned(),
                parent_message_id: None
            }]
        );
        let ev = d
            .ingest(
                &json!({"type": "TOOL_CALL_ARGS", "toolCallId": "tc1", "delta": r#"{"x":1}"#})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ToolArguments {
                id: "tc1".to_owned(),
                delta: r#"{"x":1}"#.to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "TOOL_CALL_END", "toolCallId": "tc1"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ToolCompleted {
                id: "tc1".to_owned(),
                name: "calc".to_owned(),
                arguments: json!({"x": 1})
            }]
        );
        let ev = d.ingest(&json!({"type": "TOOL_CALL_RESULT", "messageId": "m_res", "toolCallId": "tc1", "content": "result_ok"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ToolResult {
                message_id: "m_res".to_owned(),
                call_id: "tc1".to_owned(),
                content: "result_ok".to_owned()
            }]
        );
    }

    // 12. TOOL_CALL_CHUNK
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "TOOL_CALL_CHUNK", "toolCallId": "tchunk1", "toolCallName": "fetch", "delta": r#"{"a":1}"#}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![
                AguiEvent::ToolStarted {
                    id: "tchunk1".to_owned(),
                    name: "fetch".to_owned(),
                    parent_message_id: None
                },
                AguiEvent::ToolArguments {
                    id: "tchunk1".to_owned(),
                    delta: r#"{"a":1}"#.to_owned()
                }
            ]
        );
        let ev = d
            .ingest(&json!({"type": "TOOL_CALL_CHUNK", "delta": ""}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ToolCompleted {
                id: "tchunk1".to_owned(),
                name: "fetch".to_owned(),
                arguments: json!({"a": 1})
            }]
        );
    }

    // 13. STATE_SNAPSHOT & 14. STATE_DELTA
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(&json!({"type": "STATE_SNAPSHOT", "snapshot": {"k": 10}}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::StateSnapshot {
                untrusted_snapshot: json!({"k": 10})
            }]
        );
        let ev = d.ingest(&json!({"type": "STATE_DELTA", "delta": [{"op": "replace", "path": "/k", "value": 20}]}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::StateDelta {
                untrusted_patch: vec![json!({"op": "replace", "path": "/k", "value": 20})]
            }]
        );
        assert_eq!(d.state()["k"], 20);
    }

    // 15. MESSAGES_SNAPSHOT
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "MESSAGES_SNAPSHOT", "messages": [{"id": "msg1", "role": "developer", "content": "dev prompt"}]}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::MessagesSnapshot {
                untrusted_messages: vec![
                    json!({"id": "msg1", "role": "developer", "content": "dev prompt"})
                ]
            }]
        );
        assert_eq!(d.messages().len(), 1);
    }

    // 16. ACTIVITY_SNAPSHOT & 17. ACTIVITY_DELTA
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "ACTIVITY_SNAPSHOT", "messageId": "act1", "activityType": "task", "content": {"done": false}}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ActivitySnapshot {
                message_id: "act1".to_owned(),
                activity_type: "task".to_owned(),
                untrusted_content: json!({"done": false}),
                replace: true
            }]
        );
        let ev = d.ingest(&json!({"type": "ACTIVITY_DELTA", "messageId": "act1", "activityType": "task", "patch": [{"op": "replace", "path": "/done", "value": true}]}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ActivityDelta {
                message_id: "act1".to_owned(),
                activity_type: "task".to_owned(),
                untrusted_patch: vec![json!({"op": "replace", "path": "/done", "value": true})]
            }]
        );
        assert_eq!(d.activity("act1").unwrap()["done"], true);
    }

    // 18. RAW & 19. CUSTOM
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(&json!({"type": "RAW", "event": {"raw": 1}, "source": "gateway"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::Raw {
                source: Some("gateway".to_owned()),
                untrusted_event: json!({"raw": 1})
            }]
        );
        let ev = d
            .ingest(&json!({"type": "CUSTOM", "name": "ping", "value": {"t": 123}}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::Custom {
                name: "ping".to_owned(),
                untrusted_value: json!({"t": 123})
            }]
        );
    }

    // 20. REASONING_START & 21. REASONING_MESSAGE_START & 22. REASONING_MESSAGE_CONTENT & 23. REASONING_MESSAGE_END & 24. REASONING_END
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(&json!({"type": "REASONING_START", "messageId": "rs1"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningStarted {
                id: "rs1".to_owned()
            }]
        );
        let ev = d.ingest(&json!({"type": "REASONING_MESSAGE_START", "messageId": "rm1", "role": "reasoning"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningMessageStarted {
                id: "rm1".to_owned()
            }]
        );
        let ev = d.ingest(&json!({"type": "REASONING_MESSAGE_CONTENT", "messageId": "rm1", "delta": "thinking"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningDelta {
                id: "rm1".to_owned(),
                delta: "thinking".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "REASONING_MESSAGE_END", "messageId": "rm1"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningMessageEnded {
                id: "rm1".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "REASONING_END", "messageId": "rs1"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningEnded {
                id: "rs1".to_owned()
            }]
        );
    }

    // 25. REASONING_MESSAGE_CHUNK
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "REASONING_MESSAGE_CHUNK", "messageId": "rchunk1", "delta": "partial reasoning"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![
                AguiEvent::ReasoningMessageStarted {
                    id: "rchunk1".to_owned()
                },
                AguiEvent::ReasoningDelta {
                    id: "rchunk1".to_owned(),
                    delta: "partial reasoning".to_owned()
                }
            ]
        );
        let ev = d
            .ingest(&json!({"type": "REASONING_MESSAGE_CHUNK", "delta": ""}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningMessageEnded {
                id: "rchunk1".to_owned()
            }]
        );
    }

    // 26. THINKING_START & 27. THINKING_TEXT_MESSAGE_START & 28. THINKING_TEXT_MESSAGE_CONTENT & 29. THINKING_TEXT_MESSAGE_END & 30. THINKING_END
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(&json!({"type": "THINKING_START", "title": "legacy title"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningStarted {
                id: "thinking:r".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "THINKING_TEXT_MESSAGE_START"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningMessageStarted {
                id: "thinking-text:r".to_owned()
            }]
        );
        let ev = d
            .ingest(
                &json!({"type": "THINKING_TEXT_MESSAGE_CONTENT", "delta": "thought chunk"})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningDelta {
                id: "thinking-text:r".to_owned(),
                delta: "thought chunk".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "THINKING_TEXT_MESSAGE_END"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningMessageEnded {
                id: "thinking-text:r".to_owned()
            }]
        );
        let ev = d
            .ingest(&json!({"type": "THINKING_END"}).to_string())
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningEnded {
                id: "thinking:r".to_owned()
            }]
        );
    }

    // 31. REASONING_ENCRYPTED_VALUE
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "REASONING_ENCRYPTED_VALUE", "subtype": "message", "entityId": "msg1", "encryptedValue": "secret"}).to_string()).unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::ReasoningEncrypted {
                subtype: "message".to_owned(),
                entity_id: "msg1".to_owned(),
                encrypted_value: "secret".to_owned()
            }]
        );
    }

    // 32. RUN_FINISHED (success & interrupt)
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d.ingest(&json!({"type": "RUN_FINISHED", "threadId": "t", "runId": "r", "outcome": {"type": "success"}}).to_string()).unwrap();
        assert_eq!(ev, vec![AguiEvent::RunFinished]);
    }

    // 33. RUN_ERROR
    {
        let mut d = AguiDecoder::new("t", "r", json!({})).unwrap();
        d.ingest(&json!({"type": "RUN_STARTED", "threadId": "t", "runId": "r"}).to_string())
            .unwrap();
        let ev = d
            .ingest(
                &json!({"type": "RUN_ERROR", "message": "fail", "code": "ERR_FAIL"}).to_string(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![AguiEvent::RunError {
                message: "fail".to_owned(),
                code: Some("ERR_FAIL".to_owned())
            }]
        );
    }
}

#[test]
fn test_official_fixture_provenance_integrity() {
    let repo_root = workspace_root();
    let provenance_path = repo_root.join("fixtures/agui/official-event-family.provenance.json");
    let prov_bytes = fs::read(&provenance_path)
        .unwrap_or_else(|err| panic!("failed to read provenance file: {}", err));
    let prov: Value = serde_json::from_slice(&prov_bytes).expect("valid JSON");

    assert_eq!(prov["schema"], "openbot-fixture-provenance-v1");
    assert_eq!(prov["protocol"], "AG-UI");
    assert_eq!(prov["version"], AGUI_SCHEMA_VERSION);
    assert_eq!(prov["license"]["spdx"], "MIT");

    // Check official-event-family.jsonl SHA-256
    let fixture_path = repo_root.join("fixtures/agui/official-event-family.jsonl");
    let fixture_bytes = fs::read(&fixture_path).expect("read fixture");
    let fixture_sha = Sha256Digest::of(&fixture_bytes).to_hex();
    assert_eq!(prov["fixture"]["sha256"], fixture_sha);
    assert_eq!(prov["fixture"]["bytes"], fixture_bytes.len());
    assert_eq!(prov["fixture"]["line_count"], read_fixture_lines().len());
    assert_eq!(prov["provenance"]["slsa_signature_verified"], false);

    // Check all vendored schema files exist and match recorded hashes
    let schema_dir = repo_root.join("fixtures/agui/schema-0.0.57");
    let files_map = prov["vendored_schema"]["files"]
        .as_object()
        .expect("vendored_schema.files must be object");

    let expected = BTreeSet::from([
        "package-manifest.json",
        "events.ts",
        "types.ts",
        "capabilities.ts",
        "index.ts",
        "LICENSE",
        "README.md",
    ]);
    assert_eq!(
        files_map
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected
    );
    let actual = fs::read_dir(&schema_dir)
        .expect("schema directory")
        .map(|entry| {
            let entry = entry.expect("entry");
            assert!(
                entry.file_type().expect("type").is_file(),
                "regular files only"
            );
            entry.file_name().into_string().expect("UTF-8 filename")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        expected
    );

    for (file_name, info) in files_map {
        let file_path = schema_dir.join(file_name);
        assert!(
            file_path.exists(),
            "vendored file {:?} must exist",
            file_path
        );
        let content = fs::read(&file_path).unwrap();
        assert_eq!(info["bytes"], content.len(), "source byte count");
        let actual_sha = Sha256Digest::of(&content).to_hex();
        let expected_sha = info["sha256"].as_str().expect("sha256 string");
        assert_eq!(
            actual_sha, expected_sha,
            "hash mismatch on vendored file {}",
            file_name
        );
    }
}

#[test]
fn test_official_run_agent_input_wire_compatibility() {
    let messages = vec![
        ProviderMessage {
            role: ProviderMessageRole::System,
            content: "You are a helpful assistant.".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        },
        ProviderMessage {
            role: ProviderMessageRole::User,
            content: "Please check weather.".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        },
        ProviderMessage {
            role: ProviderMessageRole::Assistant,
            content: "Checking now.".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: vec![ProviderToolCall {
                call_id: "tc-weather-1".to_owned(),
                name: "get_weather".to_owned(),
                arguments: json!({"location": "Tokyo"}),
            }],
        },
        ProviderMessage {
            role: ProviderMessageRole::Tool,
            content: r#"{"temp": 22}"#.to_owned(),
            tool_call_id: Some("tc-weather-1".to_owned()),
            tool_name: Some("get_weather".to_owned()),
            tool_calls: Vec::new(),
        },
    ];

    let tools = vec![ProviderToolDefinition {
        name: "get_weather".to_owned(),
        description: "Get current weather for location".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "location": { "type": "string" }
            },
            "required": ["location"]
        }),
    }];

    let encoded = encode_run_agent_input(
        "thread-wire-1",
        "run-wire-1",
        &messages,
        &tools,
        json!({"customClientProp": "value1"}),
    )
    .expect("encode_run_agent_input");

    let wire: Value = serde_json::from_slice(&encoded).expect("valid wire json");

    // Conformance with official @ag-ui/core RunAgentInputSchema
    assert_eq!(wire["threadId"], "thread-wire-1");
    assert_eq!(wire["runId"], "run-wire-1");
    assert!(wire["state"].is_object());
    assert!(wire["messages"].is_array());
    assert_eq!(wire["messages"].as_array().unwrap().len(), 4);
    assert_eq!(wire["tools"].as_array().unwrap().len(), 1);
    assert_eq!(wire["tools"][0]["name"], "get_weather");
    assert_eq!(wire["tools"][0]["parameters"]["type"], "object");
    assert!(wire["context"].is_array());
    assert_eq!(wire["forwardedProps"]["customClientProp"], "value1");

    // Resume conformance
    let resume = ProviderRemoteResume::new(
        "run-wire-1".to_owned(),
        "run-wire-2".to_owned(),
        vec![
            ProviderRemoteResumeEntry::new(
                "int-auth-01".to_owned(),
                ProviderRemoteResumeStatus::Resolved,
                Some(json!({"confirmed": true})),
            )
            .expect("valid resume entry"),
        ],
    )
    .expect("valid resume");

    let encoded_resumed = encode_run_agent_input_with_resume(
        "thread-wire-1",
        "run-wire-2",
        &messages[..2],
        &tools,
        json!({}),
        Some("run-wire-1"),
        Some(&resume),
    )
    .expect("encode resumed");

    let wire_resumed: Value = serde_json::from_slice(&encoded_resumed).expect("valid wire json");
    assert_eq!(wire_resumed["threadId"], "thread-wire-1");
    assert_eq!(wire_resumed["runId"], "run-wire-2");
    assert_eq!(wire_resumed["parentRunId"], "run-wire-1");
    assert_eq!(wire_resumed["resume"][0]["interruptId"], "int-auth-01");
    assert_eq!(wire_resumed["resume"][0]["status"], "resolved");
    assert_eq!(wire_resumed["resume"][0]["payload"]["confirmed"], true);
}
