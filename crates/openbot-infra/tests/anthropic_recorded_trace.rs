//! Offline replay of Anthropic-published Messages API recorded responses.

use std::time::Duration;

use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderMessage, ProviderMessageRole,
    ProviderOutputKind, ProviderRequest, ProviderToolDefinition, ProviderUsage,
};
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::provider::anthropic::{
    AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const TOOL_TRACE: &[u8] =
    include_bytes!("../../../fixtures/provider/anthropic-messages-tool-use-stream.sse");
const TOOL_PROVENANCE: &str =
    include_str!("../../../fixtures/provider/anthropic-messages-tool-use-stream.provenance.json");
const THINKING_TRACE: &[u8] =
    include_bytes!("../../../fixtures/provider/anthropic-messages-thinking-stream.sse");
const THINKING_PROVENANCE: &str =
    include_str!("../../../fixtures/provider/anthropic-messages-thinking-stream.provenance.json");

const API_KEY: &str = "fixture-only-not-a-secret";
const TOOL_RESPONSE_ID: &str = "msg_01H1pwRRkQxKbUGKi785gT4M";
const TOOL_CALL_ID: &str = "toolu_01RaX2WYWRWCbaeFHssmGJXG";
const TOOL_NAME: &str = "get_weather";
const THINKING_RESPONSE_ID: &str = "msg_thinking_x";
const VENDOR_BODY_CANARY: &str = "OPENBOT_ANTHROPIC_VENDOR_BODY_CANARY_67c104e7";
const IRREGULAR_CHUNKS: &[usize] = &[1, 2, 3, 5, 8, 13, 21, 34, 55, 89];
const BYTEWISE_CHUNKS: &[usize] = &[1];

#[derive(Clone, Copy)]
struct RecordedTraceIdentity {
    trace: &'static [u8],
    provenance: &'static str,
    fixture_path: &'static str,
    fixture_bytes: usize,
    fixture_sha256: &'static str,
    repository: &'static str,
    source_commit: &'static str,
    source_commit_time_utc: &'static str,
    source_record_url: &'static str,
    source_test_url: &'static str,
    recording_proof_url: &'static str,
    source_record_blob_sha1: &'static str,
    source_record_bytes: usize,
    source_record_sha256: &'static str,
    retrieved_at_utc: &'static str,
    api: &'static str,
    source_endpoint: &'static str,
    request_model: &'static str,
    response_model: &'static str,
    retained_public_protocol_values: &'static [(&'static str, &'static str)],
}

const TOOL_IDENTITY: RecordedTraceIdentity = RecordedTraceIdentity {
    trace: TOOL_TRACE,
    provenance: TOOL_PROVENANCE,
    fixture_path: "fixtures/provider/anthropic-messages-tool-use-stream.sse",
    fixture_bytes: 3_489,
    fixture_sha256: "9e75e3423449cfda1266e73327f43949fa0318b68a1d17293d4d06fe7ecbd783",
    repository: "https://github.com/anthropics/anthropic-sdk-go",
    source_commit: "e9c104e7e5fb80a26ff26e398c0e4e3fe1fe7f33",
    source_commit_time_utc: "2026-09-03T22:32:55Z",
    source_record_url: "https://github.com/anthropics/anthropic-sdk-go/blob/e9c104e7e5fb80a26ff26e398c0e4e3fe1fe7f33/toolrunner/testdata/cassettes/tool_runner_streaming_all.yaml",
    source_test_url: "https://github.com/anthropics/anthropic-sdk-go/blob/e9c104e7e5fb80a26ff26e398c0e4e3fe1fe7f33/toolrunner/runner_test.go#L188-L227",
    recording_proof_url: "https://github.com/anthropics/anthropic-sdk-go/blob/e9c104e7e5fb80a26ff26e398c0e4e3fe1fe7f33/internal/testutil/vcr.go#L12-L35",
    source_record_blob_sha1: "2085d5a9d2bb3b97992e74206a35fb0c92253ecb",
    source_record_bytes: 10_980,
    source_record_sha256: "a523fe3e4db93da6e1b8f715e151d448bc9cc2231bae603d5357f2f6583140fe",
    retrieved_at_utc: "2026-09-04T22:13:41Z",
    api: "Beta Messages",
    source_endpoint: "https://api.anthropic.com/v1/messages?beta=true",
    request_model: "claude-3-7-sonnet-latest",
    response_model: "claude-3-7-sonnet-20250219",
    retained_public_protocol_values: &[
        ("message_id", TOOL_RESPONSE_ID),
        ("tool_use_id", TOOL_CALL_ID),
    ],
};

const THINKING_IDENTITY: RecordedTraceIdentity = RecordedTraceIdentity {
    trace: THINKING_TRACE,
    provenance: THINKING_PROVENANCE,
    fixture_path: "fixtures/provider/anthropic-messages-thinking-stream.sse",
    fixture_bytes: 1_415,
    fixture_sha256: "d5cf8f848dd95e809110c93c7531d3689331f52a92f0722211ca5c71bbff23d8",
    repository: "https://github.com/anthropics/anthropic-sdk-php",
    source_commit: "93aa419595dceeb7062292e09406b4e2a63b96e1",
    source_commit_time_utc: "2026-09-01T18:08:37Z",
    source_record_url: "https://github.com/anthropics/anthropic-sdk-php/blob/93aa419595dceeb7062292e09406b4e2a63b96e1/fixtures/ga/thinking.txt",
    source_test_url: "https://github.com/anthropics/anthropic-sdk-php/blob/93aa419595dceeb7062292e09406b4e2a63b96e1/tests/Lib/Streaming/MessageAccumulatorTest.php#L25-L49",
    recording_proof_url: "https://github.com/anthropics/anthropic-sdk-php/blob/93aa419595dceeb7062292e09406b4e2a63b96e1/fixtures/README.md#L10-L19",
    source_record_blob_sha1: "b6d1f6575606504542fd59bf55b8ef6cbeaa7731",
    source_record_bytes: 1_609,
    source_record_sha256: "70366a8b43b634eb1bc1e4e1fabbc7c14a8d182cca7561402ff40c07594652ef",
    retrieved_at_utc: "2026-09-04T22:13:41Z",
    api: "Messages",
    source_endpoint: "https://api.anthropic.com/v1/messages",
    request_model: "claude-sonnet-4-5",
    response_model: "claude-sonnet-4-5",
    retained_public_protocol_values: &[
        ("message_id", THINKING_RESPONSE_ID),
        ("signature_delta", "abc123sig=="),
    ],
};

#[derive(Clone, Copy)]
struct ReplayCase {
    model: &'static str,
    tool_name: Option<&'static str>,
}

const TOOL_CASE: ReplayCase = ReplayCase {
    model: "claude-3-7-sonnet-latest",
    tool_name: Some(TOOL_NAME),
};
const THINKING_CASE: ReplayCase = ReplayCase {
    model: "claude-sonnet-4-5",
    tool_name: None,
};

#[derive(Clone, Copy)]
struct ResponseSpec {
    status_line: &'static str,
    content_type: &'static str,
}

const OK_SSE: ResponseSpec = ResponseSpec {
    status_line: "200 OK",
    content_type: "text/event-stream; charset=utf-8",
};
const SERVER_ERROR_JSON: ResponseSpec = ResponseSpec {
    status_line: "500 Internal Server Error",
    content_type: "application/json",
};

#[tokio::test]
async fn anthropic_recorded_traces_replay_through_production_adapter() {
    assert_fixture_identity_and_provenance(TOOL_IDENTITY);
    assert_fixture_identity_and_provenance(THINKING_IDENTITY);
    assert_fixtures_have_no_secret_or_request_material();

    let expected_tool = expected_tool_events();
    assert_recorded_replay_across_chunk_patterns(TOOL_CASE, TOOL_TRACE, &expected_tool).await;

    let expected_thinking = expected_thinking_events();
    assert_recorded_replay_across_chunk_patterns(THINKING_CASE, THINKING_TRACE, &expected_thinking)
        .await;
}

async fn assert_recorded_replay_across_chunk_patterns(
    case: ReplayCase,
    trace: &[u8],
    expected_events: &[ProviderEvent],
) {
    let whole_trace = [trace.len()];
    for chunk_sizes in [&whole_trace[..], IRREGULAR_CHUNKS, BYTEWISE_CHUNKS] {
        let events = replay(case, trace, chunk_sizes, OK_SSE).await;
        assert_eq!(events.as_slice(), expected_events);
        assert_single_terminal(&events, true);
    }
}

#[tokio::test]
async fn test_only_utf8_extension_preserves_recorded_output() {
    // Test-only mutation, never a recorded fixture: insert an unknown event containing a
    // multibyte scalar before the recorded terminal and frame every HTTP body byte separately.
    let mutated = insert_unknown_utf8_extension(TOOL_TRACE);
    assert!(
        mutated
            .windows("雪".len())
            .any(|bytes| bytes == "雪".as_bytes())
    );
    let events = replay(TOOL_CASE, &mutated, BYTEWISE_CHUNKS, OK_SSE).await;
    assert_eq!(events, expected_tool_events());
    assert_single_terminal(&events, true);
}

#[tokio::test]
async fn negative_mutations_fail_closed_without_vendor_body_or_key_leakage() {
    // Negative mutation, not a recorded fixture: malformed SSE data must not echo vendor text.
    let malformed = format!("event: message_start\ndata: {VENDOR_BODY_CANARY}\n\n");
    let malformed_events = replay(TOOL_CASE, malformed.as_bytes(), BYTEWISE_CHUNKS, OK_SSE).await;
    assert_failed_without_canary(
        &malformed_events,
        ProviderFailure::InvalidResponse,
        VENDOR_BODY_CANARY,
    );

    // Negative mutation, not a recorded fixture: an Anthropic error message remains opaque.
    let in_stream_error = format!(
        "event: error\ndata: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"{VENDOR_BODY_CANARY}\"}}}}\n\n"
    );
    let in_stream_events = replay(
        TOOL_CASE,
        in_stream_error.as_bytes(),
        IRREGULAR_CHUNKS,
        OK_SSE,
    )
    .await;
    assert_failed_without_canary(
        &in_stream_events,
        ProviderFailure::ServerUnavailable { retry_after: None },
        VENDOR_BODY_CANARY,
    );

    // Negative mutation, not a recorded fixture: HTTP error bodies never become provider events.
    let error_body = format!("{{\"error\":{{\"message\":\"{VENDOR_BODY_CANARY}\"}}}}");
    let error_events = replay(
        TOOL_CASE,
        error_body.as_bytes(),
        IRREGULAR_CHUNKS,
        SERVER_ERROR_JSON,
    )
    .await;
    assert_failed_without_canary(
        &error_events,
        ProviderFailure::ServerUnavailable { retry_after: None },
        VENDOR_BODY_CANARY,
    );

    // Negative mutation, not a recorded fixture: the final usage may repeat but cannot regress.
    let regressed_usage = replace_exact_once(
        TOOL_TRACE,
        br#""output_tokens":89"#,
        br#""output_tokens":1"#,
    );
    let regression_events = replay(TOOL_CASE, &regressed_usage, IRREGULAR_CHUNKS, OK_SSE).await;
    assert_terminal_failure_without_canary(
        &regression_events,
        ProviderFailure::InvalidResponse,
        VENDOR_BODY_CANARY,
    );

    // Negative mutation, not a recorded fixture: remove one terminal delimiter byte.
    let incomplete = &THINKING_TRACE[..THINKING_TRACE.len() - 1];
    let incomplete_events = replay(THINKING_CASE, incomplete, BYTEWISE_CHUNKS, OK_SSE).await;
    assert_terminal_failure_without_canary(
        &incomplete_events,
        ProviderFailure::InvalidResponse,
        VENDOR_BODY_CANARY,
    );
}

fn assert_fixture_identity_and_provenance(identity: RecordedTraceIdentity) {
    assert_eq!(identity.trace.len(), identity.fixture_bytes);
    assert_eq!(
        format!("{:x}", Sha256::digest(identity.trace)),
        identity.fixture_sha256
    );
    assert!(
        identity.trace.ends_with(b"\n\n"),
        "the exact vendor SSE body retains its terminal event delimiter"
    );

    let provenance: Value =
        serde_json::from_str(identity.provenance).expect("valid provenance JSON");
    let protocol = &provenance["protocol"];
    let source_provenance = &provenance["provenance"];
    let payload = &provenance["payload"];
    let license = &provenance["license"];

    assert_eq!(provenance["schema"], "openbot-provider-recorded-trace-v1");
    assert_eq!(provenance["provider"], "anthropic");
    assert_eq!(protocol["api"], identity.api);
    assert_eq!(protocol["transport"], "HTTP/1.1 server-sent events");
    assert_eq!(protocol["endpoint"], identity.source_endpoint);
    assert_eq!(
        protocol["replay_endpoint"],
        "https://api.anthropic.com/v1/messages"
    );
    assert_eq!(protocol["method"], "POST");
    assert_eq!(protocol["anthropic_version"], "2023-06-01");
    assert_eq!(protocol["request_model"], identity.request_model);
    assert_eq!(protocol["response_model"], identity.response_model);
    assert_eq!(protocol["status_code"], 200);
    assert_eq!(
        source_provenance["kind"],
        "vendor_capture_published_by_vendor"
    );
    assert_eq!(source_provenance["publisher"], "Anthropic");
    assert_eq!(source_provenance["repository"], identity.repository);
    assert_eq!(source_provenance["source_commit"], identity.source_commit);
    assert_eq!(
        source_provenance["source_commit_time_utc"],
        identity.source_commit_time_utc
    );
    assert_eq!(
        source_provenance["source_record_url"],
        identity.source_record_url
    );
    assert_eq!(
        source_provenance["source_test_url"],
        identity.source_test_url
    );
    assert_eq!(
        source_provenance["recording_proof_url"],
        identity.recording_proof_url
    );
    assert_eq!(
        source_provenance["source_record_git_blob_sha1"],
        identity.source_record_blob_sha1
    );
    assert_eq!(
        source_provenance["source_record_bytes"],
        identity.source_record_bytes
    );
    assert_eq!(
        source_provenance["source_record_sha256"],
        identity.source_record_sha256
    );
    assert_eq!(
        source_provenance["retrieved_at_utc"],
        identity.retrieved_at_utc
    );
    assert_eq!(payload["path"], identity.fixture_path);
    assert_eq!(payload["raw_response_body_bytes"], identity.fixture_bytes);
    assert_eq!(payload["raw_response_body_sha256"], identity.fixture_sha256);
    assert_eq!(payload["fixture_bytes"], identity.fixture_bytes);
    assert_eq!(payload["fixture_sha256"], identity.fixture_sha256);
    assert!(
        payload["derivation"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let preserved = provenance["response_headers"]["preserved"]
        .as_object()
        .expect("preserved response headers object");
    assert_eq!(preserved.len(), 1);
    assert_eq!(
        preserved.get("content-type"),
        Some(&json!("text/event-stream; charset=utf-8"))
    );
    for field in [
        "request_prompt_stored",
        "authorization_or_api_key_stored",
        "customer_data_stored",
        "verifiable_secret_hash_stored",
    ] {
        assert_eq!(provenance["redaction"][field], Value::Bool(false));
    }
    let retained_values = provenance["redaction"]["retained_public_protocol_values"]
        .as_object()
        .expect("retained public protocol values object");
    assert_eq!(
        retained_values.len(),
        identity.retained_public_protocol_values.len()
    );
    for (kind, expected_value) in identity.retained_public_protocol_values {
        let entry = retained_values.get(*kind).expect("retained protocol value");
        assert_eq!(entry["value"], *expected_value);
        assert!(
            entry["non_secret_basis"]
                .as_str()
                .is_some_and(|basis| basis.contains("grants no authority")),
            "retained protocol value must state its non-secret authority boundary"
        );
    }
    assert_eq!(license["spdx"], "MIT");
    assert_eq!(license["copyright"], "Copyright 2023 Anthropic, PBC.");
}

fn assert_fixtures_have_no_secret_or_request_material() {
    for trace in [TOOL_TRACE, THINKING_TRACE] {
        let trace = core::str::from_utf8(trace).expect("recorded trace is UTF-8 SSE");
        for forbidden in [
            "Authorization",
            "Bearer ",
            "ANTHROPIC_API_KEY",
            "X-Api-Key",
            "x-api-key",
            "sk-ant-",
            "fake-api-key",
            "anthropic-organization-id",
            "anthropic-ratelimit",
            "RequestBody",
            "RequestHeaders",
            "https://api.anthropic.com",
            "\"messages\"",
            "\"max_tokens\"",
            "\"stream\":true",
            "req_",
            "OPENBOT_CUSTOMER_DATA_CANARY_",
        ] {
            assert!(
                !trace.contains(forbidden),
                "forbidden fixture material: {forbidden}"
            );
        }
        assert!(
            !trace.contains('@'),
            "fixture must not contain an email-like value"
        );
        assert!(
            !contains_uuid_like(trace),
            "fixture must not retain an organization/customer UUID"
        );
    }

    for provenance in [TOOL_PROVENANCE, THINKING_PROVENANCE] {
        let value: Value = serde_json::from_str(provenance).expect("valid provenance JSON");
        assert_no_sensitive_provenance_keys(&value);
        for forbidden in [
            "fake-api-key",
            "req_",
            VENDOR_BODY_CANARY,
            "OPENBOT_CUSTOMER_DATA_CANARY_",
        ] {
            assert!(
                !provenance.contains(forbidden),
                "forbidden provenance material: {forbidden}"
            );
        }
        assert!(
            !contains_uuid_like(provenance),
            "provenance must not retain an organization/customer UUID"
        );
    }
}

fn assert_no_sensitive_provenance_keys(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    !matches!(
                        key.as_str(),
                        "authorization"
                            | "api_key"
                            | "organization_id"
                            | "request_body"
                            | "request_headers"
                            | "request_id"
                            | "request_prompt"
                    ),
                    "provenance must not retain sensitive field: {key}"
                );
                assert_no_sensitive_provenance_keys(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_no_sensitive_provenance_keys(value);
            }
        }
        _ => {}
    }
}

fn contains_uuid_like(value: &str) -> bool {
    value.as_bytes().windows(36).any(|candidate| {
        candidate
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
    })
}

fn expected_tool_events() -> Vec<ProviderEvent> {
    let mut events = vec![
        ProviderEvent::ResponseStarted {
            response_id: TOOL_RESPONSE_ID.to_owned(),
        },
        ProviderEvent::OutputItemAdded {
            index: 0,
            kind: ProviderOutputKind::Message,
        },
    ];
    for delta in [
        "I'll",
        " get",
        " the current weather in",
        " San Francisco for you in",
        " Fahrenheit.",
    ] {
        events.push(ProviderEvent::TextDelta {
            index: 0,
            delta: delta.to_owned(),
        });
    }
    events.extend([
        ProviderEvent::OutputItemAdded {
            index: 1,
            kind: ProviderOutputKind::FunctionCall,
        },
        ProviderEvent::ToolCallStarted {
            index: 1,
            call_id: TOOL_CALL_ID.to_owned(),
            name: Some(TOOL_NAME.to_owned()),
        },
    ]);
    for delta in [
        "{\"city",
        "\": \"S",
        "an F",
        "ra",
        "ncisco",
        "\"",
        ", \"units\"",
        ": \"fahr",
        "enhei",
        "t\"}",
    ] {
        events.push(ProviderEvent::ToolArgumentsDelta {
            index: 1,
            call_id: TOOL_CALL_ID.to_owned(),
            delta: delta.to_owned(),
        });
    }
    events.extend([
        ProviderEvent::ToolCallCompleted {
            index: 1,
            call_id: TOOL_CALL_ID.to_owned(),
            name: TOOL_NAME.to_owned(),
            arguments: json!({"city":"San Francisco","units":"fahrenheit"}),
        },
        ProviderEvent::Usage(ProviderUsage {
            input_tokens: 397,
            output_tokens: 89,
            total_tokens: 486,
        }),
        ProviderEvent::Completed,
    ]);
    events
}

fn expected_thinking_events() -> Vec<ProviderEvent> {
    vec![
        ProviderEvent::ResponseStarted {
            response_id: THINKING_RESPONSE_ID.to_owned(),
        },
        ProviderEvent::OutputItemAdded {
            index: 0,
            kind: ProviderOutputKind::Reasoning,
        },
        ProviderEvent::ReasoningDelta {
            index: 0,
            delta: "Let me think. ".to_owned(),
        },
        ProviderEvent::ReasoningDelta {
            index: 0,
            delta: "2 + 2 = 4.".to_owned(),
        },
        ProviderEvent::OutputItemAdded {
            index: 1,
            kind: ProviderOutputKind::Message,
        },
        ProviderEvent::TextDelta {
            index: 1,
            delta: "The answer is 4.".to_owned(),
        },
        ProviderEvent::Usage(ProviderUsage {
            input_tokens: 15,
            output_tokens: 20,
            total_tokens: 35,
        }),
        ProviderEvent::Completed,
    ]
}

fn assert_single_terminal(events: &[ProviderEvent], completed: bool) {
    let completed_count = events
        .iter()
        .filter(|event| matches!(event, ProviderEvent::Completed))
        .count();
    let failed_count = events
        .iter()
        .filter(|event| matches!(event, ProviderEvent::Failed(_)))
        .count();
    assert_eq!(
        completed_count + failed_count,
        1,
        "terminal must occur once"
    );
    assert_eq!(completed_count, usize::from(completed));
    assert_eq!(failed_count, usize::from(!completed));
    assert!(
        events.last().is_some_and(|event| matches!(
            event,
            ProviderEvent::Completed | ProviderEvent::Failed(_)
        )),
        "terminal must be the last normalized event"
    );
}

fn assert_failed_without_canary(events: &[ProviderEvent], expected: ProviderFailure, canary: &str) {
    assert_eq!(events, [ProviderEvent::Failed(expected)]);
    assert_terminal_failure_without_canary(events, expected, canary);
}

fn assert_terminal_failure_without_canary(
    events: &[ProviderEvent],
    expected: ProviderFailure,
    canary: &str,
) {
    assert_eq!(events.last(), Some(&ProviderEvent::Failed(expected)));
    assert_single_terminal(events, false);
    assert!(!format!("{events:?}").contains(canary));
}

fn insert_unknown_utf8_extension(trace: &[u8]) -> Vec<u8> {
    let marker = b"event: message_stop\n";
    let offset = trace
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("recorded message_stop event");
    let extension = concat!(
        "event: future_extension\n",
        "data: {\"type\":\"future_extension\",\"opaque\":\"雪\"}\n\n",
    );
    let mut output = Vec::with_capacity(trace.len() + extension.len());
    output.extend_from_slice(&trace[..offset]);
    output.extend_from_slice(extension.as_bytes());
    output.extend_from_slice(&trace[offset..]);
    output
}

fn replace_exact_once(input: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    assert_eq!(
        input
            .windows(old.len())
            .filter(|window| *window == old)
            .count(),
        1
    );
    let offset = input
        .windows(old.len())
        .position(|window| window == old)
        .expect("negative mutation marker");
    let mut output = Vec::with_capacity(input.len() - old.len() + new.len());
    output.extend_from_slice(&input[..offset]);
    output.extend_from_slice(new);
    output.extend_from_slice(&input[offset + old.len()..]);
    output
}

async fn replay(
    case: ReplayCase,
    body: &[u8],
    chunk_sizes: &[usize],
    response: ResponseSpec,
) -> Vec<ProviderEvent> {
    assert!(!chunk_sizes.is_empty());
    assert!(chunk_sizes.iter().all(|size| *size > 0));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind offline replay server");
    let address = listener.local_addr().expect("offline replay address");
    let body = body.to_vec();
    let chunk_sizes = chunk_sizes.to_vec();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept replay request");
        let request = read_http_request(&mut stream).await;
        assert_anthropic_request(&request, case);
        write_chunked_response(&mut stream, &body, &chunk_sizes, response).await;
    });

    let config = AnthropicProviderConfig::new_with_transport_policy(
        Url::parse(&format!("http://{address}/v1/messages")).expect("replay URL"),
        case.model.to_owned(),
        AnthropicApiKey::from_bytes(API_KEY.as_bytes().to_vec()).expect("offline API key"),
        SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).expect("HTTP budget"),
        Some(Duration::from_secs(2)),
        SchemePolicy::HttpOrHttps,
    )
    .expect("offline provider config");
    assert!(!format!("{config:?}").contains(API_KEY));
    let adapter = AnthropicProvider::new(
        config,
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("loopback allowlist"),
        )),
    );
    let mut session = adapter
        .start(provider_request(case))
        .await
        .expect("start production Anthropic adapter");

    let mut events = Vec::new();
    while let Some(event) = session
        .next_event()
        .await
        .expect("read normalized provider event")
    {
        events.push(event);
    }
    server.await.expect("offline replay server");
    events
}

fn provider_request(case: ReplayCase) -> ProviderRequest {
    let tools = match case.tool_name {
        Some(name) => vec![ProviderToolDefinition {
            name: name.to_owned(),
            description: "Offline fixture weather tool.".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "city":{"type":"string"},
                    "units":{"type":"string","enum":["celsius","fahrenheit"]}
                },
                "required":["city"],
                "additionalProperties":false
            }),
        }],
        None => Vec::new(),
    };

    ProviderRequest {
        route: openbot_application::ProviderRoute::Managed,
        messages: vec![ProviderMessage {
            role: ProviderMessageRole::User,
            content: "offline Anthropic recorded fixture replay".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }],
        tools,
        max_output_tokens: Some(512),
        rate_card: None,
        cost_cap: None,
    }
}

fn assert_anthropic_request(request: &[u8], case: ReplayCase) {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("request header separator");
    let headers = core::str::from_utf8(&request[..header_end]).expect("request headers are UTF-8");
    let body = &request[header_end..];
    assert!(headers.starts_with("POST /v1/messages HTTP/1.1\r\n"));

    let lower_headers = headers.to_ascii_lowercase();
    assert_eq!(
        lower_headers
            .lines()
            .filter(|line| line.starts_with("x-api-key:"))
            .count(),
        1
    );
    assert!(lower_headers.contains(&format!("x-api-key: {API_KEY}")));
    assert_eq!(headers.matches(API_KEY).count(), 1);
    assert!(!lower_headers.contains("authorization:"));
    assert!(lower_headers.contains("anthropic-version: 2023-06-01"));
    assert!(lower_headers.contains("content-type: application/json"));
    assert!(lower_headers.contains("accept: text/event-stream, application/json"));
    assert!(
        !core::str::from_utf8(body)
            .expect("request body is UTF-8")
            .contains(API_KEY)
    );

    let request_body: Value = serde_json::from_slice(body).expect("request body is JSON");
    assert_eq!(request_body["model"], case.model);
    assert_eq!(request_body["stream"], true);
    assert_eq!(request_body["max_tokens"], 512);
    assert_eq!(
        request_body["messages"][0]["content"][0]["text"],
        "offline Anthropic recorded fixture replay"
    );
    match case.tool_name {
        Some(name) => assert_eq!(request_body["tools"][0]["name"], name),
        None => assert!(request_body.get("tools").is_none()),
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .await
            .expect("read request headers");
        assert_ne!(count, 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 64 * 1024, "request headers are bounded");
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = core::str::from_utf8(&bytes[..header_end]).expect("request headers are UTF-8");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.parse::<usize>().ok())
        })
        .expect("request content length");
    assert!(content_length <= 64 * 1024, "request body is bounded");
    while bytes.len() < header_end + content_length {
        let count = stream.read(&mut buffer).await.expect("read request body");
        assert_ne!(count, 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    bytes
}

async fn write_chunked_response(
    stream: &mut TcpStream,
    body: &[u8],
    chunk_sizes: &[usize],
    response: ResponseSpec,
) {
    let headers = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        response.status_line, response.content_type
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write replay response headers");
    let mut offset = 0;
    let mut chunk_index = 0;
    while offset < body.len() {
        let requested_size = chunk_sizes[chunk_index % chunk_sizes.len()];
        let chunk_end = offset.saturating_add(requested_size).min(body.len());
        let mut chunk_frame = format!("{:x}\r\n", chunk_end - offset).into_bytes();
        chunk_frame.extend_from_slice(&body[offset..chunk_end]);
        chunk_frame.extend_from_slice(b"\r\n");
        stream
            .write_all(&chunk_frame)
            .await
            .expect("write replay response chunk");
        offset = chunk_end;
        chunk_index += 1;
    }
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .expect("finish replay response");
}
