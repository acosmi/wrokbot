//! Offline replay of one OpenAI-published Responses API recorded session.

use std::time::Duration;

use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderMessage, ProviderMessageRole,
    ProviderOutputKind, ProviderRequest, ProviderToolDefinition, ProviderUsage,
};
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::provider::openai::{
    OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const TRACE: &[u8] =
    include_bytes!("../../../fixtures/provider/openai-responses-function-tool-stream.sse");
const PROVENANCE: &str = include_str!(
    "../../../fixtures/provider/openai-responses-function-tool-stream.provenance.json"
);
const TRACE_BYTES: usize = 9_070;
const TRACE_SHA256: &str = "fe38a7a044f8de33d441d0c9bf426e1291b1401bb9099ef419f62651b50d2927";
const SOURCE_COMMIT: &str = "19d0a3cb8e0cf0f3137a5c56c3c70a0c3f6c96f5";
const SOURCE_RECORD_BYTES: usize = 13_211;
const SOURCE_RECORD_BLOB_SHA1: &str = "3272bc4116a32b4472d21f68b41ce23ce363c02c";
const SOURCE_RECORD_SHA256: &str =
    "ff7fadb3baabc1fd1fc482fe9ec28ba93d5a899b961cce73bf19f8d9c1fe20b8";
const RESPONSE_ID: &str = "resp_0efaed9f1deaf0e9006a9351c0441c87d0b2a10bdeadce69d1";
const CALL_ID: &str = "call_qhXV6DQEZjbWPC51jqVwS4gh";
const TOOL_NAME: &str = "get_weather_at_location";
const ERROR_BODY_CANARY: &str = "OPENBOT_VENDOR_BODY_CANARY_8d892cb0";

#[tokio::test]
async fn openai_responses_recorded_trace_replays_through_production_adapter() {
    assert_fixture_identity_and_provenance();
    assert_fixture_has_no_secret_or_request_material();

    let expected = expected_events();
    let whole = replay(TRACE, &[TRACE.len()]).await;
    assert_eq!(whole, expected);
    assert!(!whole.iter().any(|event| matches!(
        event,
        ProviderEvent::TextDelta { .. } | ProviderEvent::ReasoningDelta { .. }
    )));

    let irregular = replay(TRACE, &[1, 2, 3, 5, 8, 13, 21, 34, 55, 89]).await;
    assert_eq!(irregular, expected);

    // This is a test-only mutation, not part of the recorded fixture: an unknown extension with a
    // multibyte scalar is inserted, then each HTTP body byte is framed separately. The production
    // SSE/Responses path must preserve the recorded normalized result across every byte boundary.
    let extended = insert_unknown_utf8_extension(TRACE);
    assert!(
        extended
            .windows("雪".len())
            .any(|bytes| bytes == "雪".as_bytes())
    );
    let bytewise = replay(&extended, &[1]).await;
    assert_eq!(bytewise, expected);

    let invalid = format!("data: {ERROR_BODY_CANARY}\n\n");
    let failed = replay(invalid.as_bytes(), &[1]).await;
    assert_eq!(
        failed,
        vec![ProviderEvent::Failed(ProviderFailure::InvalidResponse)]
    );
    assert!(!format!("{failed:?}").contains(ERROR_BODY_CANARY));
}

fn assert_fixture_identity_and_provenance() {
    assert_eq!(TRACE.len(), TRACE_BYTES);
    assert_eq!(format!("{:x}", Sha256::digest(TRACE)), TRACE_SHA256);
    assert!(
        TRACE.ends_with(b"\n\n"),
        "the exact vendor SSE body retains its terminal event delimiter"
    );

    let provenance: Value = serde_json::from_str(PROVENANCE).expect("valid provenance JSON");
    assert_eq!(provenance["schema"], "openbot-provider-recorded-trace-v1");
    assert_eq!(provenance["provider"], "openai");
    assert_eq!(provenance["protocol"]["api"], "Responses");
    assert_eq!(
        provenance["protocol"]["transport"],
        "HTTP/1.1 server-sent events"
    );
    assert_eq!(provenance["protocol"]["method"], "POST");
    assert_eq!(provenance["protocol"]["status_code"], 200);
    assert_eq!(
        provenance["protocol"]["endpoint"],
        "https://api.openai.com/v1/responses"
    );
    assert_eq!(provenance["protocol"]["openai_version"], "2020-10-01");
    assert_eq!(provenance["protocol"]["request_model"], "gpt-4o-mini");
    assert_eq!(
        provenance["protocol"]["response_model"],
        "gpt-4o-mini-2024-07-18"
    );
    assert_eq!(
        provenance["protocol"]["response_created_at_utc"],
        "2026-08-29T21:40:16Z"
    );
    assert_eq!(
        provenance["provenance"]["kind"],
        "vendor_capture_published_by_vendor"
    );
    assert_eq!(provenance["provenance"]["publisher"], "OpenAI");
    assert_eq!(
        provenance["provenance"]["repository"],
        "https://github.com/openai/openai-dotnet"
    );
    assert_eq!(provenance["provenance"]["source_commit"], SOURCE_COMMIT);
    assert_eq!(
        provenance["provenance"]["source_commit_time_utc"],
        "2026-09-02T18:33:36Z"
    );
    assert_eq!(
        provenance["provenance"]["source_record_git_blob_sha1"],
        SOURCE_RECORD_BLOB_SHA1
    );
    assert_eq!(
        provenance["provenance"]["source_record_bytes"],
        SOURCE_RECORD_BYTES
    );
    assert_eq!(
        provenance["provenance"]["source_record_sha256"],
        SOURCE_RECORD_SHA256
    );
    assert_eq!(
        provenance["provenance"]["retrieved_at_utc"],
        "2026-09-04T09:39:09Z"
    );
    assert_eq!(
        provenance["payload"]["path"],
        "fixtures/provider/openai-responses-function-tool-stream.sse"
    );
    assert_eq!(
        provenance["payload"]["raw_response_body_bytes"],
        TRACE_BYTES
    );
    assert_eq!(
        provenance["payload"]["raw_response_body_sha256"],
        TRACE_SHA256
    );
    assert_eq!(provenance["payload"]["fixture_bytes"], TRACE_BYTES);
    assert_eq!(provenance["payload"]["fixture_sha256"], TRACE_SHA256);
    assert_eq!(provenance["license"]["spdx"], "MIT");
    assert_eq!(
        provenance["license"]["copyright"],
        "Copyright (c) 2024 OpenAI (https://openai.com)"
    );

    let preserved = provenance["response_headers"]["preserved"]
        .as_object()
        .expect("preserved response headers object");
    assert_eq!(preserved.len(), 2);
    assert_eq!(
        preserved.get("content-type"),
        Some(&json!("text/event-stream; charset=utf-8"))
    );
    assert_eq!(preserved.get("openai-version"), Some(&json!("2020-10-01")));
    assert_eq!(
        provenance["redaction"]["request_prompt_stored"],
        Value::Bool(false)
    );
    assert_eq!(
        provenance["redaction"]["authorization_or_api_key_stored"],
        Value::Bool(false)
    );
    assert_eq!(
        provenance["redaction"]["customer_data_stored"],
        Value::Bool(false)
    );
    assert_eq!(
        provenance["redaction"]["verifiable_secret_hash_stored"],
        Value::Bool(false)
    );
}

fn assert_fixture_has_no_secret_or_request_material() {
    let trace = core::str::from_utf8(TRACE).expect("recorded trace is UTF-8 SSE");
    for forbidden in [
        "Authorization",
        "Bearer ",
        "OPENAI_API_KEY",
        "RequestBody",
        "RequestHeaders",
        "Variables",
        "api-key",
        "sk-",
        "input_text",
        "OPENBOT_CUSTOMER_DATA_CANARY_ea41d34f",
        "sk-openbot-fixture-secret-canary",
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
}

fn expected_events() -> Vec<ProviderEvent> {
    let mut events = vec![
        ProviderEvent::ResponseStarted {
            response_id: RESPONSE_ID.to_owned(),
        },
        ProviderEvent::OutputItemAdded {
            index: 0,
            kind: ProviderOutputKind::FunctionCall,
        },
        ProviderEvent::ToolCallStarted {
            index: 0,
            call_id: CALL_ID.to_owned(),
            name: Some(TOOL_NAME.to_owned()),
        },
    ];
    for delta in [
        "{\"",
        "location",
        "\":\"",
        "San",
        " Francisco",
        ",",
        " CA",
        "\",\"",
        "unit",
        "\":\"",
        "C",
        "\"}",
    ] {
        events.push(ProviderEvent::ToolArgumentsDelta {
            index: 0,
            call_id: CALL_ID.to_owned(),
            delta: delta.to_owned(),
        });
    }
    events.extend([
        ProviderEvent::ToolCallCompleted {
            index: 0,
            call_id: CALL_ID.to_owned(),
            name: TOOL_NAME.to_owned(),
            arguments: json!({"location":"San Francisco, CA","unit":"C"}),
        },
        ProviderEvent::Usage(ProviderUsage {
            input_tokens: 85,
            output_tokens: 13,
            total_tokens: 98,
        }),
        ProviderEvent::Completed,
    ]);
    events
}

fn insert_unknown_utf8_extension(trace: &[u8]) -> Vec<u8> {
    let marker = b"event: response.completed\n";
    let offset = trace
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("recorded completed event");
    let extension = concat!(
        "event: response.future_extension\n",
        "data: {\"type\":\"response.future_extension\",\"opaque\":\"雪\"}\n\n",
    );
    let mut output = Vec::with_capacity(trace.len() + extension.len());
    output.extend_from_slice(&trace[..offset]);
    output.extend_from_slice(extension.as_bytes());
    output.extend_from_slice(&trace[offset..]);
    output
}

async fn replay(body: &[u8], chunk_sizes: &[usize]) -> Vec<ProviderEvent> {
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
        assert!(request.starts_with(b"POST /v1/responses HTTP/1.1\r\n"));
        assert!(
            request
                .windows(b"authorization: Bearer fixture-only-not-a-secret".len())
                .any(|window| window == b"authorization: Bearer fixture-only-not-a-secret")
        );
        write_chunked_response(&mut stream, &body, &chunk_sizes).await;
    });

    let config = OpenAiProviderConfig::new_with_transport_policy(
        Url::parse(&format!("http://{address}/v1/responses")).expect("replay URL"),
        "gpt-4o-mini".to_owned(),
        OpenAiProtocol::Responses,
        SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).expect("HTTP budget"),
        Some(Duration::from_secs(2)),
        SchemePolicy::HttpOrHttps,
    )
    .expect("offline provider config");
    let adapter = OpenAiProvider::new(
        config,
        OpenAiApiKey::from_bytes(b"fixture-only-not-a-secret".to_vec()).expect("offline API key"),
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("loopback allowlist"),
        )),
    );
    let mut session = adapter
        .start(ProviderRequest {
            route: openbot_application::ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "offline fixture replay".to_owned(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            tools: vec![ProviderToolDefinition {
                name: TOOL_NAME.to_owned(),
                description: "Offline fixture tool.".to_owned(),
                input_schema: json!({
                    "type":"object",
                    "properties":{
                        "location":{"type":"string"},
                        "unit":{"type":"string","enum":["C","F","K"]}
                    },
                    "required":["location","unit"],
                    "additionalProperties":false
                }),
            }],
            max_output_tokens: Some(128),
            rate_card: None,
            cost_cap: None,
        })
        .await
        .expect("start production OpenAI adapter");

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

async fn write_chunked_response(stream: &mut TcpStream, body: &[u8], chunk_sizes: &[usize]) {
    stream
        .write_all(
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream; charset=utf-8\r\n",
                "openai-version: 2020-10-01\r\n",
                "Transfer-Encoding: chunked\r\n",
                "Connection: close\r\n\r\n",
            )
            .as_bytes(),
        )
        .await
        .expect("write replay response headers");
    let mut offset = 0;
    let mut chunk_index = 0;
    while offset < body.len() {
        let requested = chunk_sizes[chunk_index % chunk_sizes.len()];
        let end = offset.saturating_add(requested).min(body.len());
        let mut frame = format!("{:x}\r\n", end - offset).into_bytes();
        frame.extend_from_slice(&body[offset..end]);
        frame.extend_from_slice(b"\r\n");
        stream
            .write_all(&frame)
            .await
            .expect("write replay response chunk");
        offset = end;
        chunk_index += 1;
    }
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .expect("finish replay response");
}
