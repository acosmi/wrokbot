//! SDK 5 request/stream deltas exercised through the existing production transport and owned TLS.

use super::*;

fn sdk5_openai_text_usage_done() -> String {
    [
        format!(
            "data: {}\n\n",
            json!({
                "id": "chat-sdk5",
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant", "content": "hello sdk5"},
                    "finish_reason": null
                }]
            })
        ),
        format!(
            "data: {}\n\n",
            json!({
                "id": "chat-sdk5",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            })
        ),
        format!(
            "data: {}\n\n",
            json!({
                "id": "chat-sdk5",
                "object": "chat.completion.chunk",
                "choices": [],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
            })
        ),
        "data: [DONE]\n\n".to_owned(),
    ]
    .concat()
}

fn sdk5_openai_finish_then_failed() -> String {
    [
        format!(
            "data: {}\n\n",
            json!({
                "id": "chat-sdk5-failed",
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {"content": "visible before failure"},
                    "finish_reason": null
                }]
            })
        ),
        format!(
            "data: {}\n\n",
            json!({
                "id": "chat-sdk5-failed",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            })
        ),
        "event: failed\n".to_owned(),
        format!(
            "data: {}\n\n",
            json!({
                "errorCode": "settlement_failed",
                "stage": "settlement",
                "message": "post-finish gateway failure",
                "retryable": false
            })
        ),
    ]
    .concat()
}

async fn messages_events(client: &Client) -> Vec<acosmi::Result<acosmi::StreamEvent>> {
    let stream = client.chat_messages_stream_with_options(
        "qa-model",
        &request(),
        None,
        acosmi::ChatOptions::default(),
    );
    futures_util::pin_mut!(stream);
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn sdk5_openai_stream_adds_only_include_usage_and_delivers_usage_tail() {
    let fixture = TlsFixture::new(vec![
        ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi)),
        ResponsePlan::ok(sdk5_openai_text_usage_done()),
    ])
    .await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let client = client(
        &fixture,
        transport(
            &fixture,
            GatewayModelWire::OpenAi,
            fence.clone(),
            outcomes.clone(),
            64 * 1024,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;

    let events = messages_events(&client).await;
    assert!(events.iter().all(Result::is_ok));
    let events: Vec<_> = events.into_iter().map(Result::unwrap).collect();
    assert_eq!(
        events.last().map(|event| event.event.as_str()),
        Some("message_stop")
    );
    assert!(events.iter().any(|event| {
        event.event == "content_block_delta"
            && serde_json::from_str::<Value>(&event.data).is_ok_and(|data| {
                data["delta"]["type"] == "text_delta" && data["delta"]["text"] == "hello sdk5"
            })
    }));
    let usage = events
        .iter()
        .find(|event| event.event == "message_delta")
        .map(|event| serde_json::from_str::<Value>(&event.data).unwrap())
        .expect("SDK5 must emit one message_delta before message_stop");
    assert_eq!(usage["delta"]["stop_reason"], "end_turn");
    assert_eq!(usage["usage"]["input_tokens"], 2);
    assert_eq!(usage["usage"]["output_tokens"], 3);

    assert_eq!(fixture.count(), 2);
    let captures = fixture.captures.lock().unwrap().clone();
    let body: Value = serde_json::from_slice(&captures[1].body).unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"], json!({"include_usage": true}));
    let mut keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["max_tokens", "messages", "stream", "stream_options"]
            .map(str::to_owned)
            .to_vec(),
        "SDK5 must not invent extra_body/thinking/effort/reasoning fields"
    );
    drop(captures);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
    let snapshots = outcomes.snapshots();
    assert_eq!(snapshots.len(), 2);
    assert!(snapshots[0].may_have_sent());
    assert_eq!(snapshots[0].response_status(), Some(200));
    assert!(snapshots[0].permit_released());
    assert!(snapshots[0].complete());
    assert_eq!(snapshots[0].failure(), None);
    assert!(snapshots[1].may_have_sent());
    assert_eq!(snapshots[1].response_status(), Some(200));
    assert!(snapshots[1].permit_released());
    assert!(!snapshots[1].complete());
    assert_eq!(snapshots[1].failure(), Some(GatewayFailure::Cancelled));
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn sdk5_finish_then_gateway_failed_is_an_explicit_stream_error() {
    let fixture = TlsFixture::new(vec![
        ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi)),
        ResponsePlan::ok(sdk5_openai_finish_then_failed()),
    ])
    .await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let client = client(
        &fixture,
        transport(
            &fixture,
            GatewayModelWire::OpenAi,
            fence.clone(),
            outcomes,
            64 * 1024,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;

    let events = messages_events(&client).await;
    let successful: Vec<_> = events
        .iter()
        .filter_map(|event| event.as_ref().ok())
        .collect();
    assert!(successful.iter().any(|event| {
        event.event == "content_block_delta" && event.data.contains("visible before failure")
    }));
    assert!(successful.iter().all(|event| event.event != "message_stop"));
    let errors: Vec<_> = events.into_iter().filter_map(Result::err).collect();
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        acosmi::Error::Stream(error) => {
            assert_eq!(error.code, "settlement_failed");
            assert_eq!(error.stage, "settlement");
            assert_eq!(error.user_message, "post-finish gateway failure");
            assert!(!error.retryable);
        }
        other => panic!("expected explicit SDK5 stream error, got {other:?}"),
    }
    assert_eq!(fixture.count(), 2);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
    fixture.stop().await;
}
