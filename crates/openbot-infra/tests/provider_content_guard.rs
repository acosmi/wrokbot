use std::time::Duration;

use openbot_application::{
    ProviderAdapter, ProviderMessage, ProviderMessageRole, ProviderPortError, ProviderRequest,
    ProviderRoute, ProviderToolDefinition,
};
use openbot_infra::{
    net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy},
    provider::{
        anthropic::{AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig},
        google::{GoogleApiKey, GoogleProvider, GoogleProviderConfig},
        openai::{OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig},
    },
};
use serde_json::json;
use tokio::net::TcpListener;
use url::Url;

fn request(secret: bool) -> ProviderRequest {
    ProviderRequest {
        route: ProviderRoute::PackageOpenAi,
        messages: vec![ProviderMessage {
            role: ProviderMessageRole::User,
            content: "Explain password rotation".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: vec![],
        }],
        tools: vec![ProviderToolDefinition {
            name: "password_help".into(),
            description: "Explain credentials".into(),
            input_schema: if secret {
                json!({"type":"object","properties":{"value":{"default":"SECRET-CANARY-schema"}}})
            } else {
                json!({"type":"object","properties":{"password":{"type":"string"}}})
            },
        }],
        max_output_tokens: Some(32),
        rate_card: None,
        cost_cap: None,
    }
}

fn adapters(endpoint: &Url, model: &str) -> Vec<Box<dyn ProviderAdapter>> {
    let dialer = || {
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
        ))
    };
    let budget = || SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap();
    let mut result: Vec<Box<dyn ProviderAdapter>> =
        [OpenAiProtocol::Responses, OpenAiProtocol::ChatCompletions]
            .into_iter()
            .map(|protocol| {
                Box::new(OpenAiProvider::new(
                    OpenAiProviderConfig::new_with_transport_policy(
                        endpoint.clone(),
                        model.into(),
                        protocol,
                        budget(),
                        None,
                        SchemePolicy::HttpOrHttps,
                    )
                    .unwrap(),
                    OpenAiApiKey::from_bytes(b"SECRET-CANARY-typed-auth".to_vec()).unwrap(),
                    dialer(),
                )) as Box<dyn ProviderAdapter>
            })
            .collect();
    result.push(Box::new(AnthropicProvider::new(
        AnthropicProviderConfig::new_with_transport_policy(
            endpoint.clone(),
            model.into(),
            AnthropicApiKey::from_bytes(b"SECRET-CANARY-typed-auth".to_vec()).unwrap(),
            budget(),
            None,
            SchemePolicy::HttpOrHttps,
        )
        .unwrap(),
        dialer(),
    )));
    let mut google_endpoint = endpoint.clone();
    google_endpoint.set_query(Some("alt=sse"));
    result.push(Box::new(GoogleProvider::new(
        GoogleProviderConfig::new_with_transport_policy(
            google_endpoint,
            model.into(),
            GoogleApiKey::from_bytes(b"SECRET-CANARY-typed-auth".to_vec()).unwrap(),
            budget(),
            None,
            SchemePolicy::HttpOrHttps,
        )
        .unwrap(),
        dialer(),
    )));
    result
}

#[tokio::test]
async fn all_vendor_adapters_reject_business_secrets_without_opening_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        Url::parse(&format!("http://{}/stream", listener.local_addr().unwrap())).unwrap();
    for (model, input) in [
        ("test-model", request(true)),
        ("SECRET-CANARY-model", request(false)),
    ] {
        for adapter in adapters(&endpoint, model) {
            assert!(matches!(
                adapter.start(input.clone()).await,
                Err(ProviderPortError::InvalidRequest {
                    field: "content_secret"
                })
            ));
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn typed_authentication_and_credential_discussion_still_reach_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        Url::parse(&format!("http://{}/stream", listener.local_addr().unwrap())).unwrap();
    for adapter in adapters(&endpoint, "test-model") {
        let request = request(false);
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = adapter.start(request) => panic!("transport did not connect: {}", result.err().unwrap()),
                accepted = listener.accept() => { accepted.unwrap(); }
            }
        }).await;
        assert!(
            result.is_ok(),
            "allowed business input did not reach the loopback transport"
        );
    }
}
