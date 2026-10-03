//! Actual SDK/account requests forwarded into the production frame, with independent wire oracles.
use super::*;
use acosmi::{HttpPurpose, HttpRequest, HttpResponse, HttpTransport, TransportError};
use openbot_domain::vault::SecretBytes;
use openbot_infra::gateway_account::GatewayAccountClient;

#[path = "../support/provider_target_fixture.rs"]
mod provider_target_fixture;
use provider_target_fixture::{Counts, OwnedWire, Reply, WireRecord};

const MODEL_ID: &str = "qa/model +%?";
const ENCODED_MODEL_ID: &str = "qa%2Fmodel%20%2B%25%3F";

#[derive(Clone)]
struct Frame {
    method: http::Method,
    url: String,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Forwarded {
    original: Frame,
    actual: Frame,
}

struct Tap {
    inner: Arc<dyn HttpTransport>,
    purpose: HttpPurpose,
    replacement: Option<url::Url>,
    frames: Mutex<Vec<Forwarded>>,
    rewrites: AtomicUsize,
}

impl Tap {
    fn new(
        inner: Arc<dyn HttpTransport>,
        purpose: HttpPurpose,
        replacement: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            purpose,
            replacement: replacement.map(|value| url::Url::parse(&value).unwrap()),
            frames: Mutex::new(Vec::new()),
            rewrites: AtomicUsize::new(0),
        })
    }

    fn snapshot(&self) -> Vec<Forwarded> {
        self.frames.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for Tap {
    async fn execute(
        &self,
        mut request: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, TransportError> {
        let original = Frame {
            method: request.method.clone(),
            url: request.url.to_string(),
            body: request.body.clone(),
        };
        if request.context.purpose == self.purpose
            && let Some(target) = &self.replacement
        {
            request.url = target.clone();
            self.rewrites.fetch_add(1, Ordering::SeqCst);
        }
        let actual = Frame {
            method: request.method.clone(),
            url: request.url.to_string(),
            body: request.body.clone(),
        };
        self.frames
            .lock()
            .unwrap()
            .push(Forwarded { original, actual });
        self.inner.execute(request, cancel).await
    }
}

fn wire_certificate() -> [&'static str; 3] {
    [
        TEST_CA_DER_BASE64,
        TEST_LEAF_DER_BASE64,
        TEST_KEY_DER_BASE64,
    ]
}

fn gateway(
    wire: &OwnedWire,
    base: &str,
    model: Option<GatewayModelWire>,
    profile: bool,
    fence: Arc<Fence>,
    out: Arc<Outcomes>,
) -> Arc<dyn HttpTransport> {
    let origin = wire.origin();
    let oauth = GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Desktop,
        &format!("{origin}/oauth/desktop/register"),
        &format!("{origin}/oauth/desktop/token"),
        Some(&format!("{origin}/oauth/desktop/revoke")),
    )
    .unwrap();
    let endpoints =
        VerifiedGatewayEndpoints::new(base, model.map(|wire| (MODEL_ID, wire)), Some(oauth))
            .unwrap();
    let endpoints = if profile {
        endpoints.with_account_profile().unwrap()
    } else {
        endpoints
    };
    GatewayTransportFactory::new(
        wire.dialer(),
        endpoints,
        GatewayTransportLimits::new(Duration::from_secs(3), 64 * 1024).unwrap(),
    )
    .for_operation(
        fence,
        out,
        Instant::now() + Duration::from_secs(15),
        Duration::from_secs(2),
    )
    .unwrap()
}

fn sdk_catalogue(wire: GatewayModelWire) -> String {
    let mut value: Value = serde_json::from_str(&catalogue(wire)).unwrap();
    value["data"][0]["id"] = json!(MODEL_ID);
    value.to_string()
}

fn sdk_body(wire: GatewayModelWire) -> Vec<u8> {
    let mut value = json!({"messages":[{"role":"user","content":"owned test prompt"}],"max_tokens":32,"stream":true});
    if matches!(wire, GatewayModelWire::OpenAi) {
        value["stream_options"] = json!({"include_usage":true});
    }
    serde_json::to_vec(&value).unwrap()
}

async fn collect_sdk(c: &Client) -> Vec<bool> {
    let stream = c.chat_stream(MODEL_ID, &request(), None);
    futures_util::pin_mut!(stream);
    let mut result = Vec::new();
    while let Some(event) = stream.next().await {
        result.push(event.is_ok());
    }
    result
}

struct SdkCatalogueProof {
    creation_error_variant: Option<String>,
    catalogue_error_variant: Option<String>,
    ids: Vec<String>,
}

async fn catalogue_before_model(client: &acosmi::Result<Client>) -> SdkCatalogueProof {
    let mut proof = SdkCatalogueProof {
        creation_error_variant: client
            .as_ref()
            .err()
            .map(|error| format!("{:?}", std::mem::discriminant(error))),
        catalogue_error_variant: None,
        ids: vec![],
    };
    if let Ok(client) = client {
        // SDK5 creation reconciles authority without HTTP. Explicitly complete the actual
        // catalogue API/cache before observing the baseline for the following model request.
        match client.list_models(None, false).await {
            Ok(models) => proof.ids = models.into_iter().map(|model| model.id).collect(),
            Err(error) => {
                proof.catalogue_error_variant =
                    Some(format!("{:?}", std::mem::discriminant(&error)))
            }
        }
    }
    proof
}

fn assert_sdk_setup(
    proof: &SdkCatalogueProof,
    frames: &[Forwarded],
    out: &Outcomes,
    fence_baseline: usize,
    baseline: Counts,
) {
    // These are synthetic fixture URLs and bounded lengths. Never format SDK errors,
    // request headers, token authority contents or request bodies in diagnostics.
    let safe_frames: Vec<_> = frames
        .iter()
        .map(|frame| {
            (
                frame.original.method.as_str(),
                frame.original.url.as_str(),
                frame.actual.url.as_str(),
                frame.original.body.len(),
                frame.actual.body.len(),
            )
        })
        .collect();
    let safe_outcomes: Vec<_> = out
        .snapshots()
        .iter()
        .map(|attempt| {
            (
                attempt.failure(),
                attempt.may_have_sent(),
                attempt.permit_released(),
            )
        })
        .collect();
    println!(
        "SDK setup creation_error_variant={:?} catalogue_error_variant={:?} catalogue_ids={:?} baseline={baseline:?} fence_baseline={fence_baseline} frames={safe_frames:?} outcomes={safe_outcomes:?}",
        proof.creation_error_variant, proof.catalogue_error_variant, proof.ids
    );
    assert!(
        proof.creation_error_variant.is_none(),
        "actual SDK creation succeeded; see safe variant diagnostic"
    );
    assert!(
        proof.catalogue_error_variant.is_none(),
        "actual SDK catalogue succeeded; see safe variant diagnostic"
    );
    assert_eq!(
        proof.ids,
        vec![MODEL_ID.to_owned()],
        "actual SDK catalogue selected independently configured model"
    );
    assert_eq!(fence_baseline, 1);
}

fn assert_joined(record: &WireRecord) {
    assert_eq!(
        record.joined, record.counts.tcp,
        "all accepted sockets joined before assertions"
    );
    assert_eq!(record.failed, 0, "owned TLS children completed");
}

#[tokio::test]
async fn sdk_exact_full_targets_and_raw_bodies() {
    for protocol in [GatewayModelWire::OpenAi, GatewayModelWire::Anthropic] {
        for (base_suffix, api_prefix) in [
            ("", "/api/v4"),
            ("/owned-route", "/owned-route/api/v4"),
            ("/owned-route/api/v4", "/owned-route/api/v4"),
        ] {
            let wire = OwnedWire::new(
                vec![
                    Reply {
                        content_type: "application/json",
                        body: sdk_catalogue(protocol),
                    },
                    Reply {
                        content_type: "text/event-stream",
                        body: model_response(protocol),
                    },
                ],
                wire_certificate(),
            )
            .await;
            let origin = wire.origin();
            let base = format!("{origin}{base_suffix}");
            let fence = Arc::new(Fence::default());
            let out = Arc::new(Outcomes::default());
            let tap = Tap::new(
                gateway(
                    &wire,
                    &base,
                    Some(protocol),
                    false,
                    fence.clone(),
                    out.clone(),
                ),
                HttpPurpose::Model,
                None,
            );
            let client = Client::create_with_authority(
                config(&base),
                tap.clone(),
                Authority::new(&base, false),
                None,
            )
            .await;
            let setup = catalogue_before_model(&client).await;
            let baseline = wire.counts();
            let fence_baseline = fence.calls.load(Ordering::SeqCst);
            let event_results = if let Ok(client) = &client
                && setup.catalogue_error_variant.is_none()
            {
                collect_sdk(client).await
            } else {
                vec![]
            };
            drop(client);
            let frames = tap.snapshot();
            let record = wire.finish().await;
            // All listener/connection tasks have completed before any case verdict.
            assert_joined(&record);
            assert_sdk_setup(&setup, &frames, &out, fence_baseline, baseline);
            assert_eq!(
                baseline,
                Counts {
                    dns: 1,
                    tcp: 1,
                    http: 1
                }
            );
            assert!(!event_results.is_empty() && event_results.iter().all(|ok| *ok));
            assert_eq!(
                record.counts,
                Counts {
                    dns: 2,
                    tcp: 2,
                    http: 2
                }
            );
            assert_eq!(frames.len(), 2);
            let suffix = match protocol {
                GatewayModelWire::OpenAi => "chat",
                GatewayModelWire::Anthropic => "anthropic",
            };
            let catalogue_target = format!("{api_prefix}/managed-models");
            let selected_target =
                format!("{api_prefix}/managed-models/{ENCODED_MODEL_ID}/{suffix}");
            assert_eq!(
                frames[0].original.url,
                format!("{origin}{catalogue_target}")
            );
            assert_eq!(frames[1].original.url, format!("{origin}{selected_target}"));
            for (index, target) in [catalogue_target, selected_target].into_iter().enumerate() {
                let actual = &record.requests[index];
                let frame = &frames[index];
                assert_eq!(frame.original.url, frame.actual.url);
                assert_eq!(frame.original.method, frame.actual.method);
                assert_eq!(frame.original.body, frame.actual.body);
                assert_eq!(actual.target, target);
                assert_eq!(actual.method, if index == 0 { "GET" } else { "POST" });
                assert_eq!(actual.method, frame.actual.method.as_str());
                assert_eq!(
                    actual.body, frame.actual.body,
                    "same actual SDK bytes reach TLS"
                );
                assert_eq!(
                    actual.headers["host"],
                    origin.trim_start_matches("https://")
                );
                assert_eq!(actual.header_counts["authorization"], 1);
                assert_eq!(actual.headers["authorization"], "Bearer QA_FAKE_ACCESS");
            }
            assert!(record.requests[0].body.is_empty());
            assert_eq!(
                record.requests[1].body,
                sdk_body(protocol),
                "independent typed input and SDK5 wire shape"
            );
            assert_eq!(record.requests[1].headers["accept"], "text/event-stream");
            assert_eq!(
                record.requests[1].headers["content-type"],
                "application/json"
            );
            assert_eq!(tap.rewrites.load(Ordering::SeqCst), 0);
            assert!(out.snapshots().iter().all(|a| a.permit_released()));
            println!(
                "SDK positive wire={protocol:?} base={base_suffix}: catalogue1 + model1; exact full target/method/raw body; TLS tasks joined"
            );
        }
    }
}

#[tokio::test]
async fn sdk_actual_model_target_drift_rejected_after_catalogue() {
    for protocol in [GatewayModelWire::OpenAi, GatewayModelWire::Anthropic] {
        for mode in 0..8 {
            let wire = OwnedWire::new(
                vec![Reply {
                    content_type: "application/json",
                    body: sdk_catalogue(protocol),
                }],
                wire_certificate(),
            )
            .await;
            let origin = wire.origin();
            let base = format!("{origin}/owned-route");
            let suffix = match protocol {
                GatewayModelWire::OpenAi => "chat",
                GatewayModelWire::Anthropic => "anthropic",
            };
            let selected = format!("{base}/api/v4/managed-models/{ENCODED_MODEL_ID}/{suffix}");
            let bad = match mode {
                0 => selected.replace("/owned-route/", "/shadow-route/"),
                1 => format!("{selected}/child"),
                2 => format!("{origin}/api/v4/managed-models/{ENCODED_MODEL_ID}/{suffix}"),
                3 => format!("{selected}?unexpected=1"),
                4 => format!("{selected}?"),
                5 => selected.replace("%2F", "%252F"),
                6 => selected.replace("%2F", "%2f"),
                _ => format!("{selected}/"),
            };
            let fence = Arc::new(Fence::default());
            let out = Arc::new(Outcomes::default());
            let tap = Tap::new(
                gateway(
                    &wire,
                    &base,
                    Some(protocol),
                    false,
                    fence.clone(),
                    out.clone(),
                ),
                HttpPurpose::Model,
                Some(bad.clone()),
            );
            let client = Client::create_with_authority(
                config(&base),
                tap.clone(),
                Authority::new(&base, false),
                None,
            )
            .await;
            let setup = catalogue_before_model(&client).await;
            let baseline = wire.counts();
            let fence_baseline = fence.calls.load(Ordering::SeqCst);
            let results = if let Ok(client) = &client
                && setup.catalogue_error_variant.is_none()
            {
                collect_sdk(client).await
            } else {
                vec![]
            };
            drop(client);
            let frames = tap.snapshot();
            let record = wire.finish().await;
            assert_joined(&record);
            assert_sdk_setup(&setup, &frames, &out, fence_baseline, baseline);
            assert_eq!(
                baseline,
                Counts {
                    dns: 1,
                    tcp: 1,
                    http: 1
                }
            );
            assert_eq!(fence_baseline, 1);
            assert_eq!(
                record.counts, baseline,
                "model rejection DNS/TCP/HTTP deltas0 after actual catalogue"
            );
            assert_eq!(fence.calls.load(Ordering::SeqCst), fence_baseline);
            assert_eq!(frames.len(), 2);
            assert_eq!(tap.rewrites.load(Ordering::SeqCst), 1);
            assert_eq!(frames[1].original.url, selected);
            assert_eq!(frames[1].actual.url, bad);
            assert_eq!(frames[1].original.method, http::Method::POST);
            assert_eq!(frames[1].actual.method, frames[1].original.method);
            assert_eq!(frames[1].actual.body, frames[1].original.body);
            assert_eq!(frames[1].actual.body, sdk_body(protocol));
            assert!(!results.is_empty() && results.iter().any(|ok| !*ok));
            let attempts = out.snapshots();
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[1].failure(), Some(GatewayFailure::InvalidRequest));
            assert!(!attempts[1].may_have_sent());
            println!(
                "SDK drift wire={protocol:?} mode={mode}: catalogue baseline1; model fence/DNS/TCP/HTTP delta0; injected exactly1; tasks joined"
            );
        }
    }
}

fn metadata() -> String {
    json!({"issuer":"OWNED_ORIGIN","authorization_endpoint":"OWNED_ORIGIN/oauth/desktop/authorize","token_endpoint":"OWNED_ORIGIN/oauth/desktop/token","registration_endpoint":"OWNED_ORIGIN/oauth/desktop/register","revocation_endpoint":"OWNED_ORIGIN/oauth/desktop/revoke","scopes_supported":["ai","account"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"grant_types_supported":["authorization_code","refresh_token"],"crabcode_auth_contract_version":2,"gateway_error_contract_version":1}).to_string()
}

#[tokio::test]
async fn account_actual_profile_target_drift_rejected_after_metadata() {
    for mode in 0..7 {
        let mut replies = vec![Reply {
            content_type: "application/json",
            body: metadata(),
        }];
        if mode == 0 {
            replies.push(Reply { content_type: "application/json", body: json!({"id":"target-account","uuid":"target-account","account":{"uuid":"target-account"},"organization":{"uuid":"target-org"}}).to_string() });
        }
        let wire = OwnedWire::new(replies, wire_certificate()).await;
        let origin = wire.origin();
        let selected = format!("{origin}/api/oauth/profile");
        let replacement = match mode {
            0 => None,
            1 => Some(format!("{origin}/owned-prefix/api/oauth/profile")),
            2 => Some(format!("{selected}/child")),
            3 => Some(format!("{selected}-shadow")),
            4 => Some(format!("{origin}/api/profile")),
            5 => Some(format!("{selected}?unexpected=1")),
            _ => Some(format!("{selected}/")),
        };
        let fence = Arc::new(Fence::default());
        let out = Arc::new(Outcomes::default());
        let tap = Tap::new(
            gateway(&wire, &origin, None, true, fence.clone(), out.clone()),
            HttpPurpose::Api,
            replacement.clone(),
        );
        let client = GatewayAccountClient::new(&origin, tap.clone()).unwrap();
        let metadata = client.fetch_metadata(CancellationToken::new()).await;
        let baseline = wire.counts();
        let fence_baseline = fence.calls.load(Ordering::SeqCst);
        let identity = if let Ok(metadata) = &metadata {
            Some(
                client
                    .fetch_profile(
                        metadata,
                        &SecretBytes::new(b"TARGET_ACCOUNT_ACCESS".to_vec()),
                        CancellationToken::new(),
                    )
                    .await,
            )
        } else {
            None
        };
        let frames = tap.snapshot();
        let record = wire.finish().await;
        assert_joined(&record);
        assert!(metadata.is_ok());
        assert_eq!(
            baseline,
            Counts {
                dns: 1,
                tcp: 1,
                http: 1
            }
        );
        assert_eq!(fence_baseline, 1);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].original.url,
            format!("{origin}/.well-known/oauth-authorization-server/desktop")
        );
        assert_eq!(
            record.requests[0].target,
            "/.well-known/oauth-authorization-server/desktop"
        );
        assert_eq!(record.requests[0].method, "GET");
        assert!(record.requests[0].body.is_empty());
        assert_eq!(frames[1].original.url, selected);
        assert_eq!(frames[1].original.method, http::Method::GET);
        assert_eq!(frames[1].actual.method, http::Method::GET);
        assert!(frames[1].original.body.is_empty() && frames[1].actual.body.is_empty());
        let result = identity.unwrap();
        if let Some(bad) = replacement {
            assert!(result.is_err());
            assert_eq!(frames[1].actual.url, bad);
            assert_eq!(
                record.counts, baseline,
                "profile rejection DNS/TCP/HTTP deltas0 after metadata"
            );
            assert_eq!(fence.calls.load(Ordering::SeqCst), fence_baseline);
            assert_eq!(tap.rewrites.load(Ordering::SeqCst), 1);
            let attempts = out.snapshots();
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[1].failure(), Some(GatewayFailure::InvalidRequest));
            assert!(!attempts[1].may_have_sent());
        } else {
            let identity = result.unwrap();
            assert_eq!(identity.issuer(), origin);
            assert_eq!(identity.account_id(), "target-account");
            assert_eq!(identity.organization_id(), Some("target-org"));
            assert_eq!(
                record.counts,
                Counts {
                    dns: 2,
                    tcp: 2,
                    http: 2
                }
            );
            assert_eq!(frames[1].actual.url, selected);
            let profile = &record.requests[1];
            assert_eq!(profile.target, "/api/oauth/profile");
            assert_eq!(profile.method, "GET");
            assert_eq!(profile.body, frames[1].actual.body);
            assert!(profile.body.is_empty());
            assert_eq!(profile.header_counts["authorization"], 1);
            assert_eq!(profile.header_counts["accept"], 1);
            assert_eq!(
                profile.headers["authorization"],
                "Bearer TARGET_ACCOUNT_ACCESS"
            );
            assert_eq!(profile.headers["accept"], "application/json");
            assert_eq!(
                profile.headers["host"],
                origin.trim_start_matches("https://")
            );
            assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
            assert_eq!(tap.rewrites.load(Ordering::SeqCst), 0);
        }
        println!(
            "Account profile mode={mode}: metadata baseline1, profile exact positive or fence/DNS/TCP/HTTP rejection delta0; tasks joined"
        );
    }
}
