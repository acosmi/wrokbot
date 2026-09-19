//! Account metadata/profile protocol through the production fenced transport and owned TLS.

use super::*;
use openbot_domain::vault::SecretBytes;
use openbot_infra::gateway_account::{GatewayAccountClient, GatewayAccountError};

const ACCOUNT_ID: &str = "ACCOUNT_ID_MARKER";
const ACCESS_TOKEN: &[u8] = b"ACCESS_TOKEN_MARKER";

fn json_plan(body: String) -> ResponsePlan {
    let mut plan = ResponsePlan::ok(body);
    plan.content_type = "application/json";
    plan
}

fn metadata_value() -> Value {
    json!({
        "issuer": "OWNED_ORIGIN",
        "authorization_endpoint": "OWNED_ORIGIN/oauth/desktop/authorize",
        "token_endpoint": "OWNED_ORIGIN/oauth/desktop/token",
        "registration_endpoint": "OWNED_ORIGIN/oauth/desktop/register",
        "revocation_endpoint": "OWNED_ORIGIN/oauth/desktop/revoke",
        "scopes_supported": ["ai", "account"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "crabcode_auth_contract_version": 2,
        "gateway_error_contract_version": 1,
        "ignored_extension": "METADATA_EXTENSION_MARKER"
    })
}

fn metadata_body() -> String {
    metadata_value().to_string()
}

fn profile_body(account: &str, organization: &str) -> String {
    json!({
        "id": account,
        "uuid": account,
        "account": {"uuid": account, "email": "PROFILE_EMAIL_MARKER"},
        "organization": {"uuid": organization},
        "name": "PROFILE_NAME_MARKER"
    })
    .to_string()
}

fn account_transport(
    fixture: &TlsFixture,
    account_profile: bool,
    fence: Arc<Fence>,
    outcomes: Arc<Outcomes>,
) -> Arc<dyn acosmi::HttpTransport> {
    account_transport_with_limit(fixture, account_profile, fence, outcomes, 64 * 1024)
}

fn account_transport_with_limit(
    fixture: &TlsFixture,
    account_profile: bool,
    fence: Arc<Fence>,
    outcomes: Arc<Outcomes>,
    response_bytes: usize,
) -> Arc<dyn acosmi::HttpTransport> {
    let base = fixture.endpoint();
    let oauth = GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Desktop,
        &format!("{base}/oauth/desktop/register"),
        &format!("{base}/oauth/desktop/token"),
        Some(&format!("{base}/oauth/desktop/revoke")),
    )
    .unwrap();
    let endpoints = VerifiedGatewayEndpoints::new(&base, None, Some(oauth)).unwrap();
    let endpoints = if account_profile {
        endpoints.with_account_profile().unwrap()
    } else {
        endpoints
    };
    GatewayTransportFactory::new(
        fixture.dialer_with(false, true),
        endpoints,
        GatewayTransportLimits::new(Duration::from_secs(10), response_bytes).unwrap(),
    )
    .for_operation(
        fence,
        outcomes,
        Instant::now() + Duration::from_secs(15),
        Duration::from_millis(250),
    )
    .unwrap()
}

fn raw_profile(base: &str) -> acosmi::HttpRequest {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer ACCESS_TOKEN_MARKER"),
    );
    headers.insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );
    acosmi::HttpRequest {
        method: http::Method::GET,
        url: format!("{base}/api/oauth/profile").parse().unwrap(),
        headers,
        body: Vec::new(),
        context: acosmi::HttpContext::buffered(acosmi::HttpPurpose::Api, 10_000),
    }
}

async fn metadata_and_profile_error(profile: ResponsePlan, expected: GatewayAccountError) {
    let fixture = TlsFixture::new(vec![json_plan(metadata_body()), profile]).await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let transport = account_transport(&fixture, true, fence.clone(), outcomes.clone());
    let client = GatewayAccountClient::new(&fixture.endpoint(), transport).unwrap();
    let metadata = client
        .fetch_metadata(CancellationToken::new())
        .await
        .unwrap();
    let token = SecretBytes::new(ACCESS_TOKEN.to_vec());
    let error = client
        .fetch_profile(&metadata, &token, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error, expected);
    let debug = format!("{error:?}");
    for marker in ["ACCOUNT_ID_MARKER", "PROFILE_", "ACCESS_TOKEN_MARKER"] {
        assert!(!debug.contains(marker));
    }
    assert_eq!(fixture.count(), 2);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    let snapshots = outcomes.snapshots();
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|attempt| attempt.response_status().is_some())
    );
    assert!(snapshots.iter().all(|attempt| attempt.permit_released()));
    fixture.stop().await;
}

#[tokio::test]
async fn account_profile_is_opt_in_and_bad_frames_stop_before_fence_and_socket() {
    let fixture = TlsFixture::new(Vec::new()).await;
    let base = fixture.endpoint();
    assert!(
        VerifiedGatewayEndpoints::new(&base, None, None)
            .unwrap()
            .with_account_profile()
            .is_err()
    );
    let web = GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Web,
        &format!("{base}/oauth/web/register"),
        &format!("{base}/oauth/web/token"),
        Some(&format!("{base}/oauth/web/revoke")),
    )
    .unwrap();
    assert!(
        VerifiedGatewayEndpoints::new(&base, None, Some(web))
            .unwrap()
            .with_account_profile()
            .is_err()
    );
    let old_fence = Arc::new(Fence::default());
    let old_outcomes = Arc::new(Outcomes::default());
    let old = account_transport(&fixture, false, old_fence.clone(), old_outcomes.clone());
    assert!(
        old.execute(raw_profile(&fixture.endpoint()), CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(old_fence.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.count(), 0);
    assert_eq!(
        old_outcomes.snapshots()[0].failure(),
        Some(GatewayFailure::InvalidRequest)
    );

    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let transport = account_transport(&fixture, true, fence.clone(), outcomes.clone());
    for mode in 0..6 {
        let mut request = raw_profile(&fixture.endpoint());
        match mode {
            0 => request.url.set_query(Some("unexpected=1")),
            1 => request.method = http::Method::POST,
            2 => {
                request.headers.remove(http::header::AUTHORIZATION);
            }
            3 => request.context.response_mode = acosmi::HttpResponseMode::Streaming,
            4 => {
                request.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
            }
            _ => request.body = b"{}".to_vec(),
        }
        assert!(
            transport
                .execute(request, CancellationToken::new())
                .await
                .is_err()
        );
    }
    assert_eq!(fence.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.count(), 0);
    assert_eq!(outcomes.snapshots().len(), 6);
    assert!(
        outcomes
            .snapshots()
            .iter()
            .all(|attempt| attempt.failure() == Some(GatewayFailure::InvalidRequest))
    );
    for bad_base in [
        "http://idp.test",
        "https://user@idp.test",
        "https://idp.test/not-api",
        "https://idp.test/api/v4?query=1",
        "https://idp.test/api/v4#fragment",
    ] {
        assert!(GatewayAccountClient::new(bad_base, transport.clone()).is_err());
    }
    fixture.stop().await;
}

#[tokio::test]
async fn account_metadata_and_profile_positive_path_is_exact_and_redacted() {
    let fixture = TlsFixture::new(vec![json_plan(metadata_body()), {
        let mut plan = json_plan(profile_body(ACCOUNT_ID, ""));
        plan.content_type = "application/json; charset=utf-8";
        plan
    }])
    .await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let transport = account_transport(&fixture, true, fence.clone(), outcomes.clone());
    let client =
        GatewayAccountClient::new(&format!("{}/api/v4/", fixture.endpoint()), transport).unwrap();
    let metadata = client
        .fetch_metadata(CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(metadata.sdk_metadata().issuer, fixture.endpoint());
    assert_eq!(
        metadata.sdk_metadata().authorization_endpoint,
        format!("{}/oauth/desktop/authorize", fixture.endpoint())
    );
    assert_eq!(
        metadata.sdk_metadata().token_endpoint,
        format!("{}/oauth/desktop/token", fixture.endpoint())
    );
    assert!(
        metadata
            .sdk_metadata()
            .scopes_supported
            .iter()
            .any(|s| s == "ai")
    );
    assert!(
        metadata
            .sdk_metadata()
            .scopes_supported
            .iter()
            .any(|s| s == "account")
    );
    assert!(!format!("{metadata:?}").contains("METADATA_EXTENSION_MARKER"));

    for bytes in [Vec::new(), b"TOKEN WITH SPACE".to_vec(), vec![0xff]] {
        let invalid_token = SecretBytes::new(bytes);
        assert_eq!(
            client
                .fetch_profile(&metadata, &invalid_token, CancellationToken::new())
                .await
                .unwrap_err(),
            GatewayAccountError::Configuration
        );
    }
    assert_eq!(fixture.count(), 1);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 1);

    let token = SecretBytes::new(ACCESS_TOKEN.to_vec());
    let identity = client
        .fetch_profile(&metadata, &token, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(identity.issuer(), fixture.endpoint());
    assert_eq!(identity.account_id(), ACCOUNT_ID);
    assert_eq!(identity.organization_id(), None);
    let debug = format!("{identity:?}");
    for marker in [ACCOUNT_ID, "PROFILE_", "ACCESS_TOKEN_MARKER"] {
        assert!(!debug.contains(marker));
    }

    let captures = fixture.captures.lock().unwrap().clone();
    assert_eq!(captures.len(), 2);
    assert_eq!(
        captures[0].path,
        "/.well-known/oauth-authorization-server/desktop"
    );
    assert_eq!(captures[0].method, "GET");
    assert!(captures[0].body.is_empty());
    assert_eq!(
        captures[0].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert!(!captures[0].headers.contains_key("authorization"));
    assert!(!captures[0].headers.contains_key("content-type"));
    assert_eq!(captures[1].path, "/api/oauth/profile");
    assert_eq!(captures[1].method, "GET");
    assert!(captures[1].body.is_empty());
    assert_eq!(
        captures[1].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        captures[1].headers.get("authorization").map(String::as_str),
        Some("Bearer ACCESS_TOKEN_MARKER")
    );
    assert!(!captures[1].headers.contains_key("content-type"));
    drop(captures);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    assert!(
        outcomes
            .snapshots()
            .iter()
            .all(|attempt| attempt.complete())
    );
    fixture.stop().await;
}

#[tokio::test]
async fn account_metadata_rejects_missing_drift_duplicate_and_incomplete_contracts() {
    let mut missing = metadata_value();
    missing
        .as_object_mut()
        .unwrap()
        .remove("gateway_error_contract_version");
    let mut version = metadata_value();
    version["crabcode_auth_contract_version"] = json!(3);
    let mut endpoint = metadata_value();
    endpoint["token_endpoint"] = json!("OWNED_ORIGIN/oauth/desktop/other");
    let mut scope = metadata_value();
    scope["scopes_supported"] = json!(["ai"]);
    let mut too_many = metadata_value();
    let mut scopes = vec!["ai".to_owned(), "account".to_owned()];
    scopes.extend((0..63).map(|index| format!("extra-{index}")));
    too_many["scopes_supported"] = json!(scopes);
    let duplicate =
        metadata_body().replacen("\"issuer\":", "\"issuer\":\"OWNED_ORIGIN\",\"issuer\":", 1);
    for body in [
        missing.to_string(),
        version.to_string(),
        endpoint.to_string(),
        scope.to_string(),
        too_many.to_string(),
        duplicate,
    ] {
        let fixture = TlsFixture::new(vec![json_plan(body)]).await;
        let fence = Arc::new(Fence::default());
        let outcomes = Arc::new(Outcomes::default());
        let transport = account_transport(&fixture, true, fence.clone(), outcomes.clone());
        let client = GatewayAccountClient::new(&fixture.endpoint(), transport).unwrap();
        let error = client
            .fetch_metadata(CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error, GatewayAccountError::MetadataInvalid);
        assert!(!format!("{error:?}").contains("METADATA_EXTENSION_MARKER"));
        assert_eq!(fixture.count(), 1);
        assert_eq!(fence.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fence.releases.load(Ordering::SeqCst), 1);
        assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
        assert!(outcomes.snapshots()[0].complete());
        fixture.stop().await;
    }
}

#[tokio::test]
async fn account_profile_route_keeps_64k_response_cap_when_host_allows_more() {
    let oversized = json!({
        "id": ACCOUNT_ID,
        "uuid": ACCOUNT_ID,
        "account": {"uuid": ACCOUNT_ID},
        "organization": {"uuid": "org"},
        "padding": "OVERSIZE_RESPONSE_MARKER".repeat(3_000)
    })
    .to_string();
    assert!(oversized.len() > 64 * 1024);
    let fixture = TlsFixture::new(vec![json_plan(metadata_body()), json_plan(oversized)]).await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let transport =
        account_transport_with_limit(&fixture, true, fence.clone(), outcomes.clone(), 1024 * 1024);
    let client = GatewayAccountClient::new(&fixture.endpoint(), transport).unwrap();
    let metadata = client
        .fetch_metadata(CancellationToken::new())
        .await
        .unwrap();
    let token = SecretBytes::new(ACCESS_TOKEN.to_vec());
    let error = client
        .fetch_profile(&metadata, &token, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error, GatewayAccountError::Transport);
    assert!(!format!("{error:?}").contains("OVERSIZE_RESPONSE_MARKER"));
    assert_eq!(fixture.count(), 2);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 1);
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    let snapshots = outcomes.snapshots();
    assert_eq!(snapshots.len(), 2);
    assert!(snapshots[0].complete());
    assert!(snapshots[1].may_have_sent());
    assert_eq!(snapshots[1].response_status(), None);
    assert!(!snapshots[1].permit_released());
    assert!(!snapshots[1].complete());
    assert_eq!(snapshots[1].failure(), Some(GatewayFailure::Body));
    fixture.stop().await;
}

#[tokio::test]
async fn account_profile_rejects_identity_shape_content_and_status_failures() {
    let mismatch = json!({
        "id": ACCOUNT_ID,
        "uuid": "OTHER_ACCOUNT",
        "account": {"uuid": ACCOUNT_ID},
        "organization": {"uuid": "org"}
    })
    .to_string();
    let bad_id = profile_body(" ACCOUNT_ID_MARKER ", "org");
    let duplicate = format!(
        "{{\"id\":\"{ACCOUNT_ID}\",\"uuid\":\"{ACCOUNT_ID}\",\"uuid\":\"{ACCOUNT_ID}\",\"account\":{{\"uuid\":\"{ACCOUNT_ID}\"}},\"organization\":{{\"uuid\":\"org\"}}}}"
    );
    let oversized = profile_body(&"x".repeat(257), "org");
    let missing_organization = json!({
        "id": ACCOUNT_ID,
        "uuid": ACCOUNT_ID,
        "account": {"uuid": ACCOUNT_ID}
    })
    .to_string();
    let null_organization = json!({
        "id": ACCOUNT_ID,
        "uuid": ACCOUNT_ID,
        "account": {"uuid": ACCOUNT_ID},
        "organization": null
    })
    .to_string();
    let missing_organization_uuid = json!({
        "id": ACCOUNT_ID,
        "uuid": ACCOUNT_ID,
        "account": {"uuid": ACCOUNT_ID},
        "organization": {}
    })
    .to_string();
    for (body, expected) in [
        (mismatch, GatewayAccountError::ProfileInvalid),
        (bad_id, GatewayAccountError::ProfileInvalid),
        (duplicate, GatewayAccountError::ProfileInvalid),
        (oversized, GatewayAccountError::ProfileInvalid),
        (missing_organization, GatewayAccountError::ProfileInvalid),
        (null_organization, GatewayAccountError::ProfileInvalid),
        (
            missing_organization_uuid,
            GatewayAccountError::ProfileInvalid,
        ),
        (
            "PROFILE_NON_JSON_MARKER".to_owned(),
            GatewayAccountError::ProfileInvalid,
        ),
    ] {
        metadata_and_profile_error(json_plan(body), expected).await;
    }

    let mut duplicate_content_type = json_plan(profile_body(ACCOUNT_ID, "org"));
    duplicate_content_type.extra_headers = "Content-Type: application/json\r\n".to_owned();
    metadata_and_profile_error(duplicate_content_type, GatewayAccountError::ContentType).await;

    let mut unauthorized = json_plan(profile_body(ACCOUNT_ID, "org"));
    unauthorized.status = 401;
    metadata_and_profile_error(unauthorized, GatewayAccountError::HttpStatus(401)).await;
}

#[tokio::test]
async fn account_profile_does_not_follow_redirect_and_cancellation_closes_exact_body() {
    let target = TlsFixture::new(Vec::new()).await;
    let mut redirect = json_plan(profile_body(ACCOUNT_ID, "org"));
    redirect.status = 302;
    redirect.location = Some(format!("{}/profile-leak", target.endpoint()));
    metadata_and_profile_error(redirect, GatewayAccountError::HttpStatus(302)).await;
    assert_eq!(target.count(), 0);
    target.stop().await;

    let gate = Arc::new(Semaphore::new(0));
    let mut blocked = json_plan(profile_body(ACCOUNT_ID, "org"));
    blocked.body_gate = Some(gate);
    let fixture = TlsFixture::new(vec![json_plan(metadata_body()), blocked]).await;
    let fence = Arc::new(Fence::default());
    let outcomes = Arc::new(Outcomes::default());
    let transport = account_transport(&fixture, true, fence.clone(), outcomes.clone());
    let client = GatewayAccountClient::new(&fixture.endpoint(), transport).unwrap();
    let metadata = client
        .fetch_metadata(CancellationToken::new())
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let child_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let token = SecretBytes::new(ACCESS_TOKEN.to_vec());
        client.fetch_profile(&metadata, &token, child_cancel).await
    });
    fixture.wait_count(2).await;
    cancel.cancel();
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        GatewayAccountError::Cancelled
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.closed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    let snapshots = outcomes.snapshots();
    assert!(snapshots[0].complete());
    assert_eq!(snapshots[1].response_status(), Some(200));
    assert!(snapshots[1].permit_released());
    assert_eq!(snapshots[1].failure(), Some(GatewayFailure::Cancelled));
    fixture.stop().await;
}
