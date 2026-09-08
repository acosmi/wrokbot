//! Pinned RMCP 3.1.4 client over the repository's unique SafeDialer.
//!
//! RMCP owns MCP negotiation/JSON-RPC/session semantics. This adapter supplies the HTTP backend so
//! DNS, redirect, peer binding, TLS, credential stripping, body limits and real read-gap watchdogs
//! remain identical to every other external protocol in the product. RMCP/reqwest is not enabled.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{StreamExt as _, stream};
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue, WWW_AUTHENTICATE};
use http::{HeaderMap, StatusCode};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CancelledNotificationParam, ClientCapabilities,
    ClientInfo, ClientJsonRpcMessage, ClientRequest, ContentBlock, Implementation,
    ListToolsRequest, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ServerJsonRpcMessage, ServerResult,
};
use rmcp::service::PeerRequestOptions;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::common::client_side_sse::NeverRetry;
use rmcp::transport::streamable_http_client::{
    AuthRequiredError, InsufficientScopeError, SseError, StreamableHttpClient,
    StreamableHttpClientTransportConfig, StreamableHttpError, StreamableHttpPostResponse,
};
use rmcp::{ClientLifecycleMode, ClientServiceExt as _, RoleClient};
use serde_json::Value;
use sse_stream::{Sse, SseStream};
use url::Url;
use zeroize::Zeroizing;

use openbot_application::ToolExecutionCancellation;
use openbot_domain::audit::hash::Sha256Digest;

use crate::net::safe_http::{
    AuthorizationValue, CidrAllowlist, EgressPolicy, McpHttpMethod, SafeDialer, SafeHttpBudget,
    SafeHttpError, SafeHttpRequest, SafeHttpStreamResponse, SchemePolicy,
};

/// Parity timeout for `tools/list`.
pub const MCP_LIST_TIMEOUT: Duration = Duration::from_secs(15);
/// Parity timeout for `tools/call`.
pub const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Added hardening: maximum tools accepted from one server.
pub const MAX_MCP_TOOLS: usize = 1_000;
/// Added hardening: description bytes per tool.
pub const MAX_MCP_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
/// Added hardening: serialized input-schema bytes per tool.
pub const MAX_MCP_INPUT_SCHEMA_BYTES: usize = 256 * 1024;
/// Parity model-visible result cap, counted as Unicode scalar values in Rust.
pub const MAX_MCP_RESULT_CHARS: usize = 20_000;
/// Per-event SSE cap supplied to RMCP's transport.
pub const MAX_MCP_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_MCP_INIT_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_MCP_CALL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MCP_LIST_RESPONSE_BYTES: usize = 264 * 1024 * 1024;
const MAX_MCP_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MCP_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Stable MCP adapter failure. Remote URL/body/header/error text never crosses this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpClientError {
    /// Safe transport/DNS/TLS/session unavailable.
    #[error("mcp_transport_unavailable")]
    Transport,
    /// List/call wall-clock deadline exceeded.
    #[error("mcp_timeout")]
    Timeout,
    /// `tools/call` may have crossed the transport boundary, but no trustworthy outcome arrived.
    #[error("mcp_commit_unknown")]
    CommitUnknown,
    /// The run was cancelled before the vendor `tools/call` request was sent.
    #[error("mcp_cancelled_before_call")]
    CancelledBeforeCall,
    /// The vendor call was sent and a protocol cancellation was transmitted; commit is unknown.
    #[error("mcp_cancelled_after_call")]
    CancelledAfterCall,
    /// The vendor call was sent but transport-aware cancellation could not be confirmed.
    #[error("mcp_cancel_signal_unknown")]
    CancelSignalUnknown,
    /// Server lacks tools capability or returned an invalid/oversized catalog.
    #[error("mcp_catalog_invalid")]
    InvalidCatalog,
    /// Requested tool disappeared from the fresh listing.
    #[error("mcp_tool_missing")]
    ToolMissing,
    /// Requested tool still exists but its live schema no longer matches the reviewed catalog.
    #[error("mcp_catalog_changed")]
    CatalogChanged,
    /// Resource server returned an OAuth Bearer 401 challenge.
    #[error("mcp_auth_required")]
    AuthRequired,
    /// Resource server returned an OAuth insufficient-scope 403 challenge.
    #[error("mcp_insufficient_scope")]
    InsufficientScope,
    /// Protocol result could not be safely normalized.
    #[error("mcp_result_invalid")]
    InvalidResult,
}

/// One validated remote tool definition. Untrusted annotations are deliberately absent.
#[derive(Clone, PartialEq)]
pub struct McpListedTool {
    /// Vendor tool name.
    pub name: String,
    /// Missing description normalizes to empty string.
    pub description: String,
    /// Exact vendor input schema object.
    pub input_schema: Value,
}

impl core::fmt::Debug for McpListedTool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("McpListedTool")
            .field("name", &self.name)
            .field("description_bytes", &self.description.len())
            .field(
                "input_schema_bytes",
                &serde_json::to_vec(&self.input_schema).map_or(usize::MAX, |value| value.len()),
            )
            .finish()
    }
}

/// Normalized model-visible MCP outcome.
#[derive(Clone, PartialEq, Eq)]
pub struct McpCallOutcome {
    /// Bounded result text.
    pub text: String,
    /// Server reported a tool-level error; transport errors never become this value.
    pub is_error: bool,
    /// Result was visibly truncated.
    pub truncated: bool,
}

impl core::fmt::Debug for McpCallOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("McpCallOutcome")
            .field("text_chars", &self.text.chars().count())
            .field("is_error", &self.is_error)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Optional bearer credential; Clone shares one zeroizing allocation.
#[derive(Clone)]
pub struct McpBearerToken(Arc<openbot_domain::vault::SecretBytes>);

impl McpBearerToken {
    /// Construct from an already decrypted vendor token.
    pub fn new(token: String) -> Result<Self, McpClientError> {
        Self::from_secret(openbot_domain::vault::SecretBytes::new(token.into_bytes()))
    }

    /// Take ownership of an already-zeroizing credential without creating a plaintext String copy.
    pub(crate) fn from_secret(
        token: openbot_domain::vault::SecretBytes,
    ) -> Result<Self, McpClientError> {
        if token.is_empty() || token.len() > 16 * 1024 || token.expose().contains(&0) {
            return Err(McpClientError::Transport);
        }
        core::str::from_utf8(token.expose()).map_err(|_| McpClientError::Transport)?;
        Ok(Self(Arc::new(token)))
    }

    pub(crate) fn expose_for_vendor(&self) -> Result<&str, McpClientError> {
        core::str::from_utf8(self.0.expose()).map_err(|_| McpClientError::Transport)
    }
}

impl core::fmt::Debug for McpBearerToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("McpBearerToken([redacted])")
    }
}

/// Per-operation RMCP client factory. Every listing/call creates, initializes, uses, and closes a
/// distinct MCP service; no actor/Bot/session pooling exists.
#[derive(Clone, Debug)]
pub struct SafeRmcpClient {
    dialer: SafeDialer,
    scheme_policy: SchemePolicy,
    stall_timeout: Option<Duration>,
}

impl SafeRmcpClient {
    /// Construct from explicit safe egress/scheme/stall policy.
    #[must_use]
    pub const fn new(
        dialer: SafeDialer,
        scheme_policy: SchemePolicy,
        stall_timeout: Option<Duration>,
    ) -> Self {
        Self {
            dialer,
            scheme_policy,
            stall_timeout,
        }
    }

    /// Bind one server operation to its administrator-authorized exact CIDR set. The base client's
    /// resolver/TLS material is retained, so deterministic tests and production share one path.
    #[must_use]
    pub(crate) fn with_egress_allowlist(&self, allowlist: CidrAllowlist) -> Self {
        Self {
            dialer: self.dialer.with_egress_policy(EgressPolicy::new(allowlist)),
            scheme_policy: self.scheme_policy,
            stall_timeout: self.stall_timeout,
        }
    }

    /// Initialize, paginate `tools/list`, validate all limits, and close the session.
    pub async fn list_tools(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
    ) -> Result<Vec<McpListedTool>, McpClientError> {
        let mut client = self.connect(endpoint, bearer, None).await?;
        let result = list_all_tools(&client, None).await;
        let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
        result
    }

    /// Per-call initialize → fresh list membership check → tools/call → close.
    pub async fn call_tool(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
        tool_name: &str,
        arguments: Value,
    ) -> Result<McpCallOutcome, McpClientError> {
        self.call_tool_inner(endpoint, bearer, tool_name, None, arguments, None)
            .await
    }

    /// Per-call execution bound to the exact schema hash reviewed in the current grant.
    pub async fn call_tool_bound(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
        tool_name: &str,
        expected_schema_hash: Sha256Digest,
        arguments: Value,
    ) -> Result<McpCallOutcome, McpClientError> {
        self.call_tool_inner(
            endpoint,
            bearer,
            tool_name,
            Some(expected_schema_hash),
            arguments,
            None,
        )
        .await
    }

    /// Execute one schema-bound call with a private Rust-host cancellation receiver.
    ///
    /// Once sent, the adapter applies the negotiated transport's cancellation rule: modern
    /// `2026-07-28` closes the request-scoped response stream, while legacy fallback uses
    /// `notifications/cancelled` with the exact request ID.
    pub async fn call_tool_bound_cancellable(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
        tool_name: &str,
        expected_schema_hash: Sha256Digest,
        arguments: Value,
        cancellation: ToolExecutionCancellation,
    ) -> Result<McpCallOutcome, McpClientError> {
        self.call_tool_inner(
            endpoint,
            bearer,
            tool_name,
            Some(expected_schema_hash),
            arguments,
            Some(cancellation),
        )
        .await
    }

    async fn call_tool_inner(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
        tool_name: &str,
        expected_schema_hash: Option<Sha256Digest>,
        arguments: Value,
        mut cancellation: Option<ToolExecutionCancellation>,
    ) -> Result<McpCallOutcome, McpClientError> {
        if cancellation
            .as_ref()
            .and_then(ToolExecutionCancellation::requested)
            .is_some()
        {
            return Err(McpClientError::CancelledBeforeCall);
        }
        if tool_name.is_empty()
            || tool_name.len() > 512
            || tool_name.as_bytes().contains(&0)
            || !arguments.is_object()
        {
            return Err(McpClientError::InvalidCatalog);
        }
        let arguments = arguments
            .as_object()
            .cloned()
            .ok_or(McpClientError::InvalidCatalog)?;
        let mut client = self.connect(endpoint, bearer, cancellation.clone()).await?;
        let tools = match list_all_tools(&client, cancellation.as_mut()).await {
            Ok(tools) => tools,
            Err(error) => {
                let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
                return Err(error);
            }
        };
        let Some(live_tool) = tools.iter().find(|tool| tool.name == tool_name) else {
            let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
            return Err(McpClientError::ToolMissing);
        };
        if expected_schema_hash.is_some_and(|expected| {
            serde_json::to_vec(&live_tool.input_schema)
                .map(|bytes| Sha256Digest::of(&bytes) != expected)
                .unwrap_or(true)
        }) {
            let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
            return Err(McpClientError::CatalogChanged);
        }
        if cancellation
            .as_ref()
            .and_then(ToolExecutionCancellation::requested)
            .is_some()
        {
            let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
            return Err(McpClientError::CancelledBeforeCall);
        }
        // From this await onward, a transport error or timeout cannot prove the vendor did not
        // receive a non-idempotent call. Keep that fact distinct from pre-call list/connect errors.
        let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(arguments);
        let request = ClientRequest::CallToolRequest(CallToolRequest::new(params));
        let options = PeerRequestOptions::with_timeout(MCP_CALL_TIMEOUT)
            .reset_timeout_on_progress()
            .with_max_total_timeout(MCP_CALL_TIMEOUT);
        let result = match client
            .peer()
            .send_cancellable_request(request, options)
            .await
        {
            Ok(handle) => {
                let request_id = handle.id.clone();
                let peer = handle.peer.clone();
                match cancellation.as_mut() {
                    Some(cancellation) => {
                        let response = handle.await_response();
                        tokio::pin!(response);
                        tokio::select! {
                            biased;
                            response = &mut response => map_call_response(response),
                            reason = cancellation.cancelled() => {
                                match peer.notify_cancelled(CancelledNotificationParam::new(
                                    Some(request_id),
                                    Some(reason.stable_code().to_owned()),
                                )).await {
                                    Ok(()) => Err(McpClientError::CancelledAfterCall),
                                    Err(_) => Err(McpClientError::CancelSignalUnknown),
                                }
                            }
                        }
                    }
                    None => map_call_response(handle.await_response().await),
                }
            }
            Err(error) => Err(map_service_error(error)),
        };
        let _ = client.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
        result
    }

    async fn connect(
        &self,
        endpoint: &str,
        bearer: Option<McpBearerToken>,
        cancellation: Option<ToolExecutionCancellation>,
    ) -> Result<RunningRmcpClient, McpClientError> {
        let url = Url::parse(endpoint).map_err(|_| McpClientError::Transport)?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(McpClientError::Transport);
        }
        let http = SafeRmcpHttpClient {
            dialer: self.dialer.clone(),
            scheme_policy: self.scheme_policy,
            stall_timeout: self.stall_timeout,
            bearer,
            cancellation,
        };
        let mut config = StreamableHttpClientTransportConfig::with_uri(endpoint.to_owned());
        config.retry_config = Arc::new(NeverRetry::default());
        config.allow_stateless = true;
        config.reinit_on_expired_session = false;
        config.max_sse_event_size = MAX_MCP_SSE_EVENT_BYTES;
        let transport = StreamableHttpClientTransport::with_client(http, config);
        let client_info = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("openbot-rs", env!("CARGO_PKG_VERSION")),
        );
        let lifecycle = ClientLifecycleMode::Auto {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            legacy_version: Some(ProtocolVersion::V_2025_11_25),
        };
        tokio::time::timeout(
            MCP_LIST_TIMEOUT,
            client_info.serve_with_lifecycle(transport, lifecycle),
        )
        .await
        .map_err(|_| McpClientError::Timeout)?
        .map_err(map_initialize_error)
    }
}

fn map_call_response(
    response: Result<ServerResult, rmcp::service::ServiceError>,
) -> Result<McpCallOutcome, McpClientError> {
    match response {
        Ok(ServerResult::CallToolResult(result)) => {
            normalize_result(&result.content, result.is_error == Some(true))
                .map_err(|_| McpClientError::CommitUnknown)
        }
        Ok(_) => Err(McpClientError::CommitUnknown),
        Err(error) => match map_service_error(error) {
            McpClientError::AuthRequired => Err(McpClientError::AuthRequired),
            McpClientError::InsufficientScope => Err(McpClientError::InsufficientScope),
            _ => Err(McpClientError::CommitUnknown),
        },
    }
}

type RunningRmcpClient = rmcp::service::RunningService<RoleClient, ClientInfo>;

async fn list_all_tools(
    client: &RunningRmcpClient,
    mut cancellation: Option<&mut ToolExecutionCancellation>,
) -> Result<Vec<McpListedTool>, McpClientError> {
    if client
        .peer_info()
        .as_ref()
        .is_none_or(|info| info.capabilities.tools.is_none())
    {
        return Err(McpClientError::InvalidCatalog);
    }
    let mut cursor = None;
    let mut output = Vec::new();
    let mut names = BTreeSet::new();
    let deadline = tokio::time::Instant::now() + MCP_LIST_TIMEOUT;
    loop {
        if cancellation
            .as_deref()
            .and_then(ToolExecutionCancellation::requested)
            .is_some()
        {
            return Err(McpClientError::CancelledBeforeCall);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(McpClientError::Timeout);
        }
        let params = cursor
            .clone()
            .map(|value| PaginatedRequestParams::default().with_cursor(Some(value)));
        let request = ClientRequest::ListToolsRequest(ListToolsRequest {
            method: Default::default(),
            params,
            extensions: Default::default(),
        });
        let options = PeerRequestOptions::with_timeout(remaining).with_max_total_timeout(remaining);
        let handle = client
            .peer()
            .send_cancellable_request(request, options)
            .await
            .map_err(map_service_error)?;
        let page = await_list_response(handle, cancellation.as_deref_mut()).await?;
        for tool in page.tools {
            if output.len() >= MAX_MCP_TOOLS {
                return Err(McpClientError::InvalidCatalog);
            }
            let name = tool.name.into_owned();
            let description = tool.description.map_or_else(String::new, Cow::into_owned);
            let input_schema = Value::Object((*tool.input_schema).clone());
            if name.is_empty()
                || name.len() > 512
                || name.as_bytes().contains(&0)
                || description.len() > MAX_MCP_TOOL_DESCRIPTION_BYTES
                || description.as_bytes().contains(&0)
                || serde_json::to_vec(&input_schema)
                    .map_err(|_| McpClientError::InvalidCatalog)?
                    .len()
                    > MAX_MCP_INPUT_SCHEMA_BYTES
                || !names.insert(name.clone())
            {
                return Err(McpClientError::InvalidCatalog);
            }
            output.push(McpListedTool {
                name,
                description,
                input_schema,
            });
        }
        match page.next_cursor {
            Some(next) if !next.is_empty() && cursor.as_deref() != Some(next.as_str()) => {
                cursor = Some(next);
            }
            Some(_) => return Err(McpClientError::InvalidCatalog),
            None => break,
        }
    }
    Ok(output)
}

async fn await_list_response(
    handle: rmcp::service::RequestHandle<RoleClient>,
    cancellation: Option<&mut ToolExecutionCancellation>,
) -> Result<ListToolsResult, McpClientError> {
    let response = match cancellation {
        Some(cancellation) => {
            let request_id = handle.id.clone();
            let peer = handle.peer.clone();
            let response = handle.await_response();
            tokio::pin!(response);
            tokio::select! {
                biased;
                response = &mut response => response,
                reason = cancellation.cancelled() => {
                    if peer.notify_cancelled(CancelledNotificationParam::new(
                        Some(request_id),
                        Some(reason.stable_code().to_owned()),
                    )).await.is_err() {
                        tracing::warn!(
                            code = "mcp_list_cancel_signal_unknown",
                            "RMCP tools/list transport cancellation could not be confirmed"
                        );
                    }
                    return Err(McpClientError::CancelledBeforeCall);
                }
            }
        }
        None => handle.await_response().await,
    };
    match response {
        Ok(ServerResult::ListToolsResult(page)) => Ok(page),
        Ok(_) => Err(McpClientError::InvalidCatalog),
        Err(rmcp::service::ServiceError::Timeout { .. }) => Err(McpClientError::Timeout),
        Err(error) => Err(map_service_error(error)),
    }
}

fn map_service_error(error: rmcp::service::ServiceError) -> McpClientError {
    if let rmcp::service::ServiceError::TransportSend(dynamic) = &error
        && let Some(error) = dynamic
            .error
            .downcast_ref::<StreamableHttpError<SafeRmcpHttpError>>()
    {
        return match error {
            StreamableHttpError::AuthRequired(_) => McpClientError::AuthRequired,
            StreamableHttpError::InsufficientScope(_) => McpClientError::InsufficientScope,
            StreamableHttpError::Client(SafeRmcpHttpError::CancelledBeforeCall) => {
                McpClientError::CancelledBeforeCall
            }
            StreamableHttpError::Client(SafeRmcpHttpError::CancelledAfterCall) => {
                McpClientError::CancelledAfterCall
            }
            _ => McpClientError::Transport,
        };
    }
    McpClientError::Transport
}

fn map_initialize_error(error: rmcp::service::ClientInitializeError) -> McpClientError {
    if error.auth_challenge().is_some_and(|challenge| {
        challenge
            .to_ascii_lowercase()
            .contains("insufficient_scope")
    }) {
        McpClientError::InsufficientScope
    } else if error.is_authorization_required() {
        McpClientError::AuthRequired
    } else {
        McpClientError::Transport
    }
}

/// Pure model-visible projection of RMCP content blocks.
pub fn normalize_result(
    content: &[ContentBlock],
    is_error: bool,
) -> Result<McpCallOutcome, McpClientError> {
    let mut parts = Vec::with_capacity(content.len());
    for item in content {
        let value = match item {
            ContentBlock::Text(text) => text.text.clone(),
            ContentBlock::Image(_) => "[image]".to_owned(),
            ContentBlock::Audio(_) => "[audio]".to_owned(),
            ContentBlock::Resource(_) => "[resource]".to_owned(),
            ContentBlock::ResourceLink(_) => "[resource_link]".to_owned(),
            _ => "[unknown]".to_owned(),
        };
        parts.push(value);
    }
    let joined = parts.join("\n");
    if joined.trim().is_empty() {
        return Ok(McpCallOutcome {
            text: "The tool returned no content. Nothing was found, so there is nothing here to answer from."
                .to_owned(),
            is_error,
            truncated: false,
        });
    }
    let count = joined.chars().count();
    if count <= MAX_MCP_RESULT_CHARS {
        return Ok(McpCallOutcome {
            text: joined,
            is_error,
            truncated: false,
        });
    }
    let prefix = joined
        .chars()
        .take(MAX_MCP_RESULT_CHARS)
        .collect::<String>();
    Ok(McpCallOutcome {
        text: format!("{prefix}\n\n[truncated: the tool returned {count} characters]"),
        is_error,
        truncated: true,
    })
}

#[derive(Clone)]
struct SafeRmcpHttpClient {
    dialer: SafeDialer,
    scheme_policy: SchemePolicy,
    stall_timeout: Option<Duration>,
    bearer: Option<McpBearerToken>,
    cancellation: Option<ToolExecutionCancellation>,
}

impl core::fmt::Debug for SafeRmcpHttpClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SafeRmcpHttpClient")
            .field("dialer", &self.dialer)
            .field("scheme_policy", &self.scheme_policy)
            .field("stall_timeout", &self.stall_timeout)
            .field("bearer", &self.bearer.is_some())
            .field("cancellable", &self.cancellation.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum SafeRmcpHttpError {
    #[error("safe_rmcp_http")]
    Transport,
    #[error("safe_rmcp_sse_event_too_large")]
    EventTooLarge,
    #[error("safe_rmcp_cancelled_before_call")]
    CancelledBeforeCall,
    #[error("safe_rmcp_cancelled_after_call")]
    CancelledAfterCall,
}

impl SafeRmcpHttpClient {
    fn authorization(
        &self,
        unexpected: Option<String>,
    ) -> Result<Option<AuthorizationValue>, SafeRmcpHttpError> {
        if unexpected.is_some() {
            return Err(SafeRmcpHttpError::Transport);
        }
        let Some(token) = &self.bearer else {
            return Ok(None);
        };
        let token = token
            .expose_for_vendor()
            .map_err(|_| SafeRmcpHttpError::Transport)?;
        let mut value = Zeroizing::new(String::with_capacity(token.len() + 7));
        value.push_str("Bearer ");
        value.push_str(token);
        AuthorizationValue::parse(value.as_str())
            .map(Some)
            .map_err(|_| SafeRmcpHttpError::Transport)
    }

    fn headers(
        &self,
        mut custom: HashMap<HeaderName, HeaderValue>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
    ) -> Result<HeaderMap, SafeRmcpHttpError> {
        let mut headers = HeaderMap::new();
        for (name, value) in custom.drain() {
            headers.insert(name, value);
        }
        if let Some(session_id) = session_id {
            headers.insert(
                HeaderName::from_static("mcp-session-id"),
                HeaderValue::from_str(session_id.as_ref())
                    .map_err(|_| SafeRmcpHttpError::Transport)?,
            );
        }
        if let Some(last_event_id) = last_event_id {
            headers.insert(
                HeaderName::from_static("last-event-id"),
                HeaderValue::from_str(&last_event_id).map_err(|_| SafeRmcpHttpError::Transport)?,
            );
        }
        Ok(headers)
    }

    fn budget(&self, message: &ClientJsonRpcMessage) -> Result<SafeHttpBudget, SafeRmcpHttpError> {
        let value = serde_json::to_value(message).map_err(|_| SafeRmcpHttpError::Transport)?;
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (bytes, timeout) = match method {
            "tools/list" => (MAX_MCP_LIST_RESPONSE_BYTES, MCP_LIST_TIMEOUT),
            "tools/call" => (MAX_MCP_CALL_RESPONSE_BYTES, MCP_CALL_TIMEOUT),
            _ => (MAX_MCP_INIT_RESPONSE_BYTES, MCP_LIST_TIMEOUT),
        };
        SafeHttpBudget::new(bytes, timeout).map_err(|_| SafeRmcpHttpError::Transport)
    }

    fn cancellation_error(
        &self,
        message: &ClientJsonRpcMessage,
        custom_headers: &HashMap<HeaderName, HeaderValue>,
    ) -> Result<Option<SafeRmcpHttpError>, SafeRmcpHttpError> {
        let is_modern_streamable_http = custom_headers
            .get(&HeaderName::from_static("mcp-protocol-version"))
            .and_then(|value| value.to_str().ok())
            == Some(ProtocolVersion::V_2026_07_28.as_str());
        if self.cancellation.is_none() || !is_modern_streamable_http {
            return Ok(None);
        }
        let value = serde_json::to_value(message).map_err(|_| SafeRmcpHttpError::Transport)?;
        Ok(match value.get("method").and_then(Value::as_str) {
            Some("tools/list") => Some(SafeRmcpHttpError::CancelledBeforeCall),
            // Starting the transport future is the conservative external-effect boundary.
            Some("tools/call") => Some(SafeRmcpHttpError::CancelledAfterCall),
            // Never cancel negotiation, lifecycle notifications, or session cleanup.
            _ => None,
        })
    }

    async fn post(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<SafeRmcpHttpError>> {
        let url = Url::parse(uri.as_ref())
            .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let body = serde_json::to_vec(&message)?;
        let budget = self.budget(&message).map_err(StreamableHttpError::Client)?;
        let cancellation_error = self
            .cancellation_error(&message, &custom_headers)
            .map_err(StreamableHttpError::Client)?;
        let had_session = session_id.is_some();
        let headers = self
            .headers(custom_headers, session_id, None)
            .map_err(StreamableHttpError::Client)?;
        let request = SafeHttpRequest::mcp(
            url,
            self.scheme_policy,
            McpHttpMethod::Post,
            body,
            self.authorization(auth_header)
                .map_err(StreamableHttpError::Client)?,
            headers,
            budget,
        )
        .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let execute = self.dialer.execute_stream(request);
        tokio::pin!(execute);
        let response = match (cancellation_error, self.cancellation.clone()) {
            (Some(error), Some(mut cancellation)) => {
                tokio::select! {
                    biased;
                    response = &mut execute => response.map_err(map_safe_http)?,
                    _ = cancellation.cancelled() => {
                        // Dropping the exact in-flight SafeDialer future closes this request's
                        // HTTP response stream. This is the 2026-07-28 Streamable HTTP cancel
                        // signal and also avoids rmcp 3.1.4's pre-first-event worker stall.
                        return Err(StreamableHttpError::Client(error));
                    }
                }
            }
            _ => execute.await.map_err(map_safe_http)?,
        };
        classify_auth(&response)?;
        let status = response.status();
        if matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT) {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if status == StatusCode::NOT_FOUND && had_session {
            return Err(StreamableHttpError::SessionExpired);
        }
        let content_type = content_type(&response);
        let session = response
            .header(&HeaderName::from_static("mcp-session-id"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if content_type.as_deref() == Some("text/event-stream") && status.is_success() {
            return Ok(StreamableHttpPostResponse::Sse(
                bounded_sse(response, self.stall_timeout, max_sse_event_size),
                session,
            ));
        }
        let bytes = read_all(response, self.stall_timeout)
            .await
            .map_err(StreamableHttpError::Client)?;
        if bytes.is_empty() && status.is_success() {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if content_type.as_deref() == Some("application/json") {
            if let Ok(message) = serde_json::from_slice::<ServerJsonRpcMessage>(&bytes) {
                return Ok(StreamableHttpPostResponse::Json(message, session));
            }
            if status.is_success() {
                return Ok(StreamableHttpPostResponse::Accepted);
            }
        }
        Err(StreamableHttpError::UnexpectedServerResponse(
            Cow::Borrowed("remote MCP HTTP response rejected"),
        ))
    }
}

impl StreamableHttpClient for SafeRmcpHttpClient {
    type Error = SafeRmcpHttpError;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.post(
            uri,
            message,
            session_id,
            auth_header,
            custom_headers,
            MAX_MCP_SSE_EVENT_BYTES,
        )
        .await
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.post(
            uri,
            message,
            session_id,
            auth_header,
            custom_headers,
            max_sse_event_size,
        )
        .await
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let url = Url::parse(uri.as_ref())
            .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let headers = self
            .headers(custom_headers, Some(session_id), None)
            .map_err(StreamableHttpError::Client)?;
        let request = SafeHttpRequest::mcp(
            url,
            self.scheme_policy,
            McpHttpMethod::Delete,
            Vec::new(),
            self.authorization(auth_header)
                .map_err(StreamableHttpError::Client)?,
            headers,
            SafeHttpBudget::new(64 * 1024, MCP_LIST_TIMEOUT)
                .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?,
        )
        .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let response = self.dialer.execute(request).await.map_err(map_safe_http)?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED || response.status().is_success() {
            Ok(())
        } else {
            Err(StreamableHttpError::UnexpectedServerResponse(
                Cow::Borrowed("remote MCP session delete rejected"),
            ))
        }
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        self.get_stream_with_max_sse_event_size(
            uri,
            session_id,
            last_event_id,
            auth_header,
            custom_headers,
            MAX_MCP_SSE_EVENT_BYTES,
        )
        .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        let url = Url::parse(uri.as_ref())
            .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let headers = self
            .headers(custom_headers, session_id, last_event_id)
            .map_err(StreamableHttpError::Client)?;
        let request = SafeHttpRequest::mcp(
            url,
            self.scheme_policy,
            McpHttpMethod::Get,
            Vec::new(),
            self.authorization(auth_header)
                .map_err(StreamableHttpError::Client)?,
            headers,
            SafeHttpBudget::new(MAX_MCP_STREAM_BYTES, MCP_LIST_TIMEOUT)
                .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?,
        )
        .map_err(|_| StreamableHttpError::Client(SafeRmcpHttpError::Transport))?;
        let response = self
            .dialer
            .execute_stream(request)
            .await
            .map_err(map_safe_http)?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        classify_auth(&response)?;
        if !response.status().is_success()
            || content_type(&response).as_deref() != Some("text/event-stream")
        {
            return Err(StreamableHttpError::UnexpectedContentType(content_type(
                &response,
            )));
        }
        Ok(bounded_sse(
            response,
            self.stall_timeout,
            max_sse_event_size,
        ))
    }
}

fn content_type(response: &SafeHttpStreamResponse) -> Option<String> {
    response
        .header(&CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
}

fn classify_auth(
    response: &SafeHttpStreamResponse,
) -> Result<(), StreamableHttpError<SafeRmcpHttpError>> {
    let challenge = response
        .header(&WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    match (response.status(), challenge) {
        (StatusCode::UNAUTHORIZED, Some(challenge)) => Err(StreamableHttpError::AuthRequired(
            AuthRequiredError::new(challenge),
        )),
        (StatusCode::FORBIDDEN, Some(challenge)) => {
            let scope = extract_scope(&challenge);
            Err(StreamableHttpError::InsufficientScope(
                InsufficientScopeError::new(challenge, scope),
            ))
        }
        _ => Ok(()),
    }
}

fn extract_scope(header: &str) -> Option<String> {
    let lower = header.to_ascii_lowercase();
    let start = lower.find("scope=")? + "scope=".len();
    let rest = &header[start..];
    if let Some(rest) = rest.strip_prefix('"') {
        return rest.find('"').map(|end| rest[..end].to_owned());
    }
    let end = rest
        .find(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .unwrap_or(rest.len());
    (end > 0).then(|| rest[..end].to_owned())
}

async fn read_all(
    mut response: SafeHttpStreamResponse,
    stall: Option<Duration>,
) -> Result<Vec<u8>, SafeRmcpHttpError> {
    let mut output = Vec::new();
    while let Some(chunk) = response
        .next_chunk(stall)
        .await
        .map_err(|_| SafeRmcpHttpError::Transport)?
    {
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

#[derive(Debug)]
struct SseLimitState {
    response: SafeHttpStreamResponse,
    stall: Option<Duration>,
    event_bytes: usize,
    line_bytes: usize,
    previous_cr: bool,
    max_event_bytes: usize,
}

impl SseLimitState {
    fn observe(&mut self, chunk: &[u8]) -> Result<(), SafeRmcpHttpError> {
        for byte in chunk {
            if self.previous_cr {
                self.previous_cr = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            self.event_bytes = self.event_bytes.saturating_add(1);
            if self.event_bytes > self.max_event_bytes {
                return Err(SafeRmcpHttpError::EventTooLarge);
            }
            match *byte {
                b'\r' => {
                    self.finish_line();
                    self.previous_cr = true;
                }
                b'\n' => self.finish_line(),
                _ => self.line_bytes = self.line_bytes.saturating_add(1),
            }
        }
        Ok(())
    }

    fn finish_line(&mut self) {
        if self.line_bytes == 0 {
            self.event_bytes = 0;
        }
        self.line_bytes = 0;
    }
}

fn bounded_sse(
    response: SafeHttpStreamResponse,
    stall: Option<Duration>,
    max_event_bytes: usize,
) -> futures_util::stream::BoxStream<'static, Result<Sse, SseError>> {
    let state = SseLimitState {
        response,
        stall,
        event_bytes: 0,
        line_bytes: 0,
        previous_cr: false,
        max_event_bytes,
    };
    let bytes = stream::unfold(state, |mut state| async move {
        match state.response.next_chunk(state.stall).await {
            Ok(Some(chunk)) => {
                let result = state.observe(&chunk).map(|()| chunk);
                Some((result, state))
            }
            Ok(None) => None,
            Err(_) => Some((Err(SafeRmcpHttpError::Transport), state)),
        }
    });
    SseStream::from_bytes_stream(bytes).boxed()
}

fn map_safe_http(error: SafeHttpError) -> StreamableHttpError<SafeRmcpHttpError> {
    tracing::debug!(code = %error, "MCP SafeDialer operation failed");
    StreamableHttpError::Client(SafeRmcpHttpError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_projection_handles_empty_mixed_non_text_and_unicode_scalar_truncation() {
        let empty = normalize_result(&[], false).unwrap();
        assert!(empty.text.to_ascii_lowercase().contains("no content"));
        assert!(empty.text.to_ascii_lowercase().contains("nothing"));
        assert!(!empty.truncated);

        let mixed = normalize_result(
            &[
                ContentBlock::text("here is the chart"),
                ContentBlock::image("AA==", "image/png"),
            ],
            false,
        )
        .unwrap();
        assert_eq!(mixed.text, "here is the chart\n[image]");
        assert!(!mixed.is_error);

        let scalar = "🦀".repeat(MAX_MCP_RESULT_CHARS + 1);
        let truncated = normalize_result(&[ContentBlock::text(scalar)], true).unwrap();
        assert!(truncated.truncated);
        assert!(truncated.is_error);
        assert!(truncated.text.contains("20001 characters"));
        assert_eq!(
            truncated.text.chars().take(MAX_MCP_RESULT_CHARS).count(),
            MAX_MCP_RESULT_CHARS
        );
    }

    #[test]
    fn bearer_and_result_debug_are_redacted() {
        let token = McpBearerToken::new("TOKEN-CANARY".to_owned()).unwrap();
        assert!(!format!("{token:?}").contains("TOKEN-CANARY"));
        let result = McpCallOutcome {
            text: "RESULT-CANARY".to_owned(),
            is_error: false,
            truncated: false,
        };
        assert!(!format!("{result:?}").contains("RESULT-CANARY"));
    }
}
