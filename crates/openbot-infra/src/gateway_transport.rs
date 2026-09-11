//! SDK4 HTTP framing through the unique SafeDialer, with mandatory per-request host authority.
//! This transport contains no token store, PostgreSQL authority or provider/Agent execution loop.

mod endpoints;
mod framing;
mod outcome;
use crate::net::safe_http::{SafeDialer, SafeHttpError, SafeHttpStreamResponse};
use acosmi::core::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use async_trait::async_trait;
pub use endpoints::{
    GatewayModelWire, GatewayOAuthEndpoints, GatewayOAuthProfile, VerifiedGatewayEndpoints,
};
use http::HeaderMap;
use outcome::AttemptGuard;
pub use outcome::{GatewayAttempt, GatewayAttemptSnapshot, GatewayFailure, GatewayHttpOutcomes};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Static invalid host configuration, without URL, identity or credential values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("gateway_transport_configuration")]
pub struct GatewayConfigError;
/// Closed validated request category. HttpContext is checked against this destination-derived kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRequestKind {
    /// Protected model catalogue.
    Catalogue,
    /// One host-selected model wire endpoint.
    Model,
    /// Fixed OAuth discovery URL.
    OAuthDiscovery,
    /// Fixed public client registration endpoint.
    OAuthRegistration,
    /// Fixed public PKCE code/refresh endpoint.
    OAuthToken,
    /// Fixed token revocation endpoint.
    OAuthRevocation,
}
/// Non-serializable bounded descriptor supplied to a mandatory host fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayRequestDescriptor {
    kind: GatewayRequestKind,
    streaming: bool,
}
impl GatewayRequestDescriptor {
    /// Destination-derived request kind.
    pub const fn kind(self) -> GatewayRequestKind {
        self.kind
    }
    /// True only for the fixed model endpoint's streaming wire.
    pub const fn streaming(self) -> bool {
        self.streaming
    }
}
/// Host may tighten fixed R230 budgets; it cannot remove their hard upper bounds.
#[derive(Clone, Copy, Debug)]
pub struct GatewayTransportLimits {
    request_timeout: Duration,
    response_bytes: usize,
}
impl GatewayTransportLimits {
    /// Select positive host ceilings, intersected with each route's fixed R230 ceilings.
    pub fn new(
        request_timeout: Duration,
        response_bytes: usize,
    ) -> Result<Self, GatewayConfigError> {
        if request_timeout.is_zero()
            || request_timeout > Duration::from_secs(30)
            || response_bytes == 0
            || response_bytes > 64 * 1024 * 1024
        {
            return Err(GatewayConfigError);
        }
        Ok(Self {
            request_timeout,
            response_bytes,
        })
    }
}
/// Closed host-fence failure; no backend messages or identity values cross this interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayFenceError {
    /// Current actor/source/run is not authorized.
    Refused,
    /// A pre-send authority dependency is unavailable.
    Unavailable,
    /// Authority state/cleanup is uncertain and must not be retried as an unsent operation.
    CleanupUnknown,
}
/// Required current host authority; there is deliberately no default or no-op implementation.
#[async_trait]
pub trait GatewayHttpAuthority: Send + Sync {
    /// Revalidate this request before DNS/socket. Implementations must cooperate with cancellation.
    /// Token rotation must reuse its held strict-authority context rather than reenter its lock.
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        cancel: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError>;
}
/// Unique authority lease for one execute. Drop must safely cancel/release its owned work.
#[async_trait]
pub trait GatewayHttpPermit: Send {
    /// Confirm authority release (including a required PG rollback ACK) before exposing headers.
    async fn release_after_headers(self: Box<Self>) -> Result<(), GatewayFenceError>;
}
/// Shared trusted networking factory, without account identity or cached credentials.
#[derive(Clone)]
pub struct GatewayTransportFactory {
    dialer: SafeDialer,
    endpoints: VerifiedGatewayEndpoints,
    limits: GatewayTransportLimits,
}
impl GatewayTransportFactory {
    /// Bind the existing host SafeDialer, reviewed exact endpoints and closed budget ceilings.
    pub fn new(
        dialer: SafeDialer,
        endpoints: VerifiedGatewayEndpoints,
        limits: GatewayTransportLimits,
    ) -> Self {
        Self {
            dialer,
            endpoints,
            limits,
        }
    }
    /// Create one operation's transport. Both absolute deadline and read-stall limit are mandatory.
    /// No authorization is inferred from construction; every execute calls the supplied fence.
    pub fn for_operation(
        &self,
        authority: Arc<dyn GatewayHttpAuthority>,
        outcomes: Arc<dyn GatewayHttpOutcomes>,
        deadline: Instant,
        stall: Duration,
    ) -> Result<Arc<dyn HttpTransport>, GatewayConfigError> {
        let now = Instant::now();
        if deadline <= now || stall.is_zero() || now.checked_add(stall).is_none() {
            return Err(GatewayConfigError);
        }
        Ok(Arc::new(GatewayTransport {
            factory: self.clone(),
            authority,
            outcomes,
            deadline,
            stall,
        }))
    }
}
impl std::fmt::Debug for GatewayTransportFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatewayTransportFactory([redacted])")
    }
}
struct GatewayTransport {
    factory: GatewayTransportFactory,
    authority: Arc<dyn GatewayHttpAuthority>,
    outcomes: Arc<dyn GatewayHttpOutcomes>,
    deadline: Instant,
    stall: Duration,
}
#[async_trait]
impl HttpTransport for GatewayTransport {
    async fn execute(
        &self,
        request: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, TransportError> {
        let started = Instant::now();
        let framed = self
            .deadline
            .checked_duration_since(started)
            .ok_or(TransportError::Timeout)
            .and_then(|remaining| {
                framing::frame(
                    request,
                    &self.factory.endpoints,
                    self.factory.limits,
                    remaining,
                )
            });
        let attempt = AttemptGuard::new(
            framed.as_ref().ok().map(|f| f.descriptor),
            self.outcomes.as_ref(),
        );
        if cancel.is_cancelled() {
            attempt.fail(GatewayFailure::Cancelled);
            return Err(TransportError::Cancelled);
        }
        let framed = match framed {
            Ok(framed) => framed,
            Err(error) => {
                attempt.fail(if error == TransportError::Timeout {
                    GatewayFailure::Timeout
                } else {
                    GatewayFailure::InvalidRequest
                });
                return Err(error);
            }
        };
        let deadline = started
            .checked_add(framed.timeout)
            .ok_or(TransportError::InvalidRequest)?
            .min(self.deadline);
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => { attempt.fail(GatewayFailure::Cancelled); return Err(TransportError::Cancelled); }
            _ = tokio::time::sleep_until(deadline) => { attempt.fail(GatewayFailure::Timeout); return Err(TransportError::Timeout); }
            permit = self.authority.before_request(framed.descriptor, cancel.clone()) => match permit {
                Ok(permit) => permit,
                Err(error) => { attempt.fence_failed(error); return Err(TransportError::Rejected); }
            }
        };
        // Conservative effect marker: SafeDialer errors do not expose the exact send stage.
        attempt.dispatched();
        let response = tokio::select! {
            biased;
            _ = cancel.cancelled() => { attempt.fail(GatewayFailure::Cancelled); return Err(TransportError::Rejected); }
            _ = tokio::time::sleep_until(deadline) => { attempt.fail(GatewayFailure::Timeout); return Err(TransportError::Rejected); }
            response = self.factory.dialer.execute_stream(framed.request) => response,
        };
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                attempt.fail(map_http(error));
                return Err(TransportError::Rejected);
            }
        };
        let status = response.status();
        attempt.headers(status.as_u16());
        let headers = response.take_headers();
        let release = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(GatewayFenceError::CleanupUnknown),
            _ = tokio::time::sleep_until(deadline) => Err(GatewayFenceError::CleanupUnknown),
            release = permit.release_after_headers() => release,
        };
        if release.is_err() {
            attempt.fence_failed(GatewayFenceError::CleanupUnknown);
            return Err(TransportError::Rejected);
        }
        attempt.released();
        // Once HTTP headers exist, confirm authority cleanup even if the Gateway-specific header
        // budget rejects them. Permit Drop alone cannot prove a required PG rollback ACK.
        if !valid_response_headers(&headers) {
            attempt.fail(GatewayFailure::Rejected);
            return Err(TransportError::Rejected);
        }
        let body_deadline = if framed.descriptor.streaming {
            self.deadline
        } else {
            deadline
        };
        let watcher = BodyWatch(tokio::spawn({
            let cancel = cancel.clone();
            let attempt = attempt.watch();
            let driver = response.abort_handle();
            async move {
                let failure = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => GatewayFailure::Cancelled,
                    _ = tokio::time::sleep_until(body_deadline) => GatewayFailure::Timeout,
                };
                // Settle exactly once before waking a concurrent body poll through driver abort;
                // EOF/completion and watcher causes therefore cannot overwrite each other.
                if attempt.fail(failure) {
                    driver.abort();
                }
            }
        }));
        let state = BodyState {
            _watcher: watcher,
            response: Some(response),
            cancel,
            attempt,
            deadline: body_deadline,
            stall: self.stall,
            terminal: false,
        };
        let body = futures_util::stream::unfold(state, |mut state| async move {
            if state.terminal {
                return None;
            }
            let response = state.response.as_mut()?;
            let next = tokio::select! {
                biased;
                _ = state.cancel.cancelled() => Err(GatewayFailure::Cancelled),
                _ = tokio::time::sleep_until(state.deadline) => Err(GatewayFailure::Timeout),
                next = response.next_chunk(Some(state.stall)) => next.map_err(map_http),
            };
            match next {
                Ok(Some(bytes)) => Some((Ok(bytes), state)),
                Ok(None) => {
                    if state.attempt.completed() {
                        None
                    } else {
                        state.terminal = true;
                        Some((Err(TransportError::Body), state))
                    }
                }
                Err(error) => {
                    state.response.take();
                    state.attempt.fail(error);
                    state.terminal = true;
                    Some((Err(TransportError::Body), state))
                }
            }
        });
        Ok(HttpResponse {
            status,
            headers,
            body: Box::pin(body),
        })
    }
}
struct BodyState {
    _watcher: BodyWatch,
    response: Option<SafeHttpStreamResponse>,
    cancel: CancellationToken,
    attempt: AttemptGuard,
    deadline: Instant,
    stall: Duration,
    terminal: bool,
}

struct BodyWatch(tokio::task::JoinHandle<()>);

impl Drop for BodyWatch {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn valid_response_headers(headers: &HeaderMap) -> bool {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (name, value) in headers {
        count += 1;
        if count > 64 || value.as_bytes().len() > 8 * 1024 {
            return false;
        }
        let Some(total) = bytes
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(value.as_bytes().len()))
        else {
            return false;
        };
        bytes = total;
        if bytes > 64 * 1024 {
            return false;
        }
    }
    true
}
fn map_http(error: SafeHttpError) -> GatewayFailure {
    match error {
        SafeHttpError::DeadlineExceeded | SafeHttpError::StreamStalled => GatewayFailure::Timeout,
        SafeHttpError::InvalidUrl
        | SafeHttpError::SchemeRejected
        | SafeHttpError::InvalidBudget
        | SafeHttpError::InvalidHeader
        | SafeHttpError::InvalidAllowlist
        | SafeHttpError::DestinationDenied => GatewayFailure::Rejected,
        _ => GatewayFailure::Body,
    }
}
