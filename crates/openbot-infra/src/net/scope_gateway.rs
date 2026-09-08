//! One Rust-owned, revocable network capability per browser scope. This adapter is not a tool
//! authorizer: ComputerManager must own one instance per verified scope/generation and retire it
//! with that authority. No request can supply an actor, tenant, policy or alternate resolver.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::stream;
use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use openbot_domain::vault::SecretBytes;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

use super::safe_http::{ProxyHop, SafeDialer, SafeHttpError};

const HEADER_BYTES: usize = 32 * 1024;
const HEADER_COUNT: usize = 64;
const COPY_BYTES: usize = 16 * 1024;
const PROXY_USERNAME: &str = "scope";
type ProxyBody = UnsyncBoxBody<Bytes, GatewayError>;
type Tunnel = Pin<Box<dyn Future<Output = Result<(), GatewayError>> + Send>>;

/// Closed errors; targets, headers, credentials and peer prose never cross this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// Invalid host-owned configuration or malformed request.
    #[error("scope_gateway_invalid")]
    Invalid,
    /// Destination is outside this scope's configured rules.
    #[error("scope_gateway_denied")]
    Denied,
    /// A bounded transport operation failed.
    #[error("scope_gateway_unavailable")]
    Unavailable,
    /// A configured resource limit was reached.
    #[error("scope_gateway_budget")]
    Budget,
    /// The owning scope has retired.
    #[error("scope_gateway_closed")]
    Closed,
}

/// A canonical exact host or explicit subdomain rule. Ports and IP classes are checked separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayHostRule {
    host: String,
    subdomains: bool,
}

impl GatewayHostRule {
    /// Parse `example.com`, an IP literal, or `*.example.com`; wildcard matches subdomains only.
    pub fn parse(value: &str) -> Result<Self, GatewayError> {
        let (value, subdomains) = value
            .strip_prefix("*.")
            .map_or((value, false), |v| (v, true));
        let host = canonical_host(value)?;
        if subdomains && !matches!(url::Host::parse(value), Ok(url::Host::Domain(_))) {
            return Err(GatewayError::Invalid);
        }
        Ok(Self { host, subdomains })
    }
    fn matches(&self, host: &str) -> bool {
        let Ok(host) = canonical_host(host) else {
            return false;
        };
        if self.subdomains {
            host.strip_suffix(&self.host)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
        } else {
            host == self.host
        }
    }
}

/// Immutable host-owned policy. `None` explicitly allows any host surviving IP/port/deny checks;
/// `Some([])` denies every host. There is no policy field in an inbound proxy request.
#[derive(Clone, Debug)]
pub struct GatewayPolicy {
    allow: Option<Vec<GatewayHostRule>>,
    deny: Vec<GatewayHostRule>,
    ports: BTreeSet<u16>,
}

impl GatewayPolicy {
    /// Build reviewed tenant host/port rules; the supplied SafeDialer separately owns exact CIDRs.
    pub fn new(
        allow: Option<Vec<GatewayHostRule>>,
        deny: Vec<GatewayHostRule>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Result<Self, GatewayError> {
        let ports = ports.into_iter().collect::<BTreeSet<_>>();
        if ports.is_empty()
            || ports.len() > 64
            || ports.contains(&0)
            || deny.len() > 256
            || allow.as_ref().is_some_and(|v| v.len() > 256)
        {
            return Err(GatewayError::Invalid);
        }
        Ok(Self { allow, deny, ports })
    }
    /// Standard web ports. The separate SafeDialer IP policy defaults to public-only; a reviewed
    /// explicit CIDR exception remains an intentional override, including with these port rules.
    pub fn public_web() -> Self {
        Self::new(None, Vec::new(), [80, 443]).expect("fixed web policy")
    }
    fn permits(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        self.ports
            .contains(&url.port_or_known_default().unwrap_or(0))
            && !self.deny.iter().any(|rule| rule.matches(host))
            && self
                .allow
                .as_ref()
                .is_none_or(|rules| rules.iter().any(|rule| rule.matches(host)))
    }
}

/// Hard bounded defaults for one network scope; callers may tighten them before launch.
#[derive(Clone, Copy, Debug)]
pub struct GatewayBudget {
    /// Maximum accepted downstream sockets, including pre-authentication handshakes.
    pub connections: usize,
    /// Downstream header, DNS/connect and upgrade deadline.
    pub handshake: Duration,
    /// Shared bidirectional idle interval for a tunnel.
    pub idle: Duration,
    /// Maximum lifetime of one downstream socket.
    pub connection_lifetime: Duration,
    /// Maximum ordinary HTTP request body.
    pub request_bytes: usize,
    /// Maximum ordinary HTTP response body.
    pub response_bytes: usize,
    /// Maximum total bytes in one upgraded tunnel.
    pub tunnel_bytes: u64,
    /// Aggregate byte rate shared by all sockets in both directions.
    pub bytes_per_second: u64,
    /// Initial/maximum token bucket burst.
    pub burst_bytes: u64,
}

impl Default for GatewayBudget {
    fn default() -> Self {
        Self {
            connections: 32,
            handshake: Duration::from_secs(10),
            idle: Duration::from_secs(30),
            connection_lifetime: Duration::from_secs(30 * 60),
            request_bytes: 8 * 1024 * 1024,
            response_bytes: 64 * 1024 * 1024,
            tunnel_bytes: 1024 * 1024 * 1024,
            bytes_per_second: 8 * 1024 * 1024,
            burst_bytes: 1024 * 1024,
        }
    }
}

impl GatewayBudget {
    fn validate(self) -> Result<Self, GatewayError> {
        let maximum = Self::default();
        if self.connections == 0
            || self.connections > maximum.connections
            || self.handshake.is_zero()
            || self.handshake > maximum.handshake
            || self.idle.is_zero()
            || self.idle > maximum.idle
            || self.connection_lifetime.is_zero()
            || self.connection_lifetime > maximum.connection_lifetime
            || self.request_bytes == 0
            || self.request_bytes > maximum.request_bytes
            || self.response_bytes == 0
            || self.response_bytes > maximum.response_bytes
            || self.tunnel_bytes == 0
            || self.tunnel_bytes > maximum.tunnel_bytes
            || self.bytes_per_second == 0
            || self.bytes_per_second > maximum.bytes_per_second
            || self.burst_bytes < COPY_BYTES as u64
            || self.burst_bytes > maximum.burst_bytes
        {
            return Err(GatewayError::Invalid);
        }
        Ok(self)
    }
}

/// Secret connection material for the trusted engine bootstrap only. No Serialize or Display.
#[derive(Clone)]
pub struct GatewayBinding {
    address: SocketAddr,
    password: Arc<Zeroizing<String>>,
}

impl GatewayBinding {
    /// Loopback endpoint; never a renderer-selected address.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
    /// Fixed proxy username.
    pub const fn username(&self) -> &'static str {
        PROXY_USERNAME
    }
    /// Explicit exposure only to trusted process bootstrap/auth callback configuration.
    pub fn expose_password(&self) -> &str {
        self.password.as_str()
    }
}

impl std::fmt::Debug for GatewayBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayBinding")
            .field("address", &self.address)
            .field("credential", &"[redacted]")
            .finish()
    }
}

/// Bounded counters contain no destination or request content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayStats {
    /// Currently owned sockets.
    pub active_connections: usize,
    /// Requests admitted to destination validation.
    pub authenticated_requests: u64,
    /// Authentication failures; no DNS or target connection was attempted.
    pub authentication_failures: u64,
    /// Destination/shape refusals.
    pub refused_requests: u64,
    /// Payload bytes admitted for forwarding across both directions (not a wire receipt).
    pub forwarded_bytes: u64,
}

#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    authenticated: AtomicU64,
    unauthenticated: AtomicU64,
    refused: AtomicU64,
    bytes: AtomicU64,
}
struct Shared {
    dialer: SafeDialer,
    policy: GatewayPolicy,
    budget: GatewayBudget,
    auth_key: SecretBytes,
    auth_digest: [u8; 32],
    cancel: watch::Sender<bool>,
    counters: Counters,
    rate: Mutex<Bucket>,
}
struct Bucket {
    credit: u128,
    updated: Instant,
}

/// Unique scope owner. Drop retires the listener and every ordinary/upgraded connection; explicit
/// shutdown additionally waits for task completion. No global endpoint or credential is reused.
pub struct ScopedEgressGateway {
    binding: GatewayBinding,
    shared: Arc<Shared>,
    task: Option<JoinHandle<()>>,
}

impl ScopedEgressGateway {
    /// Bind one local per-scope listener with an independent 256-bit secret. No outgoing network
    /// connection can occur until proxy authentication and the host/port/IP checks have passed.
    pub async fn start(
        dialer: SafeDialer,
        policy: GatewayPolicy,
        budget: GatewayBudget,
    ) -> Result<Self, GatewayError> {
        let budget = budget.validate()?;
        let mut random = Zeroizing::new([0_u8; 32]);
        getrandom::fill(random.as_mut()).map_err(|_| GatewayError::Unavailable)?;
        let mut password = Zeroizing::new(String::with_capacity(64));
        for byte in random.iter() {
            write!(&mut *password, "{byte:02x}").map_err(|_| GatewayError::Unavailable)?;
        }
        let password = Arc::new(password);
        let mut pair = Zeroizing::new(String::with_capacity(PROXY_USERNAME.len() + 65));
        pair.push_str(PROXY_USERNAME);
        pair.push(':');
        pair.push_str(password.as_str());
        let mut basic = Zeroizing::new(String::with_capacity(128));
        basic.push_str("Basic ");
        STANDARD.encode_string(pair.as_bytes(), &mut basic);
        let mut key = Zeroizing::new(vec![0_u8; 32]);
        getrandom::fill(&mut key).map_err(|_| GatewayError::Unavailable)?;
        let auth_key = SecretBytes::new(std::mem::take(&mut *key));
        let mut mac =
            Hmac::<Sha256>::new_from_slice(auth_key.expose()).map_err(|_| GatewayError::Invalid)?;
        mac.update(basic.as_bytes());
        let auth_digest = mac.finalize().into_bytes().into();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        let address = listener
            .local_addr()
            .map_err(|_| GatewayError::Unavailable)?;
        let (cancel, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            dialer,
            policy,
            budget,
            auth_key,
            auth_digest,
            cancel,
            counters: Counters::default(),
            rate: Mutex::new(Bucket {
                credit: u128::from(budget.burst_bytes) * 1_000_000_000,
                updated: Instant::now(),
            }),
        });
        let task = tokio::spawn(accept(listener, shared.clone()));
        Ok(Self {
            binding: GatewayBinding { address, password },
            shared,
            task: Some(task),
        })
    }
    /// Clone only the trusted bootstrap material, not ownership of the live scope.
    pub fn binding(&self) -> GatewayBinding {
        self.binding.clone()
    }
    /// Current bounded diagnostics.
    pub fn stats(&self) -> GatewayStats {
        let c = &self.shared.counters;
        GatewayStats {
            active_connections: c.active.load(Ordering::SeqCst),
            authenticated_requests: c.authenticated.load(Ordering::Relaxed),
            authentication_failures: c.unauthenticated.load(Ordering::Relaxed),
            refused_requests: c.refused.load(Ordering::Relaxed),
            forwarded_bytes: c.bytes.load(Ordering::Relaxed),
        }
    }
    /// Retire all traffic and await listener/connection cleanup.
    pub async fn shutdown(mut self) -> Result<(), GatewayError> {
        self.shared.cancel.send_replace(true);
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| GatewayError::Unavailable)?;
        }
        Ok(())
    }
}
impl Drop for ScopedEgressGateway {
    fn drop(&mut self) {
        self.shared.cancel.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn accept(listener: TcpListener, shared: Arc<Shared>) {
    let slots = Arc::new(Semaphore::new(shared.budget.connections));
    let mut tasks = JoinSet::new();
    let mut cancel = shared.cancel.subscribe();
    loop {
        tokio::select! {biased;
            _=cancel.wait_for(|closed|*closed)=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            incoming=listener.accept()=>{
                let Ok((socket,_))=incoming else{break};
                let Ok(permit)=slots.clone().try_acquire_owned()else{drop(socket);continue};
                shared.counters.active.fetch_add(1,Ordering::SeqCst);
                let active=Active(shared.clone());let state=shared.clone();
                tasks.spawn(async move{let _permit=permit;let _active=active;let _=serve(socket,state).await;});
            }
        }
    }
    drop(listener);
    shared.cancel.send_replace(true);
    // Each connection observes cancellation, drops its HTTP/tunnel future, then aborts AND joins
    // its sole upstream driver. Explicit scope shutdown waits for this entire ownership tree.
    while tasks.join_next().await.is_some() {}
}
struct Active(Arc<Shared>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.counters.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Connection {
    scope: Arc<Shared>,
    activity: watch::Sender<Instant>,
    tunnel: Mutex<Option<Tunnel>>,
    driver: Mutex<Option<JoinHandle<()>>>,
}
impl Connection {
    fn touch(&self) {
        self.activity.send_replace(Instant::now());
    }
    fn install_tunnel(&self, tunnel: Tunnel) -> Result<(), GatewayError> {
        let mut slot = self.tunnel.lock().map_err(|_| GatewayError::Closed)?;
        if slot.is_some() {
            return Err(GatewayError::Closed);
        }
        *slot = Some(tunnel);
        Ok(())
    }
    async fn stop_driver(&self) {
        let driver = self
            .driver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(driver) = driver {
            driver.abort();
            let _ = driver.await;
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(driver) = self
            .driver
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            driver.abort();
        }
    }
}

async fn serve(socket: TcpStream, shared: Arc<Shared>) -> Result<(), GatewayError> {
    let (activity, _) = watch::channel(Instant::now());
    let connection = Arc::new(Connection {
        scope: shared.clone(),
        activity,
        tunnel: Mutex::new(None),
        driver: Mutex::new(None),
    });
    let state = connection.clone();
    let service = service_fn(move |request| handle(request, state.clone()));
    let mut builder = hyper::server::conn::http1::Builder::new();
    // One request owns one upstream connection. CONNECT/WS retain it until the tunnel closes.
    // No cross-request pool, speculative dial, automatic retry, or redirect following exists.
    builder
        .keep_alive(false)
        .max_headers(HEADER_COUNT)
        .max_buf_size(HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(shared.budget.handshake);
    let mut cancel = shared.cancel.subscribe();
    let result = {
        let work = async {
            builder
                .serve_connection(TokioIo::new(socket), service)
                .with_upgrades()
                .await
                .map_err(|_| GatewayError::Unavailable)?;
            let tunnel = connection
                .tunnel
                .lock()
                .map_err(|_| GatewayError::Closed)?
                .take();
            if let Some(tunnel) = tunnel {
                tunnel.await?;
            }
            Ok(())
        };
        tokio::select! {biased;
            _=cancel.wait_for(|closed|*closed)=>Err(GatewayError::Closed),
            result=idle(connection.activity.subscribe(),shared.budget.idle)=>result,
            result=tokio::time::timeout(shared.budget.connection_lifetime,work)=>result.unwrap_or(Err(GatewayError::Budget)),
        }
    };
    connection.stop_driver().await;
    result
}

async fn idle(
    mut activity: watch::Receiver<Instant>,
    budget: Duration,
) -> Result<(), GatewayError> {
    loop {
        let deadline = *activity.borrow_and_update() + budget;
        tokio::select! {biased;
            changed=activity.changed()=>{changed.map_err(|_|GatewayError::Closed)?;}
            _=tokio::time::sleep_until(deadline)=>return Err(GatewayError::Budget),
        }
    }
}

fn response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(Bytes::new())
            .map_err(|never: Infallible| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Scoped network\""),
        );
    }
    response
}

fn authenticated(request: &Request<Incoming>, shared: &Shared) -> bool {
    let mut values = request
        .headers()
        .get_all(http::header::PROXY_AUTHORIZATION)
        .iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(shared.auth_key.expose()) else {
        return false;
    };
    mac.update(value.as_bytes());
    mac.verify_slice(&shared.auth_digest).is_ok()
}

async fn handle(
    mut request: Request<Incoming>,
    connection: Arc<Connection>,
) -> Result<Response<ProxyBody>, Infallible> {
    for value in request.headers_mut().values_mut() {
        value.set_sensitive(true);
    }
    let shared = &connection.scope;
    if *shared.cancel.borrow() {
        return Ok(response(StatusCode::SERVICE_UNAVAILABLE));
    }
    // Include parsed request headers in aggregate admission cost, even for refused credentials.
    // Parser buffers and the pre-auth connection semaphore separately bound raw ingress.
    let cost = request.method().as_str().len()
        + request.uri().to_string().len()
        + 16
        + header_bytes(request.headers());
    if charge_amount(shared, cost).await.is_err() {
        return Ok(response(StatusCode::SERVICE_UNAVAILABLE));
    }
    if !authenticated(&request, shared) {
        shared
            .counters
            .unauthenticated
            .fetch_add(1, Ordering::Relaxed);
        return Ok(response(StatusCode::PROXY_AUTHENTICATION_REQUIRED));
    }
    shared
        .counters
        .authenticated
        .fetch_add(1, Ordering::Relaxed);
    connection.touch();
    let result = handle_authenticated(request, connection.clone()).await;
    Ok(match result {
        Ok(response) => response,
        Err(error) => {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            response(match error {
                GatewayError::Invalid => StatusCode::BAD_REQUEST,
                GatewayError::Denied => StatusCode::FORBIDDEN,
                GatewayError::Budget => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::BAD_GATEWAY,
            })
        }
    })
}

async fn handle_authenticated(
    mut request: Request<Incoming>,
    connection: Arc<Connection>,
) -> Result<Response<ProxyBody>, GatewayError> {
    let shared = &connection.scope;
    let is_connect = request.method() == Method::CONNECT;
    let target = parse_target(request.uri(), is_connect)?;
    validate_host(request.headers(), &target)?;
    if !shared.policy.permits(&target) {
        return Err(GatewayError::Denied);
    }
    let declared = content_length(request.headers())?;
    if is_connect {
        if request
            .headers()
            .contains_key(http::header::TRANSFER_ENCODING)
            || declared.is_some_and(|size| size != 0)
            || request.headers().contains_key(http::header::UPGRADE)
        {
            return Err(GatewayError::Invalid);
        }
    } else if declared.is_some_and(|size| size > shared.budget.request_bytes) {
        return Err(GatewayError::Budget);
    }
    let websocket = websocket_request(&request)?;
    let mut headers = request.headers().clone();
    strip_hop_headers(&mut headers)?;
    let host = &target[url::Position::BeforeHost..url::Position::AfterPort];
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host).map_err(|_| GatewayError::Invalid)?,
    );
    let hop = tokio::time::timeout(
        shared.budget.handshake,
        shared.dialer.connect_proxy_hop(&target),
    )
    .await
    .map_err(|_| GatewayError::Unavailable)?
    .map_err(map_dial_error)?;
    connection.touch();
    if is_connect {
        let upgrade = hyper::upgrade::on(&mut request);
        let state = shared.clone();
        let activity = connection.activity.clone();
        connection.install_tunnel(Box::pin(async move {
            let downstream = tokio::time::timeout(state.budget.handshake, upgrade)
                .await
                .map_err(|_| GatewayError::Unavailable)?
                .map_err(|_| GatewayError::Unavailable)?;
            pump(TokioIo::new(downstream), hop.into_tunnel(), state, activity).await
        }))?;
        return Ok(response(StatusCode::OK));
    }
    forward_http(request, headers, hop, connection, websocket).await
}

fn map_dial_error(error: SafeHttpError) -> GatewayError {
    match error {
        SafeHttpError::DestinationDenied | SafeHttpError::PeerMismatch => GatewayError::Denied,
        SafeHttpError::InvalidUrl | SafeHttpError::SchemeRejected => GatewayError::Invalid,
        _ => GatewayError::Unavailable,
    }
}

fn parse_target(uri: &Uri, connect: bool) -> Result<Url, GatewayError> {
    let text = uri.to_string();
    if text.contains('\\')
        || uri
            .authority()
            .is_some_and(|value| value.as_str().contains('@'))
    {
        return Err(GatewayError::Invalid);
    }
    let url = if connect {
        if uri.scheme().is_some() || uri.path_and_query().is_some() {
            return Err(GatewayError::Invalid);
        }
        let authority = uri.authority().ok_or(GatewayError::Invalid)?;
        if authority.port_u16().is_none_or(|port| port == 0) {
            return Err(GatewayError::Invalid);
        }
        Url::parse(&format!("https://{authority}/")).map_err(|_| GatewayError::Invalid)?
    } else {
        Url::parse(&text).map_err(|_| GatewayError::Invalid)?
    };
    if (!connect && url.scheme() != "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(GatewayError::Invalid);
    }
    canonical_host(url.host_str().ok_or(GatewayError::Invalid)?)?;
    Ok(url)
}

fn canonical_host(value: &str) -> Result<String, GatewayError> {
    if value.is_empty()
        || value.len() > 253
        || value.trim() != value
        || value.contains(['/', '\\', '@', '#', '?', '%', '*'])
    {
        return Err(GatewayError::Invalid);
    }
    let parsed = url::Host::parse(value).map_err(|_| GatewayError::Invalid)?;
    match parsed {
        url::Host::Domain(domain) => {
            let domain = domain.strip_suffix('.').unwrap_or(&domain);
            if domain.is_empty()
                || domain
                    .split('.')
                    .any(|label| label.is_empty() || label.len() > 63)
            {
                return Err(GatewayError::Invalid);
            }
            Ok(domain.to_owned())
        }
        ip => Ok(ip.to_string()),
    }
}

fn validate_host(headers: &HeaderMap, target: &Url) -> Result<(), GatewayError> {
    let mut hosts = headers.get_all(http::header::HOST).iter();
    let host = hosts
        .next()
        .ok_or(GatewayError::Invalid)?
        .to_str()
        .map_err(|_| GatewayError::Invalid)?;
    if hosts.next().is_some()
        || host.contains(['/', '\\', '@', '?', '#', '%'])
        || host.trim() != host
    {
        return Err(GatewayError::Invalid);
    }
    let url =
        Url::parse(&format!("{}://{host}/", target.scheme())).map_err(|_| GatewayError::Invalid)?;
    if canonical_host(url.host_str().ok_or(GatewayError::Invalid)?)?
        != canonical_host(target.host_str().ok_or(GatewayError::Invalid)?)?
        || url.port_or_known_default() != target.port_or_known_default()
    {
        return Err(GatewayError::Invalid);
    }
    Ok(())
}

fn content_length(headers: &HeaderMap) -> Result<Option<usize>, GatewayError> {
    let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || headers.contains_key(http::header::TRANSFER_ENCODING) {
        return Err(GatewayError::Invalid);
    }
    let value = value.to_str().map_err(|_| GatewayError::Invalid)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GatewayError::Invalid);
    }
    value.parse().map(Some).map_err(|_| GatewayError::Invalid)
}

fn connection_tokens(headers: &HeaderMap) -> Result<Vec<http::HeaderName>, GatewayError> {
    let mut tokens = Vec::new();
    for value in headers.get_all(http::header::CONNECTION) {
        for token in value
            .to_str()
            .map_err(|_| GatewayError::Invalid)?
            .split(',')
        {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            tokens.push(
                http::HeaderName::from_bytes(token.as_bytes())
                    .map_err(|_| GatewayError::Invalid)?,
            );
            if tokens.len() > HEADER_COUNT {
                return Err(GatewayError::Invalid);
            }
        }
    }
    Ok(tokens)
}

fn strip_hop_headers(headers: &mut HeaderMap) -> Result<(), GatewayError> {
    for name in connection_tokens(headers)? {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    Ok(())
}

fn websocket_request(request: &Request<Incoming>) -> Result<bool, GatewayError> {
    let connection_upgrade = connection_tokens(request.headers())?.contains(&http::header::UPGRADE);
    let mut upgrades = request.headers().get_all(http::header::UPGRADE).iter();
    let Some(value) = upgrades.next() else {
        return if connection_upgrade {
            Err(GatewayError::Invalid)
        } else {
            Ok(false)
        };
    };
    if upgrades.next().is_some()
        || !value.as_bytes().eq_ignore_ascii_case(b"websocket")
        || !connection_upgrade
        || request.method() != Method::GET
        || content_length(request.headers())?.is_some_and(|len| len != 0)
        || request
            .headers()
            .contains_key(http::header::TRANSFER_ENCODING)
    {
        return Err(GatewayError::Invalid);
    }
    let mut keys = request.headers().get_all("sec-websocket-key").iter();
    let key = keys.next().ok_or(GatewayError::Invalid)?;
    if keys.next().is_some()
        || STANDARD
            .decode(key.as_bytes())
            .map_or(true, |bytes| bytes.len() != 16)
    {
        return Err(GatewayError::Invalid);
    }
    let mut versions = request.headers().get_all("sec-websocket-version").iter();
    if versions.next().is_none_or(|v| v != "13") || versions.next().is_some() {
        return Err(GatewayError::Invalid);
    }
    Ok(true)
}

fn websocket_response(headers: &HeaderMap) -> Result<(), GatewayError> {
    let mut values = headers.get_all(http::header::UPGRADE).iter();
    if values
        .next()
        .is_none_or(|v| !v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        || values.next().is_some()
        || !connection_tokens(headers)?.contains(&http::header::UPGRADE)
    {
        return Err(GatewayError::Unavailable);
    }
    let mut accepts = headers.get_all("sec-websocket-accept").iter();
    if accepts.next().is_none_or(|v| {
        STANDARD
            .decode(v.as_bytes())
            .map_or(true, |b| b.len() != 20)
    }) || accepts.next().is_some()
    {
        return Err(GatewayError::Unavailable);
    }
    Ok(())
}

async fn forward_http(
    mut request: Request<Incoming>,
    headers: HeaderMap,
    hop: ProxyHop,
    connection: Arc<Connection>,
    websocket: bool,
) -> Result<Response<ProxyBody>, GatewayError> {
    let shared = &connection.scope;
    let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let path = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .parse::<Uri>()
        .map_err(|_| GatewayError::Invalid)?;
    let (parts, body) = request.into_parts();
    let mut outgoing = Request::new(bounded_body(
        body,
        shared.budget.request_bytes,
        shared.clone(),
        connection.activity.clone(),
    ));
    *outgoing.method_mut() = parts.method;
    *outgoing.uri_mut() = path;
    *outgoing.headers_mut() = headers;
    if websocket {
        outgoing
            .headers_mut()
            .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        outgoing.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
    }
    let (mut sender, driver) =
        tokio::time::timeout(shared.budget.handshake, hop.http::<ProxyBody>())
            .await
            .map_err(|_| GatewayError::Unavailable)?
            .map_err(map_dial_error)?;
    {
        let mut slot = connection.driver.lock().map_err(|_| GatewayError::Closed)?;
        if slot.is_some() {
            return Err(GatewayError::Closed);
        }
        *slot = Some(tokio::spawn(async move {
            let _ = driver.await;
        }));
    }
    let mut incoming = sender
        .send_request(outgoing)
        .await
        .map_err(|_| GatewayError::Unavailable)?;
    for value in incoming.headers_mut().values_mut() {
        value.set_sensitive(true);
    }
    connection.touch();
    charge_amount(shared, header_bytes(incoming.headers()) + 16).await?;
    if incoming.status() == StatusCode::SWITCHING_PROTOCOLS {
        if !websocket {
            return Err(GatewayError::Unavailable);
        }
        websocket_response(incoming.headers()).map_err(|_| GatewayError::Unavailable)?;
        let upstream_upgrade = hyper::upgrade::on(&mut incoming);
        let state = shared.clone();
        let activity = connection.activity.clone();
        let downstream = downstream_upgrade.ok_or(GatewayError::Unavailable)?;
        let mut response = response(StatusCode::SWITCHING_PROTOCOLS);
        *response.headers_mut() = incoming.headers().clone();
        strip_hop_headers(response.headers_mut()).map_err(|_| GatewayError::Unavailable)?;
        response.headers_mut().remove(http::header::CONTENT_LENGTH);
        response
            .headers_mut()
            .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        response.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
        connection.install_tunnel(Box::pin(async move {
            let (left, right) = tokio::time::timeout(state.budget.handshake, async {
                tokio::try_join!(downstream, upstream_upgrade)
            })
            .await
            .map_err(|_| GatewayError::Unavailable)?
            .map_err(|_| GatewayError::Unavailable)?;
            pump(TokioIo::new(left), TokioIo::new(right), state, activity).await
        }))?;
        return Ok(response);
    }
    if !incoming.body().is_end_stream()
        && content_length(incoming.headers())
            .map_err(|_| GatewayError::Unavailable)?
            .is_some_and(|len| len > shared.budget.response_bytes)
    {
        return Err(GatewayError::Budget);
    }
    let (parts, body) = incoming.into_parts();
    let mut response = Response::new(bounded_body(
        body,
        shared.budget.response_bytes,
        shared.clone(),
        connection.activity.clone(),
    ));
    *response.status_mut() = parts.status;
    *response.headers_mut() = parts.headers;
    strip_hop_headers(response.headers_mut()).map_err(|_| GatewayError::Unavailable)?;
    Ok(response)
}

struct BodyState {
    body: Incoming,
    remaining: usize,
    pending: Bytes,
    done: bool,
    shared: Arc<Shared>,
    activity: watch::Sender<Instant>,
}
fn bounded_body(
    body: Incoming,
    remaining: usize,
    shared: Arc<Shared>,
    activity: watch::Sender<Instant>,
) -> ProxyBody {
    if body.is_end_stream() {
        return Full::new(Bytes::new())
            .map_err(|never: Infallible| match never {})
            .boxed_unsync();
    }
    StreamBody::new(stream::unfold(
        BodyState {
            body,
            remaining,
            pending: Bytes::new(),
            done: false,
            shared,
            activity,
        },
        |mut state| async move {
            if state.done {
                return None;
            }
            let result = async {
                loop {
                    if !state.pending.is_empty() {
                        let bytes = state.pending.split_to(state.pending.len().min(COPY_BYTES));
                        charge(&state.shared, bytes.len()).await?;
                        state.activity.send_replace(Instant::now());
                        state
                            .shared
                            .counters
                            .bytes
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        return Ok(Some(Frame::data(bytes)));
                    }
                    let Some(frame) =
                        tokio::time::timeout(state.shared.budget.idle, state.body.frame())
                            .await
                            .map_err(|_| GatewayError::Budget)?
                    else {
                        return Ok(None);
                    };
                    let frame = frame.map_err(|_| GatewayError::Unavailable)?;
                    match frame.into_data() {
                        Ok(bytes) => {
                            state.remaining = state
                                .remaining
                                .checked_sub(bytes.len())
                                .ok_or(GatewayError::Budget)?;
                            state.pending = bytes;
                        }
                        Err(frame) => {
                            if let Ok(mut trailers) = frame.into_trailers() {
                                if trailers.len() > HEADER_COUNT
                                    || header_bytes(&trailers) > HEADER_BYTES
                                {
                                    return Err(GatewayError::Budget);
                                }
                                strip_hop_headers(&mut trailers)?;
                                for name in [
                                    "host",
                                    "content-length",
                                    "authorization",
                                    "cookie",
                                    "set-cookie",
                                ] {
                                    trailers.remove(name);
                                }
                                charge_amount(&state.shared, header_bytes(&trailers)).await?;
                                state.done = true;
                                return Ok(Some(Frame::trailers(trailers)));
                            }
                        }
                    }
                }
            }
            .await;
            match result {
                Ok(Some(frame)) => Some((Ok::<_, GatewayError>(frame), state)),
                Ok(None) => None,
                Err(error) => {
                    state.done = true;
                    Some((Err(error), state))
                }
            }
        },
    ))
    .boxed_unsync()
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum()
}
async fn charge_amount(shared: &Shared, mut amount: usize) -> Result<(), GatewayError> {
    while amount > 0 {
        let chunk = amount.min(COPY_BYTES);
        charge(shared, chunk).await?;
        amount -= chunk;
    }
    Ok(())
}
async fn charge(shared: &Shared, amount: usize) -> Result<(), GatewayError> {
    let amount = u128::try_from(amount).map_err(|_| GatewayError::Budget)? * 1_000_000_000;
    loop {
        let wait = {
            let mut bucket = shared.rate.lock().map_err(|_| GatewayError::Closed)?;
            let now = Instant::now();
            let earned = now
                .duration_since(bucket.updated)
                .as_nanos()
                .saturating_mul(u128::from(shared.budget.bytes_per_second));
            bucket.credit = bucket
                .credit
                .saturating_add(earned)
                .min(u128::from(shared.budget.burst_bytes) * 1_000_000_000);
            bucket.updated = now;
            if bucket.credit >= amount {
                bucket.credit -= amount;
                None
            } else {
                Some(Duration::from_nanos(
                    u64::try_from(
                        (amount - bucket.credit)
                            .div_ceil(u128::from(shared.budget.bytes_per_second)),
                    )
                    .map_err(|_| GatewayError::Budget)?,
                ))
            }
        };
        if let Some(wait) = wait {
            tokio::time::sleep(wait).await
        } else {
            return Ok(());
        }
    }
}

async fn pump<A, B>(
    a: A,
    b: B,
    shared: Arc<Shared>,
    activity: watch::Sender<Instant>,
) -> Result<(), GatewayError>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let total = Arc::new(AtomicU64::new(0));
    tokio::try_join!(
        copy(ar, bw, shared.clone(), activity.clone(), total.clone()),
        copy(br, aw, shared, activity, total)
    )?;
    Ok(())
}
async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    shared: Arc<Shared>,
    activity: watch::Sender<Instant>,
    total: Arc<AtomicU64>,
) -> Result<(), GatewayError> {
    let mut bytes = Zeroizing::new([0_u8; COPY_BYTES]);
    loop {
        let count = reader
            .read(bytes.as_mut())
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        if count == 0 {
            writer
                .shutdown()
                .await
                .map_err(|_| GatewayError::Unavailable)?;
            return Ok(());
        }
        total
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                previous
                    .checked_add(count as u64)
                    .filter(|sum| *sum <= shared.budget.tunnel_bytes)
            })
            .map_err(|_| GatewayError::Budget)?;
        activity.send_replace(Instant::now());
        charge(&shared, count).await?;
        tokio::time::timeout(shared.budget.idle, writer.write_all(&bytes[..count]))
            .await
            .map_err(|_| GatewayError::Budget)?
            .map_err(|_| GatewayError::Unavailable)?;
        shared
            .counters
            .bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        activity.send_replace(Instant::now());
    }
}
