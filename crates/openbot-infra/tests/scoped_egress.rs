//! Real loopback HTTP/CONNECT/WebSocket evidence for the Rust gateway substrate.
//! No Engine/ComputerManager, OS namespace, live website or tenant authorization claim.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use openbot_infra::net::scope_gateway::{
    GatewayBinding, GatewayBudget, GatewayHostRule, GatewayPolicy, ScopedEgressGateway,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(3);

struct Resolver {
    calls: AtomicUsize,
    addresses: Mutex<Vec<SocketAddr>>,
}

#[async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addresses.lock().unwrap().clone())
    }
}

fn resolver(addresses: Vec<SocketAddr>) -> Arc<Resolver> {
    Arc::new(Resolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(addresses),
    })
}

fn dialer(resolver: Arc<Resolver>, private: bool) -> SafeDialer {
    SafeDialer::with_resolver(
        EgressPolicy::new(
            CidrAllowlist::parse_exact(if private {
                vec!["127.0.0.1/32"]
            } else {
                vec![]
            })
            .unwrap(),
        ),
        resolver,
    )
}

fn policy(port: u16) -> GatewayPolicy {
    GatewayPolicy::new(
        Some(vec![GatewayHostRule::parse("target.test").unwrap()]),
        vec![],
        [port],
    )
    .unwrap()
}

fn auth(binding: &GatewayBinding) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            binding.username(),
            binding.expose_password()
        ))
    )
}

fn get(target: &str, host: &str, credential: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {credential}\r\n\r\n")
}

async fn exchange(binding: &GatewayBinding, request: &str) -> Vec<u8> {
    timeout(DEADLINE, async {
        let mut socket = TcpStream::connect(binding.address()).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .expect("bounded gateway response")
}

fn status(response: &[u8], code: u16) {
    assert!(response.starts_with(format!("HTTP/1.1 {code} ").as_bytes()));
}

async fn head(socket: &mut TcpStream) -> Vec<u8> {
    timeout(DEADLINE, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
            bytes.push(byte[0]);
            assert!(bytes.len() <= 64 * 1024);
        }
        bytes
    })
    .await
    .expect("bounded HTTP headers")
}

async fn assert_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    let result = timeout(DEADLINE, socket.read(&mut byte))
        .await
        .expect("owned socket must close");
    assert!(matches!(result, Ok(0)) || result.is_err());
}

async fn wait_connections(gateway: &ScopedEgressGateway, count: usize) {
    timeout(DEADLINE, async {
        while gateway.stats().active_connections != count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection ownership settled");
}

#[tokio::test]
async fn authentication_shape_host_and_ip_refusals_happen_before_effects() {
    let dns = resolver(vec!["127.0.0.1:9".parse().unwrap()]);
    let gateway = ScopedEgressGateway::start(
        dialer(dns.clone(), true),
        policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let second = ScopedEgressGateway::start(
        dialer(dns.clone(), true),
        policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    assert!(!format!("{binding:?}").contains(binding.expose_password()));
    assert!(binding.expose_password() != second.binding().expose_password());
    for request in [
        "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\n\r\n".to_owned(),
        get("http://target.test/", "target.test", "Basic incorrect"),
        get(
            "http://target.test/",
            "target.test",
            &auth(&second.binding()),
        ),
        format!(
            "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\nProxy-Authorization: {}\r\nProxy-Authorization: {}\r\n\r\n",
            auth(&binding),
            auth(&binding)
        ),
    ] {
        status(&exchange(&binding, &request).await, 407);
    }
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    for (target, host) in [
        ("/relative", "target.test"),
        ("https://target.test/", "target.test"),
        ("http://user@target.test/", "target.test"),
        ("http://@target.test/", "target.test"),
        ("http://target.test/", "wrong.test"),
        ("http://target.test../", "target.test.."),
    ] {
        status(
            &exchange(&binding, &get(target, host, &auth(&binding))).await,
            400,
        );
    }
    for (target, host) in [
        ("http://denied.test/", "denied.test"),
        ("http://target.test:81/", "target.test:81"),
    ] {
        status(
            &exchange(&binding, &get(target, host, &auth(&binding))).await,
            403,
        );
    }
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.stats().authentication_failures, 4);
    second.shutdown().await.unwrap();
    gateway.shutdown().await.unwrap();

    let dns = resolver(vec![
        "127.0.0.1:9".parse().unwrap(),
        "169.254.169.254:80".parse().unwrap(),
        "[::1]:80".parse().unwrap(),
    ]);
    let gateway = ScopedEgressGateway::start(
        dialer(dns.clone(), false),
        policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    status(
        &exchange(
            &gateway.binding(),
            &get(
                "http://target.test/",
                "target.test",
                &auth(&gateway.binding()),
            ),
        )
        .await,
        403,
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_forwards_body_and_end_to_end_headers_but_never_proxy_credential_or_redirect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dns = resolver(vec!["127.0.0.1:9".parse().unwrap()]); // resolver's poisoned port is overwritten
    let gateway = ScopedEgressGateway::start(
        dialer(dns.clone(), true),
        policy(port),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    let secret = auth(&binding);
    let source_secret = secret.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let headers = head(&mut socket).await;
        let text = String::from_utf8(headers).unwrap();
        let lower = text.to_ascii_lowercase();
        assert!(text.starts_with("POST /path%2Fname?x=1 HTTP/1.1\r\n"));
        assert!(lower.contains("authorization: origin-credential\r\n"));
        assert!(lower.contains("cookie: own=value\r\n"));
        assert!(!text.contains(&source_secret));
        assert!(!lower.contains("proxy-authorization"));
        assert!(!lower.contains("x-hop:"));
        assert!(!lower.contains("proxy-connection:"));
        let mut body = [0; 7];
        socket.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"payload");
        socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://denied.test/\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nConnection: close, x-private\r\nX-Private: remove\r\nContent-Length: 5\r\n\r\nhello").await.unwrap();
    });
    let request = format!(
        "POST http://target.test:{port}/path%2Fname?x=1 HTTP/1.1\r\nHost: target.test:{port}\r\nProxy-Authorization: {secret}\r\nAuthorization: origin-credential\r\nCookie: own=value\r\nConnection: x-hop\r\nX-Hop: remove\r\nProxy-Connection: keep-alive\r\nContent-Length: 7\r\n\r\npayload"
    );
    let result = exchange(&binding, &request).await;
    status(&result, 302);
    let result = String::from_utf8(result).unwrap().to_ascii_lowercase();
    assert!(result.contains("location: http://denied.test/"));
    assert_eq!(result.matches("set-cookie:").count(), 2);
    assert!(!result.contains("x-private:"));
    assert!(result.ends_with("hello"));
    server.await.unwrap();
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    status(
        &exchange(
            &binding,
            &get("http://denied.test/", "denied.test", &secret),
        )
        .await,
        403,
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    // A subsequent request must re-resolve instead of reusing a previously vetted address.
    *dns.addresses.lock().unwrap() = vec!["169.254.169.254:80".parse().unwrap()];
    status(
        &exchange(
            &binding,
            &get(
                &format!("http://target.test:{port}/"),
                &format!("target.test:{port}"),
                &secret,
            ),
        )
        .await,
        403,
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2);
    gateway.shutdown().await.unwrap();
}

async fn connect(binding: &GatewayBinding, host: &str, port: u16) -> TcpStream {
    let mut socket = TcpStream::connect(binding.address()).await.unwrap();
    let request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: {}\r\n\r\n",
        auth(binding)
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let headers = head(&mut socket).await;
    status(&headers, 200);
    let text = String::from_utf8(headers).unwrap().to_ascii_lowercase();
    assert!(!text.contains("content-length:"));
    assert!(!text.contains("transfer-encoding:"));
    socket
}

#[tokio::test]
async fn connect_is_bidirectional_and_scope_shutdown_joins_both_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dns = resolver(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)]);
    let gateway =
        ScopedEgressGateway::start(dialer(dns, true), policy(port), GatewayBudget::default())
            .await
            .unwrap();
    let binding = gateway.binding();
    let mut downstream = connect(&binding, "target.test", port).await;
    let (mut upstream, _) = listener.accept().await.unwrap();
    downstream.write_all(b"request bytes").await.unwrap();
    let mut data = [0; 13];
    upstream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"request bytes");
    upstream.write_all(b"reply bytes").await.unwrap();
    let mut data = [0; 11];
    downstream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"reply bytes");
    assert_eq!(gateway.stats().forwarded_bytes, 24);
    gateway.shutdown().await.unwrap();
    assert_closed(&mut downstream).await;
    assert_closed(&mut upstream).await;
    assert!(TcpStream::connect(binding.address()).await.is_err());
}

#[tokio::test]
async fn websocket_upgrade_preserves_rfc6455_frames_and_retires_its_driver() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer(resolver(vec!["127.0.0.1:9".parse().unwrap()]), true),
        policy(port),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let bytes = head(&mut stream).await;
        let headers = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(headers.starts_with("get /ws http/1.1"));
        assert!(headers.contains("upgrade: websocket"));
        assert!(headers.contains("connection: upgrade"));
        assert!(!headers.contains("proxy-authorization"));
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
        let mut frame = [0; 9];
        stream.read_exact(&mut frame).await.unwrap();
        assert_eq!(
            &frame,
            &[0x81, 0x83, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2, b'y' ^ 3]
        );
        stream
            .write_all(&[0x81, 3, b'h', b'e', b'y'])
            .await
            .unwrap();
        assert_closed(&mut stream).await;
    });
    let binding = gateway.binding();
    let mut socket = TcpStream::connect(binding.address()).await.unwrap();
    socket.write_all(format!("GET http://target.test:{port}/ws HTTP/1.1\r\nHost: target.test:{port}\r\nProxy-Authorization: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",auth(&binding)).as_bytes()).await.unwrap();
    status(&head(&mut socket).await, 101);
    socket
        .write_all(&[0x81, 0x83, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2, b'y' ^ 3])
        .await
        .unwrap();
    let mut frame = [0; 5];
    socket.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, &[0x81, 3, b'h', b'e', b'y']);
    gateway.shutdown().await.unwrap();
    assert_closed(&mut socket).await;
    server.await.unwrap();
}

#[tokio::test]
async fn denied_shapes_and_declared_body_limit_never_connect() {
    let dns = resolver(vec!["127.0.0.1:9".parse().unwrap()]);
    let gateway = ScopedEgressGateway::start(
        dialer(dns.clone(), true),
        policy(80),
        GatewayBudget {
            request_bytes: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    let auth = auth(&binding);
    for request in [
        format!(
            "CONNECT target.test HTTP/1.1\r\nHost: target.test\r\nProxy-Authorization: {auth}\r\n\r\n"
        ),
        format!(
            "CONNECT target.test:80 HTTP/1.1\r\nHost: target.test:80\r\nProxy-Authorization: {auth}\r\nContent-Length: 1\r\n\r\nx"
        ),
        format!(
            "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\nProxy-Authorization: {auth}\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n"
        ),
    ] {
        status(&exchange(&binding, &request).await, 400);
    }
    let request = format!(
        "POST http://target.test/ HTTP/1.1\r\nHost: target.test\r\nProxy-Authorization: {auth}\r\nContent-Length: 11\r\n\r\n"
    );
    status(&exchange(&binding, &request).await, 413);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn preauth_capacity_idle_lifetime_and_drop_close_owned_connections() {
    let gateway = ScopedEgressGateway::start(
        dialer(resolver(vec![]), false),
        GatewayPolicy::public_web(),
        GatewayBudget {
            connections: 1,
            idle: Duration::from_millis(150),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    let mut first = TcpStream::connect(binding.address()).await.unwrap();
    wait_connections(&gateway, 1).await;
    let mut second = TcpStream::connect(binding.address()).await.unwrap();
    assert_closed(&mut second).await;
    assert_closed(&mut first).await;
    wait_connections(&gateway, 0).await;
    let mut third = TcpStream::connect(binding.address()).await.unwrap();
    wait_connections(&gateway, 1).await;
    drop(gateway);
    assert_closed(&mut third).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer(resolver(vec!["127.0.0.1:9".parse().unwrap()]), true),
        policy(port),
        GatewayBudget {
            connection_lifetime: Duration::from_millis(150),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut socket = connect(&gateway.binding(), "target.test", port).await;
    let (mut peer, _) = listener.accept().await.unwrap();
    assert_closed(&mut socket).await;
    assert_closed(&mut peer).await;
    wait_connections(&gateway, 0).await;
    gateway.shutdown().await.unwrap();
}

#[test]
fn policy_rules_are_canonical_and_do_not_admit_ambiguous_wildcards() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../fixtures/computer/scoped-egress-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["schema"], "openbot-scoped-egress-v1");
    assert!(
        fixture["remaining"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == false)
    );
    let budget = GatewayBudget::default();
    assert_eq!(fixture["defaults"]["connections"], budget.connections);
    assert_eq!(
        fixture["defaults"]["request_body_bytes"],
        budget.request_bytes
    );
    assert_eq!(
        fixture["defaults"]["response_body_bytes"],
        budget.response_bytes
    );
    assert_eq!(
        fixture["defaults"]["tunnel_bytes_both_directions"],
        budget.tunnel_bytes
    );
    assert_eq!(
        fixture["defaults"]["aggregate_bytes_per_second"],
        budget.bytes_per_second
    );
    assert_eq!(fixture["defaults"]["burst_bytes"], budget.burst_bytes);
    assert_eq!(
        fixture["defaults"]["downstream_header_dns_connect_upgrade_ms"],
        budget.handshake.as_millis() as u64
    );
    assert_eq!(
        fixture["defaults"]["idle_ms"],
        budget.idle.as_millis() as u64
    );
    assert_eq!(
        fixture["defaults"]["connection_lifetime_ms"],
        budget.connection_lifetime.as_millis() as u64
    );

    for value in [
        "",
        "*",
        "foo*bar.test",
        "a..test",
        "example.test..",
        "user@host",
        "host/path",
        "*.127.0.0.1",
        "[::1%25lo0]",
    ] {
        assert!(GatewayHostRule::parse(value).is_err());
    }
    assert_eq!(
        GatewayHostRule::parse("EXAMPLE.test.").unwrap(),
        GatewayHostRule::parse("example.test").unwrap()
    );
    assert!(GatewayHostRule::parse("[::1]").is_ok());
    assert!(GatewayPolicy::new(None, vec![], [0]).is_err());
}

#[tokio::test]
async fn deny_rules_override_allowed_subdomains_and_an_empty_allowlist_denies_everything() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dns = resolver(vec!["127.0.0.1:9".parse().unwrap()]);
    let rules = GatewayPolicy::new(
        Some(vec![GatewayHostRule::parse("*.example.test").unwrap()]),
        vec![GatewayHostRule::parse("blocked.example.test").unwrap()],
        [port],
    )
    .unwrap();
    let gateway =
        ScopedEgressGateway::start(dialer(dns.clone(), true), rules, GatewayBudget::default())
            .await
            .unwrap();
    let binding = gateway.binding();
    for host in ["example.test", "blocked.example.test", "wrongexample.test"] {
        let authority = format!("{host}:{port}");
        status(
            &exchange(
                &binding,
                &get(&format!("http://{authority}/"), &authority, &auth(&binding)),
            )
            .await,
            403,
        );
    }
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        head(&mut peer).await;
        peer.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let authority = format!("ok.example.test:{port}");
    status(
        &exchange(
            &binding,
            &get(&format!("http://{authority}/"), &authority, &auth(&binding)),
        )
        .await,
        204,
    );
    server.await.unwrap();
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    gateway.shutdown().await.unwrap();
    let gateway = ScopedEgressGateway::start(
        dialer(dns.clone(), true),
        GatewayPolicy::new(Some(vec![]), vec![], [port]).unwrap(),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    status(
        &exchange(
            &binding,
            &get(&format!("http://{authority}/"), &authority, &auth(&binding)),
        )
        .await,
        403,
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn ipv6_literals_use_the_vetted_numeric_address_without_dns() {
    let listener = TcpListener::bind("[::1]:0")
        .await
        .expect("native IPv6 loopback");
    let port = listener.local_addr().unwrap().port();
    let dns = resolver(vec![]);
    let dialer = SafeDialer::with_resolver(
        EgressPolicy::new(CidrAllowlist::parse_exact(["::1/128"]).unwrap()),
        dns.clone(),
    );
    let policy = GatewayPolicy::new(
        Some(vec![GatewayHostRule::parse("[::1]").unwrap()]),
        vec![],
        [port],
    )
    .unwrap();
    let gateway = ScopedEgressGateway::start(dialer, policy, GatewayBudget::default())
        .await
        .unwrap();
    let mut downstream = connect(&gateway.binding(), "[::1]", port).await;
    let (mut upstream, _) = listener.accept().await.unwrap();
    downstream.write_all(b"ipv6").await.unwrap();
    let mut bytes = [0; 4];
    upstream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ipv6");
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    gateway.shutdown().await.unwrap();
    assert_closed(&mut upstream).await;
}

struct PendingResolver {
    started: tokio::sync::Notify,
    dropped: Arc<AtomicUsize>,
}
struct ResolutionGuard(Arc<AtomicUsize>);
impl Drop for ResolutionGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl DnsResolver for PendingResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        let _guard = ResolutionGuard(self.dropped.clone());
        self.started.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn shutdown_drops_pending_resolution_and_joins_a_stalled_http_driver() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let dns = Arc::new(PendingResolver {
        started: tokio::sync::Notify::new(),
        dropped: dropped.clone(),
    });
    let dialer = SafeDialer::with_resolver(
        EgressPolicy::new(CidrAllowlist::parse_exact([] as [&str; 0]).unwrap()),
        dns.clone(),
    );
    let gateway = ScopedEgressGateway::start(dialer, policy(80), GatewayBudget::default())
        .await
        .unwrap();
    let binding = gateway.binding();
    let client = tokio::spawn(async move {
        exchange(
            &binding,
            &get("http://target.test/", "target.test", &auth(&binding)),
        )
        .await
    });
    timeout(DEADLINE, dns.started.notified()).await.unwrap();
    gateway.shutdown().await.unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(client.await.unwrap().is_empty());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget::default(),
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    let client = tokio::spawn(async move {
        exchange(
            &binding,
            &get(
                &format!("http://target.test:{port}/"),
                &format!("target.test:{port}"),
                &auth(&binding),
            ),
        )
        .await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    head(&mut peer).await;
    gateway.shutdown().await.unwrap();
    assert_closed(&mut peer).await;
    assert!(client.await.unwrap().is_empty());
}

fn dialer_for_loopback() -> SafeDialer {
    dialer(resolver(vec!["127.0.0.1:9".parse().unwrap()]), true)
}

#[tokio::test]
async fn body_and_tunnel_byte_limits_are_enforced_while_data_flows() {
    // Unknown-length HTTP response: the over-budget frame must never reach the downstream.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget {
            response_bytes: 8,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        head(&mut peer).await;
        peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ngood\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = peer.write_all(b"9\r\nforbidden\r\n0\r\n\r\n").await;
        assert_closed(&mut peer).await;
    });
    let binding = gateway.binding();
    let response = exchange(
        &binding,
        &get(
            &format!("http://target.test:{port}/"),
            &format!("target.test:{port}"),
            &auth(&binding),
        ),
    )
    .await;
    status(&response, 200);
    assert!(!response.windows(9).any(|bytes| bytes == b"forbidden"));
    assert!(!response.ends_with(b"0\r\n\r\n"));
    assert!(gateway.stats().forwarded_bytes <= 8);
    server.await.unwrap();
    gateway.shutdown().await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget {
            tunnel_bytes: 6,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut client = connect(&gateway.binding(), "target.test", port).await;
    let (mut peer, _) = listener.accept().await.unwrap();
    client.write_all(b"1234").await.unwrap();
    let mut bytes = [0; 4];
    peer.read_exact(&mut bytes).await.unwrap();
    peer.write_all(b"567").await.unwrap();
    assert_closed(&mut client).await;
    assert_closed(&mut peer).await;
    assert_eq!(gateway.stats().forwarded_bytes, 4);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_chunked_upload_cannot_forward_its_over_budget_suffix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget {
            request_bytes: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let binding = gateway.binding();
    let mut client = TcpStream::connect(binding.address()).await.unwrap();
    client.write_all(format!("POST http://target.test:{port}/ HTTP/1.1\r\nHost: target.test:{port}\r\nProxy-Authorization: {}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n",auth(&binding)).as_bytes()).await.unwrap();
    let (mut peer, _) = timeout(DEADLINE, listener.accept()).await.unwrap().unwrap();
    let headers = head(&mut peer).await;
    assert!(
        String::from_utf8(headers)
            .unwrap()
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    );
    let mut first = [0; 10];
    timeout(DEADLINE, peer.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&first, b"5\r\n12345\r\n");
    client.write_all(b"6\r\nabcdef\r\n0\r\n\r\n").await.unwrap();
    let mut result = Vec::new();
    timeout(DEADLINE, client.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    status(&result, 502);
    let mut tail = Vec::new();
    timeout(DEADLINE, peer.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(!tail.windows(6).any(|bytes| bytes == b"abcdef"));
    assert_eq!(gateway.stats().forwarded_bytes, 5);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn aggregate_bandwidth_is_shared_between_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget {
            burst_bytes: 16 * 1024,
            bytes_per_second: 32 * 1024,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut first = connect(&gateway.binding(), "target.test", port).await;
    let (mut first_peer, _) = listener.accept().await.unwrap();
    let mut second = connect(&gateway.binding(), "target.test", port).await;
    let (mut second_peer, _) = listener.accept().await.unwrap();
    let payload = vec![b'x'; 16 * 1024];
    let started = tokio::time::Instant::now();
    first.write_all(&payload).await.unwrap();
    second.write_all(&payload).await.unwrap();
    let (mut a, mut b) = (vec![0; 16 * 1024], vec![0; 16 * 1024]);
    timeout(DEADLINE, async {
        tokio::try_join!(
            first_peer.read_exact(&mut a),
            second_peer.read_exact(&mut b)
        )
        .unwrap();
    })
    .await
    .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "a per-connection burst would incorrectly admit both payloads immediately"
    );
    assert!(a == payload && b == payload);
    assert_eq!(gateway.stats().forwarded_bytes, 32 * 1024);
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn activity_in_one_direction_keeps_a_tunnel_alive_then_idle_closes_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gateway = ScopedEgressGateway::start(
        dialer_for_loopback(),
        policy(port),
        GatewayBudget {
            idle: Duration::from_millis(150),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut client = connect(&gateway.binding(), "target.test", port).await;
    let (mut peer, _) = listener.accept().await.unwrap();
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
    }
    assert_closed(&mut client).await;
    assert_closed(&mut peer).await;
    wait_connections(&gateway, 0).await;
    gateway.shutdown().await.unwrap();
}

// Existing W-7 non-production test CA/leaf/key, SAN=idp.test; no host trust is modified.
const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY_DER_BASE64: &str =
    "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[tokio::test]
async fn https_connect_carries_real_tls_with_client_side_certificate_verification() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let root = CertificateDer::from(STANDARD.decode(TEST_CA_DER_BASE64).unwrap());
    let certificate = CertificateDer::from(STANDARD.decode(TEST_LEAF_DER_BASE64).unwrap());
    let key = PrivateKeyDer::try_from(STANDARD.decode(TEST_KEY_DER_BASE64).unwrap()).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(crypto.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let client_config = ClientConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let policy = GatewayPolicy::new(
        Some(vec![GatewayHostRule::parse("idp.test").unwrap()]),
        vec![],
        [port],
    )
    .unwrap();
    let gateway =
        ScopedEgressGateway::start(dialer_for_loopback(), policy, GatewayBudget::default())
            .await
            .unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tls.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() < 4096);
        }
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("GET /tls HTTP/1.1"));
        assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    });
    let socket = connect(&gateway.binding(), "idp.test", port).await;
    let mut tls = timeout(
        DEADLINE,
        connector.connect(ServerName::try_from("idp.test").unwrap(), socket),
    )
    .await
    .unwrap()
    .unwrap();
    tls.write_all(b"GET /tls HTTP/1.1\r\nHost: idp.test\r\n\r\n")
        .await
        .unwrap();
    let mut result = Vec::new();
    timeout(DEADLINE, tls.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    status(&result, 200);
    assert!(result.ends_with(b"tls-ok"));
    server.await.unwrap();
    gateway.shutdown().await.unwrap();
}
