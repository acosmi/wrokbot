//! Dedicated integration verification for §10.5a / PA-06 / V5-EGRESS-01.
//!
//! Verifies egress enforcement plan compilation, fidelity reporting, and that
//! policies requiring TLS inner inspection fail closed before network/bind.

use std::net::SocketAddr;
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
    EgressFidelity, GatewayBinding, GatewayBudget, GatewayError, GatewayHostRule, GatewayPolicy,
    ScopedEgressGateway, bind_attempts,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(3);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct MockResolver {
    calls: AtomicUsize,
    addresses: Mutex<Vec<SocketAddr>>,
}

#[async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addresses.lock().unwrap().clone())
    }
}

fn test_dialer(resolver: Arc<MockResolver>) -> SafeDialer {
    SafeDialer::with_resolver(
        EgressPolicy::new(CidrAllowlist::parse_exact(vec!["127.0.0.1/32"]).unwrap()),
        resolver,
    )
}

fn destination_policy(port: u16) -> GatewayPolicy {
    GatewayPolicy::new(
        Some(vec![GatewayHostRule::parse("target.test").unwrap()]),
        vec![],
        [port],
    )
    .unwrap()
}

fn basic_auth(binding: &GatewayBinding) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            binding.username(),
            binding.expose_password()
        ))
    )
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

#[tokio::test]
async fn controller_review_plan_cannot_be_reused_with_different_destination_policy() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec![]),
    });
    let plan = destination_policy(80).compile_plan().unwrap();
    let before = bind_attempts();
    let result = ScopedEgressGateway::start_with_plan(
        test_dialer(dns.clone()),
        plan,
        destination_policy(8080),
        GatewayBudget::default(),
    )
    .await;
    let rejected = result.is_err();
    if let Ok(gateway) = result {
        gateway.shutdown().await.unwrap();
    }
    assert!(
        rejected,
        "a compiled plan must describe the exact policy used by its gateway"
    );
    assert_eq!(before, bind_attempts());
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn destination_policy_reports_network_destination_enforced_fidelity() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec!["127.0.0.1:80".parse().unwrap()]),
    });
    let policy = destination_policy(80);
    assert!(!policy.requires_strong_tls_enforcement());

    let plan = policy.compile_plan().expect("destination plan compiles");
    assert_eq!(plan.fidelity(), EgressFidelity::NetworkDestinationEnforced);
    assert_eq!(plan.fidelity().as_str(), "network_destination_enforced");

    let gateway =
        ScopedEgressGateway::start(test_dialer(dns.clone()), policy, GatewayBudget::default())
            .await
            .expect("gateway starts for destination-only policy");

    assert_eq!(
        gateway.fidelity(),
        EgressFidelity::NetworkDestinationEnforced
    );
    assert_eq!(
        format!("{}", gateway.fidelity()),
        "network_destination_enforced"
    );

    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn three_categories_of_tls_strong_rules_fail_closed_before_network_and_bind() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec!["127.0.0.1:443".parse().unwrap()]),
    });

    let initial_binds = bind_attempts();

    // Category 1: TLS inner authority and URL path inspection
    let policy_path = destination_policy(443).with_tls_inner_path_enforcement();
    assert!(policy_path.requires_strong_tls_enforcement());
    assert!(matches!(
        policy_path.compile_plan(),
        Err(GatewayError::EgressPolicyUnsupported)
    ));
    let res1 = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        policy_path,
        GatewayBudget::default(),
    )
    .await;
    assert!(matches!(
        res1.err(),
        Some(GatewayError::EgressPolicyUnsupported)
    ));
    assert_eq!(bind_attempts(), initial_binds);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);

    // Category 2: Same-connection multi-authority inspection
    let policy_multi = destination_policy(443).with_same_connection_multi_authority_enforcement();
    assert!(policy_multi.requires_strong_tls_enforcement());
    assert!(matches!(
        policy_multi.compile_plan(),
        Err(GatewayError::EgressPolicyUnsupported)
    ));
    let res2 = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        policy_multi,
        GatewayBudget::default(),
    )
    .await;
    assert!(matches!(
        res2.err(),
        Some(GatewayError::EgressPolicyUnsupported)
    ));
    assert_eq!(bind_attempts(), initial_binds);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);

    // Category 3: Encrypted redirect inspection inside TLS
    let policy_redirect = destination_policy(443).with_encrypted_redirect_enforcement();
    assert!(policy_redirect.requires_strong_tls_enforcement());
    assert!(matches!(
        policy_redirect.compile_plan(),
        Err(GatewayError::EgressPolicyUnsupported)
    ));
    let res3 = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        policy_redirect,
        GatewayBudget::default(),
    )
    .await;
    assert!(matches!(
        res3.err(),
        Some(GatewayError::EgressPolicyUnsupported)
    ));
    assert_eq!(bind_attempts(), initial_binds);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gateway_enforces_auth_host_and_port_refusals() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec!["127.0.0.1:80".parse().unwrap()]),
    });
    let gateway = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        destination_policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();

    let binding = gateway.binding();

    // 1. Missing authentication
    let no_auth = "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\n\r\n";
    let resp = exchange(&binding, no_auth).await;
    assert!(resp.starts_with(b"HTTP/1.1 407 "));

    // 2. Denied host
    let denied_host = format!(
        "GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\nProxy-Authorization: {}\r\n\r\n",
        basic_auth(&binding)
    );
    let resp = exchange(&binding, &denied_host).await;
    assert!(resp.starts_with(b"HTTP/1.1 403 "));

    // 3. Denied port
    let denied_port = format!(
        "GET http://target.test:8080/ HTTP/1.1\r\nHost: target.test:8080\r\nProxy-Authorization: {}\r\n\r\n",
        basic_auth(&binding)
    );
    let resp = exchange(&binding, &denied_port).await;
    assert!(resp.starts_with(b"HTTP/1.1 403 "));

    // Destination checks reject before attempting DNS
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);

    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_revocation_closes_existing_and_rejects_new_connections() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec!["127.0.0.1:80".parse().unwrap()]),
    });
    let gateway = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        destination_policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();

    let binding = gateway.binding().clone();
    let addr = binding.address();

    // Connect a socket before shutdown
    let mut socket = TcpStream::connect(addr).await.unwrap();

    // Explicit shutdown revokes capability
    gateway.shutdown().await.unwrap();

    // The existing socket should now be closed / EOF
    let mut buf = [0_u8; 1];
    let res = socket.read(&mut buf).await;
    assert!(matches!(res, Ok(0)) || res.is_err());

    // New connection attempts to the retired listener address must fail
    let new_conn = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await;
    assert!(new_conn.is_err() || new_conn.unwrap().is_err());
}

#[tokio::test]
async fn cannot_bypass_enforcement_with_mismatched_plan_or_request_header() {
    let _lock = TEST_LOCK.lock().await;
    let dns = Arc::new(MockResolver {
        calls: AtomicUsize::new(0),
        addresses: Mutex::new(vec!["127.0.0.1:80".parse().unwrap()]),
    });

    // 1. Forged/mismatched plan rejection: passing destination plan to strong TLS policy
    let dest_policy = destination_policy(80);
    let dest_plan = dest_policy.compile_plan().unwrap();

    let tls_policy = destination_policy(443).with_tls_inner_path_enforcement();
    let initial_binds = bind_attempts();

    let start_res = ScopedEgressGateway::start_with_plan(
        test_dialer(dns.clone()),
        dest_plan,
        tls_policy,
        GatewayBudget::default(),
    )
    .await;
    assert!(matches!(
        start_res.err(),
        Some(GatewayError::EgressPolicyUnsupported)
    ));
    assert_eq!(bind_attempts(), initial_binds);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);

    // 2. Client request header cannot elevate fidelity
    let gateway = ScopedEgressGateway::start(
        test_dialer(dns.clone()),
        destination_policy(80),
        GatewayBudget::default(),
    )
    .await
    .unwrap();

    let binding = gateway.binding();
    let spoof_req = format!(
        "GET http://target.test/ HTTP/1.1
Host: target.test
Proxy-Authorization: {}
X-Egress-Fidelity: https_request_policy_enforced

",
        basic_auth(&binding)
    );
    let _ = exchange(&binding, &spoof_req).await;

    // Fidelity remains network destination enforced
    assert_eq!(
        gateway.fidelity(),
        EgressFidelity::NetworkDestinationEnforced
    );
    assert_eq!(gateway.fidelity().as_str(), "network_destination_enforced");

    gateway.shutdown().await.unwrap();
}
