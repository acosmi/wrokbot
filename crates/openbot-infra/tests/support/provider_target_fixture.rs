//! Owned TLS canary for exact-target tests. No vendor credentials or host trust changes.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

pub struct Reply {
    pub content_type: &'static str,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct RawRequest {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub header_counts: BTreeMap<String, usize>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub dns: usize,
    pub tcp: usize,
    pub http: usize,
}

pub struct WireRecord {
    pub counts: Counts,
    pub requests: Vec<RawRequest>,
    pub joined: usize,
    pub failed: usize,
}

struct Resolver {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if host != "idp.test" || port != self.address.port() {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}

pub struct OwnedWire {
    address: SocketAddr,
    root: CertificateDer<'static>,
    dns: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<RawRequest>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<(usize, usize)>>,
}

impl OwnedWire {
    pub async fn new(replies: Vec<Reply>, certificate: [&str; 3]) -> Self {
        let root = CertificateDer::from(STANDARD.decode(certificate[0]).unwrap());
        let leaf = CertificateDer::from(STANDARD.decode(certificate[1]).unwrap());
        let key = PrivateKeyDer::try_from(STANDARD.decode(certificate[2]).unwrap()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(![39025, 39027].contains(&address.port()));
        let dns = Arc::new(AtomicUsize::new(0));
        let tcp = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plans = Arc::new(Mutex::new(VecDeque::from(replies)));
        let (stop, mut stopped) = oneshot::channel();
        let accepted = tcp.clone();
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            let mut joined = 0;
            let mut failed = 0;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    connection = listener.accept() => {
                        let (stream, _) = connection.unwrap();
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let tls = acceptor.clone();
                        let captured = captured.clone();
                        let plans = plans.clone();
                        children.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(8), async move {
                                let mut stream = tls.accept(stream).await.unwrap();
                                let request = read_request(&mut stream).await;
                                captured.lock().unwrap().push(request);
                                let reply = plans.lock().unwrap().pop_front()
                                    .expect("unexpected actual HTTP request reached canary");
                                let body = reply.body.replace("OWNED_ORIGIN", &format!("https://idp.test:{}", address.port()));
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    reply.content_type, body.len()
                                );
                                stream.write_all(header.as_bytes()).await.unwrap();
                                stream.write_all(body.as_bytes()).await.unwrap();
                                // SDK may close after its terminal SSE marker; that does not
                                // change the captured request or imply an HTTP EOF observation.
                                let _ = stream.shutdown().await;
                            }).await.expect("owned TLS connection deadline");
                        });
                    },
                    result = children.join_next(), if !children.is_empty() => {
                        joined += 1;
                        failed += usize::from(result.unwrap().is_err());
                    }
                }
            }
            drop(listener);
            // Stop accepting, then join every bounded connection, including any failed child.
            while let Some(result) = children.join_next().await {
                joined += 1;
                failed += usize::from(result.is_err());
            }
            (joined, failed)
        });
        Self {
            address,
            root,
            dns,
            tcp,
            requests,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub fn origin(&self) -> String {
        format!("https://idp.test:{}", self.address.port())
    }

    pub fn dialer(&self) -> SafeDialer {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap()),
            Arc::new(Resolver {
                address: self.address,
                calls: self.dns.clone(),
            }),
            [self.root.clone()],
        )
        .unwrap()
    }

    pub fn counts(&self) -> Counts {
        Counts {
            dns: self.dns.load(Ordering::SeqCst),
            tcp: self.tcp.load(Ordering::SeqCst),
            http: self.requests.lock().unwrap().len(),
        }
    }

    pub fn requests(&self) -> Vec<RawRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub async fn finish(mut self) -> WireRecord {
        self.stop.take().unwrap().send(()).unwrap();
        let (joined, failed) = self.task.take().unwrap().await.unwrap();
        WireRecord {
            counts: self.counts(),
            requests: self.requests(),
            joined,
            failed,
        }
    }
}

impl Drop for OwnedWire {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> RawRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let split = loop {
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(n > 0, "HTTP header EOF");
        bytes.extend_from_slice(&buffer[..n]);
        assert!(bytes.len() <= 8 * 1024 * 1024, "owned request size");
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            assert!(pos < 64 * 1024, "owned header size");
            break pos + 4;
        }
        assert!(bytes.len() <= 64 * 1024, "owned header size");
    };
    let head = String::from_utf8(bytes[..split].to_vec()).unwrap();
    let mut lines = head.lines();
    let parts: Vec<_> = lines.next().unwrap().split_whitespace().collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2], "HTTP/1.1");
    let mut headers = BTreeMap::new();
    let mut header_counts = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        let name = name.to_ascii_lowercase();
        *header_counts.entry(name.clone()).or_insert(0) += 1;
        headers.insert(name, value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map_or(0, |v| v.parse::<usize>().unwrap());
    assert!(length <= 8 * 1024 * 1024 - split);
    assert!(!headers.contains_key("transfer-encoding"));
    while bytes.len() < split + length {
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(n > 0, "HTTP body EOF");
        bytes.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(
        bytes.len(),
        split + length,
        "no bytes beyond framed request"
    );
    RawRequest {
        method: parts[0].to_owned(),
        target: parts[1].to_owned(),
        headers,
        header_counts,
        body: bytes[split..].to_vec(),
    }
}
