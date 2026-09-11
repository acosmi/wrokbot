// Reuses this repository's W-7 owned test certificate, never a vendor credential.
#[derive(Clone)]
struct ResponsePlan {
    status: u16,
    body: String,
    location: Option<String>,
    extra_headers: String,
    header_gate: Option<Arc<Semaphore>>,
    body_gate: Option<Arc<Semaphore>>,
}
impl ResponsePlan {
    fn ok(body: String) -> Self {
        Self {
            status: 200,
            body,
            location: None,
            extra_headers: String::new(),
            header_gate: None,
            body_gate: None,
        }
    }
}
#[derive(Clone)]
struct Capture {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct LocalResolver {
    address: SocketAddr,
    expected_host: String,
    calls: AtomicUsize,
    fail_after_first: bool,
}
#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if host != self.expected_host
            || port != self.address.port()
            || (self.fail_after_first && n > 0)
        {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}
struct TlsFixture {
    address: SocketAddr,
    root: CertificateDer<'static>,
    captures: Arc<Mutex<Vec<Capture>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    closed: Arc<AtomicUsize>,
    tls_failures: Arc<AtomicUsize>,
}
impl TlsFixture {
    async fn new(plans: Vec<ResponsePlan>) -> Self {
        let root = CertificateDer::from(STANDARD.decode(TEST_CA_DER_BASE64).unwrap());
        let leaf = CertificateDer::from(STANDARD.decode(TEST_LEAF_DER_BASE64).unwrap());
        let key = PrivateKeyDer::try_from(STANDARD.decode(TEST_KEY_DER_BASE64).unwrap()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(![39025, 39027].contains(&address.port()));
        let captures = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(plans)));
        let seen = captures.clone();
        let planned = queue.clone();
        let (stop, mut stopped) = oneshot::channel();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed_task = closed.clone();
        let tls_failures = Arc::new(AtomicUsize::new(0));
        let tls_failures_task = tls_failures.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let tls = tls.clone();
                        let seen = seen.clone();
                        let planned = planned.clone();
                        let closed = closed_task.clone();
                        let tls_failures = tls_failures_task.clone();
                        children.spawn(async move {
                            let mut stream = match tls.accept(stream).await {
                                Ok(stream) => stream,
                                Err(_) => {
                                    tls_failures.fetch_add(1, Ordering::SeqCst);
                                    return;
                                }
                            };
                            let Some(capture) = read_http(&mut stream).await else { return; };
                            let mut plan = planned.lock().unwrap().pop_front()
                                .expect("owned fixture has no planned response");
                            plan.body = plan.body.replace("OWNED_ORIGIN", &format!("https://idp.test:{}", address.port()));
                            seen.lock().unwrap().push(capture);
                            if let Some(gate) = &plan.header_gate {
                                let mut probe = [0u8];
                                tokio::select! {
                                    permit = gate.acquire() => { let Ok(permit) = permit else { return; }; permit.forget(); }
                                    _ = stream.read(&mut probe) => { closed.fetch_add(1, Ordering::SeqCst); return; }
                                }
                            }
                            let extra = plan.location.as_ref()
                                .map(|url| format!("Location: {url}\r\n")).unwrap_or_default();
                            let retry = if plan.status == 429 { "Retry-After: 1\r\n" } else { "" };
                            let headers = format!(
                                "HTTP/1.1 {} OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n{extra}{retry}{}\r\n",
                                plan.status, plan.body.len(), plan.extra_headers
                            );
                            if stream.write_all(headers.as_bytes()).await.is_err() { return; }
                            if let Some(gate) = &plan.body_gate {
                                let mut probe = [0u8];
                                tokio::select! {
                                    permit = gate.acquire() => { let Ok(permit) = permit else { return; }; permit.forget(); }
                                    _ = stream.read(&mut probe) => { closed.fetch_add(1, Ordering::SeqCst); return; }
                                }
                            }
                            let _ = stream.write_all(plan.body.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                    },
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            address,
            root,
            captures,
            stop: Some(stop),
            task: Some(task),
            closed,
            tls_failures,
        }
    }
    fn endpoint(&self) -> String {
        self.endpoint_for_host("idp.test")
    }
    fn endpoint_for_host(&self, host: &str) -> String {
        format!("https://{host}:{}", self.address.port())
    }
    fn dialer_with(&self, fail_after_first: bool, allow: bool) -> SafeDialer {
        self.dialer_for_host("idp.test", fail_after_first, allow, true)
    }
    fn dialer_for_host(
        &self,
        host: &str,
        fail_after_first: bool,
        allow: bool,
        trust_test_ca: bool,
    ) -> SafeDialer {
        let policy = EgressPolicy::new(
            CidrAllowlist::parse_exact(if allow { vec!["127.0.0.1/32"] } else { vec![] }).unwrap(),
        );
        let resolver = Arc::new(LocalResolver {
            address: self.address,
            expected_host: host.to_owned(),
            calls: AtomicUsize::new(0),
            fail_after_first,
        });
        if !trust_test_ca {
            return SafeDialer::with_resolver(policy, resolver);
        }
        SafeDialer::with_extra_roots(policy, resolver, [self.root.clone()]).unwrap()
    }
    fn count(&self) -> usize {
        self.captures.lock().unwrap().len()
    }
    async fn wait_count(&self, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.count() < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "owned TLS request deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}
impl Drop for TlsFixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn read_http<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Capture> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let split = loop {
        let n = stream.read(&mut buffer).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 8 * 1024 * 1024 {
            return None;
        }
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8(bytes[..split].to_vec()).ok()?;
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.into();
    let path = first.next()?.into();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < split + length {
        let n = stream.read(&mut buffer).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    let body = bytes[split..split + length].to_vec();
    Some(Capture {
        method,
        path,
        headers,
        body,
    })
}
fn chat_text() -> String {
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"id":"chat-owned","choices":[{"index":0,"delta":{"content":"hello custom"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}})
    )
}

const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY_DER_BASE64: &str =
    "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
