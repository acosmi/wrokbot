//! Owned synthetic Host, PG and TLS producers. Production authority and transaction code are unchanged.
use super::super::*;
use super::{GatewayAuthorizationJournal, GatewayAuthorizationJournalRuntimeOwner};
use openbot_domain::vault::SecretBytes;
use openbot_infra::GatewayAuthorizationCancellationToken as CancellationToken;
use openbot_infra::db::tables::gateway_authorization_attempts::Row as AttemptRow;
use openbot_infra::db::{
    fresh,
    pool::{self, DatabaseConfig},
};
use openbot_infra::gateway_account::{GatewayAccountClient, GatewayDesktopMetadata};
use openbot_infra::gateway_transport::*;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use serde_json::Value;
use std::{
    io::{BufRead as _, Read as _, Write as _},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};

pub(super) mod harness {
    use std::future::Future;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
pub(super) const DEP: &str = "owned-journal-deployment";
pub(super) const TENANT: &str = "owned-journal-tenant";
pub(super) const ACTOR: &str = "owned-journal-owner";
pub(super) const COOKIE: &str = "owned-journal-cookie-00000000000001";
pub(super) const NEXT_COOKIE: &str = "owned-journal-cookie-00000000000002";
pub(super) const INSTALLATION: &str =
    "2828282828282828282828282828282828282828282828282828282828282828";
pub(super) const REDIRECT: &str = "http://127.0.0.1:48281/callback";
const SESSION_KEY: &[u8] = b"owned-journal-session-hash-key";

pub(super) struct Fixture {
    pub(super) config: DatabaseConfig,
    pub(super) pool: pool::DatabasePool,
    pub(super) runtime: Option<Arc<GatewayAuthorizationJournalRuntimeOwner>>,
    pub(super) journal: Arc<GatewayAuthorizationJournal>,
    pub(super) resolver: Arc<PostgresSessionAuthResolver>,
    tls: Option<OwnedTls>,
}
impl Fixture {
    pub(super) async fn new(config: DatabaseConfig, size: usize) -> Result<Self, String> {
        let config = config.with_max_pool_size(size);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut client).await.map_err(|e| e.to_string())?;
        client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('owned-journal-owner','journal@example.test',7),('owned-journal-other','other@example.test',7),('dev-local-user','dev@openbot.local',7); INSERT INTO public.user_roles(user_id,role) VALUES('owned-journal-owner','user'),('owned-journal-other','user'),('dev-local-user','admin');").await.map_err(|e|e.to_string())?;
        let now = OffsetDateTime::now_utc();
        for (id, cookie) in [
            ("owned-journal-session", COOKIE),
            ("owned-journal-next-session", NEXT_COOKIE),
        ] {
            let hash = SessionTokenHash::compute(
                SessionToken::new(cookie.as_bytes()),
                SessionHashKey::new(SESSION_KEY),
            )
            .to_column_value();
            client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,7)",&[&id,&ACTOR,&hash,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e|e.to_string())?;
        }
        drop(client);
        let env = crate::config::EnvMap::from([(
            "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
            INSTALLATION.to_owned(),
        )]);
        let config_value =
            crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
        let (runtime, journal) = assemble_gateway_authorization_journal(
            &config_value,
            pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x28; 32]),
        )
        .map_err(|e| e.to_string())?
        .ok_or("configured journal missing")?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                openbot_infra::auth::config::default_session_lifetime(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(|e| e.to_string())?,
        );
        resolver
            .install_gateway_authorization_journal(&journal)
            .map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            config,
            pool,
            runtime: Some(runtime),
            journal,
            resolver,
            tls: Some(OwnedTls::new("journal")?),
        })
    }
    pub(super) async fn auth(&self) -> Result<AuthContext, String> {
        self.auth_cookie(COOKIE).await
    }
    pub(super) async fn auth_cookie(&self, cookie: &str) -> Result<AuthContext, String> {
        self.resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-journal")
                    .header("cookie", format!("openbot_session={cookie}"))
                    .body(())
                    .map_err(|e| e.to_string())?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())
    }
    pub(super) fn fresh_pair(
        &self,
    ) -> Result<
        (
            Arc<GatewayAuthorizationJournalRuntimeOwner>,
            Arc<GatewayAuthorizationJournal>,
        ),
        String,
    > {
        fresh_pair(
            self.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
    }
    pub(super) async fn single(
        &self,
        journal: &Arc<GatewayAuthorizationJournal>,
    ) -> Result<SingleUserAuthResolver, String> {
        let principal = openbot_infra::auth::single_user::load_single_user_principal(
            &self.pool,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
        )
        .await
        .map_err(|e| e.to_string())?;
        let resolver = SingleUserAuthResolver::from_verified_principal(
            principal,
            openbot_infra::auth::config::default_session_lifetime(),
        );
        resolver
            .install_gateway_authorization_journal(journal, &self.pool)
            .map_err(|e| format!("{e:?}"))?;
        Ok(resolver)
    }
    pub(super) async fn metadata(
        &self,
        parent: CancellationToken,
    ) -> Result<GatewayDesktopMetadata, String> {
        let tls = self.tls.as_ref().ok_or("owned TLS closed")?;
        let origin = tls.endpoint();
        let oauth = GatewayOAuthEndpoints::new(
            GatewayOAuthProfile::Desktop,
            &format!("{origin}/oauth/desktop/register"),
            &format!("{origin}/oauth/desktop/token"),
            Some(&format!("{origin}/oauth/desktop/revoke")),
        )
        .map_err(|e| e.to_string())?;
        let factory = GatewayTransportFactory::new(
            tls.dialer()?,
            VerifiedGatewayEndpoints::new(&origin, None, Some(oauth)).map_err(|e| e.to_string())?,
            GatewayTransportLimits::new(Duration::from_secs(10), 65536)
                .map_err(|e| e.to_string())?,
        );
        let transport = factory
            .for_operation(
                Arc::new(DiscoveryOnly),
                Arc::new(DiscoveryObserved),
                tokio::time::Instant::now() + Duration::from_secs(15),
                Duration::from_secs(2),
            )
            .map_err(|e| e.to_string())?;
        let client = GatewayAccountClient::new(&origin, transport).map_err(|e| e.to_string())?;
        client
            .fetch_metadata(parent)
            .await
            .map_err(|e| e.to_string())
    }
    pub(super) fn issuer(&self) -> String {
        self.tls.as_ref().unwrap().endpoint()
    }
    pub(super) async fn rows(&self) -> Result<Vec<AttemptRow>, String> {
        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        client.query("SELECT * FROM openbot_internal.gateway_authorization_attempts ORDER BY created_at,attempt_id",&[]).await.map_err(|e|e.to_string())?.iter().map(|row|AttemptRow::try_from(row).map_err(|e|e.to_string())).collect()
    }
    pub(super) async fn row(&self, id: uuid::Uuid) -> Result<AttemptRow, String> {
        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one(
                "SELECT * FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1",
                &[&id],
            )
            .await
            .map_err(|e| e.to_string())?;
        AttemptRow::try_from(&row).map_err(|e| e.to_string())
    }
    pub(super) async fn audits(&self) -> Result<Vec<Value>, String> {
        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        Ok(client.query("SELECT payload FROM public.audit_events WHERE event_type LIKE 'gateway_authorization_%' ORDER BY created_at,id",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect())
    }
    pub(super) async fn direct(&self) -> Result<pool::DatabasePool, String> {
        pool::connect(&self.config.clone().with_max_pool_size(2))
            .await
            .map_err(|e| e.to_string())
    }
    pub(super) fn disarm_host(&self) {
        self.resolver.close_request_bindings();
    }
    pub(super) fn captures(&self) -> Result<Vec<Value>, String> {
        self.tls.as_ref().ok_or("owned TLS absent")?.captures()
    }
    pub(super) async fn finish(mut self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        if let Some(runtime) = self.runtime.take() {
            runtime.close();
        }
        let tls = self.tls.take().ok_or("owned TLS absent")?;
        let captures = tls.captures()?;
        if captures
            .iter()
            .any(|x| x["method"] != "GET" || x["authorization"] != Value::Null)
        {
            return Err("unexpected journal TLS dispatch".into());
        }
        let closed = tls.finish();
        self.pool.close();
        eprintln!(
            "GATEWAY_JOURNAL_FIXTURE setup_discovery_gets={} registration_posts=0 token_posts=0 pool_closed={} individual_production_driver_join=UNPROVEN",
            captures.len(),
            self.pool.is_closed()
        );
        closed
    }
}
pub(super) fn fresh_pair(
    pool: pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
) -> Result<
    (
        Arc<GatewayAuthorizationJournalRuntimeOwner>,
        Arc<GatewayAuthorizationJournal>,
    ),
    String,
> {
    let env = crate::config::EnvMap::from([(
        "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
        INSTALLATION.to_owned(),
    )]);
    let config = crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
    assemble_gateway_authorization_journal(
        &config,
        pool,
        deployment,
        tenant,
        SecretBytes::new(vec![0x28; 32]),
    )
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "configured journal missing".to_owned())
}
pub(super) fn session_resolver(
    pool: pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
) -> Result<Arc<PostgresSessionAuthResolver>, String> {
    Ok(Arc::new(
        PostgresSessionAuthResolver::new(
            pool,
            SESSION_KEY,
            openbot_infra::auth::config::default_session_lifetime(),
            deployment,
            tenant,
        )
        .map_err(|e| e.to_string())?,
    ))
}
struct DiscoveryOnly;
struct DiscoveryPermit;
struct DiscoveryObserved;
#[async_trait::async_trait]
impl GatewayHttpAuthority for DiscoveryOnly {
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        cancel: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        if request.kind() != GatewayRequestKind::OAuthDiscovery || cancel.is_cancelled() {
            return Err(GatewayFenceError::Refused);
        }
        Ok(Box::new(DiscoveryPermit))
    }
}
#[async_trait::async_trait]
impl GatewayHttpPermit for DiscoveryPermit {
    async fn release_after_headers(self: Box<Self>) -> Result<(), GatewayFenceError> {
        Ok(())
    }
}
impl GatewayHttpOutcomes for DiscoveryObserved {
    fn started(&self, _: GatewayAttempt) {}
}

// The Python interpreter is an explicit Root-frozen test input. It only owns this fixture's
// random temporary directory, listener and child process; it never changes system trust.
struct OwnedTls {
    root: PathBuf,
    child: Option<Child>,
    address: SocketAddr,
    ca: Vec<u8>,
    stdout_reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
    root_removed: bool,
}

impl OwnedTls {
    fn new(label: &str) -> Result<Self, String> {
        let interpreter = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_TLS_PYTHON")
                .ok_or("Root-pinned Python TLS interpreter missing")?,
        );
        if !interpreter.is_absolute() {
            return Err("TLS interpreter must be an absolute pinned input".to_owned());
        }
        let root = std::env::temp_dir().join(format!(
            "openbot-journal-owned-tls-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let child = Command::new(interpreter)
            .args(["-I", "-u", "-c", PYTHON_TLS])
            .arg(&root)
            .args([TEST_CA, TEST_LEAF, TEST_KEY])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut fixture = Self {
            root,
            child: Some(child),
            address: "127.0.0.1:0".parse().unwrap(),
            ca: Vec::new(),
            stdout_reader: None,
            root_removed: false,
        };
        let stdout = fixture
            .child
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .ok_or("owned TLS stdout missing")?;
        let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
        fixture.stdout_reader = Some(std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            let bytes = reader
                .by_ref()
                .take(8193)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            if bytes == 0 || bytes > 8192 {
                return Err("owned TLS startup output missing or unbounded".to_owned());
            }
            ready_send.send(line).map_err(|e| e.to_string())?;
            let mut tail = Vec::new();
            reader
                .take(65537)
                .read_to_end(&mut tail)
                .map_err(|e| e.to_string())?;
            if tail.len() > 65536 {
                return Err("owned TLS stdout tail exceeded budget".to_owned());
            }
            Ok(tail)
        }));
        let line = ready_receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("owned TLS startup not acknowledged: {e}"))?;
        let ready: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let port = ready["port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("owned TLS port invalid")?;
        if port == 0 || [39025, 39027].contains(&port) {
            return Err("owned TLS port is outside fixture policy".to_owned());
        }
        fixture.address = SocketAddr::from(([127, 0, 0, 1], port));
        fixture.ca = serde_json::from_value(ready["ca"].clone()).map_err(|e| e.to_string())?;
        eprintln!(
            "GATEWAY_JOURNAL_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
            fixture.child.as_ref().unwrap().id(),
            fixture.root.display()
        );
        Ok(fixture)
    }
    fn endpoint(&self) -> String {
        format!("https://idp.test:{}", self.address.port())
    }
    fn dialer(&self) -> Result<SafeDialer, String> {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|e| e.to_string())?,
            ),
            Arc::new(OwnedDns(self.address)),
            [self.ca.clone().into()],
        )
        .map_err(|e| e.to_string())
    }
    fn release(&self) -> Result<(), String> {
        std::fs::write(self.root.join("release"), b"owned").map_err(|e| e.to_string())
    }
    fn captures(&self) -> Result<Vec<Value>, String> {
        let path = self.root.join("captures.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
            return Err("owned TLS captures exceeded budget".to_owned());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let captures: Vec<Value> = contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if captures.len() > 64 {
            return Err("owned TLS capture count exceeded budget".to_owned());
        }
        Ok(captures)
    }
    fn finish(mut self) -> Result<(), String> {
        self.release()?;
        let child = self.child.as_mut().ok_or("owned TLS child absent")?;
        child
            .stdin
            .as_mut()
            .ok_or("owned TLS stop channel absent")?
            .write_all(b"x")
            .map_err(|e| e.to_string())?;
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if !status.success() {
                    return Err("owned TLS child did not exit naturally with zero".to_owned());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("owned TLS child did not acknowledge stop".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = child.id();
        drop(self.child.take());
        let tail = self
            .stdout_reader
            .take()
            .ok_or("owned TLS stdout reader absent")?
            .join()
            .map_err(|_| "owned TLS stdout reader panicked")??;
        let stopped: Value = serde_json::from_slice(&tail).map_err(|e| e.to_string())?;
        if stopped["stopped"] != true {
            return Err("owned TLS stop output missing".to_owned());
        }
        let count = self.captures()?.len();
        std::fs::remove_dir_all(&self.root).map_err(|e| e.to_string())?;
        if self.root.exists() {
            return Err("owned TLS root survived cleanup".to_owned());
        }
        self.root_removed = true;
        eprintln!(
            "GATEWAY_JOURNAL_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
            self.root.display()
        );
        Ok(())
    }
}
impl Drop for OwnedTls {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("GATEWAY_JOURNAL_OWNED_TLS fallback_kill=true natural_stop_unproven=true");
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if !self.root_removed {
            eprintln!(
                "GATEWAY_JOURNAL_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
                self.root.display()
            );
        }
    }
}
struct OwnedDns(SocketAddr);
#[async_trait]
impl DnsResolver for OwnedDns {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        if host == "idp.test" && port == self.0.port() {
            Ok(vec![self.0])
        } else {
            Err(DnsUnavailable)
        }
    }
}

const PYTHON_TLS: &str = r#"
import base64,http.server,json,os,pathlib,ssl,sys,threading
root=pathlib.Path(sys.argv[1]); os.umask(0o077)
ca,leaf,key=[base64.b64decode(x,validate=True) for x in sys.argv[2:5]]
def pem(kind,data): return ('-----BEGIN '+kind+'-----\n'+base64.encodebytes(data).decode()+'-----END '+kind+'-----\n')
(root/'leaf.pem').write_text(pem('CERTIFICATE',leaf)); (root/'key.pem').write_text(pem('PRIVATE KEY',key))
stop=threading.Event(); count=0
def stopping(): sys.stdin.buffer.read(1); stop.set()
thread=threading.Thread(target=stopping); thread.start()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        global count
        self.connection.settimeout(5)
        if self.path!='/.well-known/oauth-authorization-server/desktop' or count>=64: raise RuntimeError('owned discovery path/budget')
        if self.headers.get('Authorization') is not None: raise RuntimeError('owned discovery carried bearer')
        origin='https://idp.test:'+str(self.server.server_port)
        data=json.dumps({'issuer':origin,'authorization_endpoint':origin+'/oauth/desktop/authorize','token_endpoint':origin+'/oauth/desktop/token','registration_endpoint':origin+'/oauth/desktop/register','revocation_endpoint':origin+'/oauth/desktop/revoke','scopes_supported':['ai','account'],'response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'grant_types_supported':['authorization_code','refresh_token'],'crabcode_auth_contract_version':2,'gateway_error_contract_version':1},separators=(',',':')).encode()
        count+=1
        with (root/'captures.jsonl').open('a') as f: f.write(json.dumps({'method':'GET','path':self.path,'authorization':None},separators=(',',':'))+'\n'); f.flush()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
    def do_POST(self): raise RuntimeError('journal test must never dispatch registration or tokens')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'leaf.pem',root/'key.pem')
class Server(http.server.HTTPServer):
    def get_request(self):
        raw,address=self.socket.accept(); raw.settimeout(3)
        try: return context.wrap_socket(raw,server_side=True),address
        except BaseException: raw.close(); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=.2
print(json.dumps({'port':server.server_port,'ca':list(ca)}),flush=True)
try:
    while not stop.is_set(): server.handle_request()
finally: server.server_close(); stop.set(); thread.join(timeout=2)
if thread.is_alive(): raise RuntimeError('owned stop reader did not join')
print(json.dumps({'stopped':True,'requests':count}),flush=True)
"#;

// Existing repository non-production W7 CA/leaf/key, SAN=idp.test. Never installed in OS trust.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

// Select only the original journal transaction on its real backend, never a v2 classifier.
#[derive(Clone, Copy, Debug)]
pub(super) enum TerminalStage {
    CreateCommit,
    AdmitCommit,
    CloseCommit,
    ReadbackRollback,
}
impl TerminalStage {
    fn command(self) -> &'static [u8] {
        if matches!(self, Self::ReadbackRollback) {
            b"ROLLBACK\0"
        } else {
            b"COMMIT\0"
        }
    }
    fn sql_bits(self, sql: &[u8]) -> u8 {
        let Ok(sql) = std::str::from_utf8(sql) else {
            return 0;
        };
        let canonical = sql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let (marker, body) = if let Some(comment) = canonical.strip_prefix("/* ") {
            let Some((marker, body)) = comment.split_once(" */") else {
                return 0;
            };
            (Some(marker), body.trim_start())
        } else {
            (None, canonical.as_str())
        };
        let assignments = body.split(" where ").next().unwrap_or(body);
        let journal = match self {
            Self::CreateCommit => {
                marker == Some("gateway_authorization_attempt_created")
                    && body
                        .starts_with("insert into openbot_internal.gateway_authorization_attempts")
            }
            Self::AdmitCommit => {
                marker == Some("gateway_authorization_registration_admitted")
                    && assignments
                        .starts_with("update openbot_internal.gateway_authorization_attempts")
                    && assignments.contains("registration_admitted_at")
                    && !assignments.contains("finished_at")
            }
            Self::CloseCommit => {
                marker == Some("gateway_authorization_attempt_closed")
                    && assignments
                        .starts_with("update openbot_internal.gateway_authorization_attempts")
                    && assignments.contains("finished_at")
                    && assignments.contains("outcome_code")
            }
            Self::ReadbackRollback => {
                marker == Some("gateway_authorization_exact_readback")
                    && body.starts_with("select ")
                    && body.contains("from openbot_internal.gateway_authorization_attempts")
                    && !body.contains("for update")
            }
        };
        let audit = body.starts_with("insert into public.audit_events");
        u8::from(journal) | (u8::from(audit) << 1)
    }
    fn complete_bits(self) -> u8 {
        if matches!(self, Self::ReadbackRollback) {
            1
        } else {
            3
        }
    }
}

struct TerminalGateState {
    stage: TerminalStage,
    discard: bool,
    armed: std::sync::atomic::AtomicBool,
    claimed: std::sync::atomic::AtomicBool,
    original_backend_pid: AtomicUsize,
    selected_backend_pid: AtomicUsize,
    stage_seen: AtomicUsize,
    begins: AtomicUsize,
    commits: AtomicUsize,
    rollbacks: AtomicUsize,
    command_acks: AtomicUsize,
    ready_acks: AtomicUsize,
    forwarded_acks: AtomicUsize,
    accepted: AtomicUsize,
    joined: AtomicUsize,
    held: Semaphore,
    release: Semaphore,
    forwarded: Semaphore,
}
pub(super) struct PgTerminalAckGate {
    pub(super) config: DatabaseConfig,
    state: Arc<TerminalGateState>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), String>>>,
}
impl PgTerminalAckGate {
    pub(super) async fn new(config: &DatabaseConfig, stage: TerminalStage, discard: bool) -> Self {
        assert_eq!(config.host, "127.0.0.1");
        let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut routed = config.clone();
        routed.port = listener.local_addr().unwrap().port();
        assert!(![39025, 39027].contains(&routed.port));
        let state = Arc::new(TerminalGateState {
            stage,
            discard,
            armed: std::sync::atomic::AtomicBool::new(false),
            claimed: std::sync::atomic::AtomicBool::new(false),
            original_backend_pid: AtomicUsize::new(0),
            selected_backend_pid: AtomicUsize::new(0),
            stage_seen: AtomicUsize::new(0),
            begins: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            rollbacks: AtomicUsize::new(0),
            command_acks: AtomicUsize::new(0),
            ready_acks: AtomicUsize::new(0),
            forwarded_acks: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            joined: AtomicUsize::new(0),
            held: Semaphore::new(0),
            release: Semaphore::new(0),
            forwarded: Semaphore::new(0),
        });
        eprintln!(
            "GATEWAY_JOURNAL_TERMINAL_RELAY_START owned_process_pid={} stage={stage:?} relay_port={} upstream_port={}",
            std::process::id(),
            routed.port,
            config.port
        );
        let shared = state.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (downstream, _) = accepted.map_err(|_| "terminal relay accept")?;
                        let count = shared.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        if count > 64 || children.len() >= 32 {
                            return Err("terminal relay bounded connection limit".into());
                        }
                        children.spawn(terminal_relay_connection(downstream, upstream, shared.clone()));
                    },
                    Some(child) = children.join_next(), if !children.is_empty() => {
                        child.map_err(|_| "terminal relay child join")??;
                        shared.joined.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            drop(listener);
            // The Pool/assembly are closed before stop. Normal success must reap
            // every owned relay child, without abort_all or a synthetic join ACK.
            tokio::time::timeout(Duration::from_secs(8), async {
                while let Some(child) = children.join_next().await {
                    child.map_err(|_| "terminal relay tail child join")??;
                    shared.joined.fetch_add(1, Ordering::SeqCst);
                }
                Ok::<(), String>(())
            })
            .await
            .map_err(|_| "terminal relay normal tail deadline")??;
            Ok(())
        });
        Self {
            config: routed,
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub(super) async fn arm_original(&self, f: &Fixture) -> pool::ConnectionObservation {
        assert_eq!(f.pool.status().max_size, 1);
        let client = f.pool.get().await.unwrap();
        let backend: i32 = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        assert!(backend > 0);
        let original = client.observation();
        assert!(!original.snapshot().retirement_requested);
        assert!(!original.snapshot().connection_destroyed);
        self.state
            .original_backend_pid
            .store(backend as usize, Ordering::SeqCst);
        drop(client);
        self.state.armed.store(true, Ordering::SeqCst);
        original
    }
    pub(super) async fn held(&self) {
        tokio::time::timeout(Duration::from_secs(6), self.state.held.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
    pub(super) fn original_pid(&self) -> i32 {
        i32::try_from(self.state.original_backend_pid.load(Ordering::SeqCst)).unwrap()
    }
    pub(super) async fn release_original_ack(&self) {
        assert!(!self.state.discard);
        self.state.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), self.state.forwarded.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        // A successful socket write is not driver receipt or join. Allow the
        // real driver to run while the original business future stays unpolled;
        // only its later real owner result can establish known-late state.
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    pub(super) fn assert_target(&self, expected_forwarded: usize) {
        assert_eq!(
            self.state.selected_backend_pid.load(Ordering::SeqCst),
            self.state.original_backend_pid.load(Ordering::SeqCst)
        );
        assert_ne!(self.state.selected_backend_pid.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 1);
        assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 1);
        assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.state.forwarded_acks.load(Ordering::SeqCst),
            expected_forwarded
        );
        assert_eq!(self.state.begins.load(Ordering::SeqCst), 1);
        match self.state.stage {
            TerminalStage::CreateCommit
            | TerminalStage::AdmitCommit
            | TerminalStage::CloseCommit => {
                assert_eq!(self.state.commits.load(Ordering::SeqCst), 1);
                assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 0);
            }
            _ => {
                assert_eq!(self.state.commits.load(Ordering::SeqCst), 0);
                assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 1);
            }
        }
    }
    pub(super) async fn stop(mut self) {
        self.state.armed.store(false, Ordering::SeqCst);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let mut task = self.task.take().unwrap();
        match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("terminal relay did not naturally join");
            }
        }
        let accepted = self.state.accepted.load(Ordering::SeqCst);
        let joined = self.state.joined.load(Ordering::SeqCst);
        assert_eq!(accepted, joined);
        eprintln!(
            "GATEWAY_JOURNAL_TERMINAL_RELAY stage={:?} backend_pid={} accepted={} naturally_joined={} command_ack={} ready_ack={} forwarded_ack={} listener_closed=true",
            self.state.stage,
            self.state.selected_backend_pid.load(Ordering::SeqCst),
            accepted,
            joined,
            self.state.command_acks.load(Ordering::SeqCst),
            self.state.ready_acks.load(Ordering::SeqCst),
            self.state.forwarded_acks.load(Ordering::SeqCst)
        );
    }
}
impl Drop for PgTerminalAckGate {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            eprintln!(
                "GATEWAY_JOURNAL_TERMINAL_RELAY fallback_abort=true normal_join_unproven=true"
            );
            task.abort();
        }
    }
}
fn pg_statement(tag: u8, bytes: &[u8]) -> Option<&[u8]> {
    let sql = match tag {
        b'Q' => bytes,
        b'P' => &bytes[bytes.iter().position(|b| *b == 0)? + 1..],
        _ => return None,
    };
    Some(&sql[..sql.iter().position(|b| *b == 0)?])
}
async fn terminal_relay_connection(
    mut downstream: TcpStream,
    upstream_address: SocketAddr,
    state: Arc<TerminalGateState>,
) -> Result<(), String> {
    let mut upstream = TcpStream::connect(upstream_address)
        .await
        .map_err(|_| "terminal upstream connect")?;
    let len = downstream
        .read_u32()
        .await
        .map_err(|_| "terminal startup length")?;
    if !(8..=65536).contains(&len) {
        return Err("terminal startup bound".into());
    }
    let mut startup = vec![0; len as usize - 4];
    downstream
        .read_exact(&mut startup)
        .await
        .map_err(|_| "terminal startup read")?;
    upstream
        .write_u32(len)
        .await
        .map_err(|_| "terminal startup header")?;
    upstream
        .write_all(&startup)
        .await
        .map_err(|_| "terminal startup forwarding")?;
    if len == 16 && startup[..4] == 80877102_u32.to_be_bytes() {
        // Forward the actual cancellation packet without inventing a terminal ACK.
        upstream
            .shutdown()
            .await
            .map_err(|_| "terminal cancel forwarding shutdown")?;
        return Ok(());
    }
    if startup[..4] != 196608_u32.to_be_bytes() {
        return Err("terminal relay requires original NoTls protocol3 startup".into());
    }
    let (mut down_read, mut down_write) = downstream.into_split();
    let (mut up_read, mut up_write) = upstream.into_split();
    let backend = Arc::new(AtomicUsize::new(0));
    let selected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let client_state = state.clone();
    let client_backend = backend.clone();
    let client_selected = selected.clone();
    let client = async move {
        let mut stage_bits = 0;
        let mut seen_stage = false;
        let mut original_begin = false;
        let mut original_read_only = false;
        while let Some((tag, bytes)) = terminal_frame(&mut down_read).await? {
            if client_state.armed.load(Ordering::SeqCst)
                && client_backend.load(Ordering::SeqCst)
                    == client_state.original_backend_pid.load(Ordering::SeqCst)
                && client_backend.load(Ordering::SeqCst) != 0
            {
                if tag == b'Q'
                    && (bytes.starts_with(b"START TRANSACTION") || bytes.starts_with(b"BEGIN"))
                {
                    stage_bits = 0;
                    seen_stage = false;
                    let query = std::str::from_utf8(&bytes).map_err(|_| "terminal BEGIN UTF8")?;
                    original_begin = query.contains("ISOLATION LEVEL READ COMMITTED");
                    original_read_only = query.contains("READ ONLY");
                }
                if let Some(sql) = pg_statement(tag, &bytes) {
                    stage_bits |= client_state.stage.sql_bits(sql);
                    if stage_bits == client_state.stage.complete_bits() && !seen_stage {
                        if !original_begin
                            || original_read_only
                                != matches!(client_state.stage, TerminalStage::ReadbackRollback)
                        {
                            return Err(
                                "terminal original business RC/read-only mode mismatch".into()
                            );
                        }
                        seen_stage = true;
                        client_state.begins.fetch_add(1, Ordering::SeqCst);
                        client_state.stage_seen.fetch_add(1, Ordering::SeqCst);
                    }
                }
                if tag == b'Q' && seen_stage {
                    if bytes.eq_ignore_ascii_case(b"COMMIT\0") {
                        client_state.commits.fetch_add(1, Ordering::SeqCst);
                    }
                    if bytes.eq_ignore_ascii_case(b"ROLLBACK\0") {
                        client_state.rollbacks.fetch_add(1, Ordering::SeqCst);
                    }
                    if seen_stage
                        && bytes.eq_ignore_ascii_case(client_state.stage.command())
                        && client_state
                            .claimed
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        client_state
                            .selected_backend_pid
                            .store(client_backend.load(Ordering::SeqCst), Ordering::SeqCst);
                        client_selected.store(true, Ordering::SeqCst);
                    }
                }
            }
            up_write
                .write_u8(tag)
                .await
                .map_err(|_| "terminal frontend tag write")?;
            up_write
                .write_u32(bytes.len() as u32 + 4)
                .await
                .map_err(|_| "terminal frontend length write")?;
            up_write
                .write_all(&bytes)
                .await
                .map_err(|_| "terminal frontend body write")?;
            if tag == b'Q'
                && (bytes.eq_ignore_ascii_case(b"COMMIT\0")
                    || bytes.eq_ignore_ascii_case(b"ROLLBACK\0"))
            {
                stage_bits = 0;
                seen_stage = false;
                original_begin = false;
                original_read_only = false;
            }
        }
        Ok::<(), String>(())
    };
    let server = async move {
        let mut command_complete = None;
        while let Some((tag, bytes)) = terminal_frame(&mut up_read).await? {
            if tag == b'K' {
                if bytes.len() != 8 {
                    return Err("terminal BackendKeyData shape".into());
                }
                backend.store(
                    u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
                    Ordering::SeqCst,
                );
            }
            if selected.load(Ordering::SeqCst) {
                if tag == b'C' && bytes == state.stage.command() {
                    if command_complete.is_some() {
                        return Err("terminal original CommandComplete mismatch".into());
                    }
                    state.command_acks.fetch_add(1, Ordering::SeqCst);
                    command_complete = Some(bytes);
                    continue;
                }
                if tag == b'Z' && command_complete.is_some() {
                    let completion = command_complete
                        .take()
                        .ok_or("terminal ReadyForQuery without original C")?;
                    if bytes != b"I" {
                        return Err("terminal original ACK did not leave idle".into());
                    }
                    state.ready_acks.fetch_add(1, Ordering::SeqCst);
                    state.held.add_permits(1);
                    if state.discard {
                        return Ok(());
                    }
                    tokio::time::timeout(Duration::from_secs(8), state.release.acquire())
                        .await
                        .map_err(|_| "terminal original ACK release deadline")?
                        .map_err(|_| "terminal original ACK release closed")?
                        .forget();
                    down_write
                        .write_u8(b'C')
                        .await
                        .map_err(|_| "terminal C write")?;
                    down_write
                        .write_u32(completion.len() as u32 + 4)
                        .await
                        .map_err(|_| "terminal C length")?;
                    down_write
                        .write_all(&completion)
                        .await
                        .map_err(|_| "terminal C body")?;
                    down_write
                        .write_u8(b'Z')
                        .await
                        .map_err(|_| "terminal Z write")?;
                    down_write
                        .write_u32(bytes.len() as u32 + 4)
                        .await
                        .map_err(|_| "terminal Z length")?;
                    down_write
                        .write_all(&bytes)
                        .await
                        .map_err(|_| "terminal Z body")?;
                    state.forwarded_acks.fetch_add(1, Ordering::SeqCst);
                    state.forwarded.add_permits(1);
                    selected.store(false, Ordering::SeqCst);
                    continue;
                }
                // An earlier prepared Statement Drop can still have CloseComplete/
                // ReadyForQuery on this same socket. Forward those until the exact
                // target C is seen; they never count as the target terminal ACK.
                if tag == b'E' || (command_complete.is_some() && tag != b'N') {
                    return Err("terminal unexpected backend frame around original ACK".into());
                }
            }
            down_write
                .write_u8(tag)
                .await
                .map_err(|_| "terminal backend tag write")?;
            down_write
                .write_u32(bytes.len() as u32 + 4)
                .await
                .map_err(|_| "terminal backend length write")?;
            down_write
                .write_all(&bytes)
                .await
                .map_err(|_| "terminal backend body write")?;
        }
        Ok::<(), String>(())
    };
    tokio::select! { result = client => result, result = server => result }
}
async fn terminal_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    let tag = match reader.read_u8().await {
        Ok(tag) => tag,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err("terminal frame tag IO".into()),
    };
    let len = reader
        .read_u32()
        .await
        .map_err(|_| "terminal partial frame length")?;
    if !(4..=8 * 1024 * 1024).contains(&len) {
        return Err("terminal frame bound".into());
    }
    let mut bytes = vec![0; len as usize - 4];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "terminal partial frame body")?;
    Ok(Some((tag, bytes)))
}
