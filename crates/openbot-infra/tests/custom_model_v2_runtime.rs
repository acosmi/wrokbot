//! Real current-dataset v2 provider starts against owned PG, original Vault and loopback TLS.
#![cfg(feature = "server-runtime")]
mod harness;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{
    AgentContextSource, BeginThreadRunV2Request, ProviderAdapter, ProviderEvent, ProviderPortError,
    ProviderRequest, ProviderRoute, ProviderSession, RunExecutionLease, ThreadDirectory,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRunV2, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    model_connections::*,
};
use openbot_domain::{
    thread::FencingToken,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer, SafeHttpBudget,
};
use openbot_infra::{
    db::{
        fresh,
        pool::{self, DatabaseConfig},
    },
    model_connections::PostgresModelConnections,
    provider::{context::PostgresAgentContextSource, custom::PostgresCustomModelProvider},
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
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
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use zeroize::Zeroizing;

use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::versioned_model_selection::{
    ModelSelectionIntentSource, RunModelSelectionV2,
};
struct ClosedProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}
async fn assemble(
    p: &pool::DatabasePool,
    config: &DatabaseConfig,
    vault: &CredentialRecordVault,
) -> openbot_infra::application_assembly::PostgresApplicationAssembly {
    use openbot_infra::application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    };
    let policy_store = openbot_infra::policy::PolicyStore::postgres(p.clone(), None);
    policy_store.load().await.unwrap();
    assemble_postgres_application(PostgresApplicationAssemblyInput {
        pool: p.clone(),
        listener_database: config.clone().into(),
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        single_user: false,
        admin_floor: None,
        model: "owned-model".into(),
        credential_key_id: "owned-key-ref".into(),
        credential_vault: vault.clone(),
        audit_key: SecretBytes::new(vec![0x62; 32]),
        remote_assertions: Arc::new(
            openbot_domain::remote_callback::RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap(),
        ),
        mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
        policy_store,
        ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
        screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
        artifacts: None,
        runtime_capabilities: None,
        remote_agent_probe: Arc::new(ClosedProbe),
        managed_slot_available: false,
        channel_routing_provider: ChannelRoutingProviderInput {
            endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
            environment_api_key: None,
            egress_allow_cidrs: vec!["127.0.0.1/32".into()],
            allow_http: true,
        },
        stall_timeout: Some(Duration::from_secs(2)),
        oauth_public_url: None,
        app_url: None,
    })
    .await
    .unwrap()
}

const DEP: &str = "custom-runtime-dep";
const TENANT: &str = "custom-runtime-tenant";
const OWNER: &str = "custom-runtime";
const KEY: &str = "OWNED_CUSTOM_MODEL_CANARY";
fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    directory: PostgresThreadDirectory,
    models: Arc<PostgresModelConnections>,
    vault: CredentialRecordVault,
    binding: Arc<openbot_infra::model_dataset::PostgresModelDatasetBinding>,
    registry: Option<Arc<openbot_infra::artifact_registry::ArtifactDatasetRegistry>>,
    assembly: openbot_infra::application_assembly::PostgresApplicationAssembly,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Self {
        Self::new_size(config, 6).await
    }
    async fn new_size(config: DatabaseConfig, size: usize) -> Self {
        let config = config.with_max_pool_size(size);
        let pool = pool::connect(&config).await.unwrap();
        let mut c = pool.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','alice@example.test',7),('bob','bob@example.test',3);INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Bot','built_in','{\"systemPrompt\":\"Standing prompt.\",\"providerSource\":\"managed\"}');INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Bot','','seed','public');INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Channel','',ARRAY[]::text[],ARRAY[]::text[]);INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x71; 32]).unwrap(),
        );
        let models = PostgresModelConnections::new(
            pool.clone(),
            vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x72; 32]),
        )
        .unwrap();
        let registry = Arc::new(
            openbot_infra::artifact_registry::ArtifactDatasetRegistry::from_server(
                pool.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .unwrap(),
        );
        let assembly = assemble(&pool, &config, &vault).await;
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            OWNER.into(),
            time::Duration::seconds(30),
        )
        .unwrap()
        .with_model_dataset_binding(binding.clone())
        .unwrap();
        Self {
            binding,
            registry: Some(registry),
            assembly,
            pool,
            directory,
            models: Arc::new(models),
            vault,
        }
    }
    fn context(&self) -> PostgresAgentContextSource {
        PostgresAgentContextSource::new(
            self.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            Some(32),
        )
        .unwrap()
        .with_model_dataset_binding(self.binding.clone())
        .unwrap()
    }
    fn adapter(&self, dialer: SafeDialer, timeout: Duration) -> PostgresCustomModelProvider {
        PostgresCustomModelProvider::new(
            self.pool.clone(),
            self.vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            dialer,
            SafeHttpBudget::new(64 * 1024 * 1024, timeout).unwrap(),
            Some(Duration::from_secs(2)),
        )
        .unwrap()
        .with_model_dataset_binding(self.binding.clone())
        .unwrap()
    }
    async fn begin(
        &self,
        index: u64,
        protocol: CustomModelProtocol,
        endpoint: &str,
        channel: bool,
    ) -> (ModelConnection, BeginThreadRunV2Request, ProviderRequest) {
        let model = self
            .models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Chosen connection".into(),
                    protocol,
                    endpoint: endpoint.into(),
                    model: "exact-chosen-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new(KEY.into())).unwrap(),
                },
            )
            .await
            .unwrap();
        let mut entropy = [0; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        let req = BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("custom-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "User prompt".into(),
                selected_skill_slugs: vec![],
                model_selection: RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    model.id.clone(),
                    model.revision,
                    format!("custom:{}", model.id),
                    1,
                )
                .unwrap(),
            },
        };
        self.directory
            .begin_thread_run_v2(req.clone())
            .await
            .unwrap();
        let request = self.context().load(&lease(&req)).await.unwrap();
        (model, req, request)
    }
    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
        let observations = self.pool.connection_observations();
        self.pool.close();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        for o in observations {
            assert_eq!(
                o.wait_for_destruction_before(deadline).await.unwrap(),
                pool::ConnectionDestruction::ConnectionDestroyed
            );
        }
    }
}

fn lease(req: &BeginThreadRunV2Request) -> RunExecutionLease {
    RunExecutionLease::new(
        req.command.run_id.clone(),
        req.command.thread_id.clone(),
        req.command.bot_id.clone(),
        req.actor.clone(),
        FencingToken::new(1).unwrap(),
        0,
    )
    .unwrap()
}
fn update(model: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: model.revision,
        name: model.name.clone(),
        protocol: model.protocol,
        endpoint: model.endpoint.clone(),
        model: model.model.clone(),
        enabled: model.enabled,
        api_key: None,
    }
}
#[derive(Clone)]
struct ResponsePlan {
    status: u16,
    body: String,
    location: Option<String>,
    header_gate: Option<Arc<Semaphore>>,
    body_gate: Option<Arc<Semaphore>>,
}
impl ResponsePlan {
    fn ok(body: String) -> Self {
        Self {
            status: 200,
            body,
            location: None,
            header_gate: None,
            body_gate: None,
        }
    }
    fn retry() -> Self {
        Self {
            status: 429,
            body: "{}".into(),
            location: None,
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
    body: Value,
}
struct LocalResolver {
    address: SocketAddr,
    calls: AtomicUsize,
    fail_after_first: bool,
}
#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if host != "idp.test" || port != self.address.port() || (self.fail_after_first && n > 0) {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}
struct TlsFixture {
    address: SocketAddr,
    root: CertificateDer<'static>,
    captures: Arc<Mutex<Vec<Capture>>>,
    plans: Arc<Mutex<VecDeque<ResponsePlan>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
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
                        children.spawn(async move {
                            let Ok(mut stream) = tls.accept(stream).await else { return; };
                            let Some(capture) = read_http(&mut stream).await else { return; };
                            let plan = planned.lock().unwrap().pop_front()
                                .unwrap_or_else(|| ResponsePlan::ok(chat_text()));
                            seen.lock().unwrap().push(capture);
                            if let Some(gate) = &plan.header_gate {
                                let Ok(permit) = gate.acquire().await else { return; };
                                permit.forget();
                            }
                            let extra = plan.location.as_ref()
                                .map(|url| format!("Location: {url}\r\n")).unwrap_or_default();
                            let retry = if plan.status == 429 { "Retry-After: 1\r\n" } else { "" };
                            let headers = format!(
                                "HTTP/1.1 {} OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n{extra}{retry}\r\n",
                                plan.status, plan.body.len()
                            );
                            if stream.write_all(headers.as_bytes()).await.is_err() { return; }
                            if let Some(gate) = &plan.body_gate {
                                let Ok(permit) = gate.acquire().await else { return; };
                                permit.forget();
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
            plans: queue,
            stop: Some(stop),
            task: Some(task),
        }
    }
    fn endpoint(&self) -> String {
        format!("https://idp.test:{}/v1", self.address.port())
    }
    fn dialer(&self) -> SafeDialer {
        self.dialer_with(false, true)
    }
    fn dialer_with(&self, fail_after_first: bool, allow: bool) -> SafeDialer {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(if allow { vec!["127.0.0.1/32"] } else { vec![] })
                    .unwrap(),
            ),
            Arc::new(LocalResolver {
                address: self.address,
                calls: AtomicUsize::new(0),
                fail_after_first,
            }),
            [self.root.clone()],
        )
        .unwrap()
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
    let body = if length == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[split..split + length]).ok()?
    };
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
fn responses_text() -> String {
    [
 json!({"type":"response.created","response":{"id":"responses-owned"},"sequence_number":0}),
 json!({"type":"response.output_text.delta","output_index":0,"delta":"hello custom","sequence_number":1}),
 json!({"type":"response.completed","response":{"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}},"sequence_number":2})].into_iter().map(|v|format!("data: {v}\n\n")).collect()
}
fn anthropic_text() -> String {
    [
 json!({"type":"message_start","message":{"id":"anthropic-owned","content":[],"usage":{"input_tokens":2,"output_tokens":0}}}),
 json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
 json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello custom"}}),
 json!({"type":"content_block_stop","index":0}),json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),json!({"type":"message_stop"})].into_iter().map(|v|format!("data: {v}\n\n")).collect()
}
async fn events(mut session: Box<dyn ProviderSession>) -> Vec<ProviderEvent> {
    let mut out = vec![];
    while let Some(event) = session.next_event().await.unwrap() {
        out.push(event);
    }
    out
}

const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY_DER_BASE64: &str =
    "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default, Default)]
struct NoFallback(AtomicUsize);
#[async_trait]
impl ProviderAdapter for NoFallback {
    async fn start(
        &self,
        _: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProviderPortError::InvalidRequest {
            field: "unexpected_legacy",
        })
    }
}
fn retried(inner: Arc<dyn ProviderAdapter>) -> openbot_agent::RetryingProvider {
    openbot_agent::RetryingProvider::new(
        inner,
        openbot_agent::RetryingProviderConfig {
            max_retries: 1,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(100),
            jitter: false,
        },
    )
    .unwrap()
}
fn refused(result: Result<Box<dyn ProviderSession>, ProviderPortError>) {
    assert!(
        matches!(result, Err(ProviderPortError::InvalidRequest { .. })),
        "expected pre-adapter closed authority"
    );
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn v2_three_protocols_repeat_original_dataset_context_and_real_sampling() {
    let admin = harness::admin_config("v2_runtime_three_tls");
    harness::with_temp_database(&admin, "v2runtimethreetls", |config| async move {
        let f = Fixture::new(config).await;
        let tls = TlsFixture::new(vec![
            ResponsePlan::ok(chat_text()),
            ResponsePlan::ok(chat_text()),
            ResponsePlan::ok(responses_text()),
            ResponsePlan::ok(responses_text()),
            ResponsePlan::ok(anthropic_text()),
            ResponsePlan::ok(anthropic_text()),
        ])
        .await;
        for (index, protocol) in [
            CustomModelProtocol::OpenaiChatCompletions,
            CustomModelProtocol::OpenaiResponses,
            CustomModelProtocol::AnthropicMessages,
        ]
        .into_iter()
        .enumerate()
        {
            let (model, req, request) = f
                .begin(index as u64 + 1, protocol, &tls.endpoint(), index % 2 == 1)
                .await;
            let ProviderRoute::CustomModel(binding) = &request.route else {
                panic!("explicit v2 must be custom")
            };
            let snapshot = binding.v2_snapshot().expect("complete V2 details retained");
            assert_eq!(snapshot.selection(), &req.command.model_selection);
            assert_eq!(snapshot.dataset().binding_schema(), 1);
            assert_eq!(
                snapshot.credential_policy().as_str(),
                "custom_fixed_secret_revision_v1"
            );
            assert_eq!(binding.endpoint(), model.endpoint);
            assert_eq!(binding.model(), model.model);
            for sampling in 0..2 {
                let next = f.context().load(&lease(&req)).await.unwrap();
                assert_eq!(next.route, request.route);
                let output = events(
                    f.adapter(tls.dialer(), Duration::from_secs(5))
                        .start(next)
                        .await
                        .unwrap(),
                )
                .await;
                assert!(output.iter().any(
                    |e| matches!(e,ProviderEvent::TextDelta{delta,..}if delta=="hello custom")
                ));
                assert_eq!(output.last(), Some(&ProviderEvent::Completed));
                let capture = tls.captures.lock().unwrap()[index * 2 + sampling].clone();
                assert_eq!(capture.method, "POST");
                assert_eq!(
                    capture.path,
                    url::Url::parse(&model.endpoint).unwrap().path()
                );
                assert_eq!(capture.body["model"], model.model);
                assert_eq!(capture.body["stream"], true);
                for hidden in [
                    "modelSelection",
                    "datasetId",
                    "credentialPolicy",
                    "connectionId",
                    "secretId",
                    "authGeneration",
                    KEY,
                ] {
                    assert!(!capture.body.to_string().contains(hidden));
                }
                match protocol {
                    CustomModelProtocol::AnthropicMessages => {
                        assert_eq!(capture.headers["x-api-key"], KEY);
                        assert_eq!(capture.headers["anthropic-version"], "2023-06-01");
                    }
                    _ => assert_eq!(capture.headers["authorization"], format!("Bearer {KEY}")),
                }
            }
        }
        assert_eq!(tls.count(), 6);
        assert!(tls.plans.lock().unwrap().is_empty());
        tls.stop().await;
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn v2_retry_reopens_current_catalog_connection_and_actor_without_legacy_fallback() {
    let admin = harness::admin_config("v2_runtime_retry");
    harness::with_temp_database(&admin, "v2runtimeretry", |config| async move {
        let f = Fixture::new(config).await;
        for mode in 0..3 {
            let tls =
                TlsFixture::new(vec![ResponsePlan::retry(), ResponsePlan::ok(chat_text())]).await;
            let (model, _, request) = f
                .begin(
                    20 + mode,
                    CustomModelProtocol::OpenaiChatCompletions,
                    &tls.endpoint(),
                    false,
                )
                .await;
            let fallback = Arc::new(NoFallback::default());
            let router = openbot_agent::ProviderRouter::new(fallback.clone(), None)
                .with_custom(Arc::new(f.adapter(tls.dialer(), Duration::from_secs(5))));
            let task = tokio::spawn(async move { retried(Arc::new(router)).start(request).await });
            tls.wait_count(1).await;
            if mode == 1 {
                let mut edit = update(&model);
                edit.model = "owned-changed-after-429".into();
                f.models.update(&auth(), &model.id, &edit).await.unwrap();
            }
            if mode == 2 {
                f.pool
                    .get()
                    .await
                    .unwrap()
                    .execute(
                        "UPDATE public.users SET auth_generation=8 WHERE id='alice'",
                        &[],
                    )
                    .await
                    .unwrap();
            }
            let result = tokio::time::timeout(Duration::from_secs(8), task)
                .await
                .unwrap()
                .unwrap();
            if mode == 0 {
                assert_eq!(
                    events(result.unwrap()).await.last(),
                    Some(&ProviderEvent::Completed)
                );
                assert_eq!(tls.count(), 2);
            } else {
                refused(result);
                assert_eq!(tls.count(), 1);
            }
            assert_eq!(fallback.0.load(Ordering::SeqCst), 0);
            tls.stop().await;
        }
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn v2_snapshot_half_dual_policy_catalog_and_dataset_drift_never_reach_tls() {
    let admin = harness::admin_config("v2_runtime_current_refusal");
    harness::with_temp_database(&admin,"v2runtimecurrentrefusal",|config|async move{
        let f=Fixture::new(config).await;
        // All mutations are confined to this newly owned test DB. Restoration below is
        // fixture cleanup, never a production self-repair or an accepted schema oracle.
        for mode in 0..7u64{
            let tls=TlsFixture::new(vec![]).await;let(model,req,request)=f.begin(40+mode,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
            let c=f.pool.get().await.unwrap();let run=req.command.run_id.as_str();let id=Uuid::parse_str(&model.id).unwrap();
            match mode{
                0=>{c.execute("DELETE FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                1=>{c.execute("UPDATE public.messages SET content=content-'modelSelection' WHERE message_id=$1||':input'",&[&run]).await.unwrap();},
                2=>{c.execute("INSERT INTO public.run_model_selections SELECT run_id,deployment_id,tenant_id,owner_user_id,auth_generation,connection_id,connection_revision,secret_id,protocol,endpoint,model,created_at FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                3=>{c.execute("UPDATE public.custom_model_catalogs SET catalog_revision=catalog_revision+1 WHERE connection_id=$1",&[&id]).await.unwrap();},
                4=>{c.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&id]).await.unwrap();},
                5=>{c.execute("UPDATE public.model_connection_secrets SET encrypted_value='owned-invalid-Vault-envelope' WHERE connection_id=$1",&[&id]).await.unwrap();},
                _=>{c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-dataset-drift' WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();},
            }drop(c);
            if mode!=5{assert!(f.context().load(&lease(&req)).await.is_err());}
            refused(f.adapter(tls.dialer(),Duration::from_secs(5)).start(request).await);assert_eq!(tls.count(),0);
            tls.stop().await;if mode==6{break;}
        }f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn v2_configured_pool_size_one_releases_probe_and_authoritative_guard_before_common_projection()
 {
    let admin = harness::admin_config("v2_runtime_pool_one");
    harness::with_temp_database(&admin, "v2runtimepoolone", |config| async move {
        let f = Fixture::new_size(config, 1).await;
        let tls = TlsFixture::new(vec![ResponsePlan::ok(chat_text())]).await;
        let (_, req, request) = f
            .begin(
                70,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        let loaded = tokio::time::timeout(Duration::from_secs(6), f.context().load(&lease(&req)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.route, request.route);
        assert_eq!(f.pool.status().size, 1);
        assert_eq!(
            events(
                f.adapter(tls.dialer(), Duration::from_secs(5))
                    .start(loaded)
                    .await
                    .unwrap()
            )
            .await
            .last(),
            Some(&ProviderEvent::Completed)
        );
        assert_eq!(tls.count(), 1);
        tls.stop().await;
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn v2_headers_timeout_is_unknown_and_cancelled_original_guard_releases_locks() {
    let admin = harness::admin_config("v2_runtime_headers");
    harness::with_temp_database(&admin, "v2runtimeheaders", |config| async move {
        let f = Fixture::new(config).await;
        for mode in 0..3u64 {
            let gate = Arc::new(Semaphore::new(0));
            let mut plan = ResponsePlan::ok(chat_text());
            if mode == 2 {
                plan.body_gate = Some(gate.clone());
            } else {
                plan.header_gate = Some(gate.clone());
            }
            let tls = TlsFixture::new(vec![plan]).await;
            let (model, _, request) = f
                .begin(
                    80 + mode,
                    CustomModelProtocol::OpenaiChatCompletions,
                    &tls.endpoint(),
                    false,
                )
                .await;
            let adapter = Arc::new(f.adapter(
                tls.dialer(),
                if mode == 1 {
                    Duration::from_millis(500)
                } else {
                    Duration::from_secs(5)
                },
            ));
            let task = {
                let adapter = adapter.clone();
                let request = request.clone();
                tokio::spawn(async move { adapter.start(request).await })
            };
            tls.wait_count(1).await;
            if mode == 2 {
                let session = tokio::time::timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let mut edit = update(&model);
                edit.enabled = false;
                tokio::time::timeout(
                    Duration::from_secs(3),
                    f.models.update(&auth(), &model.id, &edit),
                )
                .await
                .unwrap()
                .unwrap();
                gate.add_permits(1);
                assert_eq!(
                    events(session).await.last(),
                    Some(&ProviderEvent::Completed)
                );
                refused(adapter.start(request).await);
            } else {
                let models = f.models.clone();
                let mut edit = update(&model);
                edit.enabled = false;
                let id = model.id.clone();
                let mut change =
                    tokio::spawn(async move { models.update(&auth(), &id, &edit).await });
                assert!(
                    tokio::time::timeout(Duration::from_millis(60), &mut change)
                        .await
                        .is_err()
                );
                if mode == 0 {
                    task.abort();
                    assert!(matches!(task.await,Err(error)if error.is_cancelled()));
                } else {
                    assert!(matches!(
                        task.await.unwrap(),
                        Err(ProviderPortError::CommitUnknown)
                    ));
                }
                tokio::time::timeout(Duration::from_secs(3), change)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(tls.count(), 1);
            drop(adapter);
            tls.stop().await;
        }
        f.finish().await;
        Ok(())
    })
    .await;
}

// A newly owned loopback-only PG relay. The original Pool, registry enrollment and
// acceptance all use this same relay from startup; no second manager is substituted.
struct PgRollbackAckLoss {
    config: DatabaseConfig,
    armed: Arc<std::sync::atomic::AtomicBool>,
    lost: Arc<AtomicUsize>,
    rollback_sent: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl PgRollbackAckLoss {
    async fn new(config: &DatabaseConfig) -> Self {
        assert_eq!(config.host, "127.0.0.1");
        let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut routed = config.clone();
        routed.port = listener.local_addr().unwrap().port();
        assert!(![39025, 39027].contains(&routed.port));
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lost = Arc::new(AtomicUsize::new(0));
        let rollback_sent = Arc::new(AtomicUsize::new(0));
        let arm = armed.clone();
        let lose = lost.clone();
        let sent = rollback_sent.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    accepted=listener.accept()=>{
                        let Ok((mut downstream,_))=accepted else{break;};let arm=arm.clone();let lose=lose.clone();let sent=sent.clone();
                        children.spawn(async move{
                            let Ok(mut upstream)=TcpStream::connect(upstream).await else{return;};
                            let Ok(len)=downstream.read_u32().await else{return;};if !(8..=65536).contains(&len){return;}
                            let mut startup=vec![0;len as usize-4];if downstream.read_exact(&mut startup).await.is_err(){return;}
                            if upstream.write_u32(len).await.is_err()||upstream.write_all(&startup).await.is_err(){return;}
                            if startup[..4]==80877102_u32.to_be_bytes(){return;}
                            let(mut down_read,mut down_write)=downstream.into_split();let(mut up_read,mut up_write)=upstream.into_split();
                            let rollback=Arc::new(std::sync::atomic::AtomicBool::new(false));let rolled=rollback.clone();
                            let client=async move{
                                while let Some((tag,bytes))=pg_frame(&mut down_read).await{
                                    if tag==b'Q'&&bytes.eq_ignore_ascii_case(b"ROLLBACK\0")&&arm.load(Ordering::SeqCst){
                                        sent.fetch_add(1,Ordering::SeqCst);rolled.store(true,Ordering::SeqCst);
                                    }
                                    if up_write.write_u8(tag).await.is_err()||up_write.write_u32(bytes.len()as u32+4).await.is_err()||up_write.write_all(&bytes).await.is_err(){break;}
                                }
                            };
                            let server=async move{
                                while let Some((tag,bytes))=pg_frame(&mut up_read).await{
                                    if tag==b'Z'&&rollback.load(Ordering::SeqCst){lose.fetch_add(1,Ordering::SeqCst);break;}
                                    if down_write.write_u8(tag).await.is_err()||down_write.write_u32(bytes.len()as u32+4).await.is_err()||down_write.write_all(&bytes).await.is_err(){break;}
                                }
                            };
                            tokio::select!{_=client=>{},_=server=>{}}
                        });
                    },
                    Some(_)=children.join_next(),if !children.is_empty()=>{}
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            config: routed,
            armed,
            lost,
            rollback_sent,
            stop: Some(stop),
            task: Some(task),
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
impl Drop for PgRollbackAckLoss {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn pg_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Option<(u8, Vec<u8>)> {
    let tag = reader.read_u8().await.ok()?;
    let len = reader.read_u32().await.ok()?;
    if !(4..=8 * 1024 * 1024).contains(&len) {
        return None;
    }
    let mut bytes = vec![0; len as usize - 4];
    reader.read_exact(&mut bytes).await.ok()?;
    Some((tag, bytes))
}

#[tokio::test]
#[ignore = "requires explicitly owned PG, TLS and relay; selected include-ignored only"]
async fn v2_original_rollback_ack_loss_after_adapter_is_unknown_without_a_retry_post() {
    let admin = harness::admin_config("v2_runtime_ack_loss");
    harness::with_temp_database(&admin, "v2runtimeackloss", |config| async move {
        let proxy = PgRollbackAckLoss::new(&config).await;
        let f = Fixture::new(proxy.config.clone()).await;
        let tls = TlsFixture::new(vec![ResponsePlan::ok(chat_text())]).await;
        let (model, _, request) = f
            .begin(
                100,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        proxy.armed.store(true, Ordering::SeqCst);
        let adapter = Arc::new(f.adapter(tls.dialer(), Duration::from_secs(5)));
        assert!(matches!(
            retried(adapter.clone()).start(request).await,
            Err(ProviderPortError::CommitUnknown)
        ));
        assert_eq!(tls.count(), 1);
        assert_eq!(proxy.rollback_sent.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
        proxy.armed.store(false, Ordering::SeqCst);
        let mut edit = update(&model);
        edit.enabled = false;
        tokio::time::timeout(
            Duration::from_secs(3),
            f.models.update(&auth(), &model.id, &edit),
        )
        .await
        .unwrap()
        .unwrap();
        drop(adapter);
        tls.stop().await;
        f.finish().await;
        proxy.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG, TLS and relay; selected include-ignored only"]
async fn v2_classification_rollback_ack_loss_closes_before_authoritative_checkout() {
    let admin = harness::admin_config("v2_runtime_probe_ack_loss");
    harness::with_temp_database(&admin, "v2runtimeprobeackloss", |config| async move {
        let proxy = PgRollbackAckLoss::new(&config).await;
        let f = Fixture::new(proxy.config.clone()).await;
        let tls = TlsFixture::new(vec![]).await;
        let (_, req, _) = f
            .begin(
                110,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        proxy.armed.store(true, Ordering::SeqCst);
        assert!(matches!(
            f.context().load(&lease(&req)).await,
            Err(openbot_application::AgentContextError::Unavailable)
        ));
        assert_eq!(proxy.rollback_sent.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
        assert_eq!(tls.count(), 0);
        proxy.armed.store(false, Ordering::SeqCst);
        tls.stop().await;
        f.finish().await;
        proxy.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PG and TLS; selected include-ignored only"]
async fn unconfigured_constructor_closes_v2_and_keeps_actual_legacy_v1_route() {
    let admin = harness::admin_config("v2_runtime_constructor_compat");
    harness::with_temp_database(&admin, "v2runtimeconstructorcompat", |config| async move {
        let f = Fixture::new(config).await;
        let tls = TlsFixture::new(vec![
            ResponsePlan::ok(chat_text()),
            ResponsePlan::ok(chat_text()),
        ])
        .await;
        let (model, req, request) = f
            .begin(
                120,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        let old_context = PostgresAgentContextSource::new(
            f.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            Some(32),
        )
        .unwrap();
        assert!(old_context.load(&lease(&req)).await.is_err());
        let old_provider = PostgresCustomModelProvider::new(
            f.pool.clone(),
            f.vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            tls.dialer(),
            SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(5)).unwrap(),
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        refused(old_provider.start(request).await);
        assert_eq!(tls.count(), 0);
        let mut entropy = [0u8; 16];
        entropy[8..].copy_from_slice(&121u64.to_be_bytes());
        let legacy = openbot_application::BeginThreadRunRequest {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: openbot_contracts::command::BeginThreadRun {
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new("owned-v2-legacy-compat-121"),
                bot_id: BotId::new("bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "Original legacy words".into(),
                selected_skill_slugs: vec![],
                model_selection: Some(RunModelSelection {
                    connection_id: model.id.clone(),
                    expected_revision: model.revision,
                }),
            },
        };
        f.directory.begin_thread_run(legacy.clone()).await.unwrap();
        let legacy_lease = RunExecutionLease::new(
            legacy.command.run_id.clone(),
            legacy.command.thread_id.clone(),
            legacy.command.bot_id.clone(),
            legacy.actor.clone(),
            FencingToken::new(1).unwrap(),
            0,
        )
        .unwrap();
        let old_request = old_context.load(&legacy_lease).await.unwrap();
        let configured_request = f.context().load(&legacy_lease).await.unwrap();
        assert_eq!(old_request.route, configured_request.route);
        let ProviderRoute::CustomModel(binding) = &old_request.route else {
            panic!("legacy explicit choice remains custom")
        };
        assert!(binding.v2_snapshot().is_none());
        assert_eq!(
            events(old_provider.start(old_request).await.unwrap())
                .await
                .last(),
            Some(&ProviderEvent::Completed)
        );
        assert_eq!(
            events(
                f.adapter(tls.dialer(), Duration::from_secs(5))
                    .start(configured_request)
                    .await
                    .unwrap()
            )
            .await
            .last(),
            Some(&ProviderEvent::Completed)
        );
        assert_eq!(tls.count(), 2);
        drop(old_provider);
        drop(old_context);
        tls.stop().await;
        f.finish().await;
        Ok(())
    })
    .await;
}
