//! Personal custom inference uses the existing PG/Vault, provider decoders and SafeDialer.
//! No connection object, key or static provider survives across sampling or retry attempts.

use super::{
    anthropic::{AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig},
    openai::{OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig},
};
use crate::{
    model_runtime,
    net::safe_http::{SafeDialer, SafeHttpBudget},
    vault::CredentialRecordVault,
};
use async_trait::async_trait;
use openbot_application::{
    AgentContextError, ProviderAdapter, ProviderPortError, ProviderRequest, ProviderRoute,
    ProviderSession,
};
use openbot_contracts::{
    ids::{DeploymentId, TenantId},
    model_connections::CustomModelProtocol,
};
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use uuid::Uuid;

/// Shared Server/Desktop factory; every start reopens current authority and a short-lived key.
pub struct PostgresCustomModelProvider {
    pool: crate::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    dialer: SafeDialer,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    model_dataset_binding: Option<Arc<crate::model_dataset::PostgresModelDatasetBinding>>,
    #[cfg(test)]
    v2_vault_opens: std::sync::atomic::AtomicUsize,
}
impl PostgresCustomModelProvider {
    /// Bind only trusted host infrastructure. URL/model/key are never accepted by this factory.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        vault: CredentialRecordVault,
        deployment: DeploymentId,
        tenant: TenantId,
        dialer: SafeDialer,
        connect_budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
    ) -> Result<Self, ProviderPortError> {
        if deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
            || connect_budget.timeout() > Duration::from_secs(30)
            || connect_budget.max_response_bytes() > 64 * 1024 * 1024
            || stall_timeout.is_some_and(|value| value.is_zero())
        {
            return Err(invalid("custom_model_configuration"));
        }
        Ok(Self {
            pool,
            vault,
            deployment,
            tenant,
            dialer,
            connect_budget,
            stall_timeout,
            model_dataset_binding: None,
            #[cfg(test)]
            v2_vault_opens: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Attach the original dataset producer once. A missing producer never enables v2.
    pub fn with_model_dataset_binding(
        mut self,
        binding: Arc<crate::model_dataset::PostgresModelDatasetBinding>,
    ) -> Result<Self, ProviderPortError> {
        if self.model_dataset_binding.is_some()
            || !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(invalid("model_dataset_binding"));
        }
        self.model_dataset_binding = Some(binding);
        Ok(self)
    }

    async fn start_v2(
        &self,
        request: ProviderRequest,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let binding = self
            .model_dataset_binding
            .as_ref()
            .ok_or_else(|| invalid("model_dataset_binding"))?;
        if !binding.matches_pool_scope(&self.pool, &self.deployment, &self.tenant) {
            return Err(invalid("model_dataset_binding"));
        }
        let progress = StartProgress::default();
        let result=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),async{
            let mut checkout=binding.checkout(deadline).await.map_err(map_start_dataset)?;
            let transaction=checkout.begin_read_committed().await.map_err(map_start_transaction)?;
            let result=async {
                let remaining=deadline.saturating_duration_since(std::time::Instant::now()).as_millis().max(1).to_string();
                transaction.as_transaction().query_one(
                    "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining])
                    .await.map_err(|_|ProviderPortError::Unavailable)?;
                let ProviderRoute::CustomModel(expected)=&request.route else{return Err(invalid("custom_model_route"));};
                if expected.v2_snapshot().is_none(){return Err(invalid("custom_model_binding"));}
                let lease=expected.identity_lease().map_err(map_authority)?;
                let loaded=model_runtime::load_v2_for_start(&transaction,&self.deployment,&self.tenant,&lease)
                    .await.map_err(map_authority)?;
                if loaded.binding!=*expected{return Err(invalid("custom_model_binding"));}
                if loaded.has_cost_cap{return Err(invalid("custom_model_unpriced"));}
                let secret_id=Uuid::parse_str(loaded.binding.secret_id()).map_err(|_|invalid("custom_model_credential"))?;
                #[cfg(test)]
                self.v2_vault_opens.fetch_add(1,Ordering::SeqCst);
                let opened=self.vault.open(&secret_id,SecretKind::Model,
                    SecretPrincipal::Actor(loaded.binding.actor().clone()),
                    SecretPrincipal::Service(ServiceId::new(loaded.binding.connection_id())),&loaded.encrypted_value)
                    .map_err(|_|invalid("custom_model_credential"))?;
                if opened.needs_migration(){return Err(invalid("custom_model_credential"));}
                let key=opened.into_secret();
                let text=core::str::from_utf8(key.expose()).map_err(|_|invalid("custom_model_credential"))?;
                if text.is_empty() || text.len()>16*1024 || text.trim()!=text || text.contains(['\r','\n','\0']){
                    return Err(invalid("custom_model_credential"));
                }
                let endpoint=url::Url::parse(loaded.binding.endpoint()).map_err(|_|invalid("custom_model_configuration"))?;
                let adapter:Box<dyn ProviderAdapter>=match loaded.binding.protocol(){
                    CustomModelProtocol::OpenaiChatCompletions|CustomModelProtocol::OpenaiResponses=>{
                        let protocol=if loaded.binding.protocol()==CustomModelProtocol::OpenaiResponses{
                            OpenAiProtocol::Responses
                        }else{OpenAiProtocol::ChatCompletions};
                        let config=OpenAiProviderConfig::new(endpoint,loaded.binding.model().to_owned(),protocol,
                            self.connect_budget,self.stall_timeout)?;
                        Box::new(OpenAiProvider::new(config,OpenAiApiKey::from_secret(key)?,self.dialer.clone()))
                    }
                    CustomModelProtocol::AnthropicMessages=>{
                        let config=AnthropicProviderConfig::new(endpoint,loaded.binding.model().to_owned(),
                            AnthropicApiKey::from_secret(key)?,self.connect_budget,self.stall_timeout)?;
                        Box::new(AnthropicProvider::new(config,self.dialer.clone()))
                    }
                };
                // This is a conservative may-have-effect fence, not a remote-send or ACK.
                progress.network_started.store(true,Ordering::SeqCst);
                adapter.start(request).await
            }.await;
            if let Err(error)=&result && let Ok(mut failure)=progress.failure.lock(){*failure=Some(*error);}
            let ended=transaction.rollback().await;
            if let Err(end)=ended{tracing::warn!(state=?end,"custom v2 original start rollback state");}
            let after_adapter=progress.network_started.load(Ordering::SeqCst);
            match result {
                Ok(session)=>{
                    if ended.is_err() || std::time::Instant::now()>=deadline {
                        drop(session);
                        return Err(ProviderPortError::CommitUnknown);
                    }
                    // Only a successful adapter plus the original timely rollback ACK may
                    // transfer the live session to the existing decoder/retry machinery.
                    Ok(session)
                }
                Err(_) if after_adapter=>Err(ProviderPortError::CommitUnknown),
                Err(error)=>Err(error),
            }
        }).await;
        match result {
            Ok(result) => result,
            Err(_) => {
                if progress.network_started.load(Ordering::SeqCst) {
                    return Err(ProviderPortError::CommitUnknown);
                }
                Err(progress
                    .failure
                    .lock()
                    .ok()
                    .and_then(|failure| *failure)
                    .unwrap_or(ProviderPortError::Unavailable))
            }
        }
    }

    async fn start_locked(
        &self,
        client: &mut crate::db::pool::PooledClient,
        request: ProviderRequest,
        progress: &StartProgress,
    ) -> Attempt {
        let tx = match client.transaction().await {
            Ok(tx) => tx,
            Err(_) => {
                return Attempt {
                    result: Err(ProviderPortError::Unavailable),
                    clean: false,
                };
            }
        };
        let result = async {
            // Bound a disconnected caller's outstanding SQL too. Values are parameters, not SQL.
            let timeout_ms = self.connect_budget.timeout().as_millis().max(1).to_string();
            tx.query_one(
                "SELECT set_config('statement_timeout',$1,true)",
                &[&timeout_ms],
            )
            .await
            .map_err(|_| ProviderPortError::Unavailable)?;
            let ProviderRoute::CustomModel(expected) = &request.route else {
                return Err(invalid("custom_model_route"));
            };
            let lease = expected.identity_lease().map_err(map_authority)?;
            let loaded =
                model_runtime::load_current_selection(&tx, &self.deployment, &self.tenant, &lease)
                    .await
                    .map_err(map_authority)?
                    .ok_or_else(|| invalid("custom_model_binding"))?;
            if loaded.binding != *expected {
                return Err(invalid("custom_model_binding"));
            }
            if loaded.has_cost_cap {
                return Err(invalid("custom_model_unpriced"));
            }
            let secret_id = Uuid::parse_str(loaded.binding.secret_id())
                .map_err(|_| invalid("custom_model_credential"))?;
            let opened = self
                .vault
                .open(
                    &secret_id,
                    SecretKind::Model,
                    SecretPrincipal::Actor(loaded.binding.actor().clone()),
                    SecretPrincipal::Service(ServiceId::new(loaded.binding.connection_id())),
                    &loaded.encrypted_value,
                )
                .map_err(|_| invalid("custom_model_credential"))?;
            if opened.needs_migration() {
                return Err(invalid("custom_model_credential"));
            }
            let key = opened.into_secret();
            let text = core::str::from_utf8(key.expose())
                .map_err(|_| invalid("custom_model_credential"))?;
            if text.is_empty()
                || text.len() > 16 * 1024
                || text.trim() != text
                || text.contains(['\r', '\n', '\0'])
            {
                return Err(invalid("custom_model_credential"));
            }
            let endpoint = url::Url::parse(loaded.binding.endpoint())
                .map_err(|_| invalid("custom_model_configuration"))?;
            let adapter: Box<dyn ProviderAdapter> = match loaded.binding.protocol() {
                CustomModelProtocol::OpenaiChatCompletions
                | CustomModelProtocol::OpenaiResponses => {
                    let protocol =
                        if loaded.binding.protocol() == CustomModelProtocol::OpenaiResponses {
                            OpenAiProtocol::Responses
                        } else {
                            OpenAiProtocol::ChatCompletions
                        };
                    let config = OpenAiProviderConfig::new(
                        endpoint,
                        loaded.binding.model().to_owned(),
                        protocol,
                        self.connect_budget,
                        self.stall_timeout,
                    )?;
                    Box::new(OpenAiProvider::new(
                        config,
                        OpenAiApiKey::from_secret(key)?,
                        self.dialer.clone(),
                    ))
                }
                CustomModelProtocol::AnthropicMessages => {
                    let config = AnthropicProviderConfig::new(
                        endpoint,
                        loaded.binding.model().to_owned(),
                        AnthropicApiKey::from_secret(key)?,
                        self.connect_budget,
                        self.stall_timeout,
                    )?;
                    Box::new(AnthropicProvider::new(config, self.dialer.clone()))
                }
            };
            progress.network_started.store(true, Ordering::SeqCst);
            // Existing transport errors do not identify the redirect hop. A 303/307 POST may
            // already have happened before a later DNS/connect error, so never retry that error.
            match adapter.start(request).await {
                Err(ProviderPortError::Unavailable) => Err(ProviderPortError::CommitUnknown),
                result => result,
            }
        }
        .await;
        if let Err(error) = &result
            && let Ok(mut failure) = progress.failure.lock()
        {
            *failure = Some(*error);
        }
        let clean = tx.rollback().await.is_ok();
        let result = match result {
            Ok(_) if !clean => Err(ProviderPortError::CommitUnknown),
            other => other,
        };
        Attempt { result, clean }
    }
}
impl core::fmt::Debug for PostgresCustomModelProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgresCustomModelProvider([redacted])")
    }
}

#[async_trait]
impl ProviderAdapter for PostgresCustomModelProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let v2_deadline = std::time::Instant::now() + self.connect_budget.timeout();
        super::common::validate_request(&request)?;
        let ProviderRoute::CustomModel(binding) = &request.route else {
            return Err(invalid("custom_model_route"));
        };
        if binding.deployment() != &self.deployment || binding.tenant() != &self.tenant {
            return Err(invalid("custom_model_scope"));
        }
        if request.rate_card.is_some() || request.cost_cap.is_some() {
            return Err(invalid("custom_model_unpriced"));
        }
        if binding.v2_snapshot().is_some() {
            return self.start_v2(request, v2_deadline).await;
        }
        let deadline = tokio::time::Instant::now() + self.connect_budget.timeout();
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| ProviderPortError::Unavailable)?
            .map_err(|_| ProviderPortError::Unavailable)?;
        let mut connection = StartConnection {
            client: Some(client),
            clean: false,
            cancel_budget: self.connect_budget.timeout(),
        };
        let progress = StartProgress::default();
        let result = tokio::time::timeout_at(
            deadline,
            self.start_locked(
                connection.client.as_mut().expect("owned start connection"),
                request,
                &progress,
            ),
        )
        .await;
        match result {
            Ok(attempt) => {
                connection.clean = attempt.clean;
                attempt.result
            }
            Err(_) => Err(progress
                .failure
                .lock()
                .ok()
                .and_then(|failure| *failure)
                .unwrap_or_else(|| {
                    if progress.network_started.load(Ordering::SeqCst) {
                        ProviderPortError::CommitUnknown
                    } else {
                        ProviderPortError::Unavailable
                    }
                })),
        }
    }
}

fn invalid(field: &'static str) -> ProviderPortError {
    ProviderPortError::InvalidRequest { field }
}
fn map_start_dataset(error: crate::model_dataset::ModelDatasetError) -> ProviderPortError {
    match error {
        crate::model_dataset::ModelDatasetError::InvalidBinding => invalid("model_dataset_binding"),
        crate::model_dataset::ModelDatasetError::Unavailable => ProviderPortError::Unavailable,
    }
}
fn map_start_transaction(error: crate::db::pool::TransactionOwnerError) -> ProviderPortError {
    use crate::db::pool::TransactionOwnerError as E;
    tracing::warn!(state=?error,"custom v2 original start transaction state");
    match error {
        E::AlreadyStarted => invalid("model_dataset_transaction"),
        E::DeadlineExceeded
        | E::BeginUnavailable
        | E::CommitUnknown
        | E::RollbackUnproven
        | E::CommitAcknowledgedAfterDeadline
        | E::RollbackAcknowledgedAfterDeadline => ProviderPortError::Unavailable,
    }
}
fn map_authority(error: AgentContextError) -> ProviderPortError {
    match error {
        AgentContextError::Unavailable => ProviderPortError::Unavailable,
        _ => invalid("custom_model_authority"),
    }
}
#[derive(Default)]
struct StartProgress {
    network_started: AtomicBool,
    failure: Mutex<Option<ProviderPortError>>,
}
struct Attempt {
    result: Result<Box<dyn ProviderSession>, ProviderPortError>,
    clean: bool,
}

/// A cancelled in-flight SQL request must never be returned to a different pool borrower.
/// Normal completion explicitly confirms rollback. Cancellation detaches the physical connection
/// before sending its private PG cancellation token; no subsequent caller can be cancelled by it.
struct StartConnection {
    client: Option<crate::db::pool::PooledClient>,
    clean: bool,
    cancel_budget: Duration,
}
impl Drop for StartConnection {
    fn drop(&mut self) {
        if self.clean {
            return;
        }
        let Some(client) = self.client.take() else {
            return;
        };
        let owned = crate::db::pool::PooledClient::take(client);
        let cancel = owned.cancel_token();
        let budget = self.cancel_budget;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ =
                    tokio::time::timeout(budget, cancel.cancel_query(tokio_postgres::NoTls)).await;
                // ClientWrapper drop aborts its driver and closes this detached connection.
                drop(owned);
            });
        }
    }
}

#[cfg(test)]
mod v2_test_harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}

#[cfg(test)]
mod v2_vault_tests {
    use super::*;
    use crate::{
        artifact_registry::ArtifactDatasetRegistry,
        db::{fresh, pool},
        model_connections::PostgresModelConnections,
        model_dataset::PostgresModelDatasetBinding,
        provider::context::PostgresAgentContextSource,
        thread_directory::PostgresThreadDirectory,
    };
    use async_trait::async_trait;
    use openbot_application::model_connections::ModelConnectionAdministration;
    use openbot_application::{
        AgentContextSource, BeginThreadRunV2Request, RunExecutionLease, ThreadDirectory,
    };
    use openbot_contracts::{
        auth::{AuthContextBuilder, AuthGeneration, Role},
        command::{BeginThreadRunV2, ThreadRunAnchor},
        ids::thread::ThreadIdentity,
        ids::{ActorId, BotId, RunId},
        model_connections::{CreateModelConnection, ModelApiKey},
        versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
    };
    use openbot_domain::{
        thread::FencingToken,
        vault::{KeyVersion, SecretBytes, WrappingKey},
    };
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use zeroize::Zeroizing;

    struct CountedDns(AtomicUsize);
    #[async_trait]
    impl crate::net::safe_http::DnsResolver for CountedDns {
        async fn resolve(
            &self,
            _: &str,
            _: u16,
        ) -> Result<Vec<SocketAddr>, crate::net::safe_http::DnsUnavailable> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(crate::net::safe_http::DnsUnavailable)
        }
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; only original provider Vault-call observations"]
    async fn current_predicate_refusals_observe_zero_actual_vault_opens_and_zero_dns_then_positive_control()
     {
        const DEP: &str = "owned-v2-vault-observation-deployment";
        const TENANT: &str = "owned-v2-vault-observation-tenant";
        let admin = super::v2_test_harness::admin_config("v2_vault_real_calls");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2vaultrealcalls",|config|async move{
            let p=pool::connect(&config.clone().with_max_pool_size(4)).await.unwrap();
            let mut c=p.get().await.unwrap();fresh::apply(&mut c).await.unwrap();
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-vault-alice@example.test',7),('bob','owned-vault-bob@example.test',7);
                INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');").await.unwrap();drop(c);
            let vault=CredentialRecordVault::single_key(TenantId::new(TENANT),KeyVersion::new(1),WrappingKey::from_bytes(vec![0x76;32]).unwrap());
            let models=PostgresModelConnections::new(p.clone(),vault.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),SecretBytes::new(vec![0x77;32])).unwrap();
            let registry=Arc::new(ArtifactDatasetRegistry::from_server(p.clone(),&DeploymentId::new(DEP),&TenantId::new(TENANT)).await.unwrap());
            let binding=Arc::new(PostgresModelDatasetBinding::unbound(p.clone(),DeploymentId::new(DEP),TenantId::new(TENANT)).unwrap());
            binding.enroll_original_registry(&registry).unwrap();
            let directory=PostgresThreadDirectory::with_runtime(p.clone(),config.clone(),"owned-vault-runtime".into(),time::Duration::seconds(30)).unwrap()
                .with_model_dataset_binding(binding.clone()).unwrap();
            let context=PostgresAgentContextSource::new(p.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),Some(32)).unwrap()
                .with_model_dataset_binding(binding.clone()).unwrap();
            let auth=AuthContextBuilder::from_verified_session(DeploymentId::new(DEP),TenantId::new(TENANT),ActorId::new("alice"),AuthGeneration::new(7),false)
                .with_roles([Role::User]).build();
            let original_dataset:String=p.get().await.unwrap().query_one("SELECT dataset_id FROM openbot_internal.artifact_dataset_bindings WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap().get(0);
            for mode in 0..12u64 {
                let model=models.create(&auth,&CreateModelConnection{name:"Owned no-effect choice".into(),protocol:CustomModelProtocol::OpenaiChatCompletions,
                    endpoint:"https://owned-no-network.example.test/v1".into(),model:"owned-no-effect-model".into(),enabled:true,
                    api_key:ModelApiKey::new(Zeroizing::new("OWNED_V2_VAULT_CALL_CANARY".into())).unwrap()}).await.unwrap();
                let mut entropy=[0u8;16];entropy[8..].copy_from_slice(&(500+mode).to_be_bytes());
                let req=BeginThreadRunV2Request{deployment:DeploymentId::new(DEP),tenant:TenantId::new(TENANT),actor:ActorId::new("alice"),auth_generation:AuthGeneration::new(7),
                    command:BeginThreadRunV2{thread_id:ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),run_id:RunId::new(format!("owned-vault-run-{mode}")),
                        bot_id:BotId::new("bot"),anchor:ThreadRunAnchor::DirectBot,message:"Owned vault observation words".into(),selected_skill_slugs:vec![],
                        model_selection:RunModelSelectionV2::new(ModelSelectionIntentSource::Custom,model.id.clone(),model.revision,format!("custom:{}",model.id),1).unwrap()}};
                directory.begin_thread_run_v2(req.clone()).await.unwrap();
                let lease=RunExecutionLease::new(req.command.run_id.clone(),req.command.thread_id.clone(),req.command.bot_id.clone(),req.actor.clone(),FencingToken::new(1).unwrap(),0).unwrap();
                let request=context.load(&lease).await.unwrap();
                let dns=Arc::new(CountedDns(AtomicUsize::new(0)));
                let dialer=SafeDialer::with_resolver(crate::net::safe_http::EgressPolicy::default(),dns.clone());
                let adapter=PostgresCustomModelProvider::new(p.clone(),vault.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),dialer,
                    SafeHttpBudget::new(64*1024*1024,Duration::from_secs(5)).unwrap(),Some(Duration::from_secs(2))).unwrap()
                    .with_model_dataset_binding(binding.clone()).unwrap();
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                let c=p.get().await.unwrap();let id=Uuid::parse_str(&model.id).unwrap();let run=req.command.run_id.as_str();
                match mode{
                    0=>{c.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[]).await.unwrap();},
                    1=>{c.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&id]).await.unwrap();},
                    2=>{c.execute("UPDATE public.custom_model_catalogs SET catalog_revision=catalog_revision+1 WHERE connection_id=$1",&[&id]).await.unwrap();},
                    3=>{c.execute("UPDATE public.messages SET content=jsonb_set(content,'{modelSelection,source}','\"sdk_gateway\"'::jsonb) WHERE message_id=$1||':input'",&[&run]).await.unwrap();},
                    4=>{c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-observed-drift' WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();},
                    5=>{c.execute("INSERT INTO public.run_model_selections SELECT run_id,deployment_id,tenant_id,owner_user_id,auth_generation,connection_id,connection_revision,secret_id,protocol,endpoint,model,created_at FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                    6=>{c.execute("DELETE FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",&[&run]).await.unwrap();},
                    7=>{c.execute("UPDATE public.runs SET budget_cost_currency='USD',budget_max_cost_micro_units=1 WHERE run_id=$1",&[&run]).await.unwrap();},
                    8=>{c.execute("UPDATE openbot_internal.run_model_selection_v2_snapshots SET owner_user_id='bob' WHERE run_id=$1",&[&run]).await.unwrap();},
                    9=>{c.batch_execute("GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC").await.unwrap();},
                    10=>{c.execute("UPDATE public.model_connection_secrets SET retired_at=clock_timestamp() WHERE connection_id=$1",&[&id]).await.unwrap();},
                    _=>{},
                }drop(c);
                let result=adapter.start(request).await;
                if mode==11{
                    // A real matching producer reaches exactly the original synchronous Vault
                    // call and the owned DNS control. This proves the counters are connected.
                    assert!(matches!(result,Err(ProviderPortError::CommitUnknown)));
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),1);assert_eq!(dns.0.load(Ordering::SeqCst),1);
                }else{
                    assert!(matches!(result,Err(ProviderPortError::InvalidRequest{..})),"closed current predicate {mode}");
                    assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0,"actual provider Vault call {mode}");
                    assert_eq!(dns.0.load(Ordering::SeqCst),0,"actual DNS before effect {mode}");
                }
                let c=p.get().await.unwrap();
                if mode==0{c.execute("UPDATE public.users SET auth_generation=7 WHERE id='alice'",&[]).await.unwrap();}
                if mode==4{c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id=$3 WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT,&original_dataset]).await.unwrap();}
                if mode==9{c.batch_execute("REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM PUBLIC").await.unwrap();}
                drop(c);drop(adapter);
            }
            drop(context);drop(directory);drop(models);drop(binding);drop(registry);drop(vault);
            let observations=p.connection_observations();p.close();let deadline=std::time::Instant::now()+Duration::from_secs(10);
            for o in observations{assert_eq!(o.wait_for_destruction_before(deadline).await.unwrap(),pool::ConnectionDestruction::ConnectionDestroyed);}Ok(())
        }).await;
    }

    // This producer stays inside Infra cfg(test). Its Vault counter must never be
    // presented as a counter in a Server/Desktop dependency build.
    struct ConcurrentAuthorityFixture {
        pool: pool::DatabasePool,
        vault: CredentialRecordVault,
        models: PostgresModelConnections,
        registry: Arc<ArtifactDatasetRegistry>,
        binding: Arc<PostgresModelDatasetBinding>,
        directory: PostgresThreadDirectory,
        context: PostgresAgentContextSource,
        auth: openbot_contracts::auth::AuthContext,
    }
    impl ConcurrentAuthorityFixture {
        async fn new(config: pool::DatabaseConfig) -> Self {
            const DEP: &str = "owned-v2-concurrent-deployment";
            const TENANT: &str = "owned-v2-concurrent-tenant";
            let p = pool::connect(&config.clone().with_max_pool_size(8))
                .await
                .unwrap();
            let mut c = p.get().await.unwrap();
            fresh::apply(&mut c).await.unwrap();
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation)
                VALUES('alice','owned-concurrent-alice@example.test',7),('bob','owned-concurrent-bob@example.test',7);
                INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('bot','alice','Owned bot','','owned','public');
                INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups)
                VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
                INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
                INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
            drop(c);
            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x78; 32]).unwrap(),
            );
            let models = PostgresModelConnections::new(
                p.clone(),
                vault.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![0x79; 32]),
            )
            .unwrap();
            let registry = Arc::new(
                ArtifactDatasetRegistry::from_server(
                    p.clone(),
                    &DeploymentId::new(DEP),
                    &TenantId::new(TENANT),
                )
                .await
                .unwrap(),
            );
            let binding = Arc::new(
                PostgresModelDatasetBinding::unbound(
                    p.clone(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )
                .unwrap(),
            );
            binding.enroll_original_registry(&registry).unwrap();
            let directory = PostgresThreadDirectory::with_runtime(
                p.clone(),
                config,
                "owned-concurrent-runtime".into(),
                time::Duration::seconds(30),
            )
            .unwrap()
            .with_model_dataset_binding(binding.clone())
            .unwrap();
            let context = PostgresAgentContextSource::new(
                p.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                Some(32),
            )
            .unwrap()
            .with_model_dataset_binding(binding.clone())
            .unwrap();
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                ActorId::new("alice"),
                AuthGeneration::new(7),
                false,
            )
            .with_roles([Role::User])
            .build();
            Self {
                pool: p,
                vault,
                models,
                registry,
                binding,
                directory,
                context,
                auth,
            }
        }
        async fn request(&self, index: u64, channel: bool) -> (Uuid, ProviderRequest) {
            let model = self
                .models
                .create(
                    &self.auth,
                    &CreateModelConnection {
                        name: "Owned concurrent selection".into(),
                        protocol: CustomModelProtocol::OpenaiChatCompletions,
                        endpoint: "https://owned-concurrent-no-network.example.test/v1".into(),
                        model: "owned-concurrent-model".into(),
                        enabled: true,
                        api_key: ModelApiKey::new(Zeroizing::new(
                            "OWNED_V2_CONCURRENT_VAULT_CANARY".into(),
                        ))
                        .unwrap(),
                    },
                )
                .await
                .unwrap();
            let mut entropy = [0u8; 16];
            entropy[8..].copy_from_slice(&index.to_be_bytes());
            let req = BeginThreadRunV2Request {
                deployment: self.auth.deployment().clone(),
                tenant: self.auth.tenant().clone(),
                actor: ActorId::new("alice"),
                auth_generation: AuthGeneration::new(7),
                command: BeginThreadRunV2 {
                    thread_id: ThreadIdentity::new(self.auth.deployment())
                        .mint_from_entropy(entropy),
                    run_id: RunId::new(format!("owned-concurrent-run-{index}")),
                    bot_id: BotId::new("bot"),
                    anchor: if channel {
                        ThreadRunAnchor::Channel {
                            channel_id: openbot_contracts::ids::ChannelId::new("channel"),
                        }
                    } else {
                        ThreadRunAnchor::DirectBot
                    },
                    message: "Owned concurrent selection words".into(),
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
            let lease = RunExecutionLease::new(
                req.command.run_id,
                req.command.thread_id,
                req.command.bot_id,
                req.actor,
                FencingToken::new(1).unwrap(),
                0,
            )
            .unwrap();
            (
                Uuid::parse_str(&model.id).unwrap(),
                self.context.load(&lease).await.unwrap(),
            )
        }
        fn adapter(&self) -> (Arc<PostgresCustomModelProvider>, Arc<CountedDns>) {
            let dns = Arc::new(CountedDns(AtomicUsize::new(0)));
            let dialer = SafeDialer::with_resolver(
                crate::net::safe_http::EgressPolicy::default(),
                dns.clone(),
            );
            let adapter = PostgresCustomModelProvider::new(
                self.pool.clone(),
                self.vault.clone(),
                self.auth.deployment().clone(),
                self.auth.tenant().clone(),
                dialer,
                SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(5)).unwrap(),
                Some(Duration::from_secs(2)),
            )
            .unwrap()
            .with_model_dataset_binding(self.binding.clone())
            .unwrap();
            (Arc::new(adapter), dns)
        }
        async fn finish(self) {
            drop(self.context);
            drop(self.directory);
            drop(self.models);
            drop(self.binding);
            drop(self.registry);
            drop(self.vault);
            drop(self.auth);
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

    async fn wait_owned_pg_wait(client: &pool::PooledClient, blocker: i32, needle: &str) -> i32 {
        let pattern = format!("%{needle}%");
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                if let Some(row)=client.query_opt("SELECT pid FROM pg_stat_activity
                    WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2
                    ORDER BY pid LIMIT 1",&[&blocker,&pattern]).await.unwrap() { return row.get(0); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("actual owned PG waiter reached the named original lock")
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; original provider Vault-call observations"]
    async fn final_current_revocation_after_connection_wait_refuses_before_actual_vault_and_dns() {
        let admin = super::v2_test_harness::admin_config("v2_final_current_wait");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2finalcurrentwait",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            for channel in [false,true] {
                let (id,request)=f.request(600+u64::from(channel),channel).await;
                let (adapter,dns)=f.adapter();
                let mut blocker=f.pool.get().await.unwrap();
                let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                let barrier=blocker.transaction().await.unwrap();
                barrier.query_one("SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",&[&id]).await.unwrap();
                let task={let adapter=adapter.clone();tokio::spawn(async move {adapter.start(request).await})};
                let checker=f.pool.get().await.unwrap();
                wait_owned_pg_wait(&checker,blocker_pid,"FROM public.model_connections c").await;
                checker.execute("INSERT INTO public.revoked_access(email,revoked_by)
                    VALUES('owned-concurrent-alice@example.test','bob')",&[]).await.unwrap();
                barrier.commit().await.unwrap();
                let result=tokio::time::timeout(Duration::from_secs(3),task).await.unwrap().unwrap();
                assert!(matches!(result,Err(ProviderPortError::InvalidRequest{..})));
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                assert_eq!(dns.0.load(Ordering::SeqCst),0);
                checker.execute("DELETE FROM public.revoked_access WHERE email='owned-concurrent-alice@example.test'",&[]).await.unwrap();
                drop(checker);drop(blocker);drop(adapter);
            }
            f.finish().await;Ok(())
        }).await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly owned PG17; current target row locks and original guard cancellation"]
    async fn target_and_membership_withdrawal_lock_order_cancel_and_successor_refuse_without_vault_or_dns()
     {
        let admin = super::v2_test_harness::admin_config("v2_target_current_wait");
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        super::v2_test_harness::with_temp_database(&admin,"v2targetcurrentwait",|config|async move {
            let f=ConcurrentAuthorityFixture::new(config).await;
            for (index,(channel,withdrawal_first)) in [(false,true),(true,true),(false,false),(true,false)].into_iter().enumerate() {
                let (id,request)=f.request(700+index as u64,channel).await;
                let (adapter,dns)=f.adapter();
                let statement=if channel {"DELETE FROM public.channel_memberships WHERE channel_id='channel' AND user_id='alice'"}
                    else {"UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='bot'"};
                let checker=f.pool.get().await.unwrap();
                if withdrawal_first {
                    let mut revoker=f.pool.get().await.unwrap();
                    let revoker_pid:i32=revoker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                    let tx=revoker.transaction().await.unwrap();tx.execute(statement,&[]).await.unwrap();
                    let task={let adapter=adapter.clone();let request=request.clone();tokio::spawn(async move {adapter.start(request).await})};
                    wait_owned_pg_wait(&checker,revoker_pid,if channel {"FROM public.channels c"} else {"JOIN public.agent_profiles p"}).await;
                    tx.commit().await.unwrap();
                    assert!(matches!(tokio::time::timeout(Duration::from_secs(3),task).await.unwrap().unwrap(),Err(ProviderPortError::InvalidRequest{..})));
                    drop(revoker);
                } else {
                    let mut blocker=f.pool.get().await.unwrap();
                    let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get(0);
                    let barrier=blocker.transaction().await.unwrap();
                    barrier.query_one("SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",&[&id]).await.unwrap();
                    let task={let adapter=adapter.clone();let request=request.clone();tokio::spawn(async move {adapter.start(request).await})};
                    let consumer_pid=wait_owned_pg_wait(&checker,blocker_pid,"FROM public.model_connections c").await;
                    let revoker=f.pool.get().await.unwrap();
                    let change=tokio::spawn(async move {revoker.execute(statement,&[]).await.unwrap()});
                    wait_owned_pg_wait(&checker,consumer_pid,if channel {"DELETE FROM public.channel_memberships"} else {"UPDATE public.agent_profiles"}).await;
                    // The withdrawal is still waiting on positive current authority; it
                    // has not committed. Cancellation drops the original guarded owner.
                    task.abort();assert!(matches!(task.await,Err(error)if error.is_cancelled()));
                    assert_eq!(tokio::time::timeout(Duration::from_secs(3),change).await.unwrap().unwrap(),1);
                    barrier.commit().await.unwrap();drop(blocker);
                }
                // This actual retry observes the now-committed withdrawal, without
                // treating cancellation/Drop or lock release as a rollback ACK.
                assert!(matches!(adapter.start(request).await,Err(ProviderPortError::InvalidRequest{..})));
                assert_eq!(adapter.v2_vault_opens.load(Ordering::SeqCst),0);
                assert_eq!(dns.0.load(Ordering::SeqCst),0);
                if channel {checker.execute("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice')",&[]).await.unwrap();}
                else {checker.execute("UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot'",&[]).await.unwrap();}
                drop(checker);drop(adapter);
            }
            f.finish().await;Ok(())
        }).await;
    }
}
