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
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use uuid::Uuid;

/// Shared Server/Desktop factory; every start reopens current authority and a short-lived key.
pub struct PostgresCustomModelProvider {
    pool: deadpool_postgres::Pool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    dialer: SafeDialer,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
}
impl PostgresCustomModelProvider {
    /// Bind only trusted host infrastructure. URL/model/key are never accepted by this factory.
    pub fn new(
        pool: deadpool_postgres::Pool,
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
        })
    }

    async fn start_locked(
        &self,
        client: &mut deadpool_postgres::Client,
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
    client: Option<deadpool_postgres::Client>,
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
        let owned = deadpool_postgres::Client::take(client);
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
