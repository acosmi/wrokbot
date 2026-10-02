//! A real built-in worker must stop when its first effect's outcome arrives after terminal.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use openbot_agent::{
    AgentToolInvokeError, AgentToolInvoker, AgentToolReply, AgentToolScheduling,
    AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime,
};
use openbot_application::{
    AgentContextError, AgentContextSource, AppEventStream, ApplicationService, NoAgentAudit,
    OpenBotApplication, ProviderAdapter, ProviderEvent, ProviderMessage, ProviderMessageRole,
    ProviderPortError, ProviderRequest, ProviderRoute, ProviderSession, ProviderToolDefinition,
    RunDispatchDecision, RunExecutionLease, RunRuntime, RunTerminal, ToolExecutionCancellation,
    ToolPortError,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::RunId;
use openbot_infra::agent_tools::PostgresAgentAuthorizationSource;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::repo::channels::ChannelRepo;
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::support::{Fixture, Stage, snapshot, wait_for};

const TOOL: &str = "computer.write";

#[derive(Default)]
struct CountingContext {
    loads: AtomicUsize,
}

#[async_trait]
impl AgentContextSource for CountingContext {
    async fn load(&self, _lease: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "Exercise two serial writes.".to_owned(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            tools: vec![ProviderToolDefinition {
                name: TOOL.to_owned(),
                description: "A counted test write.".to_owned(),
                input_schema: json!({
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                    "additionalProperties": false
                }),
            }],
            // A configured token cap requires a Usage event before the tool batch. This narrow
            // journal journey intentionally has no provider-usage or text writes.
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        })
    }
}

#[derive(Default)]
struct TwoWriteProvider {
    starts: AtomicUsize,
}

#[async_trait]
impl ProviderAdapter for TwoWriteProvider {
    async fn start(
        &self,
        _request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let start = self.starts.fetch_add(1, Ordering::SeqCst);
        let mut events = VecDeque::new();
        if start == 0 {
            for (index, call_id) in [(0, "provider-first"), (1, "provider-second")] {
                events.push_back(ProviderEvent::ToolCallCompleted {
                    index,
                    call_id: call_id.to_owned(),
                    name: TOOL.to_owned(),
                    arguments: json!({"message": "hello"}),
                });
            }
        }
        events.push_back(ProviderEvent::Completed);
        Ok(Box::new(RecordedSession { events }))
    }
}

struct RecordedSession {
    events: VecDeque<ProviderEvent>,
}

#[async_trait]
impl ProviderSession for RecordedSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.events.pop_front())
    }
}

struct ObservedApplication {
    inner: Arc<dyn ApplicationService>,
    outcomes: Mutex<Vec<Result<(), AppError>>>,
}

#[async_trait]
impl ApplicationService for ObservedApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        let is_tool = matches!(&command, AppCommand::InvokeTool(_));
        let result = self.inner.execute(auth, command).await;
        if is_tool {
            self.outcomes
                .lock()
                .expect("observed application outcomes lock")
                .push(result.as_ref().map(|_| ()).map_err(Clone::clone));
        }
        result
    }

    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        self.inner.subscribe(auth, request).await
    }
}

struct ObservedGateway {
    inner: AuthorizedAgentToolGateway,
    invocations: Mutex<Vec<String>>,
    outcomes: Mutex<Vec<Result<(), AgentToolInvokeError>>>,
    releases: AtomicUsize,
    finished: Notify,
}

impl ObservedGateway {
    fn entered(&self, provider_call_id: &str) {
        self.invocations
            .lock()
            .expect("observed gateway invocations lock")
            .push(provider_call_id.to_owned());
    }

    fn completed(&self, result: &Result<AgentToolReply, AgentToolInvokeError>) {
        self.outcomes
            .lock()
            .expect("observed gateway outcomes lock")
            .push(result.as_ref().map(|_| ()).map_err(|error| *error));
    }
}

#[async_trait]
impl AgentToolInvoker for ObservedGateway {
    fn scheduling(&self, tool_name: &str) -> AgentToolScheduling {
        self.inner.scheduling(tool_name)
    }

    async fn invoke(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        self.entered(provider_call_id);
        let result = self
            .inner
            .invoke(lease, provider_call_id, tool_name, arguments)
            .await;
        self.completed(&result);
        result
    }

    async fn invoke_cancellable(
        &self,
        lease: &RunExecutionLease,
        provider_call_id: &str,
        tool_name: &str,
        arguments: Value,
        cancellation: ToolExecutionCancellation,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        self.entered(provider_call_id);
        let result = self
            .inner
            .invoke_cancellable(lease, provider_call_id, tool_name, arguments, cancellation)
            .await;
        self.completed(&result);
        result
    }

    fn release(&self, run_id: &RunId) {
        self.inner.release(run_id);
        self.releases.fetch_add(1, Ordering::SeqCst);
        // BuiltInAgentRuntime calls this only after execute_run returns. Waiting here before
        // stop() distinguishes the journal-driven exit from test cleanup cancellation.
        self.finished.notify_one();
    }
}

pub async fn journey(config: &DatabaseConfig) -> Result<(), String> {
    let fixture = Fixture::new(config).await?;
    let control = fixture.control();
    let journal = fixture.journal(Stage::Outcome)?;
    let gate = journal.gate.clone();
    let application: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(ChannelRepo::new(fixture.pool.clone()))
            .with_tools(control.clone(), journal),
    );
    let observed_application = Arc::new(ObservedApplication {
        inner: application,
        outcomes: Mutex::new(Vec::new()),
    });
    let tools = Arc::new(ObservedGateway {
        inner: AuthorizedAgentToolGateway::new(
            observed_application.clone(),
            Arc::new(PostgresAgentAuthorizationSource::new(
                fixture.pool.clone(),
                fixture.request.deployment.clone(),
                fixture.request.tenant.clone(),
                false,
            )),
        ),
        invocations: Mutex::new(Vec::new()),
        outcomes: Mutex::new(Vec::new()),
        releases: AtomicUsize::new(0),
        finished: Notify::new(),
    });
    let context = Arc::new(CountingContext::default());
    let provider = Arc::new(TwoWriteProvider::default());
    let agent = BuiltInAgentRuntime::start(
        fixture.runtime.clone(),
        context.clone(),
        provider.clone(),
        tools.clone(),
        Arc::new(NoAgentAudit),
        BuiltInAgentConfig {
            queue_capacity: 4,
            max_concurrency: 1,
            max_tool_concurrency: 1,
            // All synchronization waits are bounded at five seconds. Neither heartbeat loss nor
            // a deadline should substitute for the late-outcome conflict under observation.
            lease_renew_interval: Duration::from_secs(60),
            run_deadline: None,
        },
    )
    .map_err(|error| format!("built-in journey runtime config: {error:?}"))?;

    let result = async {
        let consumer = agent.consumer();
        // Fixture's lease was issued by real claim + acknowledge. This test manually activates
        // that exact lease so no relay polling or second worker can drive the observation.
        if consumer.dispatch(fixture.lease.clone()).await != RunDispatchDecision::Accepted {
            return Err("built-in journey dispatch was not accepted".to_owned());
        }
        consumer
            .activate(&fixture.lease)
            .await
            .map_err(|error| format!("built-in journey activation: {error:?}"))?;
        wait_for(&gate.entered).await?;
        if control.executions() != 1 {
            return Err(
                "first effect must execute exactly once before outcome is paused".to_owned(),
            );
        }
        super::assert_paused_stage(&fixture, Stage::Outcome).await?;
        if gate
            .last_result
            .lock()
            .map_err(|_| "journal result lock poisoned".to_owned())?
            .is_some()
        {
            return Err("paused outcome must not already have reached the real journal".to_owned());
        }

        let next_sequence: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT next_event_seq FROM public.runs WHERE run_id=$1",
                &[&fixture.lease.run_id().as_str()],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        let next_sequence =
            u64::try_from(next_sequence).map_err(|_| "negative run next sequence".to_owned())?;
        let terminal = fixture
            .terminal_writer()?
            .finish_run(&fixture.lease, next_sequence, RunTerminal::Completed)
            .await
            .map_err(|error| error.to_string())?;
        if terminal.replayed {
            return Err("journey must commit the original Completed terminal".to_owned());
        }
        let after_terminal = snapshot(&fixture.pool).await?;

        gate.resume.add_permits(1);
        wait_for(&tools.finished).await?;

        if *gate
            .last_result
            .lock()
            .map_err(|_| "journal result lock poisoned".to_owned())?
            != Some(Err(ToolPortError::Conflict))
        {
            return Err("late real journal outcome must return exact Conflict".to_owned());
        }
        if observed_application
            .outcomes
            .lock()
            .map_err(|_| "application outcomes lock poisoned".to_owned())?
            .as_slice()
            != [Err(AppError::ReconciliationRequired { accepted: false })]
        {
            return Err("application must report one unaccepted reconciliation outcome".to_owned());
        }
        if tools
            .outcomes
            .lock()
            .map_err(|_| "gateway outcomes lock poisoned".to_owned())?
            .as_slice()
            != [Err(AgentToolInvokeError::ReconciliationRequired)]
        {
            return Err(
                "gateway must propagate the reconciliation terminal to the worker".to_owned(),
            );
        }
        if tools
            .invocations
            .lock()
            .map_err(|_| "gateway invocations lock poisoned".to_owned())?
            .as_slice()
            != ["provider-first"]
            || control.executions() != 1
            || context.loads.load(Ordering::SeqCst) != 1
            || provider.starts.load(Ordering::SeqCst) != 1
            || tools.releases.load(Ordering::SeqCst) != 1
        {
            return Err(
                "worker must naturally exit after one effect without a second tool or sampling"
                    .to_owned(),
            );
        }
        if snapshot(&fixture.pool).await? != after_terminal {
            return Err(
                "late outcome/worker exit mutated the committed terminal snapshot".to_owned(),
            );
        }
        super::assert_paused_stage(&fixture, Stage::Outcome).await?;
        Ok(())
    }
    .await;

    // Unblock an errored assertion path before stopping. Success above already observed the
    // worker's natural release and all durable/command assertions before this cleanup begins.
    gate.resume.add_permits(1);
    agent.stop().await;
    fixture.pool.close();
    result
}
