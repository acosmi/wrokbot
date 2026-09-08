//! W-3b application tool pipeline + PostgreSQL journal 真库矩阵。

mod harness;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::Arc;

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    AuthorizedToolCall, ResolvedToolScope, ToolApprovalRequest, ToolControlPlane,
    ToolExecutionReport, ToolPolicyEvaluation, ToolPortError, invoke_tool,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, CatalogGeneration, DeploymentId, RunId, TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::tool::ToolInvocation;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::policy::context::{ActorRef, BotRef, PageRef, PolicyContext, ToolRef};
use openbot_domain::policy::{ActionPolicy, CompiledActionPolicy, PolicyMode, evaluate};
use openbot_domain::tool::approval::ApprovalTarget;
use openbot_domain::tool::args::ToolArguments;
use openbot_domain::tool::commit::CommitState;
use openbot_domain::tool::metadata::{
    ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    ToolMetadata, ToolName,
};
use openbot_domain::tool::pipeline::ApprovalOutcome;
use serde_json::json;

use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::tools::PostgresToolJournal;

const AUDIT_KEY: &[u8] = b"tool-application-postgres17-test-key";

#[derive(Clone)]
struct FakeControl {
    policy: ActionPolicy,
    commit_state: CommitState,
    executions: Arc<AtomicUsize>,
}

impl FakeControl {
    fn allow(commit_state: CommitState) -> Self {
        Self {
            policy: ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: Vec::new(),
                allow: vec!["true".to_owned()],
            },
            commit_state,
            executions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn deny() -> Self {
        Self {
            policy: ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: vec!["true".to_owned()],
                allow: Vec::new(),
            },
            commit_state: CommitState::NotCommitted,
            executions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn executions(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ToolControlPlane for FakeControl {
    async fn metadata(&self, _name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        Ok(metadata())
    }

    async fn resolve_scope(
        &self,
        auth: &AuthContext,
        invocation: &ToolInvocation,
        _arguments: &ToolArguments,
        _metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        Ok(ResolvedToolScope {
            tenant_id: auth.tenant().clone(),
            run_id: invocation.run_id.clone(),
            thread_id: ThreadId::new("thread-tool-1"),
            bot_id: invocation.bot_id.clone(),
            call_seq: invocation.call_seq,
            target: ApprovalTarget {
                kind: "computer",
                id: "computer-1".to_owned(),
            },
            computer_generation: openbot_contracts::ids::ComputerGeneration::new(1),
            target_document_generation: None,
            approval_presentation: None,
            policy_context: policy_context(auth.actor(), &invocation.bot_id),
            idempotency_key: None,
            preflight_refusal: None,
        })
    }

    async fn evaluate_policy(
        &self,
        context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        let policy = CompiledActionPolicy::compile(&self.policy);
        Ok(ToolPolicyEvaluation::from_domain(&evaluate(
            &policy, context,
        )))
    }

    async fn approval(
        &self,
        _request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        Err(ToolPortError::Corrupt {
            field: "unexpected_approval_lookup",
        })
    }

    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let (call, redeemed) = call.redeem();
        assert_eq!(call.actor().actor().as_str(), "actor-1");
        assert_eq!(call.arguments().as_value(), &json!({"message":"hello"}));
        ToolExecutionReport::new(
            redeemed,
            "redacted-result".to_owned(),
            self.commit_state,
            Duration::from_millis(17),
            None,
        )
    }
}

fn metadata() -> ToolMetadata {
    ToolMetadata {
        name: ToolName::new("computer.write").unwrap(),
        schema_hash: Sha256Digest::of(b"schema"),
        catalog_generation: CatalogGeneration::new(3),
        effect: EffectClassification::declared(Effect::Write),
        idempotency: Idempotency::NonIdempotent,
        parallel_safe: false,
        timeout: Duration::from_secs(5),
        approval_class: ApprovalClass::NotRequired,
        sandbox: SandboxRequirement::RequiredNoEgress,
        limits: ToolLimits {
            max_input_bytes: 1024,
            max_output_bytes: 1024,
            max_model_visible_bytes: 1024,
        },
        resource_locks: Vec::new(),
    }
}

fn policy_context(actor: &ActorId, bot: &BotId) -> PolicyContext {
    PolicyContext {
        tool: ToolRef {
            name: "computer.write".to_owned(),
        },
        bot: BotRef {
            id: bot.as_str().to_owned(),
        },
        page: PageRef {
            url: "https://example.test/".to_owned(),
            host: "example.test".to_owned(),
        },
        actor: ActorRef {
            id: actor.as_str().to_owned(),
        },
        element: None,
        key: None,
        intent: None,
        file: None,
        mcp: None,
        command: None,
    }
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("dep-1"),
        TenantId::new("tenant-1"),
        ActorId::new("actor-1"),
        openbot_contracts::auth::AuthGeneration::new(1),
        false,
    )
    .with_role(Role::User)
    .build()
}

fn invocation(call_id: &str, call_seq: u64) -> ToolInvocation {
    ToolInvocation {
        call_id: ToolCallId::new(call_id),
        run_id: RunId::new("run-1"),
        bot_id: BotId::new("bot-1"),
        call_seq,
        tool_name: "computer.write".to_owned(),
        arguments: json!({"message":"hello"}),
    }
}

async fn provision(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.threads(\
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id) \
             VALUES('thread-tool-1','tenant-1','dep-1','actor-1','direct_bot','bot-1'); \
             INSERT INTO public.runs(\
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at) \
             VALUES('run-1','thread-tool-1','bot-1','actor-1',false,'running',1,now());",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn scalar(pool: &deadpool_postgres::Pool, sql: &str) -> Result<i64, String> {
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(sql, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn full_pipeline_commits_decision_attempt_capability_outcome_and_audit_in_order() {
    let admin = admin_config(
        "full_pipeline_commits_decision_attempt_capability_outcome_and_audit_in_order",
    );
    with_temp_database(&admin, "tool_pipeline", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let control = FakeControl::allow(CommitState::Committed);
            let journal = PostgresToolJournal::new(pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?;
            let result = invoke_tool(&control, &journal, &auth(), invocation("call-1", 0))
                .await
                .map_err(|error| error.to_string())?;
            if result.content != "redacted-result" || control.executions() != 1 {
                return Err(format!("model result/execution count 不符：{result:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT c.actor_id,c.bot_id,c.args_hash,a.status,a.commit_state,a.capability_id \
                     FROM public.tool_calls c JOIN public.tool_attempts a USING(tool_call_id) \
                     WHERE c.tool_call_id='call-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let args_hash: String = row.get("args_hash");
            if row.get::<_, &str>("actor_id") != "actor-1"
                || row.get::<_, &str>("bot_id") != "bot-1"
                || args_hash.len() != 64
                || row.get::<_, &str>("status") != "completed"
                || row.get::<_, Option<String>>("commit_state").as_deref() != Some("committed")
                || row.get::<_, Option<String>>("capability_id").is_none()
            {
                return Err("journal 行没有完整落地".to_owned());
            }
            let audit = client
                .query_one(
                    "SELECT event_type,payload::text FROM public.audit_events",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let payload: String = audit.get(1);
            if audit.get::<_, &str>(0) != "computer.action_allowed"
                || !payload.contains("canonical_args_hash")
                || payload.contains("hello")
            {
                return Err(format!("outcome audit 形状/脱敏不符：{payload}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn policy_refusal_writes_audit_but_no_decision_attempt_or_execution() {
    let admin = admin_config("policy_refusal_writes_audit_but_no_decision_attempt_or_execution");
    with_temp_database(&admin, "tool_refusal", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let control = FakeControl::deny();
            let journal = PostgresToolJournal::new(pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?;
            let error = invoke_tool(&control, &journal, &auth(), invocation("call-denied", 0))
                .await
                .expect_err("enforce deny 必须拒绝");
            if !matches!(error, AppError::PolicyRefused { .. }) || control.executions() != 0 {
                return Err(format!("拒绝映射/执行数不符：{error:?}"));
            }
            if scalar(&pool, "SELECT count(*)::bigint FROM public.tool_calls").await? != 0
                || scalar(&pool, "SELECT count(*)::bigint FROM public.tool_attempts").await? != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.audit_events WHERE event_type='computer.action_refused'",
                )
                .await?
                    != 1
            {
                return Err("拒绝路径错误创建 attempt 或漏 audit".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn audit_failure_rolls_back_outcome_and_forces_unaccepted_reconciliation() {
    let admin =
        admin_config("audit_failure_rolls_back_outcome_and_forces_unaccepted_reconciliation");
    with_temp_database(&admin, "tool_audit_rollback", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .batch_execute(
                    "INSERT INTO public.audit_events \
                     (id,event_type,target_type,payload,created_at,prev_hash,row_hash) VALUES \
                     ('018f47d2-2c00-7a00-8000-000000000088','legacy.linked','legacy','{}', \
                      '2026-01-01T00:00:00Z',NULL,repeat('0',64))",
                )
                .await
                .map_err(|error| error.to_string())?;
            let control = FakeControl::allow(CommitState::Committed);
            let journal = PostgresToolJournal::new(pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?;
            let result = invoke_tool(&control, &journal, &auth(), invocation("call-rollback", 0))
                .await;
            if result != Err(AppError::ReconciliationRequired { accepted: false })
                || control.executions() != 1
            {
                return Err(format!("audit 故障没有进入未受理 reconciliation：{result:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT status,commit_state FROM public.tool_attempts WHERE tool_call_id='call-rollback'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if row.get::<_, &str>("status") != "executing"
                || row.get::<_, Option<String>>("commit_state").is_some()
                || scalar(&pool, "SELECT count(*)::bigint FROM public.audit_events").await? != 1
            {
                return Err("audit 失败却提交了 outcome 或新 audit".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn unknown_commit_is_durably_reconciliation_required_and_never_success() {
    let admin = admin_config("unknown_commit_is_durably_reconciliation_required_and_never_success");
    with_temp_database(&admin, "tool_unknown", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let control = FakeControl::allow(CommitState::Unknown);
            let journal = PostgresToolJournal::new(pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?;
            let result = invoke_tool(&control, &journal, &auth(), invocation("call-unknown", 0))
                .await;
            if result != Err(AppError::ReconciliationRequired { accepted: true })
                || control.executions() != 1
            {
                return Err(format!("unknown 被伪装成成功：{result:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT status,commit_state FROM public.tool_attempts WHERE tool_call_id='call-unknown'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if row.get::<_, &str>("status") != "reconciliation_required"
                || row.get::<_, Option<String>>("commit_state").as_deref() != Some("unknown")
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.audit_events WHERE event_type='computer.action_failed'",
                )
                .await?
                    != 1
            {
                return Err("unknown journal/audit 终态不符".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn duplicate_decision_cannot_reach_a_second_execution() {
    let admin = admin_config("duplicate_decision_cannot_reach_a_second_execution");
    with_temp_database(&admin, "tool_duplicate", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let control = FakeControl::allow(CommitState::Committed);
            let journal = PostgresToolJournal::new(pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?;
            invoke_tool(&control, &journal, &auth(), invocation("call-duplicate", 0))
                .await
                .map_err(|error| error.to_string())?;
            let second =
                invoke_tool(&control, &journal, &auth(), invocation("call-duplicate", 0)).await;
            if !matches!(second, Err(AppError::DependencyUnavailable { .. }))
                || control.executions() != 1
            {
                return Err(format!("重复 decision 触发了第二次执行：{second:?}"));
            }
            if scalar(&pool, "SELECT count(*)::bigint FROM public.tool_calls").await? != 1
                || scalar(&pool, "SELECT count(*)::bigint FROM public.tool_attempts").await? != 1
            {
                return Err("重复 decision 留下额外 durable 行".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
