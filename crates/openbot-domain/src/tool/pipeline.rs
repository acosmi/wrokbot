//! 唯一执行管线（v3 §8.1），做成**跳不过步**的类型状态机。
//!
//! # §8.1 逐字的那条流水线
//!
//! ```text
//! RequestedToolCall
//! → schema/size validation
//! → resolve authoritative actor/target
//! → effect classification
//! → CEL + structural/content policy
//! → optional human approval
//! → DB transaction: decision + attempt
//! → mint single-use capability
//! → execute
//! → outcome + commit_state
//! → projection/outbox
//! → redacted model-visible result
//! ```
//!
//! 十二段，落成十二个类型：[`Requested`] → [`Validated`] → [`Resolved`] → [`Classified`]
//! → [`PolicyPassed`] → [`ApprovalSettled`] → [`DecisionRecorded`] → [`ReadyToExecute`]
//! → [`Executing`] → [`ToolCallTerminal`] → [`ProjectedToolCall`] → [`ModelVisibleResult`]。
//!
//! # 判据：**没有 durable decision 就拿不到 capability，这件事必须编译不出来**
//!
//! 一条靠调用顺序自觉的管线，在"某个分支上少调了一步"时表现为**静默放行**——而这条管线上
//! 少调的那一步恰好是 §17.2 条 2「任一 acting effect 之前都有 durable decision + attempt」。
//! 所以本模块不给"顺序"留任何余地：
//!
//! - [`ReadyToExecute`] 的唯一构造入口是 [`DecisionRecorded::mint_capability`]；
//! - [`DecisionRecorded`] 的唯一构造入口是 [`ApprovalSettled::record_decision`]，而它的入参
//!   是 `Result<DurableDecisionReceipt, DecisionWriteFailed>`——**写失败被迫在类型上处理**，
//!   写失败的那一支返回 [`ToolCallTerminal`]，永远得不到 `DecisionRecorded`；
//! - 每个阶段类型的字段全私有，跨阶段跳跃没有语法可写。
//!
//! 于是"在没有 durable decision 的情况下拿到 capability"是一句**编译不过**的代码，
//! 而不是一条要靠 review 发现的顺序错误。这条由三个 `compile_fail` doctest 钉住
//! （见 [`Validated`] / [`SingleUseCapability`] / [`ReconciliationRequired`] 的文档），
//! 每个都配一个正向 doctest 证明正确写法确实能编译并跑通 —— 否则 `compile_fail`
//! 在"这个 API 压根不存在"的世界里同样会通过。
//!
//! # 诚实的边界：类型挡住的是顺序，不是伪造
//!
//! [`DurableDecisionReceipt`] 由 [`DurableDecisionReceipt::issued_by_repository`] 构造。
//! 任何代码都能调它 —— 类型系统挡不住一个存心伪造回执的调用方。它挡住的是**忘记**：
//! 忘记写 decision、忘记处理写失败、把执行提到 decision 之前。伪造是一次刻意动作，且
//! 那个构造函数的名字会让它在 review 里显眼（正常情况下它只应该出现在 repository 实现里）。
//! 这条限制写在这里，免得有人以为类型系统提供了它没提供的保证。
//!
//! # 与 `policy` 模块的关系：只表达**结论**，不 import 判定器
//!
//! [`PolicyVerdict`] 是本模块自己的窄类型。approval 侧同理（[`super::approval::PolicyVersionTag`]）。
//! 这样 CEL 求值器怎么实现、policy 文档长什么样，都不会牵动这条管线的编译面 ——
//! 集成时由 application 层把策略侧的结论映射进来。

use core::time::Duration;

use openbot_contracts::ids::{ActorId, BotId, PolicyDecisionId, RunId, ToolCallId};
pub use openbot_contracts::ids::{AttemptId, CapabilityId};

use super::approval::{
    ApprovalBinding, ApprovalInvalidation, ApprovalObservation, ApprovalTarget, ApprovalValidity,
    PolicyVersionTag,
};
use super::args::ToolArguments;
use super::commit::CommitState;
use super::metadata::{Effect, ToolMetadata, ToolMetadataError, ToolName};
use crate::audit::hash::Sha256Digest;
use crate::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};

/// policy 规则 ID。拒绝时必须带上（§15.3「policy refusal 403 + stable error code/rule ID」）。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRuleId(String);

impl PolicyRuleId {
    /// 由规则 ID 构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 调用方送进来的一次工具调用请求。**里面没有一个字段是可信的。**
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedToolCall {
    /// 调用 id。
    pub call_id: ToolCallId,
    /// 声称属于哪一次 run。权威性由 [`Validated::resolve`] 那一步重新确立。
    pub run: RunId,
    /// 声称要调用的工具名。
    pub tool: ToolName,
    /// 实参。
    pub arguments: ToolArguments,
}

/// 权威身份 —— 由 Rust 从 session / peer / DB ACL 构造，**不是**请求里自报的那份。
///
/// §5.3 与 repository contract §4 逐字：「`AuthContext` 只能由 Rust 构造，外部传来的同名字段都是
/// 不可信输入。」[`RequestedToolCall`] 里因此**没有** actor 字段 —— 不是忘了写，是不给
/// "请求里带一个 actor 然后被谁顺手采信"这条路留入口。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativeActor {
    actor: ActorId,
    bot: BotId,
}

impl AuthoritativeActor {
    /// 由已建立的认证上下文构造。
    ///
    /// 名字里带 `from_auth_context` 是刻意的：它让"这个 actor 从哪来"在调用点上可读，
    /// 而一个从请求体里取值再调它的写法会在 review 里显眼。
    #[must_use]
    pub const fn from_auth_context(actor: ActorId, bot: BotId) -> Self {
        Self { actor, bot }
    }

    /// 权威 actor。
    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 权威 bot。
    #[must_use]
    pub const fn bot(&self) -> &BotId {
        &self.bot
    }
}

/// 校验段的拒绝理由。
///
/// # 它**不是** [`ToolCallTerminal`]
///
/// §15.3 逐字：「malformed payload 400，**不产生 acting decision**。」所以这一段的失败
/// 不会走到 decision，也就不该产出一个"终态"——它在管线之外结束。审计仍然要记
/// （`AuditKind::InputRejected`），但那是一条 audit 事件，不是一次 policy 裁决。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationRejection {
    /// 请求里的工具名与 catalog 里那份声明对不上 —— 调用方拿错了 metadata。
    #[error("tool_call_metadata_mismatch")]
    ToolNameMismatch,
    /// 实参超过 [`super::metadata::ToolLimits::max_input_bytes`]。
    #[error("tool_call_input_too_large limit={limit} found={found}")]
    InputTooLarge {
        /// 声明的上限。
        limit: u32,
        /// 实际字节数。
        found: usize,
    },
    /// catalog 里那份声明本身不自洽。
    #[error("tool_metadata_invalid")]
    MetadataInvalid(#[source] ToolMetadataError),
}

/// 策略判定的**结论**（不是判定器）。理由见模块文档。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// 放行。
    Allow {
        /// 做出该判定时生效的 policy 版本。
        policy_version: PolicyVersionTag,
    },
    /// 拒绝。
    Deny {
        /// 做出该判定时生效的 policy 版本。
        policy_version: PolicyVersionTag,
        /// 触发拒绝的规则。
        rule: PolicyRuleId,
    },
}

/// 一份人工批准，连同判定它是否仍然有效所需的观测。
///
/// 两者放在一起传，是为了让 [`PolicyPassed::settle_approval`] **自己**去调
/// [`ApprovalBinding::is_still_valid`]——调用方只能提供事实，不能提供结论。
/// 只传一个 `binding` 的设计会把"这份批准还算不算数"的判断留在管线之外，而那正是
/// 一份过期批准被拿去执行的入口。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalEvidence {
    /// Durable approval row identity used by the decision/audit link.
    pub approval_id: String,
    /// 当初批准时绑定的那些字段。
    pub binding: ApprovalBinding,
    /// 此刻世界的样子。
    pub observed: ApprovalObservation,
}

/// 人工审批这一段的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// 这个工具不需要人工审批。若 catalog 声明了需要，[`PolicyPassed::settle_approval`]
    /// 会拒绝这个取值 —— 不需要审批这件事由 catalog 说了算，不由调用方说了算。
    NotRequired,
    /// 拿到了一份批准。`Box` 是因为里面装着两份完整的绑定快照，不 box 会让整个 enum 变得
    /// 很大而每个分支都要付这个代价。
    Granted(Box<ApprovalEvidence>),
    /// 人拒绝了。
    Denied,
}

/// 一次工具调用被拒的理由。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// 策略拒绝。
    PolicyDenied {
        /// 触发拒绝的规则。
        rule: PolicyRuleId,
    },
    /// 人拒绝了。
    HumanDenied,
    /// catalog 声明需要审批，但这一段拿到的是"不需要"。
    ApprovalMissing,
    /// 拿到的批准已经失效。
    ApprovalInvalid(ApprovalInvalidation),
}

impl RefusalReason {
    /// 稳定字面量（进审计用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyDenied { .. } => "policy_denied",
            Self::HumanDenied => "human_denied",
            Self::ApprovalMissing => "approval_missing",
            Self::ApprovalInvalid(_) => "approval_invalid",
        }
    }
}

/// 管线在没能把 decision 落成 durable 之前就停下的理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// decision / attempt 写不进去。§8.1 逐字：「decision 写入失败即不执行。」
    DecisionNotDurable {
        /// 出问题的依赖静态名（`"database"` 等）。**不携带数据库返回的原文** —— 那是不可信数据。
        dependency: &'static str,
    },
    /// 交回来的能力券不属于这次调用。
    CapabilityMismatch,
}

impl AbortReason {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecisionNotDurable { .. } => "decision_not_durable",
            Self::CapabilityMismatch => "capability_mismatch",
        }
    }
}

/// 写 decision / attempt 失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("decision_write_failed dependency={dependency}")]
pub struct DecisionWriteFailed {
    /// 依赖的静态名。
    pub dependency: &'static str,
}

/// 写 outcome 失败 —— **执行已经发生**，结果写不进来。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("outcome_write_failed dependency={dependency}")]
pub struct OutcomeWriteFailed {
    /// 依赖的静态名。
    pub dependency: &'static str,
}

/// decision + attempt 已经落成 durable 的回执。
///
/// **只有拿到它才能继续**。伪造它是可能的（见模块文档的"诚实的边界"一段），但忘记它
/// 是不可能的。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableDecisionReceipt {
    decision: PolicyDecisionId,
    attempt: AttemptId,
}

impl DurableDecisionReceipt {
    /// 由 repository 在**事务提交之后**签发。
    ///
    /// 名字是契约的一部分：它只应该出现在 repository 实现里。出现在别处 = 有人在声称
    /// 一件没发生的事。
    #[must_use]
    pub const fn issued_by_repository(decision: PolicyDecisionId, attempt: AttemptId) -> Self {
        Self { decision, attempt }
    }

    /// decision 行的 id。
    #[must_use]
    pub const fn decision(&self) -> &PolicyDecisionId {
        &self.decision
    }

    /// attempt 行的 id。
    #[must_use]
    pub const fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
}

/// 一次执行的结果（**不含内容**）。
///
/// 领域层拿到的是结果的**形状**，不是结果本身：repository contract §6 明确禁止持久化原始 provider
/// stream / HTTP body / screen frame。字节数与耗时够审计与限额判定用，而内容留在
/// application 层，按 [`ProjectedToolCall::model_visible`] 给出的形状去裁剪。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutcome {
    /// 提交状态。
    pub commit_state: CommitState,
    /// 结果字节数。
    pub output_bytes: u32,
    /// 执行耗时。
    pub duration: Duration,
    /// 稳定错误码（`&'static str`，与 `openbot_contracts::error::ErrorCode` 同域）。
    /// **不是**错误文本 —— 文案不进 domain（repository contract §4a）。
    pub error_code: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// 阶段类型
// ---------------------------------------------------------------------------

/// 管线在各阶段都要带着走的那份上下文。
///
/// 私有，不导出：它存在的意义就是让各阶段类型不必各写一遍同样的字段，而不是给调用方
/// 一个绕过阶段的把手。
#[derive(Clone, Debug, PartialEq, Eq)]
struct CallContext {
    call_id: ToolCallId,
    run: RunId,
    metadata: ToolMetadata,
    arguments: ToolArguments,
    args_hash: Sha256Digest,
}

/// 第 1 段：刚收到的请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    request: RequestedToolCall,
}

impl Requested {
    /// 收下一个请求。
    #[must_use]
    pub const fn new(request: RequestedToolCall) -> Self {
        Self { request }
    }

    /// 第 1 → 2 段：schema / size 校验。
    ///
    /// # Errors
    ///
    /// 见 [`ValidationRejection`]。**这一段的失败不产生 decision**（§15.3）。
    pub fn validate(self, metadata: &ToolMetadata) -> Result<Validated, ValidationRejection> {
        metadata
            .validate()
            .map_err(ValidationRejection::MetadataInvalid)?;

        if self.request.tool != metadata.name {
            return Err(ValidationRejection::ToolNameMismatch);
        }

        let found = self.request.arguments.byte_len();
        if found > metadata.limits.max_input_bytes as usize {
            return Err(ValidationRejection::InputTooLarge {
                limit: metadata.limits.max_input_bytes,
                found,
            });
        }

        let args_hash = self.request.arguments.canonical_hash();
        Ok(Validated {
            context: CallContext {
                call_id: self.request.call_id,
                run: self.request.run,
                metadata: metadata.clone(),
                arguments: self.request.arguments,
                args_hash,
            },
        })
    }
}

/// 第 2 段：已通过 schema / size 校验。
///
/// # 这里拿不到 capability —— 编译期
///
/// ```compile_fail,E0599
/// # use core::time::Duration;
/// # use openbot_contracts::ids::{RunId, ToolCallId};
/// # use openbot_domain::audit::hash::Sha256Digest;
/// # use openbot_domain::tool::args::ToolArguments;
/// # use openbot_domain::tool::metadata::*;
/// # use openbot_domain::tool::pipeline::*;
/// # let metadata = ToolMetadata {
/// #     name: ToolName::new("t").unwrap(),
/// #     schema_hash: Sha256Digest::of(b"s"),
/// #     catalog_generation: CatalogGeneration::new(1),
/// #     effect: EffectClassification::declared(Effect::Write),
/// #     idempotency: Idempotency::Idempotent,
/// #     parallel_safe: true,
/// #     timeout: Duration::from_secs(1),
/// #     approval_class: ApprovalClass::NotRequired,
/// #     sandbox: SandboxRequirement::None,
/// #     limits: ToolLimits { max_input_bytes: 64, max_output_bytes: 64, max_model_visible_bytes: 64 },
/// #     resource_locks: Vec::new(),
/// # };
/// # let request = RequestedToolCall {
/// #     call_id: ToolCallId::new("tc-1"),
/// #     run: RunId::new("run-1"),
/// #     tool: ToolName::new("t").unwrap(),
/// #     arguments: ToolArguments::new(serde_json::json!({})).unwrap(),
/// # };
/// let validated = Requested::new(request).validate(&metadata).unwrap();
/// // decision 还没写，这里没有 mint_capability 可调 —— 编译失败。
/// let _ = validated.mint_capability();
/// ```
///
/// 正向对照（证明上面那条不是因为 API 压根不存在才失败）：走完全程后**确实**能铸出
/// capability，见 [`DecisionRecorded::mint_capability`] 的示例。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validated {
    context: CallContext,
}

impl Validated {
    /// 第 2 → 3 段：解析权威 actor 与 target。
    #[must_use]
    pub fn resolve(self, actor: AuthoritativeActor, target: ApprovalTarget) -> Resolved {
        Resolved {
            context: self.context,
            actor,
            target,
        }
    }

    /// 这次调用的实参摘要（§8.5 绑定进 approval 的那一个）。
    #[must_use]
    pub const fn args_hash(&self) -> &Sha256Digest {
        &self.context.args_hash
    }
}

/// 第 3 段：actor 与 target 已由权威方解析。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
}

impl Resolved {
    /// 第 3 → 4 段：effect 分类。
    ///
    /// 分类结果取自 catalog 里那份声明（[`super::metadata::EffectClassification`]），
    /// 其中已经含着"是不是从无法识别的字符串降级来的"。这一段本身不再看任何外部自述 ——
    /// §8.2：MCP annotations、server description、工具名称和模型声明都不是可信分类来源。
    #[must_use]
    pub fn classify_effect(self) -> Classified {
        let effect = self.context.metadata.effect;
        Classified {
            context: self.context,
            actor: self.actor,
            target: self.target,
            effect: effect.effect(),
            effect_downgraded: effect.was_downgraded(),
        }
    }
}

/// 第 4 段：effect 已分类。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
}

impl Classified {
    /// 这次调用会不会"做事"。§17.2 条 2 的适用面就是它为真的那些调用。
    #[must_use]
    pub const fn is_acting(&self) -> bool {
        self.effect.is_acting()
    }

    /// 第 4 → 5 段：套用策略结论。
    ///
    /// # Errors
    ///
    /// 策略拒绝时返回 [`ToolCallRefused`]。**拒绝也是一次裁决**，仍然要写 decision 与
    /// audit（§8.3：dry-run 只改变执行拦截，不跳过 decision/audit）——本类型携带了写这
    /// 两条记录所需的全部字段。
    pub fn apply_policy(self, verdict: PolicyVerdict) -> Result<PolicyPassed, ToolCallRefused> {
        match verdict {
            PolicyVerdict::Allow { policy_version } => Ok(PolicyPassed {
                context: self.context,
                actor: self.actor,
                target: self.target,
                effect: self.effect,
                effect_downgraded: self.effect_downgraded,
                policy_version,
            }),
            PolicyVerdict::Deny {
                policy_version,
                rule,
            } => Err(ToolCallRefused {
                call_id: self.context.call_id,
                run: self.context.run,
                tool: self.context.metadata.name,
                policy_version,
                reason: RefusalReason::PolicyDenied { rule },
            }),
        }
    }
}

/// 第 5 段：策略放行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPassed {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
}

impl PolicyPassed {
    /// 第 5 → 6 段：结清人工审批。
    ///
    /// 三条判定，缺一条就有一种绕过方式：
    ///
    /// 1. catalog 说要审批而这里拿到 [`ApprovalOutcome::NotRequired`] → 拒绝
    ///    （否则调用方只要传 `NotRequired` 就能跳过审批）；
    /// 2. [`ApprovalOutcome::Denied`] → 拒绝；
    /// 3. [`ApprovalOutcome::Granted`] → **本函数自己**调
    ///    [`ApprovalBinding::is_still_valid`]，失效即拒绝（否则一份过期批准照样能用）。
    ///
    /// # Errors
    ///
    /// 见上三条，返回 [`ToolCallRefused`]。
    pub fn settle_approval(
        self,
        outcome: ApprovalOutcome,
    ) -> Result<ApprovalSettled, ToolCallRefused> {
        let refuse = |reason: RefusalReason| ToolCallRefused {
            call_id: self.context.call_id.clone(),
            run: self.context.run.clone(),
            tool: self.context.metadata.name.clone(),
            policy_version: self.policy_version.clone(),
            reason,
        };

        let approval = match outcome {
            ApprovalOutcome::Denied => return Err(refuse(RefusalReason::HumanDenied)),
            ApprovalOutcome::NotRequired => {
                if self
                    .context
                    .metadata
                    .approval_class
                    .requires_human_approval()
                {
                    return Err(refuse(RefusalReason::ApprovalMissing));
                }
                None
            }
            ApprovalOutcome::Granted(evidence) => {
                match evidence.binding.is_still_valid(&evidence.observed) {
                    ApprovalValidity::Valid => Some(evidence),
                    ApprovalValidity::Invalid(why) => {
                        return Err(refuse(RefusalReason::ApprovalInvalid(why)));
                    }
                }
            }
        };

        Ok(ApprovalSettled {
            context: self.context,
            actor: self.actor,
            target: self.target,
            effect: self.effect,
            effect_downgraded: self.effect_downgraded,
            policy_version: self.policy_version,
            approval,
        })
    }
}

/// 第 6 段：审批已结清。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalSettled {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
    approval: Option<Box<ApprovalEvidence>>,
}

impl ApprovalSettled {
    /// Durable human-approval identity, absent only for tools whose catalog says not required.
    #[must_use]
    pub fn approval_id(&self) -> Option<&str> {
        self.approval
            .as_ref()
            .map(|evidence| evidence.approval_id.as_str())
    }

    /// 第 6 → 7 段：把 decision + attempt 落成 durable。
    ///
    /// 入参是**写库的结果**，不是"打算去写"。写失败的那一支返回 [`ToolCallTerminal`]，
    /// 于是 §8.1 的「decision 写入失败即不执行」不是一条要记住的规则，而是一条走不通的路。
    ///
    /// # Errors
    ///
    /// 写失败时返回 [`ToolCallTerminal::Aborted`]——**没有执行发生**，所以它不是
    /// reconciliation（那是执行之后才可能出现的状态）。
    pub fn record_decision(
        self,
        written: Result<DurableDecisionReceipt, DecisionWriteFailed>,
    ) -> Result<DecisionRecorded, Box<ToolCallTerminal>> {
        match written {
            Ok(receipt) => Ok(DecisionRecorded {
                context: self.context,
                actor: self.actor,
                target: self.target,
                effect: self.effect,
                effect_downgraded: self.effect_downgraded,
                policy_version: self.policy_version,
                approval: self.approval,
                receipt,
            }),
            Err(failure) => Err(Box::new(ToolCallTerminal::Aborted(AbortedToolCall {
                call_id: self.context.call_id,
                run: self.context.run,
                tool: self.context.metadata.name,
                reason: AbortReason::DecisionNotDurable {
                    dependency: failure.dependency,
                },
            }))),
        }
    }
}

/// 第 7 段：decision + attempt 已 durable。**这是唯一能铸 capability 的地方。**
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecorded {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
    approval: Option<Box<ApprovalEvidence>>,
    receipt: DurableDecisionReceipt,
}

impl DecisionRecorded {
    /// 第 7 → 8 段：铸一张单次能力券。
    ///
    /// 正向对照 —— 走完全程确实拿得到 capability（与 [`Validated`] 上那条 `compile_fail`
    /// 配对，证明它不是因为 API 不存在才失败）：
    ///
    /// ```
    /// # use core::time::Duration;
    /// # use openbot_contracts::ids::{ActorId, BotId, PolicyDecisionId, RunId, ToolCallId};
    /// # use openbot_domain::audit::hash::Sha256Digest;
    /// # use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
    /// # use openbot_domain::tool::args::ToolArguments;
    /// # use openbot_domain::tool::metadata::*;
    /// # use openbot_domain::tool::pipeline::*;
    /// # let metadata = ToolMetadata {
    /// #     name: ToolName::new("t").unwrap(),
    /// #     schema_hash: Sha256Digest::of(b"s"),
    /// #     catalog_generation: CatalogGeneration::new(1),
    /// #     effect: EffectClassification::declared(Effect::Write),
    /// #     idempotency: Idempotency::Idempotent,
    /// #     parallel_safe: true,
    /// #     timeout: Duration::from_secs(1),
    /// #     approval_class: ApprovalClass::NotRequired,
    /// #     sandbox: SandboxRequirement::None,
    /// #     limits: ToolLimits { max_input_bytes: 64, max_output_bytes: 64, max_model_visible_bytes: 64 },
    /// #     resource_locks: Vec::new(),
    /// # };
    /// # let request = RequestedToolCall {
    /// #     call_id: ToolCallId::new("tc-1"),
    /// #     run: RunId::new("run-1"),
    /// #     tool: ToolName::new("t").unwrap(),
    /// #     arguments: ToolArguments::new(serde_json::json!({})).unwrap(),
    /// # };
    /// let ready = Requested::new(request)
    ///     .validate(&metadata)
    ///     .unwrap()
    ///     .resolve(
    ///         AuthoritativeActor::from_auth_context(ActorId::new("a"), BotId::new("b")),
    ///         ApprovalTarget { kind: "browser_tab", id: "tab-1".to_owned() },
    ///     )
    ///     .classify_effect()
    ///     .apply_policy(PolicyVerdict::Allow { policy_version: PolicyVersionTag::new("pv-1") })
    ///     .unwrap()
    ///     .settle_approval(ApprovalOutcome::NotRequired)
    ///     .unwrap()
    ///     .record_decision(Ok(DurableDecisionReceipt::issued_by_repository(
    ///         PolicyDecisionId::new("pd-1"),
    ///         AttemptId::new("at-1"),
    ///     )))
    ///     .unwrap()
    ///     .mint_capability();
    /// let (_executing, capability) = ready.start();
    /// assert_eq!(capability.decision().as_str(), "pd-1");
    /// ```
    #[must_use]
    pub fn mint_capability(self) -> ReadyToExecute {
        let capability = SingleUseCapability {
            id: CapabilityId::new(format!(
                "cap-{}-{}",
                self.receipt.decision.as_str(),
                self.receipt.attempt.as_str()
            )),
            call_id: self.context.call_id.clone(),
            decision: self.receipt.decision.clone(),
            attempt: self.receipt.attempt.clone(),
        };
        ReadyToExecute {
            context: self.context,
            actor: self.actor,
            target: self.target,
            effect: self.effect,
            effect_downgraded: self.effect_downgraded,
            policy_version: self.policy_version,
            approval: self.approval,
            receipt: self.receipt,
            capability,
        }
    }

    /// decision + attempt 的回执。
    #[must_use]
    pub const fn receipt(&self) -> &DurableDecisionReceipt {
        &self.receipt
    }
}

/// **单次**能力券。
///
/// # 单次性由类型承担
///
/// 它不实现 `Clone`、不实现 `Copy`，而 [`Self::redeem`] 按值消费 `self`。于是"用两次"是
/// 一次 use-after-move，编译不过：
///
/// ```compile_fail,E0382
/// # use openbot_domain::tool::pipeline::*;
/// fn twice(capability: SingleUseCapability) {
///     let _first = capability.redeem();
///     let _second = capability.redeem(); // 已经被移走了
/// }
/// ```
///
/// 正向对照：用一次是可以的，见 [`DecisionRecorded::mint_capability`] 的示例末尾。
#[derive(Debug, PartialEq, Eq)]
pub struct SingleUseCapability {
    id: CapabilityId,
    call_id: ToolCallId,
    decision: PolicyDecisionId,
    attempt: AttemptId,
}

impl SingleUseCapability {
    /// 券的 id。
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// 这张券对应的 decision。
    #[must_use]
    pub const fn decision(&self) -> &PolicyDecisionId {
        &self.decision
    }

    /// 这张券对应的 attempt。
    #[must_use]
    pub const fn attempt(&self) -> &AttemptId {
        &self.attempt
    }

    /// 兑付这张券 —— **消费 `self`**。
    #[must_use]
    pub fn redeem(self) -> RedeemedCapability {
        RedeemedCapability {
            id: self.id,
            call_id: self.call_id,
        }
    }
}

/// 已兑付的能力券。
///
/// 它是"这次执行确实持券"的凭证，[`Executing::record_outcome`] 要求出示它。同样不实现
/// `Clone` —— 一张兑付过的券再传给第二次 `record_outcome` 会被移动检查挡住。
#[derive(Debug, PartialEq, Eq)]
pub struct RedeemedCapability {
    id: CapabilityId,
    call_id: ToolCallId,
}

impl RedeemedCapability {
    /// 券的 id。
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }
}

/// 第 8 段：券已铸好，可以执行。
#[derive(Debug, PartialEq, Eq)]
pub struct ReadyToExecute {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
    approval: Option<Box<ApprovalEvidence>>,
    receipt: DurableDecisionReceipt,
    capability: SingleUseCapability,
}

impl ReadyToExecute {
    /// 第 8 → 9 段：交出券，进入执行中。
    ///
    /// 券**离开**管线交给执行方，管线自己只留下 id 用于回收核对。这样"执行方拿到了券"
    /// 与"管线还捏着一张一样的券"不可能同时成立。
    #[must_use]
    pub fn start(self) -> (Executing, SingleUseCapability) {
        let executing = Executing {
            context: self.context,
            actor: self.actor,
            target: self.target,
            effect: self.effect,
            effect_downgraded: self.effect_downgraded,
            policy_version: self.policy_version,
            approval: self.approval,
            receipt: self.receipt,
            capability_id: self.capability.id.clone(),
        };
        (executing, self.capability)
    }
}

/// 第 9 段：执行中。
#[derive(Debug, PartialEq, Eq)]
pub struct Executing {
    context: CallContext,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
    approval: Option<Box<ApprovalEvidence>>,
    receipt: DurableDecisionReceipt,
    capability_id: CapabilityId,
}

impl Executing {
    /// 第 9 → 10 段：记录 outcome 与 `commit_state`。
    ///
    /// 出示已兑付的券（[`RedeemedCapability`]），并交出**写 outcome 的结果**。
    /// 写失败 → [`ToolCallTerminal::ReconciliationRequired`]，这正是 §8.1 那句
    /// 「执行发生但 outcome 无法写入时，run 进入 `ReconciliationRequired`」。
    #[must_use]
    pub fn record_outcome(
        self,
        redeemed: RedeemedCapability,
        written: Result<ToolOutcome, OutcomeWriteFailed>,
    ) -> ToolCallTerminal {
        if redeemed.id != self.capability_id || redeemed.call_id != self.context.call_id {
            // 拿别人的券来交差。这不是执行失败，是身份不匹配 —— 归 abort。
            return ToolCallTerminal::Aborted(AbortedToolCall {
                call_id: self.context.call_id,
                run: self.context.run,
                tool: self.context.metadata.name,
                reason: AbortReason::CapabilityMismatch,
            });
        }

        match written {
            Ok(outcome) if outcome.commit_state.requires_reconciliation() => {
                ToolCallTerminal::ReconciliationRequired(ReconciliationRequired {
                    call_id: self.context.call_id,
                    run: self.context.run,
                    tool: self.context.metadata.name,
                    decision: self.receipt.decision,
                    attempt: self.receipt.attempt,
                    dependency: "commit_state",
                })
            }
            Ok(outcome) => ToolCallTerminal::Completed(Box::new(CompletedToolCall {
                call_id: self.context.call_id,
                run: self.context.run,
                metadata: self.context.metadata,
                args_hash: self.context.args_hash,
                actor: self.actor,
                target: self.target,
                effect: self.effect,
                effect_downgraded: self.effect_downgraded,
                policy_version: self.policy_version,
                receipt: self.receipt,
                outcome,
            })),
            Err(failure) => ToolCallTerminal::ReconciliationRequired(ReconciliationRequired {
                call_id: self.context.call_id,
                run: self.context.run,
                tool: self.context.metadata.name,
                decision: self.receipt.decision,
                attempt: self.receipt.attempt,
                dependency: failure.dependency,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// 终态
// ---------------------------------------------------------------------------

/// 被拒的调用。**decision 仍然存在** —— 拒绝也是一次裁决。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCallRefused {
    /// 调用 id。
    pub call_id: ToolCallId,
    /// 所属 run。
    pub run: RunId,
    /// 工具名。
    pub tool: ToolName,
    /// 做出判定时的 policy 版本。
    pub policy_version: PolicyVersionTag,
    /// 拒绝理由。
    pub reason: RefusalReason,
}

/// 在 decision 落成 durable 之前就停下的调用。**什么都没执行。**
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortedToolCall {
    /// 调用 id。
    pub call_id: ToolCallId,
    /// 所属 run。
    pub run: RunId,
    /// 工具名。
    pub tool: ToolName,
    /// 停下的理由。
    pub reason: AbortReason,
}

/// 执行完成且 outcome 已落库。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedToolCall {
    call_id: ToolCallId,
    run: RunId,
    metadata: ToolMetadata,
    args_hash: Sha256Digest,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    effect: Effect,
    effect_downgraded: bool,
    policy_version: PolicyVersionTag,
    receipt: DurableDecisionReceipt,
    outcome: ToolOutcome,
}

impl CompletedToolCall {
    /// 第 10 → 11 段：投影 / outbox。
    #[must_use]
    pub fn project(self) -> ProjectedToolCall {
        ProjectedToolCall { completed: self }
    }

    /// 执行结果。
    #[must_use]
    pub const fn outcome(&self) -> &ToolOutcome {
        &self.outcome
    }

    /// 调用 id。
    #[must_use]
    pub const fn call_id(&self) -> &ToolCallId {
        &self.call_id
    }
}

/// 执行发生了，但 outcome 写不进来 —— run 进入 reconciliation。
///
/// # 这个类型**没有**通往"继续工具循环"或"自动重试"的边
///
/// §8.1 逐字：「执行发生但 outcome 无法写入时，run 进入 `ReconciliationRequired`，
/// **不能继续工具循环或自动重试**。」所以本类型只有取值器，没有任何返回管线阶段的方法：
///
/// ```compile_fail,E0599
/// # use openbot_domain::tool::pipeline::*;
/// fn keep_going(state: ReconciliationRequired) {
///     let _ = state.retry();
/// }
/// ```
///
/// [`ToolCallTerminal::loop_directive`] 对它恒为 [`ToolLoopDirective::Halt`]，
/// 运行期的那一半由 `reconciliation_has_no_path_back_into_the_loop` 钉住。
///
/// 与 [`super::commit::judge_replay`] 的关系要说清楚：那个判定表回答的是"一次未知 commit
/// **在人参与的和解流程里**能不能重放"，而本类型表达的是"**自动**重试这条路不存在"。
/// 两者不矛盾 —— 前者是给和解流程用的判据，后者是给工具循环用的禁令。所以本类型刻意
/// **不**暴露 `replay_judgement()`：一个挂在终态上的重放建议，早晚会被当成重放授权。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationRequired {
    call_id: ToolCallId,
    run: RunId,
    tool: ToolName,
    decision: PolicyDecisionId,
    attempt: AttemptId,
    dependency: &'static str,
}

impl ReconciliationRequired {
    /// 调用 id。
    #[must_use]
    pub const fn call_id(&self) -> &ToolCallId {
        &self.call_id
    }

    /// 所属 run。
    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// 工具名。
    #[must_use]
    pub const fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// 对应的 decision。
    #[must_use]
    pub const fn decision(&self) -> &PolicyDecisionId {
        &self.decision
    }

    /// 对应的 attempt。
    #[must_use]
    pub const fn attempt(&self) -> &AttemptId {
        &self.attempt
    }

    /// 写不进去的那个依赖的静态名。
    #[must_use]
    pub const fn dependency(&self) -> &'static str {
        self.dependency
    }

    /// 这次调用的 `commit_state` —— **恒为** [`CommitState::Unknown`]。
    ///
    /// 常量而不是字段：执行已经发生、结果写不进来，按定义就是不可知。留一个字段等于给
    /// "把它填成 `NotCommitted` 然后重试"留了入口。
    #[must_use]
    pub const fn commit_state(&self) -> CommitState {
        CommitState::Unknown
    }
}

/// 工具调用的终态。四种，互斥且穷尽。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolCallTerminal {
    /// 被策略或人拒绝。
    Refused(ToolCallRefused),
    /// 在 decision durable 之前停下，什么都没执行。
    Aborted(AbortedToolCall),
    /// 完成。
    ///
    /// `Box` 是因为 [`CompletedToolCall`] 携带整份 [`ToolMetadata`] 与实参摘要等一大组
    /// 字段，比其余三个变体大一个量级；不 box 的话每个终态（包括最常见的 `Refused`）都要
    /// 为它付内存。这是 clippy `large_enum_variant` 在这里的正确处理。
    Completed(Box<CompletedToolCall>),
    /// 需要和解。
    ReconciliationRequired(ReconciliationRequired),
}

/// 工具循环该继续还是停下。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolLoopDirective {
    /// 可以继续下一次工具调用。
    Continue,
    /// 必须停下。
    Halt {
        /// 停下的理由。
        reason: HaltReason,
    },
}

/// 工具循环必须停下的理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltReason {
    /// outcome 写不进来，commit 未知（§8.1）。
    UnknownCommit,
    /// decision 落不成 durable —— 再调下去只会产生一批无人知晓的 acting（§17.2 条 2）。
    DecisionNotDurable,
    /// 交回来的券对不上，管线自身的完整性存疑。
    CapabilityMismatch,
}

impl ToolCallTerminal {
    /// 这个终态之后，工具循环该怎么办。
    ///
    /// 穷举 match：新增终态会在这里编译失败，逼作者当场表态"它能不能继续"。
    #[must_use]
    pub const fn loop_directive(&self) -> ToolLoopDirective {
        match self {
            // 被拒是一次正常结果：模型可以换个做法。它已经有 decision 与 audit。
            Self::Refused(_) | Self::Completed(_) => ToolLoopDirective::Continue,
            Self::ReconciliationRequired(_) => ToolLoopDirective::Halt {
                reason: HaltReason::UnknownCommit,
            },
            Self::Aborted(aborted) => match aborted.reason {
                AbortReason::DecisionNotDurable { .. } => ToolLoopDirective::Halt {
                    reason: HaltReason::DecisionNotDurable,
                },
                AbortReason::CapabilityMismatch => ToolLoopDirective::Halt {
                    reason: HaltReason::CapabilityMismatch,
                },
            },
        }
    }

    /// 这次调用有没有真的执行过。
    ///
    /// 用途是判"要不要担心副作用"：只有 [`Self::Completed`] 与
    /// [`Self::ReconciliationRequired`] 为真。
    #[must_use]
    pub const fn execution_happened(&self) -> bool {
        match self {
            Self::Refused(_) | Self::Aborted(_) => false,
            Self::Completed(_) | Self::ReconciliationRequired(_) => true,
        }
    }
}

/// 第 11 段：已投影 / 已入 outbox。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedToolCall {
    completed: CompletedToolCall,
}

/// 给模型看的那份结果的**形状**（第 12 段）。
///
/// 只有形状没有内容：内容由 application 层按这里给出的字节上限去裁剪。领域层不碰工具
/// 结果的原文（repository contract §6）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelVisibleResult {
    /// 结果状态。
    pub status: ModelVisibleStatus,
    /// 稳定错误码。
    pub error_code: Option<&'static str>,
    /// 模型可以看到的字节数（已按上限裁剪）。
    pub visible_bytes: u32,
    /// 是不是被裁过。
    ///
    /// 必须告诉模型：一段被悄悄截断的结果会让模型以为自己读到了全部，然后据此下结论。
    pub truncated: bool,
}

/// 模型可见结果的状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelVisibleStatus {
    /// 成功。
    Ok,
    /// 失败（工具跑了但没成）。
    Failed,
}

impl ProjectedToolCall {
    /// 第 11 → 12 段：算出给模型看的那份结果的形状。
    #[must_use]
    pub fn model_visible(&self) -> ModelVisibleResult {
        let limit = self.completed.metadata.limits.max_model_visible_bytes;
        let produced = self.completed.outcome.output_bytes;
        ModelVisibleResult {
            status: if self.completed.outcome.error_code.is_some() {
                ModelVisibleStatus::Failed
            } else {
                ModelVisibleStatus::Ok
            },
            error_code: self.completed.outcome.error_code,
            visible_bytes: produced.min(limit),
            truncated: produced > limit,
        }
    }

    /// 这次调用要写进审计的事实集合。
    ///
    /// 它是 [`crate::audit::payload`] 那份 allowlist 的实际消费点：这里能记什么，完全由
    /// [`AuditFact`] 的变体决定 —— 想记工具结果原文的代码在这里找不到可用的变体。
    ///
    /// # Errors
    ///
    /// 标识符字段（工具名 / decision id / policy 版本 / 目标 id）不满足
    /// [`AuditIdentifier`] 的约束时返回 [`crate::audit::payload::AuditFieldError`]；
    /// 重键时返回 [`crate::audit::payload::AuditPayloadError`]。两者都包成
    /// [`AuditProjectionError`]。
    pub fn audit_payload(&self) -> Result<AuditPayload, AuditProjectionError> {
        let completed = &self.completed;
        let visible = self.model_visible();

        let mut facts = vec![
            AuditFact::ToolName(AuditIdentifier::new(completed.metadata.name.as_str())?),
            AuditFact::EffectClass(AuditLabel::new(completed.effect.as_str())),
            AuditFact::EffectDowngraded(completed.effect_downgraded),
            AuditFact::CanonicalArgsHash(completed.args_hash),
            AuditFact::SchemaHash(completed.metadata.schema_hash),
            AuditFact::TargetKind(AuditLabel::new(completed.target.kind)),
            AuditFact::TargetId(AuditIdentifier::new(completed.target.id.as_str())?),
            AuditFact::DecisionId(AuditIdentifier::new(completed.receipt.decision().as_str())?),
            AuditFact::PolicyVersion(AuditIdentifier::new(completed.policy_version.as_str())?),
            AuditFact::CommitState(AuditLabel::new(completed.outcome.commit_state.as_str())),
            AuditFact::CatalogGeneration(completed.metadata.catalog_generation.get()),
            AuditFact::Idempotency(AuditLabel::new(completed.metadata.idempotency.as_str())),
            AuditFact::ApprovalClass(AuditLabel::new(completed.metadata.approval_class.as_str())),
            AuditFact::SandboxRequirement(AuditLabel::new(completed.metadata.sandbox.as_str())),
            AuditFact::ParallelSafe(completed.metadata.parallel_safe),
            AuditFact::OutputBytes(u64::from(completed.outcome.output_bytes)),
            AuditFact::OutputTruncated(visible.truncated),
            AuditFact::DurationMs(
                u64::try_from(completed.outcome.duration.as_millis()).unwrap_or(u64::MAX),
            ),
        ];
        if let Some(code) = completed.outcome.error_code {
            facts.push(AuditFact::ErrorCode(AuditLabel::new(code)));
        }

        Ok(AuditPayload::from_facts(facts)?)
    }

    /// 完成态本体。
    #[must_use]
    pub const fn completed(&self) -> &CompletedToolCall {
        &self.completed
    }
}

/// 投影成审计事实时的失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditProjectionError {
    /// 某个标识符字段不合法。
    #[error("audit_projection_field_invalid")]
    Field(#[from] crate::audit::payload::AuditFieldError),
    /// payload 组装失败。
    #[error("audit_projection_payload_invalid")]
    Payload(#[from] crate::audit::payload::AuditPayloadError),
}

#[cfg(test)]
mod tests {
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{ComputerGeneration, DocumentGeneration};
    use serde_json::json;
    use time::OffsetDateTime;

    use super::super::metadata::{
        ApprovalClass, CatalogGeneration, EffectClassification, Idempotency, SandboxRequirement,
        ToolLimits,
    };
    use super::*;

    fn metadata(approval_class: ApprovalClass) -> ToolMetadata {
        ToolMetadata {
            name: ToolName::new("browser.click").unwrap(),
            schema_hash: Sha256Digest::of(b"schema"),
            catalog_generation: CatalogGeneration::new(4),
            effect: EffectClassification::declared(Effect::Execute),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(30),
            approval_class,
            sandbox: SandboxRequirement::Required,
            limits: ToolLimits {
                max_input_bytes: 4096,
                max_output_bytes: 8192,
                max_model_visible_bytes: 1024,
            },
            resource_locks: Vec::new(),
        }
    }

    fn request() -> RequestedToolCall {
        RequestedToolCall {
            call_id: ToolCallId::new("tc-1"),
            run: RunId::new("run-1"),
            tool: ToolName::new("browser.click").unwrap(),
            arguments: ToolArguments::new(json!({"ref": "el-1"})).unwrap(),
        }
    }

    fn actor() -> AuthoritativeActor {
        AuthoritativeActor::from_auth_context(ActorId::new("actor-1"), BotId::new("bot-1"))
    }

    fn target() -> ApprovalTarget {
        ApprovalTarget {
            kind: "browser_tab",
            id: "tab-9".to_owned(),
        }
    }

    fn receipt() -> DurableDecisionReceipt {
        DurableDecisionReceipt::issued_by_repository(
            PolicyDecisionId::new("pd-1"),
            AttemptId::new("at-1"),
        )
    }

    fn allow() -> PolicyVerdict {
        PolicyVerdict::Allow {
            policy_version: PolicyVersionTag::new("pv-1"),
        }
    }

    /// 走到"券已铸好"这一步的公共前缀。
    fn ready(approval_class: ApprovalClass, outcome: ApprovalOutcome) -> ReadyToExecute {
        Requested::new(request())
            .validate(&metadata(approval_class))
            .unwrap()
            .resolve(actor(), target())
            .classify_effect()
            .apply_policy(allow())
            .unwrap()
            .settle_approval(outcome)
            .unwrap()
            .record_decision(Ok(receipt()))
            .unwrap()
            .mint_capability()
    }

    fn outcome(commit_state: CommitState) -> ToolOutcome {
        ToolOutcome {
            commit_state,
            output_bytes: 512,
            duration: Duration::from_millis(1200),
            error_code: None,
        }
    }

    /// 正向对照：完整走通一次，拿到 Completed。
    ///
    /// 它是本模块**全部**"不能跳步"断言的对照组 —— 没有它，那些断言在"管线压根走不通"
    /// 的世界里同样成立。
    #[test]
    fn the_happy_path_runs_end_to_end() {
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        assert_eq!(capability.decision().as_str(), "pd-1");
        assert_eq!(capability.attempt().as_str(), "at-1");

        let terminal =
            executing.record_outcome(capability.redeem(), Ok(outcome(CommitState::Committed)));
        match &terminal {
            ToolCallTerminal::Completed(completed) => {
                assert_eq!(completed.call_id().as_str(), "tc-1");
                assert_eq!(completed.outcome().commit_state, CommitState::Committed);
            }
            other => panic!("应当完成，实际是 {other:?}"),
        }
        assert_eq!(terminal.loop_directive(), ToolLoopDirective::Continue);
        assert!(terminal.execution_happened());
    }

    /// §8.1「decision 写入失败即不执行」：写失败拿不到 [`DecisionRecorded`]，
    /// 因此也就没有任何路径通往 `mint_capability`。
    #[test]
    fn a_failed_decision_write_can_never_reach_execution() {
        let settled = Requested::new(request())
            .validate(&metadata(ApprovalClass::NotRequired))
            .unwrap()
            .resolve(actor(), target())
            .classify_effect()
            .apply_policy(allow())
            .unwrap()
            .settle_approval(ApprovalOutcome::NotRequired)
            .unwrap();

        let terminal = *settled
            .record_decision(Err(DecisionWriteFailed {
                dependency: "database",
            }))
            .expect_err("写失败必须拿不到 DecisionRecorded");

        match &terminal {
            ToolCallTerminal::Aborted(aborted) => {
                assert_eq!(
                    aborted.reason,
                    AbortReason::DecisionNotDurable {
                        dependency: "database"
                    }
                );
            }
            other => panic!("应当 abort，实际是 {other:?}"),
        }
        // 什么都没执行 —— 这是它与 reconciliation 的关键区别。
        assert!(!terminal.execution_happened());
        // 而且工具循环必须停：再调下去只会产生一批无人知晓的 acting。
        assert_eq!(
            terminal.loop_directive(),
            ToolLoopDirective::Halt {
                reason: HaltReason::DecisionNotDurable
            }
        );
    }

    /// §8.1「执行发生但 outcome 无法写入 → `ReconciliationRequired`，不能继续工具循环或
    /// 自动重试」的运行期一半。编译期那一半是 [`ReconciliationRequired`] 文档里的
    /// `compile_fail` doctest。
    #[test]
    fn reconciliation_has_no_path_back_into_the_loop() {
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        let terminal = executing.record_outcome(
            capability.redeem(),
            Err(OutcomeWriteFailed {
                dependency: "database",
            }),
        );

        let ToolCallTerminal::ReconciliationRequired(state) = &terminal else {
            panic!("outcome 写失败必须进 reconciliation，实际是 {terminal:?}");
        };
        assert_eq!(state.commit_state(), CommitState::Unknown);
        assert_eq!(state.decision().as_str(), "pd-1");
        assert_eq!(state.attempt().as_str(), "at-1");
        assert_eq!(state.dependency(), "database");

        assert_eq!(
            terminal.loop_directive(),
            ToolLoopDirective::Halt {
                reason: HaltReason::UnknownCommit
            }
        );
        assert!(
            terminal.execution_happened(),
            "执行确实发生过 —— 这正是不能重试的理由"
        );
    }

    #[test]
    fn a_durably_recorded_unknown_commit_still_enters_reconciliation() {
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        let terminal =
            executing.record_outcome(capability.redeem(), Ok(outcome(CommitState::Unknown)));
        let ToolCallTerminal::ReconciliationRequired(state) = &terminal else {
            panic!("已落库的 unknown 也不能伪装 Completed：{terminal:?}");
        };
        assert_eq!(state.dependency(), "commit_state");
        assert_eq!(state.commit_state(), CommitState::Unknown);
        assert_eq!(
            terminal.loop_directive(),
            ToolLoopDirective::Halt {
                reason: HaltReason::UnknownCommit
            }
        );
    }

    /// 四个终态的 `loop_directive` 全覆盖，含正向对照（两个 Continue）。
    #[test]
    fn every_terminal_has_a_declared_loop_directive() {
        let refused = ToolCallTerminal::Refused(ToolCallRefused {
            call_id: ToolCallId::new("tc-1"),
            run: RunId::new("run-1"),
            tool: ToolName::new("t").unwrap(),
            policy_version: PolicyVersionTag::new("pv-1"),
            reason: RefusalReason::HumanDenied,
        });
        assert_eq!(refused.loop_directive(), ToolLoopDirective::Continue);
        assert!(!refused.execution_happened());

        let mismatch = ToolCallTerminal::Aborted(AbortedToolCall {
            call_id: ToolCallId::new("tc-1"),
            run: RunId::new("run-1"),
            tool: ToolName::new("t").unwrap(),
            reason: AbortReason::CapabilityMismatch,
        });
        assert_eq!(
            mismatch.loop_directive(),
            ToolLoopDirective::Halt {
                reason: HaltReason::CapabilityMismatch
            }
        );
    }

    /// 拿别人的券来交差 → abort，不写 outcome。
    #[test]
    fn a_capability_from_another_call_is_refused_at_outcome_time() {
        let (executing, _own) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        // 另起一条管线，拿它的券。
        let (_other_executing, foreign) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();

        // 两条管线的 receipt 相同（测试夹具），所以刻意改一下 call_id 之外的东西也无从伪装 ——
        // 这里直接检验"券的 id 必须与本管线铸出的那张相同"。
        let mut tampered = foreign.redeem();
        tampered.id = CapabilityId::new("cap-forged");

        let terminal = executing.record_outcome(tampered, Ok(outcome(CommitState::Committed)));
        match terminal {
            ToolCallTerminal::Aborted(aborted) => {
                assert_eq!(aborted.reason, AbortReason::CapabilityMismatch);
            }
            other => panic!("券对不上必须 abort，实际是 {other:?}"),
        }
    }

    /// validation 段的失败**不产生 decision**（§15.3），逐条覆盖。
    #[test]
    fn validation_failures_stop_before_any_decision() {
        // 工具名对不上。
        let mut wrong_tool = request();
        wrong_tool.tool = ToolName::new("browser.type").unwrap();
        assert_eq!(
            Requested::new(wrong_tool)
                .validate(&metadata(ApprovalClass::NotRequired))
                .unwrap_err(),
            ValidationRejection::ToolNameMismatch
        );

        // 实参超限。
        let mut small = metadata(ApprovalClass::NotRequired);
        small.limits.max_input_bytes = 4;
        let found = request().arguments.byte_len();
        assert_eq!(
            Requested::new(request()).validate(&small).unwrap_err(),
            ValidationRejection::InputTooLarge { limit: 4, found }
        );

        // catalog 声明自己就不自洽。
        let mut broken = metadata(ApprovalClass::NotRequired);
        broken.timeout = Duration::ZERO;
        assert_eq!(
            Requested::new(request()).validate(&broken).unwrap_err(),
            ValidationRejection::MetadataInvalid(ToolMetadataError::ZeroTimeout)
        );

        // 正向对照：合法请求确实能过这一段。
        assert!(
            Requested::new(request())
                .validate(&metadata(ApprovalClass::NotRequired))
                .is_ok()
        );
    }

    /// 策略拒绝是终态，且带得出规则 id（§15.3）。
    #[test]
    fn a_policy_denial_carries_its_rule_id() {
        let refused = Requested::new(request())
            .validate(&metadata(ApprovalClass::NotRequired))
            .unwrap()
            .resolve(actor(), target())
            .classify_effect()
            .apply_policy(PolicyVerdict::Deny {
                policy_version: PolicyVersionTag::new("pv-1"),
                rule: PolicyRuleId::new("deny.private_hosts"),
            })
            .unwrap_err();
        assert_eq!(
            refused.reason,
            RefusalReason::PolicyDenied {
                rule: PolicyRuleId::new("deny.private_hosts")
            }
        );
    }

    /// 三条审批判定逐条覆盖。
    #[test]
    fn approval_cannot_be_skipped_denied_or_stale() {
        let passed = || {
            Requested::new(request())
                .validate(&metadata(ApprovalClass::EveryCall))
                .unwrap()
                .resolve(actor(), target())
                .classify_effect()
                .apply_policy(allow())
                .unwrap()
        };

        // 1. catalog 说要审批，调用方却传 NotRequired。
        assert_eq!(
            passed()
                .settle_approval(ApprovalOutcome::NotRequired)
                .unwrap_err()
                .reason,
            RefusalReason::ApprovalMissing
        );

        // 2. 人拒绝。
        assert_eq!(
            passed()
                .settle_approval(ApprovalOutcome::Denied)
                .unwrap_err()
                .reason,
            RefusalReason::HumanDenied
        );

        // 3. 批准已失效（这里用过期）。
        let binding = ApprovalBinding {
            actor: ActorId::new("actor-1"),
            auth_generation: AuthGeneration::new(3),
            bot: BotId::new("bot-1"),
            run: RunId::new("run-1"),
            tool: ToolName::new("browser.click").unwrap(),
            args_hash: request().arguments.canonical_hash(),
            target: target(),
            computer_generation: ComputerGeneration::new(1),
            catalog_generation: CatalogGeneration::new(4),
            target_document_generation: Some(DocumentGeneration::new(2)),
            policy_version: PolicyVersionTag::new("pv-1"),
            expires_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        };
        let expired = ApprovalObservation {
            actor: binding.actor.clone(),
            auth_generation: binding.auth_generation,
            bot: binding.bot.clone(),
            run: binding.run.clone(),
            tool: binding.tool.clone(),
            args_hash: binding.args_hash,
            target: binding.target.clone(),
            computer_generation: binding.computer_generation,
            catalog_generation: binding.catalog_generation,
            target_document_generation: binding.target_document_generation,
            policy_version: binding.policy_version.clone(),
            actor_role_revoked: false,
            now: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
        };
        assert_eq!(
            passed()
                .settle_approval(ApprovalOutcome::Granted(Box::new(ApprovalEvidence {
                    approval_id: "approval-expired".to_owned(),
                    binding: binding.clone(),
                    observed: expired,
                })))
                .unwrap_err()
                .reason,
            RefusalReason::ApprovalInvalid(ApprovalInvalidation::Expired)
        );

        // 正向对照：一份仍然有效的批准能过。
        let fresh = ApprovalObservation {
            actor: binding.actor.clone(),
            auth_generation: binding.auth_generation,
            bot: binding.bot.clone(),
            run: binding.run.clone(),
            tool: binding.tool.clone(),
            args_hash: binding.args_hash,
            target: binding.target.clone(),
            computer_generation: binding.computer_generation,
            catalog_generation: binding.catalog_generation,
            target_document_generation: binding.target_document_generation,
            policy_version: binding.policy_version.clone(),
            actor_role_revoked: false,
            now: OffsetDateTime::from_unix_timestamp(1_699_999_999).unwrap(),
        };
        assert!(
            passed()
                .settle_approval(ApprovalOutcome::Granted(Box::new(ApprovalEvidence {
                    approval_id: "approval-valid".to_owned(),
                    binding,
                    observed: fresh,
                })))
                .is_ok()
        );
    }

    /// 模型可见结果必须**说出**自己被截断过。
    #[test]
    fn a_truncated_result_says_so() {
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        let mut large = outcome(CommitState::Committed);
        large.output_bytes = 4096; // 上限是 1024
        let ToolCallTerminal::Completed(completed) =
            executing.record_outcome(capability.redeem(), Ok(large))
        else {
            panic!("应当完成");
        };
        let visible = completed.project().model_visible();
        assert!(visible.truncated);
        assert_eq!(visible.visible_bytes, 1024);
        assert_eq!(visible.status, ModelVisibleStatus::Ok);

        // 正向对照：没超限时不报截断。
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        let ToolCallTerminal::Completed(completed) =
            executing.record_outcome(capability.redeem(), Ok(outcome(CommitState::Committed)))
        else {
            panic!("应当完成");
        };
        let visible = completed.project().model_visible();
        assert!(!visible.truncated);
        assert_eq!(visible.visible_bytes, 512);
    }

    /// 投影出的审计事实全部落在 allowlist 台账内，且关键字段都在。
    #[test]
    fn the_audit_projection_only_uses_allowlisted_fields() {
        let (executing, capability) =
            ready(ApprovalClass::NotRequired, ApprovalOutcome::NotRequired).start();
        let ToolCallTerminal::Completed(completed) =
            executing.record_outcome(capability.redeem(), Ok(outcome(CommitState::Committed)))
        else {
            panic!("应当完成");
        };
        let payload = completed.project().audit_payload().unwrap();

        let serde_json::Value::Object(object) = payload.to_json() else {
            panic!("payload 必须是 JSON 对象");
        };
        for key in object.keys() {
            assert!(
                crate::audit::payload::AUDIT_FIELD_LEDGER.contains(&key.as_str()),
                "投影产出了台账外的字段 {key}"
            );
        }
        // 关键字段在场：没有它们，这条审计回答不了"谁批的、按什么策略、动了什么参数"。
        for required in [
            "tool_name",
            "effect_class",
            "canonical_args_hash",
            "decision_id",
            "policy_version",
            "commit_state",
        ] {
            assert!(object.contains_key(required), "缺少字段 {required}");
        }
        // 实参本身绝不落盘 —— 只有它的摘要。
        assert!(!object.contains_key("arguments"));
        assert_eq!(
            object["canonical_args_hash"],
            serde_json::Value::String(request().arguments.canonical_hash().to_hex())
        );
    }

    /// effect 是降级来的这件事必须进审计 —— 否则"没人说得清这个工具会干什么"这条信息丢了。
    #[test]
    fn a_downgraded_effect_is_recorded_in_the_audit_payload() {
        let mut downgraded = metadata(ApprovalClass::NotRequired);
        downgraded.effect = EffectClassification::classify("readOnlyHint");

        let (executing, capability) = Requested::new(request())
            .validate(&downgraded)
            .unwrap()
            .resolve(actor(), target())
            .classify_effect()
            .apply_policy(allow())
            .unwrap()
            .settle_approval(ApprovalOutcome::NotRequired)
            .unwrap()
            .record_decision(Ok(receipt()))
            .unwrap()
            .mint_capability()
            .start();

        let ToolCallTerminal::Completed(completed) =
            executing.record_outcome(capability.redeem(), Ok(outcome(CommitState::Committed)))
        else {
            panic!("应当完成");
        };
        let payload = completed.project().audit_payload().unwrap();
        assert_eq!(
            payload.get("effect_downgraded"),
            Some(&AuditFact::EffectDowngraded(true))
        );
        // 而且降级后的档位是 execute，不是 read。
        assert_eq!(
            payload.get("effect_class"),
            Some(&AuditFact::EffectClass(AuditLabel::new("execute")))
        );
    }

    /// 只读工具不算 acting；其余四档算。§17.2 条 2 的适用面由它划定。
    #[test]
    fn only_read_effects_skip_the_acting_predicate() {
        let mut read_only = metadata(ApprovalClass::NotRequired);
        read_only.effect = EffectClassification::declared(Effect::Read);
        let classified = Requested::new(request())
            .validate(&read_only)
            .unwrap()
            .resolve(actor(), target())
            .classify_effect();
        assert!(!classified.is_acting());

        let classified = Requested::new(request())
            .validate(&metadata(ApprovalClass::NotRequired))
            .unwrap()
            .resolve(actor(), target())
            .classify_effect();
        assert!(classified.is_acting());
    }
}
