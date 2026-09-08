//! Compiled component catalogue and read-only governance projections.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::ids::{BotId, RunId, ThreadId};

/// Stable Activity report renderer identity.
pub const SHOW_ACTIVITY_REPORT_COMPONENT_NAME: &str = "showActivityReport";
/// Stable Activity report title.
pub const SHOW_ACTIVITY_REPORT_COMPONENT_TITLE: &str = "Activity report";
/// Default model-facing Activity report description.
pub const SHOW_ACTIVITY_REPORT_COMPONENT_DESCRIPTION: &str = "Show what this deployment has actually been doing, read from its own records rather than from anything you know. Use for 'what have the Bots been up to' and 'what has been refused'. You choose the report and the period; the figures are read for you and you will not see them.";
/// Stable data-function identity for per-Bot action counts.
pub const BOT_ACTIVITY_FUNCTION_NAME: &str = "botActivity";
/// Administrator-facing description for the Bot activity data function.
pub const BOT_ACTIVITY_FUNCTION_DESCRIPTION: &str =
    "How many actions each Bot has taken, counted from the audit trail.";
/// Stable data-function identity for recent refusal rows.
pub const RECENT_REFUSALS_FUNCTION_NAME: &str = "recentRefusals";
/// Administrator-facing description for the recent-refusals data function.
pub const RECENT_REFUSALS_FUNCTION_DESCRIPTION: &str =
    "The most recent things this deployment refused, and the reason each was refused.";
/// Stable source description shared by both first-party data functions.
pub const AUDIT_TRAIL_READS_DESCRIPTION: &str = "the audit trail";
/// Maximum UTF-8 bytes in one compiled-component model-facing description.
pub const MAX_COMPONENT_DESCRIPTION_BYTES: usize = 64 * 1024;

/// Stable tool/catalogue identity for the first compiled Rust renderer slice.
pub const SHOW_QUOTE_COMPONENT_NAME: &str = "showQuote";
/// Human-facing title stored when the build first announces the renderer.
pub const SHOW_QUOTE_COMPONENT_TITLE: &str = "Quotation";
/// Model-facing default description promoted on first arrival only.
pub const SHOW_QUOTE_COMPONENT_DESCRIPTION: &str = "Show a quotation with its attribution. Use when the exact words matter, something a person said, or a line from a document you were given.";
/// Stable Record renderer identity.
pub const SHOW_RECORD_COMPONENT_NAME: &str = "showRecord";
/// Stable Record title.
pub const SHOW_RECORD_COMPONENT_TITLE: &str = "Record";
/// Default model-facing Record description.
pub const SHOW_RECORD_COMPONENT_DESCRIPTION: &str = "Show one thing and its fields, an order, a person, a ticket. Use instead of describing a record in prose.";
/// Stable Metrics renderer identity.
pub const SHOW_METRICS_COMPONENT_NAME: &str = "showMetrics";
/// Stable Metrics title.
pub const SHOW_METRICS_COMPONENT_TITLE: &str = "Headline figures";
/// Default model-facing Metrics description.
pub const SHOW_METRICS_COMPONENT_DESCRIPTION: &str = "Show up to six headline figures, each with an optional movement. Use for a summary somebody reads at a glance.";
/// Stable Checklist renderer identity.
pub const SHOW_CHECKLIST_COMPONENT_NAME: &str = "showChecklist";
/// Stable Checklist title.
pub const SHOW_CHECKLIST_COMPONENT_TITLE: &str = "Checklist";
/// Default model-facing Checklist description.
pub const SHOW_CHECKLIST_COMPONENT_DESCRIPTION: &str = "Show a list of things and which are done. Reporting only, the person cannot tick these, so do not use it to ask for anything.";
/// Stable Notice renderer identity.
pub const SHOW_NOTICE_COMPONENT_NAME: &str = "showNotice";
/// Stable Notice title.
pub const SHOW_NOTICE_COMPONENT_TITLE: &str = "Notice";
/// Default model-facing Notice description.
pub const SHOW_NOTICE_COMPONENT_DESCRIPTION: &str = "Show a headline, a short explanation and optional supporting points. Use instead of writing several paragraphs of prose.";
/// Stable Area chart identity/title/description.
pub const SHOW_AREA_CHART_COMPONENT_NAME: &str = "showAreaChart";
/// Area chart title.
pub const SHOW_AREA_CHART_COMPONENT_TITLE: &str = "Area chart";
/// Area chart model-facing description.
pub const SHOW_AREA_CHART_COMPONENT_DESCRIPTION: &str = "The same as showLineChart with the area under each line filled. Use for volume or accumulation rather than for a rate.";
/// Stable Bar chart identity/title/description.
pub const SHOW_BAR_CHART_COMPONENT_NAME: &str = "showBarChart";
/// Bar chart title.
pub const SHOW_BAR_CHART_COMPONENT_TITLE: &str = "Bar chart";
/// Bar chart model-facing description.
pub const SHOW_BAR_CHART_COMPONENT_DESCRIPTION: &str = "Show values as a bar chart. Use when comparing a handful of named things, teams, months, categories. Not for a trend over time, which is showLineChart.";
/// Stable Line chart identity/title/description.
pub const SHOW_LINE_CHART_COMPONENT_NAME: &str = "showLineChart";
/// Line chart title.
pub const SHOW_LINE_CHART_COMPONENT_TITLE: &str = "Line chart";
/// Line chart model-facing description.
pub const SHOW_LINE_CHART_COMPONENT_DESCRIPTION: &str = "Show one or more series over an ordered axis, usually time. Every series must have one value per label.";
/// Stable Donut chart identity/title/description.
pub const SHOW_PIE_CHART_COMPONENT_NAME: &str = "showPieChart";
/// Donut chart title.
pub const SHOW_PIE_CHART_COMPONENT_TITLE: &str = "Donut chart";
/// Donut chart model-facing description.
pub const SHOW_PIE_CHART_COMPONENT_DESCRIPTION: &str = "Show how a whole is divided, as a donut with a legend. Use only when the parts sum to something meaningful, and prefer a bar chart above about six slices.";
/// Stable progress chart identity/title/description.
pub const SHOW_PROGRESS_COMPONENT_NAME: &str = "showProgress";
/// Progress chart title.
pub const SHOW_PROGRESS_COMPONENT_TITLE: &str = "Progress against target";
/// Progress chart model-facing description.
pub const SHOW_PROGRESS_COMPONENT_DESCRIPTION: &str = "Show values against their targets as progress bars. Use for 'are we there yet' questions, budget spent against budget, done against planned.";
/// Stable human approval decision component identity.
pub const ASK_APPROVAL_COMPONENT_NAME: &str = "askApproval";
/// Stable human approval decision title.
pub const ASK_APPROVAL_COMPONENT_TITLE: &str = "Approval";
/// Default model-facing human approval decision description.
pub const ASK_APPROVAL_COMPONENT_DESCRIPTION: &str = "Ask the person to approve or decline something, and WAIT for their answer. Use before doing anything you cannot undo, spending money, sending a message, changing a record. You are given their decision and any reason they typed.";
/// Stable human choice decision component identity.
pub const ASK_CHOICE_COMPONENT_NAME: &str = "askChoice";
/// Stable human choice decision title.
pub const ASK_CHOICE_COMPONENT_TITLE: &str = "Choice";
/// Default model-facing human choice decision description.
pub const ASK_CHOICE_COMPONENT_DESCRIPTION: &str = "Ask the person to pick one of several options, and WAIT for their answer. Use when you cannot sensibly guess which one they meant. You are given the id of the option they chose.";
/// Maximum UTF-8 bytes accepted for an optional Approval note.
pub const COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES: usize = 4 * 1024;

/// Closed grouping used by Admin and Settings presentation; never read by the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledComponentKind {
    /// Data visualization.
    Chart,
    /// Read-only information card.
    Card,
    /// Human-in-the-loop decision surface.
    Decision,
    /// Browser-authored source executed only by an isolated sandbox renderer.
    Sandboxed,
}

impl CompiledComponentKind {
    /// Stable database/wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chart => "chart",
            Self::Card => "card",
            Self::Decision => "decision",
            Self::Sandboxed => "sandboxed",
        }
    }
}

/// Build-owned catalogue entry. A browser may repeat it but cannot choose any field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledComponentManifestEntry {
    /// Stable model tool/catalogue key.
    pub name: String,
    /// Display title.
    pub title: String,
    /// Closed gallery grouping.
    pub kind: CompiledComponentKind,
    /// Initial model-facing description.
    pub description: String,
}

/// Exact upstream catalogue announcement wire, hardened by application identity validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentCatalogueRequest {
    /// Additive build entries; existing governance rows are never overwritten.
    pub components: Vec<CompiledComponentManifestEntry>,
}

/// Rows inserted by one additive announcement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentCatalogueAdded {
    /// Stable names actually inserted by this call, not merely requested.
    pub added: Vec<String>,
}

/// One compiled component as the authenticated read surface sees its governance state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentRecord {
    /// Stable model tool/catalogue key.
    pub name: String,
    /// Human-facing title.
    pub title: String,
    /// Closed presentation grouping.
    pub kind: CompiledComponentKind,
    /// Current editable model-facing draft.
    pub draft_description: String,
    /// Published model-facing description; absent means the component cannot be offered.
    pub published_description: Option<String>,
    /// Authoritative publication bit.
    pub published: bool,
    /// Database-clock first/last publication time.
    pub published_at: Option<OffsetDateTime>,
    /// Public identifier of the last updater, if present in the compatibility row.
    pub updated_by: Option<String>,
    /// Database-clock row update time.
    pub updated_at: OffsetDateTime,
    /// Derived comparison of draft against the published description or empty string.
    pub has_unpublished_changes: bool,
    /// Stable Agent ids explicitly withheld from this otherwise open component.
    pub withheld_from: Vec<String>,
    /// Data-function names granted to this component; empty means it may call none.
    pub functions: Vec<String>,
}

/// Authenticated component list response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRecords {
    /// All durable compiled-component governance rows in stable kind/title/name order.
    pub components: Vec<ComponentRecord>,
}

/// Exact body for granting one compiled component to one Agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentAgentGrantRequest {
    /// Server-authorized Agent identity; actor authority never comes from this body.
    pub agent_id: BotId,
}

/// Exact body for granting one build-owned data function to one component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFunctionGrantRequest {
    /// Stable function identity from the build-owned manifest.
    pub function: String,
}

/// Exact body for publishing or unpublishing one compiled component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPublicationRequest {
    /// True promotes the current draft; false makes the component unavailable to every Agent.
    pub published: bool,
}

/// Exact body for saving one compiled component's model-facing draft description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDraftRequest {
    /// Draft text; application applies ECMAScript trim and the shared byte limit.
    pub description: String,
}

/// One closed component-governance mutation after HTTP framing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComponentGovernanceMutation {
    /// Add or remove one per-Agent withholding exception.
    SetAgentGrant {
        /// Stable component identity from the route path.
        component_name: String,
        /// Server-authorized Agent identity.
        agent_id: BotId,
        /// True removes withholding; false creates it.
        granted: bool,
    },
    /// Add or remove one component-to-data-function grant.
    SetFunctionGrant {
        /// Stable component identity from the route path.
        component_name: String,
        /// Build-owned data-function identity.
        function: String,
        /// True inserts the grant; false removes it.
        granted: bool,
    },
    /// Publish or unpublish one compiled component.
    SetPublication {
        /// Stable component identity from the route path.
        component_name: String,
        /// True promotes the current draft; false preserves grants while withdrawing the tool.
        published: bool,
    },
    /// Save a compiled component draft without changing what Agents can see.
    SaveDraft {
        /// Stable component identity from the route path.
        component_name: String,
        /// Canonical, non-empty model-facing draft.
        description: String,
    },
}

impl ComponentGovernanceMutation {
    /// Borrow the component identity common to every operation.
    #[must_use]
    pub fn component_name(&self) -> &str {
        match self {
            Self::SetAgentGrant { component_name, .. }
            | Self::SetFunctionGrant { component_name, .. }
            | Self::SetPublication { component_name, .. }
            | Self::SaveDraft { component_name, .. } => component_name,
        }
    }
}

/// Mutation receipt carrying the exact authoritative governance row after commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentGovernanceReceipt {
    /// Current durable row; clients never patch governance optimistically.
    pub component: ComponentRecord,
}

/// One published compiled component actually available to one verified Agent runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedCompiledComponent {
    /// Stable renderer/tool identity.
    pub name: String,
    /// Published model-facing description; drafts never cross this boundary.
    pub description: String,
}

/// Closed runtime grant snapshot for one Agent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedCompiledComponents {
    /// Published, non-withheld components in stable name order.
    pub components: Vec<GrantedCompiledComponent>,
}

/// One pending compiled decision visible only to its authoritative actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingComponentHumanDecision {
    /// Server-minted durable identity used by the answer API.
    pub decision_id: String,
    /// Durable run waiting for this exact answer.
    pub run_id: RunId,
    /// Provider pairing id; never accepted as answer authority.
    pub provider_call_id: String,
    /// Server-derived Agent identity.
    pub agent_id: BotId,
    /// Stable `askApproval` or `askChoice` renderer identity.
    pub component_name: String,
    /// Validated renderer arguments; never policy/effect metadata.
    pub arguments: Value,
    /// Database-clock request time.
    pub requested_at: OffsetDateTime,
    /// Database-clock upper bound for accepting an answer.
    pub expires_at: OffsetDateTime,
}

/// Pending compiled decisions for one authenticated actor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingComponentHumanDecisions {
    /// Oldest first so transcript/order stays deterministic.
    pub decisions: Vec<PendingComponentHumanDecision>,
}

/// Internal Agent-host request to create and await one durable decision answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentHumanDecisionRequest {
    /// Server-minted UUIDv7 identity; never accepted from the answer endpoint.
    pub decision_id: String,
    /// Durable provider call pairing id.
    pub provider_call_id: String,
    /// Current run from the non-serializable execution lease.
    pub run_id: RunId,
    /// Current thread from the non-serializable execution lease.
    pub thread_id: ThreadId,
    /// Current Agent from the non-serializable execution lease.
    pub agent_id: BotId,
    /// Stable `askApproval` or `askChoice` identity.
    pub component_name: String,
    /// Model-produced arguments validated before persistence.
    pub arguments: Value,
}

/// Exact Approval tool result; optional note is omitted rather than serialized as null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentApprovalAnswer {
    /// Closed human answer.
    pub decision: ComponentApprovalDecision,
    /// Optional trimmed reason typed by the person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Closed Approval answer vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentApprovalDecision {
    /// Person approved the request.
    Approved,
    /// Person declined the request.
    Declined,
}

/// Exact Choice tool result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentChoiceAnswer {
    /// Stable option id from the original arguments.
    pub choice: String,
    /// Exact label paired with that option id.
    pub label: String,
}

/// Answer body accepted by the authenticated resolve endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ComponentHumanDecisionAnswer {
    /// `askApproval` answer.
    Approval(ComponentApprovalAnswer),
    /// `askChoice` answer.
    Choice(ComponentChoiceAnswer),
}

/// Stable result after one durable decision is answered or exactly replayed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentHumanDecisionResolved {
    /// Durable decision identity.
    pub decision_id: String,
    /// Exact normalized answer that becomes the provider tool result.
    pub answer: ComponentHumanDecisionAnswer,
    /// True only when this request observed an already-identical answer.
    pub replayed: bool,
}

/// Call-time authorization input for one compiled component invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentDecisionRequest {
    /// Untrusted Agent identity; authority is still derived from the verified session.
    pub agent_id: BotId,
    /// Data functions this exact invocation will read; empty for argument-only renderers.
    #[serde(default)]
    pub functions: Vec<String>,
}

/// Stable, localizable reason a component invocation was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComponentDecisionRefusal {
    /// No durable compiled-component governance row exists for the requested name.
    UnknownComponent,
    /// The component is unpublished or lacks a published model-facing description.
    Unpublished,
    /// This otherwise-open component is explicitly withheld from the Agent.
    WithheldFromAgent,
    /// The component lacks a grant for one data function declared by this invocation.
    FunctionNotGranted {
        /// Stable data-function identity; never arguments or returned data.
        function: String,
    },
    /// The requested function is not shipped by this exact Server build.
    FunctionUnavailable {
        /// Stable requested function identity.
        function: String,
    },
    /// The verified actor lacks the function's underlying data ACL.
    FunctionActorNotAuthorized {
        /// Stable requested function identity.
        function: String,
    },
    /// The current action policy refused this data read.
    FunctionPolicyRefused {
        /// Stable requested function identity.
        function: String,
    },
}

impl ComponentDecisionRefusal {
    /// Stable audit/UI classification without user-facing prose.
    #[must_use]
    pub const fn code_str(&self) -> &'static str {
        match self {
            Self::UnknownComponent => "component_unknown",
            Self::Unpublished => "component_unpublished",
            Self::WithheldFromAgent => "component_withheld",
            Self::FunctionNotGranted { .. } => "component_function_not_granted",
            Self::FunctionUnavailable { .. } => "component_function_unavailable",
            Self::FunctionActorNotAuthorized { .. } => "component_function_actor_not_authorized",
            Self::FunctionPolicyRefused { .. } => "component_function_policy_refused",
        }
    }

    /// Function identity carried by any function-level refusal.
    #[must_use]
    pub fn function(&self) -> Option<&str> {
        match self {
            Self::FunctionNotGranted { function }
            | Self::FunctionUnavailable { function }
            | Self::FunctionActorNotAuthorized { function }
            | Self::FunctionPolicyRefused { function } => Some(function),
            Self::UnknownComponent | Self::Unpublished | Self::WithheldFromAgent => None,
        }
    }
}

/// Result of the mandatory authorization check immediately before one component call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDecision {
    /// Whether the invocation may continue.
    pub allowed: bool,
    /// Present exactly when `allowed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ComponentDecisionRefusal>,
}

impl ComponentDecision {
    /// Construct the only valid allowed shape.
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            refusal: None,
        }
    }

    /// Construct the only valid refused shape.
    #[must_use]
    pub const fn refused(refusal: ComponentDecisionRefusal) -> Self {
        Self {
            allowed: false,
            refusal: Some(refusal),
        }
    }

    /// Whether the two wire fields form one valid closed result.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        self.allowed == self.refusal.is_none()
    }
}

/// One build-owned data function shown on the component administration surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDataFunctionSummary {
    /// Stable function identity.
    pub name: String,
    /// Administrator-facing purpose; never read by the model.
    pub description: String,
    /// Bounded description of the underlying data source.
    pub reads: String,
}

/// Exact data-function registry for this Server build.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDataFunctions {
    /// Build-owned summaries in stable name order.
    pub functions: Vec<ComponentDataFunctionSummary>,
}

/// The build-owned data functions shipped by this exact binary.
#[must_use]
pub fn component_data_function_manifest() -> Vec<ComponentDataFunctionSummary> {
    vec![
        ComponentDataFunctionSummary {
            name: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
            description: BOT_ACTIVITY_FUNCTION_DESCRIPTION.to_owned(),
            reads: AUDIT_TRAIL_READS_DESCRIPTION.to_owned(),
        },
        ComponentDataFunctionSummary {
            name: RECENT_REFUSALS_FUNCTION_NAME.to_owned(),
            description: RECENT_REFUSALS_FUNCTION_DESCRIPTION.to_owned(),
            reads: AUDIT_TRAIL_READS_DESCRIPTION.to_owned(),
        },
    ]
}

/// Untrusted call body for one component-owned data read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentFunctionCallRequest {
    /// Agent on whose behalf the component is rendering.
    pub agent_id: BotId,
    /// Stable build-owned function identity.
    pub function: String,
    /// Function arguments; application normalizes and bounds them by the selected registry entry.
    #[serde(default)]
    pub args: Value,
}

/// One Bot's counted actions over a bounded window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotActivityRow {
    /// Stable Bot identity from the audit payload allowlist.
    pub bot: String,
    /// Non-negative number of actions.
    pub actions: u64,
}

/// Data returned by `botActivity`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotActivityReport {
    /// Effective bounded lookback.
    pub days: u16,
    /// At most twelve Bots, ordered by actions descending then identity.
    pub rows: Vec<BotActivityRow>,
}

/// One bounded refusal projection from the audit trail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentRefusalRow {
    /// Database-clock event time.
    pub at: OffsetDateTime,
    /// Authoritative Bot identity when the event has one.
    pub bot: Option<String>,
    /// Stable audit event type.
    pub what: String,
    /// Stable error/rule classification; never raw policy or user/model prose.
    pub reason: Option<String>,
}

/// Data returned by `recentRefusals`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentRefusalsReport {
    /// At most fifty rows in reverse chronological order.
    pub rows: Vec<RecentRefusalRow>,
}

/// Typed data returned by one build-owned function while preserving upstream's untagged `data` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ComponentFunctionData {
    /// `botActivity` result.
    BotActivity(BotActivityReport),
    /// `recentRefusals` result.
    RecentRefusals(RecentRefusalsReport),
}

/// Stable non-authorization failure after the read was permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentFunctionError {
    /// The bounded local read failed; no vendor/database prose crosses the wire.
    ReadFailed,
}

/// Result of a component-owned data read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFunctionCall {
    /// False only for an authorization refusal.
    pub allowed: bool,
    /// Present only for a successful read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ComponentFunctionData>,
    /// Present only when authorization refused before the read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ComponentDecisionRefusal>,
    /// Present only when an authorized read failed and was audited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ComponentFunctionError>,
}

impl ComponentFunctionCall {
    /// Successful authorized read.
    #[must_use]
    pub const fn succeeded(data: ComponentFunctionData) -> Self {
        Self {
            allowed: true,
            data: Some(data),
            refusal: None,
            error: None,
        }
    }

    /// Authorization refusal before reading data.
    #[must_use]
    pub const fn refused(refusal: ComponentDecisionRefusal) -> Self {
        Self {
            allowed: false,
            data: None,
            refusal: Some(refusal),
            error: None,
        }
    }

    /// Authorized read failed after permission checks.
    #[must_use]
    pub const fn failed(error: ComponentFunctionError) -> Self {
        Self {
            allowed: true,
            data: None,
            refusal: None,
            error: Some(error),
        }
    }

    /// Whether exactly one valid result shape is represented.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        matches!(
            (
                self.allowed,
                self.data.is_some(),
                self.refusal.is_some(),
                self.error.is_some()
            ),
            (true, true, false, false) | (true, false, false, true) | (false, false, true, false)
        )
    }
}

/// The exact compiled renderer manifest for this build.
#[must_use]
pub fn compiled_component_manifest() -> Vec<CompiledComponentManifestEntry> {
    vec![
        manifest_entry(
            ASK_APPROVAL_COMPONENT_NAME,
            ASK_APPROVAL_COMPONENT_TITLE,
            CompiledComponentKind::Decision,
            ASK_APPROVAL_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            ASK_CHOICE_COMPONENT_NAME,
            ASK_CHOICE_COMPONENT_TITLE,
            CompiledComponentKind::Decision,
            ASK_CHOICE_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
            SHOW_ACTIVITY_REPORT_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_ACTIVITY_REPORT_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_AREA_CHART_COMPONENT_NAME,
            SHOW_AREA_CHART_COMPONENT_TITLE,
            CompiledComponentKind::Chart,
            SHOW_AREA_CHART_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_BAR_CHART_COMPONENT_NAME,
            SHOW_BAR_CHART_COMPONENT_TITLE,
            CompiledComponentKind::Chart,
            SHOW_BAR_CHART_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_CHECKLIST_COMPONENT_NAME,
            SHOW_CHECKLIST_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_CHECKLIST_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_LINE_CHART_COMPONENT_NAME,
            SHOW_LINE_CHART_COMPONENT_TITLE,
            CompiledComponentKind::Chart,
            SHOW_LINE_CHART_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_METRICS_COMPONENT_NAME,
            SHOW_METRICS_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_METRICS_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_NOTICE_COMPONENT_NAME,
            SHOW_NOTICE_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_NOTICE_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_PIE_CHART_COMPONENT_NAME,
            SHOW_PIE_CHART_COMPONENT_TITLE,
            CompiledComponentKind::Chart,
            SHOW_PIE_CHART_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_PROGRESS_COMPONENT_NAME,
            SHOW_PROGRESS_COMPONENT_TITLE,
            CompiledComponentKind::Chart,
            SHOW_PROGRESS_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_QUOTE_COMPONENT_NAME,
            SHOW_QUOTE_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_QUOTE_COMPONENT_DESCRIPTION,
        ),
        manifest_entry(
            SHOW_RECORD_COMPONENT_NAME,
            SHOW_RECORD_COMPONENT_TITLE,
            CompiledComponentKind::Card,
            SHOW_RECORD_COMPONENT_DESCRIPTION,
        ),
    ]
}

fn manifest_entry(
    name: &'static str,
    title: &'static str,
    kind: CompiledComponentKind,
    description: &'static str,
) -> CompiledComponentManifestEntry {
    CompiledComponentManifestEntry {
        name: name.to_owned(),
        title: title.to_owned(),
        kind,
        description: description.to_owned(),
    }
}

/// Stable validation failure for model-produced compiled-component arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComponentArgumentsError {
    /// This build has no ordinary compiled renderer by that name.
    #[error("component_arguments_unknown_component")]
    UnknownComponent,
    /// Arguments do not satisfy the renderer's closed schema.
    #[error("component_arguments_invalid field={field}")]
    Invalid {
        /// Static field only; model content never crosses the error boundary.
        field: &'static str,
    },
}

/// Exact parameter schema for one ordinary compiled renderer in this build.
#[must_use]
pub fn compiled_component_parameter_schema(name: &str) -> Option<Value> {
    match name {
        ASK_APPROVAL_COMPONENT_NAME => Some(ask_approval_parameter_schema()),
        ASK_CHOICE_COMPONENT_NAME => Some(ask_choice_parameter_schema()),
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => Some(show_activity_report_parameter_schema()),
        SHOW_AREA_CHART_COMPONENT_NAME => Some(show_area_chart_parameter_schema()),
        SHOW_BAR_CHART_COMPONENT_NAME => Some(show_bar_chart_parameter_schema()),
        SHOW_CHECKLIST_COMPONENT_NAME => Some(show_checklist_parameter_schema()),
        SHOW_LINE_CHART_COMPONENT_NAME => Some(show_line_chart_parameter_schema()),
        SHOW_METRICS_COMPONENT_NAME => Some(show_metrics_parameter_schema()),
        SHOW_NOTICE_COMPONENT_NAME => Some(show_notice_parameter_schema()),
        SHOW_PIE_CHART_COMPONENT_NAME => Some(show_pie_chart_parameter_schema()),
        SHOW_PROGRESS_COMPONENT_NAME => Some(show_progress_parameter_schema()),
        SHOW_QUOTE_COMPONENT_NAME => Some(show_quote_parameter_schema()),
        SHOW_RECORD_COMPONENT_NAME => Some(show_record_parameter_schema()),
        _ => None,
    }
}

/// Exact upstream confirmation returned to the model after one ordinary component is authorized.
#[must_use]
pub fn compiled_component_confirmation(name: &str) -> Option<&'static str> {
    match name {
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => Some(
            "The report is on screen for the person, filled with figures read from this deployment. You were not given the figures.",
        ),
        SHOW_AREA_CHART_COMPONENT_NAME => Some("The area chart is now on screen for the person."),
        SHOW_BAR_CHART_COMPONENT_NAME => Some("The bar chart is now on screen for the person."),
        SHOW_CHECKLIST_COMPONENT_NAME => Some("The checklist is now on screen for the person."),
        SHOW_LINE_CHART_COMPONENT_NAME => Some("The line chart is now on screen for the person."),
        SHOW_METRICS_COMPONENT_NAME => Some("The figures are now on screen for the person."),
        SHOW_NOTICE_COMPONENT_NAME => Some("The notice is now on screen for the person."),
        SHOW_PIE_CHART_COMPONENT_NAME => Some("The donut chart is now on screen for the person."),
        SHOW_PROGRESS_COMPONENT_NAME => Some("The progress chart is now on screen for the person."),
        SHOW_QUOTE_COMPONENT_NAME => Some("The quotation is now on screen for the person."),
        SHOW_RECORD_COMPONENT_NAME => Some("The record is now on screen for the person."),
        _ => None,
    }
}

/// Whether this exact build-owned component invocation may execute concurrently with another
/// first-party tool call.
///
/// This is deliberately an explicit allowlist instead of deriving the answer from component kind
/// or model-supplied metadata. Adding a renderer therefore cannot silently opt it into parallel
/// execution; the new name must be reviewed here as well.
#[must_use]
pub fn compiled_component_parallel_safe(name: &str) -> bool {
    matches!(
        name,
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME
            | SHOW_AREA_CHART_COMPONENT_NAME
            | SHOW_BAR_CHART_COMPONENT_NAME
            | SHOW_CHECKLIST_COMPONENT_NAME
            | SHOW_LINE_CHART_COMPONENT_NAME
            | SHOW_METRICS_COMPONENT_NAME
            | SHOW_NOTICE_COMPONENT_NAME
            | SHOW_PIE_CHART_COMPONENT_NAME
            | SHOW_PROGRESS_COMPONENT_NAME
            | SHOW_QUOTE_COMPONENT_NAME
            | SHOW_RECORD_COMPONENT_NAME
    )
}

/// Human-facing title for one ordinary renderer; used only in a normalized refusal sentence.
#[must_use]
pub fn compiled_component_title(name: &str) -> Option<&'static str> {
    match name {
        ASK_APPROVAL_COMPONENT_NAME => Some(ASK_APPROVAL_COMPONENT_TITLE),
        ASK_CHOICE_COMPONENT_NAME => Some(ASK_CHOICE_COMPONENT_TITLE),
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => Some(SHOW_ACTIVITY_REPORT_COMPONENT_TITLE),
        SHOW_AREA_CHART_COMPONENT_NAME => Some(SHOW_AREA_CHART_COMPONENT_TITLE),
        SHOW_BAR_CHART_COMPONENT_NAME => Some(SHOW_BAR_CHART_COMPONENT_TITLE),
        SHOW_CHECKLIST_COMPONENT_NAME => Some(SHOW_CHECKLIST_COMPONENT_TITLE),
        SHOW_LINE_CHART_COMPONENT_NAME => Some(SHOW_LINE_CHART_COMPONENT_TITLE),
        SHOW_METRICS_COMPONENT_NAME => Some(SHOW_METRICS_COMPONENT_TITLE),
        SHOW_NOTICE_COMPONENT_NAME => Some(SHOW_NOTICE_COMPONENT_TITLE),
        SHOW_PIE_CHART_COMPONENT_NAME => Some(SHOW_PIE_CHART_COMPONENT_TITLE),
        SHOW_PROGRESS_COMPONENT_NAME => Some(SHOW_PROGRESS_COMPONENT_TITLE),
        SHOW_QUOTE_COMPONENT_NAME => Some(SHOW_QUOTE_COMPONENT_TITLE),
        SHOW_RECORD_COMPONENT_NAME => Some(SHOW_RECORD_COMPONENT_TITLE),
        _ => None,
    }
}

/// Whether one exact build renderer suspends for a person's tool result.
#[must_use]
pub fn is_component_human_decision_name(name: &str) -> bool {
    matches!(
        name,
        ASK_APPROVAL_COMPONENT_NAME | ASK_CHOICE_COMPONENT_NAME
    )
}

/// Validate one ordinary renderer call and derive its build-owned data functions from arguments.
pub fn validate_compiled_component_arguments(
    name: &str,
    arguments: &Value,
) -> Result<Vec<String>, ComponentArgumentsError> {
    let object = arguments
        .as_object()
        .ok_or(invalid_component_arguments("arguments"))?;
    match name {
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => {
            allowed_keys(object, &["report", "title", "days"])?;
            optional_string(object, "title")?;
            optional_number(object, "days")?;
            match required_string(object, "report")? {
                "activity" => Ok(vec![BOT_ACTIVITY_FUNCTION_NAME.to_owned()]),
                "refusals" => Ok(vec![RECENT_REFUSALS_FUNCTION_NAME.to_owned()]),
                _ => Err(invalid_component_arguments("report")),
            }
        }
        SHOW_QUOTE_COMPONENT_NAME => {
            allowed_keys(object, &["quote", "attribution", "context"])?;
            required_string(object, "quote")?;
            required_string(object, "attribution")?;
            optional_string(object, "context")?;
            Ok(Vec::new())
        }
        SHOW_RECORD_COMPONENT_NAME => {
            allowed_keys(
                object,
                &["title", "subtitle", "status", "statusTone", "fields"],
            )?;
            required_string(object, "title")?;
            optional_string(object, "subtitle")?;
            optional_string(object, "status")?;
            optional_tone(object, "statusTone")?;
            object_array(object, "fields", |field| {
                allowed_keys(field, &["label", "value"])?;
                required_string(field, "label")?;
                required_string(field, "value")?;
                Ok(())
            })?;
            Ok(Vec::new())
        }
        SHOW_METRICS_COMPONENT_NAME => {
            allowed_keys(object, &["title", "caption", "metrics"])?;
            required_string(object, "title")?;
            optional_string(object, "caption")?;
            let metrics = required_array(object, "metrics")?;
            if metrics.len() > 6 {
                return Err(invalid_component_arguments("metrics"));
            }
            for metric in metrics {
                let metric = metric
                    .as_object()
                    .ok_or(invalid_component_arguments("metrics"))?;
                allowed_keys(metric, &["label", "value", "change", "changeTone"])?;
                required_string(metric, "label")?;
                required_string(metric, "value")?;
                optional_string(metric, "change")?;
                optional_tone(metric, "changeTone")?;
            }
            Ok(Vec::new())
        }
        SHOW_CHECKLIST_COMPONENT_NAME => {
            allowed_keys(object, &["title", "caption", "items"])?;
            required_string(object, "title")?;
            optional_string(object, "caption")?;
            object_array(object, "items", |item| {
                allowed_keys(item, &["text", "done", "note"])?;
                required_string(item, "text")?;
                required_bool(item, "done")?;
                optional_string(item, "note")?;
                Ok(())
            })?;
            Ok(Vec::new())
        }
        SHOW_NOTICE_COMPONENT_NAME => {
            allowed_keys(object, &["title", "body", "tone", "points"])?;
            required_string(object, "title")?;
            required_string(object, "body")?;
            optional_tone(object, "tone")?;
            optional_string_array(object, "points")?;
            Ok(Vec::new())
        }
        SHOW_BAR_CHART_COMPONENT_NAME | SHOW_PIE_CHART_COMPONENT_NAME => {
            point_chart_arguments(object, false)?;
            Ok(Vec::new())
        }
        SHOW_PROGRESS_COMPONENT_NAME => {
            point_chart_arguments(object, true)?;
            Ok(Vec::new())
        }
        SHOW_LINE_CHART_COMPONENT_NAME | SHOW_AREA_CHART_COMPONENT_NAME => {
            allowed_keys(object, &["title", "caption", "labels", "series"])?;
            required_string(object, "title")?;
            optional_string(object, "caption")?;
            required_string_array(object, "labels")?;
            object_array(object, "series", |series| {
                allowed_keys(series, &["name", "values"])?;
                required_string(series, "name")?;
                required_number_array(series, "values")?;
                Ok(())
            })?;
            Ok(Vec::new())
        }
        _ => Err(ComponentArgumentsError::UnknownComponent),
    }
}

/// Validate one model-produced decision call against the same closed shape as its renderer.
pub fn validate_component_human_decision_arguments(
    name: &str,
    arguments: &Value,
) -> Result<(), ComponentArgumentsError> {
    let object = arguments
        .as_object()
        .ok_or(invalid_component_arguments("arguments"))?;
    match name {
        ASK_APPROVAL_COMPONENT_NAME => {
            allowed_keys(
                object,
                &["title", "summary", "details", "approveLabel", "rejectLabel"],
            )?;
            required_string(object, "title")?;
            required_string(object, "summary")?;
            optional_string(object, "approveLabel")?;
            optional_string(object, "rejectLabel")?;
            if object.contains_key("details") {
                object_array(object, "details", |detail| {
                    allowed_keys(detail, &["label", "value"])?;
                    required_string(detail, "label")?;
                    required_string(detail, "value")?;
                    Ok(())
                })?;
            }
            Ok(())
        }
        ASK_CHOICE_COMPONENT_NAME => {
            allowed_keys(object, &["title", "summary", "options"])?;
            required_string(object, "title")?;
            optional_string(object, "summary")?;
            object_array(object, "options", |option| {
                allowed_keys(option, &["id", "label", "description"])?;
                required_string(option, "id")?;
                required_string(option, "label")?;
                optional_string(option, "description")?;
                Ok(())
            })?;
            Ok(())
        }
        _ => Err(ComponentArgumentsError::UnknownComponent),
    }
}

/// Stable failure while pairing a recorded decision result with its original closed arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComponentHumanDecisionAnswerError {
    /// This build has no decision renderer by that name.
    #[error("component_human_answer_unknown_component")]
    UnknownComponent,
    /// Answer variant or stored Choice id/label does not match the original request.
    #[error("component_human_answer_invalid")]
    Invalid,
}

/// Validate a recorded answer against the exact decision renderer and its original arguments.
pub fn validate_component_human_decision_answer(
    name: &str,
    arguments: &Value,
    answer: &ComponentHumanDecisionAnswer,
) -> Result<(), ComponentHumanDecisionAnswerError> {
    validate_component_human_decision_arguments(name, arguments)
        .map_err(|_| ComponentHumanDecisionAnswerError::Invalid)?;
    match (name, answer) {
        (ASK_APPROVAL_COMPONENT_NAME, ComponentHumanDecisionAnswer::Approval(_)) => Ok(()),
        (ASK_CHOICE_COMPONENT_NAME, ComponentHumanDecisionAnswer::Choice(choice)) => {
            let options = arguments
                .get("options")
                .and_then(Value::as_array)
                .ok_or(ComponentHumanDecisionAnswerError::Invalid)?;
            options
                .iter()
                .filter_map(Value::as_object)
                .any(|option| {
                    option.get("id").and_then(Value::as_str) == Some(choice.choice.as_str())
                        && option.get("label").and_then(Value::as_str)
                            == Some(choice.label.as_str())
                })
                .then_some(())
                .ok_or(ComponentHumanDecisionAnswerError::Invalid)
        }
        (ASK_APPROVAL_COMPONENT_NAME | ASK_CHOICE_COMPONENT_NAME, _) => {
            Err(ComponentHumanDecisionAnswerError::Invalid)
        }
        _ => Err(ComponentHumanDecisionAnswerError::UnknownComponent),
    }
}

fn point_chart_arguments(
    object: &serde_json::Map<String, Value>,
    target: bool,
) -> Result<(), ComponentArgumentsError> {
    allowed_keys(object, &["title", "caption", "points"])?;
    required_string(object, "title")?;
    optional_string(object, "caption")?;
    object_array(object, "points", |point| {
        if target {
            allowed_keys(point, &["label", "value", "target"])?;
        } else {
            allowed_keys(point, &["label", "value"])?;
        }
        required_string(point, "label")?;
        required_number(point, "value")?;
        if target {
            required_number(point, "target")?;
        }
        Ok(())
    })
}

fn allowed_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ComponentArgumentsError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(invalid_component_arguments("additional_properties"))
    } else {
        Ok(())
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ComponentArgumentsError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(invalid_component_arguments(field))
}

fn optional_string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    match object.get(field) {
        None | Some(Value::String(_)) => Ok(()),
        _ => Err(invalid_component_arguments(field)),
    }
}

fn required_bool(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    object
        .get(field)
        .filter(|value| value.is_boolean())
        .map(|_| ())
        .ok_or(invalid_component_arguments(field))
}

fn required_number(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    object
        .get(field)
        .filter(|value| value.is_number())
        .map(|_| ())
        .ok_or(invalid_component_arguments(field))
}

fn optional_number(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    match object.get(field) {
        None | Some(Value::Number(_)) => Ok(()),
        _ => Err(invalid_component_arguments(field)),
    }
}

fn optional_tone(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    match object.get(field) {
        None => Ok(()),
        Some(Value::String(value))
            if matches!(
                value.as_str(),
                "neutral" | "positive" | "caution" | "negative"
            ) =>
        {
            Ok(())
        }
        _ => Err(invalid_component_arguments(field)),
    }
}

fn required_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a Vec<Value>, ComponentArgumentsError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(invalid_component_arguments(field))
}

fn object_array(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    validate: impl Fn(&serde_json::Map<String, Value>) -> Result<(), ComponentArgumentsError>,
) -> Result<(), ComponentArgumentsError> {
    for value in required_array(object, field)? {
        validate(
            value
                .as_object()
                .ok_or(invalid_component_arguments(field))?,
        )?;
    }
    Ok(())
}

fn required_string_array(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    if required_array(object, field)?.iter().all(Value::is_string) {
        Ok(())
    } else {
        Err(invalid_component_arguments(field))
    }
}

fn optional_string_array(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    match object.get(field) {
        None => Ok(()),
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => Ok(()),
        _ => Err(invalid_component_arguments(field)),
    }
}

fn required_number_array(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ComponentArgumentsError> {
    if required_array(object, field)?.iter().all(Value::is_number) {
        Ok(())
    } else {
        Err(invalid_component_arguments(field))
    }
}

const fn invalid_component_arguments(field: &'static str) -> ComponentArgumentsError {
    ComponentArgumentsError::Invalid { field }
}

/// Exact JSON Schema for `showActivityReport`.
#[must_use]
pub fn show_activity_report_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "report": {
                "type": "string",
                "enum": ["activity", "refusals"],
                "description": "Which report to show: 'activity' for how much each Bot has done, 'refusals' for what this deployment recently refused"
            },
            "title": {
                "type": "string",
                "description": "A heading for the report, in a few words"
            },
            "days": {
                "type": "number",
                "description": "For the activity report: how many days back to count. Defaults to 7"
            }
        },
        "required": ["report"]
    })
}

/// Exact JSON Schema for `askApproval`.
#[must_use]
pub fn ask_approval_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type":"string", "description":"What is being approved, in a few words"},
            "summary": {"type":"string", "description":"What the person is agreeing to, in one or two sentences"},
            "details": {
                "type":"array",
                "description":"The facts they need in order to decide, e.g. amount, vendor, date",
                "items": {
                    "type":"object",
                    "additionalProperties":false,
                    "properties": {
                        "label":{"type":"string"},
                        "value":{"type":"string"}
                    },
                    "required":["label","value"]
                }
            },
            "approveLabel":{"type":"string", "description":"Defaults to Approve"},
            "rejectLabel":{"type":"string", "description":"Defaults to Decline"}
        },
        "required":["title","summary"]
    })
}

/// Exact JSON Schema for `askChoice`.
#[must_use]
pub fn ask_choice_parameter_schema() -> Value {
    json!({
        "type":"object",
        "additionalProperties":false,
        "properties": {
            "title":{"type":"string", "description":"The question being asked"},
            "summary":{"type":"string", "description":"Any context the person needs to choose"},
            "options": {
                "type":"array",
                "description":"The options, in the order they should be offered",
                "items": {
                    "type":"object",
                    "additionalProperties":false,
                    "properties": {
                        "id":{"type":"string", "description":"What comes back to you when this one is picked"},
                        "label":{"type":"string"},
                        "description":{"type":"string"}
                    },
                    "required":["id","label"]
                }
            }
        },
        "required":["title","options"]
    })
}

/// Exact schema for one compiled human decision.
#[must_use]
pub fn component_human_decision_parameter_schema(name: &str) -> Option<Value> {
    match name {
        ASK_APPROVAL_COMPONENT_NAME => Some(ask_approval_parameter_schema()),
        ASK_CHOICE_COMPONENT_NAME => Some(ask_choice_parameter_schema()),
        _ => None,
    }
}

/// Exact JSON Schema for `showQuote`; renderer/tool registration share this single source.
#[must_use]
pub fn show_quote_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "quote": {
                "type": "string",
                "description": "The quotation itself, without surrounding quote marks"
            },
            "attribution": {
                "type": "string",
                "description": "Who said or wrote it, e.g. 'Grace Hopper' or 'the 2026 annual report'"
            },
            "context": {
                "type": "string",
                "description": "One short line of context: where it is from, or why it matters here"
            }
        },
        "required": ["quote", "attribution"]
    })
}

/// Exact JSON Schema for `showRecord`.
#[must_use]
pub fn show_record_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "What this record is, e.g. a person or an order"},
            "subtitle": {"type": "string", "description": "One line of context under the title"},
            "status": {"type": "string", "description": "A short status word, e.g. Approved"},
            "statusTone": tone_schema(),
            "fields": {
                "type": "array",
                "description": "The fields, in the order they should be read",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "label": {"type": "string"},
                        "value": {"type": "string", "description": "Already formatted for a person to read"}
                    },
                    "required": ["label", "value"]
                }
            }
        },
        "required": ["title", "fields"]
    })
}

/// Exact JSON Schema for `showMetrics`.
#[must_use]
pub fn show_metrics_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "What these figures are about"},
            "caption": {"type": "string"},
            "metrics": {
                "type": "array",
                "maxItems": 6,
                "description": "Up to six figures. More than that wanted a table",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "label": {"type": "string"},
                        "value": {"type": "string", "description": "Already formatted, including any unit or currency"},
                        "change": {"type": "string", "description": "The movement, e.g. '+12% on last month'"},
                        "changeTone": tone_schema()
                    },
                    "required": ["label", "value"]
                }
            }
        },
        "required": ["title", "metrics"]
    })
}

/// Exact JSON Schema for `showChecklist`.
#[must_use]
pub fn show_checklist_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "What this list is"},
            "caption": {"type": "string"},
            "items": {
                "type": "array",
                "description": "The items, in the order they should be done",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "text": {"type": "string"},
                        "done": {"type": "boolean", "description": "Whether this one is already finished"},
                        "note": {"type": "string", "description": "A short aside, e.g. who it is waiting on"}
                    },
                    "required": ["text", "done"]
                }
            }
        },
        "required": ["title", "items"]
    })
}

/// Exact JSON Schema for `showNotice`.
#[must_use]
pub fn show_notice_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "The headline, in a few words"},
            "body": {"type": "string", "description": "The explanation, in one or two sentences"},
            "tone": tone_schema(),
            "points": {
                "type": "array",
                "description": "Supporting points, if there are any",
                "items": {"type": "string"}
            }
        },
        "required": ["title", "body"]
    })
}

fn tone_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["neutral", "positive", "caution", "negative"],
        "description": "How this reads at a glance. Use negative and caution sparingly, for a refusal, a breach or a failure, not for anything merely notable"
    })
}

/// Exact JSON Schema for `showBarChart`.
#[must_use]
pub fn show_bar_chart_parameter_schema() -> Value {
    point_chart_schema("One bar per point, in the order they should appear", false)
}

/// Exact JSON Schema for `showPieChart`.
#[must_use]
pub fn show_pie_chart_parameter_schema() -> Value {
    point_chart_schema(
        "One slice per point. Values are summed to make the whole",
        false,
    )
}

/// Exact shared JSON Schema for `showLineChart` and `showAreaChart`.
#[must_use]
pub fn show_line_chart_parameter_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "A short title for the chart"},
            "caption": {"type": "string", "description": "One line under the title saying what the reader should take from it"},
            "labels": {"type": "array", "description": "The x axis, e.g. months", "items": {"type": "string"}},
            "series": {
                "type": "array",
                "description": "One line per series",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string", "description": "What this line is called"},
                        "values": {"type": "array", "description": "One value per label, in the same order", "items": {"type": "number"}}
                    },
                    "required": ["name", "values"]
                }
            }
        },
        "required": ["title", "labels", "series"]
    })
}

/// Area chart intentionally reuses the exact Line chart schema.
#[must_use]
pub fn show_area_chart_parameter_schema() -> Value {
    show_line_chart_parameter_schema()
}

/// Exact JSON Schema for `showProgress`.
#[must_use]
pub fn show_progress_parameter_schema() -> Value {
    point_chart_schema("One row per thing being tracked", true)
}

fn point_chart_schema(description: &'static str, target: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        (
            "label".to_owned(),
            json!({"type": "string", "description": "What this point is called, e.g. a month or a team"}),
        ),
        (
            "value".to_owned(),
            json!({"type": "number", "description": "Its value"}),
        ),
    ]);
    let mut required = vec!["label", "value"];
    if target {
        properties.insert(
            "target".to_owned(),
            json!({"type": "number", "description": "What the value is measured against"}),
        );
        required.push("target");
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": {"type": "string", "description": "A short title for the chart"},
            "caption": {"type": "string", "description": "One line under the title saying what the reader should take from it"},
            "points": {
                "type": "array",
                "description": description,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": properties,
                    "required": required
                }
            }
        },
        "required": ["title", "points"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_and_compiled_schemas_are_exact_closed_and_stable() {
        let manifest = compiled_component_manifest();
        assert_eq!(manifest.len(), 13);
        assert_eq!(
            manifest
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [
                ASK_APPROVAL_COMPONENT_NAME,
                ASK_CHOICE_COMPONENT_NAME,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                SHOW_AREA_CHART_COMPONENT_NAME,
                SHOW_BAR_CHART_COMPONENT_NAME,
                SHOW_CHECKLIST_COMPONENT_NAME,
                SHOW_LINE_CHART_COMPONENT_NAME,
                SHOW_METRICS_COMPONENT_NAME,
                SHOW_NOTICE_COMPONENT_NAME,
                SHOW_PIE_CHART_COMPONENT_NAME,
                SHOW_PROGRESS_COMPONENT_NAME,
                SHOW_QUOTE_COMPONENT_NAME,
                SHOW_RECORD_COMPONENT_NAME,
            ]
        );
        assert_eq!(
            manifest
                .iter()
                .filter(|entry| entry.kind == CompiledComponentKind::Chart)
                .count(),
            5
        );
        assert_eq!(
            manifest
                .iter()
                .filter(|entry| entry.kind == CompiledComponentKind::Decision)
                .count(),
            2
        );
        assert_eq!(
            show_activity_report_parameter_schema()["properties"]["report"]["enum"],
            json!(["activity", "refusals"])
        );
        assert_eq!(
            show_activity_report_parameter_schema()["required"],
            json!(["report"])
        );
        assert_eq!(
            show_quote_parameter_schema()["required"],
            json!(["quote", "attribution"])
        );
        assert_eq!(show_quote_parameter_schema()["additionalProperties"], false);
        assert_eq!(
            show_metrics_parameter_schema()["properties"]["metrics"]["maxItems"],
            6
        );
        assert_eq!(
            show_record_parameter_schema()["properties"]["statusTone"]["enum"],
            json!(["neutral", "positive", "caution", "negative"])
        );
        assert_eq!(
            show_checklist_parameter_schema()["required"],
            json!(["title", "items"])
        );
        assert_eq!(
            show_notice_parameter_schema()["required"],
            json!(["title", "body"])
        );
        assert_eq!(
            show_area_chart_parameter_schema(),
            show_line_chart_parameter_schema()
        );
        assert_eq!(
            show_bar_chart_parameter_schema()["properties"]["points"]["items"]["required"],
            json!(["label", "value"])
        );
        assert_eq!(
            show_progress_parameter_schema()["properties"]["points"]["items"]["required"],
            json!(["label", "value", "target"])
        );
        assert!(
            serde_json::from_str::<ComponentCatalogueRequest>(
                r#"{"components":[],"renderer":"untrusted"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn component_record_wire_contains_governance_facts_but_no_source_or_secret() {
        let record = ComponentRecord {
            name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
            title: SHOW_QUOTE_COMPONENT_TITLE.to_owned(),
            kind: CompiledComponentKind::Card,
            draft_description: "draft".to_owned(),
            published_description: Some("published".to_owned()),
            published: true,
            published_at: Some(OffsetDateTime::UNIX_EPOCH),
            updated_by: Some("the build".to_owned()),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            has_unpublished_changes: true,
            withheld_from: vec!["agent-one".to_owned()],
            functions: vec!["readOrder".to_owned()],
        };
        let encoded = serde_json::to_value(&record).unwrap();
        assert_eq!(encoded["name"], SHOW_QUOTE_COMPONENT_NAME);
        assert_eq!(encoded["hasUnpublishedChanges"], true);
        assert!(encoded.get("source").is_none());
        assert!(encoded.get("arguments").is_none());
        assert!(encoded.get("secret").is_none());
    }

    #[test]
    fn runtime_grants_and_decisions_have_closed_payload_free_wire_shapes() {
        let request = ComponentDecisionRequest {
            agent_id: BotId::new("agent-one"),
            functions: vec!["recentRefusals".to_owned()],
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"agentId":"agent-one","functions":["recentRefusals"]}"#
        );
        assert!(
            serde_json::from_str::<ComponentDecisionRequest>(
                r#"{"agentId":"agent-one","functions":[],"actor":"admin"}"#
            )
            .is_err()
        );

        let allowed = ComponentDecision::allowed();
        assert!(allowed.is_consistent());
        assert_eq!(
            serde_json::to_string(&allowed).unwrap(),
            r#"{"allowed":true}"#
        );
        let refused = ComponentDecision::refused(ComponentDecisionRefusal::FunctionNotGranted {
            function: "recentRefusals".to_owned(),
        });
        assert!(refused.is_consistent());
        assert_eq!(
            serde_json::to_string(&refused).unwrap(),
            r#"{"allowed":false,"refusal":{"code":"function_not_granted","function":"recentRefusals"}}"#
        );
        assert_eq!(
            refused.refusal.as_ref().unwrap().code_str(),
            "component_function_not_granted"
        );

        let grants = GrantedCompiledComponents {
            components: vec![GrantedCompiledComponent {
                name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                description: SHOW_QUOTE_COMPONENT_DESCRIPTION.to_owned(),
            }],
        };
        let encoded = serde_json::to_value(grants).unwrap();
        assert_eq!(encoded["components"][0]["name"], SHOW_QUOTE_COMPONENT_NAME);
        assert!(encoded["components"][0].get("draft").is_none());
        assert!(encoded["components"][0].get("arguments").is_none());
    }

    #[test]
    fn component_data_function_registry_and_call_wire_are_exact_and_consistent() {
        let functions = component_data_function_manifest();
        assert_eq!(
            functions
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [BOT_ACTIVITY_FUNCTION_NAME, RECENT_REFUSALS_FUNCTION_NAME]
        );
        assert!(
            functions
                .iter()
                .all(|entry| entry.reads == AUDIT_TRAIL_READS_DESCRIPTION)
        );
        let request = ComponentFunctionCallRequest {
            agent_id: BotId::new("agent-one"),
            function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
            args: json!({"days": 7}),
        };
        assert!(
            serde_json::from_value::<ComponentFunctionCallRequest>(json!({
                "agentId": "agent-one",
                "function": BOT_ACTIVITY_FUNCTION_NAME,
                "args": {},
                "actor": "admin"
            }))
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"agentId":"agent-one","function":"botActivity","args":{"days":7}})
        );

        let succeeded = ComponentFunctionCall::succeeded(ComponentFunctionData::BotActivity(
            BotActivityReport {
                days: 7,
                rows: vec![BotActivityRow {
                    bot: "agent-one".to_owned(),
                    actions: 3,
                }],
            },
        ));
        let refused =
            ComponentFunctionCall::refused(ComponentDecisionRefusal::FunctionActorNotAuthorized {
                function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
            });
        let failed = ComponentFunctionCall::failed(ComponentFunctionError::ReadFailed);
        assert!(succeeded.is_consistent());
        assert!(refused.is_consistent());
        assert!(failed.is_consistent());
        assert_eq!(
            serde_json::to_value(&failed).unwrap(),
            json!({"allowed":true,"error":"read_failed"})
        );
        assert!(
            !ComponentFunctionCall {
                allowed: true,
                data: None,
                refusal: None,
                error: None,
            }
            .is_consistent()
        );
    }

    #[test]
    fn ordinary_component_registry_validates_all_eleven_and_derives_only_activity_reads() {
        let cases = [
            (
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                json!({"report":"activity"}),
                1,
            ),
            (
                SHOW_AREA_CHART_COMPONENT_NAME,
                json!({"title":"A","labels":[],"series":[]}),
                0,
            ),
            (
                SHOW_BAR_CHART_COMPONENT_NAME,
                json!({"title":"B","points":[]}),
                0,
            ),
            (
                SHOW_CHECKLIST_COMPONENT_NAME,
                json!({"title":"C","items":[]}),
                0,
            ),
            (
                SHOW_LINE_CHART_COMPONENT_NAME,
                json!({"title":"L","labels":[],"series":[]}),
                0,
            ),
            (
                SHOW_METRICS_COMPONENT_NAME,
                json!({"title":"M","metrics":[]}),
                0,
            ),
            (
                SHOW_NOTICE_COMPONENT_NAME,
                json!({"title":"N","body":"Body"}),
                0,
            ),
            (
                SHOW_PIE_CHART_COMPONENT_NAME,
                json!({"title":"P","points":[]}),
                0,
            ),
            (
                SHOW_PROGRESS_COMPONENT_NAME,
                json!({"title":"P","points":[]}),
                0,
            ),
            (
                SHOW_QUOTE_COMPONENT_NAME,
                json!({"quote":"Q","attribution":"A"}),
                0,
            ),
            (
                SHOW_RECORD_COMPONENT_NAME,
                json!({"title":"R","fields":[]}),
                0,
            ),
        ];
        for (name, arguments, function_count) in cases {
            assert!(
                compiled_component_parameter_schema(name).is_some(),
                "{name}"
            );
            assert!(compiled_component_confirmation(name).is_some(), "{name}");
            assert!(compiled_component_title(name).is_some(), "{name}");
            assert_eq!(
                validate_compiled_component_arguments(name, &arguments)
                    .unwrap()
                    .len(),
                function_count,
                "{name}"
            );
        }
        assert_eq!(
            validate_compiled_component_arguments(
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                &json!({"report":"refusals"}),
            )
            .unwrap(),
            [RECENT_REFUSALS_FUNCTION_NAME]
        );
        for invalid in [
            json!({"report":"unknown"}),
            json!({"report":"activity","function":"botActivity"}),
        ] {
            assert!(
                validate_compiled_component_arguments(
                    SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                    &invalid,
                )
                .is_err()
            );
        }
        assert!(
            validate_compiled_component_arguments(
                SHOW_METRICS_COMPONENT_NAME,
                &json!({"title":"M","metrics":[{},{},{},{},{},{},{}]}),
            )
            .is_err()
        );
        assert_eq!(
            validate_compiled_component_arguments("showStale", &json!({})),
            Err(ComponentArgumentsError::UnknownComponent)
        );
    }

    #[test]
    fn only_the_eleven_ordinary_build_components_are_parallel_safe() {
        let manifest = compiled_component_manifest();
        assert_eq!(manifest.len(), 13);
        let parallel = manifest
            .iter()
            .filter(|entry| compiled_component_parallel_safe(&entry.name))
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(parallel.len(), 11);
        for entry in manifest {
            assert_eq!(
                compiled_component_parallel_safe(&entry.name),
                compiled_component_confirmation(&entry.name).is_some(),
                "parallel allowlist and ordinary renderer registry drifted for {}",
                entry.name
            );
        }
        assert!(!compiled_component_parallel_safe("custom_report"));
        assert!(!compiled_component_parallel_safe("remember"));
    }

    #[test]
    fn human_decision_schemas_answers_and_manifest_are_closed() {
        assert_eq!(compiled_component_manifest().len(), 13);
        for name in [ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME] {
            let schema = component_human_decision_parameter_schema(name).unwrap();
            assert_eq!(schema["additionalProperties"], false, "{name}");
            assert_eq!(compiled_component_parameter_schema(name), Some(schema));
            assert!(is_component_human_decision_name(name));
        }
        validate_component_human_decision_arguments(
            ASK_APPROVAL_COMPONENT_NAME,
            &json!({
                "title":"Refund this order?",
                "summary":"The charge was duplicated.",
                "details":[{"label":"Amount","value":"$12"}]
            }),
        )
        .unwrap();
        validate_component_human_decision_arguments(
            ASK_CHOICE_COMPONENT_NAME,
            &json!({
                "title":"Where?",
                "options":[{"id":"staging","label":"Staging"}]
            }),
        )
        .unwrap();
        let choice_arguments = json!({
            "title":"Where?",
            "options":[{"id":"staging","label":"Staging"}]
        });
        let choice_answer = ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer {
            choice: "staging".to_owned(),
            label: "Staging".to_owned(),
        });
        assert_eq!(
            validate_component_human_decision_answer(
                ASK_CHOICE_COMPONENT_NAME,
                &choice_arguments,
                &choice_answer,
            ),
            Ok(())
        );
        assert_eq!(
            validate_component_human_decision_answer(
                ASK_CHOICE_COMPONENT_NAME,
                &choice_arguments,
                &ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer {
                    choice: "staging".to_owned(),
                    label: "forged".to_owned(),
                }),
            ),
            Err(ComponentHumanDecisionAnswerError::Invalid)
        );
        assert_eq!(
            validate_component_human_decision_answer(
                ASK_APPROVAL_COMPONENT_NAME,
                &json!({"title":"Approve?","summary":"Summary"}),
                &choice_answer,
            ),
            Err(ComponentHumanDecisionAnswerError::Invalid)
        );
        assert!(
            validate_component_human_decision_arguments(
                ASK_CHOICE_COMPONENT_NAME,
                &json!({"title":"Where?","options":[],"effect":"write"}),
            )
            .is_err()
        );
        let approval = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
            decision: ComponentApprovalDecision::Approved,
            note: Some("because it is exact".to_owned()),
        });
        assert_eq!(
            serde_json::to_value(&approval).unwrap(),
            json!({"decision":"approved","note":"because it is exact"})
        );
        let choice = ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer {
            choice: "production".to_owned(),
            label: "Production".to_owned(),
        });
        assert_eq!(
            serde_json::from_value::<ComponentHumanDecisionAnswer>(
                serde_json::to_value(&choice).unwrap()
            )
            .unwrap(),
            choice
        );
        assert!(
            serde_json::from_value::<ComponentHumanDecisionAnswer>(
                json!({"decision":"approved","effect":"write"})
            )
            .is_err()
        );
    }

    #[test]
    fn component_governance_requests_mutations_and_receipts_are_closed() {
        let request = ComponentAgentGrantRequest {
            agent_id: BotId::new("agent-one"),
        };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"agentId":"agent-one"})
        );
        assert!(
            serde_json::from_value::<ComponentAgentGrantRequest>(
                json!({"agentId":"agent-one","actor":"forged"})
            )
            .is_err()
        );
        let mutation = ComponentGovernanceMutation::SetFunctionGrant {
            component_name: "showQuote".to_owned(),
            function: "botActivity".to_owned(),
            granted: true,
        };
        assert_eq!(mutation.component_name(), "showQuote");
        assert_eq!(
            serde_json::to_value(&mutation).unwrap(),
            json!({
                "operation":"set_function_grant",
                "component_name":"showQuote",
                "function":"botActivity",
                "granted":true
            })
        );
        let receipt = ComponentGovernanceReceipt {
            component: ComponentRecord {
                name: "showQuote".to_owned(),
                title: "Quotation".to_owned(),
                kind: CompiledComponentKind::Card,
                draft_description: "quote".to_owned(),
                published_description: Some("quote".to_owned()),
                published: true,
                published_at: Some(OffsetDateTime::UNIX_EPOCH),
                updated_by: Some("admin".to_owned()),
                updated_at: OffsetDateTime::UNIX_EPOCH,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: vec!["botActivity".to_owned()],
            },
        };
        assert_eq!(
            serde_json::from_value::<ComponentGovernanceReceipt>(
                serde_json::to_value(&receipt).unwrap()
            )
            .unwrap(),
            receipt
        );
    }
}
