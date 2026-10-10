//! Owned initial OAuth data and response resources.
//! The registration journal retains the whole initial owner without dispatch.

use crate::gateway_account::GatewayDesktopMetadata;
use chrono::{DateTime, Utc};
use std::{fmt, num::NonZeroI64, sync::Arc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[allow(dead_code, reason = "Pending code-grant consumption")]
mod initial;
pub(crate) mod journal;
#[allow(dead_code, reason = "Pending reply consumption")]
mod reply;
#[cfg(test)]
mod tests;
#[allow(dead_code, reason = "Pending token consumption")]
mod tokens;

type ClockOwner = Arc<dyn InitialClock + Send + Sync + 'static>;

#[derive(Clone, Copy)]
struct ClockSample {
    wall: DateTime<Utc>,
    mono: Instant,
}

trait InitialClock: Send + Sync {
    fn sample(&self) -> ClockSample;
}

struct SystemClock;

impl InitialClock for SystemClock {
    fn sample(&self) -> ClockSample {
        ClockSample {
            wall: Utc::now(),
            mono: Instant::now(),
        }
    }
}

struct InitialParentBudget {
    original_parent: CancellationToken,
    owner_deadline: Instant,
}

struct OwnedInitialInput {
    kind: OwnedInitialKind,
    clock: ClockOwner,
}

enum OwnedInitialKind {
    Registration(OwnedRegistrationInput),
    #[allow(dead_code, reason = "Pending code-grant consumption")]
    Code(OwnedCodeInput),
}

struct OwnedRegistrationInput {
    metadata: GatewayDesktopMetadata,
    original_redirect_uri: Zeroizing<String>,
}

#[allow(dead_code, reason = "Pending code-grant consumption")]
struct OwnedCodeInput {
    metadata: GatewayDesktopMetadata,
    client_id: Zeroizing<String>,
    code: Zeroizing<String>,
    redirect_uri: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
    server_url: Zeroizing<String>,
}

struct InitialBudget {
    original_parent: CancellationToken,
    owner_deadline: Instant,
    http_entered_at: Instant,
    deadline: Instant,
}

impl InitialBudget {
    fn check(&self, clock: &ClockOwner) -> Result<ClockSample, InitialError> {
        check_budget(self, clock)
    }
}

#[allow(dead_code, reason = "Pending code-grant consumption")]
struct CodeTokenStart {
    original: ClockSample,
}

#[allow(dead_code, reason = "Pending token consumption")]
struct OwnedTokenBinding {
    client_id: Zeroizing<String>,
    server_url: Zeroizing<String>,
}

#[allow(dead_code, reason = "Pending code-grant and reply consumption")]
enum InitialReplyWitness {
    Registration {
        metadata: GatewayDesktopMetadata,
        original_redirect_uri: Zeroizing<String>,
    },
    Code {
        metadata: GatewayDesktopMetadata,
        binding: OwnedTokenBinding,
        start: CodeTokenStart,
    },
}

struct PreparedInitialOwner {
    request: Option<acosmi::HttpRequest>,
    witness: Option<InitialReplyWitness>,
    budget: Option<InitialBudget>,
    clock: ClockOwner,
    // This cancelled SDK child proves local helper exit, never parent authority.
    sdk_exit_child: CancellationToken,
}

#[allow(dead_code, reason = "Pending token consumption")]
struct ParsedTokenFields {
    access_token: Zeroizing<String>,
    token_type: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    scope: Zeroizing<String>,
    expires_in: NonZeroI64,
}

#[allow(dead_code, reason = "Pending token consumption")]
struct CheckedExpiry {
    original_start: ClockSample,
    wall_expiry: DateTime<Utc>,
    mono_expiry: Instant,
    encoded_wall_expiry: DateTime<Utc>,
}

#[allow(dead_code, reason = "Pending reply and token consumption")]
struct ReplyResources {
    metadata: GatewayDesktopMetadata,
    budget: InitialBudget,
    clock: ClockOwner,
}

#[allow(dead_code, reason = "Pending reply consumption")]
struct OwnedRegistrationReply {
    client_id: Zeroizing<String>,
    original_redirect_uri: Zeroizing<String>,
    resources: ReplyResources,
}

#[allow(dead_code, reason = "Pending token consumption")]
struct TokenSetGuard {
    sdk: acosmi::TokenSet,
    expiry: CheckedExpiry,
    resources: ReplyResources,
}

#[allow(dead_code, reason = "Pending reply and token consumption")]
enum InitialReply {
    Registration(OwnedRegistrationReply),
    Tokens(TokenSetGuard),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialError {
    #[allow(dead_code, reason = "Pending reply consumption")]
    ProtocolInvalid(ReplyInvalidReason),
    #[allow(dead_code, reason = "Pending reply consumption")]
    HttpStatus(u16),
    Cancelled,
    Deadline,
    ProducerEnded,
    RequestMismatch,
    #[allow(dead_code, reason = "Pending reply consumption")]
    BodyTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "Pending reply and token consumption")]
enum ReplyInvalidReason {
    JsonSyntax,
    UnknownKey,
    DuplicateKey,
    ForbiddenSecretKey,
    FieldShape,
    HeaderLimit,
    MediaType,
    BodyLimit,
    FieldLimit,
    ScopeShape,
    TokenType,
    ExpiryInteger,
    ClockOrExpiry,
    ReplyBinding,
}

impl fmt::Display for InitialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolInvalid(reason) => write!(f, "ProtocolInvalid({reason:?})"),
            Self::HttpStatus(status) => write!(f, "HttpStatus({status})"),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Deadline => f.write_str("Deadline"),
            Self::ProducerEnded => f.write_str("ProducerEnded"),
            Self::RequestMismatch => f.write_str("RequestMismatch"),
            Self::BodyTransport => f.write_str("BodyTransport"),
        }
    }
}

impl std::error::Error for InitialError {}

macro_rules! redacted_debug {
    ($($owner:ty => $tag:literal),+ $(,)?) => {
        $(impl fmt::Debug for $owner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($tag)
            }
        })+
    };
}

redacted_debug! {
    ClockSample => "ClockSample([redacted])",
    InitialParentBudget => "InitialParentBudget([redacted])",
    OwnedInitialInput => "OwnedInitialInput([redacted])",
    OwnedInitialKind => "OwnedInitialKind([redacted])",
    OwnedRegistrationInput => "OwnedRegistrationInput([redacted])",
    OwnedCodeInput => "OwnedCodeInput([redacted])",
    InitialBudget => "InitialBudget([redacted])",
    CodeTokenStart => "CodeTokenStart([redacted])",
    OwnedTokenBinding => "OwnedTokenBinding([redacted])",
    InitialReplyWitness => "InitialReplyWitness([redacted])",
    PreparedInitialOwner => "PreparedInitialOwner([redacted])",
    ParsedTokenFields => "ParsedTokenFields([redacted])",
    CheckedExpiry => "CheckedExpiry([redacted])",
    ReplyResources => "ReplyResources([redacted])",
    OwnedRegistrationReply => "OwnedRegistrationReply([redacted])",
    TokenSetGuard => "TokenSetGuard([redacted])",
    InitialReply => "InitialReply([redacted])",
}

fn check_parent_budget(
    parent: &InitialParentBudget,
    clock: &ClockOwner,
) -> Result<ClockSample, InitialError> {
    if parent.original_parent.is_cancelled() {
        return Err(InitialError::Cancelled);
    }
    let now = clock.sample();
    if parent.original_parent.is_cancelled() {
        return Err(InitialError::Cancelled);
    }
    if now.mono >= parent.owner_deadline {
        return Err(InitialError::Deadline);
    }
    Ok(now)
}

fn check_budget(budget: &InitialBudget, clock: &ClockOwner) -> Result<ClockSample, InitialError> {
    if budget.original_parent.is_cancelled() {
        return Err(InitialError::Cancelled);
    }
    let now = clock.sample();
    if budget.original_parent.is_cancelled() {
        return Err(InitialError::Cancelled);
    }
    if now.mono >= budget.deadline || now.mono >= budget.owner_deadline {
        return Err(InitialError::Deadline);
    }
    Ok(now)
}

fn retain_parent_budget(
    original_parent: CancellationToken,
    owner_deadline: Instant,
) -> InitialParentBudget {
    InitialParentBudget {
        original_parent,
        owner_deadline,
    }
}

fn owned_registration_input(
    metadata: GatewayDesktopMetadata,
    original_redirect_uri: Zeroizing<String>,
) -> Result<OwnedInitialInput, InitialError> {
    initial::owned_registration_input(metadata, original_redirect_uri)
}

#[allow(dead_code, reason = "Pending code-grant consumption")]
fn owned_code_input(
    metadata: GatewayDesktopMetadata,
    client_id: Zeroizing<String>,
    code: Zeroizing<String>,
    original_redirect_uri: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
) -> Result<OwnedInitialInput, InitialError> {
    initial::owned_code_input(
        metadata,
        client_id,
        code,
        original_redirect_uri,
        code_verifier,
    )
}

async fn prepare_initial(
    input: OwnedInitialInput,
    original_parent_budget: InitialParentBudget,
) -> Result<PreparedInitialOwner, InitialError> {
    initial::prepare_initial(input, original_parent_budget).await
}

#[allow(dead_code, reason = "Pending reply and token consumption")]
async fn consume_initial(
    prepared: PreparedInitialOwner,
    response: acosmi::HttpResponse,
) -> Result<InitialReply, InitialError> {
    reply::consume_initial(prepared, response).await
}
