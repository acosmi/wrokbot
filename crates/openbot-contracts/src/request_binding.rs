//! R425 真实宿主请求绑定。这里仅承载非 Serde port 与身份，不执行 I/O。

use crate::auth::{AuthContext, AuthGeneration, Role};
use crate::ids::{ActorId, DeploymentId, TenantId};
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use time::OffsetDateTime;

/// 已登记的真实宿主绑定种类；不作为公开 wire。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostRequestBindingKind {
    /// 真实 PostgreSQL session 行。
    ServerSession,
    /// 显式单用户 Server 的实际运行 owner。
    ServerSingleUserOwner,
    /// 实际 Desktop protocol 的当前窗口。
    DesktopWindow,
}
/// 当前宿主校验的封闭错误，不包含 locator 或秘密。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostRequestBindingError {
    /// 缺少真实绑定或身份来源。
    Missing,
    /// 原绑定已经失效。
    NotCurrent,
    /// 依赖、争用或有界等待不可用。
    Unavailable,
}
/// 已登记成果联合校验的等价非 Serde Future 返回类型；不改变输出或生命周期。
pub type ArtifactReadCurrentCheck<'a> = Pin<
    Box<
        dyn Future<Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>>
            + Send
            + 'a,
    >,
>;

/// Dedicated source selectors and adapter attachment; implementing this port grants no authority.
pub trait SourceRunArtifactIdsCurrentTarget: Send + Sync {
    /// Exact original source Thread selector.
    fn source_thread_id(&self) -> &str;
    /// Exact original source Run selector.
    fn source_run_id(&self) -> &str;
    /// Compare the original enrolled adapter identity, independently of its namespace.
    fn matches_authority(&self, authority: &Arc<()>) -> bool;
    /// Compare all six Auth facts and the original attached request binding.
    fn matches_auth(&self, auth: &AuthContext) -> bool;
}
/// A current host witness retained even when the same statement refuses the source result.
pub type SourceRunArtifactIdsCurrentOutcome = Result<
    (
        Box<dyn ArtifactReadTailWitness>,
        Result<crate::artifacts::SourceRunArtifactIds, ArtifactReadCurrentError>,
    ),
    ArtifactReadCurrentError,
>;
/// Non-Serde dedicated current observation future under the original absolute deadline.
pub type SourceRunArtifactIdsCurrentCheck<'a> =
    Pin<Box<dyn Future<Output = SourceRunArtifactIdsCurrentOutcome> + Send + 'a>>;

/// 受信 Rust host 的当前验证 port；任意 Rust 实现不自动取得可信身份。
pub trait HostRequestBindingGuard: Send + Sync {
    /// Observe the original current host and source together, or refuse unsupported composition.
    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        _auth: &'a AuthContext,
        _target: &'a dyn SourceRunArtifactIdsCurrentTarget,
        _deadline: std::time::Instant,
    ) -> SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async {
            Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ))
        })
    }
    /// 真实原宿主与成果来源的最后联合观察；未安装该真实消费者时封闭拒绝。
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        _auth: &'a AuthContext,
        _target: &'a dyn ArtifactReadCurrentTarget,
        _deadline: std::time::Instant,
    ) -> ArtifactReadCurrentCheck<'a> {
        Box::pin(async {
            Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ))
        })
    }
    /// 每次执行真实当前验证；结果不是持久权限。
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>;
    /// Verify under the caller's original absolute use-case deadline.
    /// An implementation without a true budget-aware source remains unavailable; the
    /// old fixed-budget path must not silently extend this request's remaining time.
    fn verify_current_before<'a>(
        &'a self,
        _auth: &'a AuthContext,
        _deadline: std::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Err(HostRequestBindingError::Unavailable) })
    }
}

/// 当次真实记录的非 Serde 借用比较值；不授读取权限。
pub struct ArtifactReadRecordFacts<'a> {
    /// 当前数据库实际成果 ID。
    pub artifact_id: &'a str,
    /// 当前数据库实际摘要。
    pub sha256: &'a str,
    /// 当前数据库实际长度。
    pub byte_length: u64,
    /// 当前记录及操作的真实来源 ID。
    pub source: &'a crate::artifacts::ArtifactRegistrationReceipt,
    /// 当前真实 workspace。
    pub workspace: &'a crate::artifacts::ArtifactWorkspace,
}
/// 受信真实 reader 的私有目标 port；任意 Rust 实现不自动成为生产 authority。
pub trait ArtifactReadCurrentTarget: Send + Sync {
    /// Notify only a loss of actual rollback completion proof; this never grants authority.
    /// Existing targets have no new lifecycle effect.
    fn mark_rollback_unproven(&self) {}
    /// 有界 ID 仅供真实 own-Pool 查询；不是票据。
    fn lookup_id(&self) -> &str;
    /// 精确适配器身份；必须另经真实 same-Pool enrollment。
    fn matches_authority(&self, authority: &Arc<()>) -> bool;
    /// 原六项身份及实际 binding 必须一致。
    fn matches_auth(&self, auth: &AuthContext) -> bool;
    /// 当次真实记录必须匹配原实际 reader 的记录。
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool;
    /// 原 FD/root/marker 的同步尾检；无 await、无正文读取。
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError>;
}
/// 联合读取观察的封闭 Rust 错误；不新增公开错误协议。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactReadCurrentError {
    /// 原当前宿主绑定失效或依赖不可用。
    Host(HostRequestBindingError),
    /// 当前成果或来源不存在/不可见。
    NotVisible,
    /// 当前可见来源下的脱敏 gone 状态。
    Gone(crate::artifacts::ArtifactGoneStatus),
    /// 字节、记录或实际生产依赖不能闭合。
    Unavailable,
}
/// 最后真实联合观察的同步宿主/window/clock 见证；不能成为永久授权。
pub trait ArtifactReadTailWitness: Send + Sync {
    /// 原 deadline 下的当前同步尾检；不执行额外异步查询。
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError>;
}
struct OwnerState {
    closed: AtomicBool,
}
/// 唯一实际生命周期 guard。proof、issuer 和临时观察均不持有这个 lease。
pub struct RequestBindingOwnerLease {
    state: Arc<OwnerState>,
}
impl RequestBindingOwnerLease {
    /// 仅由已验证的实际宿主构造；与生产组合根一同审计。
    #[doc(hidden)]
    #[must_use]
    pub fn for_trusted_host(kind: HostRequestBindingKind) -> (Self, RequestBindingIssuer) {
        let state = Arc::new(OwnerState {
            closed: AtomicBool::new(false),
        });
        (
            Self {
                state: Arc::clone(&state),
            },
            RequestBindingIssuer { state, kind },
        )
    }
    /// 实际 shutdown 或 Drop 前永久关闭；不可复活。
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::SeqCst);
    }
}
impl Drop for RequestBindingOwnerLease {
    fn drop(&mut self) {
        self.close();
    }
}
impl fmt::Debug for RequestBindingOwnerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBindingOwnerLease(<redacted>)")
    }
}
/// 发行点持有的身份。Clone 不拥有生命周期 lease。
#[derive(Clone)]
pub struct RequestBindingIssuer {
    state: Arc<OwnerState>,
    kind: HostRequestBindingKind,
}
/// 只 Weak 指向独立观察状态；upgrade 不会保活 lease。
#[derive(Clone)]
pub struct RequestBindingOwnerObservation {
    state: Weak<OwnerState>,
}
impl RequestBindingOwnerObservation {
    /// 当次 owner 仍运行；不证明业务 scope。
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.state
            .upgrade()
            .is_some_and(|s| !s.closed.load(Ordering::SeqCst))
    }
}
impl fmt::Debug for RequestBindingOwnerObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBindingOwnerObservation(<redacted>)")
    }
}
impl fmt::Debug for RequestBindingIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBindingIssuer(<redacted>)")
    }
}
/// 真实 session 不可变 epoch；HMAC 列保持私有且不进 Debug。
#[derive(Clone, PartialEq, Eq)]
pub struct ServerSessionBindingIdentity {
    id: String,
    user: ActorId,
    token_column: String,
    created: OffsetDateTime,
    issued: AuthGeneration,
}
impl ServerSessionBindingIdentity {
    /// 仅从真实 resolver 已验证行构造，不是 caller 自报 proof。
    #[doc(hidden)]
    #[must_use]
    pub fn from_verified_row(
        id: String,
        user: ActorId,
        token_column: String,
        created: OffsetDateTime,
        issued: AuthGeneration,
    ) -> Self {
        Self {
            id,
            user,
            token_column,
            created,
            issued,
        }
    }
}
impl fmt::Debug for ServerSessionBindingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSessionBindingIdentity(<redacted>)")
    }
}
#[derive(Clone, PartialEq, Eq)]
struct AuthFacts {
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    roles: BTreeSet<Role>,
    generation: AuthGeneration,
    single_user: bool,
}
impl AuthFacts {
    fn of(auth: &AuthContext) -> Self {
        Self {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            roles: auth.roles().clone(),
            generation: auth.auth_generation(),
            single_user: auth.is_single_user(),
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
enum Epoch {
    Session(ServerSessionBindingIdentity),
    SingleUser,
    Window { label: String, id: u64 },
}
/// 独立绑定身份；相等不证明当前可用。
#[derive(Clone)]
pub struct HostRequestBindingIdentity {
    owner: Arc<OwnerState>,
    kind: HostRequestBindingKind,
    epoch: Epoch,
    facts: AuthFacts,
}
impl HostRequestBindingIdentity {
    /// 精确 owner Arc identity、封闭种类、epoch 与原六项身份比较。
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.kind == other.kind
            && self.epoch == other.epoch
            && self.facts == other.facts
    }
}
impl fmt::Debug for HostRequestBindingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostRequestBindingIdentity(<redacted>)")
    }
}
/// 非 Serde 的自携当前校验绑定。具体 guard 由实际 host 私有 mint。
#[derive(Clone)]
pub struct VerifiedHostRequestBinding {
    identity: HostRequestBindingIdentity,
    guard: Arc<dyn HostRequestBindingGuard>,
}
impl VerifiedHostRequestBinding {
    /// 借用身份，仅供显式绑定比较。
    #[must_use]
    pub const fn identity(&self) -> &HostRequestBindingIdentity {
        &self.identity
    }
    /// 封闭绑定种类，不作为权限。
    #[must_use]
    pub const fn kind(&self) -> HostRequestBindingKind {
        self.identity.kind
    }
    fn attached_to(&self, auth: &AuthContext) -> bool {
        self.identity.facts == AuthFacts::of(auth)
    }
    /// 每次执行真正 guard，await 前后重核 owner；没有永久权限结论。
    pub async fn verify_current(&self, auth: &AuthContext) -> Result<(), HostRequestBindingError> {
        let same_binding = auth
            .request_binding()
            .is_some_and(|current| self.identity.same_binding(current.identity()));
        if !self.attached_to(auth)
            || !same_binding
            || self.identity.owner.closed.load(Ordering::SeqCst)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let result = self.guard.verify_current(auth).await;
        if self.identity.owner.closed.load(Ordering::SeqCst) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        result
    }
    /// Perform current host validation using one original monotonic use-case deadline.
    /// The guard receives the same deadline, and elapsed or closed results are withheld.
    pub async fn verify_current_before(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        let same_binding = auth
            .request_binding()
            .is_some_and(|current| self.identity.same_binding(current.identity()));
        if !self.attached_to(auth)
            || !same_binding
            || self.identity.owner.closed.load(Ordering::SeqCst)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let result = self.guard.verify_current_before(auth, deadline).await;
        let same_binding = auth
            .request_binding()
            .is_some_and(|current| self.identity.same_binding(current.identity()));
        if !self.attached_to(auth)
            || !same_binding
            || self.identity.owner.closed.load(Ordering::SeqCst)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        result
    }
    pub(crate) fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.attached_to(auth)
    }
}
impl fmt::Debug for VerifiedHostRequestBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedHostRequestBinding(<redacted>)")
    }
}
/// 附加/发行的确定性错误，不携带身份内容。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestBindingAttachError {
    /// 原六项身份不匹配。
    IdentityMismatch,
    /// 当前发行 owner 种类不匹配。
    WrongOwnerKind,
    /// 实际 owner 已关闭。
    NotCurrent,
    /// 实际 epoch 不满足构造形状。
    InvalidEpoch,
}
impl RequestBindingIssuer {
    /// Weak 观察，不包含 lease。
    #[must_use]
    pub fn observation(&self) -> RequestBindingOwnerObservation {
        RequestBindingOwnerObservation {
            state: Arc::downgrade(&self.state),
        }
    }
    /// 身份是否由本发行点产生；之后仍须当前 guard。
    #[must_use]
    pub fn owns_identity(&self, id: &HostRequestBindingIdentity) -> bool {
        Arc::ptr_eq(&self.state, &id.owner) && self.kind == id.kind
    }
    fn bind(
        &self,
        kind: HostRequestBindingKind,
        auth: &AuthContext,
        epoch: Epoch,
        guard: Arc<dyn HostRequestBindingGuard>,
    ) -> Result<VerifiedHostRequestBinding, RequestBindingAttachError> {
        if self.kind != kind {
            return Err(RequestBindingAttachError::WrongOwnerKind);
        }
        if self.state.closed.load(Ordering::SeqCst) {
            return Err(RequestBindingAttachError::NotCurrent);
        }
        Ok(VerifiedHostRequestBinding {
            identity: HostRequestBindingIdentity {
                owner: Arc::clone(&self.state),
                kind,
                epoch,
                facts: AuthFacts::of(auth),
            },
            guard,
        })
    }
    /// 仅从真实 resolver 的原行与真实 guard 发行。
    #[doc(hidden)]
    pub fn bind_server_session(
        &self,
        auth: &AuthContext,
        key: ServerSessionBindingIdentity,
        guard: Arc<dyn HostRequestBindingGuard>,
    ) -> Result<VerifiedHostRequestBinding, RequestBindingAttachError> {
        if &key.user != auth.actor() || key.issued != auth.auth_generation() {
            return Err(RequestBindingAttachError::IdentityMismatch);
        }
        self.bind(
            HostRequestBindingKind::ServerSession,
            auth,
            Epoch::Session(key),
            guard,
        )
    }
    /// 仅从实际 verified SingleUser principal 发行。
    #[doc(hidden)]
    pub fn bind_single_user_owner(
        &self,
        auth: &AuthContext,
        guard: Arc<dyn HostRequestBindingGuard>,
    ) -> Result<VerifiedHostRequestBinding, RequestBindingAttachError> {
        if !auth.is_single_user() {
            return Err(RequestBindingAttachError::IdentityMismatch);
        }
        self.bind(
            HostRequestBindingKind::ServerSingleUserOwner,
            auth,
            Epoch::SingleUser,
            guard,
        )
    }
    /// 仅由实际 native protocol 为当前 map entry 发行。
    #[doc(hidden)]
    pub fn bind_desktop_window(
        &self,
        auth: &AuthContext,
        label: String,
        id: u64,
        guard: Arc<dyn HostRequestBindingGuard>,
    ) -> Result<VerifiedHostRequestBinding, RequestBindingAttachError> {
        if id == 0 || label.is_empty() {
            return Err(RequestBindingAttachError::InvalidEpoch);
        }
        self.bind(
            HostRequestBindingKind::DesktopWindow,
            auth,
            Epoch::Window { label, id },
            guard,
        )
    }
}

/// Internal readonly lookup capacity; not a session-save or public-wire validity limit.
pub const MAX_SERVER_SESSION_EPOCH_LOOKUP_BYTES: usize = 512;

/// Issuer-owned borrowed original session epoch for a trusted own-Pool decoder.
/// No token getter, Serde or Debug is provided. Matching this epoch alone is not current
/// authorization: the decoder must also check expiry, idle, current ACL and namespace.
pub struct BorrowedServerSessionEpoch<'a> {
    epoch: &'a ServerSessionBindingIdentity,
}
impl BorrowedServerSessionEpoch<'_> {
    /// Bounded original lookup key; never a bearer token or public locator.
    #[must_use]
    pub fn lookup_id(&self) -> &str {
        &self.epoch.id
    }
    /// Compare an actual decoded row with all original immutable epoch values.
    #[must_use]
    pub fn matches_raw_row(
        &self,
        id: &str,
        user_id: &str,
        token_column: &str,
        created_at: OffsetDateTime,
        issued_auth_generation: i64,
    ) -> bool {
        self.epoch.id == id
            && self.epoch.user.as_str() == user_id
            && self.epoch.token_column == token_column
            && self.epoch.created == created_at
            && u64::try_from(issued_auth_generation).ok() == Some(self.epoch.issued.get())
    }
}
impl RequestBindingIssuer {
    /// Borrow only this running issuer's original session epoch, for readonly observation.
    /// Capacity failures are unavailable and do not invalidate historical session rows.
    #[doc(hidden)]
    pub fn borrow_server_session_epoch<'a>(
        &self,
        identity: &'a HostRequestBindingIdentity,
    ) -> Result<BorrowedServerSessionEpoch<'a>, HostRequestBindingError> {
        if !self.owns_identity(identity) || self.state.closed.load(Ordering::SeqCst) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let Epoch::Session(epoch) = &identity.epoch else {
            return Err(HostRequestBindingError::Missing);
        };
        if epoch.id.is_empty()
            || epoch.id.len() > MAX_SERVER_SESSION_EPOCH_LOOKUP_BYTES
            || epoch.id.chars().any(char::is_control)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        Ok(BorrowedServerSessionEpoch { epoch })
    }
    /// Match this running issuer's original opaque window epoch without exposing it.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_desktop_window_epoch(
        &self,
        identity: &HostRequestBindingIdentity,
        label: &str,
        binding_id: u64,
    ) -> bool {
        self.owns_identity(identity)
            && !self.state.closed.load(Ordering::SeqCst)
            && matches!(&identity.epoch, Epoch::Window { label: original, id }
                if original == label && *id == binding_id)
    }
}

struct OriginalArtifactReadTail {
    original: VerifiedHostRequestBinding,
    witness: Box<dyn ArtifactReadTailWitness>,
}
impl ArtifactReadTailWitness for OriginalArtifactReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.original
            .check_artifact_read_attachment(auth, deadline)?;
        self.witness.verify_current(auth, deadline)?;
        self.original.check_artifact_read_attachment(auth, deadline)
    }
}
impl VerifiedHostRequestBinding {
    fn check_artifact_read_attachment(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        if !self.attached_to(auth)
            || !auth
                .request_binding()
                .is_some_and(|current| self.identity.same_binding(current.identity()))
            || self.identity.owner.closed.load(Ordering::SeqCst)
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        Ok(())
    }
    /// Reject missing, stale or expired attachments without treating attachment as PG authority.
    pub fn check_source_run_artifact_ids_attachment(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.check_artifact_read_attachment(auth, deadline)
    }
    /// Retain the original binding and current host witness on both source success and refusal.
    pub async fn verify_source_run_artifact_ids_current_before(
        &self,
        auth: &AuthContext,
        target: &dyn SourceRunArtifactIdsCurrentTarget,
        deadline: std::time::Instant,
    ) -> SourceRunArtifactIdsCurrentOutcome {
        self.check_source_run_artifact_ids_attachment(auth, deadline)?;
        if !target.matches_auth(auth) {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        let outcome = self
            .guard
            .verify_source_run_artifact_ids_current_before(auth, target, deadline)
            .await;
        self.check_source_run_artifact_ids_attachment(auth, deadline)?;
        let (witness, source) = outcome?;
        self.verify_source_run_artifact_ids_tail(auth, witness.as_ref(), deadline)?;
        Ok((
            Box::new(OriginalArtifactReadTail {
                original: self.clone(),
                witness,
            }),
            source,
        ))
    }
    /// Synchronous final original binding/host/window/clock check, without FD or body access.
    pub fn verify_source_run_artifact_ids_tail(
        &self,
        auth: &AuthContext,
        witness: &dyn ArtifactReadTailWitness,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.check_source_run_artifact_ids_attachment(auth, deadline)?;
        witness.verify_current(auth, deadline)?;
        self.check_source_run_artifact_ids_attachment(auth, deadline)
    }
    /// 执行实际原宿主与成果来源的最后联合观察；返回封闭同步见证而不是正文。
    pub async fn verify_artifact_read_current_before(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        self.check_artifact_read_attachment(auth, deadline)?;
        if !target.matches_auth(auth) {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        let outcome = self
            .guard
            .verify_artifact_read_current_before(auth, target, deadline)
            .await;
        // Invalidate even an old error when the actual original owner vanished while awaiting.
        self.check_artifact_read_attachment(auth, deadline)?;
        let witness = outcome?;
        self.verify_artifact_read_tail(auth, target, witness.as_ref(), deadline)?;
        Ok(Box::new(OriginalArtifactReadTail {
            original: self.clone(),
            witness,
        }))
    }
    /// 最后同步 handoff 尾检：原 binding、真实 FD/root 及宿主/window/clock，无 await。
    pub fn verify_artifact_read_tail(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        witness: &dyn ArtifactReadTailWitness,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.check_artifact_read_attachment(auth, deadline)?;
        if !target.matches_auth(auth) {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        target.verify_physical_current()?;
        witness.verify_current(auth, deadline)?;
        self.check_artifact_read_attachment(auth, deadline)
    }
    /// Check an actual retained host witness for a no-byte ACK/closed control handoff.
    /// This does not establish physical readability or grant another byte delivery.
    pub fn verify_artifact_read_control_tail(
        &self,
        auth: &AuthContext,
        witness: &dyn ArtifactReadTailWitness,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.check_artifact_read_attachment(auth, deadline)?;
        witness.verify_current(auth, deadline)?;
        self.check_artifact_read_attachment(auth, deadline)
    }
}
