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
/// 受信 Rust host 的当前验证 port；任意 Rust 实现不自动取得可信身份。
pub trait HostRequestBindingGuard: Send + Sync {
    /// 每次执行真实当前验证；结果不是持久权限。
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>;
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
