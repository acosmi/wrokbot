//! 认证边界 —— [`AuthResolver`] port 与它在 Axum 侧的提取器 [`Authenticated`] /
//! [`OriginAuthenticated`]。
//!
//! # port 与 W-4 production 实现
//!
//! `openbot_contracts::auth::AuthContext` **刻意既不 `Serialize` 也不 `Deserialize`**
//! （§5.3）：只要它能被反序列化，任何 transport 都可以拿 renderer / 模型 / MCP server /
//! remote Agent 送来的字节直接铸造一个身份。生产构造入口因此只有一个 ——
//! `AuthContextBuilder::from_verified_session`，而它的名字本身就是一句断言：调用点必须
//! 能指出 session、连接 peer、数据库 ACL 三者各自的来源。
//!
//! [`PostgresSessionAuthResolver`] 是 W-4 production 实现：只认 `openbot_session` cookie，
//! HMAC-SHA256 后查库，要求 0015 session generation、当前 user generation、deny list、role、
//! absolute/idle 全通过；旧 plaintext/NULL-generation session 统一 401。
//!
//! # 没有默认放行
//!
//! 这是刻意的，不是"还没写"。一个默认可用的 `AuthResolver` 会在生产里变成后门：它一旦
//! 存在，接线层忘记注入真实实现就不会编译失败，只会静默地把每个请求当成合法用户。
//! 所以 [`ServerBuilder::new`](crate::http::ServerBuilder::new) 强制传入一个
//! `Arc<dyn AuthResolver>` —— 拿不出实现的宿主根本组装不出 router。
//!
//! [`FixedAuthResolver`] 与单用户固定身份测试构造器均被 `#[cfg(any(test, feature = "testkit"))]`
//! 挡在默认 feature 图之外（`testkit` 默认关）。它也不提供 `Default`：身份必须由调用方
//! 显式交出来，写不出 `FixedAuthResolver::default()` 这种"从哪来的身份？"的代码。
//!
//! # 组装链路
//!
//! ```text
//! openbot-server（本 crate）      定义 AuthResolver port
//!         ↑ 实现
//! PostgresSessionAuthResolver       把 keyed session + DB ACL 组装成权威身份，
//!                                 内部调用 AuthContextBuilder::from_verified_session
//!         ↓ 注入
//! ServerBuilder::new(app, auth)   router 拿到 Arc<dyn AuthResolver>
//! ```
//!
//! [`SingleUserAuthResolver`] 只由二进制在显式 `OPENBOT_SINGLE_USER=true` 且 loopback 绑定时构造。
//! OIDC/SAML 登录与 session 签发已由 W-7 接通；G2 仍因外审、KMS/HSM 与跨平台原生发行未闭合。

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use http::request::Parts;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::error::{AppError, SensitiveWriteReason};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::identity::session::{
    LiveSession, SensitiveWriteApproved, SensitiveWriteRejection, SensitiveWriteRequest,
    SessionHashKey, SessionLifetimePolicy, SessionState, SessionToken, SessionTokenHash,
    TrustedOrigins, authorize_fresh_origin_write, authorize_sensitive_write, evaluate_session,
};
use time::OffsetDateTime;
use tracing::Span;

use crate::error::HttpError;
use crate::http::ServerState;
use crate::telemetry::ACTOR_ID_FIELD;

/// 把一次请求的认证材料解析成权威身份。
///
/// 实现必须只依据**服务端可验证**的东西：session cookie 对应的 session 行、连接 peer、
/// 数据库 ACL。请求头里自称的角色、`principal`、租户一律是普通不可信输入（§5.3）。
///
/// 入参是 `&Parts` 而不是整个 `Request`：认证只看头部与扩展，看不到 body。这条限制是
/// 构造性的 —— 一个拿不到 body 的实现不可能"从请求体里读身份"。
#[async_trait]
pub trait AuthResolver: Send + Sync {
    /// 从请求的认证材料解析出权威身份。
    ///
    /// # Errors
    ///
    /// 无凭据 / 凭据无效 / session 已失效 → [`AppError::Unauthenticated`]（401）。
    /// 依赖（session store、目录服务）不可用 → [`AppError::DependencyUnavailable`]（503）；
    /// **不得**在依赖不可用时放行，也不得把它伪装成 401 —— 前者是后门，后者会让运维
    /// 在一堆"用户登录失败"里找不到真正的故障。
    async fn resolve(&self, parts: &Parts) -> Result<AuthContext, AppError>;

    /// 同一次认证附带 live-session assurance；普通实现缺省只有身份，敏感写会 fail-closed。
    async fn resolve_with_assurance(&self, parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.resolve(parts).await.map(ResolvedAuth::without_session)
    }

    /// 在相应认证/CSRF guard 已通过后推进 idle 活动时刻；无状态实现无需动作。
    async fn touch(&self, _resolved: &ResolvedAuth) -> Result<(), AppError> {
        Ok(())
    }

    /// Revoke exactly the concrete session carried by this resolved request.
    ///
    /// Stateless/single-user implementations have no row to revoke and fail explicitly.
    async fn revoke_session(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let _ = resolved;
        Err(AppError::RequestConflict {
            resource: "session",
        })
    }
}

/// 一次已解析身份，以及敏感写所需的 live-session 证明。
#[derive(Clone, Debug)]
pub struct ResolvedAuth {
    context: AuthContext,
    live_session: Option<LiveSession>,
    session_id: Option<String>,
}

impl ResolvedAuth {
    /// 只有身份、没有 session assurance；敏感写必须拒绝。
    #[must_use]
    pub const fn without_session(context: AuthContext) -> Self {
        Self {
            context,
            live_session: None,
            session_id: None,
        }
    }

    /// 由已验证数据库 session 构造。
    #[must_use]
    pub fn from_live_session(
        context: AuthContext,
        live_session: LiveSession,
        session_id: Option<String>,
    ) -> Self {
        Self {
            context,
            live_session: Some(live_session),
            session_id,
        }
    }

    /// 权威上下文。
    #[must_use]
    pub const fn context(&self) -> &AuthContext {
        &self.context
    }

    /// live session；`None` 时敏感写 fail-closed。
    #[must_use]
    pub const fn live_session(&self) -> Option<&LiveSession> {
        self.live_session.as_ref()
    }

    /// Whether this request is backed by one concrete, individually revocable session row.
    #[must_use]
    pub const fn has_revocable_session(&self) -> bool {
        self.session_id.is_some()
    }

    /// 交出上下文。
    #[must_use]
    pub fn into_context(self) -> AuthContext {
        self.context
    }

    fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// 已认证请求的提取器。
///
/// 把认证做成**提取器**而不是 handler 里的一行调用，是为了让"这条路由要不要认证"
/// 出现在 handler 的签名里：`list(_, Authenticated(auth), _)` 一眼可见，
/// 而漏写一行 `let auth = resolve(...)` 不会有任何东西提醒你。
///
/// 它同时是 §16.4「只取需要的 ID 字段」的落点：解析成功后只把 `actor_id` 记进当前 span，
/// **绝不**把 `AuthContext` 整体（角色集合、auth generation）交给 tracing。
pub struct Authenticated(pub AuthContext);

impl FromRequestParts<ServerState> for Authenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        state.auth_resolver().touch(&resolved).await?;
        let auth = resolved.into_context();
        // 只记 ID，不记上下文本体。`AuthContext` 没有 `Serialize`，但它**有** `Debug`，
        // 而 `Debug` 会把角色集合与 auth generation 一起打出来 —— 那是那道防线上的缺口。
        // 这里用 `Display` 只投影一个 ID 字段，把缺口堵上。
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// 已认证且携带 session assurance 的请求；敏感 admin 写 handler 使用。
pub struct SensitiveAuthenticated(pub ResolvedAuth);

impl FromRequestParts<ServerState> for SensitiveAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        Span::current().record(
            ACTOR_ID_FIELD,
            tracing::field::display(resolved.context().actor()),
        );
        Ok(Self(resolved))
    }
}

/// Fresh administrator + trusted-Origin authority resolved before any request body is read.
///
/// Unlike [`SensitiveAuthenticated`], this extractor completes the sensitive-write decision inside
/// `FromRequestParts`. A following `Json` extractor therefore cannot parse an attacker-controlled
/// body when Origin/session/admin assurance has already failed.
pub struct SensitiveOriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for SensitiveOriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        state.authorize_sensitive_write(&resolved, origin).await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// Fresh authenticated + trusted-Origin authority resolved before any owner-managed secret/body.
/// Resource ownership remains an application/infra decision; unlike
/// [`SensitiveOriginAuthenticated`], ordinary members are not rejected for lacking admin role.
pub struct FreshOriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for FreshOriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        state
            .authorize_fresh_origin_write(&resolved, origin)
            .await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// 已认证的 same-origin 操作；trusted Origin 在任何 body/upgrade 业务运行前判定。
///
/// `FromRequestParts` 构造性拿不到 body，Memory 写与 thread WebSocket 共用它，避免 CSRF
/// 失败仍读取 body 或建立能外泄 durable thread 的 cross-origin socket。
pub struct OriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for OriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        state
            .authorize_authenticated_origin(&resolved, origin)
            .await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// Same-origin authenticated request retaining the exact verified Origin for ticket binding.
pub struct OriginBoundAuthenticated {
    auth: AuthContext,
    origin: String,
}

impl OriginBoundAuthenticated {
    /// Split the authority context and exact verified Origin.
    #[must_use]
    pub fn into_parts(self) -> (AuthContext, String) {
        (self.auth, self.origin)
    }
}

impl FromRequestParts<ServerState> for OriginBoundAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginMissing,
            })?
            .to_owned();
        state
            .authorize_authenticated_origin(&resolved, Some(origin.as_str()))
            .await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self { auth, origin })
    }
}

/// 敏感 admin 写的 session/origin 配置；未注入时 ServerState 会 fail-closed。
#[derive(Clone, Debug)]
pub struct SensitiveWriteSecurity {
    lifetime: SessionLifetimePolicy,
    trusted_origins: TrustedOrigins,
}

impl SensitiveWriteSecurity {
    /// 由启动期已验证配置构造。
    #[must_use]
    pub const fn new(lifetime: SessionLifetimePolicy, trusted_origins: TrustedOrigins) -> Self {
        Self {
            lifetime,
            trusted_origins,
        }
    }

    /// 判定一次写；specific domain 原因逐项映射到稳定 contracts code。
    pub fn authorize(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<SensitiveWriteApproved, AppError> {
        let Some(session) = resolved.live_session() else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        };
        let role = if resolved.context().has_role(Role::Admin) {
            Role::Admin
        } else {
            Role::User
        };
        authorize_sensitive_write(
            self.lifetime,
            &self.trusted_origins,
            &SensitiveWriteRequest {
                session,
                role,
                origin,
            },
        )
        .map_err(|rejection| AppError::SensitiveWriteRefused {
            reason: match rejection {
                SensitiveWriteRejection::RoleInsufficient => SensitiveWriteReason::RoleInsufficient,
                SensitiveWriteRejection::OriginMissing => SensitiveWriteReason::OriginMissing,
                SensitiveWriteRejection::OriginUntrusted => SensitiveWriteReason::OriginUntrusted,
                SensitiveWriteRejection::SessionNotFresh => SensitiveWriteReason::SessionNotFresh,
            },
        })
    }

    /// 普通已认证 same-origin 操作只要求可信 Origin，不要求 admin/fresh；用于 owner memory
    /// 写与 thread WebSocket，避免跨站带 cookie 读取 durable event。
    pub fn authorize_origin(&self, origin: Option<&str>) -> Result<(), AppError> {
        let Some(origin) = origin else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginMissing,
            });
        };
        if !self.trusted_origins.trusts(origin) {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginUntrusted,
            });
        }
        Ok(())
    }

    /// Fresh same-origin credential write; resource ownership/admin is checked in application/DB.
    pub fn authorize_fresh_origin(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<(), AppError> {
        let Some(session) = resolved.live_session() else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        };
        authorize_fresh_origin_write(self.lifetime, &self.trusted_origins, session, origin)
            .map(|_| ())
            .map_err(|rejection| AppError::SensitiveWriteRefused {
                reason: match rejection {
                    SensitiveWriteRejection::RoleInsufficient => {
                        SensitiveWriteReason::RoleInsufficient
                    }
                    SensitiveWriteRejection::OriginMissing => SensitiveWriteReason::OriginMissing,
                    SensitiveWriteRejection::OriginUntrusted => {
                        SensitiveWriteReason::OriginUntrusted
                    }
                    SensitiveWriteRejection::SessionNotFresh => {
                        SensitiveWriteReason::SessionNotFresh
                    }
                },
            })
    }
}

/// Rust multi-user session cookie 名；不复用 Better Auth cookie，切换时旧会话统一失效。
pub const SESSION_COOKIE_NAME: &str = "openbot_session";

/// PostgreSQL session + ACL 的生产 resolver。
#[derive(Clone)]
pub struct PostgresSessionAuthResolver {
    pool: deadpool_postgres::Pool,
    hash_key: std::sync::Arc<[u8]>,
    lifetime: SessionLifetimePolicy,
    deployment: DeploymentId,
    tenant: TenantId,
}

impl PostgresSessionAuthResolver {
    /// 构造。session hash key 为空会使所有 token 共享无密钥摘要，直接拒绝。
    pub fn new(
        pool: deadpool_postgres::Pool,
        hash_key: impl Into<Vec<u8>>,
        lifetime: SessionLifetimePolicy,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, AppError> {
        let hash_key = hash_key.into();
        if hash_key.is_empty() {
            return Err(AppError::DependencyUnavailable {
                dependency: "session_hash_key",
            });
        }
        Ok(Self {
            pool,
            hash_key: hash_key.into(),
            lifetime,
            deployment,
            tenant,
        })
    }

    async fn resolve_token(&self, token: &str) -> Result<ResolvedAuth, AppError> {
        if token.len() < 16 || token.len() > 512 || !token.is_ascii() {
            return Err(AppError::Unauthenticated);
        }
        let token_hash = SessionTokenHash::compute(
            SessionToken::new(token.as_bytes()),
            SessionHashKey::new(&self.hash_key),
        )
        .to_column_value();
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session resolver 获取数据库连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        let row = client
            .query_opt(
                "SELECT s.id,s.user_id,s.expires_at,s.created_at,s.updated_at,s.auth_generation, \
                        coalesce(u.auth_generation,0) AS current_generation, \
                        coalesce(bool_or(ra.email IS NOT NULL),false) AS revoked, \
                        coalesce(array_agg(distinct ur.role::text) \
                          FILTER (WHERE ur.role IS NOT NULL),'{}') AS roles \
                 FROM public.sessions s \
                 JOIN public.users u ON u.id=s.user_id \
                 LEFT JOIN public.user_roles ur ON ur.user_id=u.id \
                 LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email) \
                 WHERE s.token=$1 \
                 GROUP BY s.id,u.id",
                &[&token_hash],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session resolver 查询失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        let Some(row) = row else {
            return Err(AppError::Unauthenticated);
        };
        let revoked: bool = row.try_get("revoked").map_err(auth_row_error)?;
        if revoked {
            return Err(AppError::Unauthenticated);
        }
        let issued_generation: Option<i64> =
            row.try_get("auth_generation").map_err(auth_row_error)?;
        let Some(issued_generation) = issued_generation else {
            // 0015 前旧 Better Auth session，按方案统一重新登录，不猜 generation。
            return Err(AppError::Unauthenticated);
        };
        let current_generation: i64 = row.try_get("current_generation").map_err(auth_row_error)?;
        let issued_generation =
            u64::try_from(issued_generation).map_err(|_| AppError::Unauthenticated)?;
        let current_generation =
            u64::try_from(current_generation).map_err(|_| AppError::Unauthenticated)?;
        let created_at: OffsetDateTime = row.try_get("created_at").map_err(auth_row_error)?;
        let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(auth_row_error)?;
        let expires_at: OffsetDateTime = row.try_get("expires_at").map_err(auth_row_error)?;
        let now = OffsetDateTime::now_utc();
        if now >= expires_at {
            return Err(AppError::Unauthenticated);
        }
        let live = evaluate_session(
            self.lifetime,
            SessionState::rehydrate(
                created_at,
                updated_at,
                AuthGeneration::new(issued_generation),
            ),
            AuthGeneration::new(current_generation),
            now,
        )
        .map_err(|_| AppError::Unauthenticated)?;
        let role_values: Vec<String> = row.try_get("roles").map_err(auth_row_error)?;
        let roles = role_values
            .iter()
            .map(|value| value.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "database_acl",
            })?;
        let effective =
            resolve_effective_role(roles.iter().copied()).map_err(|_| AppError::ForbiddenRole {
                required: Role::User,
            })?;
        let user_id: String = row.try_get("user_id").map_err(auth_row_error)?;
        let session_id: String = row.try_get("id").map_err(auth_row_error)?;
        let context = AuthContextBuilder::from_verified_session(
            self.deployment.clone(),
            self.tenant.clone(),
            ActorId::new(user_id),
            AuthGeneration::new(current_generation),
            false,
        )
        .with_role(effective)
        .build();
        Ok(ResolvedAuth::from_live_session(
            context,
            live,
            Some(session_id),
        ))
    }
}

impl core::fmt::Debug for PostgresSessionAuthResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresSessionAuthResolver")
            .field("hash_key", &"<redacted>")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthResolver for PostgresSessionAuthResolver {
    async fn resolve(&self, parts: &Parts) -> Result<AuthContext, AppError> {
        self.resolve_with_assurance(parts)
            .await
            .map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, parts: &Parts) -> Result<ResolvedAuth, AppError> {
        let token = session_cookie(parts).ok_or(AppError::Unauthenticated)?;
        self.resolve_token(token).await
    }

    async fn touch(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let Some(session_id) = resolved.session_id() else {
            return Ok(());
        };
        let evaluated_at = resolved
            .live_session()
            .map(|session| session.evaluated_at())
            .ok_or(AppError::Unauthenticated)?;
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session touch 获取连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        client
            .execute(
                "UPDATE public.sessions SET updated_at=greatest(updated_at,$2) WHERE id=$1",
                &[&session_id, &evaluated_at],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session touch 失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        Ok(())
    }

    async fn revoke_session(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let Some(session_id) = resolved.session_id() else {
            return Err(AppError::RequestConflict {
                resource: "session",
            });
        };
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session revoke 获取连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        client
            .execute(
                "DELETE FROM public.sessions WHERE id=$1 AND user_id=$2",
                &[&session_id, &resolved.context().actor().as_str()],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session revoke 失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        Ok(())
    }
}

/// 显式单用户部署的 production resolver。绑定范围必须在启动组装前已通过 §6.1 判定。
#[derive(Clone, Debug)]
pub struct SingleUserAuthResolver {
    context: AuthContext,
    lifetime: SessionLifetimePolicy,
}

impl SingleUserAuthResolver {
    /// Construct only from the fixed Server principal verified against its business database.
    #[must_use]
    pub fn from_verified_principal(
        principal: openbot_infra::auth::single_user::VerifiedSingleUserPrincipal,
        lifetime: SessionLifetimePolicy,
    ) -> Self {
        Self {
            context: principal.into_auth_context(),
            lifetime,
        }
    }

    /// Test-only fixed identity; excluded from the default production feature graph.
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn new(
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        lifetime: SessionLifetimePolicy,
    ) -> Self {
        Self {
            context: AuthContextBuilder::from_verified_session(
                deployment,
                tenant,
                actor,
                AuthGeneration::new(0),
                true,
            )
            .with_roles([Role::Admin, Role::User])
            .build(),
            lifetime,
        }
    }

    fn resolved(&self) -> Result<ResolvedAuth, AppError> {
        let now = OffsetDateTime::now_utc();
        let generation = self.context.auth_generation();
        let live = evaluate_session(
            self.lifetime,
            SessionState::rehydrate(now, now, generation),
            generation,
            now,
        )
        .map_err(|_| AppError::Unauthenticated)?;
        Ok(ResolvedAuth::from_live_session(
            self.context.clone(),
            live,
            None,
        ))
    }
}

#[async_trait]
impl AuthResolver for SingleUserAuthResolver {
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        self.resolved().map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, _parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.resolved()
    }
}

fn session_cookie(parts: &Parts) -> Option<&str> {
    let mut found = None;
    for header in parts.headers.get_all(http::header::COOKIE) {
        let value = header.to_str().ok()?;
        for pair in value.split(';') {
            let (name, value) = pair.trim().split_once('=')?;
            if name == SESSION_COOKIE_NAME && found.replace(value).is_some() {
                return None;
            }
        }
    }
    found
}

fn auth_row_error(error: tokio_postgres::Error) -> AppError {
    tracing::error!(error = %error, "session resolver 行解码失败");
    AppError::DependencyUnavailable {
        dependency: "database",
    }
}

/// 固定身份 / 固定拒绝的 [`AuthResolver`]，**只在测试与 `testkit` feature 下存在**。
///
/// 它没有 `Default`，也没有 `new()`：两个构造器 [`Self::granting`] 与 [`Self::rejecting`]
/// 都要求调用方明确说出"放行成谁"或"以什么理由拒绝"。
#[cfg(any(test, feature = "testkit"))]
pub struct FixedAuthResolver {
    outcome: Result<ResolvedAuth, AppError>,
}

#[cfg(any(test, feature = "testkit"))]
impl FixedAuthResolver {
    /// 恒定放行成给定身份。
    #[must_use]
    pub const fn granting(auth: AuthContext) -> Self {
        Self {
            outcome: Ok(ResolvedAuth::without_session(auth)),
        }
    }

    /// 恒定放行成调用方已构造的 live-session 结果；只供敏感写测试。
    #[must_use]
    pub const fn granting_resolved(resolved: ResolvedAuth) -> Self {
        Self {
            outcome: Ok(resolved),
        }
    }

    /// 恒定拒绝，理由由调用方给出。
    #[must_use]
    pub const fn rejecting(error: AppError) -> Self {
        Self {
            outcome: Err(error),
        }
    }
}

#[cfg(any(test, feature = "testkit"))]
#[async_trait]
impl AuthResolver for FixedAuthResolver {
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        self.outcome.clone().map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, _parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.outcome.clone()
    }
}
