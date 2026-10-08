//! 当前 owner 自定义模型库存端口；真实事务与 ACK 由已安装的 Infra 实现证明。

use std::fmt;
use std::time::Instant;

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::custom_model_catalog::{
    CustomModelCatalogPage, CustomModelCatalogPageRequest,
};
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    CustomModelCatalogHostTailWitness, HostRequestBindingError,
};

/// 封闭内部错误，不携带 SQL、原输入或物理来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomModelCatalogError {
    /// 原 cursor 不符合封闭语法。
    InvalidCursor,
    /// 原 actor 或 Host 不再可见。
    NotVisible,
    /// 依赖、预算、schema/mapping 或 rollback 证明不可用。
    Unavailable,
    /// 原 allocation 配额已满，不排队或驱逐活项。
    Busy,
}

impl CustomModelCatalogError {
    pub(crate) fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidCursor => AppError::MalformedPayload { field: "cursor" },
            Self::NotVisible => AppError::NotVisible,
            Self::Unavailable => unavailable(),
            Self::Busy => AppError::RequestConflict {
                resource: "custom_model_catalog",
            },
        }
    }
}

/// 每次执行重新读取原 Pool/Host 的只读库存；任意实现不构成生产 enrollment。
#[async_trait]
pub trait CustomModelCatalogInventory: Send + Sync {
    /// 原 deadline 从 Application admission 前开始，适配器不得续期。
    async fn list_current(
        &self,
        auth: &AuthContext,
        request: &CustomModelCatalogPageRequest,
        deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, CustomModelCatalogError>;
}

/// 未装配的库存始终不可用，不以空页伪装成功。
pub struct NoCustomModelCatalogInventory;

#[async_trait]
impl CustomModelCatalogInventory for NoCustomModelCatalogInventory {
    async fn list_current(
        &self,
        _auth: &AuthContext,
        _request: &CustomModelCatalogPageRequest,
        _deadline: Instant,
    ) -> Result<CurrentCustomModelCatalogPage, CustomModelCatalogError> {
        Err(CustomModelCatalogError::Unavailable)
    }
}

/// 实际适配器在原 rollback ACK 后交给 Application 的不可复制观察。
///
/// 公开受信构造函数为跨 crate 装配所需；函数名称与类型本身不证明真实 ACK。
pub struct CurrentCustomModelCatalogPage {
    page: CustomModelCatalogPage,
    auth: AuthContext,
    deadline: Instant,
    tail: Box<dyn CustomModelCatalogHostTailWitness>,
}

impl CurrentCustomModelCatalogPage {
    /// 真实已安装适配器只可在实际 ACK 与原 tail 成功后调用。
    ///
    /// 重验 DTO/原 actor/deadline/tail，不制造数据库或 enrollment 证明。
    pub fn from_rollback_acknowledged_observation(
        page: CustomModelCatalogPage,
        auth: AuthContext,
        deadline: Instant,
        tail: Box<dyn CustomModelCatalogHostTailWitness>,
    ) -> Result<Self, CustomModelCatalogError> {
        if !page.is_valid() {
            return Err(CustomModelCatalogError::Unavailable);
        }
        require_actor(&auth)?;
        if Instant::now() >= deadline {
            return Err(CustomModelCatalogError::Unavailable);
        }
        tail.verify_current(&auth, deadline).map_err(host_error)?;
        Ok(Self {
            page,
            auth,
            deadline,
            tail,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CustomModelCatalogPage,
        AuthContext,
        Instant,
        Box<dyn CustomModelCatalogHostTailWitness>,
    ) {
        (self.page, self.auth, self.deadline, self.tail)
    }
}

impl fmt::Debug for CurrentCustomModelCatalogPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentCustomModelCatalogPage(<redacted>)")
    }
}

pub(crate) fn require_actor(auth: &AuthContext) -> Result<(), CustomModelCatalogError> {
    if !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        || auth.request_binding().is_none()
    {
        return Err(CustomModelCatalogError::NotVisible);
    }
    Ok(())
}

pub(crate) fn same_original_auth(left: &AuthContext, right: &AuthContext) -> bool {
    left == right
        && left
            .request_binding()
            .zip(right.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
}

pub(crate) fn host_error(error: HostRequestBindingError) -> CustomModelCatalogError {
    match error {
        HostRequestBindingError::Missing | HostRequestBindingError::NotCurrent => {
            CustomModelCatalogError::NotVisible
        }
        HostRequestBindingError::Unavailable => CustomModelCatalogError::Unavailable,
    }
}

pub(crate) fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "custom_model_catalog",
    }
}
