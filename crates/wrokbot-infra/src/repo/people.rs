//! people/auth 表的类型化 PostgreSQL repositories。
//!
//! 这里只承担行持久化；“不能撤销自己”“最后一个 admin”“configured-admin floor”等业务规则
//! 仍由 application/domain 在事务入口裁决，repo 不从 transport 接收自由 SQL。

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `users` repository。
    UserRepo,
    table = users,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

impl UserRepo {
    /// 按规范化 email 读取（数据库 unique）。
    pub async fn find_by_email(
        &self,
        email: &str,
    ) -> Result<Option<crate::db::tables::users::Row>, crate::db::InfraError> {
        self.core.find("\"email\" = $1", &[&email]).await
    }
}

define_table_repo!(
    /// `sessions` repository。
    SessionRepo,
    table = sessions,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

impl SessionRepo {
    /// 按 session token 精确读取；token 只做参数绑定，不进 SQL/错误上下文。
    pub async fn find_by_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::db::tables::sessions::Row>, crate::db::InfraError> {
        self.core.find("\"token\" = $1", &[&token]).await
    }
}

define_table_repo!(
    /// `accounts` repository。
    AccountRepo,
    table = accounts,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

impl AccountRepo {
    /// 按 better-auth 的 `(provider_id, account_id)` 唯一键读取。
    pub async fn find_by_provider_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<Option<crate::db::tables::accounts::Row>, crate::db::InfraError> {
        self.core
            .find(
                "\"provider_id\" = $1 AND \"account_id\" = $2",
                &[&provider_id, &account_id],
            )
            .await
    }
}

define_table_repo!(
    /// `verifications` repository。
    VerificationRepo,
    table = verifications,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

impl VerificationRepo {
    /// 按 verification identifier 列出，调用方再按 expiry 裁决。
    pub async fn list_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Vec<crate::db::tables::verifications::Row>, crate::db::InfraError> {
        self.core
            .list_where(
                "\"identifier\" = $1",
                &[&identifier],
                "\"expires_at\", \"id\"",
            )
            .await
    }
}

define_table_repo!(
    /// `user_roles` repository。
    RoleRepo,
    table = user_roles,
    order_by = "\"user_id\", \"role\"",
    find = find_by_key(user_id: &str, role: &crate::db::types::Role) where "\"user_id\" = $1 AND \"role\" = $2"
);

impl RoleRepo {
    /// 一个用户的全部封闭角色。
    pub async fn list_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::db::tables::user_roles::Row>, crate::db::InfraError> {
        self.core
            .list_where("\"user_id\" = $1", &[&user_id], "\"role\"")
            .await
    }

    /// 当前 admin 行数；“最后一个 admin”业务事务以此为观测之一。
    pub async fn count_admins(&self) -> Result<i64, crate::db::InfraError> {
        let client = self.core.pool().get().await.map_err(|source| {
            crate::db::InfraError::connect("为 RoleRepo 统计 admin 获取连接", source)
        })?;
        client
            .query_one(
                "SELECT count(*)::bigint FROM public.user_roles WHERE role=$1",
                &[&crate::db::types::Role::Admin],
            )
            .await
            .map_err(|source| crate::db::InfraError::query("统计 admin 角色", source))?
            .try_get(0)
            .map_err(|source| {
                crate::db::RowDecodeError::column("user_roles", "count", source).into()
            })
    }
}

define_table_repo!(
    /// `revoked_access` repository。
    RevokedAccessRepo,
    table = revoked_access,
    order_by = "\"email\"",
    find = find_by_email(email: &str) where "\"email\" = $1"
);

impl RevokedAccessRepo {
    /// 规范化 email 是否在永久撤权表中。
    pub async fn is_revoked(&self, email: &str) -> Result<bool, crate::db::InfraError> {
        Ok(self.find_by_email(email).await?.is_some())
    }
}

define_table_repo!(
    /// `sso_providers` repository。
    IdentityProviderRepo,
    table = sso_providers,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

impl IdentityProviderRepo {
    /// 按 OIDC/SAML provider id 唯一键读取。
    pub async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<crate::db::tables::sso_providers::Row>, crate::db::InfraError> {
        self.core
            .find("\"provider_id\" = $1", &[&provider_id])
            .await
    }

    /// 列出声明某 email domain 的 provider；重复 domain 由 auth registry fail-closed。
    pub async fn list_by_domain(
        &self,
        domain: &str,
    ) -> Result<Vec<crate::db::tables::sso_providers::Row>, crate::db::InfraError> {
        self.core
            .list_where("\"domain\" = $1", &[&domain], "\"provider_id\"")
            .await
    }
}
