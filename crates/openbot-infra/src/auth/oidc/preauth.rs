//! pre-auth surface（v3 §6.2 末段）。
//!
//! §6.2 逐字：「pre-auth surface 只公开**环境配置的** provider ID 和『存在企业 SSO』布尔值，
//! **不列出企业 domain/provider**」。
//!
//! # 「不列出」被做成「装不下」
//!
//! [`PreAuthSurface`] 只有两个字段，**没有**放企业域名或动态注册 provider 名字的地方。
//! 这不是省略，是本类型的设计内容 —— 同一手法上游也用过：
//! `server/src/auth/identity-provider-store.ts` 的 `RegisteredIdentityProvider` 注释写
//! 「no projection that includes them can be safe to send to a browser, so the shape that
//! leaves this module cannot express them」，讲的是 client secret，判据一模一样。
//!
//! 为什么这条要紧：一个把企业域名列出来的登录页，等于把「哪些公司在用这套部署」做成一个
//! 匿名可读的名录。攻击者据此挑目标、伪造钓鱼页、判断某人属于哪个组织，而这些信息对**真正
//! 要登录的人毫无用处** —— 他知道自己的邮箱，输进去就行。
//!
//! 与 [`super::routing`] 的统一响应是同一条防线的两端：这里管「不主动列出」，那里管
//! 「不被逐个试出来」。缺任一端，另一端都没有意义。

use serde::Serialize;

use super::provider::{ProviderOrigin, ProviderRegistry};

/// 未认证访客能看到的**全部**内容。
///
/// 字段只有两个，见模块文档。想加第三个字段前先回答：一个还没登录的人拿它做什么？
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PreAuthSurface {
    /// 环境配置的 provider ID，按 ID 升序。
    ///
    /// 这些 ID 本身就是部署的公开配置（登录页要画三个按钮），且形态受
    /// [`super::provider::ProviderId`] 约束，不含自由文本。
    provider_ids: Vec<String>,

    /// 这个部署**有没有**企业 SSO —— 只有布尔值，没有是谁。
    enterprise_sso_available: bool,
}

impl PreAuthSurface {
    /// 从注册表投影出 pre-auth 面。
    ///
    /// 动态注册的 provider **只贡献那个布尔值**：它们的 ID 与域名一个都不出来。
    #[must_use]
    pub fn project(registry: &ProviderRegistry) -> Self {
        let provider_ids = registry
            .iter()
            .filter(|config| config.origin() == ProviderOrigin::EnvironmentConfigured)
            .map(|config| config.id().as_str().to_owned())
            .collect();

        let enterprise_sso_available = registry
            .iter()
            .any(|config| config.origin() == ProviderOrigin::DynamicallyRegistered);

        Self {
            provider_ids,
            enterprise_sso_available,
        }
    }

    /// 环境配置的 provider ID。
    #[must_use]
    pub fn provider_ids(&self) -> &[String] {
        &self.provider_ids
    }

    /// 是否存在企业 SSO。
    #[must_use]
    pub const fn enterprise_sso_available(&self) -> bool {
        self.enterprise_sso_available
    }
}

#[cfg(test)]
mod tests {
    use super::PreAuthSurface;
    use crate::auth::oidc::provider::fixtures::{config, okta_kind, three_providers};
    use crate::auth::oidc::provider::{ProviderOrigin, ProviderRegistry};

    fn enterprise(
        id: &str,
        issuer_host: &str,
        domain: &str,
    ) -> crate::auth::oidc::OidcProviderConfig {
        config(
            id,
            okta_kind(&format!("https://{issuer_host}/oauth2/default")),
            ProviderOrigin::DynamicallyRegistered,
            &[domain],
        )
    }

    /// 正向：环境配置的三个 ID 都列出来；没有企业 SSO 时布尔值为假。
    #[test]
    fn environment_configured_providers_are_listed() {
        let surface = PreAuthSurface::project(&three_providers());
        assert_eq!(surface.provider_ids(), ["google", "microsoft", "okta"]);
        assert!(
            !surface.enterprise_sso_available(),
            "三家都是环境配置，没有动态注册的"
        );
    }

    /// 负向：动态注册的 provider **一个字都不出来**，只把布尔值翻成真。
    #[test]
    fn dynamically_registered_providers_contribute_only_a_boolean() {
        let registry = ProviderRegistry::build([
            config(
                "google",
                crate::auth::oidc::ProviderKind::Google,
                ProviderOrigin::EnvironmentConfigured,
                &["gmail.example"],
            ),
            enterprise("acme-sso", "acme.okta-test.invalid", "acme.example"),
        ])
        .unwrap();

        let surface = PreAuthSurface::project(&registry);
        assert_eq!(surface.provider_ids(), ["google"]);
        assert!(surface.enterprise_sso_available());

        // 序列化之后同样不含企业 provider 的名字与域名。
        let json = serde_json::to_string(&surface).unwrap();
        assert!(
            !json.contains("acme-sso"),
            "企业 provider ID 泄漏了：{json}"
        );
        assert!(!json.contains("acme.example"), "企业域名泄漏了：{json}");
        assert!(!json.contains("okta-test"), "企业 issuer 泄漏了：{json}");
        // 正向对照：环境配置的 ID 确实在里面 —— 否则上面三条在「什么都不输出」的世界里
        // 同样通过。
        assert!(json.contains("google"));
        assert!(json.contains("enterprise_sso_available"));
    }

    /// 两份**只在企业 provider 上不同**的注册表，投影出逐字节相同的 pre-auth 面。
    ///
    /// 这是反枚举的核心判据：外部观察者无法通过 pre-auth 面区分「这套部署接了 Contoso」
    /// 和「接了 Initech」，甚至无法区分接了一家还是三家。
    #[test]
    fn the_surface_is_invariant_to_which_enterprises_are_registered() {
        let google = || {
            config(
                "google",
                crate::auth::oidc::ProviderKind::Google,
                ProviderOrigin::EnvironmentConfigured,
                &["gmail.example"],
            )
        };

        let one = ProviderRegistry::build([
            google(),
            enterprise("contoso", "contoso.okta-test.invalid", "contoso.example"),
        ])
        .unwrap();

        let three = ProviderRegistry::build([
            google(),
            enterprise("initech", "initech.okta-test.invalid", "initech.example"),
            enterprise("umbrella", "umbrella.okta-test.invalid", "umbrella.example"),
            enterprise("hooli", "hooli.okta-test.invalid", "hooli.example"),
        ])
        .unwrap();

        let a = serde_json::to_string(&PreAuthSurface::project(&one)).unwrap();
        let b = serde_json::to_string(&PreAuthSurface::project(&three)).unwrap();
        assert_eq!(
            a, b,
            "企业 provider 的**数量与身份**都不得从 pre-auth 面看出来"
        );

        // 正向对照：一个都没有时确实不一样（布尔值翻了）—— 否则「恒相同」是废话。
        let none = ProviderRegistry::build([google()]).unwrap();
        let c = serde_json::to_string(&PreAuthSurface::project(&none)).unwrap();
        assert_ne!(a, c);
    }

    /// 空部署：什么都没有，也不报错。
    #[test]
    fn an_empty_deployment_projects_an_empty_surface() {
        let surface = PreAuthSurface::project(&ProviderRegistry::default());
        assert!(surface.provider_ids().is_empty());
        assert!(!surface.enterprise_sso_available());
        assert_eq!(surface, PreAuthSurface::default());
    }
}
