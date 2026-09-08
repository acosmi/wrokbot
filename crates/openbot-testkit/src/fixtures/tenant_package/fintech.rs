use openbot_application::tenant::package::{
    TenantPackageEnvironment, TenantPackageFile, TenantPackageFiles, expand_environment,
    validate_tenant_package,
};

const BRAND: &str = include_str!("../../../../../examples/fintech/brand.yaml");
const AGENTS: &str = include_str!("../../../../../examples/fintech/agents.yaml");
const CHANNELS: &str = include_str!("../../../../../examples/fintech/channels.yaml");
const MODEL: &str = include_str!("../../../../../examples/fintech/model.yaml");
const KNOWLEDGE: &str = include_str!("../../../../../examples/fintech/knowledge.yaml");

#[test]
fn includes_the_complete_fintech_deployment_package_example() {
    let environment = TenantPackageEnvironment::default();
    let package = validate_tenant_package(TenantPackageFiles {
        brand: expand_environment(BRAND, TenantPackageFile::Brand, &environment).unwrap(),
        agents: expand_environment(AGENTS, TenantPackageFile::Agents, &environment).unwrap(),
        channels: expand_environment(CHANNELS, TenantPackageFile::Channels, &environment).unwrap(),
        model: expand_environment(MODEL, TenantPackageFile::Model, &environment).unwrap(),
        knowledge: expand_environment(KNOWLEDGE, TenantPackageFile::Knowledge, &environment)
            .unwrap(),
    })
    .unwrap();

    assert_eq!(package.tenant_id, "fintech");
    assert_eq!(package.product_name, "Ledgerline");
    assert_eq!(
        package.agents.len(),
        3,
        "managed slot 必须有 Rust built-in fallback"
    );
    assert_eq!(package.channels.len(), 3);
    assert!(
        package
            .channels
            .iter()
            .filter(|channel| channel.audience.is_everyone())
            .count()
            >= 2
    );
    assert!(
        package
            .channels
            .iter()
            .any(|channel| channel.audience.named_groups().contains("risk"))
    );
    for contents in [BRAND, AGENTS, CHANNELS, MODEL, KNOWLEDGE] {
        assert!(contents.contains("SPDX-License-Identifier: MIT"));
        assert!(!contents.contains("product_name: OpenBot"));
    }
}
