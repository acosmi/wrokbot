# Dependency auditing

`config.toml`, `audits.toml`, and `imports.lock` contain Cargo Vet configuration and audit records. Exemptions are explicit exceptions, not completed source audits. Preserve version-specific reasoning when updating dependencies.

Run `cargo vet --locked`, `cargo deny check`, and the applicable scripts under `tools/` when changing the dependency graph. Do not broaden exemptions to conceal failing checks.
