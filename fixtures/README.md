# Test fixtures

Deterministic inputs for policy, database, provider, UI, and runtime tests. Keep synthetic data distinguishable from captured protocol data. Never include live credentials or customer content.

`MANIFEST.yaml` records fixture provenance and validation commands. `ui/icon-mappings.json` contains the independent icon mapping contract used by `cargo xtask design-lint`. Files under `ui/golden/` are test baselines; generated differences are excluded.
