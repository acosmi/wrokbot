<p align="center">
  <img src=".github/assets/wrok-bot-banner.png" alt="Wrok Bot">
</p>

<h1 align="center">Wrok Bot</h1>

<p align="center"><strong>English</strong> | <a href="README.zh-CN.md">简体中文</a></p>

<p align="center">AI workbench · Agent collaboration · Browser and computer interaction</p>

Wrok Bot is an AI workbench built with Rust, with a desktop host, server, web interface, and a mobile client under development. The project is currently in development and validation, with macOS as the first release platform.

## Current progress

Status as of September 7, 2026, based on the development and validation records available on that date. Passing individual checks does not mean the installer or the complete product has passed release validation.

| Module | Current status | Remaining work for the first release |
| --- | --- | --- |
| Workbench and UI | Branding, channels, coworkers, skills, memory, and administration screens are implemented; UI unit tests and web builds have been validated | Complete workflow, keyboard, and accessibility validation in actual macOS windows |
| Local services and data | Local services, PostgreSQL, sessions, and persistence have passed individual checks | Clean installation, credential access, reliable startup and shutdown, upgrades, and recovery validation |
| Model connections | Custom connection management and shared inference are implemented; gateway transport awaits integration validation | End-to-end model selection, live conversations, tools, cancellation, and recovery across the gateway, account bridge, and custom model connections |
| System confirmation and authorization | The local confirmation state machine, window lifecycle handling, and related tests are implemented | Native authentication, cancellation, screen locking, and sleep validation in a properly signed app |
| Browser and computer interaction | Engine, screen transport, control permissions, and input have individual implementations | End-to-end validation of real operations, manual takeover, stopping, and failure recovery within the product |
| Mobile client | Shared page source and local web previews are available, with iOS/Android resource compilation records | Real accounts, device binding, native installation, and testing on physical devices for each platform; outside the macOS first-release scope |

## Estimated completion

**Current delivery target: the first macOS release, estimated in 2–4 weeks.**

Measured from September 7, 2026, the target window is **September 21–October 5, 2026**. This is a development estimate. Final delivery depends on completing the remaining features and validating signed installers and real user workflows. This page will be updated if the estimate changes.

The first release aims to provide an installable macOS product covering three core workflows: the workbench and AI tools, browser interaction with manual takeover, and native computer interaction with stopping controls. Model connections, credential protection, data recovery, installation, and startup must also be validated.

The first release is not yet complete. Release validation still requires a signed installer, live model services, and testing on physical Macs. Apple Silicon and Intel support will be stated according to actual validation results. Windows, Linux, and mobile platforms will be validated separately, with progress published as work advances.

## Source layout

- `crates/`: domain, application, infrastructure, desktop, server, UI, and test tools.
- `apps/wrok-bot-mobile/`: mobile client source.
- `examples/`: sample application configuration.
- `fixtures/`: deterministic test data and asset contracts.
- `tools/`: dependency checks and build tool version configuration.

The Rust toolchain is pinned in `rust-toolchain.toml`, and Rust dependencies are locked in `Cargo.lock`. Native library requirements vary by platform. The CI workflow records Linux build dependencies, while `.cargo/config.toml` configures macOS library search paths.

## Local checks

```sh
cargo fmt --all -- --check
cargo test -p openbot-testkit --features xtask --bin xtask
cargo xtask i18n-check
cargo xtask design-lint
```

Before committing, install the local publication checks. Python 3 and Gitleaks are required:

```sh
python3 tools/repository_guard.py install
```

The guard checks staged content before commits and the complete history being published before pushes. GitHub Actions remains manually triggered.

## License and acknowledgements

See `LICENSE` for first-party terms and `NOTICE` for third-party acknowledgements. Fonts, icons, and other assets retain their respective licenses.
