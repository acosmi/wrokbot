//! Managed built-in Agent provider/budget environment parsing（v3 §7.2 / §7.3）。

use std::time::Duration;

use openbot_application::{
    ProviderBillingFamily, ProviderRateCard, ProviderRateCardError, ProviderRateCardInput,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::address::DeploymentAddress;
use crate::config::env::{self, EnvMap};
use crate::config::error::{ConfigProblem, Expectation};
use crate::config::secret::Secret;

/// Provider selection；三家取值逐字来自固定上游 agent-langgraph。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderKind {
    /// OpenAI-compatible。
    OpenAi,
    /// Anthropic。
    Anthropic,
    /// Google Generative AI。
    Google,
}

/// Provider config；secret Debug 由 `Secret` 自动脱敏。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedProviderConfig {
    /// Provider。
    pub provider: ManagedProviderKind,
    /// Model sent verbatim after TrimString-style outer whitespace removal。
    pub model: String,
    /// Selected provider API key。
    pub api_key: Secret,
    /// Provider base URL。
    pub base_url: DeploymentAddress,
    /// OpenAI only；exact `BOT_RESPONSES_API=true`。
    pub use_responses_api: bool,
    /// New exact numeric CIDR allowlist for private/self-hosted provider endpoints。
    pub egress_allow_cidrs: Vec<String>,
    /// New explicit HTTP override；still requires CIDR/global destination policy。
    pub allow_http: bool,
    /// Optional operator-attested pricing snapshot for this exact provider/model.
    pub rate_card: Option<ProviderRateCard>,
}

/// Agent runtime budgets independent of whether a key is currently configured。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentBudgets {
    /// `None` = AGENT_STALL_TIMEOUT_MS unset/0。
    pub stall_timeout: Option<Duration>,
    /// `None` = OPENBOT_RUN_DEADLINE_MS=0；unset defaults 30min。
    pub run_deadline: Option<Duration>,
    /// Per-sampling output cap；run-wide token/cost-upper-bound accounting由runtime独立累计。
    pub max_output_tokens: u32,
}

/// Package-declared built-in Bots 的 OpenAI transport/fallback config。
///
/// Model 与 credential key id 不来自环境；它们分别只来自已验证的 `model.yaml`。环境 key
/// 只是 PostgreSQL 中不存在 active matching model credential 时的上游兼容 fallback。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageOpenAiProviderConfig {
    /// OpenAI-compatible base URL。
    pub base_url: DeploymentAddress,
    /// Optional environment fallback；stored active credential 始终优先且每 run 重读。
    pub environment_api_key: Option<Secret>,
    /// Exact numeric CIDR allowlist for private/self-hosted endpoints。
    pub egress_allow_cidrs: Vec<String>,
    /// Explicit HTTP override；仍需 CIDR/global destination policy。
    pub allow_http: bool,
}

/// Parse budgets and optional managed provider; appends all problems, never reads process env。
pub fn parse_agent_config(
    env_map: &EnvMap,
    problems: &mut Vec<ConfigProblem>,
) -> (
    AgentBudgets,
    PackageOpenAiProviderConfig,
    Option<ManagedProviderConfig>,
) {
    let stall_timeout = parse_milliseconds(env_map, "AGENT_STALL_TIMEOUT_MS", None, problems);
    let run_deadline = parse_milliseconds(
        env_map,
        "OPENBOT_RUN_DEADLINE_MS",
        Some(1_800_000),
        problems,
    );
    let max_output_tokens = parse_output_tokens(env_map, problems);
    let budgets = AgentBudgets {
        stall_timeout,
        run_deadline,
        max_output_tokens,
    };
    let package_openai = parse_package_openai(env_map, problems);
    let managed_requested = [
        "BOT_PROVIDER",
        "BOT_MODEL",
        "BOT_RESPONSES_API",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "GOOGLE_API_KEY",
        "GOOGLE_GENERATIVE_AI_BASE_URL",
        "BOT_PRICE_CURRENCY",
        "BOT_PRICE_MAX_INPUT_MICRO_UNITS_PER_MILLION_TOKENS",
        "BOT_PRICE_MAX_OUTPUT_MICRO_UNITS_PER_MILLION_TOKENS",
        "BOT_PRICE_SOURCE_URL",
        "BOT_PRICE_SOURCE_SHA256",
        "BOT_PRICE_OBSERVED_AT",
    ]
    .into_iter()
    .any(|name| env::optional(env_map, name).is_some());
    if !managed_requested {
        return (budgets, package_openai, None);
    }
    let provider = match env::optional(env_map, "BOT_PROVIDER").unwrap_or("openai") {
        "openai" => ManagedProviderKind::OpenAi,
        "anthropic" => ManagedProviderKind::Anthropic,
        "google" => ManagedProviderKind::Google,
        _ => {
            problems.push(ConfigProblem::Malformed {
                variable: "BOT_PROVIDER",
                expectation: Expectation::ProviderName,
            });
            ManagedProviderKind::OpenAi
        }
    };
    let default_model = match provider {
        ManagedProviderKind::OpenAi => "gpt-5.5",
        ManagedProviderKind::Anthropic => "claude-sonnet-4-5",
        ManagedProviderKind::Google => "gemini-2.5-flash",
    };
    let model = env::optional(env_map, "BOT_MODEL")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_model)
        .to_owned();
    let (key_name, base_name, default_base) = match provider {
        ManagedProviderKind::OpenAi => ("OPENAI_API_KEY", "OPENAI_BASE_URL", None),
        ManagedProviderKind::Anthropic => (
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            Some("https://api.anthropic.com"),
        ),
        ManagedProviderKind::Google => (
            "GOOGLE_API_KEY",
            "GOOGLE_GENERATIVE_AI_BASE_URL",
            Some("https://generativelanguage.googleapis.com"),
        ),
    };
    let key = if provider == ManagedProviderKind::OpenAi {
        package_openai.environment_api_key.clone()
    } else {
        env::optional(env_map, key_name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Secret::new)
    };
    if key.is_none() {
        problems.push(ConfigProblem::Malformed {
            variable: key_name,
            expectation: Expectation::NonEmptySecret,
        });
    }
    let base_url = if provider == ManagedProviderKind::OpenAi {
        package_openai.base_url.clone()
    } else {
        parse_provider_base(
            env_map,
            base_name,
            default_base.expect("non-OpenAI default base"),
            problems,
        )
    };
    let rate_card = parse_managed_rate_card(env_map, provider, &model, problems);
    (
        budgets,
        package_openai.clone(),
        key.map(|api_key| ManagedProviderConfig {
            provider,
            model,
            api_key,
            base_url,
            use_responses_api: provider == ManagedProviderKind::OpenAi
                && env::optional(env_map, "BOT_RESPONSES_API") == Some("true"),
            egress_allow_cidrs: package_openai.egress_allow_cidrs.clone(),
            allow_http: package_openai.allow_http,
            rate_card,
        }),
    )
}

fn parse_managed_rate_card(
    env_map: &EnvMap,
    provider: ManagedProviderKind,
    model: &str,
    problems: &mut Vec<ConfigProblem>,
) -> Option<ProviderRateCard> {
    const CURRENCY: &str = "BOT_PRICE_CURRENCY";
    const INPUT: &str = "BOT_PRICE_MAX_INPUT_MICRO_UNITS_PER_MILLION_TOKENS";
    const OUTPUT: &str = "BOT_PRICE_MAX_OUTPUT_MICRO_UNITS_PER_MILLION_TOKENS";
    const SOURCE: &str = "BOT_PRICE_SOURCE_URL";
    const DIGEST: &str = "BOT_PRICE_SOURCE_SHA256";
    const OBSERVED: &str = "BOT_PRICE_OBSERVED_AT";
    const NAMES: [&str; 6] = [CURRENCY, INPUT, OUTPUT, SOURCE, DIGEST, OBSERVED];
    let present = NAMES
        .iter()
        .filter(|name| env::optional(env_map, name).is_some())
        .count();
    if present == 0 {
        return None;
    }
    if present != NAMES.len() {
        for name in NAMES {
            if env::optional(env_map, name).is_none() {
                problems.push(ConfigProblem::Malformed {
                    variable: name,
                    expectation: Expectation::ProviderRateCard,
                });
            }
        }
        return None;
    }
    let parse_rate = |name: &'static str, problems: &mut Vec<ConfigProblem>| {
        env::optional(env_map, name)
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value <= i64::MAX as u64)
            .or_else(|| {
                problems.push(ConfigProblem::Malformed {
                    variable: name,
                    expectation: Expectation::ProviderRateCard,
                });
                None
            })
    };
    let input = parse_rate(INPUT, problems)?;
    let output = parse_rate(OUTPUT, problems)?;
    let observed = env::optional(env_map, OBSERVED)
        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
        .or_else(|| {
            problems.push(ConfigProblem::Malformed {
                variable: OBSERVED,
                expectation: Expectation::ProviderRateCard,
            });
            None
        })?;
    let family = match provider {
        ManagedProviderKind::OpenAi => ProviderBillingFamily::OpenAiCompatible,
        ManagedProviderKind::Anthropic => ProviderBillingFamily::Anthropic,
        ManagedProviderKind::Google => ProviderBillingFamily::Google,
    };
    ProviderRateCard::new(ProviderRateCardInput {
        family,
        model: model.to_owned(),
        currency: env::optional(env_map, CURRENCY)
            .unwrap_or_default()
            .to_owned(),
        max_input_micro_units_per_million_tokens: input,
        max_output_micro_units_per_million_tokens: output,
        source_url: env::optional(env_map, SOURCE)
            .unwrap_or_default()
            .to_owned(),
        source_sha256: env::optional(env_map, DIGEST)
            .unwrap_or_default()
            .to_owned(),
        observed_at: observed,
    })
    .map_err(|error| {
        let variable = match error {
            ProviderRateCardError::Identity => "BOT_MODEL",
            ProviderRateCardError::Currency => CURRENCY,
            ProviderRateCardError::Source => SOURCE,
            ProviderRateCardError::Digest => DIGEST,
            ProviderRateCardError::ObservedAt => OBSERVED,
            ProviderRateCardError::Rate => INPUT,
        };
        problems.push(ConfigProblem::Malformed {
            variable,
            expectation: Expectation::ProviderRateCard,
        });
    })
    .ok()
}

fn parse_output_tokens(env_map: &EnvMap, problems: &mut Vec<ConfigProblem>) -> u32 {
    const DEFAULT: u32 = 16_384;
    match env::optional(env_map, "OPENBOT_PROVIDER_MAX_OUTPUT_TOKENS") {
        None => DEFAULT,
        Some(raw) => match raw.parse::<u32>() {
            Ok(value @ 1..=1_000_000) => value,
            _ => {
                problems.push(ConfigProblem::Malformed {
                    variable: "OPENBOT_PROVIDER_MAX_OUTPUT_TOKENS",
                    expectation: Expectation::WholeTokensOneToMillion,
                });
                DEFAULT
            }
        },
    }
}

fn parse_package_openai(
    env_map: &EnvMap,
    problems: &mut Vec<ConfigProblem>,
) -> PackageOpenAiProviderConfig {
    PackageOpenAiProviderConfig {
        base_url: parse_provider_base(
            env_map,
            "OPENAI_BASE_URL",
            "https://api.openai.com/v1",
            problems,
        ),
        environment_api_key: env::optional(env_map, "OPENAI_API_KEY")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Secret::new),
        egress_allow_cidrs: env::comma_separated(env_map, "OPENBOT_PROVIDER_EGRESS_ALLOW_CIDRS"),
        allow_http: env::optional(env_map, "OPENBOT_PROVIDER_ALLOW_HTTP") == Some("true"),
    }
}

fn parse_provider_base(
    env_map: &EnvMap,
    variable: &'static str,
    default: &'static str,
    problems: &mut Vec<ConfigProblem>,
) -> DeploymentAddress {
    let raw = env::optional(env_map, variable)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default);
    match DeploymentAddress::parse(raw) {
        Ok(value) => value,
        Err(_) => {
            problems.push(ConfigProblem::Malformed {
                variable,
                expectation: Expectation::AbsoluteHttpUrl,
            });
            DeploymentAddress::parse(default).expect("static provider URL")
        }
    }
}

fn parse_milliseconds(
    env_map: &EnvMap,
    variable: &'static str,
    default: Option<u64>,
    problems: &mut Vec<ConfigProblem>,
) -> Option<Duration> {
    let raw = env::optional(env_map, variable);
    let value = match raw {
        None => default,
        Some(raw) => match raw.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => {
                problems.push(ConfigProblem::Malformed {
                    variable,
                    expectation: Expectation::WholeMillisecondsOrZero,
                });
                default
            }
        },
    };
    value.and_then(|value| (value != 0).then(|| Duration::from_millis(value)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn openai_defaults_and_exact_responses_flag_match_fixed_upstream() {
        let env = BTreeMap::from([
            ("OPENAI_API_KEY".to_owned(), " key ".to_owned()),
            ("BOT_PROVIDER".to_owned(), "openai".to_owned()),
            ("BOT_RESPONSES_API".to_owned(), "TRUE".to_owned()),
        ]);
        let mut problems = Vec::new();
        let (budgets, package, provider) = parse_agent_config(&env, &mut problems);
        assert!(problems.is_empty());
        assert_eq!(budgets.stall_timeout, None);
        assert_eq!(budgets.run_deadline, Some(Duration::from_millis(1_800_000)));
        assert_eq!(budgets.max_output_tokens, 16_384);
        let provider = provider.unwrap();
        assert_eq!(
            package.environment_api_key.as_ref().unwrap().expose(),
            "key"
        );
        assert_eq!(provider.provider, ManagedProviderKind::OpenAi);
        assert_eq!(provider.model, "gpt-5.5");
        assert!(!provider.use_responses_api);
        assert!(provider.egress_allow_cidrs.is_empty());
        assert!(!provider.allow_http);
        assert_eq!(provider.api_key.expose(), "key");
        assert_eq!(provider.base_url.as_str(), "https://api.openai.com/v1");
        assert_eq!(provider.rate_card, None);

        let mut exact = env;
        exact.insert("BOT_RESPONSES_API".to_owned(), "true".to_owned());
        let (_, _, provider) = parse_agent_config(&exact, &mut Vec::new());
        assert!(provider.unwrap().use_responses_api);
    }

    #[test]
    fn anthropic_and_google_select_only_their_exact_key_base_and_model_inputs() {
        let cases = [
            (
                BTreeMap::from([
                    ("BOT_PROVIDER".to_owned(), "anthropic".to_owned()),
                    ("ANTHROPIC_API_KEY".to_owned(), " anthropic-key ".to_owned()),
                    (
                        "ANTHROPIC_BASE_URL".to_owned(),
                        " https://anthropic.example ".to_owned(),
                    ),
                    ("GOOGLE_API_KEY".to_owned(), "wrong-key".to_owned()),
                    ("BOT_RESPONSES_API".to_owned(), "true".to_owned()),
                ]),
                ManagedProviderKind::Anthropic,
                "claude-sonnet-4-5",
                "anthropic-key",
                "https://anthropic.example",
            ),
            (
                BTreeMap::from([
                    ("BOT_PROVIDER".to_owned(), "google".to_owned()),
                    ("BOT_MODEL".to_owned(), " gemini-custom ".to_owned()),
                    ("GOOGLE_API_KEY".to_owned(), " google-key ".to_owned()),
                    (
                        "GOOGLE_GENERATIVE_AI_BASE_URL".to_owned(),
                        "https://google.example/root".to_owned(),
                    ),
                    ("ANTHROPIC_API_KEY".to_owned(), "wrong-key".to_owned()),
                    ("BOT_RESPONSES_API".to_owned(), "true".to_owned()),
                ]),
                ManagedProviderKind::Google,
                "gemini-custom",
                "google-key",
                "https://google.example/root",
            ),
        ];
        for (env, expected_kind, expected_model, expected_key, expected_base) in cases {
            let mut problems = Vec::new();
            let (_, _, provider) = parse_agent_config(&env, &mut problems);
            assert!(problems.is_empty());
            let provider = provider.unwrap();
            assert_eq!(provider.provider, expected_kind);
            assert_eq!(provider.model, expected_model);
            assert_eq!(provider.api_key.expose(), expected_key);
            assert_eq!(provider.base_url.as_str(), expected_base);
            assert!(!provider.use_responses_api);
            assert_eq!(provider.rate_card, None);
        }
    }

    #[test]
    fn managed_rate_card_is_all_or_none_and_binds_exact_provider_model() {
        let mut env = BTreeMap::from([
            ("BOT_PROVIDER".to_owned(), "anthropic".to_owned()),
            ("BOT_MODEL".to_owned(), "claude-priced".to_owned()),
            ("ANTHROPIC_API_KEY".to_owned(), "key".to_owned()),
            (
                "BOT_PRICE_MAX_INPUT_MICRO_UNITS_PER_MILLION_TOKENS".to_owned(),
                "1500000".to_owned(),
            ),
            (
                "BOT_PRICE_MAX_OUTPUT_MICRO_UNITS_PER_MILLION_TOKENS".to_owned(),
                "2000000".to_owned(),
            ),
            ("BOT_PRICE_CURRENCY".to_owned(), "USD".to_owned()),
            (
                "BOT_PRICE_SOURCE_URL".to_owned(),
                "https://prices.example.test/archive/2026-08-30".to_owned(),
            ),
            ("BOT_PRICE_SOURCE_SHA256".to_owned(), "a".repeat(64)),
            (
                "BOT_PRICE_OBSERVED_AT".to_owned(),
                "2026-08-30T12:00:00Z".to_owned(),
            ),
        ]);
        let mut problems = Vec::new();
        let (_, _, provider) = parse_agent_config(&env, &mut problems);
        assert!(problems.is_empty());
        let rate = provider.unwrap().rate_card.expect("rate card");
        assert_eq!(rate.family(), ProviderBillingFamily::Anthropic);
        assert_eq!(rate.model(), "claude-priced");
        assert_eq!(rate.currency(), "USD");
        assert_eq!(rate.max_input_rate(), 1_500_000);
        assert_eq!(rate.max_output_rate(), 2_000_000);

        env.remove("BOT_PRICE_SOURCE_SHA256");
        let mut problems = Vec::new();
        let (_, _, provider) = parse_agent_config(&env, &mut problems);
        assert_eq!(provider.unwrap().rate_card, None);
        assert!(problems.contains(&ConfigProblem::Malformed {
            variable: "BOT_PRICE_SOURCE_SHA256",
            expectation: Expectation::ProviderRateCard,
        }));
        env.insert("BOT_PRICE_SOURCE_SHA256".to_owned(), "a".repeat(64));
        env.insert("BOT_PRICE_CURRENCY".to_owned(), "usd".to_owned());
        let mut problems = Vec::new();
        let (_, _, provider) = parse_agent_config(&env, &mut problems);
        assert_eq!(provider.unwrap().rate_card, None);
        assert!(problems.contains(&ConfigProblem::Malformed {
            variable: "BOT_PRICE_CURRENCY",
            expectation: Expectation::ProviderRateCard,
        }));
    }

    #[test]
    fn zero_disables_budgets_and_bad_values_are_all_reported() {
        let env = BTreeMap::from([
            ("AGENT_STALL_TIMEOUT_MS".to_owned(), "0".to_owned()),
            ("OPENBOT_RUN_DEADLINE_MS".to_owned(), "0".to_owned()),
            ("BOT_PROVIDER".to_owned(), "OPENAI".to_owned()),
            ("OPENAI_BASE_URL".to_owned(), "file:///tmp/model".to_owned()),
        ]);
        let mut problems = Vec::new();
        let (budgets, _, provider) = parse_agent_config(&env, &mut problems);
        assert_eq!(budgets.stall_timeout, None);
        assert_eq!(budgets.run_deadline, None);
        assert!(provider.is_none());
        assert_eq!(problems.len(), 3);
    }

    #[test]
    fn package_base_url_does_not_require_an_environment_key_because_vault_is_authoritative() {
        let env = BTreeMap::from([(
            "OPENAI_BASE_URL".to_owned(),
            "https://gateway.example/v1".to_owned(),
        )]);
        let mut problems = Vec::new();
        let (_, package, managed) = parse_agent_config(&env, &mut problems);
        assert!(problems.is_empty());
        assert!(managed.is_none());
        assert!(package.environment_api_key.is_none());
        assert_eq!(package.base_url.as_str(), "https://gateway.example/v1");
    }

    #[test]
    fn private_provider_transport_overrides_are_explicit_and_http_is_exact_true_only() {
        let env = BTreeMap::from([
            (
                "OPENBOT_PROVIDER_EGRESS_ALLOW_CIDRS".to_owned(),
                "10.42.0.0/16,127.0.0.1/32".to_owned(),
            ),
            ("OPENBOT_PROVIDER_ALLOW_HTTP".to_owned(), "TRUE".to_owned()),
        ]);
        let mut problems = Vec::new();
        let (_, package, managed) = parse_agent_config(&env, &mut problems);
        assert!(problems.is_empty());
        assert!(managed.is_none());
        assert_eq!(package.egress_allow_cidrs, ["10.42.0.0/16", "127.0.0.1/32"]);
        assert!(!package.allow_http);

        let mut exact = env;
        exact.insert("OPENBOT_PROVIDER_ALLOW_HTTP".to_owned(), "true".to_owned());
        let (_, package, _) = parse_agent_config(&exact, &mut Vec::new());
        assert!(package.allow_http);
    }

    #[test]
    fn provider_output_token_budget_is_bounded_and_never_silently_disabled() {
        for raw in ["0", "1000001", "-1", "1.5"] {
            let env = BTreeMap::from([(
                "OPENBOT_PROVIDER_MAX_OUTPUT_TOKENS".to_owned(),
                raw.to_owned(),
            )]);
            let mut problems = Vec::new();
            let (budgets, _, _) = parse_agent_config(&env, &mut problems);
            assert_eq!(budgets.max_output_tokens, 16_384);
            assert_eq!(problems.len(), 1, "{raw}");
        }
        let env = BTreeMap::from([(
            "OPENBOT_PROVIDER_MAX_OUTPUT_TOKENS".to_owned(),
            "32768".to_owned(),
        )]);
        let (budgets, _, _) = parse_agent_config(&env, &mut Vec::new());
        assert_eq!(budgets.max_output_tokens, 32_768);
    }
}
