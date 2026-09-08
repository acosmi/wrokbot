//! 固定上游 `server/tests/computer-policy.test.ts` 的 28 条求值判据逐项移植。

use openbot_domain::policy::context::{
    ActorRef, BotRef, ElementRef, FileRef, McpEffect, McpRef, PageRef, ToolRef,
};
use openbot_domain::policy::{
    ActionPolicy, CompiledActionPolicy, Intent, PolicyContext, PolicyMode, PolicySource, Refusal,
    evaluate,
};

#[derive(Debug)]
struct Outcome {
    allowed: bool,
    forward: bool,
    source: PolicySource,
    matched: Option<String>,
    refusal: Option<Refusal>,
}

fn context() -> PolicyContext {
    PolicyContext {
        tool: ToolRef {
            name: "computer_click".to_owned(),
        },
        bot: BotRef {
            id: "risk-analyst".to_owned(),
        },
        page: PageRef {
            url: "https://example.com/order".to_owned(),
            host: "example.com".to_owned(),
        },
        actor: ActorRef {
            id: "dev-local-user".to_owned(),
        },
        element: Some(ElementRef {
            reference: "e13".to_owned(),
            role: "button".to_owned(),
            name: "Submit order".to_owned(),
            kind: None,
        }),
        key: None,
        intent: None,
        file: None,
        mcp: None,
        command: None,
    }
}

fn policy(mode: PolicyMode, deny: &[&str], allow: &[&str]) -> ActionPolicy {
    ActionPolicy {
        mode,
        deny: deny.iter().map(|value| (*value).to_owned()).collect(),
        allow: allow.iter().map(|value| (*value).to_owned()).collect(),
    }
}

fn decide(policy: Option<ActionPolicy>, context: PolicyContext) -> Outcome {
    let compiled = policy.as_ref().map_or_else(
        CompiledActionPolicy::unconfigured,
        CompiledActionPolicy::compile,
    );
    let decision = evaluate(&compiled, &context);
    Outcome {
        allowed: decision.allowed,
        forward: decision.forward,
        source: decision.source,
        matched: decision.matched.map(str::to_owned),
        refusal: decision.refusal,
    }
}

fn permissive() -> ActionPolicy {
    policy(PolicyMode::Enforce, &[], &["true"])
}

#[test]
fn absent_policy_refuses_rather_than_permitting_everything() {
    let decision = decide(None, context());
    assert!(!decision.allowed);
    assert!(!decision.forward);
    assert_eq!(decision.source, PolicySource::Default);
}

#[test]
fn empty_allow_list_refuses() {
    let decision = decide(Some(policy(PolicyMode::Enforce, &[], &[])), context());
    assert!(!decision.allowed);
    assert!(!decision.forward);
}

#[test]
fn deny_beats_allow_even_when_allow_matches_everything() {
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["contains(element.name, \"submit\")"],
            &["true"],
        )),
        context(),
    );
    assert!(!decision.allowed);
    assert!(!decision.forward);
    assert_eq!(decision.source, PolicySource::Deny);
    assert_eq!(
        decision.refusal,
        Some(Refusal::Element {
            name: "Submit order".to_owned(),
            host: "example.com".to_owned(),
        })
    );
}

#[test]
fn deny_rule_leaves_unrelated_elements_alone() {
    let mut input = context();
    input.element = Some(ElementRef {
        reference: "e6".to_owned(),
        role: "input".to_owned(),
        name: "Large".to_owned(),
        kind: None,
    });
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["contains(element.name, \"submit\")"],
            &["true"],
        )),
        input,
    );
    assert!(decision.allowed && decision.forward);
}

#[test]
fn substring_matching_is_case_insensitive() {
    let mut input = context();
    input.element.as_mut().unwrap().name = "SUBMIT NOW".to_owned();
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["contains(element.name, \"submit\")"],
                &["true"],
            )),
            input,
        )
        .allowed
    );
}

#[test]
fn broken_deny_expression_still_denies() {
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["this is not ( valid cel"],
            &["true"],
        )),
        context(),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.source, PolicySource::Deny);
}

#[test]
fn deny_expressions_that_are_not_questions_still_deny() {
    for rule in [
        "\"Submit order\"",
        "element.name",
        "contains(element.name, \"submit\") ? element.name : false",
        "repeat.count",
    ] {
        let decision = decide(
            Some(policy(PolicyMode::Enforce, &[rule], &["true"])),
            context(),
        );
        assert!(!decision.allowed, "{rule}");
        assert_eq!(decision.source, PolicySource::Deny, "{rule}");
    }
}

#[test]
fn allow_expression_that_is_not_a_question_does_not_permit() {
    let decision = decide(
        Some(policy(PolicyMode::Enforce, &[], &["\"Submit order\""])),
        context(),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.source, PolicySource::Default);
}

#[test]
fn deny_expression_that_answers_false_permits() {
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["contains(element.name, \"cancel\")"],
            &["true"],
        )),
        context(),
    );
    assert!(decision.allowed);
    assert_eq!(decision.source, PolicySource::Allow);
}

#[test]
fn broken_allow_expression_does_not_permit() {
    let decision = decide(
        Some(policy(PolicyMode::Enforce, &[], &["also not ( valid"])),
        context(),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.source, PolicySource::Default);
}

#[test]
fn dry_run_records_refusal_but_forwards_work() {
    let decision = decide(
        Some(policy(
            PolicyMode::DryRun,
            &["contains(element.name, \"submit\")"],
            &["true"],
        )),
        context(),
    );
    assert!(!decision.allowed);
    assert!(decision.forward);
    assert_eq!(decision.source, PolicySource::Deny);
}

#[test]
fn rules_can_target_tool_host_and_bot() {
    let mut by_tool = context();
    by_tool.tool.name = "computer_type".to_owned();
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["tool.name == \"computer_type\""],
                &["true"],
            )),
            by_tool,
        )
        .allowed
    );
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["page.host == \"example.com\""],
                &["true"],
            )),
            context(),
        )
        .allowed
    );
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["bot.id == \"risk-analyst\""],
                &["true"],
            )),
            context(),
        )
        .allowed
    );
}

#[test]
fn element_rule_still_decides_when_element_is_unknown() {
    let mut input = context();
    input.element = None;
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["contains(element.name, \"submit\")"],
                &["true"],
            )),
            input,
        )
        .allowed
    );
}

fn key_context(key: &str) -> PolicyContext {
    let mut input = context();
    input.tool.name = "computer_key".to_owned();
    input.bot.id = "sales".to_owned();
    input.actor.id = "someone".to_owned();
    input.key = Some(key.to_owned());
    input
}

#[test]
fn rule_can_refuse_keypress_not_only_click() {
    let boundary = policy(
        PolicyMode::Enforce,
        &["tool.name == \"computer_key\" && key == \"Enter\""],
        &["true"],
    );
    assert!(!decide(Some(boundary.clone()), key_context("Enter")).allowed);
    assert!(decide(Some(boundary), key_context("a")).allowed);
}

fn activate(mut input: PolicyContext) -> PolicyContext {
    input.intent = Some(Intent::Activate);
    input
}

fn activation_policy() -> ActionPolicy {
    policy(
        PolicyMode::Enforce,
        &["intent == \"activate\" && contains(element.name, \"submit\")"],
        &["true"],
    )
}

#[test]
fn intent_rule_catches_click_on_button() {
    assert!(!decide(Some(activation_policy()), activate(context())).allowed);
}

#[test]
fn intent_rule_catches_enter_on_same_button() {
    let mut input = activate(context());
    input.tool.name = "computer_key".to_owned();
    input.key = Some("Enter".to_owned());
    assert!(!decide(Some(activation_policy()), input).allowed);
}

#[test]
fn intent_rule_catches_space_on_same_button() {
    let mut input = activate(context());
    input.tool.name = "computer_key".to_owned();
    input.key = Some("Space".to_owned());
    assert!(!decide(Some(activation_policy()), input).allowed);
}

#[test]
fn intent_rule_leaves_ordinary_typing_alone() {
    let mut input = context();
    input.tool.name = "computer_type".to_owned();
    input.intent = Some(Intent::Type);
    input.element = Some(ElementRef {
        reference: "e2".to_owned(),
        role: "textbox".to_owned(),
        name: "Customer name:".to_owned(),
        kind: None,
    });
    assert!(decide(Some(activation_policy()), input).allowed);
}

#[test]
fn intent_rule_does_not_catch_enter_in_text_field_but_preset_does() {
    let mut input = activate(context());
    input.tool.name = "computer_key".to_owned();
    input.key = Some("Enter".to_owned());
    input.element = Some(ElementRef {
        reference: "e3".to_owned(),
        role: "textbox".to_owned(),
        name: "E-mail address:".to_owned(),
        kind: None,
    });
    assert!(decide(Some(activation_policy()), input.clone()).allowed);
    let preset = policy(
        PolicyMode::Enforce,
        &[
            "intent == \"activate\" && contains(element.name, \"submit\")",
            "key == \"Enter\"",
        ],
        &["true"],
    );
    assert!(!decide(Some(preset), input).allowed);
}

fn navigation() -> PolicyContext {
    let mut input = context();
    input.tool.name = "computer_navigate".to_owned();
    input.bot.id = "b".to_owned();
    input.actor.id = "a".to_owned();
    input.page = PageRef {
        url: "https://httpbin.org/forms/post".to_owned(),
        host: "httpbin.org".to_owned(),
    };
    input.intent = Some(Intent::Navigate);
    input.element = None;
    input.key = None;
    input
}

#[test]
fn unguarded_optional_identifier_refuses_navigation_without_key() {
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["key == \"Enter\""],
                &["true"],
            )),
            navigation(),
        )
        .allowed
    );
}

#[test]
fn tool_guard_allows_navigation_without_key() {
    assert!(
        decide(
            Some(policy(
                PolicyMode::Enforce,
                &["tool.name == \"computer_key\" && key == \"Enter\""],
                &["true"],
            )),
            navigation(),
        )
        .allowed
    );
}

#[test]
fn guarded_rule_still_refuses_its_keypress() {
    let mut input = navigation();
    input.tool.name = "computer_key".to_owned();
    input.intent = Some(Intent::Activate);
    input.key = Some("Enter".to_owned());
    input.element = Some(ElementRef {
        reference: "e1".to_owned(),
        role: "textbox".to_owned(),
        name: "E-mail address:".to_owned(),
        kind: None,
    });
    assert!(
        !decide(
            Some(policy(
                PolicyMode::Enforce,
                &["tool.name == \"computer_key\" && key == \"Enter\""],
                &["true"],
            )),
            input,
        )
        .allowed
    );
}

#[test]
fn refused_mcp_call_names_tool_and_server_not_neutral_file() {
    let mut input = context();
    input.tool.name = "mcp__notes__search_notes".to_owned();
    input.page = PageRef {
        url: String::new(),
        host: String::new(),
    };
    input.element = Some(ElementRef {
        reference: String::new(),
        role: String::new(),
        name: String::new(),
        kind: Some(String::new()),
    });
    input.key = Some(String::new());
    input.file = Some(FileRef {
        path: String::new(),
        name: String::new(),
        extension: String::new(),
    });
    input.mcp = Some(McpRef {
        server: "notes".to_owned(),
        tool: "search_notes".to_owned(),
        effect: McpEffect::Read,
    });
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["mcp.server == \"notes\""],
            &["true"],
        )),
        input,
    );
    assert_eq!(
        decision.refusal,
        Some(Refusal::Mcp {
            server: "notes".to_owned(),
            tool: "search_notes".to_owned(),
        })
    );
}

#[test]
fn refused_file_action_still_names_file() {
    let mut input = context();
    input.tool.name = "computer_read_file".to_owned();
    input.file = Some(FileRef {
        path: "/workspace/secrets.env".to_owned(),
        name: "secrets.env".to_owned(),
        extension: "env".to_owned(),
    });
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["contains(file.path, \"secrets\")"],
            &["true"],
        )),
        input,
    );
    assert_eq!(
        decision.refusal,
        Some(Refusal::File {
            path: "/workspace/secrets.env".to_owned(),
        })
    );
}

fn command_context(command: &str) -> PolicyContext {
    let mut input = context();
    input.tool.name = "computer_run_command".to_owned();
    input.bot.id = "general-assistant".to_owned();
    input.page = PageRef {
        url: String::new(),
        host: String::new(),
    };
    input.intent = Some(Intent::RunCommand);
    input.command = Some(command.to_owned());
    input.element = Some(ElementRef {
        reference: String::new(),
        role: String::new(),
        name: String::new(),
        kind: Some(String::new()),
    });
    input.key = Some(String::new());
    input
}

#[test]
fn deployment_can_refuse_shell_outright() {
    let decision = decide(
        Some(policy(
            PolicyMode::Enforce,
            &["intent == \"run_command\""],
            &["true"],
        )),
        command_context("apt-get install -y jq"),
    );
    assert!(!decision.allowed);
    assert_eq!(
        decision.matched.as_deref(),
        Some("intent == \"run_command\"")
    );
}

#[test]
fn command_rule_can_name_what_command_says() {
    let boundary = policy(
        PolicyMode::Enforce,
        &["contains(command, \"rm -rf\")"],
        &["true"],
    );
    assert!(!decide(Some(boundary.clone()), command_context("rm -rf /")).allowed);
    assert!(decide(Some(boundary), command_context("ls -la")).allowed);
}

#[test]
fn commands_are_allowed_when_nothing_refuses_them() {
    assert!(decide(Some(permissive()), command_context("echo hello")).allowed);
}

#[test]
fn browser_rule_does_not_refuse_command_with_neutral_fields() {
    assert!(
        decide(
            Some(policy(
                PolicyMode::Enforce,
                &["contains(element.name, \"submit\") || key == \"Enter\""],
                &["true"],
            )),
            command_context("echo hello"),
        )
        .allowed
    );
}
