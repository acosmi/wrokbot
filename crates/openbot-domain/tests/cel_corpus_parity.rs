//! T-FIX-0005 —— CEL corpus golden 对照（v3 §8.3）。
//!
//! # 判据不是"全都一样"，是"分歧恰好等于台账"
//!
//! 两个引擎注定不一致：`cel-js@0.8.2` 没有任何字符串方法、`||` 完全不短路，标准 CEL 两样都有
//! （`fixtures/policy/cel-corpus.json` 的 `measured_findings` F-CEL-1 / F-CEL-3）。所以"全绿 =
//! 逐条相同"是一个永远达不到、达到了反而说明测试没跑的目标。
//!
//! 本文件把分歧集合本身钉成常量 [`DIVERGENCE_LEDGER`]：
//!
//! - **多一条分歧要红** —— 有一条既有规则的语义在没人知道的情况下翻转了。
//! - **少一条分歧也要红** —— `cel` 升了版本、改了行为，同样需要有人来看。上一条如果单独存在，
//!   一次"顺手升依赖"就能悄悄把差异抹平，而抹平的方向可能正是放宽。
//!
//! # 为什么还要断言 fixture 自己的 recount
//!
//! 台账钉的是"哪几条不一样"，recount 钉的是"一共跑了多少条"。只有前者的话，把 corpus 删到只
//! 剩那 6 条分歧，本文件照样全绿。recount 的四个数字直接取自 corpus 的 `recount` 段（那是
//! fixture 自带的可复算口径），fixture 被人动过就会红。
//!
//! # 上下文为什么手工读而不是 `derive(Deserialize)`
//!
//! [`PolicyContext`] 刻意不实现 `Deserialize`（理由见 `openbot_domain::policy::context` 的模块
//! 文档：能从字节铸造上下文，就等于能从请求体里指定"我正在点的是哪个元素"）。于是本文件自己
//! 读 —— 并且读完立刻**序列化回去与 fixture 逐字段比对**
//! （[`every_context_round_trips_through_the_domain_type`]）。那条往返比对同时钉住两件事：
//! 读的时候没丢字段，以及可选字段的"缺席"在序列化侧被原样保留（F-CEL-4 的核心）。

use std::collections::BTreeMap;
use std::path::PathBuf;

use openbot_domain::policy::CompiledRule;
use openbot_domain::policy::cel::ResultKind;
use openbot_domain::policy::context::{
    ActorRef, BotRef, ElementRef, FileRef, Intent, McpEffect, McpRef, PageRef, PolicyContext,
    ToolRef,
};
use openbot_domain::policy::preflight::{
    self, MigrationEffect, PreflightCase, PreflightRule, PreflightSample,
};
use serde_json::{Map, Value};

/// corpus 钉的上游提交。fixture 换了上游快照而没人重跑对照，这里当场红。
const PINNED_UPSTREAM_COMMIT: &str = "891df72f1827454d8b353d108fe5dd2313b7e30d";

/// 台账：本引擎与 oracle 的**全部**分歧。
///
/// 每一行都是本轮在本机实跑 `cargo test -p openbot-domain --test cel_corpus_parity` 得到的，
/// 不是从方案文档抄的。归因列指向 corpus 的 `measured_findings` 条目。
struct LedgerRow {
    /// corpus 的 `entries[].id`。
    entry_id: &'static str,
    /// oracle（`cel-js@0.8.2`）的结果类别。
    oracle: ResultKind,
    /// 本引擎（`cel 0.14.3`，`default-features = false`）的结果类别。
    candidate: ResultKind,
    /// 归因：corpus `measured_findings` 里的哪一条。
    finding: &'static str,
    /// 这条分歧写在 deny 表上的后果。
    deny_side: MigrationEffect,
    /// 这条分歧写在 allow 表上的后果。
    allow_side: MigrationEffect,
}

/// **恰 6 条。**
///
/// 三条 F-CEL-1（cel-js 没有字符串方法，而 `cel` 有内建且大小写敏感）+ 三条 F-CEL-3
/// （标准 CEL 的 `&&` / `||` 对错误有交换律吸收，cel-js 没有）。
///
/// `method-form-matches` **不在**表里：关掉 `cel` 的 `regex` feature 之后它没有内建方法，
/// 落到本仓注册的全局 `matches` 上只带一个实参，报实参个数错 —— 与 oracle 同为 `error`。
/// 那正是 workspace 根 `Cargo.toml` 里 `default-features = false` 那条裁决买到的东西。
const DIVERGENCE_LEDGER: [LedgerRow; 6] = [
    LedgerRow {
        entry_id: "method-form-contains",
        oracle: ResultKind::Error,
        candidate: ResultKind::False,
        finding: "F-CEL-1",
        deny_side: MigrationEffect::Loosened,
        allow_side: MigrationEffect::Unchanged,
    },
    LedgerRow {
        entry_id: "method-form-startswith",
        oracle: ResultKind::Error,
        candidate: ResultKind::True,
        finding: "F-CEL-1",
        deny_side: MigrationEffect::Unchanged,
        allow_side: MigrationEffect::Loosened,
    },
    LedgerRow {
        entry_id: "method-form-endswith",
        oracle: ResultKind::Error,
        candidate: ResultKind::True,
        finding: "F-CEL-1",
        deny_side: MigrationEffect::Unchanged,
        allow_side: MigrationEffect::Loosened,
    },
    LedgerRow {
        entry_id: "and-no-reverse-shortcircuit",
        oracle: ResultKind::Error,
        candidate: ResultKind::False,
        finding: "F-CEL-3",
        deny_side: MigrationEffect::Loosened,
        allow_side: MigrationEffect::Unchanged,
    },
    LedgerRow {
        entry_id: "or-no-shortcircuit-left-true",
        oracle: ResultKind::Error,
        candidate: ResultKind::True,
        finding: "F-CEL-3",
        deny_side: MigrationEffect::Unchanged,
        allow_side: MigrationEffect::Loosened,
    },
    LedgerRow {
        entry_id: "or-no-shortcircuit-right-true",
        oracle: ResultKind::Error,
        candidate: ResultKind::True,
        finding: "F-CEL-3",
        deny_side: MigrationEffect::Unchanged,
        allow_side: MigrationEffect::Loosened,
    },
];

/// corpus 的路径。用 `CARGO_MANIFEST_DIR` 往上拼，不写绝对路径 —— 绝对路径会让这条测试
/// 只在写它的那台机器上有意义。
fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/policy/cel-corpus.json")
}

fn corpus() -> Value {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} 不是合法 JSON：{error}", path.display()))
}

// ---------------------------------------------------------------------------
// fixture -> 领域类型：显式、严格、丢字段就 panic
// ---------------------------------------------------------------------------

fn object<'a>(value: &'a Value, path: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{path} 必须是对象，实得 {value}"))
}

/// 拒绝任何不在清单里的键。
///
/// 没有这条，fixture 里新增一个字段会被静默忽略 —— 而"静默忽略一个新字段"正是让 Rust 侧与
/// 上游语义悄悄分家的那条路。
fn reject_unknown_keys(map: &Map<String, Value>, allowed: &[&str], path: &str) {
    for key in map.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "{path} 出现未知字段 {key:?}；fixture 变了就必须同 PR 改这里的读取器与领域类型"
        );
    }
}

fn required_string(map: &Map<String, Value>, key: &str, path: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{path}.{key} 必须是字符串"))
        .to_string()
}

fn optional_string(map: &Map<String, Value>, key: &str, path: &str) -> Option<String> {
    map.get(key).map(|value| {
        value
            .as_str()
            .unwrap_or_else(|| panic!("{path}.{key} 若在场必须是字符串"))
            .to_string()
    })
}

fn read_context(name: &str, value: &Value) -> PolicyContext {
    let root = object(value, name);
    reject_unknown_keys(
        root,
        &[
            "tool", "bot", "page", "actor", "element", "key", "intent", "file", "mcp", "command",
        ],
        name,
    );

    let tool = object(&root["tool"], &format!("{name}.tool"));
    reject_unknown_keys(tool, &["name"], &format!("{name}.tool"));
    let bot = object(&root["bot"], &format!("{name}.bot"));
    reject_unknown_keys(bot, &["id"], &format!("{name}.bot"));
    let page = object(&root["page"], &format!("{name}.page"));
    reject_unknown_keys(page, &["url", "host"], &format!("{name}.page"));
    let actor = object(&root["actor"], &format!("{name}.actor"));
    reject_unknown_keys(actor, &["id"], &format!("{name}.actor"));

    let element = root.get("element").map(|value| {
        let path = format!("{name}.element");
        let map = object(value, &path);
        reject_unknown_keys(map, &["ref", "role", "name", "type"], &path);
        ElementRef {
            reference: required_string(map, "ref", &path),
            role: required_string(map, "role", &path),
            name: required_string(map, "name", &path),
            kind: optional_string(map, "type", &path),
        }
    });

    let file = root.get("file").map(|value| {
        let path = format!("{name}.file");
        let map = object(value, &path);
        reject_unknown_keys(map, &["path", "name", "extension"], &path);
        FileRef {
            path: required_string(map, "path", &path),
            name: required_string(map, "name", &path),
            extension: required_string(map, "extension", &path),
        }
    });

    let mcp = root.get("mcp").map(|value| {
        let path = format!("{name}.mcp");
        let map = object(value, &path);
        reject_unknown_keys(map, &["server", "tool", "effect"], &path);
        let effect = required_string(map, "effect", &path);
        McpRef {
            server: required_string(map, "server", &path),
            tool: required_string(map, "tool", &path),
            effect: effect
                .parse::<McpEffect>()
                .unwrap_or_else(|_| panic!("{path}.effect 不在封闭词表里：{effect:?}")),
        }
    });

    let intent = optional_string(root, "intent", name).map(|value| {
        value
            .parse::<Intent>()
            .unwrap_or_else(|_| panic!("{name}.intent 不在封闭词表里：{value:?}"))
    });

    PolicyContext {
        tool: ToolRef {
            name: required_string(tool, "name", &format!("{name}.tool")),
        },
        bot: BotRef {
            id: required_string(bot, "id", &format!("{name}.bot")),
        },
        page: PageRef {
            url: required_string(page, "url", &format!("{name}.page")),
            host: required_string(page, "host", &format!("{name}.page")),
        },
        actor: ActorRef {
            id: required_string(actor, "id", &format!("{name}.actor")),
        },
        element,
        key: optional_string(root, "key", name),
        intent,
        file,
        mcp,
        command: optional_string(root, "command", name),
    }
}

fn read_all_contexts(corpus: &Value) -> BTreeMap<String, PolicyContext> {
    object(&corpus["contexts"], "contexts")
        .iter()
        .map(|(name, value)| (name.clone(), read_context(name, value)))
        .collect()
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

/// corpus 自带的 `recount` 数字仍然成立。
///
/// 四条判据逐条对应 fixture 的 `recount` 段（那里记的是可以在 shell 里用 `jq` 复算的命令）。
/// 这条测试的作用是：**fixture 被人动过就红**，于是"分歧恰好 6 条"不能靠删样本来达成。
#[test]
fn corpus_recount_still_holds() {
    let corpus = corpus();

    assert_eq!(corpus["schema"], "cel-corpus");
    assert_eq!(corpus["schema_version"], 1);
    assert_eq!(corpus["upstream_commit"], PINNED_UPSTREAM_COMMIT);
    assert_eq!(corpus["oracle"]["engine"], "cel-js");
    assert_eq!(corpus["oracle"]["version"], "0.8.2");
    assert_eq!(corpus["candidate"]["engine"], "cel");
    assert_eq!(corpus["candidate"]["version"], "0.14.3");

    let entries = corpus["entries"].as_array().expect("entries 是数组");
    assert_eq!(entries.len(), 69, "entries 计数");

    let contexts = object(&corpus["contexts"], "contexts");
    assert_eq!(contexts.len(), 21, "contexts 计数");

    let divergence_group = entries
        .iter()
        .filter(|entry| entry["group"] == "engine-divergence")
        .count();
    assert_eq!(divergence_group, 8, "engine-divergence 组计数");

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in entries {
        let class = entry["result_class"]
            .as_str()
            .expect("result_class 是字符串");
        *counts.entry(class).or_default() += 1;
    }
    assert_eq!(
        counts.get("true").copied(),
        Some(35),
        "result_class=true 计数"
    );
    assert_eq!(
        counts.get("false").copied(),
        Some(15),
        "result_class=false 计数"
    );
    assert_eq!(
        counts.get("error").copied(),
        Some(19),
        "result_class=error 计数"
    );
    assert_eq!(counts.len(), 3, "result_class 词表恰三个取值");

    // 词表本身也钉住：多一个取值意味着 ResultKind 需要跟着扩。
    let vocabulary = corpus["result_class_vocabulary"]["values"]
        .as_array()
        .expect("词表是数组");
    let vocabulary: Vec<&str> = vocabulary
        .iter()
        .map(|v| v.as_str().expect("字符串"))
        .collect();
    assert_eq!(vocabulary, ["true", "false", "error"]);
}

/// 21 份上下文都能读进领域类型，**并且原样序列化回去**。
///
/// 往返比对是这条测试的全部力量所在：
///
/// - 正向：`mcp_search_notes` 这种"字段全在场但全是空串"的上下文必须原样保留空串。
/// - 负向：`navigate_httpbin` 这种"根本没有 key"的上下文必须**不长出** `"key": null`
///   —— 那正是 `skip_serializing_if` 在守的东西，少了它 `key == "Enter"` 会从 `error`
///   变成 `false`，deny 规则由拒绝变放行。
///
/// 两种形态都在 21 份里，所以这条测试同时带着正反两个对照。
#[test]
fn every_context_round_trips_through_the_domain_type() {
    let corpus = corpus();
    let raw_contexts = object(&corpus["contexts"], "contexts");

    let mut saw_present_but_empty = false;
    let mut saw_absent = false;

    for (name, raw) in raw_contexts {
        let parsed = read_context(name, raw);
        let reserialized = serde_json::to_value(&parsed)
            .unwrap_or_else(|error| panic!("{name} 序列化失败：{error}"));
        assert_eq!(&reserialized, raw, "{name} 往返之后与 fixture 不逐字段相等");

        let map = object(raw, name);
        if map.get("key").and_then(Value::as_str) == Some("") {
            saw_present_but_empty = true;
        }
        if !map.contains_key("key") {
            saw_absent = true;
        }
    }

    assert!(
        saw_present_but_empty,
        "corpus 里必须有『字段在场且为空』的上下文，否则本测试测不到那半边"
    );
    assert!(
        saw_absent,
        "corpus 里必须有『字段根本不在场』的上下文，否则本测试测不到另外那半边"
    );
}

/// 69 条逐条求值，分歧集合必须**恰好等于**台账。
#[test]
fn divergences_are_exactly_the_recorded_ledger() {
    let corpus = corpus();
    let contexts = read_all_contexts(&corpus);
    let entries = corpus["entries"].as_array().expect("entries 是数组");

    let mut observed: BTreeMap<String, (ResultKind, ResultKind)> = BTreeMap::new();
    let mut evaluated = 0usize;

    for entry in entries {
        let id = entry["id"].as_str().expect("id 是字符串");
        let expression = entry["expression"].as_str().expect("expression 是字符串");
        let context_name = entry["context"].as_str().expect("context 是字符串");
        let oracle: ResultKind = entry["result_class"]
            .as_str()
            .expect("result_class 是字符串")
            .parse()
            .unwrap_or_else(|_| panic!("{id} 的 result_class 不在词表里"));
        let context = contexts
            .get(context_name)
            .unwrap_or_else(|| panic!("{id} 引用了不存在的 context {context_name:?}"));

        let candidate = match openbot_domain::policy::cel::compile(expression) {
            Ok(compiled) => compiled.evaluate(context).kind(),
            Err(_) => ResultKind::Error,
        };
        evaluated += 1;

        if candidate != oracle {
            observed.insert(id.to_string(), (oracle, candidate));
        }
    }

    assert_eq!(evaluated, 69, "必须逐条跑完 69 条，不许跳过");

    let expected: BTreeMap<String, (ResultKind, ResultKind)> = DIVERGENCE_LEDGER
        .iter()
        .map(|row| (row.entry_id.to_string(), (row.oracle, row.candidate)))
        .collect();

    assert_eq!(
        observed, expected,
        "分歧集合必须恰好等于台账。多一条 = 有既有规则的语义悄悄翻转了；\
         少一条 = cel 改了行为，同样需要有人来看（很可能是往放宽的方向）"
    );

    // 台账自身的一致性：6 条、id 两两不同、每条都指向一个真实的 finding。
    assert_eq!(DIVERGENCE_LEDGER.len(), 6);
    let mut ids: Vec<&str> = DIVERGENCE_LEDGER.iter().map(|row| row.entry_id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), DIVERGENCE_LEDGER.len(), "台账 id 必须两两不同");

    let findings = corpus["measured_findings"]
        .as_array()
        .expect("measured_findings 是数组");
    for row in &DIVERGENCE_LEDGER {
        assert!(
            findings.iter().any(|finding| finding["id"] == row.finding),
            "台账里 {} 的归因 {} 在 corpus 的 measured_findings 里不存在",
            row.entry_id,
            row.finding
        );
    }
}

/// `method-form-matches` 与 oracle 同类 —— 这是关掉 `cel` 的 `regex` feature 买到的东西。
///
/// 单列一条而不是让它默默落在"其余 63 条同类"里：它是 workspace 根 `Cargo.toml` 那条
/// `default-features = false` 裁决的**唯一**可观察证据。谁把 feature 打开，这条当场红，
/// 而不是让台账在下一次全量跑时莫名多出一行。
#[test]
fn disabling_the_regex_feature_keeps_method_form_matches_in_the_error_class() {
    let corpus = corpus();
    let contexts = read_all_contexts(&corpus);
    let entry = corpus["entries"]
        .as_array()
        .expect("entries 是数组")
        .iter()
        .find(|entry| entry["id"] == "method-form-matches")
        .expect("corpus 必须有 method-form-matches");

    let context = contexts
        .get(entry["context"].as_str().expect("context 是字符串"))
        .expect("context 必须存在");
    let compiled =
        openbot_domain::policy::cel::compile(entry["expression"].as_str().expect("expression"))
            .expect("这条表达式语法合法");

    assert_eq!(entry["result_class"], "error", "oracle 侧就是 error");
    assert_eq!(compiled.evaluate(context).kind(), ResultKind::Error);
    // 正向对照：全局形式在同一份上下文上**确实**答得出布尔，所以上面那个 error
    // 不是因为 matches 整个不可用。
    let global_form = openbot_domain::policy::cel::compile("matches(element.name, \"sub.*\")")
        .expect("全局形式语法合法");
    assert_eq!(global_form.evaluate(context).kind(), ResultKind::True);
}

/// 迁移 preflight 把这 6 条全部标成需要确认，并且逐条给出两张表上的后果。
#[test]
fn preflight_flags_every_ledger_row_with_its_direction() {
    let corpus = corpus();
    let contexts = read_all_contexts(&corpus);
    let entries = corpus["entries"].as_array().expect("entries 是数组");

    let cases: Vec<PreflightCase<'_>> = entries
        .iter()
        .map(|entry| {
            let context_name = entry["context"].as_str().expect("context 是字符串");
            PreflightCase {
                entry_id: entry["id"].as_str().expect("id 是字符串"),
                expression: entry["expression"].as_str().expect("expression 是字符串"),
                context_name,
                context: contexts.get(context_name).expect("context 必须存在"),
                oracle: entry["result_class"]
                    .as_str()
                    .expect("result_class 是字符串")
                    .parse()
                    .expect("result_class 在词表内"),
            }
        })
        .collect();

    let report = preflight::run(&cases);

    assert!(
        report.requires_operator_confirmation(),
        "有分歧就必须要人确认"
    );
    assert!(
        report.would_loosen(),
        "这 6 条里有放宽项，报告必须敢说出来 —— 收紧会被用户当场发现，放宽不会"
    );
    assert_eq!(report.divergences().len(), DIVERGENCE_LEDGER.len());
    assert_eq!(
        report.agreements().len(),
        69 - DIVERGENCE_LEDGER.len(),
        "一致项也要留在报告里，否则回答不了『另外那些跑过了吗』"
    );

    for row in &DIVERGENCE_LEDGER {
        let divergence = report
            .divergences()
            .iter()
            .find(|divergence| divergence.entry_id == row.entry_id)
            .unwrap_or_else(|| panic!("台账里的 {} 没有出现在 preflight 报告里", row.entry_id));

        assert_eq!(
            divergence.oracle, row.oracle,
            "{} 的 oracle 类别",
            row.entry_id
        );
        assert_eq!(
            divergence.candidate, row.candidate,
            "{} 的本引擎类别",
            row.entry_id
        );
        assert_eq!(
            divergence.deny_side, row.deny_side,
            "{} 的 deny 侧后果",
            row.entry_id
        );
        assert_eq!(
            divergence.allow_side, row.allow_side,
            "{} 的 allow 侧后果",
            row.entry_id
        );
        assert!(
            !divergence.expression.is_empty(),
            "报告必须带规则原文供人定位"
        );
        assert!(
            !divergence.context_name.is_empty(),
            "报告必须说明是哪种动作形态"
        );
    }

    // 6 条里，deny 侧放宽 2 条、allow 侧放宽 4 条 —— 这两个数字本身就是"要盯哪几条"的口径。
    let deny_loosened = report
        .divergences()
        .iter()
        .filter(|divergence| divergence.deny_side == MigrationEffect::Loosened)
        .count();
    let allow_loosened = report
        .divergences()
        .iter()
        .filter(|divergence| divergence.allow_side == MigrationEffect::Loosened)
        .count();
    assert_eq!(deny_loosened, 2);
    assert_eq!(allow_loosened, 4);
    assert_eq!(report.loosening_divergences().len(), 6);

    // 负向对照：一致项里**没有**任何一条被标成分歧，所以上面那些计数不是靠"什么都算分歧"
    // 凑出来的。
    for agreement in report.agreements() {
        assert!(
            !DIVERGENCE_LEDGER
                .iter()
                .any(|row| row.entry_id == agreement.entry_id),
            "{} 既在一致项里又在台账里",
            agreement.entry_id
        );
    }
}

/// compile-once 路径与逐条编译路径在**真实的 69 条样本**上逐字段相等。
///
/// # 这条测的是"复用编译不改变答案"，顺带把编译次数摆成可读的算术
///
/// corpus 的 69 条样本只有 **51 条互不相同的表达式**（多条 preset 在不同 context 上各出现一次），
/// 所以：
///
/// - `preflight::run` 编译 **69** 次（每条样本一次）；
/// - `preflight::run_compiled` 自己**一次都不编译**，编译由本测试亲手做 **51** 次
///   （`rules` 这个 `Vec` 的长度就是次数，不必相信实现）。
///
/// 真实迁移比这更悬殊：N 条已持久化规则要在 M 个 corpus context 上各跑一遍，逐条路径是 N×M，
/// 复用路径仍是 N。
///
/// 正向对照：两份报告都必须**非空且同时含一致项与分歧项**（下面的 `assert!`）——否则两个空
/// 报告也相等，这条测试就什么都没测。
#[test]
fn both_preflight_paths_agree_on_the_whole_corpus() {
    let corpus = corpus();
    let contexts = read_all_contexts(&corpus);
    let entries = corpus["entries"].as_array().expect("entries 是数组");

    // 按表达式分组，保持首次出现的次序 —— 两条路径的报告顺序要一致，就得让摊平后的样本
    // 次序与分组次序相同（见 `preflight::run_compiled` 的文档）。
    let mut order: Vec<&str> = Vec::new();
    let mut grouped: BTreeMap<&str, Vec<PreflightSample<'_>>> = BTreeMap::new();
    for entry in entries {
        let expression = entry["expression"].as_str().expect("expression 是字符串");
        let context_name = entry["context"].as_str().expect("context 是字符串");
        if !grouped.contains_key(expression) {
            order.push(expression);
        }
        grouped
            .entry(expression)
            .or_default()
            .push(PreflightSample {
                entry_id: entry["id"].as_str().expect("id 是字符串"),
                context_name,
                context: contexts.get(context_name).expect("context 必须存在"),
                oracle: entry["result_class"]
                    .as_str()
                    .expect("result_class 是字符串")
                    .parse()
                    .expect("result_class 在词表内"),
            });
    }

    assert_eq!(
        order.len(),
        51,
        "corpus 的 69 条样本共用 51 条互不相同的表达式"
    );

    // 复用路径：本测试亲手编译 51 次。
    let rules: Vec<CompiledRule> = order
        .iter()
        .map(|expression| CompiledRule::compile(expression))
        .collect();
    assert_eq!(rules.len(), 51, "复用路径的编译次数 = 互不相同的表达式条数");

    let compiled_rules: Vec<PreflightRule<'_>> = order
        .iter()
        .zip(rules.iter())
        .map(|(expression, rule)| PreflightRule {
            rule,
            samples: grouped[expression].as_slice(),
        })
        .collect();

    // 逐条路径：同一批样本按同样的分组次序摊平，于是它编译 69 次。
    let flat_cases: Vec<PreflightCase<'_>> = order
        .iter()
        .flat_map(|expression| {
            grouped[expression].iter().map(move |sample| PreflightCase {
                entry_id: sample.entry_id,
                expression,
                context_name: sample.context_name,
                context: sample.context,
                oracle: sample.oracle,
            })
        })
        .collect();
    assert_eq!(flat_cases.len(), 69, "逐条路径的编译次数 = 样本条数");
    assert!(rules.len() < flat_cases.len(), "51 < 69");

    let compiling_path = preflight::run(&flat_cases);
    let reusing_path = preflight::run_compiled(&compiled_rules);

    assert_eq!(
        compiling_path, reusing_path,
        "两条 preflight 路径必须逐字段相等（含顺序、规则原文与两侧后果）"
    );

    // 正向对照：报告确实两类都有，而且分歧仍然恰好是台账那 6 条。
    assert_eq!(reusing_path.divergences().len(), DIVERGENCE_LEDGER.len());
    assert_eq!(
        reusing_path.agreements().len(),
        69 - DIVERGENCE_LEDGER.len()
    );
    let mut observed: Vec<&str> = reusing_path
        .divergences()
        .iter()
        .map(|divergence| divergence.entry_id.as_str())
        .collect();
    observed.sort_unstable();
    let mut expected: Vec<&str> = DIVERGENCE_LEDGER.iter().map(|row| row.entry_id).collect();
    expected.sort_unstable();
    assert_eq!(observed, expected, "复用路径找到的分歧必须还是台账那 6 条");
}
