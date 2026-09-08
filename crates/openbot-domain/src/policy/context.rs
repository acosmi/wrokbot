//! [`PolicyContext`] —— 一条策略规则能够写在什么属性上。
//!
//! # 为什么这些字段是这些字段
//!
//! 逐条对应上游 `server/src/computer/policy.ts` 的 `PolicyContext` 类型。它不是"把手头有的
//! 东西都塞进去"，每一条都是上游注释里写明了理由的：
//!
//! - `element` **由 gateway 从服务端自己抓到的快照解析**，不取调用方声称在点什么。上游原话是
//!   「A policy that decides on an attacker-supplied label is decoration」—— 一条"不许点
//!   Submit"的规则，如果判据来自调用方自报的标签，改个名字就绕过去了。
//! - `key` 存在的理由是一次真实的绕过：点击"Submit order"被 deny 之后，agent 改按 Enter，
//!   订单照样提交，因为 context 里没有任何东西能区分两次按键。
//! - `intent` 与 `tool.name` 并存：`tool.name` 描述机制，`intent` 描述效果。一个按钮可以被
//!   点击、Enter、Space 三种方式激活，只写 `computer_click` 的规则只盖住其中一条路径。
//! - `file` / `mcp` 把路径、扩展名、server、tool、effect 拆成独立字段，理由同一条：逼管理员
//!   在 CEL 里对 `mcp__jira__editJiraIssue` 做字符串手术，等于保证规则第一次改名就悄悄失效。
//!
//! # 「存在且为空」必须区别于「不存在」（F-CEL-4）
//!
//! 这是本模块最容易被"顺手优化"掉的一条不变量。上游 gateway 给 MCP / command 形态的 context
//! **刻意塞满空串字段**（见 `fixtures/policy/cel-corpus.json` 的 `mcp_search_notes` /
//! `run_command_echo_neutral`），好让一条写给浏览器的规则求值成 `false` 而不是不可求值。
//! 与之相对，`navigate_httpbin` 这类 context **根本没有** `key`，于是 `key == "Enter"` 抛错。
//!
//! 两者在 policy 层的后果不同：`false` 是"这条规则不适用"，`error` 在 deny 侧是"拒绝"。所以
//! 每个 `Option` 字段都必须 `skip_serializing_if = "Option::is_none"` —— 少了它，缺席的字段
//! 会以 `null` 进入 CEL 上下文，`key == "Enter"` 从 `error` 变成 `false`，deny 规则由拒绝变
//! 放行。闸门是 `absent_optional_fields_do_not_reach_the_evaluator`，正向对照是同一条测试里
//! 「存在且为空的字段确实到达了求值器」。
//!
//! # 为什么本类型**不**实现 `Deserialize`
//!
//! 与 `openbot_contracts::auth::AuthContext` 同一条理由：能从字节铸造出一个 `PolicyContext`，
//! 就等于能从请求体里指定"我正在点的是哪个元素"，上面第一条不变量当场失效。构造点只能是
//! gateway 自己（快照解析 + 会话 + 工具调用参数）。封闭词表 [`Intent`] / [`McpEffect`] 实现
//! [`core::str::FromStr`]，那是**值**的解析，造出一个 `Intent::Activate` 并不能造出一份上下文。

use core::fmt;
use core::str::FromStr;

use serde::Serialize;

use super::cel::failure::CelFailure;

/// 被判定的那次动作的全部属性。
///
/// 字段的可选性逐条对应上游：`tool` / `bot` / `page` / `actor` 恒存在，其余按动作形态出现。
/// 可选字段的"缺席"是**语义**而不是省略，见模块文档。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyContext {
    /// 被调用的工具。描述**机制**。
    pub tool: ToolRef,
    /// 发起这次动作的 Bot。
    pub bot: BotRef,
    /// 动作发生时浏览器所在的页面。
    pub page: PageRef,
    /// 这次动作最终归属的人。
    pub actor: ActorRef,
    /// 被作用的页面元素，由服务端快照解析而来。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element: Option<ElementRef>,
    /// 即将被按下的键。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// 这次动作**做什么**，与 `tool` 的"用什么做"正交。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<Intent>,
    /// 被读写的工作区文件。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileRef>,
    /// 被调用的第三方 MCP server 与工具。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpRef>,
    /// 即将执行的命令**原文**。
    ///
    /// 原文是因为一条关于 shell 的规则只能写在真正被敲下去的字符串上。上游同时提醒：命令文本
    /// 匹配是过滤器不是边界 —— 边界是命令跑在哪个容器里。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// 工具身份。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolRef {
    /// 工具名，例如 `computer_click`、`mcp__notes__search_notes`。
    pub name: String,
}

/// Bot 身份。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BotRef {
    /// Bot id。
    pub id: String,
}

/// 页面身份。
///
/// `host` 单列而不是让规则自己从 `url` 里切：绝大多数边界写的是"我们自己的域之外"，逼管理员
/// 在 CEL 里做 URL 解析等于保证规则在第一个带端口或带子域的 URL 上出错。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PageRef {
    /// 完整 URL。
    pub url: String,
    /// 主机名。
    pub host: String,
}

/// 动作归属的人。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActorRef {
    /// actor id。
    pub id: String,
}

/// 页面元素。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElementRef {
    /// 快照里的元素引用。
    ///
    /// Rust 里 `ref` 是关键字，所以字段名是 `reference`，但**线上名字必须是 `ref`** ——
    /// 规则写的是 `element.ref == "e13"`，改名就是让所有既有规则失效。
    #[serde(rename = "ref")]
    pub reference: String,
    /// 可访问性角色，例如 `button` / `textbox`。
    pub role: String,
    /// 可访问名（按钮上的字）。
    pub name: String,
    /// 表单控件类型。**上游此字段本身可选**，所以它在这里也是 `Option`。
    ///
    /// 这不是可以拉平的多余一层：corpus 的 `probe-has-absent-field` 与
    /// `probe-absent-nested-field-read` 一对，正是在钉「element 存在但没有 type 键」这个状态
    /// —— `has(element.type)` 答 `false`，而 `element.type == "textbox"` 抛错。把它写成
    /// `String` 默认空串，两条都会变成别的答案。
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// 工作区文件。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileRef {
    /// Bot 请求的路径，相对于它的工作区。
    ///
    /// 越界路径由 computer 自己拒绝，不由策略负责 —— 上游原话「Containment is not policy」。
    /// 这里的规则说的是工作区**之内**哪些文件这个 Bot 可以碰。
    pub path: String,
    /// 文件名。
    pub name: String,
    /// 扩展名，**不带点、已小写**；无扩展名时为空串。
    pub extension: String,
}

/// 第三方 MCP server 与工具。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct McpRef {
    /// server 名。
    pub server: String,
    /// 工具名（不含 `mcp__<server>__` 前缀）。
    pub tool: String,
    /// 该工具改不改东西。
    pub effect: McpEffect,
}

/// 动作的效果类别。封闭词表，取值逐字取自上游联合类型。
///
/// 新增一个取值不是在这里加变体那么简单：它同时是既有规则的可写词汇，加进来就意味着一条
/// `intent == "…"` 的规则可能从不匹配变成匹配。所以扩表是一次带 ledger 条目的产品变更。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    /// 按下某个东西：点击，或 Enter / Space。
    Activate,
    /// 文本进入某个字段，以及其它按键。
    Type,
    /// 打开一个页面。
    Navigate,
    /// 看页面、列出页面上有什么。
    Read,
    /// 读工作区文件。
    ReadFile,
    /// 写工作区文件。
    WriteFile,
    /// 列工作区文件。
    ListFiles,
    /// 调用第三方 MCP 的只读工具。
    ReadTool,
    /// 调用第三方 MCP 的写工具。
    WriteTool,
    /// 在 computer 上执行命令。
    RunCommand,
}

impl Intent {
    /// 稳定的线上表示，与既有规则里的字面量逐字相同。
    ///
    /// 它是**标识符**不是文案：不随 locale 变化（repository contract §4a）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Type => "type",
            Self::Navigate => "navigate",
            Self::Read => "read",
            Self::ReadFile => "read_file",
            Self::WriteFile => "write_file",
            Self::ListFiles => "list_files",
            Self::ReadTool => "read_tool",
            Self::WriteTool => "write_tool",
            Self::RunCommand => "run_command",
        }
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析 [`Intent`] 失败。
///
/// 刻意报错而不是回落到某个"最像"的取值：一个拼错的 intent 静默变成另一个 intent，会让一条
/// deny 规则安静地不再匹配。调用方必须自己决定怎么处理，并且必须把它当故障记录。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown_intent")]
pub struct UnknownIntent;

impl FromStr for Intent {
    type Err = UnknownIntent;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "activate" => Ok(Self::Activate),
            "type" => Ok(Self::Type),
            "navigate" => Ok(Self::Navigate),
            "read" => Ok(Self::Read),
            "read_file" => Ok(Self::ReadFile),
            "write_file" => Ok(Self::WriteFile),
            "list_files" => Ok(Self::ListFiles),
            "read_tool" => Ok(Self::ReadTool),
            "write_tool" => Ok(Self::WriteTool),
            "run_command" => Ok(Self::RunCommand),
            _ => Err(UnknownIntent),
        }
    }
}

/// MCP 工具改不改东西。封闭词表。
///
/// 上游把判据写死为 fail-closed：**不能正面确定是只读的一律算写**。分类来源是 server 自报的
/// 目录与一份人工复核过的清单，不是工具名，也不是模型的声称。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpEffect {
    /// 只读。
    Read,
    /// 会改东西。
    Write,
}

impl McpEffect {
    /// 稳定的线上表示。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl fmt::Display for McpEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析 [`McpEffect`] 失败。
///
/// 同 [`UnknownIntent`]：不回落。这里回落尤其危险 —— 唯一"安全"的回落是 [`McpEffect::Write`]，
/// 而那会让一条 `mcp.effect == "read"` 的 allow 规则突然不再放行，看起来像功能坏了而不像
/// 数据坏了。让调用方显式处理。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown_mcp_effect")]
pub struct UnknownMcpEffect;

impl FromStr for McpEffect {
    type Err = UnknownMcpEffect;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(UnknownMcpEffect),
        }
    }
}

/// 把一份 [`PolicyContext`] 装进 CEL 求值上下文。
///
/// # 为什么装的是"顶层字段"而不是一个叫 `context` 的变量
///
/// 既有规则写的是 `element.name`、`page.host`、`key`，不是 `context.element.name`。变量名就是
/// 契约，包一层就是让所有已落库的规则同时失效。
///
/// # 为什么经 [`serde`] 而不是手写十次 `add_variable`
///
/// 手写会把「哪些字段可选」这条判据抄到第二个地方，而模块文档里那条不变量（缺席 ≠ 空）正是
/// 靠 `skip_serializing_if` 兑现的。走同一条序列化路径，可选性只有一个真源；
/// `absent_optional_fields_do_not_reach_the_evaluator` 才能真的守住它。
///
/// # Errors
///
/// [`PolicyContext`] 是纯字符串与封闭枚举的记录，序列化在构造上不会失败；但 `cel::to_value`
/// 的签名是 fallible，而领域层不 `unwrap`。真出现失败一律压成 [`CelFailure::Runtime`] ——
/// 它是本枚举唯一的兜底变体，且方向安全（deny 侧照拒、allow 侧不放行）。
pub fn bind_policy_context(
    context: &PolicyContext,
    target: &mut cel::Context<'_>,
) -> Result<(), CelFailure> {
    let value = cel::to_value(context).map_err(|_| CelFailure::Runtime)?;
    let cel::Value::Map(map) = value else {
        return Err(CelFailure::Runtime);
    };
    for (key, entry) in map.map.iter() {
        let cel::objects::Key::String(name) = key else {
            return Err(CelFailure::Runtime);
        };
        target.add_variable_from_value(name.as_str(), entry.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browsing_context() -> PolicyContext {
        PolicyContext {
            tool: ToolRef {
                name: "computer_click".to_string(),
            },
            bot: BotRef {
                id: "risk-analyst".to_string(),
            },
            page: PageRef {
                url: "https://example.com/order".to_string(),
                host: "example.com".to_string(),
            },
            actor: ActorRef {
                id: "dev-local-user".to_string(),
            },
            element: Some(ElementRef {
                reference: "e13".to_string(),
                role: "button".to_string(),
                name: "Submit order".to_string(),
                kind: None,
            }),
            key: None,
            intent: None,
            file: None,
            mcp: None,
            command: None,
        }
    }

    fn evaluate(source: &str, context: &PolicyContext) -> Result<cel::Value, cel::ExecutionError> {
        let program = cel::Program::compile(source).expect("测试表达式必须可解析");
        let mut cel_context = cel::Context::default();
        super::super::cel::globals::install(&mut cel_context);
        bind_policy_context(context, &mut cel_context).expect("绑定不应失败");
        program.execute(&cel_context)
    }

    /// 缺席的可选字段**根本不进求值器**，于是读它抛错而不是答 `false`。
    ///
    /// 正向对照在同一条测试里：把同一个字段设成**空串**，它就到达了求值器，
    /// `key == "Enter"` 答出真正的 `false`。没有这个对照，本测试在「所有字段都没进去」的
    /// 世界里同样通过 —— 那个世界里连 `page.host` 都读不到，功能压根不存在。
    #[test]
    fn absent_optional_fields_do_not_reach_the_evaluator() {
        let mut context = browsing_context();

        context.key = None;
        let absent = evaluate("key == \"Enter\"", &context);
        assert!(
            matches!(absent, Err(cel::ExecutionError::UndeclaredReference(_))),
            "缺席的 key 必须不可求值，实得 {absent:?}"
        );

        context.key = Some(String::new());
        let present_but_empty = evaluate("key == \"Enter\"", &context);
        assert_eq!(present_but_empty, Ok(cel::Value::Bool(false)));

        // 必存在字段确实进去了 —— 否则上面那条"抛错"只是因为什么都没绑。
        assert_eq!(
            evaluate("page.host == \"example.com\"", &context),
            Ok(cel::Value::Bool(true))
        );
    }

    /// 嵌套的可选字段同样区分"没有这一层"与"这一层是空串"。
    ///
    /// 这条对应 corpus 的 `probe-has-absent-field` / `probe-absent-nested-field-read` 一对。
    #[test]
    fn absent_nested_optional_fields_keep_the_same_distinction() {
        let mut context = browsing_context();

        assert_eq!(
            evaluate("has(element.name)", &context),
            Ok(cel::Value::Bool(true))
        );
        assert_eq!(
            evaluate("has(element.type)", &context),
            Ok(cel::Value::Bool(false))
        );
        assert!(
            matches!(
                evaluate("element.type == \"textbox\"", &context),
                Err(cel::ExecutionError::NoSuchKey(_))
            ),
            "element 存在但没有 type 键时，读它必须抛错"
        );

        context.element.as_mut().expect("上面刚设过").kind = Some(String::new());
        assert_eq!(
            evaluate("has(element.type)", &context),
            Ok(cel::Value::Bool(true))
        );
        assert_eq!(
            evaluate("element.type == \"textbox\"", &context),
            Ok(cel::Value::Bool(false))
        );
    }

    /// 线上字段名是契约：`ref` 与 `type` 不能因为 Rust 关键字而改名。
    #[test]
    fn wire_field_names_are_not_the_rust_field_names() {
        let context = browsing_context();
        assert_eq!(
            evaluate("element.ref == \"e13\"", &context),
            Ok(cel::Value::Bool(true))
        );
        // 负向对照：Rust 侧的字段名不应该出现在求值面上。
        assert!(matches!(
            evaluate("element.reference == \"e13\"", &context),
            Err(cel::ExecutionError::NoSuchKey(_))
        ));
    }

    /// 封闭词表的线上取值逐字对齐上游联合类型，`as_str` 与 serde 输出必须是同一个字符串。
    #[test]
    fn closed_vocabularies_serialize_to_their_stable_names() {
        let all = [
            Intent::Activate,
            Intent::Type,
            Intent::Navigate,
            Intent::Read,
            Intent::ReadFile,
            Intent::WriteFile,
            Intent::ListFiles,
            Intent::ReadTool,
            Intent::WriteTool,
            Intent::RunCommand,
        ];
        let expected = [
            "activate",
            "type",
            "navigate",
            "read",
            "read_file",
            "write_file",
            "list_files",
            "read_tool",
            "write_tool",
            "run_command",
        ];
        for (intent, name) in all.iter().zip(expected) {
            assert_eq!(intent.as_str(), name);
            assert_eq!(intent.to_string(), name);
            assert_eq!(Intent::from_str(name), Ok(*intent));
            assert_eq!(
                cel::to_value(intent).expect("封闭词表必然可序列化"),
                cel::Value::String(std::sync::Arc::new(name.to_string()))
            );
        }
        assert_eq!(Intent::from_str("activate "), Err(UnknownIntent));
        assert_eq!(Intent::from_str("Activate"), Err(UnknownIntent));

        for (effect, name) in [(McpEffect::Read, "read"), (McpEffect::Write, "write")] {
            assert_eq!(effect.as_str(), name);
            assert_eq!(effect.to_string(), name);
            assert_eq!(McpEffect::from_str(name), Ok(effect));
        }
        assert_eq!(McpEffect::from_str("readonly"), Err(UnknownMcpEffect));
    }

    /// `intent` 在 CEL 里就是一个字符串 —— 规则写的是 `intent == "activate"`，
    /// 不是某个结构化对象。
    #[test]
    fn intent_is_a_plain_string_on_the_evaluation_surface() {
        let mut context = browsing_context();
        context.intent = Some(Intent::Activate);
        assert_eq!(
            evaluate("intent == \"activate\"", &context),
            Ok(cel::Value::Bool(true))
        );
        assert_eq!(
            evaluate("intent == \"run_command\"", &context),
            Ok(cel::Value::Bool(false))
        );
    }
}
