//! `xtask test-inventory` —— 上游 105 个测试文件的 **AST 级** test inventory。
//!
//! # 为什么必须是 AST
//!
//! v3 §1.3 逐字写着"1,007 是词法命中，不冒充 AST 解析后的精确 test 数"，而 §24 G0 要求
//! "上游基线测试原始结果归档"、G8 要求"Phase 0 AST 级 test inventory mapping 100%"。
//! 词法 `grep -oE '\b(test|it)\('` 会把 `/secret/i.test(k)` 这种正则方法调用一并数进去
//! （本轮实测上游恰有 1 处），也照不到 `test.each([...])("标题", fn)` 这种柯里化写法
//! （本轮实测 41 处）。两个方向的偏差同时存在，所以词法数只能做交叉检查。
//!
//! # 解析器
//!
//! `oxc_parser` `0.146.0`（纯 Rust，配套 `oxc_allocator` / `oxc_ast` / `oxc_ast_visit` /
//! `oxc_span` 同版本）。选纯 Rust 而不是起 Node/Bun 子进程：v3 §3.5 已裁决删除 Bun launcher，
//! 把闸门的正确性系在一个本仓刻意不安装的运行时上等于把闸门交给环境。
//!
//! # fail-closed
//!
//! 三处刻意不容错，因为它们的失败形态都是"inventory 假装完整"：
//!
//! 1. 解析出任何 error 级诊断 → 整条命令退出，不静默跳过文件；
//! 2. 扫到的文件不在 [`FILE_RULES`] 里 → 退出，不给未分类项留缺口（v3 §21.1 条 4「未分类为 0」）；
//! 3. [`FILE_RULES`] 里有条目没被扫到（上游文件改名/删除）→ 退出。
//!
//! # 产物
//!
//! - `fixtures/tests/upstream-ast-inventory.json` —— 原始抽取结果，含行列号与 skip/only/each 标记，供复算；
//! - `parity/tests.yaml` —— 统一 parity ledger schema v1，一个 AST 用例一条 entry。
//!
//! 行号只进 JSON 机器产物，**不进** ledger 与文档正文（repository contract §8：位置引用只用符号名）。
//!
//! # 用法
//!
//! ```text
//! cargo xtask test-inventory --upstream <上游干净克隆路径>
//! cargo xtask test-inventory --upstream <路径> --dry-run     # 只打印统计，不写盘
//! ```

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression, TemplateLiteral};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 契约常量
// ---------------------------------------------------------------------------

/// v3 §1.2 固定源码基线。ledger 的 `upstream_commit` 与本值逐字符相等。
const UPSTREAM_COMMIT: &str = "891df72f1827454d8b353d108fe5dd2313b7e30d";

/// 解析器版本。与仓根 `Cargo.toml` 的 `[workspace.dependencies] oxc_parser` 同值，
/// 由 `tests::oxc_version_matches_workspace_manifest` 双向钉死 —— 写进产物的
/// “用 OXC_VERSION 解析”必须是真的，不能是注释里的旧值。
const OXC_VERSION: &str = "0.146.0";

/// v3 §1.3 的词法基线，只用于交叉检查（`§28.4` 的
/// `git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\b(test|it)\(' | wc -l`）。
const LEXICAL_TEST_HITS: usize = 1007;

/// v3 §1.3 的测试文件数。
const UPSTREAM_TEST_FILE_COUNT: usize = 105;

/// ledger 里 `test_id` 的前缀。`parity/tests.yaml` 独占 `T-TEST-`，与
/// `parity/routes.yaml` 的 `T-ROUTE-` 不相交（规则 5：test_id 全仓唯一）。
const TEST_ID_PREFIX: &str = "T-TEST-";

/// 被认作"用例声明"的根标识符。
///
/// 固定集合而不是启发式：任何一个新根（`suite` / `bench` / `xit` …）都必须同 PR 进这张表，
/// 否则 inventory 会静默漏掉一整类用例。本轮实测上游只用到 `describe` 与 `test`
/// （`git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\b(describe|test|it)(\.[a-zA-Z]+)*\('`
/// 得 `test(` 1007 / `describe(` 224 / `test.each(` 41 / `describe.skipIf(` 6，`it` 零命中），
/// `it` 保留在表里是为了让"上游哪天开始用 it"不成为盲区。
const CASE_ROOTS: [(&str, NodeKind); 3] = [
    ("describe", NodeKind::Describe),
    ("test", NodeKind::Test),
    ("it", NodeKind::Test),
];

/// 判为"跳过"的修饰符。`skipIf` / `todoIf` 是条件跳过，同样计入 `skip` 并额外标 `conditional`。
const SKIP_MODIFIERS: [&str; 4] = ["skip", "skipIf", "todo", "todoIf"];

/// 判为"独占"的修饰符。
const ONLY_MODIFIERS: [&str; 2] = ["only", "onlyIf"];

/// 判为"表驱动"的修饰符。
const EACH_MODIFIERS: [&str; 1] = ["each"];

/// 条件修饰符（跟着一个条件实参，本身不改变用例是不是用例）。
const CONDITIONAL_MODIFIERS: [&str; 4] = ["skipIf", "todoIf", "onlyIf", "runIf"];

// ---------------------------------------------------------------------------
// 迁移三档（v3 §21.1 条 4）
// ---------------------------------------------------------------------------

/// v3 §21.1 条 4 固定的三档，未分类为 0。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Tier {
    /// 判据逐条移植到 Rust 测试。
    Ported,
    /// 判据由 golden trace / fixture 对照覆盖，不做 1:1 移植。
    CoveredByGolden,
    /// 被测面在 Rust 版不存在，且有 v3 正文出处作为"证明"。
    NotApplicableWithProof,
}

impl Tier {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ported => "ported",
            Self::CoveredByGolden => "covered-by-golden",
            Self::NotApplicableWithProof => "not-applicable-with-proof",
        }
    }

    /// 三档到统一 schema v1 `migration_rule` 封闭前缀的映射。
    ///
    /// `migration_rule` 的域是 `preserve|rename|remove|n/a`（校验器规则），三档是 v3 §21.1 条 4
    /// 的域，两者不是同一个轴，所以这里显式映射而不是硬塞。冒号后缀带上原档名，让 ledger 里
    /// 能直接读到三档分类，不必回查本文件。
    fn migration_rule(self, label: Label) -> String {
        match self {
            Self::Ported if label == Label::Substitute => {
                "rename: ported —— 判据保留，承载它的机制在 Rust 版换了一个".to_string()
            }
            Self::Ported => "preserve: ported".to_string(),
            Self::CoveredByGolden => "preserve: covered-by-golden".to_string(),
            Self::NotApplicableWithProof => "remove: not-applicable-with-proof".to_string(),
        }
    }
}

/// repository contract §4〈parity 与新增必须分开标注〉的三值封闭域。
///
/// 本 ledger 里 **不会出现 `新增`**：每一条 entry 都由一个上游 AST 用例生成，按定义就有上游
/// 对应物。Rust 侧新起炉灶的测试不属于"上游测试 inventory"，登记在各自的立项文档里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    /// 被测行为在 Rust 版原样保留。
    Parity,
    /// 被测行为的承载机制在 Rust 版被换掉（含"被换成明确的不做"）。
    Substitute,
}

impl Label {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Parity => "parity",
            Self::Substitute => "替代",
        }
    }
}

// ---------------------------------------------------------------------------
// 105 个文件的分类表
// ---------------------------------------------------------------------------

/// 一个上游测试文件的迁移裁决。
///
/// **粒度说明（必须读）**：`tier` / `label` / `owner` / `target_module` 取**文件**粒度。
/// `label` 的取法是保守方向 —— 只要该文件的被测面在 v3 里有任一处换机制，整个文件标 `替代`，
/// 绝不把换了机制的东西写成 `parity`（repository contract §4：把新增/替代写成"当前行为"是最重的一类错误）。
/// 反方向的代价只是把若干条 parity 条目多标了一次 `替代`，进入 G8 逐条复核时会被收敛。
struct FileRule {
    /// 上游仓相对路径，必须与 `git ls-files '*.test.ts' '*.test.tsx'` 的输出逐字符相等。
    file: &'static str,
    /// v3 §5.1 十个 crate 之一。
    owner: &'static str,
    /// Rust 落点模块路径（不含 `::tests::<fn>` 尾巴，尾巴由用例标题派生）。
    target_module: &'static str,
    tier: Tier,
    label: Label,
    /// 裁决理由，必须指得出 v3 的章节号。会原样进 ledger 的 `notes`。
    reason: &'static str,
}

/// 105 行，与上游 `git ls-files '*.test.ts' '*.test.tsx'` 一一对应。
///
/// 缺一行或多一行都会让 [`run`] 直接失败（fail-closed），所以这张表不会悄悄落后于上游。
#[rustfmt::skip]
const FILE_RULES: [FileRule; UPSTREAM_TEST_FILE_COUNT] = [
    // --- agent-computer/tests（8）：v3 §10 隔离 + §11 browser engine + §12 screen -----
    FileRule { file: "agent-computer/tests/aria-snapshot.test.ts", owner: "openbot-computer", target_module: "openbot_computer::browser::aria", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §11.1 单一 engine / §11.2 Engine 协议：aria snapshot 解析是 engine 侧纯函数，判据逐条移植。" },
    FileRule { file: "agent-computer/tests/authorisation.test.ts", owner: "openbot-computer", target_module: "openbot_computer::manager::authorisation", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.3 Desktop 与 Server 安全表述：manager 侧共享密钥校验与未认证可达面逐条移植。" },
    FileRule { file: "agent-computer/tests/bot-id.test.ts", owner: "openbot-computer", target_module: "openbot_computer::identity::bot_id", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §10.1 明写 bot_id 不足以定界，Rust 侧隔离键换成 ComputerSecurityScope；id 合法性与 profile 目录派生的判据本身逐条移植。" },
    FileRule { file: "agent-computer/tests/browser-eviction.test.ts", owner: "openbot-computer", target_module: "openbot_computer::browser::eviction", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §11.3 Browser 安全配置：并发上限、闲置回收与运营方配额读取判据逐条移植。" },
    FileRule { file: "agent-computer/tests/control.test.ts", owner: "openbot-computer", target_module: "openbot_computer::screen::handover", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §12.5 Input / §12.4 Viewer ticket：take-the-wheel 的交接、双驾驶冲突与密钥不外泄判据逐条移植。" },
    FileRule { file: "agent-computer/tests/egress.test.ts", owner: "openbot-computer", target_module: "openbot_computer::egress", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.5 Network egress：代理变量命名、按 Bot 解析与对外展示面判据逐条移植。" },
    FileRule { file: "agent-computer/tests/shell.test.ts", owner: "openbot-computer", target_module: "openbot_computer::shell", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.1 唯一执行管线：命令继承什么、实际执行什么、不能对宿主做什么，判据逐条移植。" },
    FileRule { file: "agent-computer/tests/workspace.test.ts", owner: "openbot-computer", target_module: "openbot_computer::files::workspace", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.2 Engine 能看到什么：工作区内读写、列举与越界拒绝判据逐条移植。" },

    // --- agent-langgraph（1）：v3 §3.5 框架样例不进第一方生产仓 ------------------------
    FileRule { file: "agent-langgraph/tests/history.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::fixtures::remote_agent::langgraph", tier: Tier::CoveredByGolden, label: Label::Substitute,
        reason: "v3 §3.5 逐字：agent-langgraph 等框架样例不进入第一方生产仓代码，兼容性通过固定上游 container/trace fixture 验证，故转 golden 对照而非 1:1 移植。" },

    // --- app/src/components/channels/composer（2）：v3 §13.1 GUI --------------------
    FileRule { file: "app/src/components/channels/composer/draft.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::channels::composer::draft", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §13.1 GUI：草稿构造、单 Agent 约束与命令 chip 应用是纯状态函数，判据逐条移植。" },
    FileRule { file: "app/src/components/channels/composer/queue.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::channels::composer::queue", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §13.1 GUI：发送队列的提交/落定/移除是纯状态函数，判据逐条移植。" },

    // --- app/tests（18）：v3 §13 Tauri/Leptos ---------------------------------------
    FileRule { file: "app/tests/agents.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::coworkers", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §13.2 typed in-process transport 取代 TanStack Query 的 query key 体系（key 相等性判据在 Rust 侧无对应物）；coworker 表单校验判据逐条移植。" },
    FileRule { file: "app/tests/audit-silence.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::audit::stalled_turn", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.6 Audit：停滞回合在审计页留下什么，判据逐条移植。" },
    FileRule { file: "app/tests/auth-client.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::auth::client", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §6.2 必须实现的认证面：Better Auth 客户端被 Rust 自建认证面取代；登录入口与 provider 显示名判据逐条移植。" },
    FileRule { file: "app/tests/auth-queries.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::auth::queries", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §13.2：query key 稳定性是 TanStack Query 的机制属性，Leptos + typed in-process 侧无对应物；当前用户读取语义逐条移植。" },
    FileRule { file: "app/tests/bot-thread.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::threads::bot_thread", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §13.2：botThreadKey 是 query key（换机制）；threadToUse 的线程选择判据逐条移植。" },
    FileRule { file: "app/tests/compose-state.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::channels::compose_state", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §13.1 GUI：收件人增删与可发送判据是纯状态函数，逐条移植。" },
    FileRule { file: "app/tests/computer-activity.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::computer::activity", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.3 Generative UI：调用输出的读取与活动面板呈现判据逐条移植。" },
    FileRule { file: "app/tests/credential-form.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::credentials::form", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.4 Vault：必填四项（类型/供应商/key id/密文）的校验规则不变，zod 换成 Rust 校验器不改变判据。" },
    FileRule { file: "app/tests/new-id.test.ts", owner: "openbot-contracts", target_module: "openbot_contracts::ids::mint", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §5.3：ID 是 string newtype，创建端可用 UUIDv7/ULID、兼容端必须接受上游既有字符串；铸造函数的唯一性与形态判据逐条移植。" },
    FileRule { file: "app/tests/query-client.test.ts", owner: "openbot-ui", target_module: "openbot_ui::data::client", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §13.2：TanStack QueryClient 的默认重试配置在 Leptos + typed in-process transport 下无对应物，判据搬到 Rust 侧的请求重试策略。" },
    FileRule { file: "app/tests/repair-history.test.ts", owner: "openbot-domain", target_module: "openbot_domain::agent::history_repair", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.2 Agent reducer：未应答 tool call 的历史修复是 reducer 前置不变量，落在 domain，判据逐条移植。" },
    FileRule { file: "app/tests/router.test.ts", owner: "openbot-ui", target_module: "openbot_ui::shell::router", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §13.1：TanStack Router 生成路由表换成 leptos_router；路由存在性与 fullPath 判据搬到 parity/routes.yaml 的同一批 31 条落点上。" },
    FileRule { file: "app/tests/stopped-turn.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::threads::stopped_turn", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.4 Retry、Cancel、Budget 与 Commit：回合结束原因的呈现判据逐条移植。" },
    FileRule { file: "app/tests/take-the-wheel.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::computer::take_the_wheel", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §12.5 Input：页面坐标换算是纯几何函数，判据逐条移植。" },
    FileRule { file: "app/tests/theme-preference.test.ts", owner: "openbot-ui", target_module: "openbot_ui::theme", tier: Tier::Ported, label: Label::Substitute,
        reason: "设计系统文档 §17 记录上游主题不跟随系统（prefers-color-scheme 零命中），Rust 侧主题是三态（含 system），故偏好读写语义换了一个；两态之间的持久化判据逐条移植。" },
    FileRule { file: "app/tests/tool-name.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::threads::tool_name", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.2 Tool metadata：工具调用显示名派生判据逐条移植。" },
    FileRule { file: "app/tests/tool-result.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::threads::tool_result", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.2 Tool metadata：工具结果的读取与展示判据逐条移植。" },
    FileRule { file: "app/tests/transcript-messages.test.ts", owner: "openbot-ui", target_module: "openbot_ui::features::threads::transcript", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §2.4 第 2 行（上游 issue #44：malformed AG-UI message.content 可使 transcript 崩溃）明写不得照译 —— Rust 版对所有外部 payload 做结构验证、损坏事件隔离成可展示错误，故 transcript 构造语义换了一个；正常路径判据逐条移植。" },

    // --- server/tests（65） ----------------------------------------------------------
    FileRule { file: "server/tests/agent-callback-token.test.ts", owner: "openbot-agent", target_module: "openbot_agent::callback::token", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.5 Remote AG-UI：回调 token 的铸造、run 断言与调用者身份判据逐条移植。注意 v3 §28.4 复算记录上游共享 token 旧路径仍在（server/src/agents/callback-token.ts 的 legacyToken && sameToken），移植该分支前须单列裁决，不得默认照译。" },
    FileRule { file: "server/tests/agent-connection-live.test.ts", owner: "openbot-agent", target_module: "openbot_agent::registry::connection_probe", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.5 Remote AG-UI：注册时的真实连通性探测（答得好 / 答得坏）判据逐条移植。" },
    FileRule { file: "server/tests/agent-endpoint.test.ts", owner: "openbot-agent", target_module: "openbot_agent::registry::endpoint", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §2.4 第 1 行（上游 issue #36：agent endpoint 30x 可绕过初始 URL 检查、DNS rebinding 未解决）明写不得照译 —— Rust 版每一跳重新做 scheme/host/IP policy 且固定已校验 IP 与 TLS SNI，故 endpoint 校验语义换了一个；表单与密钥保管判据逐条移植。" },
    FileRule { file: "server/tests/agent-profile-policy.test.ts", owner: "openbot-domain", target_module: "openbot_domain::agent::profile_policy", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §5.2 Hexagonal ownership：agent profile 权限判据是纯领域规则，逐条移植。" },
    FileRule { file: "server/tests/agent-profile-store.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::agent_profile", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §14.1 单数据库裁决：agent profile 的持久化往返判据逐条移植到 PostgreSQL 后端。" },
    FileRule { file: "server/tests/agent-registry.test.ts", owner: "openbot-agent", target_module: "openbot_agent::registry", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.1 产品中存在两类 Agent：内建与远程 Agent 的可用性汇报且不泄漏密钥，判据逐条移植。" },
    FileRule { file: "server/tests/agent-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::agents", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §15.1 Canonical inventory + §21.1 条 1（每个 route 覆盖 happy/401/403/404/400/dependency failure）：agent 路由的输入解析与生命周期判据逐条移植。" },
    FileRule { file: "server/tests/audit-retention.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::audit_retention", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §16.5 Retention：审计留存策略的裁剪判据逐条移植。" },
    FileRule { file: "server/tests/audit.test.ts", owner: "openbot-application", target_module: "openbot_application::audit", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §8.6 Audit：上游自由 JSON + 敏感键黑名单改为封闭 AuditFact 字段 allowlist；事件目录、不可变与管理端读取判据逐条移植（写/读面均穿 ApplicationService，v3 §5.2）。" },
    FileRule { file: "server/tests/bot-access.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::bot_access", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.2 无权访问统一 404 + §10.1：Bot 对 computer / 工具 / component 面的可达性判据逐条移植。" },
    FileRule { file: "server/tests/bot-lifecycle-audit.test.ts", owner: "openbot-application", target_module: "openbot_application::bot::lifecycle_audit", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.6 Audit：Bot 隐藏/恢复等生命周期动作在审计上留下什么，判据逐条移植。" },
    FileRule { file: "server/tests/channel-activity.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::channel_activity", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.2 Channel + §14.1：某人可读哪些 channel、channel 活动如何汇总，判据逐条移植。" },
    FileRule { file: "server/tests/channel-events.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::events::channel_hub", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §4.3 Native thread/realtime：channel 事件枢纽与投递判据逐条移植到 Rust/PostgreSQL 真源。" },
    FileRule { file: "server/tests/channel-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::channels", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §15.1 + §21.1 条 1：channel 路由输入解析、路由组合与并发写判据逐条移植。" },
    FileRule { file: "server/tests/component-decision.test.ts", owner: "openbot-domain", target_module: "openbot_domain::components::decision", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.3 Generative UI 与 Components：选用哪个 component 是纯领域裁决，判据逐条移植。" },
    FileRule { file: "server/tests/component-store.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::components", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.3 + §21.1 条 5（每个 compiled component 具参数/render/action golden，sandboxed component 具 publish/revision/security fixture）：持久化与发布判据逐条移植。" },
    FileRule { file: "server/tests/computer-client.test.ts", owner: "openbot-computer", target_module: "openbot_computer::client", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §11.2 Engine 协议 + §7.4 Cancel：元素不存在、调用方 Stop 与调用时限判据逐条移植。" },
    FileRule { file: "server/tests/computer-fleet-route.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::computer_fleet", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.4 Server v1 + §15.1：列举部署内全部 computer 的路由判据逐条移植。" },
    FileRule { file: "server/tests/computer-gateway.test.ts", owner: "openbot-computer", target_module: "openbot_computer::gateway", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.1 唯一执行管线 + §10.4：网关裁决、人工输入命名手势而非路径、跨副本解析 ref，判据逐条移植。" },
    FileRule { file: "server/tests/computer-policy-route.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::computer_policy", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §15.1 + §8.3 + R57：部署边界读写判据逐条移植；PUT 额外要求 fresh admin + trusted Origin，且 Axum 精确路由取代 Hono wildcard exemption。" },
    FileRule { file: "server/tests/computer-policy.test.ts", owner: "openbot-domain", target_module: "openbot_domain::policy::computer", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §8.3 CEL：表达式引擎从 cel-js@0.8.2 换成 crate cel 0.14.3，且已核实两处引擎差异（cel-js 无字符串方法、靠注入的全局 contains/matches 工作）必须进 golden corpus，故求值语义承载物换了一个；deny 先于 allow、fail-closed、拒绝描述等判据逐条移植。" },
    FileRule { file: "server/tests/computer-provider.test.ts", owner: "openbot-computer", target_module: "openbot_computer::provider", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.2 / §10.4：隔离级别描述、共享 provider 与工厂选择判据逐条移植。" },
    FileRule { file: "server/tests/computer-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::computer", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §15.1 + §21.1 条 1：computer 路由、fleet 列举与人工输入路由判据逐条移植。" },
    FileRule { file: "server/tests/computer-snapshot-store.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::computer_snapshot", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.4 Server v1：一台服务器上拍的快照在另一台上可读，判据逐条移植到 PostgreSQL 后端。" },
    FileRule { file: "server/tests/computer-snapshot-store.test.ts", owner: "openbot-computer", target_module: "openbot_computer::snapshot::memory_store", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §12.3 Frame contract：内存快照存储的读写与淘汰判据逐条移植。" },
    FileRule { file: "server/tests/computer-supervisor.test.ts", owner: "openbot-computer", target_module: "openbot_computer::supervisor", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.4：定位 Bot 的 computer 与 Docker supervisor provider 判据逐条移植。" },
    FileRule { file: "server/tests/computer-target.test.ts", owner: "openbot-computer", target_module: "openbot_computer::target", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §11.3 Browser 安全配置：导航目标与 computer 地址校验判据逐条移植。" },
    FileRule { file: "server/tests/config.test.ts", owner: "openbot-server", target_module: "openbot_server::config", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §15.4 已对环境变量逐项裁决 preserve/rename/remove（parity/env.yaml 是同一批的表），配置面的变量名与默认值随之改动，故换机制；未知变量不静默忽略这条判据逐条移植（v3 §21.1 条 6）。" },
    FileRule { file: "server/tests/copilot.test.ts", owner: "openbot-agent", target_module: "openbot_agent::compat::copilotkit_facade", tier: Tier::CoveredByGolden, label: Label::Substitute,
        reason: "v3 §15.2：最终 Leptos GUI 不依赖 @copilotkit/react-core 或 /api/copilotkit，迁移期只保留一个 Rust compatibility facade，其输入输出由固定 trace 验证、React 客户端退役后从发行物删除 —— 故转 golden trace 对照而非 1:1 移植。" },
    FileRule { file: "server/tests/credentials.test.ts", owner: "openbot-infra", target_module: "openbot_infra::vault::credentials", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §2.4 第 3 行（上游 issue #53：credential rotate 先写新值再 revoke 旧值，失败留 orphan）明写不得照译 —— Rust 版单事务切换 active pointer、外部 revoke 独立进 reconciliation，故轮换语义换了一个；加解密与查找判据逐条移植。" },
    FileRule { file: "server/tests/database.test.ts", owner: "openbot-infra", target_module: "openbot_infra::db::client", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §14.1 单数据库裁决：构造数据库边界时不发查询，判据逐条移植。" },
    FileRule { file: "server/tests/deployment-route-bot-end-to-end.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::deployment_route_bot", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.2 Routing：以部署路由命名的 Bot 端到端判据逐条移植。" },
    FileRule { file: "server/tests/dev-actor.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::auth::single_user", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.1 Desktop 与 Server 身份模型：开发态 actor 的持久化判据逐条移植。" },
    FileRule { file: "server/tests/encrypt-sso-config.test.ts", owner: "openbot-infra", target_module: "openbot_infra::vault::sso_config", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.4 Vault：身份提供方配置在数据库里的加密形态判据逐条移植。" },
    FileRule { file: "server/tests/entra-profile.test.ts", owner: "openbot-infra", target_module: "openbot_infra::auth::oidc::claims", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.2 必须实现的认证面：Entra 档案映射判据逐条移植。" },
    FileRule { file: "server/tests/google-drive-rest.test.ts", owner: "openbot-agent", target_module: "openbot_agent::connectors::google_drive", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §9.5 Google Drive REST 不是 MCP；且 §2.4 第 6 行明写上游 disconnect 尚未实现、Rust 版必须本地立即 deny + tombstone + vendor revoke + revocation_pending 重试，故连接生命周期语义换了一个；搜索/读取/告知模型什么的判据逐条移植。" },
    FileRule { file: "server/tests/guards.test.ts", owner: "openbot-application", target_module: "openbot_application::authz::guards", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §5.2：授权守卫是 ApplicationService 的入口不变量，判据逐条移植。" },
    FileRule { file: "server/tests/health.test.ts", owner: "openbot-server", target_module: "openbot_server::health", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §16.1 Server 发行物（health/readiness）：健康端点、运行时能力、认证可用性与 IdP 注册判据逐条移植。" },
    FileRule { file: "server/tests/human-input-end-to-end.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::human_input", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §12.5 Input + §8.5 Approval：人工输入端到端判据逐条移植。" },
    FileRule { file: "server/tests/jsonb-encoding.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::db::jsonb", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §21.1 条 3（关键 JSON canonical hash 差异为 0）：jsonb 列实际存了什么，判据逐条移植。" },
    FileRule { file: "server/tests/mcp-protocol.test.ts", owner: "openbot-agent", target_module: "openbot_agent::mcp::protocol", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §9.1 首版 MCP runtime 的精确范围：列举、调用与不可达服务器判据逐条移植。" },
    FileRule { file: "server/tests/mcp-result.test.ts", owner: "openbot-agent", target_module: "openbot_agent::mcp::result", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §9.1 + §28.4 记录的 MAX_RESULT_CHARS = 20_000：空结果、有内容结果与超长结果的处理判据逐条移植。" },
    FileRule { file: "server/tests/people-paging.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::people", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.1：部署内人员分页读取判据逐条移植。" },
    FileRule { file: "server/tests/people-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::people", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §15.1 + §21.1 条 1：people 路由判据逐条移植。" },
    FileRule { file: "server/tests/plugin-catalogue.test.ts", owner: "openbot-agent", target_module: "openbot_agent::mcp::catalogue", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §2.4 第 5 行（上游 issue #106：withdrawn tool 的 stale grant 可能在 transport 切换后复活）明写不得照译 —— Rust 版 catalog refresh 把 grant 标 suspended_missing 且永不静默复活（§9.3），故目录刷新语义换了一个；服务器名单、凭据归属与工具描述判据逐条移植。" },
    FileRule { file: "server/tests/plugin-oauth.test.ts", owner: "openbot-agent", target_module: "openbot_agent::mcp::oauth", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §9.4 OAuth：state、PKCE、去向地址与回调后落点判据逐条移植。" },
    FileRule { file: "server/tests/plugin-store.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::plugin_grants", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §2.4 末行（MCP success/failure 审计发生在 vendor 调用之后）明写不得照译 —— Rust 版 action 前持久化 decision + attempt、action 后持久化 outcome + commit state，故审计时序换了一个；grant 与 policy 双门、第二读者可读同一条轨迹等判据逐条移植。" },
    FileRule { file: "server/tests/plugin-user-credential.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::plugin_user_credential", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.4 Vault + §9.2 连接生命周期：个人凭据的连接、缺失与退役判据逐条移植。" },
    FileRule { file: "server/tests/policy-durability.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::store::policy_durability", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.3：运行中设置的边界必须持久，判据逐条移植。" },
    FileRule { file: "server/tests/policy-fanout.integration.test.ts", owner: "openbot-infra", target_module: "openbot_infra::events::policy_fanout", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.3 明写沿用上游 policy-listener.ts 形态（LISTEN/NOTIFY 只做唤醒、每个 replica 整表重读、policy_version 进 decision），故 fanout 判据逐条移植。" },
    FileRule { file: "server/tests/roles.test.ts", owner: "openbot-domain", target_module: "openbot_domain::identity::roles", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §6.1 / §6.2：按邮箱定角色、设角色、应用配置管理员与种子角色是纯领域规则，判据逐条移植（§6.5 修正的是 group，不是 role）。" },
    FileRule { file: "server/tests/routing-classify.test.ts", owner: "openbot-domain", target_module: "openbot_domain::routing::classify", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.2 Routing：无 @mention 时的分派与按 coworker 可达面分派，判据逐条移植。" },
    FileRule { file: "server/tests/routing-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::routing", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §15.1 + §3.2：记录消息去了哪个 coworker 的路由判据逐条移植。" },
    FileRule { file: "server/tests/runtime-agents.integration.test.ts", owner: "openbot-agent", target_module: "openbot_agent::runtime::loading", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.1：运行时 agent 装载判据逐条移植。" },
    FileRule { file: "server/tests/sandboxed-components.integration.test.ts", owner: "openbot-application", target_module: "openbot_application::components::sandboxed", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §3.3：免重建撰写 component、以及不得删除本面不拥有的名字，判据逐条移植。" },
    FileRule { file: "server/tests/schema.test.ts", owner: "openbot-infra", target_module: "openbot_infra::db::schema", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §14.2 28 表 parity ledger + §21.1 条 3：schema 断言逐条移植，并与 parity/tables.yaml 同一批 28 张表交叉。" },
    FileRule { file: "server/tests/server-side-tools.integration.test.ts", owner: "openbot-agent", target_module: "openbot_agent::tools::server_side", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §8.1 唯一执行管线：Bot 在服务端被交到手上的工具集判据逐条移植。" },
    FileRule { file: "server/tests/single-user.test.ts", owner: "openbot-server", target_module: "openbot_infra::auth::config", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §6.1 + §6.5 条 3：无登录运行判据逐条移植；但 §28.1 R34 已把旧 `OPENBOT_DEV_NO_AUTH` 从继续生效改为 rename→`OPENBOT_SINGLE_USER` 且启动拒绝，因此整文件按保守粒度标替代，不能把旧别名那条写成 parity。" },
    FileRule { file: "server/tests/skill-ownership.integration.test.ts", owner: "openbot-application", target_module: "openbot_application::skills::ownership", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §9.6 Skills 与 tool discovery：可见性、归属、编辑保持归属与 HTTP 可做什么，判据逐条移植。" },
    FileRule { file: "server/tests/stall-guard.test.ts", owner: "openbot-agent", target_module: "openbot_agent::stall_guard", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.4 Retry、Cancel、Budget 与 Commit：停流判定、留给人的那句话与不该碰的东西，判据逐条移植。" },
    FileRule { file: "server/tests/tenant-package.test.ts", owner: "openbot-application", target_module: "openbot_application::tenant::package", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §3.2 / §6.5 + GUI 第一真源 §4.1：allowed_groups 改为真实 membership projection；runtime tenant theme 被 tokens.toml 单一来源取代且 loader 只读五份 YAML；其余 schema/reference/env/sync 判据逐条移植。" },
    FileRule { file: "server/tests/thread-identity.test.ts", owner: "openbot-contracts", target_module: "openbot_contracts::ids::thread", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §5.3：ThreadId 携带铸造它的 deployment，兼容端必须接受上游既有字符串，判据逐条移植。" },
    FileRule { file: "server/tests/thread-routes.test.ts", owner: "openbot-server", target_module: "openbot_server::routes::threads", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §4.1 条 1/2/3（Rust/PostgreSQL 是 thread 唯一真源，最终请求路径不读不写 Intelligence）+ §2.4 第 4 行（issue #72：从未运行的 thread history 返回 500 → Rust 版明确返回空 history），故'向上游确认线程是否还在'这一面被删除、错误语义被修正；铸造线程判据逐条移植。" },
    FileRule { file: "server/tests/thread-status.test.ts", owner: "openbot-application", target_module: "openbot_application::migration::intelligence_thread", tier: Tier::CoveredByGolden, label: Label::Substitute,
        reason: "v3 §4.1 条 3：Intelligence 只用于旧数据导出、迁移核对和一次性导入，最终请求路径不连接它 —— 该文件的被测面整体从运行路径搬进 §20.3 的迁移工具，由迁移 fixture 对照覆盖而非 1:1 移植。" },
    FileRule { file: "server/tests/turn-watchdog.test.ts", owner: "openbot-agent", target_module: "openbot_agent::turn::watchdog", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.4：回合按活性而不是按时长判定、停流只报一次、未配置则不启用，判据逐条移植。" },

    // --- shared（2） -----------------------------------------------------------------
    FileRule { file: "shared/agent-authorisation.test.ts", owner: "openbot-domain", target_module: "openbot_domain::agent::authorisation", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §5.2 + §7.1：托管 agent 的授权判定是纯领域规则，判据逐条移植。" },
    FileRule { file: "shared/bot-prompt.test.ts", owner: "openbot-agent", target_module: "openbot_agent::prompt::computer_guidance", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §7.2 Agent reducer：COMPUTER_GUIDANCE 提示词内容契约判据逐条移植。" },

    // --- supervisor（2） -------------------------------------------------------------
    FileRule { file: "supervisor/tests/docker.integration.test.ts", owner: "openbot-computer", target_module: "openbot_computer::supervisor::docker", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.4 Server v1：容器归属规则对真实 daemon 的判据（同名冲突返回 409）逐条移植。" },
    FileRule { file: "supervisor/tests/names.test.ts", owner: "openbot-computer", target_module: "openbot_computer::supervisor::names", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §10.1：supervisor 接受哪些 id，判据逐条移植。" },

    // --- 仓根 tests（6） --------------------------------------------------------------
    FileRule { file: "tests/agent-bot.test.ts", owner: "openbot-agent", target_module: "openbot_agent::reference::bootstrap", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §3.5：agent-bot 的手写 AG-UI reference 行为重写为 Rust openbot-reference-agent，上游用 Bun.spawn 起 TS 入口的启动形态不复存在；'没有模型 key 就不该报健康'这条判据逐条移植。" },
    FileRule { file: "tests/clean-checkout.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::repo::clean_checkout", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §3.5 删除 Bun launcher：'只跑过 bun install 的克隆'换成'只跑过 cargo fetch 的克隆'；'依赖必须在根解析得到'与'租户包不得要求 .env'两条判据逐条移植到 cargo workspace 与 fixture 上。" },
    FileRule { file: "tests/compose.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::repo::compose", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §14.1 单数据库裁决（PostgreSQL + pgvector）：docker-compose 提供本地开发数据库的判据逐条移植。" },
    FileRule { file: "tests/fintech-package.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::fixtures::tenant_package::fintech", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §3.2 / §6.5 保留五文件示例与 all audience；§16.2 禁止对外 product name 复用 OpenBot/CopilotKit 标记，所以 fixture 改为 fintech/Ledgerline 并增加反向品牌断言。" },
    FileRule { file: "tests/smoke/journey.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::smoke::journey", tier: Tier::Ported, label: Label::Parity,
        reason: "v3 §21.5 性能/稳定性 + §21.1：一次贯穿运行中部署的旅程（服务器→supervisor→网关→浏览器→轨迹）判据逐条移植；上游同样不在默认套件里，按名字调用。" },
    FileRule { file: "tests/workspace.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::repo::workspace", tier: Tier::Ported, label: Label::Substitute,
        reason: "v3 §5.1 精简 workspace：bun workspace 的包清单换成 cargo workspace 的十个 crate；'每个成员都声明了名字且被根清单收录'这条判据逐条移植。" },

    // --- worker（1）：v3 §3.5 逐字点名 -----------------------------------------------
    FileRule { file: "worker/tests/status.test.ts", owner: "openbot-testkit", target_module: "openbot_testkit::retired::worker_status", tier: Tier::NotApplicableWithProof, label: Label::Substitute,
        reason: "v3 §3.5 逐字：'当前 worker 只返回 {status:\"idle\"} 且没有 job，Rust 版不发布空 worker binary；该测试标记 not-applicable-with-proof'。证明面 = 发行物清单里不得出现 worker 二进制（v3 §16.1/§16.2），由 openbot_testkit::retired::worker_status 做反向断言，不是把 idle 断言照抄一遍。" },
];

// ---------------------------------------------------------------------------
// 阶段队列（v3 §24 G2 / G6；§28.1 R52）
// ---------------------------------------------------------------------------

/// G2 的上游 test inventory 文件集合。
///
/// 取 `FILE_RULES.reason` 引用 §6（Auth/Vault）或 §8（Policy/Audit/Tool control）的全集，
/// 再减去 [`G6_DEFERRED_G2_GUI_FILES`]。`tool-name` / `tool-result` 留在这里是刻意的：它们
/// 分别承载 §8.2 tool metadata 与 policy refusal 解码后的可识别性，不依赖 route/视觉落地。
const G2_TEST_FILES: [&str; 21] = [
    "agent-computer/tests/shell.test.ts",
    "app/tests/tool-name.test.ts",
    "app/tests/tool-result.test.ts",
    "server/tests/audit.test.ts",
    "server/tests/bot-lifecycle-audit.test.ts",
    "server/tests/computer-gateway.test.ts",
    "server/tests/computer-policy-route.test.ts",
    "server/tests/computer-policy.test.ts",
    "server/tests/dev-actor.integration.test.ts",
    "server/tests/encrypt-sso-config.test.ts",
    "server/tests/entra-profile.test.ts",
    "server/tests/human-input-end-to-end.test.ts",
    "server/tests/people-paging.integration.test.ts",
    "server/tests/plugin-user-credential.integration.test.ts",
    "server/tests/policy-durability.integration.test.ts",
    "server/tests/policy-fanout.integration.test.ts",
    "server/tests/roles.test.ts",
    "server/tests/server-side-tools.integration.test.ts",
    "server/tests/single-user.test.ts",
    "server/tests/tenant-package.test.ts",
    "tests/fintech-package.test.ts",
];

/// 引用 §6/§8、但明确归 §24 G6 的 GUI 文件。
///
/// 三者验证的是 audit 页可见文案、浏览器登录 client 与 credential form；后端闭合不能把
/// 它们冒充完成。固定上游 AST 中分别为 5 / 6 / 1 条。
#[cfg(test)]
const G6_DEFERRED_G2_GUI_FILES: [&str; 3] = [
    "app/tests/audit-silence.test.ts",
    "app/tests/auth-client.test.ts",
    "app/tests/credential-form.test.ts",
];

/// 固定上游 AST 中 G2 队列的用例数；由同名测试与 `parity/tests.yaml::recount` 双重复算。
const G2_TEST_CASE_COUNT: usize = 234;

/// 延后到 G6 的三个 GUI 文件用例数。
#[cfg(test)]
const G6_DEFERRED_G2_GUI_CASE_COUNT: usize = 12;

/// `FILE_RULES.reason` 引用 §6 或 §8 的完整用例数。
#[cfg(test)]
const G2_SECTION_REFERENCED_TEST_CASE_COUNT: usize = 246;

// ---------------------------------------------------------------------------
// AST 抽取结果
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum NodeKind {
    Describe,
    Test,
}

/// 标题的来源形态。`dynamic` 意味着首个实参不是字面量 —— 这类用例的标题在静态解析下不可知，
/// 必须显式标出来而不是编一个，否则 inventory 会把"不知道"伪装成"知道"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TitleKind {
    String,
    Template,
    Dynamic,
    Missing,
}

impl TitleKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Template => "template",
            Self::Dynamic => "dynamic",
            Self::Missing => "missing",
        }
    }
}

/// 一个 AST 节点的原始抽取结果。行列号只进本结构（进而只进 JSON），不进 ledger。
#[derive(Debug, Clone, Serialize)]
struct RawNode {
    /// 在 `nodes[]` 中的下标，ledger 的 `evidence` 用它做指针。
    index: usize,
    file: String,
    kind: NodeKind,
    /// 调用点的书写形态，例如 `test`、`test.each(…)`、`describe.skipIf(…)`。
    callee: String,
    describe_chain: Vec<String>,
    title: String,
    title_kind: TitleKind,
    skip: bool,
    only: bool,
    each: bool,
    /// 修饰符带条件实参（`skipIf` / `runIf` …）：是否跳过取决于运行期，静态不可知。
    conditional: bool,
    /// 1-based 行号（UTF-8 字节推算）。
    line: u32,
    /// 1-based 列号（行内 UTF-8 字节偏移 + 1）。
    column: u32,
}

#[derive(Debug, Serialize)]
struct ParserInfo {
    name: &'static str,
    version: &'static str,
    source_type: &'static str,
}

#[derive(Debug, Serialize)]
struct FileSummary {
    file: String,
    describes: usize,
    tests: usize,
    tier: Tier,
}

#[derive(Debug, Serialize)]
struct Totals {
    files_scanned: usize,
    describe_nodes: usize,
    test_cases: usize,
    skip: usize,
    only: usize,
    each: usize,
    dynamic_titles: usize,
}

#[derive(Debug, Serialize)]
struct CrossCheck {
    /// v3 §1.3 的词法命中数。
    lexical_test_hits: usize,
    /// AST 真实用例数。
    ast_test_cases: usize,
    /// AST − 词法。
    delta: i64,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct Inventory {
    tool: &'static str,
    parser: ParserInfo,
    upstream_commit: &'static str,
    /// 只记相对形态，不把本机绝对路径钉进产物（换台机器复算会对不上）。
    upstream_root: &'static str,
    totals: Totals,
    cross_check: CrossCheck,
    per_file: Vec<FileSummary>,
    nodes: Vec<RawNode>,
}

/// 已有 ledger 里需要跨 AST 重生成保留的实施进度。
///
/// `id/upstream/label/owner/test_id/evidence` 仍由固定上游 AST 与 FILE_RULES 重建；只有已经离开
/// `todo` 的条目才允许覆盖目标、迁移裁决与完成证据。这样上游 inventory 可重放，又不会把
/// W-5/G8 已经亲跑过的证据静默抹回 todo。
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProgressOverlay {
    target: String,
    migration_rule: String,
    status: String,
    done_evidence: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExistingLedger {
    entries: Vec<ExistingProgressEntry>,
}

#[derive(Debug, Deserialize)]
struct ExistingProgressEntry {
    id: String,
    #[serde(default)]
    upstream: String,
    target: String,
    migration_rule: String,
    status: String,
    done_evidence: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct G2ProgressCounts {
    done: usize,
    todo: usize,
    in_progress: usize,
}

impl G2ProgressCounts {
    const fn total(self) -> usize {
        self.done + self.todo + self.in_progress
    }

    fn rendered(self) -> String {
        format!(
            "done={} todo={} in_progress={} total={}",
            self.done,
            self.todo,
            self.in_progress,
            self.total()
        )
    }
}

// ---------------------------------------------------------------------------
// 子命令入口
// ---------------------------------------------------------------------------

/// `cargo xtask test-inventory` 的实现。`root` 是仓库根（由 `xtask.rs::workspace_root` 定位）。
pub fn run(args: &[String], root: &Path) -> Result<()> {
    let mut upstream: Option<PathBuf> = None;
    let mut dry_run = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--upstream" => {
                let value = iter
                    .next()
                    .context("test-inventory: `--upstream` 后面缺路径")?;
                upstream = Some(PathBuf::from(value));
            }
            "--dry-run" => dry_run = true,
            other => {
                bail!("test-inventory: 未知参数 `{other}`（只接受 --upstream <路径> / --dry-run）")
            }
        }
    }

    let upstream = upstream.context(
        "test-inventory: 必须给 `--upstream <上游干净克隆路径>`；不给默认值是刻意的 —— \
         猜错路径会得到一份空 inventory 而不是一条错误",
    )?;
    if !upstream.is_dir() {
        bail!(
            "test-inventory: `--upstream` 指向的不是目录：{}",
            upstream.display()
        );
    }

    // 1) 收集上游测试文件：直接走 FILE_RULES 的路径清单，逐个 assert 存在。
    //    不用 walkdir 扫盘的理由是 fail-closed 的方向：表里有而盘上没有 = 上游动了，必须炸；
    //    盘上有而表里没有 = 未分类项，也必须炸。两条都要，所以两边都查。
    let mut nodes: Vec<RawNode> = Vec::new();
    let mut per_file: Vec<FileSummary> = Vec::new();

    for rule in &FILE_RULES {
        let path = upstream.join(rule.file);
        if !path.is_file() {
            bail!(
                "test-inventory: FILE_RULES 里的 `{}` 在上游克隆里不存在（{}）—— \
                 上游基线变了就必须走 v3 §1.2 的 delta audit，不能让 inventory 少一块",
                rule.file,
                path.display()
            );
        }
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 {} 失败", path.display()))?;
        let extracted =
            extract_file(rule.file, &source).with_context(|| format!("解析 {} 失败", rule.file))?;

        let describes = extracted
            .iter()
            .filter(|n| n.kind == NodeKind::Describe)
            .count();
        let tests = extracted
            .iter()
            .filter(|n| n.kind == NodeKind::Test)
            .count();
        per_file.push(FileSummary {
            file: rule.file.to_string(),
            describes,
            tests,
            tier: rule.tier,
        });
        nodes.extend(extracted);
    }

    // 反向：盘上有而表里没有的测试文件 = 未分类项。
    let declared: HashSet<&str> = FILE_RULES.iter().map(|r| r.file).collect();
    let on_disk = discover_test_files(&upstream)?;
    let mut undeclared: Vec<String> = on_disk
        .iter()
        .filter(|f| !declared.contains(f.as_str()))
        .cloned()
        .collect();
    undeclared.sort();
    if !undeclared.is_empty() {
        bail!(
            "test-inventory: 上游有 {} 个测试文件不在 FILE_RULES 里（v3 §21.1 条 4「未分类为 0」）：{}",
            undeclared.len(),
            undeclared.join(", ")
        );
    }
    if on_disk.len() != UPSTREAM_TEST_FILE_COUNT {
        bail!(
            "test-inventory: 上游测试文件实得 {}，v3 §1.3 基线是 {}",
            on_disk.len(),
            UPSTREAM_TEST_FILE_COUNT
        );
    }

    // 2) 给每个节点编号（ledger 的 evidence 指针）。
    for (i, node) in nodes.iter_mut().enumerate() {
        node.index = i;
    }

    let test_cases = nodes.iter().filter(|n| n.kind == NodeKind::Test).count();
    let describe_nodes = nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Describe)
        .count();
    let totals = Totals {
        files_scanned: FILE_RULES.len(),
        describe_nodes,
        test_cases,
        skip: nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Test && n.skip)
            .count(),
        only: nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Test && n.only)
            .count(),
        each: nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Test && n.each)
            .count(),
        dynamic_titles: nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Test && n.title_kind == TitleKind::Dynamic)
            .count(),
    };

    let inventory = Inventory {
        tool: "cargo xtask test-inventory",
        parser: ParserInfo {
            name: "oxc_parser",
            version: OXC_VERSION,
            source_type: "oxc_span::SourceType::from_path（.ts → TS，.tsx → TSX）",
        },
        upstream_commit: UPSTREAM_COMMIT,
        upstream_root: "CopilotKit/openbot @ 891df72f1827454d8b353d108fe5dd2313b7e30d 的干净克隆",
        cross_check: CrossCheck {
            lexical_test_hits: LEXICAL_TEST_HITS,
            ast_test_cases: test_cases,
            delta: test_cases as i64 - LEXICAL_TEST_HITS as i64,
            note: "词法命中 = grep -hoE '\\b(test|it)\\(' 的原始计数，会数到正则方法调用 \
                   （如 /secret/i.test(k)）也数不到柯里化的 test.each([...])(\"标题\", fn) 的标题实参；\
                   两个方向的偏差同时存在，差值必须逐项解释，不能一句'正常'带过。",
        },
        totals,
        per_file,
        nodes,
    };

    print_summary(&inventory);

    if dry_run {
        println!("\n--dry-run：未写盘。");
        return Ok(());
    }

    let yaml_path = root.join("parity/tests.yaml");
    let progress = load_progress_overlays(&yaml_path)?;
    let g2_progress = load_g2_progress_counts(&yaml_path)?;
    let yaml = render_ledger(&inventory, &progress, g2_progress)?;

    let json_path = root.join("fixtures/tests/upstream-ast-inventory.json");
    write_json(&json_path, &inventory)?;
    println!("已写 {}", json_path.display());

    write_text(&yaml_path, &yaml)?;
    println!("已写 {}", yaml_path.display());

    Ok(())
}

fn print_summary(inv: &Inventory) {
    println!(
        "== xtask test-inventory（{} {}）==",
        inv.parser.name, inv.parser.version
    );
    println!("上游 commit        : {}", inv.upstream_commit);
    println!("扫描测试文件       : {}", inv.totals.files_scanned);
    println!("AST describe 节点  : {}", inv.totals.describe_nodes);
    println!("AST 用例数         : {}", inv.totals.test_cases);
    println!("  其中 skip        : {}", inv.totals.skip);
    println!("  其中 only        : {}", inv.totals.only);
    println!("  其中 each        : {}", inv.totals.each);
    println!("  标题非字面量     : {}", inv.totals.dynamic_titles);
    println!(
        "词法命中（v3 §1.3）: {}  → AST − 词法 = {:+}",
        inv.cross_check.lexical_test_hits, inv.cross_check.delta
    );

    let mut tiers: BTreeMap<&str, usize> = BTreeMap::new();
    for rule in &FILE_RULES {
        *tiers.entry(rule.tier.as_str()).or_insert(0) += 1;
    }
    println!("文件级三档分布     :");
    for (tier, count) in &tiers {
        println!("  {tier:<26} {count}");
    }
}

// ---------------------------------------------------------------------------
// 文件发现
// ---------------------------------------------------------------------------

/// 扫上游工作树里的 `*.test.ts` / `*.test.tsx`，跳过 `.git` 与 `node_modules`。
///
/// 与 `git ls-files '*.test.ts' '*.test.tsx'` 的口径对齐靠两点：干净克隆里工作树 == 索引；
/// 且这里显式跳过唯一两个非版本控制目录。数量对不上会在调用方炸。
fn discover_test_files(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !(e.file_type().is_dir() && (name == ".git" || name == "node_modules"))
    }) {
        let entry = entry.context("遍历上游克隆失败")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !(name.ends_with(".test.ts") || name.ends_with(".test.tsx")) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .context("strip_prefix 失败")?
            .to_string_lossy()
            .replace('\\', "/");
        out.push(rel);
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// AST 抽取
// ---------------------------------------------------------------------------

/// 解析一个文件并抽出全部 describe / test 节点。
///
/// error 级诊断一律抛错：静默跳过文件会让 inventory 假装完整 —— 那正是本产物要消灭的失效模式。
fn extract_file(rel_path: &str, source: &str) -> Result<Vec<RawNode>> {
    let source_type = SourceType::from_path(rel_path)
        .map_err(|e| anyhow::anyhow!("SourceType::from_path 拒绝 `{rel_path}`：{e}"))?;
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type).parse();

    if ret.panicked {
        bail!(
            "oxc_parser 在 `{rel_path}` 上 panicked（AST 为空）；诊断：{:?}",
            ret.diagnostics
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }
    if ret.diagnostics.has_errors() {
        let messages: Vec<String> = ret.diagnostics.iter().map(ToString::to_string).collect();
        bail!("oxc_parser 在 `{rel_path}` 上报了 error 级诊断：{messages:?}");
    }

    let mut collector = Collector {
        file: rel_path.to_string(),
        line_starts: line_starts(source),
        chain: Vec::new(),
        nodes: Vec::new(),
        suppressed: HashSet::new(),
    };
    collector.visit_program(&ret.program);
    Ok(collector.nodes)
}

struct Collector {
    file: String,
    line_starts: Vec<u32>,
    chain: Vec<String>,
    nodes: Vec<RawNode>,
    /// 柯里化调用（`test.each([...])(…)`）的**内层** call 的 span，防止它被当成第二个用例。
    /// 用 `(start, end)` 而不是 `start`：内外两层的 `start` 是同一个字节偏移。
    suppressed: HashSet<(u32, u32)>,
}

/// 调用点分类结果。
struct CalleeInfo {
    kind: NodeKind,
    modifiers: Vec<String>,
    /// 柯里化时的内层 call span。
    curried_inner: Option<(u32, u32)>,
    /// 书写形态，例如 `test.each(…)`。
    text: String,
}

fn root_kind(name: &str) -> Option<NodeKind> {
    CASE_ROOTS
        .iter()
        .find(|(root, _)| *root == name)
        .map(|(_, kind)| *kind)
}

/// 剥掉不改变"这是谁在被调用"的包装（括号、TS 非空断言、`as` 断言）。
fn unwrap_expression<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(inner) => unwrap_expression(&inner.expression),
        Expression::TSNonNullExpression(inner) => unwrap_expression(&inner.expression),
        Expression::TSAsExpression(inner) => unwrap_expression(&inner.expression),
        Expression::TSSatisfiesExpression(inner) => unwrap_expression(&inner.expression),
        other => other,
    }
}

fn classify_callee(expr: &Expression<'_>) -> Option<CalleeInfo> {
    match unwrap_expression(expr) {
        Expression::Identifier(ident) => {
            let name = ident.name.as_str();
            root_kind(name).map(|kind| CalleeInfo {
                kind,
                modifiers: Vec::new(),
                curried_inner: None,
                text: name.to_string(),
            })
        }
        Expression::StaticMemberExpression(member) => {
            let mut base = classify_callee(&member.object)?;
            // 柯里化之后再取成员（`test.each([...]).foo`）不是已知写法，认它只会制造假条目。
            if base.curried_inner.is_some() {
                return None;
            }
            let property = member.property.name.as_str();
            base.text.push('.');
            base.text.push_str(property);
            base.modifiers.push(property.to_string());
            Some(base)
        }
        Expression::CallExpression(call) => {
            let mut base = classify_callee(&call.callee)?;
            // 双重柯里化不是已知写法；认它会让标题取错一层。
            if base.curried_inner.is_some() {
                return None;
            }
            base.curried_inner = Some((call.span.start, call.span.end));
            base.text.push_str("(…)");
            Some(base)
        }
        _ => None,
    }
}

impl<'a> Visit<'a> for Collector {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let key = (it.span.start, it.span.end);
        if self.suppressed.remove(&key) {
            walk::walk_call_expression(self, it);
            return;
        }

        let Some(info) = classify_callee(&it.callee) else {
            walk::walk_call_expression(self, it);
            return;
        };

        if let Some(inner) = info.curried_inner {
            self.suppressed.insert(inner);
        }

        let (title, title_kind) = extract_title(it.arguments.first());
        let (line, column) = line_col(&self.line_starts, it.span.start);

        let skip = info
            .modifiers
            .iter()
            .any(|m| SKIP_MODIFIERS.contains(&m.as_str()));
        let only = info
            .modifiers
            .iter()
            .any(|m| ONLY_MODIFIERS.contains(&m.as_str()));
        let each = info
            .modifiers
            .iter()
            .any(|m| EACH_MODIFIERS.contains(&m.as_str()));
        let conditional = info
            .modifiers
            .iter()
            .any(|m| CONDITIONAL_MODIFIERS.contains(&m.as_str()));

        self.nodes.push(RawNode {
            index: 0, // 全量收集完后统一编号
            file: self.file.clone(),
            kind: info.kind,
            callee: info.text,
            describe_chain: self.chain.clone(),
            title: title.clone(),
            title_kind,
            skip,
            only,
            each,
            conditional,
            line,
            column,
        });

        if info.kind == NodeKind::Describe {
            self.chain.push(title);
            walk::walk_call_expression(self, it);
            self.chain.pop();
        } else {
            walk::walk_call_expression(self, it);
        }
    }
}

/// 从首个实参取标题。非字面量一律标 `dynamic` 并把源形态留空，不编造。
fn extract_title(arg: Option<&Argument<'_>>) -> (String, TitleKind) {
    let Some(arg) = arg else {
        return (String::new(), TitleKind::Missing);
    };
    let Some(expr) = arg.as_expression() else {
        return (String::new(), TitleKind::Dynamic);
    };
    match unwrap_expression(expr) {
        Expression::StringLiteral(lit) => (lit.value.as_str().to_string(), TitleKind::String),
        Expression::TemplateLiteral(tpl) => (render_template(tpl), TitleKind::Template),
        _ => (String::new(), TitleKind::Dynamic),
    }
}

/// 模板串渲染成稳定文本：字面段原样，插值段一律写成 `${?}`。
///
/// 不求值插值（求值需要作用域信息，静态解析拿不到），也不把它省略掉 —— 省略会让两条只差插值
/// 位置的用例塌成同一个 id。
fn render_template(tpl: &TemplateLiteral<'_>) -> String {
    let mut out = String::new();
    for (i, quasi) in tpl.quasis.iter().enumerate() {
        let text = quasi
            .value
            .cooked
            .as_ref()
            .map_or_else(|| quasi.value.raw.as_str(), |cooked| cooked.as_str());
        out.push_str(text);
        if i < tpl.expressions.len() {
            out.push_str("${?}");
        }
    }
    out
}

fn line_starts(source: &str) -> Vec<u32> {
    let mut starts = vec![0u32];
    for (i, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push((i + 1) as u32);
        }
    }
    starts
}

fn line_col(starts: &[u32], offset: u32) -> (u32, u32) {
    let idx = starts.partition_point(|&s| s <= offset).saturating_sub(1);
    (idx as u32 + 1, offset - starts[idx] + 1)
}

// ---------------------------------------------------------------------------
// ledger 渲染
// ---------------------------------------------------------------------------

/// slug 化：ASCII 字母数字保留并转小写，其余一律折成单个 `-`。
///
/// 非 ASCII 直接丢弃而不是转拼音/编码：上游 105 个文件的标题全是英文（本轮实测），真出现非 ASCII
/// 标题时会塌成空串，由调用方的去重后缀兜底，不会产生重复 id。
fn slugify(input: &str, max_len: usize) -> String {
    let mut out = String::new();
    let mut prev_dash = true; // 前导 `-` 一并吃掉
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
        if out.len() >= max_len {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Rust 测试函数名：slug 的下划线形态，且不以数字开头。
fn rust_fn_name(input: &str, max_len: usize) -> String {
    let slug = slugify(input, max_len).replace('-', "_");
    if slug.is_empty() {
        "unnamed_case".to_string()
    } else if slug.starts_with(|c: char| c.is_ascii_digit()) {
        format!("case_{slug}")
    } else {
        slug
    }
}

/// YAML 双引号标量。所有可能带 `:` `#` `%` `"` `\` 的值都走这里，避免依赖 plain scalar 的边界规则。
fn yaml_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn rule_for(file: &str) -> &'static FileRule {
    FILE_RULES
        .iter()
        .find(|r| r.file == file)
        .expect("nodes 全部来自 FILE_RULES 的路径清单")
}

fn load_progress_overlays(path: &Path) -> Result<BTreeMap<String, ProgressOverlay>> {
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("读取已有 test parity ledger {} 失败", path.display()))?;
    parse_progress_overlays(&source)
        .with_context(|| format!("读取已有 test parity 进度 {} 失败", path.display()))
}

fn load_g2_progress_counts(path: &Path) -> Result<G2ProgressCounts> {
    if !path.is_file() {
        return Ok(G2ProgressCounts {
            todo: G2_TEST_CASE_COUNT,
            ..G2ProgressCounts::default()
        });
    }
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("读取已有 G2 test 进度 {} 失败", path.display()))?;
    let ledger: ExistingLedger =
        serde_yaml::from_str(&source).context("tests.yaml 不是合法 YAML")?;
    let files: HashSet<&str> = G2_TEST_FILES.into_iter().collect();
    let mut counts = G2ProgressCounts::default();
    for entry in ledger.entries {
        let file = entry.upstream.split("::").next().unwrap_or_default();
        if !files.contains(file) {
            continue;
        }
        match entry.status.as_str() {
            "done" => counts.done += 1,
            "todo" => counts.todo += 1,
            "in_progress" => counts.in_progress += 1,
            other => bail!(
                "test-inventory: G2 条目 `{}` 的 status `{other}` 非法",
                entry.id
            ),
        }
    }
    if counts.total() != G2_TEST_CASE_COUNT {
        bail!(
            "test-inventory: G2 进度总数实得 {}，固定队列应为 {G2_TEST_CASE_COUNT}",
            counts.total()
        );
    }
    Ok(counts)
}

fn parse_progress_overlays(source: &str) -> Result<BTreeMap<String, ProgressOverlay>> {
    let ledger: ExistingLedger =
        serde_yaml::from_str(source).context("tests.yaml 不是合法 YAML")?;
    let mut progress = BTreeMap::new();
    for entry in ledger.entries {
        match entry.status.as_str() {
            "todo" => {
                if entry.done_evidence.is_some() {
                    bail!(
                        "test-inventory: todo 条目 `{}` 不得携带 done_evidence",
                        entry.id
                    );
                }
                continue;
            }
            "done" => {
                if entry
                    .done_evidence
                    .as_deref()
                    .is_none_or(|evidence| evidence.trim().is_empty())
                {
                    bail!(
                        "test-inventory: done 条目 `{}` 缺非空 done_evidence",
                        entry.id
                    );
                }
            }
            "in_progress" => {}
            other => bail!(
                "test-inventory: 条目 `{}` 的 status `{other}` 不在 todo/in_progress/done 封闭域",
                entry.id
            ),
        }
        if entry.target.trim().is_empty() || entry.migration_rule.trim().is_empty() {
            bail!(
                "test-inventory: 非 todo 条目 `{}` 缺 target 或 migration_rule",
                entry.id
            );
        }
        let id = entry.id;
        let overlay = ProgressOverlay {
            target: entry.target,
            migration_rule: entry.migration_rule,
            status: entry.status,
            done_evidence: entry.done_evidence,
        };
        if progress.insert(id.clone(), overlay).is_some() {
            bail!("test-inventory: 已有 ledger 出现重复进度 ID `{id}`");
        }
    }
    Ok(progress)
}

fn render_ledger(
    inv: &Inventory,
    progress: &BTreeMap<String, ProgressOverlay>,
    g2_progress: G2ProgressCounts,
) -> Result<String> {
    let cases: Vec<&RawNode> = inv
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Test)
        .collect();

    let mut label_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut tier_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for case in &cases {
        let rule = rule_for(&case.file);
        *label_counts.entry(rule.label.as_str()).or_insert(0) += 1;
        *tier_counts.entry(rule.tier.as_str()).or_insert(0) += 1;
    }

    let mut out = String::new();
    let w = &mut out;

    writeln!(
        w,
        "# parity/tests.yaml —— 上游 {UPSTREAM_TEST_FILE_COUNT} 个 .test.ts/.test.tsx 文件的 **AST 级** test inventory。"
    )?;
    writeln!(w, "#")?;
    writeln!(
        w,
        "# 本文件的 AST 身份字段由 `cargo xtask test-inventory --upstream <上游干净克隆>` 生成："
    )?;
    writeln!(
        w,
        "# id/upstream/label/owner/test_id/evidence 不手改；非 todo 的 target/migration_rule/status/done_evidence 会按稳定 id 保留。"
    )?;
    writeln!(
        w,
        "# 已完成 id 若在重生成后消失会硬失败，不会静默丢证据或错接到另一条 AST 用例。"
    )?;
    writeln!(
        w,
        "# 分类真源 = crates/openbot-testkit/src/xtask/test_inventory.rs::FILE_RULES（{UPSTREAM_TEST_FILE_COUNT} 行，一行一个上游文件）。"
    )?;
    writeln!(
        w,
        "# G2 队列真源 = 同文件 G2_TEST_FILES（21 文件 / {G2_TEST_CASE_COUNT} 用例）；§6/§8 的 3 个 GUI 文件另归 G6。"
    )?;
    writeln!(w, "#")?;
    writeln!(w, "# 真源与依据：")?;
    writeln!(
        w,
        "# - v3 §1.3：1,007 是词法命中，不冒充 AST 解析后的精确 test 数；Phase 0 必须生成 AST 级 inventory 并归档原始结果。"
    )?;
    writeln!(
        w,
        "# - v3 §21.1 条 4：{UPSTREAM_TEST_FILE_COUNT} 个现有测试文件以及全部 AST 级用例逐个标记 ported / covered-by-golden / not-applicable-with-proof，未分类为 0。"
    )?;
    writeln!(
        w,
        "# - v3 §24 G0：test parity ledger 未分类项 = 0，上游基线测试原始结果归档。"
    )?;
    writeln!(
        w,
        "# - v3 §24 G8：Phase 0 AST 级 test inventory mapping 100%。"
    )?;
    writeln!(
        w,
        "# - v3 §3.5：worker 只返回 {{status:\"idle\"}} 且没有 job，Rust 版不发布空 worker binary，该测试标记 not-applicable-with-proof。"
    )?;
    writeln!(w, "#")?;
    writeln!(
        w,
        "# 三档（v3 §21.1 条 4）到统一 schema v1 `migration_rule`（preserve|rename|remove|n/a）的映射："
    )?;
    writeln!(w, "#   ported（机制不变）          -> preserve: ported")?;
    writeln!(
        w,
        "#   ported（承载机制换了一个）  -> rename:   ported —— 判据保留，承载它的机制在 Rust 版换了一个"
    )?;
    writeln!(
        w,
        "#   covered-by-golden           -> preserve: covered-by-golden"
    )?;
    writeln!(
        w,
        "#   not-applicable-with-proof   -> remove:   not-applicable-with-proof"
    )?;
    writeln!(
        w,
        "# 三档写在 notes 开头，机器可读（`grep -c 'notes: \"ported '` 等，见 recount）。"
    )?;
    writeln!(w, "#")?;
    writeln!(w, "# label 粒度与取向（repository contract §4）：")?;
    writeln!(
        w,
        "# label / tier / owner / 初始 target 取**文件**粒度。label 取保守方向 —— 只要该文件的被测面在 v3 里"
    )?;
    writeln!(
        w,
        "# 有任一处换机制，整个文件标 `替代`，绝不把换了机制的东西写成 `parity`。反方向的代价只是把"
    )?;
    writeln!(
        w,
        "# 若干条 parity 条目多标了一次 `替代`，会在 G8 逐条复核时收敛。"
    )?;
    writeln!(
        w,
        "# 本表**不含 `新增`**：每条 entry 都由一个上游 AST 用例生成，按定义都有上游对应物；"
    )?;
    writeln!(
        w,
        "# Rust 侧新起炉灶的测试不属于「上游测试 inventory」，登记在各自立项文档。"
    )?;
    writeln!(w, "#")?;
    writeln!(w, "# 字段约定：")?;
    writeln!(
        w,
        "# - upstream = `<上游文件路径>::<describe 链，用 :: 连接>`，无 describe 时只有文件路径。"
    )?;
    writeln!(
        w,
        "#   **不带行号**（repository contract §8：位置引用只用符号名）；行列号只在 fixtures/tests/upstream-ast-inventory.json 里。"
    )?;
    writeln!(
        w,
        "# - target 初值由用例标题派生；条目闭合时改成亲跑证据的真实 Rust 落点，并由生成器保留。"
    )?;
    writeln!(
        w,
        "# - evidence = fixtures/tests/upstream-ast-inventory.json 的 nodes[] 下标，一一对应，可直接 jq 复核。"
    )?;
    writeln!(
        w,
        "# - status 初值为 todo；只有本轮亲跑证据齐全时改 done，done_evidence 缺失会被生成器与 parity-check 双重拒绝。"
    )?;
    writeln!(w, "#")?;
    writeln!(
        w,
        "# 交叉检查（v3 §1.3 / §28.4）：词法命中 {} vs AST 用例 {}，差值 {:+}。",
        inv.cross_check.lexical_test_hits, inv.cross_check.ast_test_cases, inv.cross_check.delta
    )?;
    writeln!(w, "# 差值逐项闭合，每一项都由本文件 recount 段的命令复算：")?;
    writeln!(
        w,
        "#   词法 {} = 语句位置的 `test(` {} + 1 处正则方法调用 `/secret/i.test(k)`",
        inv.cross_check.lexical_test_hits,
        inv.cross_check.ast_test_cases - inv.totals.each
    )?;
    writeln!(
        w,
        "#     （唯一那处在 agent-computer/tests/control.test.ts；`\\btest\\(` 的词边界会把 `.test(` 一并命中）"
    )?;
    writeln!(
        w,
        "#   AST  {} = 同一批 `test(` {} + {} 处柯里化 `test.each([...])(\"标题\", fn)`",
        inv.cross_check.ast_test_cases,
        inv.cross_check.ast_test_cases - inv.totals.each,
        inv.totals.each
    )?;
    writeln!(
        w,
        "#     （`\\b(test|it)\\(` 匹配不到 `test.each(`，柯里化用例的标题实参在外层调用上）"
    )?;
    writeln!(
        w,
        "#   故 {:+} = +{} − 1。",
        inv.cross_check.delta, inv.totals.each
    )?;
    writeln!(
        w,
        "# describe 侧同理：词法全量 {} vs AST {}，多出来的 1 处在块注释里（supervisor/tests/",
        inv.totals.describe_nodes + 1,
        inv.totals.describe_nodes
    )?;
    writeln!(
        w,
        "# docker.integration.test.ts 的文件头注释写了 `describe.skipIf(runtime === null)`）；行首锚版本的词法命中与 AST 相等。"
    )?;
    writeln!(w, "#")?;
    writeln!(
        w,
        "# 解析器：{} {}（{}）。",
        inv.parser.name, inv.parser.version, inv.parser.source_type
    )?;
    writeln!(w)?;

    writeln!(w, "schema: tests")?;
    writeln!(w, "schema_version: 1")?;
    writeln!(w, "upstream_commit: {UPSTREAM_COMMIT}")?;
    writeln!(w, "generated_by: \"xtask test-inventory\"")?;
    writeln!(w, "recount:")?;

    let g2_files_json =
        serde_json::to_string(&G2_TEST_FILES).context("序列化 G2 test file 集合失败")?;
    let recounts: Vec<(String, &str, String)> = vec![
        (
            "git ls-files '*.test.ts' '*.test.tsx' | wc -l".to_string(),
            "upstream",
            UPSTREAM_TEST_FILE_COUNT.to_string(),
        ),
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\b(test|it)\(' | wc -l"#
                .to_string(),
            "upstream",
            LEXICAL_TEST_HITS.to_string(),
        ),
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\.test\(' | wc -l"#
                .to_string(),
            "upstream",
            "1".to_string(),
        ),
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '^[[:space:]]*test\(' | wc -l"#
                .to_string(),
            "upstream",
            (inv.cross_check.ast_test_cases - inv.totals.each).to_string(),
        ),
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '^[[:space:]]*test\.each\(' | wc -l"#
                .to_string(),
            "upstream",
            inv.totals.each.to_string(),
        ),
        (
            "grep -c '^  - id: ' parity/tests.yaml".to_string(),
            "repo",
            cases.len().to_string(),
        ),
        (
            "jq '[.nodes[] | select(.kind == \"test\")] | length' fixtures/tests/upstream-ast-inventory.json"
                .to_string(),
            "repo",
            cases.len().to_string(),
        ),
        (
            format!(
                "jq --argjson files '{g2_files_json}' '[.nodes[] | select(.kind == \"test\" and (.file as $file | $files | index($file)))] | length' fixtures/tests/upstream-ast-inventory.json"
            ),
            "repo",
            G2_TEST_CASE_COUNT.to_string(),
        ),
        (
            format!(
                "python3 -c 'import io,json,sys,yaml;files=set(json.loads(sys.argv[1]));doc=yaml.safe_load(io.open(\"parity/tests.yaml\",encoding=\"utf-8\"));entries=[e for e in doc[\"entries\"] if e[\"upstream\"].split(\"::\",1)[0] in files];print(\"done=%d todo=%d in_progress=%d total=%d\"%(sum(e[\"status\"]==\"done\" for e in entries),sum(e[\"status\"]==\"todo\" for e in entries),sum(e[\"status\"]==\"in_progress\" for e in entries),len(entries)))' '{g2_files_json}'"
            ),
            "repo",
            g2_progress.rendered(),
        ),
        (
            "jq '[.nodes[] | select(.kind == \"describe\")] | length' fixtures/tests/upstream-ast-inventory.json"
                .to_string(),
            "repo",
            inv.totals.describe_nodes.to_string(),
        ),
        // describe 侧的交叉检查：词法全量 230 与 AST 229 差 1，那 1 处是块注释里的
        // `describe.skipIf(...)`（supervisor/tests/docker.integration.test.ts 的文件头注释）。
        // 下面三条把"多出来的到底是哪一处"钉成可复算的，而不是留一句"注释里有一处"。
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\bdescribe(\.[a-zA-Z]+)*\(' | wc -l"#
                .to_string(),
            "upstream",
            (inv.totals.describe_nodes + 1).to_string(),
        ),
        (
            r#"git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '^[[:space:]]*describe(\.[a-zA-Z]+)*\(' | wc -l"#
                .to_string(),
            "upstream",
            inv.totals.describe_nodes.to_string(),
        ),
        (
            r#"grep -cE '^ \* .*describe\.skipIf' supervisor/tests/docker.integration.test.ts"#
                .to_string(),
            "upstream",
            "1".to_string(),
        ),
        (
            "jq -r '[.nodes[].file] | unique | length' fixtures/tests/upstream-ast-inventory.json"
                .to_string(),
            "repo",
            UPSTREAM_TEST_FILE_COUNT.to_string(),
        ),
        (
            "grep -c '^    label: parity$' parity/tests.yaml".to_string(),
            "repo",
            label_counts.get("parity").copied().unwrap_or(0).to_string(),
        ),
        (
            "grep -c '^    label: 替代$' parity/tests.yaml".to_string(),
            "repo",
            label_counts.get("替代").copied().unwrap_or(0).to_string(),
        ),
        (
            "grep -c '^    label: 新增$' parity/tests.yaml".to_string(),
            "repo",
            "0".to_string(),
        ),
        (
            "grep -c '^    notes: \"ported ' parity/tests.yaml".to_string(),
            "repo",
            tier_counts.get("ported").copied().unwrap_or(0).to_string(),
        ),
        (
            "grep -c '^    notes: \"covered-by-golden ' parity/tests.yaml".to_string(),
            "repo",
            tier_counts
                .get("covered-by-golden")
                .copied()
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "grep -c '^    notes: \"not-applicable-with-proof ' parity/tests.yaml".to_string(),
            "repo",
            tier_counts
                .get("not-applicable-with-proof")
                .copied()
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "grep -c '^    status: todo$' parity/tests.yaml".to_string(),
            "repo",
            cases
                .len()
                .checked_sub(progress.len())
                .context("test-inventory: 进度条目数超过 AST 用例数")?
                .to_string(),
        ),
        (
            r#"grep -oE '^    upstream: "[^:"]+' parity/tests.yaml | sed 's/.*"//' | sort -u | wc -l"#
                .to_string(),
            "repo",
            UPSTREAM_TEST_FILE_COUNT.to_string(),
        ),
        (
            "grep -cE '^    test_id: T-TEST-[0-9]{4}$' parity/tests.yaml".to_string(),
            "repo",
            cases.len().to_string(),
        ),
        (
            // 行首锚 + 四个空格：不加锚的话这条命令自己的源码字符串会被数进去（实测 106 而不是 105）。
            r#"grep -cE '^    FileRule \{ file: "' crates/openbot-testkit/src/xtask/test_inventory.rs"#
                .to_string(),
            "repo",
            UPSTREAM_TEST_FILE_COUNT.to_string(),
        ),
    ];
    for (command, cwd, expect) in &recounts {
        writeln!(w, "  - command: {}", yaml_quote(command))?;
        writeln!(w, "    cwd: {cwd}")?;
        writeln!(w, "    expect: {expect}")?;
    }
    writeln!(w)?;
    writeln!(w, "entries:")?;

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut used_progress: HashSet<String> = HashSet::new();
    let mut current_file = "";
    for (ordinal, case) in cases.iter().enumerate() {
        let rule = rule_for(&case.file);
        if current_file != rule.file {
            current_file = rule.file;
            writeln!(
                w,
                "  # ---------------------------------------------------------------------------"
            )?;
            writeln!(
                w,
                "  # {} —— owner {} / {} / {}",
                rule.file,
                rule.owner,
                rule.tier.as_str(),
                rule.label.as_str()
            )?;
            writeln!(
                w,
                "  # ---------------------------------------------------------------------------"
            )?;
        }

        let file_slug = slugify(
            rule.file
                .trim_end_matches(".test.ts")
                .trim_end_matches(".test.tsx"),
            64,
        );
        let chain_slug = case
            .describe_chain
            .iter()
            .map(|c| slugify(c, 40))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("--");
        let title_slug =
            if case.title_kind == TitleKind::Dynamic || case.title_kind == TitleKind::Missing {
                format!("{}-title", case.title_kind.as_str())
            } else {
                slugify(&case.title, 56)
            };
        let mut id = [file_slug.as_str(), chain_slug.as_str(), title_slug.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("--");
        if id.is_empty() {
            id = format!("case-{}", case.index);
        }
        let base_id = id.clone();
        let mut dup = 2;
        while !seen_ids.insert(id.clone()) {
            id = format!("{base_id}-{dup}");
            dup += 1;
        }

        let upstream = if case.describe_chain.is_empty() {
            rule.file.to_string()
        } else {
            format!("{}::{}", rule.file, case.describe_chain.join("::"))
        };
        // 校验器规则 7：upstream 不得以裸行号结尾。describe 标题理论上可以以 `:12` 结尾，
        // 真出现就当场炸而不是悄悄改写 —— 改写会让 ledger 与上游对不上。
        if upstream
            .rsplit(':')
            .next()
            .is_some_and(|tail| !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()))
            && upstream.contains(':')
        {
            bail!(
                "test-inventory: 生成的 upstream `{upstream}` 以裸行号形态结尾，会撞上 parity-check 规则 7；\
                 请在 render_ledger 里为该 describe 标题单列处理"
            );
        }

        let fn_name = rust_fn_name(
            if case.title.is_empty() {
                case.title_kind.as_str()
            } else {
                &case.title
            },
            56,
        );
        let target = format!("{}::tests::{}", rule.target_module, fn_name);
        let overlay = progress.get(&id);
        if overlay.is_some() {
            used_progress.insert(id.clone());
        }

        let mut markers: Vec<&str> = Vec::new();
        if case.skip {
            markers.push("skip");
        }
        if case.only {
            markers.push("only");
        }
        if case.each {
            markers.push("each（表驱动，一条声明展开成多个运行期用例）");
        }
        if case.conditional {
            markers.push("conditional（跳过与否取决于运行期条件，静态不可知）");
        }
        if case.title_kind != TitleKind::String {
            markers.push(match case.title_kind {
                TitleKind::Template => "标题是模板串，插值段渲染为 ${?}",
                TitleKind::Dynamic => "标题不是字面量，静态解析取不到",
                TitleKind::Missing => "调用没有首实参",
                TitleKind::String => unreachable!(),
            });
        }

        let mut notes = format!("{} —— {}", rule.tier.as_str(), rule.reason);
        let _ = write!(notes, "上游用例标题：{}", display_title(case));
        if !markers.is_empty() {
            let _ = write!(notes, "。AST 标记：{}", markers.join("、"));
        }
        notes.push('。');

        writeln!(w, "  - id: {}", yaml_quote(&id))?;
        writeln!(w, "    upstream: {}", yaml_quote(&upstream))?;
        writeln!(w, "    label: {}", rule.label.as_str())?;
        writeln!(
            w,
            "    target: {}",
            yaml_quote(overlay.map_or(target.as_str(), |item| item.target.as_str()))
        )?;
        writeln!(w, "    owner: {}", rule.owner)?;
        writeln!(w, "    test_id: {TEST_ID_PREFIX}{:04}", ordinal + 1)?;
        let default_migration_rule = rule.tier.migration_rule(rule.label);
        writeln!(
            w,
            "    migration_rule: {}",
            yaml_quote(overlay.map_or(default_migration_rule.as_str(), |item| {
                item.migration_rule.as_str()
            }))
        )?;
        writeln!(
            w,
            "    status: {}",
            overlay.map_or("todo", |item| item.status.as_str())
        )?;
        writeln!(
            w,
            "    evidence: {}",
            yaml_quote(&format!(
                "fixtures/tests/upstream-ast-inventory.json::nodes[{}]（cargo xtask test-inventory，oxc_parser {}）",
                case.index, OXC_VERSION
            ))
        )?;
        if let Some(done_evidence) = overlay.and_then(|item| item.done_evidence.as_deref()) {
            writeln!(w, "    done_evidence: {}", yaml_quote(done_evidence))?;
        }
        writeln!(w, "    notes: {}", yaml_quote(&notes))?;
    }

    if used_progress.len() != progress.len() {
        let missing = progress
            .keys()
            .filter(|id| !used_progress.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        bail!(
            "test-inventory: {} 个已有非 todo ID 在重建 AST inventory 后消失；拒绝丢证据：{}",
            missing.len(),
            missing.join(", ")
        );
    }

    if cases.len() > 9999 {
        bail!(
            "test-inventory: 用例数 {} 超过 T-TEST-#### 的四位容量，需要先扩 test_id 位宽（校验器规则 6）",
            cases.len()
        );
    }

    Ok(out)
}

fn display_title(case: &RawNode) -> String {
    match case.title_kind {
        TitleKind::String | TitleKind::Template => format!("「{}」", case.title),
        TitleKind::Dynamic => "（非字面量，静态取不到）".to_string(),
        TitleKind::Missing => "（无首实参）".to_string(),
    }
}

// ---------------------------------------------------------------------------
// 写盘
// ---------------------------------------------------------------------------

/// 统一走 LF：仓根 `.gitattributes` 对文本强制 LF，Windows 上用 `writeln!` 攒出来的也是 `\n`，
/// 但读进来再写出去的路径上仍然显式 normalize 一次，避免 CRLF 混入。
fn write_text(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建目录 {} 失败", parent.display()))?;
    }
    let normalized = content.replace("\r\n", "\n");
    std::fs::write(path, normalized.as_bytes())
        .with_context(|| format!("写 {} 失败", path.display()))
}

fn write_json(path: &Path, inventory: &Inventory) -> Result<()> {
    let mut json = serde_json::to_string_pretty(inventory).context("序列化 inventory 失败")?;
    json.push('\n');
    write_text(path, &json)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 产物里写着"用 oxc_parser <版本> 解析"，这个版本必须真的是 Cargo 解析出来的那个。
    /// 反面（没有这条）：升 oxc 之后产物继续声称旧版本，而声明与事实的偏差正是本轮要消灭的。
    #[test]
    fn oxc_version_matches_workspace_manifest() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/openbot-testkit 的祖父目录 = 仓根")
            .join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("读仓根 Cargo.toml");
        let needle = format!("oxc_parser = \"{OXC_VERSION}\"");
        assert!(
            text.contains(&needle),
            "仓根 Cargo.toml 里找不到 `{needle}`；OXC_VERSION 与 [workspace.dependencies] 漂了"
        );
        // 正向对照：这条断言不是恒真的 —— 一个不存在的版本必须找不到。
        assert!(
            !text.contains("oxc_parser = \"0.0.0-never\""),
            "对照失败：contains() 在任意串上都为真，说明断言无效"
        );
    }

    /// `it` 在固定 commit 的上游是零命中（实测
    /// `git ls-files '*.test.ts' '*.test.tsx' | xargs grep -hoE '\bit\(' | wc -l` = 0），
    /// 所以它在 CASE_ROOTS 里是一条**没有被上游行使过**的分支。这条测试把它行使一遍 ——
    /// 否则"上游哪天开始用 it 也不会成为盲区"只是注释里的愿望，不是被证明过的行为。
    #[test]
    fn it_root_is_recognised_even_though_upstream_never_uses_it() {
        let source = "describe(\"g\", () => {\n  it(\"does a thing\", () => {});\n  it.each([[1]])(\"table %p\", (n) => {});\n});\n";
        let nodes = extract_file("it.test.ts", source).expect("解析样例");
        let tests: Vec<&RawNode> = nodes.iter().filter(|n| n.kind == NodeKind::Test).collect();
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].title, "does a thing");
        assert_eq!(tests[0].describe_chain, vec!["g".to_string()]);
        assert_eq!(tests[1].callee, "it.each(…)");
        assert!(tests[1].each);
        // 负向对照：同名前缀的普通标识符不得被认成用例根。
        let other = extract_file("x.test.ts", "iterate(\"nope\", () => {});\n").expect("解析样例");
        assert!(
            other.is_empty(),
            "`iterate(` 不该被当成 `it(`，实得 {other:?}"
        );
    }

    /// FILE_RULES 恰好 105 行且路径互不重复。
    #[test]
    fn file_rules_cover_exactly_the_upstream_baseline() {
        assert_eq!(FILE_RULES.len(), UPSTREAM_TEST_FILE_COUNT);
        let unique: std::collections::BTreeSet<&str> = FILE_RULES.iter().map(|r| r.file).collect();
        assert_eq!(
            unique.len(),
            UPSTREAM_TEST_FILE_COUNT,
            "FILE_RULES 里有重复路径"
        );
    }

    /// 移交指南里的“G2 相关 234 条”必须是一张封闭分区，不是碰巧加出同一个数字。
    #[test]
    fn g2_test_inventory_is_exactly_234() {
        let cited: std::collections::BTreeSet<&str> = FILE_RULES
            .iter()
            .filter(|rule| rule.reason.contains("§6") || rule.reason.contains("§8"))
            .map(|rule| rule.file)
            .collect();
        let g2: std::collections::BTreeSet<&str> = G2_TEST_FILES.into_iter().collect();
        let deferred: std::collections::BTreeSet<&str> =
            G6_DEFERRED_G2_GUI_FILES.into_iter().collect();
        assert!(g2.is_disjoint(&deferred), "一个文件不能同时归 G2 与 G6");
        let partition: std::collections::BTreeSet<&str> = g2.union(&deferred).copied().collect();
        assert_eq!(
            partition, cited,
            "§6/§8 引用文件必须恰好分到 G2 或显式延后的 G6，不能漏也不能多"
        );

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/openbot-testkit 的祖父目录 = 仓根");
        let fixture =
            std::fs::read_to_string(root.join("fixtures/tests/upstream-ast-inventory.json"))
                .expect("读取固定上游 AST fixture");
        let inventory: serde_json::Value = serde_json::from_str(&fixture).expect("fixture 是 JSON");
        let nodes = inventory["nodes"].as_array().expect("fixture.nodes 是数组");
        let count = |files: &std::collections::BTreeSet<&str>| {
            nodes
                .iter()
                .filter(|node| {
                    node["kind"].as_str() == Some("test")
                        && node["file"]
                            .as_str()
                            .is_some_and(|file| files.contains(file))
                })
                .count()
        };

        assert_eq!(count(&g2), G2_TEST_CASE_COUNT);
        assert_eq!(count(&deferred), G6_DEFERRED_G2_GUI_CASE_COUNT);
        assert_eq!(count(&cited), G2_SECTION_REFERENCED_TEST_CASE_COUNT);
        assert_eq!(
            G2_TEST_CASE_COUNT + G6_DEFERRED_G2_GUI_CASE_COUNT,
            G2_SECTION_REFERENCED_TEST_CASE_COUNT
        );
    }

    /// owner 必须落在 v3 §5.1 的十个 crate 内（parity-check 规则 3 在 ledger 上也会查一遍，
    /// 这里提前到编译-测试期，免得跑完全流程才发现）。
    #[test]
    fn file_rule_owners_are_within_the_ten_crates() {
        const OWNERS: [&str; 10] = [
            "openbot-contracts",
            "openbot-domain",
            "openbot-application",
            "openbot-infra",
            "openbot-agent",
            "openbot-computer",
            "openbot-server",
            "openbot-ui",
            "openbot-desktop",
            "openbot-testkit",
        ];
        for rule in &FILE_RULES {
            assert!(
                OWNERS.contains(&rule.owner),
                "{} 的 owner `{}` 不在十个 crate 内",
                rule.file,
                rule.owner
            );
            assert!(!rule.reason.is_empty(), "{} 缺裁决理由", rule.file);
        }
    }

    /// v3 §3.5 逐字点名的那条必须是 not-applicable-with-proof，不能被顺手改成 ported。
    #[test]
    fn worker_status_is_not_applicable_with_proof() {
        let rule = FILE_RULES
            .iter()
            .find(|r| r.file == "worker/tests/status.test.ts")
            .expect("worker/tests/status.test.ts 必须在表里");
        assert_eq!(rule.tier, Tier::NotApplicableWithProof);
        // 正向对照：同一个查找在一个确定是 ported 的文件上给出不同答案。
        let other = FILE_RULES
            .iter()
            .find(|r| r.file == "server/tests/schema.test.ts")
            .expect("server/tests/schema.test.ts 必须在表里");
        assert_eq!(other.tier, Tier::Ported);
    }

    #[test]
    fn classifies_plain_and_curried_calls() {
        let source = r#"
describe("outer", () => {
  test("plain case", () => {});
  test.each([[1], [2]])("table case %p", (n) => {});
  describe.skipIf(true)("conditional group", () => {
    test("nested case", () => {});
  });
});
const re = /x/;
if (re.test("x")) {
}
"#;
        let nodes = extract_file("sample.test.ts", source).expect("解析样例");
        let tests: Vec<&RawNode> = nodes.iter().filter(|n| n.kind == NodeKind::Test).collect();
        let describes: Vec<&RawNode> = nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Describe)
            .collect();

        // `re.test("x")` 不得被认成用例（词法 grep 会数到它）。
        assert_eq!(
            tests.len(),
            3,
            "实得 {:?}",
            tests.iter().map(|n| &n.title).collect::<Vec<_>>()
        );
        assert_eq!(describes.len(), 2);

        assert_eq!(tests[0].title, "plain case");
        assert_eq!(tests[0].describe_chain, vec!["outer".to_string()]);

        // 柯里化只产生一条，而且标题取的是外层调用的首实参。
        assert_eq!(tests[1].title, "table case %p");
        assert!(tests[1].each);
        assert_eq!(tests[1].callee, "test.each(…)");

        assert_eq!(tests[2].title, "nested case");
        assert_eq!(
            tests[2].describe_chain,
            vec!["outer".to_string(), "conditional group".to_string()]
        );

        assert!(describes[1].skip, "describe.skipIf 计入 skip");
        assert!(describes[1].conditional);
    }

    #[test]
    fn template_titles_render_placeholders() {
        let source = "test(`a ${1} b`, () => {});\n";
        let nodes = extract_file("t.test.ts", source).expect("解析样例");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].title, "a ${?} b");
        assert_eq!(nodes[0].title_kind, TitleKind::Template);
    }

    #[test]
    fn non_literal_titles_are_marked_dynamic_not_invented() {
        let source = "const name = \"x\";\ntest(name, () => {});\n";
        let nodes = extract_file("t.test.ts", source).expect("解析样例");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].title_kind, TitleKind::Dynamic);
        assert_eq!(nodes[0].title, "");
    }

    #[test]
    fn parse_errors_are_fatal_not_skipped() {
        let err = extract_file("broken.test.ts", "test(\"unclosed\", () => {\n")
            .expect_err("语法错误必须炸，不能静默跳过");
        let text = format!("{err:#}");
        assert!(text.contains("broken.test.ts"), "实得 {text}");
        // 正向对照：同一条路径在合法源码上必须不炸。
        extract_file("ok.test.ts", "test(\"fine\", () => {});\n").expect("合法源码不该报错");
    }

    #[test]
    fn line_col_is_one_based() {
        let src = "a\nbb\nccc";
        let starts = line_starts(src);
        assert_eq!(line_col(&starts, 0), (1, 1));
        assert_eq!(line_col(&starts, 2), (2, 1));
        assert_eq!(line_col(&starts, 5), (3, 1));
    }

    #[test]
    fn yaml_quote_escapes_quotes_and_backslashes() {
        assert_eq!(yaml_quote(r#"a"b\c"#), "\"a\\\"b\\\\c\"");
        assert_eq!(yaml_quote("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn regeneration_preserves_only_evidenced_non_todo_progress() {
        let source = r#"
entries:
  - id: todo-case
    target: generated::todo
    migration_rule: "preserve: ported"
    status: todo
  - id: done-case
    target: real::integration::test
    migration_rule: "rename: ported"
    status: done
    done_evidence: "cargo test => 1/0/0"
  - id: active-case
    target: real::work_in_progress
    migration_rule: "preserve: ported"
    status: in_progress
"#;
        let progress = parse_progress_overlays(source).expect("合法进度 overlay");
        assert_eq!(progress.len(), 2);
        assert!(!progress.contains_key("todo-case"));
        assert_eq!(
            progress.get("done-case"),
            Some(&ProgressOverlay {
                target: "real::integration::test".to_owned(),
                migration_rule: "rename: ported".to_owned(),
                status: "done".to_owned(),
                done_evidence: Some("cargo test => 1/0/0".to_owned()),
            })
        );
        assert_eq!(
            progress
                .get("active-case")
                .expect("in_progress 也不能被重置")
                .status,
            "in_progress"
        );
    }

    #[test]
    fn regeneration_rejects_done_without_evidence_and_duplicate_progress_ids() {
        let missing = r#"
entries:
  - id: done-case
    target: real::test
    migration_rule: "preserve: ported"
    status: done
"#;
        assert!(
            parse_progress_overlays(missing)
                .unwrap_err()
                .to_string()
                .contains("缺非空 done_evidence")
        );

        let duplicate = r#"
entries:
  - id: same
    target: real::one
    migration_rule: "preserve: ported"
    status: in_progress
  - id: same
    target: real::two
    migration_rule: "preserve: ported"
    status: in_progress
"#;
        assert!(
            parse_progress_overlays(duplicate)
                .unwrap_err()
                .to_string()
                .contains("重复进度 ID")
        );
    }

    #[test]
    fn slug_and_fn_name_are_stable() {
        assert_eq!(
            slugify("rejects a non-object root: %p", 64),
            "rejects-a-non-object-root-p"
        );
        assert_eq!(rust_fn_name("42 things", 64), "case_42_things");
        assert_eq!(rust_fn_name("", 64), "unnamed_case");
    }
}
