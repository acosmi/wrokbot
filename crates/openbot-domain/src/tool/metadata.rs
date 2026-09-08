//! tool metadata（v3 §8.2）：每个 tool 固定声明的那一组字段，以及**未知 effect 的
//! fail-closed 由类型承担**。
//!
//! # §8.2 的字段清单，逐条落点
//!
//! | §8.2 逐字 | 落点 |
//! | --- | --- |
//! | `name` / `schema_hash` / `catalog_generation` | [`ToolMetadata::name`] / [`ToolMetadata::schema_hash`] / [`ToolMetadata::catalog_generation`] |
//! | `effect = read \| write \| execute \| network \| credential` | [`Effect`]，分类结果见 [`EffectClassification`] |
//! | `idempotency = idempotent \| keyed \| non_idempotent` | [`Idempotency`] |
//! | `parallel_safe` | [`ToolMetadata::parallel_safe`] |
//! | `timeout/deadline` | [`ToolMetadata::timeout`] |
//! | `approval_class` | [`ApprovalClass`] |
//! | `sandbox_requirement` | [`SandboxRequirement`] |
//! | `input/output/redaction limits` | [`ToolLimits`] |
//! | `resource_lock keys` | [`ToolMetadata::resource_locks`] |
//!
//! # 未知 effect：**没有 `Unknown` 变体**，而且没有会返回 `Read` 的解析入口
//!
//! §8.2 逐字：「未知 effect 固定按 write/execute；MCP annotations、server description、
//! 工具名称和模型声明**都不是可信分类来源**。」
//!
//! 这句话有三种实现方式，本模块选了第三种，理由要写清楚：
//!
//! 1. `Effect::Unknown` 变体 + 每个消费点自己判 —— **否决**。它把 fail-closed 变成一条
//!    需要在 N 个 match 里各写对一次的纪律，而漏掉一处的表现是"未知被当成最宽松档放行"。
//! 2. `FromStr -> Result<Effect, _>` —— **否决**。返回 `Result` 的形状会招来
//!    `.unwrap_or(Effect::Read)`：一次看起来很自然的降级，效果是把"我不知道这是什么"
//!    渲染成"这是只读的"。这不是假想 —— 它正是 repository contract 记着的那类"未知悄悄变成安全"。
//! 3. **本模块的做法**：从不可信字符串到 [`Effect`] 的唯一入口是
//!    [`EffectClassification::classify`]，它**不会失败**，也**不可能返回 [`Effect::Read`]**
//!    （除非输入逐字节等于 `"read"`），并且在降级发生时留下
//!    [`EffectSource::DowngradedFromUnrecognized`] 这条标记。
//!
//! 于是"未知 effect 不会变成 read"是类型与函数签名的性质，不是复核清单上的一行。
//!
//! ## 为什么降级到 `Execute` 而不是 `Write`
//!
//! §8.2 写的是"按 write/execute"，两者都合规，所以这是一次需要给理由的裁决：
//! **write 是对已知数据的有界修改，execute 是无界的副作用**。把一个来路不明的工具按
//! execute 处理，得到的是两者中更严的那套约束（approval、sandbox、非幂等假设）；反过来
//! 按 write 处理，就要在"它其实会起进程"的世界里发现自己少了一道门。
//! [`UNRECOGNIZED_EFFECT_FALLBACK`] 是这条裁决的唯一落点。
//!
//! ## 为什么是**精确**匹配（`"READ"` 也算未知）
//!
//! 这些字符串来自 MCP annotation、server description 这类**明确不可信**的来源。对不可信
//! 词汇做大小写归一、trim、别名映射，等于扩大"能被认成已知档"的输入集合，而扩大的每一寸
//! 都在降低分类的可信度。已知档的取值由本仓自己的 catalog 写死，精确匹配足够；认不出来的
//! 一律降级，代价只是多一道审批。

use core::time::Duration;

pub use openbot_contracts::ids::CatalogGeneration;

use crate::audit::hash::Sha256Digest;

/// 工具的 effect 分类。**封闭五档，没有 `Unknown`。**
///
/// 取值与 §8.2 逐字一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// 只读：不改变任何状态。
    Read,
    /// 写：对已知数据的有界修改。
    Write,
    /// 执行：起进程 / 跑命令 / 无界副作用。
    Execute,
    /// 网络出站。
    Network,
    /// 触碰凭据。
    Credential,
}

impl Effect {
    /// 稳定字面量。同时是 catalog 里声明 effect 时的合法取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Network => "network",
            Self::Credential => "credential",
        }
    }

    /// 这次调用会不会"做事"（acting）。
    ///
    /// 判据：**除 [`Self::Read`] 之外全是**。§17.2 条 2「任一 acting effect 之前都有 durable
    /// decision + attempt」用的就是这个谓词，所以它必须是穷举 match 而不是取反某个白名单 ——
    /// 新增一档 effect 时，作者会被编译器逼着在这里表态。
    #[must_use]
    pub const fn is_acting(self) -> bool {
        match self {
            Self::Read => false,
            Self::Write | Self::Execute | Self::Network | Self::Credential => true,
        }
    }
}

/// 全部 effect 档位。顺序与 §8.2 的列举一致。
pub const ALL_EFFECTS: &[Effect] = &[
    Effect::Read,
    Effect::Write,
    Effect::Execute,
    Effect::Network,
    Effect::Credential,
];

/// 认不出来的 effect 字符串一律降级到这一档。裁决理由见模块文档。
pub const UNRECOGNIZED_EFFECT_FALLBACK: Effect = Effect::Execute;

/// 这一档 effect 是**声明**来的还是**降级**来的。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectSource {
    /// 声明的字符串逐字节命中了某一档。
    Declared,
    /// 认不出来，按 [`UNRECOGNIZED_EFFECT_FALLBACK`] 降级。
    DowngradedFromUnrecognized,
}

impl EffectSource {
    /// 稳定字面量（进审计 payload 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::DowngradedFromUnrecognized => "downgraded_from_unrecognized",
        }
    }
}

/// 一次 effect 分类的结果：档位 + 它的来源。
///
/// 两者必须一起走。只留档位就把"这个工具的分类根本没人说得清"这条信息删掉了 —— 而那正是
/// 审计里最该看见的一条（[`crate::audit::payload::AuditFact::EffectDowngraded`] 是它的落点）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClassification {
    effect: Effect,
    source: EffectSource,
}

impl EffectClassification {
    /// 从**不可信**字符串分类。**不会失败，也不会把未知判成 [`Effect::Read`]。**
    ///
    /// 精确匹配（不 trim、不改大小写、不认别名），理由见模块文档。
    #[must_use]
    pub fn classify(declared: &str) -> Self {
        for effect in ALL_EFFECTS {
            if effect.as_str() == declared {
                return Self {
                    effect: *effect,
                    source: EffectSource::Declared,
                };
            }
        }
        Self {
            effect: UNRECOGNIZED_EFFECT_FALLBACK,
            source: EffectSource::DowngradedFromUnrecognized,
        }
    }

    /// 由第一方 catalog 直接声明（不经字符串）。
    ///
    /// 这条入口存在是因为本仓自己的内建工具不需要绕一圈字符串；它**不是**给外部数据用的 ——
    /// 外部数据的唯一入口是 [`Self::classify`]。
    #[must_use]
    pub const fn declared(effect: Effect) -> Self {
        Self {
            effect,
            source: EffectSource::Declared,
        }
    }

    /// 档位。
    #[must_use]
    pub const fn effect(self) -> Effect {
        self.effect
    }

    /// 来源。
    #[must_use]
    pub const fn source(self) -> EffectSource {
        self.source
    }

    /// 是不是降级来的。
    #[must_use]
    pub const fn was_downgraded(self) -> bool {
        matches!(self.source, EffectSource::DowngradedFromUnrecognized)
    }
}

/// 幂等性档位（§8.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Idempotency {
    /// 重放安全：同样的调用做两次与做一次等价。
    Idempotent,
    /// 带幂等键：**只有在重放时复用同一个键**才安全。键缺席时按不安全处理
    /// （见 [`super::commit`]）。
    Keyed,
    /// 非幂等：重放会产生第二次副作用。
    NonIdempotent,
}

impl Idempotency {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idempotent => "idempotent",
            Self::Keyed => "keyed",
            Self::NonIdempotent => "non_idempotent",
        }
    }
}

/// 审批档位（§8.2 `approval_class`）。
///
/// 它只回答"**什么时候**要问人"，**不回答"要不要写 decision"**。§8.3 的 dry-run 条款给了
/// 同构的理由：改变执行拦截不等于跳过 decision/audit。所以 [`Self::NotRequired`] 的语义
/// 严格是"不必等人点头"，不是"这次不留记录"。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApprovalClass {
    /// 不需要人工审批。
    NotRequired,
    /// 每个 run 里问一次，之后同 run 内复用（仍受 [`super::approval`] 的绑定约束）。
    OncePerRun,
    /// 每次调用都问。
    EveryCall,
}

impl ApprovalClass {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::OncePerRun => "once_per_run",
            Self::EveryCall => "every_call",
        }
    }

    /// 这一档是否要求在执行前拿到一份人工批准。
    #[must_use]
    pub const fn requires_human_approval(self) -> bool {
        match self {
            Self::NotRequired => false,
            Self::OncePerRun | Self::EveryCall => true,
        }
    }
}

/// 沙箱要求（§8.2 `sandbox_requirement`）。
///
/// **没有从字符串解析的入口**：与 effect 不同，沙箱要求从来不来自 MCP annotation 这类
/// 外部自述 —— 它是本仓 catalog 对该工具的第一方判断。留一个 `parse` 就是给"外部工具自称
/// 不需要沙箱"开一扇门。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SandboxRequirement {
    /// 可以在宿主进程内直接跑（纯计算、纯本地读）。
    None,
    /// 必须在沙箱里跑。
    Required,
    /// 必须在沙箱里跑，且不给出站网络。
    RequiredNoEgress,
}

impl SandboxRequirement {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Required => "required",
            Self::RequiredNoEgress => "required_no_egress",
        }
    }
}

/// 输入 / 输出 / 脱敏三个字节上限（§8.2 `input/output/redaction limits`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolLimits {
    /// 实参 JSON 的字节上限。超限在管线的 validation 段就拒，**不进 policy、不写 decision**
    /// （§15.3：malformed payload 不产生 acting decision）。
    pub max_input_bytes: u32,
    /// 工具结果的字节上限。
    pub max_output_bytes: u32,
    /// **给模型看的**那份脱敏结果的字节上限。
    ///
    /// 必须 `<= max_output_bytes`：模型可见的那份是完整结果的投影，投影比原件还大说明有人
    /// 把两个概念搞混了。由 [`ToolMetadata::validate`] 强制。
    pub max_model_visible_bytes: u32,
}

/// 资源锁键（§8.2 `resource_lock keys`）。
///
/// 语义：两次持有同一个键的调用不得并发。键本身是不透明标识（例如
/// `"computer:c-1:tab:t-9"`），领域层不解释它的结构 —— 解释结构就等于在这里第二次实现
/// 一遍作用域规则，而作用域的真源是 §10.1 的 `ComputerSecurityScope`。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceLockKey(String);

impl ResourceLockKey {
    /// 校验并构造。
    ///
    /// # Errors
    ///
    /// 空串或超过 256 字节时返回 [`ToolMetadataError`]。
    pub fn new(value: impl Into<String>) -> Result<Self, ToolMetadataError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ToolMetadataError::EmptyResourceLockKey);
        }
        if value.len() > 256 {
            return Err(ToolMetadataError::ResourceLockKeyTooLong { found: value.len() });
        }
        Ok(Self(value))
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 工具名。
///
/// 与 `openbot_contracts::ids` 的十五个 ID 不同，它**有**格式约束：它同时是模型看到的
/// tool name 和 catalog 的键，而模型侧的 tool name 在各家 provider 上都有字符集限制。
/// 允许集合取最窄的交集：ASCII 字母数字加 `_` `-` `.`，1..=128 字节。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolName(String);

impl ToolName {
    /// 名字的字节上限。
    pub const MAX_BYTES: usize = 128;

    /// 校验并构造。
    ///
    /// # Errors
    ///
    /// 空、超长、含允许集合之外的字符时返回 [`ToolMetadataError`]。
    pub fn new(value: impl Into<String>) -> Result<Self, ToolMetadataError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ToolMetadataError::EmptyToolName);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ToolMetadataError::ToolNameTooLong { found: value.len() });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(ToolMetadataError::ToolNameHasIllegalCharacter);
        }
        Ok(Self(value))
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一个工具在 catalog 里的完整声明（§8.2）。
///
/// # 为什么字段全公开、且**没有** `Default`
///
/// §8.2 说的是"每个 tool **固定声明**"这一整组字段。`Default` 会让"少声明一项"变成一次
/// 无声的选择（少写 `sandbox_requirement` 就默认不要沙箱），而字段全公开 + 无 `Default`
/// 意味着**新增一个字段会让所有构造点编译失败**，作者必须逐个表态。这比任何"记得补上"的
/// 注释都可靠。
///
/// 跨字段的约束由 [`Self::validate`] 承担，并且它不是可选步骤 —— 管线的第一段
/// （`super::pipeline::Requested::validate`）必调它，跳过这一段就拿不到后续任何一个状态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolMetadata {
    /// 工具名，同时是模型侧的 tool name。
    pub name: ToolName,
    /// 入参 schema 的摘要。schema 变了它就变，于是旧的 approval 自动失效（§8.5）。
    pub schema_hash: Sha256Digest,
    /// 这份声明属于哪一代 catalog。
    pub catalog_generation: CatalogGeneration,
    /// effect 分类结果（含"是不是降级来的"）。
    pub effect: EffectClassification,
    /// 幂等性档位。
    pub idempotency: Idempotency,
    /// 是否允许与其它调用并行。
    pub parallel_safe: bool,
    /// 单次调用的时间预算。
    pub timeout: Duration,
    /// 审批档位。
    pub approval_class: ApprovalClass,
    /// 沙箱要求。
    pub sandbox: SandboxRequirement,
    /// 三个字节上限。
    pub limits: ToolLimits,
    /// 资源锁键。空表示这次调用不与任何东西互斥。
    pub resource_locks: Vec<ResourceLockKey>,
}

impl ToolMetadata {
    /// 跨字段校验。
    ///
    /// # Errors
    ///
    /// 见 [`ToolMetadataError`]。三条规则各有理由：
    ///
    /// - **`timeout` 必须为正**：零预算的工具永远超时，等于一条声明出来的死代码；
    /// - **`max_model_visible_bytes <= max_output_bytes`**：模型可见的那份是投影，不能比原件大；
    /// - **上限不得为 0**：0 字节的输入上限会让每一次调用都在 validation 段被拒，而症状是
    ///   "这个工具从来没成功过"，排查时最不容易想到的地方就是它自己的声明。
    pub fn validate(&self) -> Result<(), ToolMetadataError> {
        if self.timeout.is_zero() {
            return Err(ToolMetadataError::ZeroTimeout);
        }
        if self.limits.max_input_bytes == 0 || self.limits.max_output_bytes == 0 {
            return Err(ToolMetadataError::ZeroLimit);
        }
        if self.limits.max_model_visible_bytes > self.limits.max_output_bytes {
            return Err(ToolMetadataError::ModelVisibleLimitExceedsOutputLimit);
        }
        Ok(())
    }
}

/// tool metadata 的构造 / 校验失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolMetadataError {
    /// 工具名为空。
    #[error("tool_name_empty")]
    EmptyToolName,
    /// 工具名超过 [`ToolName::MAX_BYTES`]。
    #[error("tool_name_too_long found={found}")]
    ToolNameTooLong {
        /// 实际字节数。
        found: usize,
    },
    /// 工具名含允许集合之外的字符。
    #[error("tool_name_illegal_character")]
    ToolNameHasIllegalCharacter,
    /// 资源锁键为空。
    #[error("resource_lock_key_empty")]
    EmptyResourceLockKey,
    /// 资源锁键过长。
    #[error("resource_lock_key_too_long found={found}")]
    ResourceLockKeyTooLong {
        /// 实际字节数。
        found: usize,
    },
    /// `timeout` 为零。
    #[error("tool_timeout_is_zero")]
    ZeroTimeout,
    /// 某个字节上限为零。
    #[error("tool_limit_is_zero")]
    ZeroLimit,
    /// 模型可见上限超过了输出上限。
    #[error("model_visible_limit_exceeds_output_limit")]
    ModelVisibleLimitExceedsOutputLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ToolMetadata {
        ToolMetadata {
            name: ToolName::new("browser.click").unwrap(),
            schema_hash: Sha256Digest::of(b"schema"),
            catalog_generation: CatalogGeneration::new(3),
            effect: EffectClassification::declared(Effect::Execute),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(30),
            approval_class: ApprovalClass::EveryCall,
            sandbox: SandboxRequirement::Required,
            limits: ToolLimits {
                max_input_bytes: 16 * 1024,
                max_output_bytes: 256 * 1024,
                max_model_visible_bytes: 32 * 1024,
            },
            resource_locks: vec![ResourceLockKey::new("computer:c-1").unwrap()],
        }
    }

    /// 正向对照：五个已声明的档位逐字节命中时**必须**判为 `Declared`。
    ///
    /// 没有它，下面那条"未知不会变成 read"的测试在"classify 永远返回 execute"的世界里
    /// 同样全绿。
    #[test]
    fn declared_effect_strings_classify_exactly() {
        for effect in ALL_EFFECTS {
            let classified = EffectClassification::classify(effect.as_str());
            assert_eq!(classified.effect(), *effect);
            assert_eq!(classified.source(), EffectSource::Declared);
            assert!(!classified.was_downgraded());
        }
    }

    /// **未知 effect 永远不会变成 `Read`**，而且一定带降级标记。
    ///
    /// 语料刻意包含几类真实来源：MCP annotation 的驼峰名、模型可能自述的词、大小写变体、
    /// 带空白的 `"read"`、空串、以及一个只差一个字母的近似词。
    #[test]
    fn unrecognized_effects_never_become_read() {
        let adversarial = [
            "",
            " ",
            "READ",
            "Read",
            "read ",
            " read",
            "reed",
            "readOnly",
            "readOnlyHint",
            "read-only",
            "safe",
            "none",
            "null",
            "unknown",
            "query",
            "get",
            "\u{0}read",
            "read\u{0}",
            "写",
        ];
        for raw in adversarial {
            let classified = EffectClassification::classify(raw);
            assert_ne!(
                classified.effect(),
                Effect::Read,
                "{raw:?} 被判成了 read —— 未知绝不能变成最宽松的一档"
            );
            assert_eq!(
                classified.effect(),
                UNRECOGNIZED_EFFECT_FALLBACK,
                "{raw:?} 应当降级到固定档位"
            );
            assert!(classified.was_downgraded(), "{raw:?} 应当带降级标记");
        }
    }

    /// 降级档必须是 acting —— 否则"降级"只是换了个名字，仍然绕过 §17.2 条 2。
    #[test]
    fn the_fallback_effect_is_an_acting_effect() {
        assert!(UNRECOGNIZED_EFFECT_FALLBACK.is_acting());
        // §8.2 允许 write/execute 两者，本仓裁决取 execute（更严的一档）。
        assert_eq!(UNRECOGNIZED_EFFECT_FALLBACK, Effect::Execute);
    }

    /// `is_acting` 的完整真值表：只有 read 不是 acting。
    #[test]
    fn only_read_is_not_acting() {
        assert!(!Effect::Read.is_acting());
        for effect in ALL_EFFECTS.iter().filter(|e| **e != Effect::Read) {
            assert!(effect.is_acting(), "{} 必须算 acting", effect.as_str());
        }
    }

    #[test]
    fn effect_labels_are_unique_and_match_the_plan_vocabulary() {
        let labels: Vec<&str> = ALL_EFFECTS.iter().map(|e| e.as_str()).collect();
        assert_eq!(
            labels,
            vec!["read", "write", "execute", "network", "credential"],
            "取值与 §8.2 的列举逐字一致"
        );
    }

    #[test]
    fn tool_name_rejects_shapes_that_break_provider_tool_names() {
        assert_eq!(ToolName::new(""), Err(ToolMetadataError::EmptyToolName));
        assert_eq!(
            ToolName::new("has space"),
            Err(ToolMetadataError::ToolNameHasIllegalCharacter)
        );
        assert_eq!(
            ToolName::new("emoji-🙂"),
            Err(ToolMetadataError::ToolNameHasIllegalCharacter)
        );
        assert_eq!(
            ToolName::new("x".repeat(ToolName::MAX_BYTES + 1)),
            Err(ToolMetadataError::ToolNameTooLong {
                found: ToolName::MAX_BYTES + 1
            })
        );
        // 正向对照。
        assert!(ToolName::new("browser.click").is_ok());
        assert!(ToolName::new("mcp_drive-search.v2").is_ok());
        assert!(ToolName::new("x".repeat(ToolName::MAX_BYTES)).is_ok());
    }

    #[test]
    fn metadata_validation_covers_every_cross_field_rule() {
        assert_eq!(metadata().validate(), Ok(()));

        let mut zero_timeout = metadata();
        zero_timeout.timeout = Duration::ZERO;
        assert_eq!(zero_timeout.validate(), Err(ToolMetadataError::ZeroTimeout));

        let mut zero_input = metadata();
        zero_input.limits.max_input_bytes = 0;
        assert_eq!(zero_input.validate(), Err(ToolMetadataError::ZeroLimit));

        let mut zero_output = metadata();
        zero_output.limits.max_output_bytes = 0;
        assert_eq!(zero_output.validate(), Err(ToolMetadataError::ZeroLimit));

        let mut inverted = metadata();
        inverted.limits.max_model_visible_bytes = inverted.limits.max_output_bytes + 1;
        assert_eq!(
            inverted.validate(),
            Err(ToolMetadataError::ModelVisibleLimitExceedsOutputLimit)
        );

        // 边界：相等是合法的（模型可见 = 全部输出）。
        let mut equal = metadata();
        equal.limits.max_model_visible_bytes = equal.limits.max_output_bytes;
        assert_eq!(equal.validate(), Ok(()));
    }

    #[test]
    fn approval_class_requires_human_only_where_it_should() {
        assert!(!ApprovalClass::NotRequired.requires_human_approval());
        assert!(ApprovalClass::OncePerRun.requires_human_approval());
        assert!(ApprovalClass::EveryCall.requires_human_approval());
    }

    /// catalog 代际按**数值**序比较 —— 与 contracts 裁决 D7 同一条理由。
    #[test]
    fn catalog_generation_orders_numerically() {
        assert!(CatalogGeneration::new(9) < CatalogGeneration::new(10));
        // 负向对照：字典序会给出相反答案，这正是它不是字符串的理由。
        assert!("10" < "9");
    }
}
