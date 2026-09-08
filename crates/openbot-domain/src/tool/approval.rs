//! approval 绑定与失效判定（v3 §8.5）。
//!
//! # §8.5 逐字，以及它的两半
//!
//! > approval 绑定 `actor + bot + run + tool + canonical args hash + target +
//! > computer/catalog generation + policy version + expiry`。**任一字段变化、角色撤销、
//! > 页面导航、computer restart 或 catalog refresh 都使 approval 失效。**
//!
//! 这段话里有两类东西，不能混在一起实现：
//!
//! - **字段**（前半句）：批准这个动作时，这九项分别是什么。它们进 [`ApprovalBinding`]，
//!   是一份写下来就不再变的**快照**。
//! - **事件**（后半句）：角色撤销、页面导航、computer restart、catalog refresh。它们不是
//!   binding 的字段，是**此刻世界的样子**，进 [`ApprovalObservation`]。
//!
//! 其中三个事件已经有了机械形式，不必单独表达：computer restart 会递增
//! `ComputerGeneration`（§17.2 条 6），catalog refresh 会递增 `CatalogGeneration`，页面导航
//! 会递增 `DocumentGeneration`（§17.2 条 4）。所以它们落成"binding 里记的代际 vs 此刻的
//! 代际"，一次比较即可 —— 而**角色撤销没有代际**，它只能作为一个显式观测量传进来。
//!
//! 把 document generation 也放进 binding 是本模块的一处具体化：§8.5 的字段列表里写的是
//! "computer/catalog generation"，页面导航在后半句。做法是给 binding 加一个
//! `target_document_generation: Option<DocumentGeneration>`——浏览器目标有它，别的目标没有。
//! 这样"页面导航使 approval 失效"就与另外两个代际同构，而不是又一个只能靠调用方记得传的
//! 布尔。
//!
//! # 为什么判定要说出**是哪一项**失效
//!
//! 与 [`crate::audit::chain::verify_chain`] 同一条理由：函数内部已经知道是哪个字段对不上，
//! 只回一个 `false` 是把这条信息算出来又扔掉。而这条信息直接决定产品行为 ——
//! "参数变了，请重新确认" 和 "你的权限被撤销了" 是两件必须区分的事，也是两条不同的
//! 审计记录。

use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, BotId, ComputerGeneration, DocumentGeneration, RunId};
use time::OffsetDateTime;

use super::metadata::{CatalogGeneration, ToolName};
use crate::audit::hash::Sha256Digest;

/// 一次批准所针对的目标。
///
/// 目标必须是**权威解析过的**结果，不是调用方自述的那一份（§8.1 的
/// `resolve authoritative actor/target` 那一段）。这里只表达它的身份，不表达它的内容。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalTarget {
    /// 目标类别，例如 `"browser_tab"` / `"mcp_server"`。封闭词汇，由 catalog 给出。
    pub kind: &'static str,
    /// 目标标识。
    pub id: String,
}

/// policy 文档的版本标记。
///
/// # 为什么是本模块的窄类型而不是 `crate::policy` 的类型
///
/// §8.3 规定 policy version 由**内容派生**（`action_policy` 主键恒为 `'current'`，没有版本
/// 列，一次内容相同的重写不该让全部既有 approval 失效）。派生它是 `policy` 模块的事；
/// 本模块只需要"两次判定用的是不是同一份策略"这一个比较。
///
/// 用窄类型表达而不是 import `crate::policy`，是一次刻意的解耦：approval 的失效判定不该
/// 依赖策略求值器的任何细节，否则改一次 CEL 实现就会牵动 approval 的编译面。集成时由
/// application 层把 policy 侧的版本摘要包进来即可。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersionTag(String);

impl PolicyVersionTag {
    /// 由版本标记构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一份人工批准所绑定的全部字段（§8.5 前半句）。
///
/// 字段全公开且无 `Default`：与 [`super::metadata::ToolMetadata`] 同一条理由 —— 新增一个
/// 绑定字段必须让所有构造点编译失败，而不是默认成某个"看起来没问题"的值。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalBinding {
    /// 批准这次操作的人。
    pub actor: ActorId,
    /// Actor role/access generation at approval time. Any authoritative role/access mutation bumps
    /// it, even when the actor still retains some other role.
    pub auth_generation: AuthGeneration,
    /// 代表哪个 Bot 行动。
    pub bot: BotId,
    /// 属于哪一次 run。
    pub run: RunId,
    /// 批准的是哪个工具。
    pub tool: ToolName,
    /// 批准的是哪一组实参（[`super::args::ToolArguments::canonical_hash`]）。
    pub args_hash: Sha256Digest,
    /// 批准的是对哪个目标动手。
    pub target: ApprovalTarget,
    /// 批准时 computer 处在哪一代（restart / reset 会让它前进，§17.2 条 6）。
    pub computer_generation: ComputerGeneration,
    /// 批准时 catalog 处在哪一代（refresh 会让它前进）。
    pub catalog_generation: CatalogGeneration,
    /// 批准时目标页面处在哪一代；非浏览器目标为 `None`。
    ///
    /// 这是"页面导航使 approval 失效"的机械形式（§17.2 条 4：snapshot ref 绑定 document
    /// generation）。
    pub target_document_generation: Option<DocumentGeneration>,
    /// 批准时生效的 policy 版本。
    pub policy_version: PolicyVersionTag,
    /// 过期时刻。**由调用方在批准时算好并写下**，领域层没有时钟。
    pub expires_at: OffsetDateTime,
}

/// 判定时刻"世界的样子"（§8.5 后半句）。
///
/// 与 [`ApprovalBinding`] 的字段一一对照 —— 除了 [`Self::actor_role_revoked`]，它是唯一
/// 没有代际可比的那个事件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalObservation {
    /// 此刻真正要执行的 actor。
    pub actor: ActorId,
    /// Current authoritative role/access generation.
    pub auth_generation: AuthGeneration,
    /// 此刻真正要执行的 bot。
    pub bot: BotId,
    /// 此刻的 run。
    pub run: RunId,
    /// 此刻要调用的工具。
    pub tool: ToolName,
    /// 此刻这组实参的摘要。
    pub args_hash: Sha256Digest,
    /// 此刻的目标。
    pub target: ApprovalTarget,
    /// 此刻 computer 的代际。
    pub computer_generation: ComputerGeneration,
    /// 此刻 catalog 的代际。
    pub catalog_generation: CatalogGeneration,
    /// 此刻目标页面的代际。
    pub target_document_generation: Option<DocumentGeneration>,
    /// 此刻生效的 policy 版本。
    pub policy_version: PolicyVersionTag,
    /// 批准人的角色是否已被撤销。
    ///
    /// 显式布尔而不是"重新查一次角色"：领域层不做 I/O。查角色是 application 的事，
    /// 这里只接收它的结论。
    pub actor_role_revoked: bool,
    /// 此刻。
    pub now: OffsetDateTime,
}

/// 批准是否仍然有效。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalValidity {
    /// 仍然有效。
    Valid,
    /// 已失效，附具体原因。
    Invalid(ApprovalInvalidation),
}

/// 批准失效的具体原因。**逐字段一个变体**，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalInvalidation {
    /// 换人了。
    ActorChanged,
    /// Actor role/access generation changed.
    AuthGenerationChanged,
    /// 换 Bot 了。
    BotChanged,
    /// 换 run 了。
    RunChanged,
    /// 换工具了。
    ToolChanged,
    /// 实参变了。
    ArgumentsChanged,
    /// 目标变了。
    TargetChanged,
    /// computer 换代了（restart / reset）。
    ComputerGenerationChanged,
    /// catalog 换代了（refresh）。
    CatalogGenerationChanged,
    /// 页面换代了（导航）。
    DocumentGenerationChanged,
    /// policy 版本变了。
    PolicyVersionChanged,
    /// 批准人的角色被撤销。
    ActorRoleRevoked,
    /// 过期。
    Expired,
}

impl ApprovalInvalidation {
    /// 稳定字面量（进审计与错误码用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActorChanged => "actor_changed",
            Self::AuthGenerationChanged => "auth_generation_changed",
            Self::BotChanged => "bot_changed",
            Self::RunChanged => "run_changed",
            Self::ToolChanged => "tool_changed",
            Self::ArgumentsChanged => "arguments_changed",
            Self::TargetChanged => "target_changed",
            Self::ComputerGenerationChanged => "computer_generation_changed",
            Self::CatalogGenerationChanged => "catalog_generation_changed",
            Self::DocumentGenerationChanged => "document_generation_changed",
            Self::PolicyVersionChanged => "policy_version_changed",
            Self::ActorRoleRevoked => "actor_role_revoked",
            Self::Expired => "expired",
        }
    }
}

impl ApprovalBinding {
    /// 这份批准此刻还算不算数。
    ///
    /// # 判定顺序
    ///
    /// 先判两个"与实参无关的世界状态"（角色撤销、过期），再逐字段比。顺序对结果没有影响
    /// （每次只会有一个原因被报出来，而调用方拿到任一原因都必须停），选这个顺序是因为它
    /// 让最常见的两种失效在日志里最先出现，排查时不必先读完九个字段比较。
    #[must_use]
    pub fn is_still_valid(&self, observed: &ApprovalObservation) -> ApprovalValidity {
        use ApprovalInvalidation as Why;

        // 角色撤销：§8.5 后半句里唯一没有代际可比的事件。
        if observed.actor_role_revoked {
            return ApprovalValidity::Invalid(Why::ActorRoleRevoked);
        }
        // 过期用 `>=`：恰好到点即失效。批准的有效期是一个闭区间的**左**端，
        // "刚好在最后一纳秒挤进去"不是一个值得支持的语义。
        if observed.now >= self.expires_at {
            return ApprovalValidity::Invalid(Why::Expired);
        }

        let mismatch = if self.actor != observed.actor {
            Some(Why::ActorChanged)
        } else if self.auth_generation != observed.auth_generation {
            Some(Why::AuthGenerationChanged)
        } else if self.bot != observed.bot {
            Some(Why::BotChanged)
        } else if self.run != observed.run {
            Some(Why::RunChanged)
        } else if self.tool != observed.tool {
            Some(Why::ToolChanged)
        } else if self.args_hash != observed.args_hash {
            Some(Why::ArgumentsChanged)
        } else if self.target != observed.target {
            Some(Why::TargetChanged)
        } else if self.computer_generation != observed.computer_generation {
            Some(Why::ComputerGenerationChanged)
        } else if self.catalog_generation != observed.catalog_generation {
            Some(Why::CatalogGenerationChanged)
        } else if self.target_document_generation != observed.target_document_generation {
            Some(Why::DocumentGenerationChanged)
        } else if self.policy_version != observed.policy_version {
            Some(Why::PolicyVersionChanged)
        } else {
            None
        };

        mismatch.map_or(ApprovalValidity::Valid, ApprovalValidity::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn binding() -> ApprovalBinding {
        ApprovalBinding {
            actor: ActorId::new("actor-1"),
            auth_generation: AuthGeneration::new(7),
            bot: BotId::new("bot-1"),
            run: RunId::new("run-1"),
            tool: ToolName::new("browser.click").unwrap(),
            args_hash: Sha256Digest::of(b"args"),
            target: ApprovalTarget {
                kind: "browser_tab",
                id: "tab-9".to_owned(),
            },
            computer_generation: ComputerGeneration::new(3),
            catalog_generation: CatalogGeneration::new(4),
            target_document_generation: Some(DocumentGeneration::new(5)),
            policy_version: PolicyVersionTag::new("pv-abc"),
            expires_at: at(1_700_000_600),
        }
    }

    fn observation() -> ApprovalObservation {
        let binding = binding();
        ApprovalObservation {
            actor: binding.actor,
            auth_generation: binding.auth_generation,
            bot: binding.bot,
            run: binding.run,
            tool: binding.tool,
            args_hash: binding.args_hash,
            target: binding.target,
            computer_generation: binding.computer_generation,
            catalog_generation: binding.catalog_generation,
            target_document_generation: binding.target_document_generation,
            policy_version: binding.policy_version,
            actor_role_revoked: false,
            now: at(1_700_000_000),
        }
    }

    /// 正向对照：**全部字段都没变**时批准仍然有效。
    ///
    /// 这条必须先立住 —— 下面十二条"改一个就失效"在"is_still_valid 恒返回 Invalid"的
    /// 世界里全都会通过。
    #[test]
    fn an_untouched_approval_is_still_valid() {
        assert_eq!(
            binding().is_still_valid(&observation()),
            ApprovalValidity::Valid
        );
    }

    /// **逐字段**：每个绑定字段各有一条自己的用例，改一个就失效，且报出的原因必须对上。
    ///
    /// "逐字段"不是形式主义：只测一个代表字段的话，漏掉比较的恰恰是那个没被代表的字段，
    /// 而那正是一份批准会被拿去执行别的东西的入口。
    #[test]
    fn changing_any_single_bound_field_invalidates_the_approval() {
        type FieldCase = (
            &'static str,
            fn(&mut ApprovalObservation),
            ApprovalInvalidation,
        );
        let cases: Vec<FieldCase> = vec![
            (
                "actor",
                |o| o.actor = ActorId::new("actor-2"),
                ApprovalInvalidation::ActorChanged,
            ),
            (
                "auth_generation",
                |o| o.auth_generation = AuthGeneration::new(8),
                ApprovalInvalidation::AuthGenerationChanged,
            ),
            (
                "bot",
                |o| o.bot = BotId::new("bot-2"),
                ApprovalInvalidation::BotChanged,
            ),
            (
                "run",
                |o| o.run = RunId::new("run-2"),
                ApprovalInvalidation::RunChanged,
            ),
            (
                "tool",
                |o| o.tool = ToolName::new("browser.type").unwrap(),
                ApprovalInvalidation::ToolChanged,
            ),
            (
                "args_hash",
                |o| o.args_hash = Sha256Digest::of(b"other-args"),
                ApprovalInvalidation::ArgumentsChanged,
            ),
            (
                "target.id",
                |o| o.target.id = "tab-10".to_owned(),
                ApprovalInvalidation::TargetChanged,
            ),
            (
                "target.kind",
                |o| o.target.kind = "mcp_server",
                ApprovalInvalidation::TargetChanged,
            ),
            (
                "computer_generation",
                |o| o.computer_generation = ComputerGeneration::new(4),
                ApprovalInvalidation::ComputerGenerationChanged,
            ),
            (
                "catalog_generation",
                |o| o.catalog_generation = CatalogGeneration::new(5),
                ApprovalInvalidation::CatalogGenerationChanged,
            ),
            (
                "target_document_generation",
                |o| o.target_document_generation = Some(DocumentGeneration::new(6)),
                ApprovalInvalidation::DocumentGenerationChanged,
            ),
            (
                "target_document_generation=None",
                |o| o.target_document_generation = None,
                ApprovalInvalidation::DocumentGenerationChanged,
            ),
            (
                "policy_version",
                |o| o.policy_version = PolicyVersionTag::new("pv-def"),
                ApprovalInvalidation::PolicyVersionChanged,
            ),
        ];

        for (field, mutate, expected) in cases {
            let mut observed = observation();
            mutate(&mut observed);
            assert_eq!(
                binding().is_still_valid(&observed),
                ApprovalValidity::Invalid(expected),
                "改了 {field} 之后判定不对"
            );
        }
    }

    /// 角色撤销：唯一没有代际可比的失效事件。
    #[test]
    fn revoking_the_approvers_role_invalidates_it() {
        let mut observed = observation();
        observed.actor_role_revoked = true;
        assert_eq!(
            binding().is_still_valid(&observed),
            ApprovalValidity::Invalid(ApprovalInvalidation::ActorRoleRevoked)
        );
    }

    /// 过期边界：恰好到点即失效，早一纳秒仍有效。
    #[test]
    fn expiry_is_inclusive_at_the_boundary() {
        let binding = binding();
        let mut observed = observation();

        observed.now = binding.expires_at - Duration::nanoseconds(1);
        assert_eq!(binding.is_still_valid(&observed), ApprovalValidity::Valid);

        observed.now = binding.expires_at;
        assert_eq!(
            binding.is_still_valid(&observed),
            ApprovalValidity::Invalid(ApprovalInvalidation::Expired)
        );

        observed.now = binding.expires_at + Duration::seconds(1);
        assert_eq!(
            binding.is_still_valid(&observed),
            ApprovalValidity::Invalid(ApprovalInvalidation::Expired)
        );
    }

    /// 三个事件（computer restart / catalog refresh / 页面导航）的机械形式都是"代际前进"。
    ///
    /// 这条把 §8.5 后半句的三个词与三个字段对上，免得后人以为它们还需要各自一个布尔。
    #[test]
    fn restart_refresh_and_navigation_are_expressed_as_generation_bumps() {
        let binding = binding();

        let mut restarted = observation();
        restarted.computer_generation = binding.computer_generation.next();
        assert_eq!(
            binding.is_still_valid(&restarted),
            ApprovalValidity::Invalid(ApprovalInvalidation::ComputerGenerationChanged)
        );

        let mut refreshed = observation();
        refreshed.catalog_generation = CatalogGeneration::new(binding.catalog_generation.get() + 1);
        assert_eq!(
            binding.is_still_valid(&refreshed),
            ApprovalValidity::Invalid(ApprovalInvalidation::CatalogGenerationChanged)
        );

        let mut navigated = observation();
        navigated.target_document_generation = binding
            .target_document_generation
            .map(DocumentGeneration::next);
        assert_eq!(
            binding.is_still_valid(&navigated),
            ApprovalValidity::Invalid(ApprovalInvalidation::DocumentGenerationChanged)
        );
    }

    /// 非浏览器目标（没有 document generation）同样能被判定，不会因为两个 `None` 就误判。
    #[test]
    fn targets_without_a_document_generation_still_validate() {
        let mut binding = binding();
        binding.target_document_generation = None;
        binding.target = ApprovalTarget {
            kind: "mcp_server",
            id: "srv-1".to_owned(),
        };

        let mut observed = observation();
        observed.target_document_generation = None;
        observed.target = ApprovalTarget {
            kind: "mcp_server",
            id: "srv-1".to_owned(),
        };

        assert_eq!(binding.is_still_valid(&observed), ApprovalValidity::Valid);
    }

    /// 失效原因的字面量两两不同 —— 撞名会让审计里两种不同的失效变成同一条记录。
    #[test]
    fn invalidation_labels_are_pairwise_distinct() {
        let all = [
            ApprovalInvalidation::ActorChanged,
            ApprovalInvalidation::AuthGenerationChanged,
            ApprovalInvalidation::BotChanged,
            ApprovalInvalidation::RunChanged,
            ApprovalInvalidation::ToolChanged,
            ApprovalInvalidation::ArgumentsChanged,
            ApprovalInvalidation::TargetChanged,
            ApprovalInvalidation::ComputerGenerationChanged,
            ApprovalInvalidation::CatalogGenerationChanged,
            ApprovalInvalidation::DocumentGenerationChanged,
            ApprovalInvalidation::PolicyVersionChanged,
            ApprovalInvalidation::ActorRoleRevoked,
            ApprovalInvalidation::Expired,
        ];
        let mut labels: Vec<&str> = all.iter().map(|reason| reason.as_str()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "失效原因的字面量有重复");
        assert_eq!(count, 13);
    }
}
