//! `allowed_groups` 三档、group claim 解析与 membership 投影（v3 §6.5）。
//!
//! # 这一整块是**确定修正**，不是 parity
//!
//! v3 §6.5 开头逐字：当前 `users.groups` 与 `channels.allowed_groups` **不是生效的控制**
//! （上游 issue [#82]），而且包声明的 channel 没有任何 membership 写入路径，对所有人不可达。
//!
//! 本轮实测复核了这两半：
//!
//! - `users.groups` 那一列在上游 `db/schema/core.ts` 里自带注释，逐字：「Empty on every row:
//!   no sign-in path, claim mapping or admin screen writes this, and nothing reads it.」
//! - `grep -rn "groups" server/src --include=*.ts`（排除测试）在 `db/schema/core.ts` 与
//!   `tenant-package.ts` 之外只命中 `computer/target.ts`，而那里的 `groups` 是 IPv6 地址的
//!   八段分组，与身份无关。也就是说全仓没有第二个读者。
//!
//! 所以这里**不能**「先照译再修」（repository contract §7）：照译出来的是一个不工作的功能。
//!
//! # 三档，以及每一档挡住的东西
//!
//! | 取值 | 语义 | 它挡住什么 |
//! | --- | --- | --- |
//! | 保留字 `all`（**精确匹配、区分大小写**） | 部署内全体有效用户 | 随包示例 `examples/fintech/channels.yaml` 用的就是 `[all]`；按「具名组必须有 IdP mapping」一刀切会把官方示例包拒在门外 |
//! | 具名组 | 必须至少有一家已配置 IdP 配了 group mapping | 一个永远没人能进的 channel 静静躺在包里 |
//! | **空列表** | 包校验**错误** | 上游的现状：不写就是对所有人不可达，而且不报错 |
//!
//! 保留字是精确匹配的直接后果：`All` / `ALL` 会被当成一个**具名组**，进而因为没有 mapping
//! 而让包校验失败 —— 这正是想要的，它把一个大小写笔误变成一条指着笔误的错误，而不是一个
//! 谁也进不去的 channel。`reserved_word_is_case_sensitive` 钉住这条。
//!
//! # 组只负责 provision，不负责运行时可见性
//!
//! §6.5 条 5：group 只负责 provision channel membership，**所有运行时 channel route 仍检查
//! materialized membership**。`openbot-application` 的 `ports::ChannelReader` 已经把这条写进
//! 了它的方法文档（「列出 actor 通过 **materialized membership** 可见的 channel」）。
//!
//! 所以本模块**不提供**任何形如 `can_access(channel)` 的函数。这个缺失是刻意的：一旦存在
//! 第二条能回答「他看得见这个 channel 吗」的路径，两条路径就会分叉，而分叉的那一天没人
//! 会注意到 —— 两边各自都「正确」。本模块的产物叫
//! [`MembershipProvisioningPlan`]，名字里的 provisioning 是契约的一部分。
//!
//! [#82]: https://github.com/CopilotKit/openbot/issues/82

use std::collections::BTreeSet;

use openbot_contracts::ids::{ActorId, ChannelId};

use super::email::NormalizedEmail;
use super::generation::AuthGeneration;
use super::revocation::AccessCleared;

/// `allowed_groups` 里代表「全体有效用户」的保留字。
///
/// 精确匹配、区分大小写（v3 §6.5 条 2 逐字）。它是**标识符**不是文案。
pub const RESERVED_AUDIENCE_ALL: &str = "all";

// ---------------------------------------------------------------------------
// 组名与规范化
// ---------------------------------------------------------------------------

/// 一家 IdP 把 claim 值折成组名的规则。
///
/// # 为什么只有两档，以及为什么两边必须用同一档
///
/// 组名是 IdP 那边的自由文本，各家习惯不同（有的全大写，有的带空格）。所以需要一条
/// 规范化规则 —— 但**同一条规则必须同时施加在 claim 值和包里的组名上**，否则会出现
/// 一种极难发现的分叉：IdP A 折成小写、IdP B 原样，包里写着 `Finance`，于是 B 的人进得去
/// 而 A 的人进不去，两边的代码各自都是对的。
/// [`EffectivePrincipal`] 因此随身带着自己那一档规则，[`ChannelAudience`] 里存的是**原始**
/// 组名，匹配时现折 —— 两边永远同规则。`both_sides_are_folded_with_the_same_rule` 钉住这条。
///
/// 只有两档是刻意的：再加一档（比如从 AD 的 `CN=Finance,OU=…` 里抽 CN）就是在发明一条
/// 会改变谁能进哪个 channel 的规则，那需要一条台账条目和一次产品裁决，不是随手加个变体。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupNormalization {
    /// 逐字节原样。默认档 —— 不动 IdP 给的值，是「不擅自改变谁能进」的那一档。
    #[default]
    Exact,
    /// 去首尾空白后小写。给那些大小写不稳定的目录用。
    TrimLowercase,
}

impl GroupNormalization {
    /// 全部档位，供遍历型测试用。
    pub const ALL: [Self; 2] = [Self::Exact, Self::TrimLowercase];

    /// 稳定标识符（配置里写的就是它）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::TrimLowercase => "trim_lowercase",
        }
    }
}

/// 一个已按某档规则折过的组名。
///
/// 非空 —— 空组名不可能匹配任何东西，留着它只会让「这个人有 3 个组」这句话不准确。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupName(String);

impl GroupName {
    /// 按给定规则折一个原始组名。
    ///
    /// 折完为空时返回 `None`（而不是错误）：一家 IdP 在数组里塞一个空串不该让这个人登不
    /// 进来，而它也不可能授予任何东西 —— 包里的组名不允许为空（见
    /// [`AudienceError::BlankGroupName`]），所以空组名永远匹配不到。
    #[must_use]
    pub fn fold(raw: &str, rule: GroupNormalization) -> Option<Self> {
        let folded = match rule {
            GroupNormalization::Exact => raw.to_owned(),
            GroupNormalization::TrimLowercase => raw.trim().to_lowercase(),
        };
        if folded.is_empty() {
            None
        } else {
            Some(Self(folded))
        }
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// ---------------------------------------------------------------------------
// IdP group claim mapping
// ---------------------------------------------------------------------------

/// 一家动态注册的 IdP 的标识（上游 `sso_providers.provider_id`）。
///
/// 它不在 `openbot_contracts::ids` 的十五个名字里（§5.3 的表钉死了那张清单），所以先落在
/// 本模块。交付报告把「要不要提进 contracts」列成一条待裁决项。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityProviderId(String);

impl IdentityProviderId {
    /// 由任意可转 `String` 的值构造。与 contracts 的 string ID 一样**不做格式校验**
    /// （§5.3：兼容端必须接受上游既有字符串）。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// claim 里通往组数组的路径。
///
/// # 为什么有两个构造函数
///
/// 点号形式（`resource_access.roles`）好写，是配置里最常见的写法。但**有些 IdP 的 claim
/// 名字本身含点号** —— Auth0 之类要求自定义 claim 带命名空间前缀，形如
/// `https://app.example.com/groups`，那里面有三个点。对这种名字按点号切分会切出一串根本
/// 不存在的层级，结果是「这个人一个组都没有」，而配置看起来完全正常。
///
/// 所以点号形式只是一个便利构造器，[`Self::from_segments`] 才是完整形态；含点号的 claim
/// 名必须走后者。`namespaced_claim_names_need_the_segment_form` 把这个陷阱钉成一条测试。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupClaimPath(Vec<String>);

/// group claim path 配置得不合法。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_group_claim_path_invalid")]
pub struct GroupClaimPathInvalid;

impl GroupClaimPathInvalid {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_group_claim_path_invalid"
    }
}

impl GroupClaimPath {
    /// 按 `.` 切分。便利构造器，含点号的 claim 名不能用它（见类型文档）。
    ///
    /// # Errors
    ///
    /// 空串、或切出空段（`a..b`、`.a`、`a.`）时返回 [`GroupClaimPathInvalid`] ——
    /// 空段永远匹配不到任何键，静默接受它等于配置了一条恒空的路径。
    pub fn from_dotted(path: &str) -> Result<Self, GroupClaimPathInvalid> {
        Self::from_segments(path.split('.'))
    }

    /// 逐段给出。含点号的 claim 名走这里。
    ///
    /// # Errors
    ///
    /// 一段都没有、或有空段时返回 [`GroupClaimPathInvalid`]。
    pub fn from_segments<I, S>(segments: I) -> Result<Self, GroupClaimPathInvalid>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let collected: Vec<String> = segments
            .into_iter()
            .map(|segment| segment.as_ref().to_owned())
            .collect();
        if collected.is_empty() || collected.iter().any(String::is_empty) {
            return Err(GroupClaimPathInvalid);
        }
        Ok(Self(collected))
    }

    /// 逐段借出。
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// 一家 IdP 的 group mapping：去哪儿取组，以及怎么折。
///
/// v3 §6.5 条 1：「每个动态 IdP 可配置一个明确的 group claim path 和规范化规则。」
/// 两者是一对 —— 只有 path 没有规则时，规则就变成隐式的，而隐式的规则正是上一节说的
/// 那种「两边各自正确」的分叉源头。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdpGroupMapping {
    provider: IdentityProviderId,
    path: GroupClaimPath,
    normalization: GroupNormalization,
}

impl IdpGroupMapping {
    /// 构造一条 mapping。
    #[must_use]
    pub const fn new(
        provider: IdentityProviderId,
        path: GroupClaimPath,
        normalization: GroupNormalization,
    ) -> Self {
        Self {
            provider,
            path,
            normalization,
        }
    }

    /// 这条 mapping 属于哪一家 IdP。
    #[must_use]
    pub const fn provider(&self) -> &IdentityProviderId {
        &self.provider
    }

    /// claim 路径。
    #[must_use]
    pub const fn path(&self) -> &GroupClaimPath {
        &self.path
    }

    /// 规范化规则。
    #[must_use]
    pub const fn normalization(&self) -> GroupNormalization {
        self.normalization
    }
}

/// claim 的形状不是这里能解释的东西。
///
/// # 为什么不「尽力而为地转换一下」
///
/// 因为转换出来的东西是**访问控制的取值**。举两个具体的：
///
/// - 把数字 `42` 转成 `"42"`：如果哪天有个组真的叫 `42`，这个人就凭一个数字进去了。
/// - 按空格切分字符串（`scope` 风格）：一个叫 `Finance Team` 的组会被切成 `Finance` 与
///   `Team` 两个组，于是它的成员**凭空**获得了 `Finance` 组的访问权 —— 而 `Finance` 可能
///   是一个真实存在、权限更大的组。
///
/// 两者都不是「宽松一点」，是**发明成员资格**。所以这里 fail-closed：形状不认识就报错，
/// 让配置的人去把 claim 配对。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_group_claim_shape_rejected")]
pub struct GroupClaimShapeRejected;

impl GroupClaimShapeRejected {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_group_claim_shape_rejected"
    }
}

/// 一次 group claim 解析的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupClaims {
    groups: BTreeSet<GroupName>,
    claim_present: bool,
}

impl GroupClaims {
    /// 解析出来的组。
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<GroupName> {
        &self.groups
    }

    /// 配置的路径在这份 claim 里**存在**吗。
    ///
    /// 与「组为空」分开，因为两者的补救完全不同：路径不存在多半是配置写错了（或者这家
    /// IdP 根本没发这个 claim），而路径存在但数组为空只是这个人不属于任何组 —— 后者是
    /// 完全正常的。把两者压成「零个组」之后，一次配错的 path 与「大家都没分组」长得一模
    /// 一样，而前者要改配置、后者什么都不用做。
    ///
    /// 它**不参与**任何访问判定：路径不存在时组就是空的，仅此而已，登录照常。
    #[must_use]
    pub const fn claim_present(&self) -> bool {
        self.claim_present
    }
}

/// 按一条 mapping 从已验证的 claim 里解析组。
///
/// 输入必须是**已经过 IdP 签名 / issuer / audience 校验**的 claim（那些校验是 infra 的
/// 事）。本函数只做纯粹的结构遍历。
///
/// 接受的形状：字符串数组，或单个字符串（等价于只有一个元素的数组 —— 有些目录在只有一个
/// 组时就这么发）。其它一律拒绝，理由见 [`GroupClaimShapeRejected`]。
///
/// # Errors
///
/// 路径中途撞上一个非对象的值，或终点的值形状不认识时，返回 [`GroupClaimShapeRejected`]。
pub fn resolve_group_claims(
    claims: &serde_json::Value,
    mapping: &IdpGroupMapping,
) -> Result<GroupClaims, GroupClaimShapeRejected> {
    let mut cursor = claims;
    for segment in mapping.path.segments() {
        let Some(object) = cursor.as_object() else {
            // 路径中途是个数组 / 字符串 / 数字：配置指的层级在这份 claim 里不存在，
            // 而且这不是「这个人没分组」，是路径与 claim 结构对不上。
            return Err(GroupClaimShapeRejected);
        };
        let Some(next) = object.get(segment) else {
            return Ok(GroupClaims {
                groups: BTreeSet::new(),
                claim_present: false,
            });
        };
        cursor = next;
    }

    let mut groups = BTreeSet::new();
    match cursor {
        serde_json::Value::Array(items) => {
            for item in items {
                let Some(text) = item.as_str() else {
                    return Err(GroupClaimShapeRejected);
                };
                if let Some(name) = GroupName::fold(text, mapping.normalization) {
                    groups.insert(name);
                }
            }
        }
        serde_json::Value::String(text) => {
            if let Some(name) = GroupName::fold(text, mapping.normalization) {
                groups.insert(name);
            }
        }
        _ => return Err(GroupClaimShapeRejected),
    }
    Ok(GroupClaims {
        groups,
        claim_present: true,
    })
}

// ---------------------------------------------------------------------------
// channel 受众
// ---------------------------------------------------------------------------

/// 包声明的 `allowed_groups` 解析不出一个受众。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AudienceError {
    /// 空列表。
    ///
    /// v3 §6.5 条 2 逐字：「空列表 = 包校验错误 "channel has no audience"，不再静默不可达。」
    /// 上游把它当成合法配置，后果是一个谁也进不去的 channel 安静地躺在包里 —— 而
    /// 「安静」是这里唯一真正的问题：写包的人以为自己发布了一个 channel。
    #[error("channel_has_no_audience")]
    NoAudience,
    /// 组名为空（`allowed_groups: ["", "risk"]`）。
    ///
    /// 空组名匹配不到任何东西，接受它等于接受一条无声失效的条目。
    #[error("channel_audience_blank_group")]
    BlankGroupName,
}

impl AudienceError {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoAudience => "channel_has_no_audience",
            Self::BlankGroupName => "channel_audience_blank_group",
        }
    }
}

/// 一个 channel 的受众。
///
/// 具名组存的是**原始**字符串，不是折过的 [`GroupName`] —— 折叠规则属于 IdP，匹配时才现折
/// （见 [`GroupNormalization`] 的类型文档）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelAudience {
    everyone: bool,
    named: BTreeSet<String>,
}

impl ChannelAudience {
    /// 解析包里的 `allowed_groups`。
    ///
    /// `all` 与具名组**可以并存**：受众是一个并集，`all ∪ 任何东西 = all`。并存时具名组
    /// 仍然参与 [`validate_audience`] 的检查 —— 否则 `[all, finnance]` 这样一个拼错的组名
    /// 会因为 `all` 兜底而永远没人发现。
    ///
    /// # Errors
    ///
    /// 见 [`AudienceError`]。
    pub fn parse<I, S>(entries: I) -> Result<Self, AudienceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut everyone = false;
        let mut named = BTreeSet::new();
        let mut seen_any = false;
        for entry in entries {
            seen_any = true;
            let raw = entry.as_ref();
            if raw == RESERVED_AUDIENCE_ALL {
                everyone = true;
                continue;
            }
            if raw.trim().is_empty() {
                return Err(AudienceError::BlankGroupName);
            }
            named.insert(raw.to_owned());
        }
        if !seen_any {
            return Err(AudienceError::NoAudience);
        }
        Ok(Self { everyone, named })
    }

    /// 是否包含保留字 `all`。
    #[must_use]
    pub const fn is_everyone(&self) -> bool {
        self.everyone
    }

    /// 具名组的原始名字。
    #[must_use]
    pub const fn named_groups(&self) -> &BTreeSet<String> {
        &self.named
    }
}

/// 部署形态。
///
/// 来自 `AuthContext::is_single_user()`（`OPENBOT_SINGLE_USER=true` / Desktop Local）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeploymentMode {
    /// 只有一个 principal。
    SingleUser,
    /// 多用户 Server。
    MultiUser,
}

/// 包校验对这个 channel 的结论性说明。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AudienceNote {
    /// 正常：受众由 `all` 与 / 或具名组裁决。
    GroupsDecide,
    /// 单用户模式：组不参与裁决。
    ///
    /// v3 §6.5 条 3 逐字要求包报告注明这一句。它是**标识符**不是文案 —— 真正的句子由 GUI
    /// 按 locale 渲染（repository contract §4a）。
    SingleUserGroupsIgnored,
}

impl AudienceNote {
    /// 稳定标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GroupsDecide => "groups_decide",
            Self::SingleUserGroupsIgnored => "single_user_groups_ignored",
        }
    }
}

/// 包校验通过时的报告。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudienceReport {
    note: AudienceNote,
    providers_without_mapping: Vec<IdentityProviderId>,
}

impl AudienceReport {
    /// 结论性说明。
    #[must_use]
    pub const fn note(&self) -> AudienceNote {
        self.note
    }

    /// 已配置但**没有** group mapping 的 IdP。
    ///
    /// 它不改变校验的成败（v3 条 3 的判据是「有没有任何一家配了」），但它是一条真实的
    /// 后果：这些 IdP 的用户永远进不了任何具名组 channel。让包报告说出来，比让人几个月后
    /// 从「为什么 Okta 的同事看不到这个频道」开始排查便宜得多。
    #[must_use]
    pub fn providers_without_mapping(&self) -> &[IdentityProviderId] {
        &self.providers_without_mapping
    }
}

/// 包校验失败：具名组没有任何 IdP 能解析。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AudienceValidationError {
    /// 用了具名组，但这个部署一家动态 IdP 都没配。
    #[error("channel_named_groups_without_identity_provider")]
    NamedGroupsWithoutIdentityProvider,
    /// 配了 IdP，但没有任何一家配了 group mapping。
    ///
    /// 携带缺 mapping 的那几家 —— v3 §6.5 条 3 要求「指出缺哪一家的 mapping」。
    #[error("channel_named_groups_without_group_mapping")]
    NamedGroupsWithoutGroupMapping {
        /// 缺 group mapping 的 IdP。
        missing: Vec<IdentityProviderId>,
    },
}

impl AudienceValidationError {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NamedGroupsWithoutIdentityProvider => {
                "channel_named_groups_without_identity_provider"
            }
            Self::NamedGroupsWithoutGroupMapping { .. } => {
                "channel_named_groups_without_group_mapping"
            }
        }
    }
}

/// 校验一个 channel 的受众在这个部署里说得通。
///
/// `providers` 是**已配置的全部动态 IdP**，`mappings` 是其中配了 group mapping 的那些。
/// 两个参数分开传，是因为「一家 IdP 存在」与「它配了 group mapping」是两件不同的事，而
/// 错误消息要能指出后者缺在哪几家 —— 只传 mappings 的话，缺的那几家的名字根本传不进来。
///
/// # 单用户模式为什么不拒绝启动
///
/// v3 §6.5 条 3 逐字：单用户模式只有一个 principal，组无法区分任何人，所以该 principal 被
/// provision 进**全部**包 channel，包报告注明「单用户：组不参与裁决」，**不拒绝启动**。
/// 在一个只有一个人的部署里，因为「没配 IdP group mapping」而拒绝启动，是让一条对谁都没
/// 有意义的规则挡住整个产品。
///
/// # Errors
///
/// 见 [`AudienceValidationError`]。
pub fn validate_audience(
    audience: &ChannelAudience,
    mode: DeploymentMode,
    providers: &[IdentityProviderId],
    mappings: &[IdpGroupMapping],
) -> Result<AudienceReport, AudienceValidationError> {
    if mode == DeploymentMode::SingleUser {
        return Ok(AudienceReport {
            note: AudienceNote::SingleUserGroupsIgnored,
            providers_without_mapping: Vec::new(),
        });
    }

    let mapped: BTreeSet<&IdentityProviderId> =
        mappings.iter().map(IdpGroupMapping::provider).collect();
    // 排序而不是沿用 `providers` 的顺序：这份清单会进错误消息与包报告，而调用方给的顺序
    // 可能来自一次没有 ORDER BY 的查询 —— 那会让同一个部署的同一条错误在两次启动之间
    // 长得不一样，既没法写进测试，也让人怀疑是不是配置变了。
    let mut providers_without_mapping: Vec<IdentityProviderId> = providers
        .iter()
        .filter(|provider| !mapped.contains(provider))
        .cloned()
        .collect();
    providers_without_mapping.sort_unstable();
    providers_without_mapping.dedup();

    if !audience.named.is_empty() && mappings.is_empty() {
        return Err(if providers.is_empty() {
            AudienceValidationError::NamedGroupsWithoutIdentityProvider
        } else {
            AudienceValidationError::NamedGroupsWithoutGroupMapping {
                missing: providers_without_mapping,
            }
        });
    }

    Ok(AudienceReport {
        note: AudienceNote::GroupsDecide,
        providers_without_mapping,
    })
}

// ---------------------------------------------------------------------------
// 有效主体与 membership 投影
// ---------------------------------------------------------------------------

/// 一个**有效**主体：通过了撤权闸门，可以被 provision 进 channel。
///
/// # 为什么构造它需要一份 [`AccessCleared`]
///
/// §6.5 条 2 里的「全体**有效**用户」那三个字要有意义，就必须有一个地方保证「被移除的人
/// 不算」。放在这里是因为 provisioning 是**写**：一次给被移除的人写 membership 行的操作，
/// 会在他被恢复之前一直留在库里，而运行时可见性查的正是这些行。要求闸门证明之后，这条路
/// 在类型上就不存在了。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectivePrincipal {
    actor: ActorId,
    email: NormalizedEmail,
    groups: BTreeSet<GroupName>,
    normalization: GroupNormalization,
    mode: DeploymentMode,
}

impl EffectivePrincipal {
    /// 由撤权闸门的证明 + 本次登录解析出的组构造。
    ///
    /// `normalization` 必须是**产出这批组的那一家 IdP** 的规则：匹配时包里的组名要用同一
    /// 档规则来折（见 [`GroupNormalization`]）。单用户模式没有 IdP，用
    /// [`GroupNormalization::Exact`] 即可 —— 那一档不改变任何字节，而且单用户模式下组本来
    /// 就不参与裁决。
    #[must_use]
    pub fn from_cleared(
        cleared: &AccessCleared,
        actor: ActorId,
        mode: DeploymentMode,
        groups: BTreeSet<GroupName>,
        normalization: GroupNormalization,
    ) -> Self {
        Self {
            actor,
            email: cleared.email().clone(),
            groups,
            normalization,
            mode,
        }
    }

    /// 主体身份。
    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 主体地址（已规范化）。
    #[must_use]
    pub const fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    /// 本次登录解析出的组。
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<GroupName> {
        &self.groups
    }

    /// 这批组是用哪一档规则折出来的。
    #[must_use]
    pub const fn normalization(&self) -> GroupNormalization {
        self.normalization
    }

    /// 部署形态。
    #[must_use]
    pub const fn mode(&self) -> DeploymentMode {
        self.mode
    }
}

/// 一个 channel 与它的受众。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelAudienceBinding {
    channel: ChannelId,
    audience: ChannelAudience,
}

impl ChannelAudienceBinding {
    /// 绑定一个 channel 与它解析好的受众。
    #[must_use]
    pub const fn new(channel: ChannelId, audience: ChannelAudience) -> Self {
        Self { channel, audience }
    }

    /// channel 身份。
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }

    /// 受众。
    #[must_use]
    pub const fn audience(&self) -> &ChannelAudience {
        &self.audience
    }
}

/// 应当为某个主体**写入**的 channel membership 集合。
///
/// # 它不是可见性答案
///
/// 名字里的 provisioning 是契约的一部分，见模块文档最后一节：运行时可见性只查
/// materialized membership（`openbot-application::ports::ChannelReader`）。本类型是那些行
/// 该长什么样的**计划**。
///
/// 同一个函数服务两个时刻（v3 §6.5 条 4）：包同步时对全体既有主体跑一遍（这就是对 `all`
/// 的全量 provision），新用户首次登录时对他跑一遍（补齐）。两个时刻用同一个纯函数，
/// 是「补齐」不会与「全量」给出不同答案的唯一保证。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct MembershipProvisioningPlan {
    channels: BTreeSet<ChannelId>,
}

impl MembershipProvisioningPlan {
    /// 从数据库当前 materialized membership 水合上一版计划。
    ///
    /// 这是 I/O adapter 的入口，不是第二条可见性判定：运行时仍只查物理 membership；本值只
    /// 用来与本次 [`project_membership`] 结果求 diff。
    pub fn from_materialized(channels: impl IntoIterator<Item = ChannelId>) -> Self {
        Self {
            channels: channels.into_iter().collect(),
        }
    }

    /// 应当持有 membership 的 channel。
    #[must_use]
    pub const fn channels(&self) -> &BTreeSet<ChannelId> {
        &self.channels
    }

    /// 与上一次的投影相比，多了什么、少了什么。
    pub fn diff(&self, previous: &Self) -> MembershipDelta {
        MembershipDelta {
            granted: self
                .channels
                .difference(&previous.channels)
                .cloned()
                .collect(),
            revoked: previous
                .channels
                .difference(&self.channels)
                .cloned()
                .collect(),
        }
    }
}

/// 为一个主体计算 membership 投影。
///
/// 单用户模式：**全部** channel（v3 §6.5 条 3）。多用户：`all` 的 channel 加上具名组命中的
/// channel，两边的组名都用主体自己那一档规则折。
pub fn project_membership(
    principal: &EffectivePrincipal,
    channels: &[ChannelAudienceBinding],
) -> MembershipProvisioningPlan {
    let mut selected = BTreeSet::new();
    for binding in channels {
        let included = match principal.mode {
            DeploymentMode::SingleUser => true,
            DeploymentMode::MultiUser => {
                binding.audience.everyone
                    || binding.audience.named.iter().any(|raw| {
                        GroupName::fold(raw, principal.normalization)
                            .is_some_and(|name| principal.groups.contains(&name))
                    })
            }
        };
        if included {
            selected.insert(binding.channel.clone());
        }
    }
    MembershipProvisioningPlan { channels: selected }
}

/// 两次投影之间的差。
///
/// # 为什么执行必须走 [`Self::settle`]
///
/// v3 §6.5 条 6：IdP 撤组之后要**递增 auth generation 并撤销相应 membership，不等待下次
/// 应用重启**。删 membership 行只解决「下次列表里没有它」，解决不了「此刻已经订在那个
/// channel 上的 WS subscription」—— 那条连接不会再查一次库。代际是它唯一看得见的信号。
///
/// 所以撤销与递增是**同一件事的两半**。把它们做成两个可以分别调用的东西，就一定会有人
/// 只调前一半（而且系统看起来完全正常）。[`Self::settle`] 是唯一能拿到可执行形态的入口，
/// 它把新代际一并交出来。[`Self::granted`] / [`Self::revoked`] 只读，供审计投影。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct MembershipDelta {
    granted: BTreeSet<ChannelId>,
    revoked: BTreeSet<ChannelId>,
}

impl MembershipDelta {
    /// 新增的 channel（只读投影）。
    #[must_use]
    pub const fn granted(&self) -> &BTreeSet<ChannelId> {
        &self.granted
    }

    /// 被撤销的 channel（只读投影）。
    #[must_use]
    pub const fn revoked(&self) -> &BTreeSet<ChannelId> {
        &self.revoked
    }

    /// 没有任何变化。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.granted.is_empty() && self.revoked.is_empty()
    }

    /// 收口成可执行形态，并给出执行之后应当写下的代际。
    ///
    /// 有撤销时代际递增，只有新增时不递增：新增不作废任何既有授权，递增只会把这个人手上
    /// 全部还有效的票据无谓地打掉一次（每次登录都重算 membership，那意味着**每次登录**
    /// 都会作废他自己刚拿到的东西）。
    pub fn settle(self, current: AuthGeneration) -> MembershipSettlement {
        let generation = if self.revoked.is_empty() {
            current
        } else {
            current.next()
        };
        MembershipSettlement {
            granted: self.granted,
            revoked: self.revoked,
            generation,
        }
    }
}

/// membership 变更的可执行形态：写什么、删什么、代际落到几。
///
/// 三样在**同一个事务**里落地。代际先于 membership 行写入还是之后，在事务内不可观察；
/// 分成两个事务则会开一个窗口，那期间旧票据仍然指着一个已经被撤销的 channel。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct MembershipSettlement {
    granted: BTreeSet<ChannelId>,
    revoked: BTreeSet<ChannelId>,
    generation: AuthGeneration,
}

impl MembershipSettlement {
    /// 要写入的 membership。
    #[must_use]
    pub const fn granted(&self) -> &BTreeSet<ChannelId> {
        &self.granted
    }

    /// 要删除的 membership。
    #[must_use]
    pub const fn revoked(&self) -> &BTreeSet<ChannelId> {
        &self.revoked
    }

    /// 执行之后这个主体的 auth generation。
    #[must_use]
    pub const fn generation(&self) -> AuthGeneration {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::revocation::{DenyListAnswer, SignInPath, screen_sign_in};
    use serde_json::json;

    fn cleared(address: &str) -> AccessCleared {
        let email = NormalizedEmail::normalize(address).unwrap();
        screen_sign_in(
            DenyListAnswer::not_listed(email),
            SignInPath::ReturningAccount,
        )
        .expect("普通地址通过闸门")
    }

    fn principal(
        groups: &[&str],
        rule: GroupNormalization,
        mode: DeploymentMode,
    ) -> EffectivePrincipal {
        let folded = groups
            .iter()
            .filter_map(|raw| GroupName::fold(raw, rule))
            .collect();
        EffectivePrincipal::from_cleared(
            &cleared("person@example.com"),
            ActorId::new("actor-1"),
            mode,
            folded,
            rule,
        )
    }

    fn binding(id: &str, entries: &[&str]) -> ChannelAudienceBinding {
        ChannelAudienceBinding::new(
            ChannelId::new(id),
            ChannelAudience::parse(entries).expect("测试受众可解析"),
        )
    }

    // -- 三档 ---------------------------------------------------------------

    /// 空列表是**错误**，不是「对所有人不可达」。
    #[test]
    fn an_empty_audience_is_a_package_error() {
        assert_eq!(
            ChannelAudience::parse(Vec::<String>::new()),
            Err(AudienceError::NoAudience)
        );
        assert_eq!(
            ChannelAudience::parse(Vec::<String>::new())
                .unwrap_err()
                .code(),
            "channel_has_no_audience"
        );
        assert_eq!(
            ChannelAudience::parse(["risk", ""]),
            Err(AudienceError::BlankGroupName)
        );
        // 正向对照：非空列表解析得出来。
        assert!(ChannelAudience::parse(["all"]).is_ok());
    }

    /// 随包示例 `examples/fintech/channels.yaml` 的两种写法都必须解析得出来。
    #[test]
    fn the_shipped_example_package_parses() {
        let everyone = ChannelAudience::parse(["all"]).unwrap();
        assert!(everyone.is_everyone());
        assert!(everyone.named_groups().is_empty());

        let named = ChannelAudience::parse(["risk", "compliance"]).unwrap();
        assert!(!named.is_everyone());
        assert_eq!(named.named_groups().len(), 2);
    }

    /// 保留字**区分大小写** —— `All` 是一个具名组，不是全体。
    #[test]
    fn reserved_word_is_case_sensitive() {
        let all = ChannelAudience::parse(["all"]).unwrap();
        assert!(all.is_everyone());

        for lookalike in ["All", "ALL", " all", "all "] {
            let audience = ChannelAudience::parse([lookalike]).unwrap();
            assert!(
                !audience.is_everyone(),
                "{lookalike:?} 不是保留字，它是一个具名组"
            );
            assert!(audience.named_groups().contains(lookalike));
        }
    }

    /// `all` 与具名组并存时具名组仍然要过校验 —— 否则拼错的组名永远没人发现。
    #[test]
    fn a_typo_next_to_all_still_fails_validation() {
        let audience = ChannelAudience::parse(["all", "finnance"]).unwrap();
        assert!(audience.is_everyone());
        let error = validate_audience(&audience, DeploymentMode::MultiUser, &[], &[])
            .expect_err("具名组没有任何 IdP 能解析");
        assert_eq!(
            error,
            AudienceValidationError::NamedGroupsWithoutIdentityProvider
        );
    }

    /// 具名组没有任何 mapping 时校验失败，并**指出缺哪一家**。
    #[test]
    fn named_groups_without_any_mapping_name_the_providers_that_lack_one() {
        let audience = ChannelAudience::parse(["risk"]).unwrap();
        let okta = IdentityProviderId::new("okta-acme");
        let entra = IdentityProviderId::new("entra-acme");

        let error = validate_audience(
            &audience,
            DeploymentMode::MultiUser,
            &[okta.clone(), entra.clone()],
            &[],
        )
        .expect_err("一家都没配 mapping");
        assert_eq!(
            error,
            AudienceValidationError::NamedGroupsWithoutGroupMapping {
                missing: vec![entra.clone(), okta.clone()],
            },
            "错误必须点名缺 mapping 的那几家"
        );

        // 正向对照 1：有一家配了 mapping 就通过，同时报告点出另一家仍然缺。
        let mapping = IdpGroupMapping::new(
            okta.clone(),
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::Exact,
        );
        let report = validate_audience(
            &audience,
            DeploymentMode::MultiUser,
            &[okta, entra.clone()],
            std::slice::from_ref(&mapping),
        )
        .expect("至少一家配了就通过");
        assert_eq!(report.note(), AudienceNote::GroupsDecide);
        assert_eq!(report.providers_without_mapping(), [entra]);

        // 正向对照 2：只用 `all` 的 channel 不需要任何 mapping。
        let everyone = ChannelAudience::parse(["all"]).unwrap();
        assert!(validate_audience(&everyone, DeploymentMode::MultiUser, &[], &[]).is_ok());
    }

    /// 单用户模式不拒绝启动，且报告注明组不参与裁决。
    #[test]
    fn single_user_mode_never_refuses_a_package_over_groups() {
        let audience = ChannelAudience::parse(["risk", "compliance"]).unwrap();
        let report = validate_audience(&audience, DeploymentMode::SingleUser, &[], &[])
            .expect("单用户模式不因为组而拒绝启动");
        assert_eq!(report.note(), AudienceNote::SingleUserGroupsIgnored);
        assert_eq!(report.note().code(), "single_user_groups_ignored");
    }

    // -- claim 解析 ---------------------------------------------------------

    fn mapping_at(path: GroupClaimPath, rule: GroupNormalization) -> IdpGroupMapping {
        IdpGroupMapping::new(IdentityProviderId::new("idp-1"), path, rule)
    }

    #[test]
    fn a_flat_group_array_resolves() {
        let claims = json!({ "groups": ["risk", "compliance"] });
        let mapping = mapping_at(
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::Exact,
        );
        let resolved = resolve_group_claims(&claims, &mapping).unwrap();
        assert!(resolved.claim_present());
        assert_eq!(resolved.groups().len(), 2);
        assert!(
            resolved
                .groups()
                .contains(&GroupName::fold("risk", GroupNormalization::Exact).unwrap())
        );
    }

    #[test]
    fn a_nested_path_resolves_and_a_single_string_counts_as_one_group() {
        let claims = json!({ "resource_access": { "roles": ["risk"] } });
        let mapping = mapping_at(
            GroupClaimPath::from_dotted("resource_access.roles").unwrap(),
            GroupNormalization::Exact,
        );
        assert_eq!(
            resolve_group_claims(&claims, &mapping)
                .unwrap()
                .groups()
                .len(),
            1
        );

        let single = json!({ "resource_access": { "roles": "risk" } });
        assert_eq!(
            resolve_group_claims(&single, &mapping)
                .unwrap()
                .groups()
                .len(),
            1
        );
    }

    /// 缺 claim 不是错误，但它与「组为空」是两个可分辨的答案。
    #[test]
    fn a_missing_claim_is_not_an_error_but_is_told_apart_from_an_empty_one() {
        let mapping = mapping_at(
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::Exact,
        );

        let absent = resolve_group_claims(&json!({ "sub": "u-1" }), &mapping).unwrap();
        assert!(absent.groups().is_empty());
        assert!(!absent.claim_present(), "路径不存在多半是配置写错了");

        let empty = resolve_group_claims(&json!({ "groups": [] }), &mapping).unwrap();
        assert!(empty.groups().is_empty());
        assert!(empty.claim_present(), "路径存在但数组为空只是这个人没分组");
    }

    /// 认不出的形状 fail-closed，绝不「尽力转换」。
    #[test]
    fn unknown_claim_shapes_are_refused_rather_than_coerced() {
        let mapping = mapping_at(
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::Exact,
        );
        for hostile in [
            json!({ "groups": 42 }),
            json!({ "groups": [42] }),
            json!({ "groups": [["risk"]] }),
            json!({ "groups": { "risk": true } }),
            json!({ "groups": null }),
        ] {
            assert_eq!(
                resolve_group_claims(&hostile, &mapping),
                Err(GroupClaimShapeRejected),
                "{hostile} 必须被拒"
            );
        }

        // 路径中途撞上非对象。
        let nested = mapping_at(
            GroupClaimPath::from_dotted("a.b").unwrap(),
            GroupNormalization::Exact,
        );
        assert_eq!(
            resolve_group_claims(&json!({ "a": ["x"] }), &nested),
            Err(GroupClaimShapeRejected)
        );

        // 负向对照：**不做**空格切分 —— 一个带空格的组名保持为一个组。
        let spaced =
            resolve_group_claims(&json!({ "groups": ["Finance Team"] }), &mapping).unwrap();
        assert_eq!(spaced.groups().len(), 1);
        assert!(
            !spaced
                .groups()
                .contains(&GroupName::fold("Finance", GroupNormalization::Exact).unwrap()),
            "按空格切分会凭空造出一个 Finance 组的成员资格"
        );
    }

    /// 命名空间 claim 名必须走 segments 形式 —— 点号形式会把它切碎。
    #[test]
    fn namespaced_claim_names_need_the_segment_form() {
        let claim_name = "https://app.example.com/groups";
        let claims = json!({ claim_name: ["risk"] });

        let segments = mapping_at(
            GroupClaimPath::from_segments([claim_name]).unwrap(),
            GroupNormalization::Exact,
        );
        assert_eq!(
            resolve_group_claims(&claims, &segments)
                .unwrap()
                .groups()
                .len(),
            1
        );

        // 负向对照：同一个名字按点号切分之后什么都取不到，而且**不报错** ——
        // 这正是它危险的地方，所以文档里把它写成陷阱。
        let dotted = mapping_at(
            GroupClaimPath::from_dotted(claim_name).unwrap(),
            GroupNormalization::Exact,
        );
        let resolved = resolve_group_claims(&claims, &dotted).unwrap();
        assert!(resolved.groups().is_empty());
        assert!(!resolved.claim_present());
    }

    #[test]
    fn empty_path_segments_are_refused() {
        for bad in ["", "a..b", ".a", "a."] {
            assert_eq!(GroupClaimPath::from_dotted(bad), Err(GroupClaimPathInvalid));
        }
        assert_eq!(
            GroupClaimPath::from_segments(Vec::<String>::new()),
            Err(GroupClaimPathInvalid)
        );
        // 正向对照。
        assert_eq!(
            GroupClaimPath::from_dotted("a.b")
                .unwrap()
                .segments()
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    // -- 投影 ---------------------------------------------------------------

    /// 两边用同一档规则折 —— 大小写不一致不会让一半的人进不去。
    #[test]
    fn both_sides_are_folded_with_the_same_rule() {
        let channels = [binding("c-risk", &["Finance"])];

        // 这家 IdP 把组折成小写；包里写的是 `Finance`。两边同规则 ⇒ 命中。
        let lowercased = principal(
            &["FINANCE"],
            GroupNormalization::TrimLowercase,
            DeploymentMode::MultiUser,
        );
        assert_eq!(
            project_membership(&lowercased, &channels).channels().len(),
            1,
            "包里的组名要用主体那一档规则折，否则 TrimLowercase 的 IdP 永远匹配不上"
        );

        // 负向对照：Exact 档下 `FINANCE` 与 `Finance` 是两个组。
        let exact = principal(
            &["FINANCE"],
            GroupNormalization::Exact,
            DeploymentMode::MultiUser,
        );
        assert!(project_membership(&exact, &channels).channels().is_empty());

        // 正向对照：Exact 档下写对大小写就命中。
        let exact_match = principal(
            &["Finance"],
            GroupNormalization::Exact,
            DeploymentMode::MultiUser,
        );
        assert_eq!(
            project_membership(&exact_match, &channels).channels().len(),
            1
        );
    }

    #[test]
    fn everyone_channels_reach_users_with_no_groups_at_all() {
        let channels = [binding("c-all", &["all"]), binding("c-risk", &["risk"])];
        let nobody_special = principal(&[], GroupNormalization::Exact, DeploymentMode::MultiUser);
        let plan = project_membership(&nobody_special, &channels);
        assert_eq!(plan.channels().len(), 1);
        assert!(plan.channels().contains(&ChannelId::new("c-all")));
        assert!(
            !plan.channels().contains(&ChannelId::new("c-risk")),
            "没有组的人不该进具名组 channel"
        );
    }

    /// 单用户模式：唯一的 principal 进**全部** channel（v3 §6.5 条 3）。
    #[test]
    fn the_single_user_principal_is_provisioned_into_every_channel() {
        let channels = [
            binding("c-all", &["all"]),
            binding("c-risk", &["risk"]),
            binding("c-compliance", &["compliance"]),
        ];
        let solo = principal(&[], GroupNormalization::Exact, DeploymentMode::SingleUser);
        assert_eq!(project_membership(&solo, &channels).channels().len(), 3);

        // 负向对照：同样没有组的多用户主体只进 `all` 的那个。
        let multi = principal(&[], GroupNormalization::Exact, DeploymentMode::MultiUser);
        assert_eq!(project_membership(&multi, &channels).channels().len(), 1);
    }

    /// 撤组 → 递增代际 + 撤销 membership，两半一起。
    #[test]
    fn losing_a_group_revokes_membership_and_advances_the_generation() {
        let channels = [binding("c-all", &["all"]), binding("c-risk", &["risk"])];
        let before = project_membership(
            &principal(
                &["risk"],
                GroupNormalization::Exact,
                DeploymentMode::MultiUser,
            ),
            &channels,
        );
        let after = project_membership(
            &principal(&[], GroupNormalization::Exact, DeploymentMode::MultiUser),
            &channels,
        );

        let delta = after.diff(&before);
        assert!(delta.granted().is_empty());
        assert_eq!(delta.revoked().len(), 1);
        assert!(delta.revoked().contains(&ChannelId::new("c-risk")));
        assert!(!delta.is_empty());

        let settlement = delta.settle(AuthGeneration::new(7));
        assert_eq!(
            settlement.generation(),
            AuthGeneration::new(8),
            "撤销 membership 必须同时递增代际，否则已经订上去的 WS subscription 不会知道"
        );
        assert_eq!(settlement.revoked().len(), 1);
    }

    /// 只新增时**不**递增代际 —— 否则每次登录都会把自己刚拿到的票据打掉。
    #[test]
    fn gaining_a_group_does_not_advance_the_generation() {
        let channels = [binding("c-risk", &["risk"])];
        let before = MembershipProvisioningPlan::default();
        let after = project_membership(
            &principal(
                &["risk"],
                GroupNormalization::Exact,
                DeploymentMode::MultiUser,
            ),
            &channels,
        );

        let delta = after.diff(&before);
        assert_eq!(delta.granted().len(), 1);
        assert!(delta.revoked().is_empty());

        let settlement = delta.settle(AuthGeneration::new(7));
        assert_eq!(settlement.generation(), AuthGeneration::new(7));
        assert_eq!(settlement.granted().len(), 1);
    }

    /// 没有变化时既不写也不递增。
    #[test]
    fn an_unchanged_projection_settles_to_nothing() {
        let channels = [binding("c-all", &["all"])];
        let who = principal(&[], GroupNormalization::Exact, DeploymentMode::MultiUser);
        let plan = project_membership(&who, &channels);
        let delta = plan.diff(&plan);
        assert!(delta.is_empty());
        assert_eq!(
            delta.settle(AuthGeneration::new(3)).generation(),
            AuthGeneration::new(3)
        );
    }

    /// 「包同步的全量 provision」与「新用户首次登录的补齐」是**同一个函数**，
    /// 所以两个时刻不可能给出不同答案（v3 §6.5 条 4）。
    #[test]
    fn package_sync_and_first_sign_in_use_the_same_projection() {
        let channels = [binding("c-all", &["all"]), binding("c-risk", &["risk"])];
        let who = principal(
            &["risk"],
            GroupNormalization::Exact,
            DeploymentMode::MultiUser,
        );
        let at_package_sync = project_membership(&who, &channels);
        let at_first_sign_in = project_membership(&who, &channels);
        assert_eq!(at_package_sync, at_first_sign_in);
        assert_eq!(at_package_sync.channels().len(), 2);
    }

    #[test]
    fn codes_are_distinct_and_agree_with_display() {
        assert_eq!(
            AudienceError::NoAudience.to_string(),
            "channel_has_no_audience"
        );
        assert_eq!(
            AudienceError::BlankGroupName.to_string(),
            AudienceError::BlankGroupName.code()
        );
        assert_eq!(
            AudienceValidationError::NamedGroupsWithoutIdentityProvider.to_string(),
            AudienceValidationError::NamedGroupsWithoutIdentityProvider.code()
        );
        let with_missing = AudienceValidationError::NamedGroupsWithoutGroupMapping {
            missing: vec![IdentityProviderId::new("okta")],
        };
        assert_eq!(with_missing.to_string(), with_missing.code());

        let mut codes = vec![
            AudienceError::NoAudience.code(),
            AudienceError::BlankGroupName.code(),
            AudienceValidationError::NamedGroupsWithoutIdentityProvider.code(),
            with_missing.code(),
            GroupClaimShapeRejected.code(),
            GroupClaimPathInvalid.code(),
            AudienceNote::GroupsDecide.code(),
            AudienceNote::SingleUserGroupsIgnored.code(),
        ];
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total);

        assert_eq!(GroupNormalization::ALL.len(), 2);
        assert_ne!(
            GroupNormalization::Exact.as_str(),
            GroupNormalization::TrimLowercase.as_str()
        );
    }

    /// 有效主体只能从撤权闸门的证明构造 —— 被移除的人拿不到 `AccessCleared`，
    /// 因此也拿不到 membership 行。
    #[test]
    fn a_revoked_person_can_never_reach_the_projection() {
        let email = NormalizedEmail::normalize("removed@example.com").unwrap();
        let refused = screen_sign_in(DenyListAnswer::listed(email), SignInPath::ReturningAccount);
        assert!(
            refused.is_err(),
            "被移除的人拿不到 AccessCleared，于是 EffectivePrincipal 构造不出来"
        );

        // 正向对照：没被移除的人拿得到，投影跑得通。
        let ok = principal(&[], GroupNormalization::Exact, DeploymentMode::MultiUser);
        assert!(
            project_membership(&ok, &[binding("c-all", &["all"])])
                .channels()
                .contains(&ChannelId::new("c-all"))
        );
    }
}
