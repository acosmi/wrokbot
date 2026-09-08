//! 角色解析、admin floor 与角色变更的授权规则（v3 §6.2 条 6/7，上游 `auth/roles.ts` +
//! `auth/guards.ts`）。
//!
//! # 三条各自挡住一种失效的规则
//!
//! 1. **缺角色行 = 403，不是降级成 `user`**。上游 `guards.ts::createRequireUser` 的解析是
//!    `roles.includes("admin") ? "admin" : roles.includes("user") ? "user" : undefined`，
//!    随后 `if (!role) return 403`。`parity/tables.yaml::tbl-user-roles` 的 notes 把它写成
//!    对 Rust 侧的要求：「枚举必须封闭且 default-deny，缺行 = 非 admin」。这里落成
//!    [`resolve_effective_role`] 返回 `Result` 而不是 `Role` —— 一个返回 `Role` 的函数
//!    必须在「没有任何角色行」时编出一个答案，而唯一能编的答案是 `User`，那就是静默提权。
//!
//! 2. **设角色是一次原子的集合替换，不是一次插入**。`user_roles` 的主键是 `(user_id, role)`
//!    复合键（同上 notes），即它是一个**集合**；而守卫「有 admin 行就算 admin」。所以
//!    「把某人设为 user」必须删掉 admin 行，只插一行 user 是无操作。上游
//!    `roles.ts::setRole` 的注释还给出了第二半理由，逐字：两条语句必须在同一个事务里，
//!    否则中间态是「这个人没有任何角色」，另一个进程上的请求会拿到一个读起来像权限 bug
//!    的 403。这里落成 [`RoleAssignmentPlan`]：它**恒**携带两条语句，没有只含插入的构造
//!    路径。
//!
//! 3. **`INITIAL_ADMIN_EMAILS` 是 floor，不是初始值**。上游
//!    `roles.ts::applyConfiguredAdmin` 的注释记着这条修的是什么：角色过去只在建账号时写
//!    一次，于是编辑名单**什么都不会发生**，而且没有任何一屏能补救。所以 floor 每次登录
//!    重新施加，且**只提升不降级** —— 别人的角色归管理界面裁决，一次登录把它覆盖掉会让
//!    那一屏在这个人下次回来之前一直在撒谎。
//!
//! # 事务边界不在这里，但「必须是一次原子替换」这条规则在这里
//!
//! 领域层不碰事务（`openbot-domain` 的 crate 文档：SQL、连接池在 `openbot-infra`）。
//! 本模块给出的是**计划**：一个不可拆的、恒含两条语句的值。infra 拿到它之后必须在单个
//! 事务里执行两条 —— 这一点由 [`RoleAssignmentPlan::statements`] 的返回类型
//! `[RoleStatement; 2]` 表达：拿不到只有一条语句的计划。

use std::collections::BTreeSet;

use openbot_contracts::auth::Role;
use openbot_contracts::ids::ActorId;

use super::email::NormalizedEmail;

/// 封闭角色全集。
///
/// 与 `openbot_contracts::auth::Role` 的变体一一对应，由
/// [`index_in_all_roles`] 的穷尽 `match` 双向钉死：contracts 里加一个变体，这里当场编译
/// 失败。没有这个钉子的话，新增一个角色会让 [`plan_set_role`] 悄悄漏删一类行 ——
/// 「设为 user」不再删掉新角色的行，于是设完角色的人还留着旧权限。
pub const ALL_ROLES: [Role; 2] = [Role::Admin, Role::User];

/// 某个角色在 [`ALL_ROLES`] 里的下标。
///
/// 存在的唯一理由是那个穷尽 `match`：它把「`ALL_ROLES` 是全集」从一句注释变成一条编译期
/// 事实。
const fn index_in_all_roles(role: Role) -> usize {
    match role {
        Role::Admin => 0,
        Role::User => 1,
    }
}

/// 由配置固定为管理员的地址集合（`INITIAL_ADMIN_EMAILS`）。
///
/// # 为什么它**不可能为空**
///
/// 空集合与「没有配置 floor」在上游是两种不同的处境，压成一个类型就把它们的区别删掉了：
///
/// - 配了 sign-in 却没给任何地址：上游 `config.ts` 直接**拒绝启动**，错误原文逐字说明
///   理由 ——「Nothing else grants the role, and no screen can promote somebody once the
///   deployment is running」。
/// - 单用户模式（`OPENBOT_SINGLE_USER=true`）：压根没有 floor，也没有 sign-in。
///
/// 所以本类型的构造入口在集合为空时返回 [`AdminFloorEmpty`]，而「没有 floor」由调用方用
/// `Option<AdminFloor>` 表达。一个可以为空的 `AdminFloor` 会让第二种处境伪装成第一种。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminFloor {
    emails: BTreeSet<NormalizedEmail>,
}

/// 配置里没有任何可用的管理员地址。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_admin_floor_empty")]
pub struct AdminFloorEmpty;

impl AdminFloorEmpty {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_admin_floor_empty"
    }
}

impl AdminFloor {
    /// 由配置项逐条构造。
    ///
    /// 每一条都过 [`NormalizedEmail::normalize`]；**规范化后为空的条目被丢弃**，与上游
    /// `config.ts::commaSeparated` 的 `.filter(Boolean)` 逐字一致 —— 一个尾随逗号或
    /// `"a@x.com,,b@x.com"` 不该让部署起不来，但也绝不能变成 floor 上一条空条目
    /// （理由见 [`super::email::EmailBlank`]）。
    ///
    /// 逗号切分**不在这里**：那是配置层的事（`commaSeparated`）。本函数收的是已经切好的
    /// 条目，这样「怎么切」与「切完算什么」各归其位。
    ///
    /// # Errors
    ///
    /// 丢弃空条目之后一条不剩时返回 [`AdminFloorEmpty`]。
    pub fn from_configured<I, S>(entries: I) -> Result<Self, AdminFloorEmpty>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let emails: BTreeSet<NormalizedEmail> = entries
            .into_iter()
            .filter_map(|entry| NormalizedEmail::normalize(entry.as_ref()).ok())
            .collect();
        if emails.is_empty() {
            return Err(AdminFloorEmpty);
        }
        Ok(Self { emails })
    }

    /// 这个地址是否被配置钉死为管理员。
    ///
    /// 比较发生在两个 [`NormalizedEmail`] 之间，所以「一边规范化了另一边没有」这种
    /// 形态在类型上不存在。
    #[must_use]
    pub fn contains(&self, email: &NormalizedEmail) -> bool {
        self.emails.contains(email)
    }

    /// floor 上的地址数量。用于启动期自检与审计投影。
    #[must_use]
    pub fn len(&self) -> usize {
        self.emails.len()
    }

    /// 恒为 `false`（本类型不可能为空），提供它只是为了满足 clippy 对 `len` 的配套要求。
    ///
    /// 它的答案是构造性的而不是运行期算出来的 —— 这一点由
    /// `admin_floor_is_never_empty_by_construction` 钉住。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.emails.is_empty()
    }

    /// 迭代 floor 上的地址。用于启动期把配置回显给运维。
    pub fn iter(&self) -> impl Iterator<Item = &NormalizedEmail> {
        self.emails.iter()
    }
}

/// 没有任何角色行 —— 按 default-deny 拒绝，不降级成 [`Role::User`]。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_no_role")]
pub struct NoRole;

impl NoRole {
    /// 稳定的分类标识符。上游同一处返回 403（`guards.ts::createRequireUser`）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_no_role"
    }
}

/// 把 `user_roles` 的行折成这次请求的有效角色。
///
/// 优先级 `admin` > `user`，与上游 `guards.ts::createRequireUser` 和
/// `people/store.ts::list`（`row.roles.includes("admin") ? "admin" : "user"`）一致。
///
/// # Errors
///
/// 一行都没有时返回 [`NoRole`]。**这不是 `User`** —— 见模块文档第 1 条。
pub fn resolve_effective_role<I>(rows: I) -> Result<Role, NoRole>
where
    I: IntoIterator<Item = Role>,
{
    let mut seen_user = false;
    for role in rows {
        match role {
            // admin 一旦出现就是答案，不必看完 —— 但也不能提前 return 之前忘了它是优先级
            // 最高的那个：这就是把优先级写成显式 match 而不是 `.contains()` 链的原因。
            Role::Admin => return Ok(Role::Admin),
            Role::User => seen_user = true,
        }
    }
    if seen_user {
        Ok(Role::User)
    } else {
        Err(NoRole)
    }
}

/// 一条要在事务里执行的 `user_roles` 语句。
///
/// 封闭枚举：它描述的是 infra 必须执行的**两种**写，不是一个可扩展的 DSL。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoleStatement {
    /// 删除该 actor **除 `keep` 之外**的全部角色行。
    ///
    /// 「除…之外」而不是「全删再插」，与上游 `setRole` 的
    /// `delete(...).where(and(eq(userId), ne(role, target)))` 逐字一致：保留目标行可以让
    /// 一次幂等的重复设置不产生「这个人短暂没有任何角色」的中间态。
    DeleteAllRolesExcept {
        /// 要保留的角色。
        keep: Role,
    },
    /// 插入角色行，主键冲突即忽略（上游 `onConflictDoNothing`）。
    UpsertRole {
        /// 要确保存在的角色。
        role: Role,
    },
}

/// 一次角色设定的完整计划。
///
/// # 它为什么是一个值而不是两个函数
///
/// 「设角色 = 删该删的 + 插该插的，且两者同事务」这条规则如果表达成两个可以分别调用的
/// 函数，就一定会有调用点只调其中一个 —— 而只调插入的那一个是**无操作**（守卫看的是
/// 「有没有 admin 行」，多插一行 user 不会拿掉 admin 行）。所以计划是一个整体：
/// [`Self::statements`] 的返回类型是 `[RoleStatement; 2]`，拿不到只有一条语句的版本。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RoleAssignmentPlan {
    subject: ActorId,
    target: Role,
}

impl RoleAssignmentPlan {
    /// 被设定角色的 actor。
    #[must_use]
    pub fn subject(&self) -> &ActorId {
        &self.subject
    }

    /// 设定之后这个人应当持有的**唯一**角色。
    #[must_use]
    pub const fn target(&self) -> Role {
        self.target
    }

    /// 必须在**同一个事务**里按顺序执行的两条语句。
    ///
    /// 顺序是「先删后插」，与上游 `setRole` 一致。反过来也能得到正确的最终状态，但先插
    /// 后删会在事务内部多出一个「同时持有两个角色」的瞬间；对一个以「有 admin 行就算
    /// admin」为判据的系统来说，那个瞬间的语义是提权而不是降权，没有理由制造它。
    #[must_use]
    pub const fn statements(&self) -> [RoleStatement; 2] {
        [
            RoleStatement::DeleteAllRolesExcept { keep: self.target },
            RoleStatement::UpsertRole { role: self.target },
        ]
    }

    /// 这次设定会删掉哪些角色行。派生量，供审计投影用。
    ///
    /// 按 [`index_in_all_roles`] 的下标筛而不是按 `!=` 筛：这样 [`ALL_ROLES`] 的那个穷尽
    /// `match` 落在**生产代码**的调用链上，而不是只被测试用到 —— 一个只在 `cfg(test)` 下
    /// 存在的编译期钉子，在 `cargo build` 里是照不到的。
    #[must_use]
    pub fn removes(&self) -> Vec<Role> {
        let keep = index_in_all_roles(self.target);
        ALL_ROLES
            .into_iter()
            .enumerate()
            .filter_map(|(index, role)| (index != keep).then_some(role))
            .collect()
    }
}

/// 计划把某人的角色集合替换成恰好一个 `target`。
///
/// 这是本模块唯一的 [`RoleAssignmentPlan`] 构造入口。
pub fn plan_set_role(subject: &ActorId, target: Role) -> RoleAssignmentPlan {
    RoleAssignmentPlan {
        subject: subject.clone(),
        target,
    }
}

/// 新身份第一次落库时的角色：在配置管理员 floor 上即 admin，否则 user。
///
/// 这同时承载固定上游 `roleForEmail` 与 `seedRole` 的纯判定；数据库写仍必须通过
/// [`plan_set_role`]，不能把“判角色”和“如何原子替换角色集合”揉成两份真源。
#[must_use]
pub fn seed_role(floor: &AdminFloor, email: &NormalizedEmail) -> Role {
    if floor.contains(email) {
        Role::Admin
    } else {
        Role::User
    }
}

/// 每次登录重新施加 admin floor 的结果。
///
/// # 为什么是枚举，而不是「一个计划 + 一个 `granted: bool`」
///
/// 上游 `applyConfiguredAdmin` 的返回值是一个布尔，它的注释解释了这个布尔为什么必须
/// 存在，逐字：floor 是静默施加的，于是**任何能编辑 `INITIAL_ADMIN_EMAILS` 的人都能
/// 把自己变成管理员，而没有任何地方留下一行记录**；同时一个每次登录都写审计行的老管理
/// 员会把这条记录淹掉，所以它答的是「**这一次**是不是它授予的」。
///
/// 一个布尔的问题在于它可以被忽略。做成枚举之后，调用点必须 `match` 三个变体才能拿到
/// 里面的计划 —— 而 [`Self::Granted`] 是唯一一个「必须同时写审计行」的变体，它无法在
/// 不被看见的情况下被执行。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum AdminFloorDecision {
    /// 这个地址不在 floor 上：**什么都不做**。
    ///
    /// 不是「降级成 user」。这个人的角色归管理界面裁决，一次登录把它覆盖掉会让那一屏
    /// 在他下次回来之前一直在撒谎（上游注释原文的意思）。
    NotOnFloor,
    /// 在 floor 上，而且**已经**是管理员：执行计划（幂等），**不写审计行**。
    AlreadyAdmin(RoleAssignmentPlan),
    /// 在 floor 上，此前**不是**管理员：执行计划，**并且必须写一行审计**。
    ///
    /// 这一行是「谁靠编辑配置把自己变成了管理员」这个问题的唯一答案。
    Granted(RoleAssignmentPlan),
}

/// 施加 admin floor：只提升，不降级。
///
/// `current_role` 是这个人此刻的有效角色（[`resolve_effective_role`] 的结果）；用它而不是
/// 「有没有 admin 行」这样一个单独的布尔，是为了让 floor 的判据与守卫的判据来自同一次
/// 解析 —— 两个各自计算的判据迟早会分叉。
///
/// `floor` 是 `Option`：单用户模式没有 floor（见 [`AdminFloor`] 的类型文档）。
pub fn apply_admin_floor(
    floor: Option<&AdminFloor>,
    subject: &ActorId,
    email: &NormalizedEmail,
    current_role: Result<Role, NoRole>,
) -> AdminFloorDecision {
    let Some(floor) = floor else {
        return AdminFloorDecision::NotOnFloor;
    };
    if !floor.contains(email) {
        return AdminFloorDecision::NotOnFloor;
    }
    let plan = plan_set_role(subject, Role::Admin);
    if current_role == Ok(Role::Admin) {
        AdminFloorDecision::AlreadyAdmin(plan)
    } else {
        AdminFloorDecision::Granted(plan)
    }
}

/// 一次角色变更请求的全部输入。
///
/// 全部字段公开：它是一个输入捆绑，不承载不变量。不变量在
/// [`authorize_role_change`] 的返回值上。
#[derive(Clone, Copy, Debug)]
pub struct RoleChangeRequest<'a> {
    /// 发起这次变更的管理员。
    pub actor: &'a ActorId,
    /// 被改的人。
    pub subject: &'a ActorId,
    /// 被改的人的地址，用于判 admin floor。
    pub subject_email: &'a NormalizedEmail,
    /// 被改的人**此刻**的有效角色。
    pub subject_role: Role,
    /// 目标角色。
    pub desired_role: Role,
    /// **除被改的人之外**，此刻还有几个有效管理员。
    ///
    /// 「有效」= 持有 admin 角色**且未被撤权**。调用方必须在与本次写入相同的事务 /
    /// 快照里数这个数 —— 用一个陈旧的计数做判定，恰好是本字段要挡住的那个竞态
    /// （见 [`RoleChangeRejection::LastAdmin`]）。
    pub other_effective_admins: usize,
}

/// 角色变更被拒绝的理由。
///
/// 每个变体对应一次**不同的补救动作**，所以它们必须是不同的 code：一个统一的
/// `role_change_denied` 会让管理员不知道该去改配置、去找同事、还是先提一个人。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum RoleChangeRejection {
    /// 这个地址被 `INITIAL_ADMIN_EMAILS` 钉死为管理员，界面上不能降权。
    ///
    /// 上游 `app.ts` 在同一处返回 409，注释原文的理由是：floor 会在这个人下次登录时把他
    /// 重新提上来，所以放行这次降权只会产出一屏**在他回来之前一直在撒谎**的界面。
    /// 正确答案是去改配置。
    #[error("identity_role_change_configured_admin")]
    ConfiguredAdmin,
    /// 管理员不能撤销自己的管理员角色。
    ///
    /// 上游 `app.ts` 的注释：这么做的人刚好把自己锁在唯一能撤销这个动作的那一屏外面。
    /// 别人可以替他做，于是交接仍然可能，而误触不再等于锁死。
    #[error("identity_role_change_self_demotion")]
    SelfDemotion,
    /// 这会让部署里一个有效管理员都不剩。
    ///
    /// # 这一条是**新增**，不是 parity（v3 §6.2 条 7）
    ///
    /// 本轮实测：上游 `server/src/app.ts` 恰有 **4** 处 409，逐条是「配置管理员不可降权 /
    /// 配置管理员不可撤销 / 不可自我降权 / 不可自我撤销」；全 `server/src` 里
    /// 「数一数还剩几个管理员」的逻辑**零命中**（正向对照：同一批文件 `requireAdmin`
    /// 命中 38 处，所以那条 grep 不是在一个空目录上跑出来的空结果）。
    ///
    /// 上游不是漏了这条，是**换了个办法**：`auth/roles.ts::isConfiguredAdmin` 的注释把
    /// `INITIAL_ADMIN_EMAILS` 说成「最后一个管理员误把自己降权之后回来的那条路」——
    /// 用一条恒定的 floor 代替一次运行期计数。对「单人误触」这个场景它是对的，也更便宜。
    ///
    /// v3 仍然要这条计数，是因为 floor 盖不住两种处境：
    ///
    /// 1. **并发**：两个管理员同时把对方降权，各自的自我检查都通过，落地之后零管理员。
    ///    自我检查看的是**身份**，这一条看的是**剩余数量** —— 只有后者能看见另一个进程
    ///    正在做什么（前提是调用方在同一个事务 / 快照里数，见
    ///    [`RoleChangeRequest::other_effective_admins`]）。
    /// 2. **floor 要求那个人真的回来登录一次**。「有一条恢复路径」不等于「此刻有人能
    ///    管理这个部署」；floor 上的地址可能属于一个已经离职的人。
    #[error("identity_role_change_last_admin")]
    LastAdmin,
}

impl RoleChangeRejection {
    /// 稳定的分类标识符。上游对应处一律 409（§15.3）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConfiguredAdmin => "identity_role_change_configured_admin",
            Self::SelfDemotion => "identity_role_change_self_demotion",
            Self::LastAdmin => "identity_role_change_last_admin",
        }
    }
}

/// 授权通过之后要做的事。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum RoleChangeEffect {
    /// 目标角色与现状相同：不写库，也不写审计行。
    ///
    /// 与上游 `app.ts` 的 `if (person.role !== role)` 一致。这不是省一次写的优化：
    /// 一次没有变化的「变更」写进审计链之后，「谁在什么时候改了谁的角色」这张表里就会
    /// 混进一批什么也没改的行。
    Unchanged,
    /// 执行这个计划，并写一行角色变更审计。
    Change(RoleAssignmentPlan),
}

/// 判定一次角色变更是否被允许。
///
/// 检查顺序 = floor → 自我降权 → 最后一个管理员，**与上游 `app.ts` 的顺序一致**（前两条）。
/// 顺序是可观察的：一个既在 floor 上又是自己的请求会拿到 [`RoleChangeRejection::ConfiguredAdmin`]。
/// 这是刻意的 —— 那个答案指向「去改配置」，是唯一能真正生效的补救；而
/// 「你不能给自己降权」会把人引去找同事，而同事做同一件事同样会被 floor 挡住。
///
/// # Errors
///
/// 见 [`RoleChangeRejection`]。
pub fn authorize_role_change(
    floor: Option<&AdminFloor>,
    request: &RoleChangeRequest<'_>,
) -> Result<RoleChangeEffect, RoleChangeRejection> {
    let demoting_from_admin =
        request.subject_role == Role::Admin && request.desired_role != Role::Admin;

    if demoting_from_admin && floor.is_some_and(|floor| floor.contains(request.subject_email)) {
        return Err(RoleChangeRejection::ConfiguredAdmin);
    }
    if demoting_from_admin && request.actor == request.subject {
        return Err(RoleChangeRejection::SelfDemotion);
    }
    if demoting_from_admin && request.other_effective_admins == 0 {
        return Err(RoleChangeRejection::LastAdmin);
    }

    if request.subject_role == request.desired_role {
        return Ok(RoleChangeEffect::Unchanged);
    }
    Ok(RoleChangeEffect::Change(plan_set_role(
        request.subject,
        request.desired_role,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(raw: &str) -> NormalizedEmail {
        NormalizedEmail::normalize(raw).expect("测试地址非空")
    }

    fn floor_of(entries: &[&str]) -> AdminFloor {
        AdminFloor::from_configured(entries).expect("测试 floor 非空")
    }

    /// [`ALL_ROLES`] 与 contracts 的封闭枚举双向对齐。
    #[test]
    fn all_roles_is_the_whole_closed_set() {
        assert_eq!(ALL_ROLES.len(), 2);
        for role in ALL_ROLES {
            assert_eq!(ALL_ROLES[index_in_all_roles(role)], role);
        }
        // 反向：两个下标各自被恰好一个角色占用。
        assert_ne!(
            index_in_all_roles(Role::Admin),
            index_in_all_roles(Role::User)
        );
    }

    /// 缺角色行 = 拒绝，不是降级成 user。
    #[test]
    fn missing_role_rows_are_refused_not_downgraded() {
        assert_eq!(resolve_effective_role([]), Err(NoRole));
        assert_ne!(
            resolve_effective_role([]),
            Ok(Role::User),
            "把「没有角色」答成 user 就是一次静默提权"
        );
    }

    /// 正向对照：有行时确实解析得出来，而且 admin 优先。
    #[test]
    fn admin_wins_over_user_and_order_does_not_matter() {
        assert_eq!(resolve_effective_role([Role::User]), Ok(Role::User));
        assert_eq!(resolve_effective_role([Role::Admin]), Ok(Role::Admin));
        assert_eq!(
            resolve_effective_role([Role::User, Role::Admin]),
            Ok(Role::Admin)
        );
        assert_eq!(
            resolve_effective_role([Role::Admin, Role::User]),
            Ok(Role::Admin)
        );
        // 重复行不影响答案（`user_roles` 是集合，但读侧不该依赖这一点）。
        assert_eq!(
            resolve_effective_role([Role::User, Role::User]),
            Ok(Role::User)
        );
    }

    /// 设角色恒是「删 + 插」两条，而且删的那条恰好覆盖目标之外的全部角色。
    #[test]
    fn setting_a_role_always_removes_the_other_rows() {
        let subject = ActorId::new("actor-1");
        for target in ALL_ROLES {
            let plan = plan_set_role(&subject, target);
            let statements = plan.statements();
            assert_eq!(
                statements,
                [
                    RoleStatement::DeleteAllRolesExcept { keep: target },
                    RoleStatement::UpsertRole { role: target },
                ],
                "计划恒含两条语句，且先删后插"
            );

            let removed = plan.removes();
            assert!(!removed.contains(&target));
            let mut covered = removed.clone();
            covered.push(target);
            covered.sort_unstable();
            let mut expected = ALL_ROLES.to_vec();
            expected.sort_unstable();
            assert_eq!(covered, expected, "删的 + 留的 = 全集，一个不漏一个不多");
        }
    }

    /// 负向对照：「只插一行」在这个模型里是无操作 —— 这正是计划不能被拆开的理由。
    ///
    /// 断言的形态是：只执行 `UpsertRole { User }` 之后，一个原本持有 admin 行的人
    /// 解析出来仍然是 admin。
    #[test]
    fn inserting_only_would_leave_the_admin_row_in_place() {
        let existing_rows = [Role::Admin];
        let insert_only: Vec<Role> = existing_rows.into_iter().chain([Role::User]).collect();
        assert_eq!(
            resolve_effective_role(insert_only),
            Ok(Role::Admin),
            "只插不删 = 降权无效；所以 RoleAssignmentPlan 不提供只含插入的形态"
        );

        // 正向对照：执行完整计划（删掉非 user 的行）之后，解析结果才是 user。
        let after_full_plan: Vec<Role> = existing_rows
            .into_iter()
            .filter(|role| *role == Role::User)
            .chain([Role::User])
            .collect();
        assert_eq!(resolve_effective_role(after_full_plan), Ok(Role::User));
    }

    #[test]
    fn admin_floor_drops_blank_entries_and_normalizes() {
        let floor = floor_of(&["  Ops@Example.COM ", "", "   ", "second@x.com"]);
        assert_eq!(floor.len(), 2);
        assert!(floor.contains(&email("ops@example.com")));
        assert!(floor.contains(&email("OPS@EXAMPLE.COM")));
        assert!(!floor.contains(&email("other@x.com")));
    }

    #[test]
    fn admin_floor_is_never_empty_by_construction() {
        assert_eq!(
            AdminFloor::from_configured(Vec::<String>::new()),
            Err(AdminFloorEmpty)
        );
        assert_eq!(AdminFloor::from_configured([" ", ""]), Err(AdminFloorEmpty));
        // 正向对照：一条有效条目就足以构造成功，所以上面两条不是「永远构造不出来」。
        let floor = floor_of(&["a@x.com"]);
        assert!(!floor.is_empty());
        assert_eq!(floor.iter().count(), 1);
    }

    /// 固定上游 `roleForEmail` / `seedRole` 四条用例的共同纯判定。
    #[test]
    fn seed_role_uses_the_normalized_admin_floor_and_defaults_to_user() {
        let floor = floor_of(&[" admin@openbot.test "]);
        assert_eq!(seed_role(&floor, &email("Admin@OpenBot.test")), Role::Admin);
        assert_eq!(seed_role(&floor, &email("member@openbot.test")), Role::User);
    }

    /// floor 每次登录重新施加：名单里新加的人，下次登录就被提上来。
    #[test]
    fn floor_promotes_on_every_sign_in_and_reports_whether_it_granted() {
        let floor = floor_of(&["boss@x.com"]);
        let subject = ActorId::new("actor-boss");
        let boss = email("Boss@X.com");

        // 第一次：此前是普通用户 → Granted（必须写审计行）。
        let first = apply_admin_floor(Some(&floor), &subject, &boss, Ok(Role::User));
        let AdminFloorDecision::Granted(plan) = first else {
            panic!("名单里的人第一次登录必须被提升，且这次调用要报告是它授予的");
        };
        assert_eq!(plan.target(), Role::Admin);
        assert_eq!(plan.subject(), &subject);

        // 第二次：已经是管理员 → AlreadyAdmin（仍然执行计划，但不写审计行）。
        let second = apply_admin_floor(Some(&floor), &subject, &boss, Ok(Role::Admin));
        assert!(
            matches!(second, AdminFloorDecision::AlreadyAdmin(_)),
            "回访的管理员不该每次登录都产一行审计"
        );

        // 连一行角色都没有的人（新建账号那一刻）同样被提升。
        let third = apply_admin_floor(Some(&floor), &subject, &boss, Err(NoRole));
        assert!(matches!(third, AdminFloorDecision::Granted(_)));
    }

    /// 只提升不降级：不在名单上的人，floor 什么都不做。
    #[test]
    fn floor_never_demotes_anybody() {
        let floor = floor_of(&["boss@x.com"]);
        let subject = ActorId::new("actor-someone");
        // 管理界面把这个人提成了管理员，他不在配置名单上 —— floor 必须放着不动。
        let decision = apply_admin_floor(
            Some(&floor),
            &subject,
            &email("someone@x.com"),
            Ok(Role::Admin),
        );
        assert_eq!(
            decision,
            AdminFloorDecision::NotOnFloor,
            "一次登录若能覆盖管理界面的裁决，那一屏就会在他下次回来之前一直撒谎"
        );

        // 没有配置 floor（单用户模式）时同理。
        assert_eq!(
            apply_admin_floor(None, &subject, &email("boss@x.com"), Ok(Role::User)),
            AdminFloorDecision::NotOnFloor
        );
    }

    #[test]
    fn configured_admin_cannot_be_demoted_from_the_screen() {
        let floor = floor_of(&["boss@x.com"]);
        let actor = ActorId::new("actor-other-admin");
        let subject = ActorId::new("actor-boss");
        let boss = email("boss@x.com");
        let request = RoleChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &boss,
            subject_role: Role::Admin,
            desired_role: Role::User,
            other_effective_admins: 5,
        };
        assert_eq!(
            authorize_role_change(Some(&floor), &request),
            Err(RoleChangeRejection::ConfiguredAdmin)
        );

        // 正向对照：不在 floor 上的同一次降权是允许的 —— 证明上一条拦的是 floor
        // 而不是「所有降权」。
        let plain = email("plain@x.com");
        let allowed = RoleChangeRequest {
            subject_email: &plain,
            ..request
        };
        assert_eq!(
            authorize_role_change(Some(&floor), &allowed),
            Ok(RoleChangeEffect::Change(plan_set_role(
                &subject,
                Role::User
            )))
        );
    }

    /// floor 的答案优先于自我降权的答案，理由见 [`authorize_role_change`] 的文档。
    #[test]
    fn floor_answer_wins_over_self_demotion_answer() {
        let floor = floor_of(&["boss@x.com"]);
        let boss_id = ActorId::new("actor-boss");
        let boss = email("boss@x.com");
        let request = RoleChangeRequest {
            actor: &boss_id,
            subject: &boss_id,
            subject_email: &boss,
            subject_role: Role::Admin,
            desired_role: Role::User,
            other_effective_admins: 3,
        };
        assert_eq!(
            authorize_role_change(Some(&floor), &request),
            Err(RoleChangeRejection::ConfiguredAdmin),
            "两条都成立时给出的必须是那个能真正生效的补救：去改配置"
        );
    }

    #[test]
    fn nobody_demotes_themselves() {
        let me = ActorId::new("actor-me");
        let mine = email("me@x.com");
        let request = RoleChangeRequest {
            actor: &me,
            subject: &me,
            subject_email: &mine,
            subject_role: Role::Admin,
            desired_role: Role::User,
            other_effective_admins: 4,
        };
        assert_eq!(
            authorize_role_change(None, &request),
            Err(RoleChangeRejection::SelfDemotion)
        );

        // 正向对照：把自己**提**成管理员不受这条约束（现实里它是无操作，但判据必须
        // 只挡降权，否则 floor 的重新施加也会被自己挡住）。
        let promote = RoleChangeRequest {
            subject_role: Role::User,
            desired_role: Role::Admin,
            ..request
        };
        assert_eq!(
            authorize_role_change(None, &promote),
            Ok(RoleChangeEffect::Change(plan_set_role(&me, Role::Admin)))
        );
    }

    /// **新增**规则：降到零管理员被拒。它挡住的是自我检查看不见的那个并发。
    #[test]
    fn the_last_effective_admin_cannot_be_demoted_by_somebody_else() {
        let peer = ActorId::new("actor-peer");
        let subject = ActorId::new("actor-last");
        let last = email("last@x.com");
        let request = RoleChangeRequest {
            actor: &peer,
            subject: &subject,
            subject_email: &last,
            subject_role: Role::Admin,
            desired_role: Role::User,
            // peer 正在被另一个并发请求降权，所以此刻「除 subject 外的有效管理员」是 0。
            other_effective_admins: 0,
        };
        assert_eq!(
            authorize_role_change(None, &request),
            Err(RoleChangeRejection::LastAdmin)
        );

        // 正向对照：还剩一个别的管理员时，同一次降权放行。
        let with_spare = RoleChangeRequest {
            other_effective_admins: 1,
            ..request
        };
        assert_eq!(
            authorize_role_change(None, &with_spare),
            Ok(RoleChangeEffect::Change(plan_set_role(
                &subject,
                Role::User
            )))
        );
    }

    #[test]
    fn a_change_to_the_same_role_writes_nothing() {
        let actor = ActorId::new("actor-admin");
        let subject = ActorId::new("actor-user");
        let address = email("u@x.com");
        let request = RoleChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &address,
            subject_role: Role::User,
            desired_role: Role::User,
            other_effective_admins: 2,
        };
        assert_eq!(
            authorize_role_change(None, &request),
            Ok(RoleChangeEffect::Unchanged)
        );
    }

    /// 提升永远不受三条拒绝规则约束 —— 它们全部只针对「拿掉管理员身份」。
    #[test]
    fn promotions_are_never_blocked_by_the_demotion_guards() {
        let me = ActorId::new("actor-me");
        let mine = email("me@x.com");
        let floor = floor_of(&["me@x.com"]);
        let request = RoleChangeRequest {
            actor: &me,
            subject: &me,
            subject_email: &mine,
            subject_role: Role::User,
            desired_role: Role::Admin,
            other_effective_admins: 0,
        };
        assert_eq!(
            authorize_role_change(Some(&floor), &request),
            Ok(RoleChangeEffect::Change(plan_set_role(&me, Role::Admin)))
        );
    }

    #[test]
    fn rejection_codes_are_distinct_and_agree_with_display() {
        let all = [
            RoleChangeRejection::ConfiguredAdmin,
            RoleChangeRejection::SelfDemotion,
            RoleChangeRejection::LastAdmin,
        ];
        for rejection in all {
            assert_eq!(rejection.to_string(), rejection.code());
        }
        let mut codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "三种补救动作必须有三个不同的 code");

        assert_eq!(NoRole.to_string(), NoRole.code());
        assert_eq!(AdminFloorEmpty.to_string(), AdminFloorEmpty.code());
    }
}
