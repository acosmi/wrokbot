//! 撤权：deny 名单、登录闸门与「移除一个人」要做的全部事（v3 §6.2 条 8 / 条 10，
//! 上游 `auth/index.ts` + `people/store.ts`）。
//!
//! # 为什么 deny 名单的键是 email 而不是 user id
//!
//! `parity/tables.yaml::tbl-revoked-access` 的 notes 逐字：
//!
//! > PK=email（不是 user id：删 user 行不是移除，下次 IdP 登录会重建；地址是唯一活得下来
//! > 的键）
//!
//! 上游 `db/schema/core.ts::revokedAccess` 的注释是同一句话的展开版：删掉 user 行之后，
//! 下一次经 IdP 登录会用一个**全新的 id** 把这个人重新建出来，什么都不记得。所以「移除」
//! 必须锚在跨账号存活的东西上，那就是地址 —— 而地址要成为可靠的键，前提是它先经过
//! [`NormalizedEmail`]。
//!
//! # 为什么必须有两条路径，以及本模块怎么让它们跑不掉
//!
//! 上游在**两处**拦被移除的人，`auth/index.ts` 的两段注释各自解释了自己为什么存在：
//!
//! - `databaseHooks.user.create.before`：「Refuse before the account exists.」—— 被移除的
//!   人再登录时会以一个**全新的 id**、没有角色、也不记得被移除过的身份到达，这正是 deny
//!   名单按地址而不是按 id 建键的原因。
//! - `databaseHooks.session.create.before`：「And again for somebody who already has an
//!   account. The user hook above only fires for a new one, so without this a removed person
//!   signs straight back in.」
//!
//! 少任何一处都会漏，而且漏的方式**不对称**：只有前一处时，老账号直接签回来；只有后一处
//! 时，新账号行已经写进库了才被拒（管理界面上多出一个幽灵）。
//!
//! 这里不靠注释守。[`AccessCleared`] 没有 public 字段、没有 `Default`、没有第二个构造
//! 函数，而 [`super::session::authenticate`] 与 [`super::groups::EffectivePrincipal`] 的
//! 构造**都要求它**。于是「铸造一个 session」与「构造一个有效主体」这两件事，在类型上
//! 都必须先经过 [`screen_sign_in`]；忘了接一条路径的后果从「静默放行」变成「编译不过」。
//!
//! [`SignInPath`] 是封闭枚举且带 [`SignInPath::ALL`]，所以将来多出第三条登录路径（例如
//! token 刷新）时，穷尽 `match` 与遍历 `ALL` 的测试会一起红，逼着那条新路径当场做出
//! 「要不要过闸门」的裁决，而不是默默地不过。

use openbot_contracts::auth::Role;
use openbot_contracts::ids::ActorId;

use super::email::NormalizedEmail;
use super::generation::AuthGeneration;
use super::roles::AdminFloor;

/// 一次登录到达撤权闸门时的路径。封闭枚举。
///
/// 两个变体对应上游 `auth/index.ts` 的两个 databaseHook，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignInPath {
    /// 这个部署里还没有这个人的账号行 —— IdP 第一次把他 provision 进来。
    ///
    /// 上游 `user.create.before`。被移除的人从这条路来时带的是一个全新 id，所以按 id
    /// 建的任何名单都拦不住他。
    NewAccount,
    /// 账号行已经存在，这是再次登录（建 session）。
    ///
    /// 上游 `session.create.before`。只接前一条时，这条路是被移除的人的直通车。
    ReturningAccount,
}

impl SignInPath {
    /// 全部路径。
    ///
    /// 遍历它的测试就是「每条路径都过了闸门」这条断言的执行体；新增变体会让那些测试
    /// 与本文件里的穷尽 `match` 一起红。
    pub const ALL: [Self; 2] = [Self::NewAccount, Self::ReturningAccount];

    /// 稳定标识符，进审计行用（上游把两处都记成 `session.refused`，但分不出是哪一处）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewAccount => "new_account",
            Self::ReturningAccount => "returning_account",
        }
    }
}

/// 一次 deny 名单查询的**结果**，与被查的那个地址绑在一起。
///
/// # 为什么答案要带上被查的地址
///
/// 因为「查了 A 却拿 B 去判定」是这条链上最容易发生也最难看出来的错误：两个钩子各自从
/// 不同的地方取地址（一个从 IdP profile，一个从 `users` 行反查），一次复制粘贴就足以让
/// 闸门查的是上一个人。把地址放进答案里之后，[`screen_sign_in`] 根本不接受第二个地址
/// 参数 —— 判定用的地址只能是被查的那一个。
///
/// 领域层无法保证调用方真的执行了那次查询（查询是 I/O）。它能保证的是：没有一个 session
/// 或有效主体能绕过这次判定存在。这条边界写在这里，是为了不假装它更强。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct DenyListAnswer {
    queried: NormalizedEmail,
    listed: bool,
}

impl DenyListAnswer {
    /// `revoked_access` 里**有**这个地址。
    pub const fn listed(queried: NormalizedEmail) -> Self {
        Self {
            queried,
            listed: true,
        }
    }

    /// `revoked_access` 里**没有**这个地址。
    ///
    /// 刻意是一个具名构造函数而不是 `new(email, false)`：一个布尔参数在调用点读作
    /// `false`，读不出「查过了，不在名单上」；写错也不会有人在 review 里发现。
    pub const fn not_listed(queried: NormalizedEmail) -> Self {
        Self {
            queried,
            listed: false,
        }
    }

    /// 被查的地址。
    #[must_use]
    pub const fn queried(&self) -> &NormalizedEmail {
        &self.queried
    }

    /// 这个地址是否在 deny 名单上。
    #[must_use]
    pub const fn is_listed(&self) -> bool {
        self.listed
    }
}

/// 这个地址已被管理员移除，登录被拒。
///
/// 携带路径供审计用：上游两处都记成 `session.refused`，于是「是哪一条路被拦的」这个
/// 排障信息在上游是丢失的。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_access_revoked")]
pub struct AccessRefused {
    path: SignInPath,
}

impl AccessRefused {
    /// 被拦下的那条路径。
    #[must_use]
    pub const fn path(self) -> SignInPath {
        self.path
    }

    /// 稳定的分类标识符。两条路径同一个 code —— 对被拒的人来说它们是同一件事，
    /// 而路径已经作为结构化字段带出去了，不必混进 code 里（§15.3：code 稳定，文案可本地化）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_access_revoked"
    }
}

/// 通过撤权闸门的**证明**。
///
/// 没有 public 字段、没有 `Default`、没有第二个构造函数：本 crate 里能产出它的只有
/// [`screen_sign_in`]。它是模块文档那条链路的中间环节 —— 铸造 session 与构造有效主体
/// 都以它为入参，于是撤权检查在类型上跑不掉。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct AccessCleared {
    email: NormalizedEmail,
    path: SignInPath,
}

impl AccessCleared {
    /// 通过闸门的那个地址。
    #[must_use]
    pub const fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    /// 这次通过的是哪条路径。
    #[must_use]
    pub const fn path(&self) -> SignInPath {
        self.path
    }
}

/// 撤权闸门：两条登录路径共用的**同一道**判定。
///
/// # Errors
///
/// 地址在 deny 名单上时返回 [`AccessRefused`]，其中带上被拦的路径。
pub fn screen_sign_in(
    answer: DenyListAnswer,
    path: SignInPath,
) -> Result<AccessCleared, AccessRefused> {
    if answer.listed {
        return Err(AccessRefused { path });
    }
    Ok(AccessCleared {
        email: answer.queried,
        path,
    })
}

/// 移除一个人时必须执行的一步。
///
/// 三步都在**同一个事务**里 —— 见 [`RevocationPlan::steps`] 的文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationStep<'a> {
    /// 把规范化地址写进 `revoked_access`（主键冲突即忽略）。
    ///
    /// 挡住的是**下一次**登录：deny 名单是那条路上唯一的关卡。
    DenyAddress {
        /// 要写入的地址。
        email: &'a NormalizedEmail,
        /// 执行这次移除的管理员，落 `revoked_by` 列（不是外键：管理员本人日后也可能被移除）。
        revoked_by: &'a ActorId,
    },
    /// 删掉这个人现存的全部 session 行。
    ///
    /// 挡住的是**当前**这一次：上游 `people/store.ts::revoke` 的注释逐字 ——
    /// 没有这一半，被移除的人会一直用到 cookie 自己过期为止，那可能是好几天。
    TerminateSessions {
        /// 被移除的人。
        subject: &'a ActorId,
    },
    /// 递增这个人的 auth generation。
    ///
    /// **新增**（v3 §6.2 条 10）。上游没有这一步，于是删 session 行拦不住那些**不经
    /// session 查库**的东西：已经建立的 WS subscription、已经发出去的 screen ticket、
    /// 客户 Agent 进程手里的 run assertion、已经批过的 approval。它们只在使用时对照
    /// 代际，所以撤权必须留下一个它们看得见的数字。
    AdvanceAuthGeneration {
        /// 被移除的人。
        subject: &'a ActorId,
        /// 递增之后的代际。
        to: AuthGeneration,
    },
}

/// 移除一个人的完整计划。
///
/// # 为什么是一个不可拆的值
///
/// 三步各自挡住一条不同的路（下一次登录 / 当前 session / 已经发出去的票据），少任何一步
/// 都留下一个「界面显示已移除，而这个人还在用」的窗口。做成一个恒含三步的值之后，
/// 「只写了 deny 行」这种半吊子实现拿不到类型。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RevocationPlan {
    subject: ActorId,
    email: NormalizedEmail,
    revoked_by: ActorId,
    next_generation: AuthGeneration,
}

impl RevocationPlan {
    /// 被移除的人。
    #[must_use]
    pub const fn subject(&self) -> &ActorId {
        &self.subject
    }

    /// 写进 deny 名单的地址（已规范化）。
    #[must_use]
    pub const fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    /// 递增之后的代际。
    #[must_use]
    pub const fn next_generation(&self) -> AuthGeneration {
        self.next_generation
    }

    /// 必须在**同一个事务**里执行的三步。
    ///
    /// 同事务的理由与顺序：deny 行与 session 删除在上游就是一个事务（`people/store.ts::
    /// revoke`）；代际递增加进来是因为它与前两者是同一条不变量的三个面，任何一个单独失败
    /// 都会留下一个可用的入口。
    ///
    /// 上游那条注释同时说明了**什么不在这个事务里**：撤销这个人授予部署的凭据
    /// （`retireOwnedCredentials`）刻意放在事务之后，因为它要写 vault 与审计，用另一个
    /// 句柄；把它拉进来会让一次无关的失败回滚掉「阻止他再进来」这两件必须落地的事。
    /// 那一步不属于本模块（它是 vault 的事），这里记下来是为了让读到这里的人知道它没被
    /// 忘掉。
    #[must_use]
    pub const fn steps(&self) -> [RevocationStep<'_>; 3] {
        [
            RevocationStep::DenyAddress {
                email: &self.email,
                revoked_by: &self.revoked_by,
            },
            RevocationStep::TerminateSessions {
                subject: &self.subject,
            },
            RevocationStep::AdvanceAuthGeneration {
                subject: &self.subject,
                to: self.next_generation,
            },
        ]
    }
}

/// 恢复一个人的访问时要执行的一步。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RestoreStep<'a> {
    /// 从 `revoked_access` 删掉这个地址。
    AllowAddress {
        /// 要删掉的地址。
        email: &'a NormalizedEmail,
    },
}

/// 恢复一个人的访问。
///
/// # 为什么这里**不**递增代际
///
/// 代际递增是为了让**既有的**授权立刻作废。恢复只是重新允许下一次登录，它不作废任何
/// 东西 —— 这个人此刻手里一张有效票据都没有（移除时已经全部作废了）。递增一次只会
/// 把同部署其它人的判定基准也动一下，纯粹是噪音。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RestorePlan {
    subject: ActorId,
    email: NormalizedEmail,
}

impl RestorePlan {
    /// 被恢复的人。
    #[must_use]
    pub const fn subject(&self) -> &ActorId {
        &self.subject
    }

    /// 从 deny 名单删掉的地址。
    #[must_use]
    pub const fn email(&self) -> &NormalizedEmail {
        &self.email
    }

    /// 要执行的步骤。
    #[must_use]
    pub const fn steps(&self) -> [RestoreStep<'_>; 1] {
        [RestoreStep::AllowAddress { email: &self.email }]
    }
}

/// 一次访问变更（移除 / 恢复）请求的全部输入。
#[derive(Clone, Copy, Debug)]
pub struct AccessChangeRequest<'a> {
    /// 发起这次变更的管理员。
    pub actor: &'a ActorId,
    /// 被改的人。
    pub subject: &'a ActorId,
    /// 被改的人的地址。
    pub subject_email: &'a NormalizedEmail,
    /// 被改的人此刻的有效角色。
    pub subject_role: Role,
    /// 被改的人此刻是否已被移除。
    pub subject_revoked: bool,
    /// 目标状态：`true` = 移除，`false` = 恢复。
    pub desired_revoked: bool,
    /// **除被改的人之外**，此刻还有几个有效管理员（定义与竞态理由见
    /// [`super::roles::RoleChangeRequest::other_effective_admins`]）。
    pub other_effective_admins: usize,
    /// 被改的人此刻的 auth generation。移除会在它之上递增。
    pub current_generation: AuthGeneration,
}

/// 访问变更被拒绝的理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AccessChangeRejection {
    /// 这个地址被 `INITIAL_ADMIN_EMAILS` 钉死，界面上不能移除。
    ///
    /// 上游 `app.ts` 的注释：移除一个配置钉死的人只能维持到他下次登录为止 —— floor 会
    /// 把他重新提成管理员，而 deny 名单是**登录前**的关卡，它会先把他拦住……于是这个
    /// 部署得到的是一个「名单说他是管理员、闸门说他进不来」的自相矛盾状态。正确答案
    /// 同样是去改配置。
    #[error("identity_access_change_configured_admin")]
    ConfiguredAdmin,
    /// 管理员不能移除自己。上游 `app.ts` 同一处 409。
    #[error("identity_access_change_self_revocation")]
    SelfRevocation,
    /// 这会让部署里一个有效管理员都不剩。**新增**（v3 §6.2 条 7），理由见
    /// [`super::roles::RoleChangeRejection::LastAdmin`]。
    #[error("identity_access_change_last_admin")]
    LastAdmin,
}

impl AccessChangeRejection {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConfiguredAdmin => "identity_access_change_configured_admin",
            Self::SelfRevocation => "identity_access_change_self_revocation",
            Self::LastAdmin => "identity_access_change_last_admin",
        }
    }
}

/// 授权通过之后要做的事。
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum AccessChangeEffect {
    /// 目标状态与现状相同：不写库，也不写审计行（上游 `if (person.revoked !== revoked)`）。
    Unchanged,
    /// 执行移除计划。
    Revoke(RevocationPlan),
    /// 执行恢复计划。
    Restore(RestorePlan),
}

/// 判定一次移除 / 恢复是否被允许。
///
/// 检查顺序 = floor → 自我移除 → 最后一个管理员，与
/// [`super::roles::authorize_role_change`] 同构，理由也相同。
///
/// # Errors
///
/// 见 [`AccessChangeRejection`]。
pub fn authorize_access_change(
    floor: Option<&AdminFloor>,
    request: &AccessChangeRequest<'_>,
) -> Result<AccessChangeEffect, AccessChangeRejection> {
    if request.desired_revoked {
        if floor.is_some_and(|floor| floor.contains(request.subject_email)) {
            return Err(AccessChangeRejection::ConfiguredAdmin);
        }
        if request.actor == request.subject {
            return Err(AccessChangeRejection::SelfRevocation);
        }
        if request.subject_role == Role::Admin && request.other_effective_admins == 0 {
            return Err(AccessChangeRejection::LastAdmin);
        }
    }

    if request.subject_revoked == request.desired_revoked {
        return Ok(AccessChangeEffect::Unchanged);
    }

    if request.desired_revoked {
        Ok(AccessChangeEffect::Revoke(RevocationPlan {
            subject: request.subject.clone(),
            email: request.subject_email.clone(),
            revoked_by: request.actor.clone(),
            next_generation: request.current_generation.next(),
        }))
    } else {
        Ok(AccessChangeEffect::Restore(RestorePlan {
            subject: request.subject.clone(),
            email: request.subject_email.clone(),
        }))
    }
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

    /// **两条路径都被拦**。这是模块文档那条不变量的执行体：遍历
    /// [`SignInPath::ALL`]，所以将来多出第三条路径时这里会红。
    #[test]
    fn a_revoked_address_is_refused_on_every_sign_in_path() {
        let removed = email("Removed@Example.com");
        for path in SignInPath::ALL {
            let answer = DenyListAnswer::listed(removed.clone());
            let refused = screen_sign_in(answer, path).expect_err("被移除的人必须被拒");
            assert_eq!(refused.path(), path, "拒绝要带上是哪条路被拦的");
            assert_eq!(refused.code(), "identity_access_revoked");
        }
        assert_eq!(SignInPath::ALL.len(), 2);
    }

    /// 正向对照：不在名单上的人两条路都放行 —— 否则上一条测试在「闸门恒拒」的世界里
    /// 同样通过，而那样的部署没有人能登录。
    #[test]
    fn an_ordinary_address_passes_on_every_sign_in_path() {
        let ordinary = email("ordinary@example.com");
        for path in SignInPath::ALL {
            let answer = DenyListAnswer::not_listed(ordinary.clone());
            let cleared = screen_sign_in(answer, path).expect("普通地址必须放行");
            assert_eq!(cleared.email(), &ordinary);
            assert_eq!(cleared.path(), path);
        }
    }

    /// 判定用的地址只能是被查的那一个 —— [`screen_sign_in`] 压根不接受第二个地址参数。
    ///
    /// 这条测试断言的是那个构造性事实的可观察后果：通过闸门之后拿到的地址，逐字等于
    /// 查询时用的地址。
    #[test]
    fn the_screened_address_is_the_one_that_was_queried() {
        let queried = email("Someone@Example.COM");
        let answer = DenyListAnswer::not_listed(queried.clone());
        assert_eq!(answer.queried(), &queried);
        assert!(!answer.is_listed());
        let cleared = screen_sign_in(answer, SignInPath::NewAccount).unwrap();
        assert_eq!(cleared.email().as_str(), "someone@example.com");
    }

    /// 大小写不同的写入与查询命中同一个键 —— 这条是 `tbl-revoked-access` 那条 notes 的
    /// 端到端兑现（写入用 [`RevocationPlan::email`]，查询用 [`DenyListAnswer`]）。
    #[test]
    fn revocation_writes_the_key_that_the_next_sign_in_will_look_up() {
        let actor = ActorId::new("actor-admin");
        let subject = ActorId::new("actor-target");
        let written_as = email("Removed.Person@EXAMPLE.com");
        let request = AccessChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &written_as,
            subject_role: Role::User,
            subject_revoked: false,
            desired_revoked: true,
            other_effective_admins: 2,
            current_generation: AuthGeneration::new(4),
        };
        let AccessChangeEffect::Revoke(plan) = authorize_access_change(None, &request).unwrap()
        else {
            panic!("普通用户的移除必须被允许");
        };

        // 下一次登录时 IdP 送来的地址大小写完全不同。
        let next_sign_in = email("removed.person@example.com");
        assert_eq!(
            plan.email(),
            &next_sign_in,
            "写入的键与下次查询的键必须相等，否则撤权在界面上显示成功而实际没生效"
        );
    }

    /// 移除恒含三步，缺一不可。
    #[test]
    fn revocation_always_carries_all_three_steps() {
        let actor = ActorId::new("actor-admin");
        let subject = ActorId::new("actor-target");
        let address = email("t@x.com");
        let request = AccessChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &address,
            subject_role: Role::User,
            subject_revoked: false,
            desired_revoked: true,
            other_effective_admins: 1,
            current_generation: AuthGeneration::new(9),
        };
        let AccessChangeEffect::Revoke(plan) = authorize_access_change(None, &request).unwrap()
        else {
            panic!("应当产出移除计划");
        };
        assert_eq!(plan.next_generation(), AuthGeneration::new(10));
        assert_eq!(
            plan.steps(),
            [
                RevocationStep::DenyAddress {
                    email: &address,
                    revoked_by: &actor,
                },
                RevocationStep::TerminateSessions { subject: &subject },
                RevocationStep::AdvanceAuthGeneration {
                    subject: &subject,
                    to: AuthGeneration::new(10),
                },
            ]
        );
    }

    /// 恢复只做一件事，而且**不**动代际。
    #[test]
    fn restoring_only_removes_the_deny_row_and_leaves_the_generation_alone() {
        let actor = ActorId::new("actor-admin");
        let subject = ActorId::new("actor-target");
        let address = email("t@x.com");
        let request = AccessChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &address,
            subject_role: Role::User,
            subject_revoked: true,
            desired_revoked: false,
            other_effective_admins: 1,
            current_generation: AuthGeneration::new(9),
        };
        let AccessChangeEffect::Restore(plan) = authorize_access_change(None, &request).unwrap()
        else {
            panic!("应当产出恢复计划");
        };
        assert_eq!(plan.subject(), &subject);
        assert_eq!(
            plan.steps(),
            [RestoreStep::AllowAddress { email: &address }]
        );
    }

    #[test]
    fn a_no_op_access_change_writes_nothing() {
        let actor = ActorId::new("actor-admin");
        let subject = ActorId::new("actor-target");
        let address = email("t@x.com");
        let base = AccessChangeRequest {
            actor: &actor,
            subject: &subject,
            subject_email: &address,
            subject_role: Role::User,
            subject_revoked: true,
            desired_revoked: true,
            other_effective_admins: 1,
            current_generation: AuthGeneration::new(9),
        };
        assert_eq!(
            authorize_access_change(None, &base),
            Ok(AccessChangeEffect::Unchanged)
        );
        let already_allowed = AccessChangeRequest {
            subject_revoked: false,
            desired_revoked: false,
            ..base
        };
        assert_eq!(
            authorize_access_change(None, &already_allowed),
            Ok(AccessChangeEffect::Unchanged)
        );
    }

    #[test]
    fn configured_admin_cannot_be_removed_and_nobody_removes_themselves() {
        let floor = floor_of(&["boss@x.com"]);
        let admin = ActorId::new("actor-admin");
        let boss_id = ActorId::new("actor-boss");
        let boss = email("boss@x.com");
        let request = AccessChangeRequest {
            actor: &admin,
            subject: &boss_id,
            subject_email: &boss,
            subject_role: Role::Admin,
            subject_revoked: false,
            desired_revoked: true,
            other_effective_admins: 3,
            current_generation: AuthGeneration::new(1),
        };
        assert_eq!(
            authorize_access_change(Some(&floor), &request),
            Err(AccessChangeRejection::ConfiguredAdmin)
        );

        let me = email("me@x.com");
        let self_removal = AccessChangeRequest {
            actor: &admin,
            subject: &admin,
            subject_email: &me,
            ..request
        };
        assert_eq!(
            authorize_access_change(Some(&floor), &self_removal),
            Err(AccessChangeRejection::SelfRevocation)
        );

        // 正向对照：换一个既不在 floor 上、也不是自己的人，同一次移除放行。
        let other_id = ActorId::new("actor-other");
        let other = email("other@x.com");
        let allowed = AccessChangeRequest {
            subject: &other_id,
            subject_email: &other,
            ..request
        };
        assert!(matches!(
            authorize_access_change(Some(&floor), &allowed),
            Ok(AccessChangeEffect::Revoke(_))
        ));
    }

    /// **新增**规则：移除最后一个有效管理员被拒。
    #[test]
    fn the_last_effective_admin_cannot_be_removed() {
        let peer = ActorId::new("actor-peer");
        let subject = ActorId::new("actor-last");
        let last = email("last@x.com");
        let request = AccessChangeRequest {
            actor: &peer,
            subject: &subject,
            subject_email: &last,
            subject_role: Role::Admin,
            subject_revoked: false,
            desired_revoked: true,
            other_effective_admins: 0,
            current_generation: AuthGeneration::new(1),
        };
        assert_eq!(
            authorize_access_change(None, &request),
            Err(AccessChangeRejection::LastAdmin)
        );

        // 正向对照 1：还剩一个别的管理员时放行。
        let with_spare = AccessChangeRequest {
            other_effective_admins: 1,
            ..request
        };
        assert!(matches!(
            authorize_access_change(None, &with_spare),
            Ok(AccessChangeEffect::Revoke(_))
        ));
        // 正向对照 2：被移除的人不是管理员时，零管理员的计数与他无关。
        let plain_user = AccessChangeRequest {
            subject_role: Role::User,
            ..request
        };
        assert!(matches!(
            authorize_access_change(None, &plain_user),
            Ok(AccessChangeEffect::Revoke(_))
        ));
    }

    /// 恢复不受这三条约束 —— 它们全部只针对「拿掉访问」。
    #[test]
    fn restoring_is_never_blocked_by_the_removal_guards() {
        let floor = floor_of(&["boss@x.com"]);
        let boss_id = ActorId::new("actor-boss");
        let boss = email("boss@x.com");
        let request = AccessChangeRequest {
            actor: &boss_id,
            subject: &boss_id,
            subject_email: &boss,
            subject_role: Role::Admin,
            subject_revoked: true,
            desired_revoked: false,
            other_effective_admins: 0,
            current_generation: AuthGeneration::new(1),
        };
        assert!(matches!(
            authorize_access_change(Some(&floor), &request),
            Ok(AccessChangeEffect::Restore(_))
        ));
    }

    #[test]
    fn codes_are_distinct_and_agree_with_display() {
        let all = [
            AccessChangeRejection::ConfiguredAdmin,
            AccessChangeRejection::SelfRevocation,
            AccessChangeRejection::LastAdmin,
        ];
        for rejection in all {
            assert_eq!(rejection.to_string(), rejection.code());
        }
        let mut codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());

        let refused = AccessRefused {
            path: SignInPath::NewAccount,
        };
        assert_eq!(refused.to_string(), refused.code());
        assert_ne!(
            SignInPath::NewAccount.as_str(),
            SignInPath::ReturningAccount.as_str()
        );
    }
}
