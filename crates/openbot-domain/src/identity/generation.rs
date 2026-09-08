//! auth generation —— 「撤权立刻生效」这条不变量的载体（v3 §6.2 条 10 / §17.2 条 6）。
//!
//! §6.2 条 10 逐字：
//!
//! > role、membership 或 access generation 更新后，现有 WS subscription、screen ticket、
//! > approval、run assertion 和 capability **立即失效**。
//!
//! # 为什么需要一个计数器，而不是「撤权时把票据都删掉」
//!
//! 因为那些票据大多**不在我们手里**：WS subscription 活在一条已经建立的连接上，run
//! assertion 由客户自己的 Agent 进程带着穿过我们控制不了的地方再回来（上游
//! `auth/signed-value.ts` 的模块注释原文），capability 是一次性发出去的授权。挨个撤销
//! 要求我们枚举得到全部持有者 —— 而「枚举得到全部持有者」在分布式系统里恰恰是做不到的
//! 那一件事，漏掉一个就是一次静默的越权。
//!
//! 计数器把问题反过来：不去找持有者，而是让每一张票据**自带它出生时的代际**，判定推迟到
//! 使用的那一刻。撤权只需要写一个数字，代价 O(1) 且不可能「漏掉一个」。
//!
//! # 为什么是 `u64` 而不是字符串（§28.1 R23）
//!
//! 「旧 generation 全失效」依赖**数值序**。字符串的字典序会给出错误答案：`"10" < "9"`。
//! `openbot_contracts::ids` 里的 `ComputerGeneration` / `DocumentGeneration` 已经按同一条
//! 裁决（D7）落成 `u64` newtype。D-2 已将本类型收口到 contracts：`AuthContext`、
//! domain、server 和 infra 从此只有一个代际类型，不再在边界退化成裸 `u64`。
//!
//! # 判据是「恰好相等」，不是「大于等于」
//!
//! 见 [`GenerationMismatch`] 的类型文档：把「来自未来的代际」放行会让一次伪造永久有效，
//! 而把它与「陈旧」压成同一个答案会让运维分不清「副本落后」与「有人在造票据」。

pub use openbot_contracts::auth::AuthGeneration;

/// 一张短期声明与当前代际对不上。
///
/// # 为什么把「陈旧」与「来自未来」分成两个变体
///
/// 判据是**恰好相等**，两侧不等各自对应一种真实处境，而它们要求的运维动作是相反的：
///
/// - [`Self::Stale`]：持有者拿的代际比当前小。这是正常路径 —— 管理员刚改了角色 / 撤了组 /
///   移除了这个人，票据应当立刻作废。答案是「重新认证」。
/// - [`Self::FromTheFuture`]：持有者拿的代际比当前**大**。单调递增的计数器不可能产出这个
///   结果，所以它只有两种成因：这个副本读到的是落后的行（复制延迟），或者有人在伪造。
///   两者都不能放行 —— 放行意味着一个足够大的伪造代际**永远**有效；但也不能与陈旧混为一
///   谈，否则运维在日志里看到的是「大家都在被登出」，而真相是「有人在造票据」或者「你的
///   只读副本落后了」。
///
/// 把两者压成一个布尔就等于把这个分辨永久删掉。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum GenerationMismatch {
    /// 票据的代际小于当前代际：授权在票据签发之后被改过。
    #[error("identity_generation_stale")]
    Stale,
    /// 票据的代际大于当前代际：本副本落后，或票据是伪造的。一律拒绝。
    #[error("identity_generation_from_the_future")]
    FromTheFuture,
}

impl GenerationMismatch {
    /// 稳定的分类标识符，进审计与错误响应用（§15.3：stale generation → 409 + stable code）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Stale => "identity_generation_stale",
            Self::FromTheFuture => "identity_generation_from_the_future",
        }
    }
}

/// 一份**绑定了 auth generation** 的短期声明。
///
/// `T` 是声明本身（screen ticket、approval、run assertion、capability、WS subscription
/// 的订阅句柄……）。这个包装的作用是让「绑定」成为构造性事实：想拿到里面的 `T`，只有
/// [`Self::into_current`] 一条路，而它必须先过代际判定。
///
/// # 为什么不提供一个「直接取出」的方法
///
/// 提供了它就会被用。一个 `fn value(&self) -> &T` 的存在，等于把「记得先判代际」退回成
/// 纪律；而这正是本模块要消除的那一类失效 —— §17.2 条 6 是**发布级不变量**，任一违反
/// 即 P0。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct GenerationBound<T> {
    generation: AuthGeneration,
    value: T,
}

impl<T> GenerationBound<T> {
    /// 在**签发时刻**把声明与当时的代际绑在一起。
    ///
    /// 调用点必须是签发方 —— 绑一个不是自己此刻读到的代际，等于凭空延长票据寿命。
    pub const fn issue(generation: AuthGeneration, value: T) -> Self {
        Self { generation, value }
    }

    /// 这张声明出生时的代际。只读，用于审计投影；它**不能**替代 [`Self::into_current`]。
    #[must_use]
    pub const fn generation(&self) -> AuthGeneration {
        self.generation
    }

    /// 按当前代际判定，通过才交出里面的声明。
    ///
    /// # Errors
    ///
    /// 代际不等时返回 [`GenerationMismatch`]，两个方向各自一个变体，理由见该类型文档。
    pub fn into_current(self, current: AuthGeneration) -> Result<T, GenerationMismatch> {
        check(self.generation, current)?;
        Ok(self.value)
    }
}

/// 判定一个代际相对当前代际是否仍然有效。
///
/// 判据是**恰好相等**。
///
/// # Errors
///
/// 见 [`GenerationMismatch`]。
pub const fn check(
    bound: AuthGeneration,
    current: AuthGeneration,
) -> Result<(), GenerationMismatch> {
    if bound.get() == current.get() {
        Ok(())
    } else if bound.get() < current.get() {
        Err(GenerationMismatch::Stale)
    } else {
        Err(GenerationMismatch::FromTheFuture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContext, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    #[test]
    fn equal_generation_is_the_only_accepted_answer() {
        let current = AuthGeneration::new(7);
        assert_eq!(check(AuthGeneration::new(7), current), Ok(()));
        assert_eq!(
            check(AuthGeneration::new(6), current),
            Err(GenerationMismatch::Stale)
        );
        assert_eq!(
            check(AuthGeneration::new(8), current),
            Err(GenerationMismatch::FromTheFuture)
        );
    }

    /// §28.1 R23 的判据本身：比较必须是**数值**的。
    ///
    /// 这一对取值是那条裁决的可执行证据 —— 字典序会判 `"10" < "9"`，于是一张代际 9 的
    /// 陈旧票据在代际 10 的部署里会被判成「来自未来」而不是「陈旧」，更糟的是把
    /// `>=` 写成字符串比较时它会被直接放行。
    #[test]
    fn generations_compare_numerically_not_lexicographically() {
        let nine = AuthGeneration::new(9);
        let ten = AuthGeneration::new(10);
        assert!(nine < ten);
        assert_eq!(check(nine, ten), Err(GenerationMismatch::Stale));
        assert_eq!(check(ten, nine), Err(GenerationMismatch::FromTheFuture));

        // 正向对照：同一对值的字典序恰好相反 —— 证明上面那条断言不是恒真。
        assert!(
            nine.to_string() > ten.to_string(),
            "\"9\" > \"10\" 是字典序的答案；用字符串承载代际序就会得到它"
        );
    }

    /// 撤权后立刻失效：一张在代际 3 签发的 run assertion，在代际递增之后交不出内容。
    #[test]
    fn a_bound_claim_dies_the_moment_the_generation_advances() {
        let issued_at = AuthGeneration::new(3);
        let ticket = GenerationBound::issue(issued_at, "screen-ticket-payload");

        // 正向对照：代际没变时它是可用的 —— 否则下一条断言在「这东西永远取不出来」的
        // 世界里同样通过。
        assert_eq!(
            ticket.into_current(issued_at),
            Ok("screen-ticket-payload"),
            "同代际必须放行，否则这个包装等于把功能关掉"
        );

        let revoked = issued_at.next();
        let ticket = GenerationBound::issue(issued_at, "screen-ticket-payload");
        assert_eq!(
            ticket.into_current(revoked),
            Err(GenerationMismatch::Stale),
            "代际一递增，既有票据必须立刻失效（§6.2 条 10）"
        );
    }

    #[test]
    fn issued_generation_is_readable_for_audit_without_bypassing_the_check() {
        let ticket = GenerationBound::issue(AuthGeneration::new(41), 1_u8);
        assert_eq!(ticket.generation(), AuthGeneration::new(41));
        // 读了代际之后仍然只能经 into_current 拿到值。
        assert_eq!(
            ticket.into_current(AuthGeneration::new(42)),
            Err(GenerationMismatch::Stale)
        );
    }

    #[test]
    fn next_saturates_instead_of_wrapping_to_zero() {
        assert_eq!(AuthGeneration::new(0).next(), AuthGeneration::new(1));
        let top = AuthGeneration::new(u64::MAX);
        assert_eq!(top.next(), top, "到顶必须停住");

        // 到顶之后 fail-closed 仍然成立：任何更小的代际仍判陈旧。
        assert_eq!(
            check(AuthGeneration::new(u64::MAX - 1), top.next()),
            Err(GenerationMismatch::Stale)
        );
        // 负向对照：如果这里回绕成 0，下面这条会变成 Ok —— 一张零代际的远古票据复活。
        assert_ne!(top.next(), AuthGeneration::new(0));
    }

    #[test]
    fn generation_is_read_from_the_authoritative_context() {
        let context = AuthContext::for_test(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new("actor-1"),
            [Role::Admin],
            AuthGeneration::new(12),
            false,
        );
        assert_eq!(
            AuthGeneration::from_context(&context),
            AuthGeneration::new(12)
        );
    }

    #[test]
    fn codes_are_distinct_and_agree_with_display() {
        for mismatch in [GenerationMismatch::Stale, GenerationMismatch::FromTheFuture] {
            assert_eq!(mismatch.to_string(), mismatch.code());
        }
        assert_ne!(
            GenerationMismatch::Stale.code(),
            GenerationMismatch::FromTheFuture.code(),
            "两种失效模式压成同一个 code，运维就分不清『副本落后』与『有人在造票据』"
        );
    }
}
