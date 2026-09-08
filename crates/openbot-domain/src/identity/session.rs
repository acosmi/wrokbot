//! session 寿命、token 的 keyed hash、fresh 判定与可信来源（v3 §6.3）。
//!
//! §6.3 里归本模块的四条：
//!
//! > - session token 数据库只保存 keyed hash，不保存可直接使用的明文 token；
//! > - 短 idle + 绝对期限；
//! > - 敏感 admin 写操作要求 fresh session，并校验 CSRF/origin；
//! > - refresh/reauth 不沿用旧 auth generation。
//!
//! # 第一条是**修正**，不是照译
//!
//! `parity/tables.yaml::tbl-sessions` 的 notes 逐字：`加密=无（token 明文列）`。也就是说
//! 上游 `sessions.token` 存的就是可以直接拿去用的那个串 —— 任何一次数据库读取（备份、
//! 只读副本、一条 `SELECT *` 的慢查询日志、一次 dump）都等于交出全部在线会话。v3 明确
//! 把它列为要**修正**的地方：列不变（`preserve`，§14.3 只允许 expand），存进去的东西变成
//! [`SessionTokenHash`]。
//!
//! 这条修正之所以能不动 schema 就落地，是因为 §6.3 最后一条：从 Better Auth 切到 Rust
//! Auth 时旧 session 全部失效、所有人重登一次。所以不存在「一半明文一半 hash」的混合期
//! 需要被兼容 —— 而正因为不存在，[`SessionTokenHash::from_column_value`] 才敢对任何不带
//! 前缀的列值 fail-closed（见该函数文档）。
//!
//! # 「为什么被登出」必须是三个答案，不是一个布尔
//!
//! idle 超时、绝对期限、代际作废是三件**成因完全不同**的事：第一件是这个人自己走开了，
//! 第二件是这条 session 到了它出生时就定好的寿命，第三件是**管理员刚刚做了什么**。
//! 压成一个 `is_valid: bool` 之后，「我的权限被撤了吗，还是我只是泡了杯咖啡」这个问题
//! 就永久没有答案了 —— 而这恰恰是撤权之后运维最需要确认的那一件事（「它真的生效了吗」）。
//! 所以 [`evaluate_session`] 返回 [`SessionRejection`]，三个变体三个 code。
//!
//! # fresh 从**认证时刻**起算，不是从活动时刻
//!
//! 这是本模块最容易写错的一处。如果 fresh 从 `last_seen_at` 起算，那么一个一直在点来点去
//! 的人**永远**是 fresh 的，重新认证这件事一次都不会发生 —— 敏感写的那道闸门就成了摆设，
//! 而且它看起来一直在工作。fresh 要回答的是「这个人**刚刚**证明过自己是他吗」，那只能从
//! [`SessionState::established_at`] 起算。测试 `activity_does_not_keep_a_session_fresh`
//! 就是这条的执行体。
//!
//! 同一条逻辑的另一面：[`LiveSession::touch`] 只推进 `last_seen_at`，**不动**
//! `established_at`。活动可以续 idle，不能续绝对期限，也不能续 fresh。

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use openbot_contracts::auth::Role;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use super::generation::{AuthGeneration, GenerationMismatch, check as check_generation};
use super::revocation::{AccessCleared, SignInPath};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// token 与 keyed hash
// ---------------------------------------------------------------------------

/// 明文 session token —— **唯一**能拿去认证的那个串。
///
/// 领域层不生成它（随机数不进领域层，见 crate 文档），只借用它算 hash。
/// `Debug` 打码：它是纯粹的 bearer 凭据，一次 `{:?}` 就等于把一个活会话写进日志（§17.2 条 8）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken<'a>(&'a [u8]);

impl<'a> SessionToken<'a> {
    /// 借一段 token 字节。
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SessionToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// 对 session token 做 keyed hash 用的密钥。
///
/// `Debug` 打码，理由同 [`super::signed_value::SigningSecret`]：派生 `Debug` 会让任何一个
/// 把入参写进错误上下文的库把密钥打进日志，而「记得别打印」是一条要求每个调用点都不出错
/// 的纪律。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionHashKey<'a>(&'a [u8]);

impl<'a> SessionHashKey<'a> {
    /// 借一段密钥材料。
    #[must_use]
    pub const fn new(material: &'a [u8]) -> Self {
        Self(material)
    }
}

impl fmt::Debug for SessionHashKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionHashKey(<redacted>)")
    }
}

/// 列值前缀。
///
/// # 它的作用是让一次回归**被看见**，不是版本协商
///
/// 按 §6.3 最后一条，切换到 Rust Auth 时旧 session 全部作废，所以这一列里不会有需要兼容
/// 的历史格式 —— 前缀不是用来分辨版本的。它挡的是另一件事：有人（或某次合并）让明文
/// token 又一次流回这一列。没有前缀时那种回归**完全没有征兆**，系统照常工作，只是安全
/// 属性没了；有前缀时 [`SessionTokenHash::from_column_value`] 当场拒绝，会话建不起来，
/// 五分钟内就有人发现。
const COLUMN_PREFIX: &str = "sh1_";

/// session token 的 keyed hash —— 数据库里真正存的东西。
///
/// # 为什么比较不能用 `derive(PartialEq)`
///
/// 派生出来的 `==` 是逐字节短路比较，耗时随「前多少字节相同」变化。攻击者可以据此逐字节
/// 试出一个有效 hash（配合一次写库能力就是一个可用会话）。所以 [`PartialEq`] 手写为
/// [`subtle::ConstantTimeEq`] —— 于是**连 `==` 本身都是常量时间的**，调用点不需要记得去
/// 用某个特殊函数，用错的那条路不存在。
#[derive(Clone, Copy, Eq)]
pub struct SessionTokenHash([u8; 32]);

impl PartialEq for SessionTokenHash {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for SessionTokenHash {
    /// 打码。
    ///
    /// hash 本身不是可以拿去认证的凭据（HMAC 不可逆），但它是一个活会话的精确关联键，
    /// 而且一个会打印它的 `Debug` 会诱导别人把整个 session 结构体（里面可能同时握着明文
    /// token）一起 dump。需要写出去时走 [`Self::to_column_value`]，那是一次显式的动作。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionTokenHash(<redacted>)")
    }
}

/// 列值不是一个合法的 keyed hash。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_session_token_hash_malformed")]
pub struct SessionTokenHashMalformed;

impl SessionTokenHashMalformed {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_session_token_hash_malformed"
    }
}

impl SessionTokenHash {
    /// `HMAC-SHA256(key, token)`。
    ///
    /// 用 keyed hash 而不是裸 SHA-256：裸摘要可以被离线彩虹表 / 暴力枚举反查（token 的熵
    /// 由签发方决定，而领域层管不着它有多少熵），keyed hash 让攻击者在拿不到密钥的情况下
    /// 连「这个 hash 对应哪个 token」都问不出来。密钥与数据库分开存放是这条的前提，
    /// 而那是部署的事。
    #[must_use]
    pub fn compute(token: SessionToken<'_>, key: SessionHashKey<'_>) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(key.0).expect("HMAC 接受任意长度密钥，构造不可能失败");
        mac.update(token.0);
        Self(mac.finalize().into_bytes().into())
    }

    /// 常量时间地判断一个明文 token 是否对应这个 hash。
    ///
    /// 这是**认证**那一步。写成一个方法而不是让调用方自己 `compute` 再比，是为了让
    /// 「比较必须是常量时间的」这件事没有第二种写法。
    #[must_use]
    pub fn matches(&self, token: SessionToken<'_>, key: SessionHashKey<'_>) -> bool {
        *self == Self::compute(token, key)
    }

    /// 写进 `sessions.token` 列的字符串。
    #[must_use]
    pub fn to_column_value(self) -> String {
        format!("{COLUMN_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }

    /// 从列值读回来。
    ///
    /// # Errors
    ///
    /// 缺前缀、base64 解不开、长度不是 32 字节时返回 [`SessionTokenHashMalformed`]。
    ///
    /// **fail-closed 是刻意的**：这一列里出现一个不带前缀的值只有一种成因 —— 有人把明文
    /// token 写回去了（见 [`COLUMN_PREFIX`]）。此时正确的行为是这条 session 用不了，
    /// 而不是「看起来能用」。
    pub fn from_column_value(value: &str) -> Result<Self, SessionTokenHashMalformed> {
        let Some(encoded) = value.strip_prefix(COLUMN_PREFIX) else {
            return Err(SessionTokenHashMalformed);
        };
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| SessionTokenHashMalformed)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| SessionTokenHashMalformed)?;
        Ok(Self(bytes))
    }
}

// ---------------------------------------------------------------------------
// 寿命策略
// ---------------------------------------------------------------------------

/// session 的三个时间窗口。
///
/// # 这里**没有**默认值，这是刻意的
///
/// v3 §6.3 只写了「短 idle + 绝对期限」，没有给数字；上游也给不出参照 —— 它对
/// `betterAuth({...})` 一个 `session` 选项都没传（本轮 grep：`auth/index.ts` 里唯一的
/// `session:` 是 `databaseHooks.session`），所以跑的是 Better Auth 的默认值。
/// 在领域层写死三个常量等于替产品做一次没有依据的裁决，而 repository contract §4 把「把新增写成
/// 当前行为」列为 v2 审计里最重的一类错误。所以三个窗口由配置层显式给出，本类型只负责
/// 保证它们之间的关系是自洽的。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLifetimePolicy {
    idle: Duration,
    absolute: Duration,
    fresh: Duration,
}

/// 三个窗口之间的关系不自洽。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SessionPolicyInvalid {
    /// 有窗口 ≤ 0。零长窗口意味着「刚建好的 session 立刻就过期」，没有任何部署想要它。
    #[error("identity_session_policy_non_positive")]
    NonPositive,
    /// `fresh` 不比 `idle` 短。
    ///
    /// 这条不是洁癖：`fresh >= idle` 时，任何一条还活着的 session 都必然是 fresh 的
    /// （能通过 idle 判定就必然通过 fresh 判定），于是「敏感 admin 写要求 fresh session」
    /// 这道闸门**恒为真** —— 它还在那儿，还在被调用，只是什么都不再挡。一个恒真的闸门
    /// 比没有闸门更糟，因为它会让人以为这件事已经做过了。
    #[error("identity_session_policy_fresh_not_shorter_than_idle")]
    FreshNotShorterThanIdle,
    /// `idle` 超过了 `absolute`。
    ///
    /// 此时绝对期限总是先到，idle 判定永远轮不到 —— 「短 idle」那一半配置是死的。
    #[error("identity_session_policy_idle_exceeds_absolute")]
    IdleExceedsAbsolute,
}

impl SessionPolicyInvalid {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NonPositive => "identity_session_policy_non_positive",
            Self::FreshNotShorterThanIdle => "identity_session_policy_fresh_not_shorter_than_idle",
            Self::IdleExceedsAbsolute => "identity_session_policy_idle_exceeds_absolute",
        }
    }
}

impl SessionLifetimePolicy {
    /// 构造并校验三个窗口的关系。
    ///
    /// # Errors
    ///
    /// 见 [`SessionPolicyInvalid`]，每个变体各自说明了它挡住的是哪一种「配置看起来生效了
    /// 其实没有」。
    pub fn new(
        idle: Duration,
        absolute: Duration,
        fresh: Duration,
    ) -> Result<Self, SessionPolicyInvalid> {
        if idle <= Duration::ZERO || absolute <= Duration::ZERO || fresh <= Duration::ZERO {
            return Err(SessionPolicyInvalid::NonPositive);
        }
        if fresh >= idle {
            return Err(SessionPolicyInvalid::FreshNotShorterThanIdle);
        }
        if idle > absolute {
            return Err(SessionPolicyInvalid::IdleExceedsAbsolute);
        }
        Ok(Self {
            idle,
            absolute,
            fresh,
        })
    }

    /// 无操作多久算 idle 超时。
    #[must_use]
    pub const fn idle(self) -> Duration {
        self.idle
    }

    /// 一条 session 从**认证时刻**起最多能活多久。
    #[must_use]
    pub const fn absolute(self) -> Duration {
        self.absolute
    }

    /// 认证之后多久之内算 fresh。
    #[must_use]
    pub const fn fresh(self) -> Duration {
        self.fresh
    }
}

// ---------------------------------------------------------------------------
// session 状态与判定
// ---------------------------------------------------------------------------

/// 一条 session 的寿命状态。
///
/// 只有三个字段，因为本模块只回答「它还算不算数」。「它是谁的」由 `sessions.user_id`
/// 那一列承载，不在这里重复一份 —— 同一个事实两个真源迟早会分叉。
///
/// # 构造入口
///
/// 只有两个：[`authenticate`]（铸造，要求一份 [`AccessCleared`]）与 [`Self::rehydrate`]
/// （从已有行读回）。**没有** `new`。这是模块间那条链路的收口点：想凭空造一条 session，
/// 得先拿到撤权闸门的证明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionState {
    established_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    generation: AuthGeneration,
}

impl SessionState {
    /// 从数据库里的一行读回。
    ///
    /// # 为什么它不需要 [`AccessCleared`]
    ///
    /// 因为它不铸造任何新东西：这一行是过去某一次 [`authenticate`] 的产物，那一次已经
    /// 过过闸门了。而「被移除的人还留着一行可以读回来的 session」这个漏洞由撤权计划的
    /// [`super::revocation::RevocationStep::TerminateSessions`] 关掉 —— 移除会把行删干净。
    ///
    /// 名字叫 `rehydrate` 而不是 `new` 是刻意的：`new` 邀请任何人调用，`rehydrate` 在
    /// review 里会引出「从哪一行读回来的」这个问题。
    #[must_use]
    pub const fn rehydrate(
        established_at: OffsetDateTime,
        last_seen_at: OffsetDateTime,
        generation: AuthGeneration,
    ) -> Self {
        Self {
            established_at,
            last_seen_at,
            generation,
        }
    }

    /// 这条 session 的**认证时刻**。绝对期限与 fresh 都从这里起算。
    #[must_use]
    pub const fn established_at(self) -> OffsetDateTime {
        self.established_at
    }

    /// 最后一次活动时刻。只有 idle 判定看它。
    #[must_use]
    pub const fn last_seen_at(self) -> OffsetDateTime {
        self.last_seen_at
    }

    /// 这条 session 出生时绑定的 auth generation。
    #[must_use]
    pub const fn generation(self) -> AuthGeneration {
        self.generation
    }
}

/// 一次刚刚铸造出来的 session，连同它是从哪条登录路径来的。
///
/// # 为什么把路径一起交出来
///
/// 上游两个 databaseHook 各自写一行 `session.signed_in`，两行**长得一模一样** ——
/// 于是「这是这个人第一次来，还是他早就有账号」这个问题，从审计上看不出来。它不是花边
/// 信息：一个本该早就存在的账号突然走了 `NewAccount` 那条路，意味着有人的 user 行被删过
/// （而删 user 行不是移除，见 [`super::revocation`] 的模块文档）。
///
/// 顺带它还让 [`authenticate`] 的 `cleared` 参数**真的被用上**：一个只为了类型约束而存在、
/// 值却被丢掉的参数，迟早会被某个人当成可以删的东西。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct MintedSession {
    state: SessionState,
    path: SignInPath,
}

impl MintedSession {
    /// 新 session 的寿命状态。
    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }

    /// 铸造它的那条登录路径，供审计行用。
    #[must_use]
    pub const fn path(self) -> SignInPath {
        self.path
    }
}

/// 铸造一条新 session。
///
/// 要求一份 [`AccessCleared`]：没有过撤权闸门就造不出 session（模块间那条链路的收口，
/// 见 `identity` 的模块文档）。
///
/// `generation` 必须是**此刻读到的当前代际**，不是任何旧 session 上的那个 —— 这就是
/// §6.3「refresh/reauth 不沿用旧 auth generation」。函数签名里根本没有「旧 session」这个
/// 参数，所以「顺手把旧值抄过来」这条路不存在。
pub fn authenticate(
    cleared: &AccessCleared,
    generation: AuthGeneration,
    now: OffsetDateTime,
) -> MintedSession {
    MintedSession {
        state: SessionState {
            established_at: now,
            last_seen_at: now,
            generation,
        },
        path: cleared.path(),
    }
}

/// session 不再有效的原因。三个成因，三个 code，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SessionRejection {
    /// 授权在这条 session 签发之后被改过（角色 / membership / 撤权）。
    ///
    /// 这是**管理员刚刚做了什么**的那一个答案，也是三者里唯一需要写进审计的 ——
    /// 「那次撤权真的生效了吗」只能靠它回答。
    #[error("identity_session_generation_superseded")]
    GenerationSuperseded,
    /// 这条 session 的代际比当前**大**：本副本落后，或这条状态是伪造的。一律拒绝。
    ///
    /// 与上一个分开的理由见 [`GenerationMismatch`]。
    #[error("identity_session_generation_from_the_future")]
    GenerationFromTheFuture,
    /// 超过绝对期限。从 [`SessionState::established_at`] 起算，活动**不能**续它。
    #[error("identity_session_absolute_expired")]
    AbsoluteExpired,
    /// 超过 idle 窗口。从 [`SessionState::last_seen_at`] 起算。
    #[error("identity_session_idle_expired")]
    IdleExpired,
    /// 三个时刻的先后关系不成立（要求 `established_at ≤ last_seen_at ≤ now`）。
    ///
    /// # 为什么这是拒绝而不是「按最宽松的解释算」
    ///
    /// 单调时钟下它不可能发生。真发生了，说明这三个时刻不是同一根时间轴上的读数
    /// （时钟回拨、多副本时钟不同步、行被手改过），此时任何关于「过期没过期」的算术
    /// 都不可信 —— 而不可信的答案里，「还没过期」是有害的那一个。所以 fail-closed。
    #[error("identity_session_timeline_incoherent")]
    TimelineIncoherent,
}

impl SessionRejection {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GenerationSuperseded => "identity_session_generation_superseded",
            Self::GenerationFromTheFuture => "identity_session_generation_from_the_future",
            Self::AbsoluteExpired => "identity_session_absolute_expired",
            Self::IdleExpired => "identity_session_idle_expired",
            Self::TimelineIncoherent => "identity_session_timeline_incoherent",
        }
    }
}

impl From<GenerationMismatch> for SessionRejection {
    fn from(mismatch: GenerationMismatch) -> Self {
        match mismatch {
            GenerationMismatch::Stale => Self::GenerationSuperseded,
            GenerationMismatch::FromTheFuture => Self::GenerationFromTheFuture,
        }
    }
}

/// 一条**此刻确实有效**的 session。
///
/// 只能由 [`evaluate_session`] 产出。它是敏感写授权与 idle 续期的入口 —— 于是
/// 「先判定再用」不是纪律，是唯一能编译的写法。
///
/// 里面记着判定发生的时刻 `evaluated_at`，[`Self::touch`] 用它推进 `last_seen_at`：
/// 续期用的时刻只能是刚刚判定用的那个，不能是调用方另外传进来的第二个「现在」。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct LiveSession {
    state: SessionState,
    evaluated_at: OffsetDateTime,
}

impl LiveSession {
    /// 底层状态。
    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }

    /// 这次判定发生的时刻。
    #[must_use]
    pub const fn evaluated_at(self) -> OffsetDateTime {
        self.evaluated_at
    }

    /// idle 续期：把 `last_seen_at` 推到判定时刻。
    ///
    /// **`established_at` 与 `generation` 原样不动。** 这是绝对期限之所以是「绝对」的
    /// 全部原因：如果活动能推进 `established_at`，一条一直有人用的 session 就永远不会到期，
    /// 而配置里那个绝对期限会变成一行没有作用的字。
    #[must_use]
    pub const fn touch(self) -> SessionState {
        SessionState {
            established_at: self.state.established_at,
            last_seen_at: self.evaluated_at,
            generation: self.state.generation,
        }
    }
}

/// 判定一条 session 在 `now` 这一刻是否有效。
///
/// # 检查顺序，以及它为什么可观察
///
/// 时间轴自洽 → 代际 → 绝对期限 → idle。
///
/// 顺序决定了「几条同时成立时给出哪个答案」。代际排在两个时间判据**之前**是刻意的：
/// 代际作废是一次**管理动作**留下的证据，而 idle / 绝对期限是时钟的自然结果。让时钟的
/// 答案盖住管理动作的答案，就等于把「那次撤权到底生效没有」这个问题的证据擦掉 ——
/// 一条既超时又被撤权的 session 报「idle 超时」，审计上看不出撤权发生过。
/// `generation_answer_wins_when_everything_is_wrong_at_once` 钉住这一点。
///
/// # Errors
///
/// 见 [`SessionRejection`]。
pub fn evaluate_session(
    policy: SessionLifetimePolicy,
    state: SessionState,
    current_generation: AuthGeneration,
    now: OffsetDateTime,
) -> Result<LiveSession, SessionRejection> {
    if state.established_at > state.last_seen_at || state.last_seen_at > now {
        return Err(SessionRejection::TimelineIncoherent);
    }
    check_generation(state.generation, current_generation)?;
    if now - state.established_at > policy.absolute {
        return Err(SessionRejection::AbsoluteExpired);
    }
    if now - state.last_seen_at > policy.idle {
        return Err(SessionRejection::IdleExpired);
    }
    Ok(LiveSession {
        state,
        evaluated_at: now,
    })
}

// ---------------------------------------------------------------------------
// 可信来源（CSRF / origin）
// ---------------------------------------------------------------------------

/// origin 字符串解析不出一个来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_origin_malformed")]
pub struct OriginMalformed;

impl OriginMalformed {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_origin_malformed"
    }
}

/// 把一个 origin 串归一成可以逐字节比较的形态。
///
/// # 归一化做什么，以及每一步为什么必须做
///
/// - **scheme 与 host 小写**：两者按 RFC 3986 就是大小写无关的，浏览器发出来的一律是小写，
///   而配置里往往是人手打的。不小写 = 一个大小写不一致的配置让**每一次**敏感写都被拒，
///   而且现场看起来像「fresh 判定坏了」。
/// - **剥掉默认端口**：`https://x` 与 `https://x:443` 按 RFC 6454 是同一个 origin，浏览器
///   在 `Origin` 头里从不带默认端口。不剥 = 一份写了 `:443` 的配置让整套 CSRF 校验恒拒。
/// - **剥掉尾部单个 `/`**：配置里常常粘的是一个 URL 而不是 origin（`parity/env.yaml` 记着
///   `OPENBOT_APP_URL` 那条回落链「尾部斜杠一律剥掉」）。
///
/// # 不做什么
///
/// **不做子域匹配**。`https://evil.example.com` 与 `https://example.com` 是两个 origin，
/// 而按后缀放行会让任何能在该域名下挂一个子域的人拿到 CSRF 豁免。测试
/// `subdomains_are_not_trusted_by_their_parent` 钉住这条。
fn canonical_origin(raw: &str) -> Result<String, OriginMalformed> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OriginMalformed);
    }
    // `null` 是浏览器对不透明来源（sandbox iframe、`data:` 文档、部分重定向）用的字面量。
    // 它不标识任何人，放行它等于放行一切说不清自己是谁的页面。
    if trimmed.eq_ignore_ascii_case("null") {
        return Err(OriginMalformed);
    }

    let Some((scheme_raw, rest_raw)) = trimmed.split_once("://") else {
        return Err(OriginMalformed);
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme.is_empty()
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
        || !scheme.starts_with(|c: char| c.is_ascii_lowercase())
    {
        return Err(OriginMalformed);
    }

    // 只剥一个尾部斜杠；`https://x//` 里剩下的那个是路径，下面会被拒。
    let rest = rest_raw.strip_suffix('/').unwrap_or(rest_raw);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(OriginMalformed);
    }

    // IPv6 字面量是 `[::1]` 或 `[::1]:3000`，它自带冒号，所以要先把方括号那段切出来。
    let (host_raw, port_raw) = if let Some(closing) = rest.strip_prefix('[') {
        let Some((inside, after)) = closing.split_once(']') else {
            return Err(OriginMalformed);
        };
        if inside.is_empty() {
            return Err(OriginMalformed);
        }
        let port = match after {
            "" => None,
            other => Some(other.strip_prefix(':').ok_or(OriginMalformed)?),
        };
        (format!("[{}]", inside.to_ascii_lowercase()), port)
    } else {
        match rest.split_once(':') {
            Some((host, port)) => (host.to_ascii_lowercase(), Some(port)),
            None => (rest.to_ascii_lowercase(), None),
        }
    };
    if host_raw.is_empty() || host_raw == "[]" {
        return Err(OriginMalformed);
    }

    let port = match port_raw {
        None => None,
        Some(text) => {
            let parsed: u16 = text.parse().map_err(|_| OriginMalformed)?;
            let default = match scheme.as_str() {
                "http" | "ws" => Some(80),
                "https" | "wss" => Some(443),
                _ => None,
            };
            if Some(parsed) == default {
                None
            } else {
                Some(parsed)
            }
        }
    };

    Ok(match port {
        Some(port) => format!("{scheme}://{host_raw}:{port}"),
        None => format!("{scheme}://{host_raw}"),
    })
}

/// 部署认可的来源集合（上游 `TRUSTED_ORIGINS`）。
///
/// # 空集合是允许的，而且它的语义是「拒绝一切敏感写」
///
/// 上游 `config.ts` 在 `TRUSTED_ORIGINS` 为空时回落到 `["http://localhost:3000"]`。那条
/// 回落是**配置层**的裁决（`parity/env.yaml` 有它的台账行），不在这里复制一份：把一个
/// 主机名写死进领域层等于替部署做决定，而且两处各写一份迟早分叉。这里只保证一件事 ——
/// 集合为空时 [`authorize_sensitive_write`] 拒绝一切，而不是放行一切。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedOrigins {
    origins: std::collections::BTreeSet<String>,
}

impl TrustedOrigins {
    /// 从配置项逐条构造，每条都过 [`canonical_origin`]。
    ///
    /// # Errors
    ///
    /// 任何一条解析不出来就整体失败，返回 [`OriginMalformed`]。
    ///
    /// **不静默丢弃坏条目**：丢掉一条写错的可信来源之后，症状是「某些人的敏感写莫名其妙
    /// 被拒」，而配置看起来是对的。启动就失败才能让人在五分钟内改对。
    pub fn from_configured<I, S>(entries: I) -> Result<Self, OriginMalformed>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut origins = std::collections::BTreeSet::new();
        for entry in entries {
            origins.insert(canonical_origin(entry.as_ref())?);
        }
        Ok(Self { origins })
    }

    /// 这个来源是否被认可。传进来的串会先归一化，所以两边永远用同一套规则比较。
    #[must_use]
    pub fn trusts(&self, origin: &str) -> bool {
        canonical_origin(origin).is_ok_and(|candidate| self.origins.contains(&candidate))
    }

    /// 认可的来源数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.origins.len()
    }

    /// 是否一条都没有（此时敏感写恒被拒）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 敏感 admin 写
// ---------------------------------------------------------------------------

/// 一次敏感 admin 写的授权请求。
#[derive(Clone, Copy, Debug)]
pub struct SensitiveWriteRequest<'a> {
    /// 已判定有效的 session。
    pub session: &'a LiveSession,
    /// 这次请求的有效角色（[`super::roles::resolve_effective_role`] 的结果）。
    pub role: Role,
    /// 请求携带的 `Origin` 头原文。`None` = 请求根本没带。
    ///
    /// **解析 header 是 transport 的事**，判定「什么算可信来源」在这里 —— 这条分界让
    /// 「哪些来源可信」只有一个真源，而不是每个 transport 各写一份。
    pub origin: Option<&'a str>,
}

/// 敏感写被拒绝的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SensitiveWriteRejection {
    /// 不是管理员。§15.3：角色不足 → 403。
    #[error("identity_sensitive_write_role_insufficient")]
    RoleInsufficient,
    /// 请求没带 `Origin`。
    ///
    /// 缺失即拒绝，不是「没带就当同源」。跨站发起的请求可以选择不带某些头，把「没带」
    /// 解释成「安全」正是 CSRF 想要的那个解释。
    #[error("identity_sensitive_write_origin_missing")]
    OriginMissing,
    /// `Origin` 不在可信集合里（或者根本解析不出一个来源）。
    #[error("identity_sensitive_write_origin_untrusted")]
    OriginUntrusted,
    /// session 还活着，但已经不 fresh 了 —— 需要重新认证。
    #[error("identity_sensitive_write_session_not_fresh")]
    SessionNotFresh,
}

impl SensitiveWriteRejection {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RoleInsufficient => "identity_sensitive_write_role_insufficient",
            Self::OriginMissing => "identity_sensitive_write_origin_missing",
            Self::OriginUntrusted => "identity_sensitive_write_origin_untrusted",
            Self::SessionNotFresh => "identity_sensitive_write_session_not_fresh",
        }
    }
}

/// 敏感 admin 写的**准许证**。
///
/// 只能由 [`authorize_sensitive_write`] 产出，没有 public 字段。要求敏感写的用例把它作为
/// 入参，「忘了检查」就编译不过 —— 与 [`AccessCleared`] 同一手法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct SensitiveWriteApproved {
    approved_at: OffsetDateTime,
}

/// Fresh same-origin approval for a credential write whose ownership/role rule is evaluated by the
/// application port rather than being administrator-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FreshOriginWriteApproved {
    approved_at: OffsetDateTime,
}

impl FreshOriginWriteApproved {
    /// Approval time for audit correlation.
    #[must_use]
    pub const fn approved_at(self) -> OffsetDateTime {
        self.approved_at
    }
}

/// Require a trusted Origin and a fresh live session, without deciding resource ownership or role.
///
/// This is for writes such as rotating a caller-owned remote Agent credential. The application/DB
/// transaction still decides whether the actor owns or administrates that exact Agent. Reusing the
/// admin-only function would incorrectly block legitimate owners; omitting freshness would make a
/// stolen long-lived session sufficient to mint a new machine credential.
pub fn authorize_fresh_origin_write(
    policy: SessionLifetimePolicy,
    trusted: &TrustedOrigins,
    session: &LiveSession,
    origin: Option<&str>,
) -> Result<FreshOriginWriteApproved, SensitiveWriteRejection> {
    let Some(origin) = origin else {
        return Err(SensitiveWriteRejection::OriginMissing);
    };
    if !trusted.trusts(origin) {
        return Err(SensitiveWriteRejection::OriginUntrusted);
    }
    if session.evaluated_at - session.state.established_at > policy.fresh {
        return Err(SensitiveWriteRejection::SessionNotFresh);
    }
    Ok(FreshOriginWriteApproved {
        approved_at: session.evaluated_at,
    })
}

impl SensitiveWriteApproved {
    /// 准许发生的时刻，供审计行用。
    #[must_use]
    pub const fn approved_at(self) -> OffsetDateTime {
        self.approved_at
    }
}

/// 判定一次敏感 admin 写是否被准许。
///
/// # 检查顺序
///
/// 角色 → origin → fresh。
///
/// 排 origin 在 fresh 之前的理由：origin 不对意味着这个请求**根本不是从我们的页面发出来
/// 的**，对它回答「请重新认证」是误导 —— 会让一个真正在被 CSRF 的用户以为自己该去登录。
/// 而合法管理员的浏览器总会带上可信 origin，所以他永远不会撞到那个答案。
///
/// # Errors
///
/// 见 [`SensitiveWriteRejection`]。
pub fn authorize_sensitive_write(
    policy: SessionLifetimePolicy,
    trusted: &TrustedOrigins,
    request: &SensitiveWriteRequest<'_>,
) -> Result<SensitiveWriteApproved, SensitiveWriteRejection> {
    if request.role != Role::Admin {
        return Err(SensitiveWriteRejection::RoleInsufficient);
    }
    let Some(origin) = request.origin else {
        return Err(SensitiveWriteRejection::OriginMissing);
    };
    if !trusted.trusts(origin) {
        return Err(SensitiveWriteRejection::OriginUntrusted);
    }
    let session = request.session;
    if session.evaluated_at - session.state.established_at > policy.fresh {
        return Err(SensitiveWriteRejection::SessionNotFresh);
    }
    Ok(SensitiveWriteApproved {
        approved_at: session.evaluated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::email::NormalizedEmail;
    use crate::identity::revocation::{DenyListAnswer, SignInPath, screen_sign_in};
    use time::macros::datetime;

    const KEY: &[u8] = b"session-hash-key-for-tests";

    fn policy() -> SessionLifetimePolicy {
        // 5 分钟 fresh < 30 分钟 idle ≤ 8 小时绝对期限。测试常量，不是产品裁决
        // （本模块刻意不提供默认值，理由见 SessionLifetimePolicy 的类型文档）。
        SessionLifetimePolicy::new(
            Duration::minutes(30),
            Duration::hours(8),
            Duration::minutes(5),
        )
        .expect("测试策略自洽")
    }

    fn cleared() -> AccessCleared {
        let email = NormalizedEmail::normalize("person@example.com").unwrap();
        screen_sign_in(DenyListAnswer::not_listed(email), SignInPath::NewAccount)
            .expect("普通地址通过闸门")
    }

    // -- keyed hash ---------------------------------------------------------

    #[test]
    fn the_same_token_and_key_always_give_the_same_hash() {
        let key = SessionHashKey::new(KEY);
        let token = SessionToken::new(b"opaque-random-token");
        let first = SessionTokenHash::compute(token, key);
        let second = SessionTokenHash::compute(token, key);
        assert_eq!(first, second);
        assert!(first.matches(token, key));
    }

    /// 换 token 或换密钥都对不上 —— 正向对照在上一条。
    #[test]
    fn a_different_token_or_key_never_matches() {
        let key = SessionHashKey::new(KEY);
        let stored = SessionTokenHash::compute(SessionToken::new(b"real-token"), key);
        assert!(!stored.matches(SessionToken::new(b"guessed-token"), key));
        assert!(!stored.matches(
            SessionToken::new(b"real-token"),
            SessionHashKey::new(b"a-different-key")
        ));
    }

    /// 列值往返，且**明文 token 不在列值里**。
    #[test]
    fn the_column_never_carries_the_token_itself() {
        let key = SessionHashKey::new(KEY);
        let token_text = "plaintext-bearer-token-value";
        let hash = SessionTokenHash::compute(SessionToken::new(token_text.as_bytes()), key);

        let column = hash.to_column_value();
        assert!(
            !column.contains(token_text),
            "列值里出现明文 token 就等于这条修正没做（tbl-sessions 的 notes：上游是明文列）"
        );
        assert!(column.starts_with(COLUMN_PREFIX));
        assert_eq!(SessionTokenHash::from_column_value(&column), Ok(hash));
    }

    /// 明文 token 被写回这一列时 fail-closed —— 前缀存在的全部理由。
    #[test]
    fn a_plaintext_token_in_the_column_is_refused() {
        for bad in [
            "plaintext-better-auth-session-token",
            "",
            "sh1_not-base64!!",
            // 前缀对但长度不对（16 字节而不是 32）。
            "sh1_AAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                SessionTokenHash::from_column_value(bad),
                Err(SessionTokenHashMalformed),
                "{bad:?} 必须被拒"
            );
        }
        // 正向对照：真正的列值读得回来，所以上面那批不是靠「什么都读不回来」通过的。
        let hash = SessionTokenHash::compute(SessionToken::new(b"t"), SessionHashKey::new(KEY));
        assert!(SessionTokenHash::from_column_value(&hash.to_column_value()).is_ok());
    }

    #[test]
    fn secrets_never_render_their_bytes() {
        assert_eq!(
            format!("{:?}", SessionToken::new(b"bearer")),
            "SessionToken(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", SessionHashKey::new(KEY)),
            "SessionHashKey(<redacted>)"
        );
        let hash = SessionTokenHash::compute(SessionToken::new(b"t"), SessionHashKey::new(KEY));
        assert_eq!(format!("{hash:?}"), "SessionTokenHash(<redacted>)");
    }

    // -- 寿命策略 -----------------------------------------------------------

    /// `fresh >= idle` 会让敏感写闸门恒真 —— 构造期就拒绝。
    #[test]
    fn a_fresh_window_that_is_not_shorter_than_idle_is_refused() {
        assert_eq!(
            SessionLifetimePolicy::new(
                Duration::minutes(30),
                Duration::hours(8),
                Duration::minutes(30)
            ),
            Err(SessionPolicyInvalid::FreshNotShorterThanIdle)
        );
        assert_eq!(
            SessionLifetimePolicy::new(
                Duration::minutes(30),
                Duration::hours(8),
                Duration::hours(1)
            ),
            Err(SessionPolicyInvalid::FreshNotShorterThanIdle)
        );
        // 正向对照：短一点就通过。
        assert!(
            SessionLifetimePolicy::new(
                Duration::minutes(30),
                Duration::hours(8),
                Duration::minutes(29)
            )
            .is_ok()
        );
    }

    #[test]
    fn idle_longer_than_absolute_is_refused_and_so_are_zero_windows() {
        assert_eq!(
            SessionLifetimePolicy::new(
                Duration::hours(9),
                Duration::hours(8),
                Duration::minutes(5)
            ),
            Err(SessionPolicyInvalid::IdleExceedsAbsolute)
        );
        assert_eq!(
            SessionLifetimePolicy::new(Duration::ZERO, Duration::hours(8), Duration::minutes(5)),
            Err(SessionPolicyInvalid::NonPositive)
        );
        assert_eq!(
            SessionLifetimePolicy::new(
                Duration::minutes(30),
                Duration::hours(8),
                Duration::seconds(-1)
            ),
            Err(SessionPolicyInvalid::NonPositive)
        );
    }

    // -- 判定 ---------------------------------------------------------------

    #[test]
    fn a_freshly_authenticated_session_is_valid() {
        let now = datetime!(2026-08-22 10:00:00 UTC);
        let generation = AuthGeneration::new(3);
        let state = authenticate(&cleared(), generation, now).state();
        assert_eq!(state.established_at(), now);
        assert_eq!(state.last_seen_at(), now);
        assert_eq!(state.generation(), generation);

        let live = evaluate_session(policy(), state, generation, now).expect("刚建好的必须有效");
        assert_eq!(live.state(), state);
        assert_eq!(live.evaluated_at(), now);
    }

    /// 铸造出来的 session 记着它是从哪条路来的 —— 上游两条路写的审计行分不开。
    #[test]
    fn a_minted_session_remembers_which_path_produced_it() {
        let now = datetime!(2026-08-22 10:00:00 UTC);
        let generation = AuthGeneration::new(1);
        for path in SignInPath::ALL {
            let email = NormalizedEmail::normalize("person@example.com").unwrap();
            let proof =
                screen_sign_in(DenyListAnswer::not_listed(email), path).expect("普通地址通过闸门");
            let minted = authenticate(&proof, generation, now);
            assert_eq!(minted.path(), path);
            assert_eq!(minted.state().established_at(), now);
        }
        // 负向对照：两条路径确实产出不同的取值，否则上面那条断言什么都没测。
        assert_ne!(SignInPath::NewAccount, SignInPath::ReturningAccount);
    }

    /// 三种失效各自给出自己的答案。
    #[test]
    fn the_three_ways_to_lose_a_session_are_told_apart() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        let generation = AuthGeneration::new(3);
        let state = authenticate(&cleared(), generation, established).state();

        // idle：最后活动之后超过 30 分钟，但绝对期限（8h）还没到。
        let idle_now = established + Duration::minutes(31);
        assert_eq!(
            evaluate_session(policy(), state, generation, idle_now),
            Err(SessionRejection::IdleExpired)
        );

        // 绝对期限：一直在活动（last_seen 贴着 now），但从认证起已经 9 小时。
        let long_running =
            SessionState::rehydrate(established, established + Duration::hours(9), generation);
        assert_eq!(
            evaluate_session(
                policy(),
                long_running,
                generation,
                established + Duration::hours(9)
            ),
            Err(SessionRejection::AbsoluteExpired)
        );

        // 代际：时间上完全健康，但管理员刚改了授权。
        assert_eq!(
            evaluate_session(
                policy(),
                state,
                generation.next(),
                established + Duration::minutes(1)
            ),
            Err(SessionRejection::GenerationSuperseded)
        );

        // 三个 code 两两不同 —— 否则「为什么被登出」还是只有一个答案。
        let mut codes = [
            SessionRejection::IdleExpired.code(),
            SessionRejection::AbsoluteExpired.code(),
            SessionRejection::GenerationSuperseded.code(),
        ];
        codes.sort_unstable();
        let mut deduped = codes.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), 3);
    }

    /// 全都不成立时，给出的必须是**代际**那个答案。
    #[test]
    fn generation_answer_wins_when_everything_is_wrong_at_once() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        let generation = AuthGeneration::new(3);
        let state = authenticate(&cleared(), generation, established).state();
        // 12 小时后：绝对期限过了、idle 也过了、代际也被撤了。
        let now = established + Duration::hours(12);
        assert_eq!(
            evaluate_session(policy(), state, generation.next(), now),
            Err(SessionRejection::GenerationSuperseded),
            "时钟的答案不能盖住管理动作的证据"
        );
    }

    #[test]
    fn a_generation_from_the_future_is_refused_on_its_own_code() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        let state = authenticate(&cleared(), AuthGeneration::new(9), established).state();
        assert_eq!(
            evaluate_session(
                policy(),
                state,
                AuthGeneration::new(8),
                established + Duration::minutes(1)
            ),
            Err(SessionRejection::GenerationFromTheFuture)
        );
    }

    #[test]
    fn an_incoherent_timeline_is_refused_rather_than_guessed_at() {
        let generation = AuthGeneration::new(1);
        let base = datetime!(2026-08-22 10:00:00 UTC);

        // last_seen 在 established 之前。
        let backwards = SessionState::rehydrate(base, base - Duration::minutes(1), generation);
        assert_eq!(
            evaluate_session(policy(), backwards, generation, base),
            Err(SessionRejection::TimelineIncoherent)
        );

        // last_seen 在 now 之后（时钟回拨）。
        let ahead = SessionState::rehydrate(base, base + Duration::minutes(5), generation);
        assert_eq!(
            evaluate_session(policy(), ahead, generation, base + Duration::minutes(1)),
            Err(SessionRejection::TimelineIncoherent)
        );

        // 正向对照：三个时刻顺序正确时不报这个错。
        let sane = SessionState::rehydrate(base, base + Duration::minutes(1), generation);
        assert!(evaluate_session(policy(), sane, generation, base + Duration::minutes(2)).is_ok());
    }

    /// 续期只推 `last_seen_at`：活动不能续绝对期限。
    #[test]
    fn touching_a_session_never_extends_its_absolute_lifetime() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        let generation = AuthGeneration::new(3);
        let mut state = authenticate(&cleared(), generation, established).state();

        // 每 20 分钟活动一次，连续活动到第 8 小时 —— idle 一直没到。
        let mut now = established;
        for _ in 0..24 {
            now += Duration::minutes(20);
            let live = evaluate_session(policy(), state, generation, now)
                .expect("持续活动期间 session 应当一直有效");
            state = live.touch();
            assert_eq!(
                state.established_at(),
                established,
                "续期绝不能推进认证时刻，否则绝对期限永远到不了"
            );
        }
        assert_eq!(now, established + Duration::hours(8));

        // 再过一分钟，绝对期限到 —— 尽管这个人一直在用。
        now += Duration::minutes(1);
        assert_eq!(
            evaluate_session(policy(), state, generation, now),
            Err(SessionRejection::AbsoluteExpired)
        );
    }

    /// 重新认证不沿用旧代际，也不沿用旧的认证时刻。
    #[test]
    fn reauthentication_takes_the_current_generation_and_restarts_the_clock() {
        let first_login = datetime!(2026-08-22 10:00:00 UTC);
        let old = authenticate(&cleared(), AuthGeneration::new(3), first_login).state();

        // 期间管理员改了这个人的角色两次。
        let current = AuthGeneration::new(5);
        assert_eq!(
            evaluate_session(policy(), old, current, first_login + Duration::minutes(1)),
            Err(SessionRejection::GenerationSuperseded)
        );

        // 重新登录：代际是**此刻**的，不是旧 session 上的。
        let second_login = first_login + Duration::hours(1);
        let fresh_state = authenticate(&cleared(), current, second_login).state();
        assert_eq!(fresh_state.generation(), current);
        assert_ne!(fresh_state.generation(), old.generation());
        assert_eq!(fresh_state.established_at(), second_login);
        assert!(evaluate_session(policy(), fresh_state, current, second_login).is_ok());
    }

    // -- origin -------------------------------------------------------------

    #[test]
    fn origin_canonicalization_folds_only_the_things_that_are_the_same_origin() {
        let trusted =
            TrustedOrigins::from_configured(["https://App.Example.COM/", "http://localhost:3000"])
                .unwrap();
        assert_eq!(trusted.len(), 2);
        assert!(!trusted.is_empty());

        // 大小写、尾部斜杠、默认端口三种写法都指向同一个 origin。
        for equivalent in [
            "https://app.example.com",
            "https://APP.EXAMPLE.COM",
            "https://app.example.com/",
            "https://app.example.com:443",
        ] {
            assert!(trusted.trusts(equivalent), "{equivalent} 应当被认可");
        }
        // 非默认端口是**另一个** origin。
        assert!(!trusted.trusts("https://app.example.com:8443"));
        // scheme 不同也是另一个 origin。
        assert!(!trusted.trusts("http://app.example.com"));
    }

    #[test]
    fn subdomains_are_not_trusted_by_their_parent() {
        let trusted = TrustedOrigins::from_configured(["https://example.com"]).unwrap();
        assert!(trusted.trusts("https://example.com"));
        for hostile in [
            "https://evil.example.com",
            "https://example.com.evil.test",
            "https://notexample.com",
        ] {
            assert!(!trusted.trusts(hostile), "{hostile} 绝不能被父域放行");
        }
    }

    #[test]
    fn ipv6_literals_round_trip_and_malformed_origins_are_refused_at_startup() {
        let trusted = TrustedOrigins::from_configured(["http://[::1]:3000"]).unwrap();
        assert!(trusted.trusts("http://[::1]:3000"));
        assert!(!trusted.trusts("http://[::1]"));

        for malformed in [
            "",
            "null",
            "NULL",
            "example.com",                    // 没有 scheme
            "https://example.com/admin",      // 带路径
            "https://example.com:not-a-port", // 端口不是数字
            "https://example.com:99999",      // 端口越界
            "https://",                       // 没有 host
            "://example.com",                 // 没有 scheme
            "https://user@example.com",       // 带 userinfo
        ] {
            assert_eq!(
                TrustedOrigins::from_configured([malformed]),
                Err(OriginMalformed),
                "{malformed:?} 必须在启动期就被拒"
            );
            assert!(!trusted.trusts(malformed));
        }
    }

    /// 空集合 = 拒绝一切，不是放行一切。
    #[test]
    fn an_empty_trusted_set_refuses_everything() {
        let empty = TrustedOrigins::from_configured(Vec::<String>::new()).unwrap();
        assert!(empty.is_empty());
        assert!(!empty.trusts("https://example.com"));
        assert_eq!(TrustedOrigins::default(), empty);
    }

    // -- 敏感写 -------------------------------------------------------------

    fn live_at(established: OffsetDateTime, now: OffsetDateTime) -> LiveSession {
        let generation = AuthGeneration::new(1);
        let state = SessionState::rehydrate(established, now, generation);
        evaluate_session(policy(), state, generation, now).expect("测试用 session 有效")
    }

    #[test]
    fn a_fresh_admin_from_a_trusted_origin_is_approved() {
        let now = datetime!(2026-08-22 10:00:00 UTC);
        let live = live_at(now - Duration::minutes(2), now);
        let trusted = TrustedOrigins::from_configured(["https://app.example.com"]).unwrap();
        let approved = authorize_sensitive_write(
            policy(),
            &trusted,
            &SensitiveWriteRequest {
                session: &live,
                role: Role::Admin,
                origin: Some("https://app.example.com"),
            },
        )
        .expect("fresh 的管理员从可信来源发起，必须放行");
        assert_eq!(approved.approved_at(), now);
    }

    /// 活动**不能**让 session 保持 fresh —— 本模块最容易写反的一条。
    #[test]
    fn activity_does_not_keep_a_session_fresh() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        // 认证已经是 20 分钟前，但一秒钟前还在活动（session 完全有效，且 idle 没到）。
        let now = established + Duration::minutes(20);
        let live = live_at(established, now);
        let trusted = TrustedOrigins::from_configured(["https://app.example.com"]).unwrap();
        let request = SensitiveWriteRequest {
            session: &live,
            role: Role::Admin,
            origin: Some("https://app.example.com"),
        };
        assert_eq!(
            authorize_sensitive_write(policy(), &trusted, &request),
            Err(SensitiveWriteRejection::SessionNotFresh),
            "fresh 从认证时刻起算；从活动时刻起算的话这道闸门永远不会拦下任何人"
        );

        // 正向对照：同一条 session 在认证后 2 分钟内是 fresh 的。
        let just_authenticated = live_at(established, established + Duration::minutes(2));
        assert!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    session: &just_authenticated,
                    role: Role::Admin,
                    origin: Some("https://app.example.com"),
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn a_missing_or_untrusted_origin_is_refused_on_its_own_code() {
        let now = datetime!(2026-08-22 10:00:00 UTC);
        let live = live_at(now, now);
        let trusted = TrustedOrigins::from_configured(["https://app.example.com"]).unwrap();
        let base = SensitiveWriteRequest {
            session: &live,
            role: Role::Admin,
            origin: Some("https://app.example.com"),
        };

        assert_eq!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    origin: None,
                    ..base
                }
            ),
            Err(SensitiveWriteRejection::OriginMissing)
        );
        assert_eq!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    origin: Some("https://evil.test"),
                    ..base
                }
            ),
            Err(SensitiveWriteRejection::OriginUntrusted)
        );
        assert_eq!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    role: Role::User,
                    ..base
                }
            ),
            Err(SensitiveWriteRejection::RoleInsufficient)
        );
    }

    /// 检查顺序可观察：全都不成立时给的是角色那个答案，其次是 origin。
    #[test]
    fn the_rejection_order_is_role_then_origin_then_freshness() {
        let established = datetime!(2026-08-22 10:00:00 UTC);
        let now = established + Duration::minutes(20); // 已经不 fresh
        let live = live_at(established, now);
        let trusted = TrustedOrigins::from_configured(["https://app.example.com"]).unwrap();

        // 角色不足 + origin 缺失 + 不 fresh → 角色。
        assert_eq!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    session: &live,
                    role: Role::User,
                    origin: None,
                }
            ),
            Err(SensitiveWriteRejection::RoleInsufficient)
        );
        // 角色够 + origin 不可信 + 不 fresh → origin，而不是「请重新认证」。
        assert_eq!(
            authorize_sensitive_write(
                policy(),
                &trusted,
                &SensitiveWriteRequest {
                    session: &live,
                    role: Role::Admin,
                    origin: Some("https://evil.test"),
                }
            ),
            Err(SensitiveWriteRejection::OriginUntrusted),
            "对一个根本不是从我们页面发来的请求说「请重新认证」是误导"
        );
    }

    #[test]
    fn codes_are_distinct_and_agree_with_display() {
        let session_codes = [
            SessionRejection::GenerationSuperseded,
            SessionRejection::GenerationFromTheFuture,
            SessionRejection::AbsoluteExpired,
            SessionRejection::IdleExpired,
            SessionRejection::TimelineIncoherent,
        ];
        for rejection in session_codes {
            assert_eq!(rejection.to_string(), rejection.code());
        }
        let write_codes = [
            SensitiveWriteRejection::RoleInsufficient,
            SensitiveWriteRejection::OriginMissing,
            SensitiveWriteRejection::OriginUntrusted,
            SensitiveWriteRejection::SessionNotFresh,
        ];
        for rejection in write_codes {
            assert_eq!(rejection.to_string(), rejection.code());
        }
        let policy_codes = [
            SessionPolicyInvalid::NonPositive,
            SessionPolicyInvalid::FreshNotShorterThanIdle,
            SessionPolicyInvalid::IdleExceedsAbsolute,
        ];
        for invalid in policy_codes {
            assert_eq!(invalid.to_string(), invalid.code());
        }

        let mut all: Vec<&str> = session_codes
            .iter()
            .map(|r| r.code())
            .chain(write_codes.iter().map(|r| r.code()))
            .chain(policy_codes.iter().map(|r| r.code()))
            .chain([OriginMalformed.code(), SessionTokenHashMalformed.code()])
            .collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "本模块每个 code 都必须是唯一的");
    }

    /// `GenerationMismatch` 到 `SessionRejection` 的映射不能塌缩。
    #[test]
    fn generation_mismatch_maps_to_two_distinct_session_codes() {
        assert_eq!(
            SessionRejection::from(GenerationMismatch::Stale),
            SessionRejection::GenerationSuperseded
        );
        assert_eq!(
            SessionRejection::from(GenerationMismatch::FromTheFuture),
            SessionRejection::GenerationFromTheFuture
        );
    }

    #[test]
    fn fresh_origin_write_separates_session_assurance_from_resource_role() {
        let now = datetime!(2026-08-24 12:00 UTC);
        let generation = AuthGeneration::new(1);
        let trusted = TrustedOrigins::from_configured(["https://app.example.test"]).unwrap();
        let fresh = evaluate_session(
            policy(),
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        assert!(
            authorize_fresh_origin_write(
                policy(),
                &trusted,
                &fresh,
                Some("https://app.example.test")
            )
            .is_ok()
        );
        assert_eq!(
            authorize_fresh_origin_write(policy(), &trusted, &fresh, None),
            Err(SensitiveWriteRejection::OriginMissing)
        );
        let stale = evaluate_session(
            policy(),
            SessionState::rehydrate(now - Duration::minutes(6), now, generation),
            generation,
            now,
        )
        .unwrap();
        assert_eq!(
            authorize_fresh_origin_write(
                policy(),
                &trusted,
                &stale,
                Some("https://app.example.test")
            ),
            Err(SensitiveWriteRejection::SessionNotFresh)
        );
    }
}
