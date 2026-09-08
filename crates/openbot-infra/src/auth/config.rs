//! 认证面的启动配置 —— 谁能登进来，以及用什么凭据（v3 §6.1 / §6.2 / §15.4）。
//!
//! # 这里的每一条拒绝，都是在拿"启动失败"换"更贵的失败"
//!
//! 上游 `server/src/config.ts::authConfig` 的 doc 逐字写着这条思路：**每一个不可能工作的
//! 组合都在启动期拒绝，而不是等某个人第一次点"登录"时才发现** —— 后者是发现配置错误
//! 最贵的时刻。本模块照搬这条判据，并且只在一个方向上收得更紧（`OPENBOT_ENV` 缺省即生产，
//! 见 [`ExampleKeyPolicy`]）。
//!
//! 清单：
//!
//! | 情形 | 为什么不能"先起来再说" |
//! | --- | --- |
//! | 某家 provider 只配了一半凭据 | 登录按钮在，点下去必失败 |
//! | 配了 provider 却没有 session secret | 没有东西能签 cookie |
//! | 配了 session secret 却一家 provider 都没有 | 那把密钥没有任何用处，多半是配漏了 |
//! | 配了 provider 却没写管理员 | **没有任何路由能事后提升管理员**，所有人都是普通用户，且永远没法补救 |
//! | Okta 有凭据没 issuer / 有 issuer 没凭据 | issuer 才让它成为"你们家的 Okta"而不是"Okta" |
//! | 一家 provider 都没有，也没说要单用户 | 每个访客都是管理员，而且看起来一切正常 |
//!
//! 最后两条是本模块存在的真正理由。上游 `auth/dev-actor.ts` 的注释记着那次事故：
//! 这道锁曾经是那个 Node 环境变量，而它默认未设 —— 于是"一台裸 VM，手写 env 文件，
//! 没有 provider"这个**唯一需要被拦住**的情形，恰恰是它放过的那个。
//!
//! # 不读进程环境
//!
//! 与 crate 根、与 [`super`] 模块文档一致：本模块所有解析函数接受一张 [`EnvMap`]，
//! 由启动层读一次进程环境后交进来。理由是硬性的 —— 读进程环境的解析器，它的测试就是
//! **对不受控的全机状态下断言**，换台机器或与别的用例并发就会翻。
//!
//! # 三档处置的**判定**不在这里
//!
//! `RETIRED_ENV_VARS` / `RENAMED_ENV_VARS` 那两张表与全环境扫描住在
//! `openbot_server::config::migration`，因为那是启动期唯一一次看得见整张环境表的地方。
//! 本模块只做一件相关的事：**绝不读旧名**。一份只写了旧 session secret 变量名的配置，
//! 在这里的表现必须与"根本没配"逐字节相同（由
//! `a_legacy_variable_name_supplies_nothing_here` 钉住），否则改名就白做了。
//!
//! # 已知的重复与偏差，交付时请一并看
//!
//! - [`Secret`] 与 `openbot_server::config::Secret` 同名但不再同形：本类型已以内层
//!   [`SecretBytes`] 获得 zeroize/no-Clone 边界；server 配置 secret 的统一属于它自己的消费者
//!   批次，不能靠复制本实现制造第二份秘密原语。
//! - `KEY_ENCRYPTION_KEY` 的台账 `target` 写的是 `openbot-infra::vault::KeyEncryptionKey`，
//!   而 `vault` 模块尚不存在。[`KeyEncryptionKey`] 暂落在本模块，**因此那条台账项没有被
//!   它自己的 `target` 字符串闭合** —— 要么 vault 落地时搬过去，要么台账改字段。
//! - 上游 `authConfig` 里"配了公共地址却没有 provider 也拒绝"这一条**没有照搬**，
//!   理由见 [`auth_config`] 的函数文档。
//! - session 的三个时间窗口是**新增裁决**，不是上游行为。见
//!   [`DEFAULT_SESSION_IDLE`] 一组常量的文档。
//!
//! # TrimString、规范化与集合类型一律复用 `openbot-domain`，本模块不再自造
//!
//! `INITIAL_ADMIN_EMAILS` 落成 [`AdminFloor`]（内含 [`NormalizedEmail`](openbot_domain::identity::email::NormalizedEmail)），
//! `TRUSTED_ORIGINS` 落成 [`TrustedOrigins`]。**不在这里再写一份规范化**，理由是
//! 领域侧那份多做了一件本模块想不到要做的事：它把 U+FEFF 也当首尾空白去掉。
//! JS 的 `trim()` 按 ECMA-262 的 `WhiteSpace` 产生式去空白，那个产生式**包含** U+FEFF；
//! Rust 的 `str::trim` 按 Unicode `White_Space` 属性去，而 U+FEFF 的类别是 `Cf`。
//! 于是一份带 BOM 保存的 `.env` 会让 `INITIAL_ADMIN_EMAILS` 的**第一项**以 U+FEFF 开头 ——
//! 那一条 floor 条目永远匹配不上任何人，**而且没有任何报错**。
//!
//! 这正是"同一判据两份实现"的标准结局：两份都自认为正确，差异只在一个看不见的码点上。
//! 本模块只负责逗号切分（那是配置层的事），trim 复用同一份 ECMAScript 封闭表，切完的
//! 条目交给领域类型。

use core::fmt;
use std::collections::BTreeMap;

use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::identity::session::{OriginMalformed, SessionLifetimePolicy, TrustedOrigins};
use openbot_domain::text::trim_ecmascript;
use openbot_domain::vault::{SecretBytes, WrappingKey};
use time::Duration;

/// 一次启动看见的全部环境变量。
///
/// 与 `openbot_server::config::EnvMap` 是**同一个类型**（两边都是
/// `BTreeMap<String, String>` 的别名，类型别名是透明的），所以启动层读一次、两边共用，
/// 中间不需要任何转换，也不存在"两份环境表可能不一致"的缝。
pub type EnvMap = BTreeMap<String, String>;

/// session secret 的最小长度（字符数）。
///
/// `32` 取自上游 `config.ts::authConfig` 的 `secret.length < 32` 与 `.env.example` 里那句
/// `At least 32 characters: openssl rand -base64 32`。
pub const SESSION_SECRET_MIN_LENGTH: usize = 32;

/// 未设 `TRUSTED_ORIGINS` 时的可信来源。
///
/// `http://localhost:3000` 取自上游 `config.ts::authConfig` 里那个三元表达式的 else 分支。
/// 注意 `.env.example` 写的是 `3010` —— 那是模板值，代码里的缺省才是缺省，
/// 两者本来就不同，不要"顺手对齐"。
pub const DEFAULT_TRUSTED_ORIGIN: &str = "http://localhost:3000";

/// 未设 `MICROSOFT_OAUTH_TENANT_ID` 时的目录。
///
/// `common` 取自上游 `config.ts::microsoftAuth` 的 `?? "common"`，也是 Microsoft 自己的缺省。
/// **它是一条安全面缺省**：`common` 放行**个人** Microsoft 账号，不只是公司账号。
/// 一家公司想要"只有我们员工"必须填目录 GUID。所以这个缺省要逐字保留 —— 悄悄改成
/// `organizations` 会让一批部署的准入范围在一次升级里静默变化。
pub const DEFAULT_MICROSOFT_TENANT_ID: &str = "common";

/// `.env.example` 里那把示例密钥。
///
/// 逐字取自上游 `config.ts::PLACEHOLDER_KEY`，与 `.env.example` 的 `KEY_ENCRYPTION_KEY=` 一行
/// 相同。**它本身是一把合法的密钥**，这正是问题所在：长度对、编码对，没有任何一条格式校验
/// 会拒绝它。一个从没改过它的部署，用一把印在公开仓库里的密钥加密自己的凭据库，
/// 而且**看起来和改过的部署一模一样**（由 `the_example_key_passes_every_format_check` 钉住）。
pub const EXAMPLE_KEY_ENCRYPTION_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// ---------------------------------------------------------------------------
// session 三个时间窗口 —— **新增裁决，不是 parity**
// ---------------------------------------------------------------------------

/// 无操作多久算 idle 超时：**8 小时**。
///
/// # 这是一次新增的产品裁决，不是上游行为
///
/// v3 §6.3 只写「短 idle + 绝对期限」和「敏感 admin 写操作要求 fresh session」，
/// **一个数字都没给**。上游也给不出参照：`server/src/auth/index.ts` 传给
/// `betterAuth({...})` 的选项里一个 `session` 配置都没有（那个文件里唯一的 `session:`
/// 在 `databaseHooks` 下面），跑的是 `better-auth 1.7.1` 的库默认值 —— 而本轮**没有
/// 测量那三个默认值的手段**（本机无 `node_modules`、不可联网）。
///
/// 所以这三个数字是产品决定，不是从上游读出来的事实。**没测出来的东西不能写成
/// "当前行为"**，本组常量因此标"新增"。改它们是一次产品决定，不是调参。
///
/// # 8 小时的理由
///
/// 覆盖一个完整工作日，人不必在午休后重登；同时把"人走了没锁屏的那台浏览器"
/// 限制在一个工作日之内。
///
/// # 为什么没有对应的环境变量
///
/// v3 §15.4 的处置表里没有这三个。加环境变量是一次 §15.4 修订 + `parity/env.yaml`
/// 变更，超出本轮范围。所以它们先是常量，并且由 [`auth_config`] 的入参**可被调用方覆盖**
/// —— 将来真要变成 env 变量时，读取点只需在启动层多一步，本模块不用动。
pub const DEFAULT_SESSION_IDLE: Duration = Duration::hours(8);

/// 一条 session 从认证时刻起最多能活多久：**7 天**。
///
/// 与活跃度无关的硬顶：一条 session 无论多活跃都活不过一周，于是"凭据泄漏之后的可用
/// 窗口"有一个上界，而不是由使用者的活跃度无限续下去。
///
/// 同 [`DEFAULT_SESSION_IDLE`]：新增裁决，不是上游行为，理由与"为什么没有环境变量"
/// 都在那条文档里。
pub const DEFAULT_SESSION_ABSOLUTE: Duration = Duration::days(7);

/// 认证之后多久之内算 fresh：**15 分钟**。
///
/// 敏感 admin 写（改角色、删用户、动 IdP）要求 fresh session。15 分钟够做完一批管理
/// 操作，又短到"走开的那个会话"不能被拿来做高权限写。
///
/// 它必须**严格短于** [`DEFAULT_SESSION_IDLE`]，否则任何一条还活着的 session 都必然是
/// fresh 的，这道闸门就恒为真 —— 一个恒真的闸门比没有闸门更糟。这条关系由
/// [`SessionLifetimePolicy::new`] 在构造期校验，本模块用
/// `default_session_lifetime_is_self_consistent` 钉住默认值确实过得了那一关。
///
/// 同 [`DEFAULT_SESSION_IDLE`]：新增裁决，不是上游行为。
pub const DEFAULT_SENSITIVE_WRITE_FRESHNESS: Duration = Duration::minutes(15);

/// 由上面三个常量构造 session 寿命策略。
///
/// # Panics
///
/// 三个常量的关系不自洽时 panic。它不可能在运行期发生：入参全是编译期常量，
/// 而 `default_session_lifetime_is_self_consistent` 在测试里走的就是这条路径 ——
/// 谁把某个常量改成不自洽的值，测试当场红，而不是等到某台机器启动时才炸。
#[must_use]
pub fn default_session_lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        DEFAULT_SESSION_IDLE,
        DEFAULT_SESSION_ABSOLUTE,
        DEFAULT_SENSITIVE_WRITE_FRESHNESS,
    )
    .expect("三个默认窗口的关系由 default_session_lifetime_is_self_consistent 钉住")
}

// ---------------------------------------------------------------------------
// 原语：与上游 `config.ts` 的两个 helper 逐条对齐
// ---------------------------------------------------------------------------

/// 读一个可选变量：两侧 `trim`，空串**等同未设**（上游 `config.ts::optional`）。
fn optional<'a>(env: &'a EnvMap, name: &str) -> Option<&'a str> {
    let value = trim_ecmascript(env.get(name)?);
    if value.is_empty() { None } else { Some(value) }
}

/// 逗号分隔的列表：切分 → 逐项 `trim` → 丢空项（上游 `config.ts::commaSeparated`）。
fn comma_separated(env: &EnvMap, name: &str) -> Vec<String> {
    optional(env, name)
        .unwrap_or_default()
        .split(',')
        .map(trim_ecmascript)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// 机密值
// ---------------------------------------------------------------------------

/// 一个不进日志的配置值。
///
/// 内层固定为 [`SecretBytes`]，所以 drop 擦除当前 allocation，且本类型不实现
/// Clone/Serialize/Display/PartialEq；`Debug` 恒印 `Secret(***)`。v3 §6.4 末段点名了一串
/// "永不进入普通日志、trace、metric、crash dump"的值，session secret 与 OAuth client secret
/// 都在其中；而 [`AuthConfig`] 是个会被人顺手 `{:?}` 出来的启动产物。用类型兑现这条禁令，
/// 于是"忘了"不再可能发生 —— 新增机密字段时也不必记得去改 `Debug` 实现。
///
/// ```compile_fail
/// use openbot_infra::auth::config::Secret;
/// let secret = Secret::new("one owned secret");
/// let copied = secret.clone();
/// # drop(copied);
/// ```
pub struct Secret(SecretBytes);

impl Secret {
    /// 由已经 `trim` 过的非空值构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretBytes::new(value.into().into_bytes()))
    }

    /// 取出真值。**调用点即泄漏面**，只在真正要把它交给对端时使用。
    #[must_use]
    pub fn expose(&self) -> &str {
        core::str::from_utf8(self.0.expose())
            .expect("Secret 只从有效 Rust String 接管字节，UTF-8 不变量不会失效")
    }

    /// 字符数。存在的唯一理由是长度校验不必先 [`Secret::expose`]。
    ///
    /// 数的是**字符**不是字节，与上游 JavaScript 的 `secret.length` 同口径。对一把
    /// `openssl rand -base64 32` 生成的 ASCII 密钥两者相同；真有人用非 ASCII 当密钥时，
    /// 字符数比字节数更接近"他数了几个字符"。
    #[must_use]
    pub fn character_count(&self) -> usize {
        self.expose().chars().count()
    }

    /// 是否为空。构造路径已排除空值，这里只是让 [`Secret::character_count`] 不孤零零地存在。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 连长度都不印：它会泄漏"这是不是那把 44 字符的示例 key"，
        // 而对排障毫无帮助 —— 想知道有没有配上，看的是字段在不在。
        formatter.write_str("Secret(***)")
    }
}

/// 示例 `KEY_ENCRYPTION_KEY` 放不放行。
///
/// # 它从哪里来
///
/// 由 `OPENBOT_ENV` 决定，而那个变量**只在 `openbot_server::config` 里解析一次**。
/// 两个 crate 是兄弟，不能共用一个类型，所以接线层写一次穷举 `match` 把它映射过来：
///
/// ```ignore
/// let policy = match server_config.deployment_environment {
///     DeploymentEnvironment::Production => ExampleKeyPolicy::Reject,
///     DeploymentEnvironment::Development => ExampleKeyPolicy::Allow,
/// };
/// ```
///
/// 穷举是重点：任何一侧新增变体，接线层当场编译失败，而不是悄悄落进某个 `_ =>`。
/// 这与 `openbot_server::readiness` 里 `DataMigrationVerdict -> ReadinessVerdict` 是同一个
/// 手法，也是同一个理由。
///
/// # 为什么缺省是 [`ExampleKeyPolicy::Reject`]
///
/// 因为 `OPENBOT_ENV` 缺省即生产。上游那个 Node 侧变量的默认方向恰好相反 —— 未设即非生产
/// —— 于是它唯一需要拦住的那台裸机，正是它放过的那台。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExampleKeyPolicy {
    /// 拒绝示例密钥。**生产语义，也是 `OPENBOT_ENV` 未设时的档位。**
    Reject,
    /// 放行示例密钥。只有显式 `OPENBOT_ENV=development` 才到这一档。
    Allow,
}

/// 这把 KEK 的强度档位。
///
/// 位数**不是秘密**（它由配置而不是密文决定），而排障时它恰好是最有用的那一半：
/// "这台机器加载的是一把 128 位的 KEK"是运维能据以行动的信息。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyEncryptionKeyStrength {
    /// 16 字节 / AES-128。
    Aes128,
    /// 24 字节 / AES-192。
    Aes192,
    /// 32 字节 / AES-256。
    Aes256,
}

impl KeyEncryptionKeyStrength {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128 => "aes_128",
            Self::Aes192 => "aes_192",
            Self::Aes256 => "aes_256",
        }
    }

    /// 由密钥位数判定。位数只可能是 128 / 192 / 256 —— [`WrappingKey`] 已经把别的挡掉了。
    const fn from_bits(bits: usize) -> Option<Self> {
        match bits {
            128 => Some(Self::Aes128),
            192 => Some(Self::Aes192),
            256 => Some(Self::Aes256),
            _ => None,
        }
    }

    /// 启动期要不要提醒运维，以及提醒的**稳定 code**。
    ///
    /// 返回 code 而不是一句话：v3 §15.3 要求稳定 code 不随文案变化，GUI 与 CLI 会各自把它
    /// 渲染成人话。一句英文散文在这两处都没法本地化，还会因为有人改措辞而让 grep 失效。
    #[must_use]
    pub const fn advisory_code(self) -> Option<&'static str> {
        match self {
            Self::Aes128 | Self::Aes192 => Some(KEY_ENCRYPTION_KEY_BELOW_AES_256),
            Self::Aes256 => None,
        }
    }
}

/// "这把 KEK 弱于 AES-256"的稳定 code。
///
/// 它是**告警不是拒绝**：这样的部署在上游能正常读写自己的凭据库，拒绝它等于把那些数据
/// 锁死（见 [`KeyEncryptionKey::from_env_map`] 的〈三档长度〉一节）。轮换路径是 §6.4 的
/// v1 → v2 迁移，新 KEK 用 32 字节。
pub const KEY_ENCRYPTION_KEY_BELOW_AES_256: &str = "key_encryption_key_below_aes_256";

/// 凭据库的主加密密钥（`KEY_ENCRYPTION_KEY`）。
///
/// 密钥材料由领域侧的 [`WrappingKey`] 持有 —— 它的 `Debug` 只印位数不印材料，
/// 而且材料是 `pub(super)` 的，本 crate 根本拿不到，只能整个交给 vault 的 AEAD 去用。
pub struct KeyEncryptionKey {
    key: WrappingKey,
    strength: KeyEncryptionKeyStrength,
}

impl KeyEncryptionKey {
    /// 从环境映射解析 `KEY_ENCRYPTION_KEY`。
    ///
    /// # 校验顺序与上游 `config.ts::keyEncryptionKey` 一致
    ///
    /// 1. 必填，缺失即拒绝启动；
    /// 2. 必须是 **canonical** base64 —— 上游用 `decoded.toString("base64") !== value` 表达
    ///    这一条，效果是"解开再编回去必须逐字符相同"。这里用严格解码器直接兑现同一个接受集：
    ///    长度是 4 的倍数、字母表内、padding 位数与末尾剩余位匹配、且剩余位全 0。
    ///    Node 的 `Buffer.from(…, "base64")` 会**忽略**非字母表字符，正是那条回编比对
    ///    把它救回来的；直接写严格解码器少一次往返，接受集不变。
    /// 3. 解出的长度必须是 AES 认识的三档之一（见下）；
    /// 4. 示例密钥在 [`ExampleKeyPolicy::Reject`] 下拒绝。
    ///
    /// # 三档长度 —— 这是对 v3 §15.4 的一次**修订**
    ///
    /// §15.4 那句"base64 **32 字节**"没有上游依据，而且照做会**锁死别人的数据**。
    ///
    /// 实测（本轮由两路独立完成，结论一致）：上游
    /// `server/src/credentials.ts::aesKey` 走的是
    /// `crypto.subtle.importKey("raw", Buffer.from(encodedKey, "base64"), {name:"AES-GCM"}, …)`，
    /// 而 WebCrypto 的 AES-GCM 接受 128 / 192 / 256 三种密钥长度：
    ///
    /// ```text
    /// 16 字节 => OK        20 字节 => DataError: Invalid key length
    /// 24 字节 => OK        31 字节 => DataError: Invalid key length
    /// 32 字节 => OK
    /// ```
    ///
    /// 那两条 `DataError` 是**正向对照**：它证明这个探测确实说得出"不"，
    /// 而不是什么都放行。
    ///
    /// 也就是说，现网完全可能存在一个用 16 或 24 字节 KEK 跑了很久的部署，它的
    /// `credentials.encrypted_value` 在上游是**读得出来的**。Rust 侧若在启动期硬要求
    /// 恰好 32 字节，那个部署起不来，于是**永远迁不了自己的数据** —— 这不是"更安全"，
    /// 这是把别人的数据锁死。
    ///
    /// 所以判据直接复用 [`WrappingKey::from_bytes`]（`ACCEPTED_BYTES = [16, 24, 32]`），
    /// **不在本模块再写一份长度表**：同一条判据两份实现，迟早在某次改动里分叉，
    /// 而分叉的那一刻正是"配置层放行了一把 vault 解不开的密钥"。
    ///
    /// 其余长度（0 / 20 / 31 / 33 …）一律拒绝启动，**绝不**截断、补零或取最近的一档。
    ///
    /// 16 / 24 字节**允许启动但带一条告警**，见 [`KeyEncryptionKey::advisory_code`]。
    ///
    /// # Errors
    ///
    /// 上述任一条不满足时返回 [`AuthConfigError`]。
    pub fn from_env_map(env: &EnvMap, policy: ExampleKeyPolicy) -> Result<Self, AuthConfigError> {
        let Some(raw) = optional(env, "KEY_ENCRYPTION_KEY") else {
            return Err(AuthConfigError::single(
                AuthConfigProblem::KeyEncryptionKeyMissing,
            ));
        };

        let Some(decoded) = decode_canonical_base64(raw) else {
            return Err(AuthConfigError::single(
                AuthConfigProblem::KeyEncryptionKeyMalformed,
            ));
        };

        let key = WrappingKey::from_bytes(decoded)
            .map_err(|_| AuthConfigError::single(AuthConfigProblem::KeyEncryptionKeyLength))?;

        if raw == EXAMPLE_KEY_ENCRYPTION_KEY && policy == ExampleKeyPolicy::Reject {
            return Err(AuthConfigError::single(
                AuthConfigProblem::KeyEncryptionKeyIsExample,
            ));
        }

        let strength = KeyEncryptionKeyStrength::from_bits(key.bits())
            .expect("WrappingKey 只接受 16 / 24 / 32 字节，位数必然是这三档之一");

        Ok(Self { key, strength })
    }

    /// 借出包装密钥，交给 `openbot_domain::vault` 的 AEAD。
    #[must_use]
    pub const fn wrapping_key(&self) -> &WrappingKey {
        &self.key
    }

    /// 交出包装密钥的所有权。
    #[must_use]
    pub fn into_wrapping_key(self) -> WrappingKey {
        self.key
    }

    /// 强度档位。
    #[must_use]
    pub const fn strength(&self) -> KeyEncryptionKeyStrength {
        self.strength
    }

    /// 启动期告警的稳定 code，`None` 表示没什么要说的。
    ///
    /// 弱于 AES-256 时是 [`KEY_ENCRYPTION_KEY_BELOW_AES_256`]。**这条告警不阻止启动** ——
    /// 拒绝它等于把一个在上游正常运行的部署的数据锁死。
    #[must_use]
    pub const fn advisory_code(&self) -> Option<&'static str> {
        self.strength.advisory_code()
    }
}

impl fmt::Debug for KeyEncryptionKey {
    /// 只印强度，不印材料。强度不是秘密（理由见 [`KeyEncryptionKeyStrength`]），
    /// 而它恰好是排障时最有用的那一半。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "KeyEncryptionKey({}, [redacted])",
            self.strength.as_str()
        )
    }
}

/// base64 字母表反查。标准字母表（`+` `/`），**不是** URL-safe 变体。
fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// 严格 canonical base64 解码。判据见 [`KeyEncryptionKey::from_env_map`] 第 3 条。
fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut padding = 0usize;
    if bytes[bytes.len() - 1] == b'=' {
        padding += 1;
        // 长度是 4 的倍数且非空 ⇒ 至少 4 个字节，下标安全。
        if bytes[bytes.len() - 2] == b'=' {
            padding += 1;
        }
    }
    // 三个及以上的 `=` 不需要单独判：多出来的那个会落进数据段，
    // 而 `base64_value(b'=')` 是 None。

    let data_len = bytes.len() - padding;
    let mut out = Vec::with_capacity(data_len * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in &bytes[..data_len] {
        accumulator = (accumulator << 6) | u32::from(base64_value(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }

    // canonical 的两半：剩余位数要与 padding 对得上，且那几位必须全 0。
    // 少了后半条，`…AAB=` 这种"解得开但编不回去"的串会被放行 —— 而上游那条
    // 回编比对恰恰拒绝它。
    let expected_leftover = match padding {
        0 => 0,
        1 => 2,
        _ => 4,
    };
    if bits != expected_leftover {
        return None;
    }
    if bits > 0 && (accumulator & ((1_u32 << bits) - 1)) != 0 {
        return None;
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// provider
// ---------------------------------------------------------------------------

/// 能把人签进来的身份提供方。
///
/// 三家**可以同时配置** —— 一家公司在迁移中期就是有的人在 Entra、有的人还在 Okta
/// （上游 `AuthConfig` 的 doc 原话）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthProviderId {
    /// Google。
    Google,
    /// Microsoft Entra ID。
    Microsoft,
    /// Okta（OIDC）。
    Okta,
}

impl AuthProviderId {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Okta => "okta",
        }
    }

    /// 这家 provider 的环境变量前缀。
    ///
    /// 上游用模板字面量 `${provider}_OAUTH_CLIENT_ID` 拼名字，所以按全名去
    /// `config.ts` 里直接 grep 是搜不到 `GOOGLE_OAUTH_CLIENT_ID` 的
    /// （`parity/env.yaml` 的 `google-oauth-client-id` 条目专门记了这一点）。
    /// 这里保留同一个形状。
    const fn env_prefix(self) -> &'static str {
        match self {
            Self::Google => "GOOGLE",
            Self::Microsoft => "MICROSOFT",
            Self::Okta => "OKTA",
        }
    }
}

/// 一副 OAuth 客户端凭据。
#[derive(Debug)]
pub struct OAuthClient {
    /// client id。**不是机密**（它会出现在浏览器地址栏里）。
    pub client_id: String,
    /// client secret。
    pub client_secret: Secret,
}

/// Microsoft Entra ID，以及它放行哪个目录。
#[derive(Debug)]
pub struct MicrosoftAuth {
    /// 客户端凭据。
    pub client: OAuthClient,
    /// 放行的目录。缺省 [`DEFAULT_MICROSOFT_TENANT_ID`]，**那会放行个人账号**。
    pub tenant_id: String,
}

/// Okta。它是 OIDC provider 而不是具名 provider，所以由 issuer 标识。
#[derive(Debug)]
pub struct OktaAuth {
    /// 客户端凭据。
    pub client: OAuthClient,
    /// issuer，例如 `https://example.okta.com/oauth2/default`。
    ///
    /// 它才让这家成为"你们家的 Okta"而不是"Okta"，所以与凭据同设同缺，不设缺省。
    pub issuer: String,
}

/// 这个部署的认证配置。[`auth_config`] 返回 `None` 表示没有任何 IdP。
#[derive(Debug)]
pub struct AuthConfig {
    /// 本部署对外的公共地址，OAuth 回调回到这里。
    ///
    /// 由启动层从 `openbot_server::config::ServerConfig::public_url` 传入，**本模块不自己读**
    /// —— 同一个变量两个解析器就是两个答案。上游它是一个 auth 专用变量，
    /// v3 §15.4 把它并进了唯一的公共地址来源。
    pub public_url: String,
    /// 签 session cookie 的密钥（`OPENBOT_SESSION_SECRET`）。
    pub session_secret: Secret,
    /// API 接受的 App 来源。未设时只含 [`DEFAULT_TRUSTED_ORIGIN`]。
    ///
    /// 类型是领域侧的 [`TrustedOrigins`]，它在构造时把每条归一化成 canonical origin，
    /// 于是"配置里写 `https://app.test:443/`、请求头来的是 `https://app.test`"
    /// 这种同一来源两种写法的比对失败，在类型层面就不存在了。
    pub trusted_origins: TrustedOrigins,
    /// session 的三个时间窗口。**新增裁决**，见 [`DEFAULT_SESSION_IDLE`]。
    ///
    /// 由 [`auth_config`] 的入参给出，不从环境读 —— §15.4 的处置表里没有它们。
    pub session_lifetime: SessionLifetimePolicy,
    /// 配置指定的管理员下限。
    ///
    /// **恒非空**：[`AdminFloor`] 的构造入口在集合为空时失败，而 [`auth_config`]
    /// 把那次失败翻译成拒绝启动。
    ///
    /// 用领域类型而不是一串 `String`：比较发生在两个
    /// [`NormalizedEmail`](openbot_domain::identity::email::NormalizedEmail) 之间，
    /// "一边规范化了另一边没有"这种形态在类型上不存在。
    pub admin_floor: AdminFloor,
    /// Google。
    pub google: Option<OAuthClient>,
    /// Microsoft Entra ID。
    pub microsoft: Option<MicrosoftAuth>,
    /// Okta。
    pub okta: Option<OktaAuth>,
}

impl AuthConfig {
    /// 这个部署实际能签人进来的 provider，**顺序固定**。
    ///
    /// 顺序是登录页上按钮的顺序，钉在代码里而不是随配置书写顺序或哈希序变化 ——
    /// 否则登录页会因为"某人改了 `.env` 里两行的先后"而换个样子（上游
    /// `configuredAuthProviders` 的 doc 原话）。
    #[must_use]
    pub fn configured_providers(&self) -> Vec<AuthProviderId> {
        let mut providers = Vec::with_capacity(3);
        if self.google.is_some() {
            providers.push(AuthProviderId::Google);
        }
        if self.microsoft.is_some() {
            providers.push(AuthProviderId::Microsoft);
        }
        if self.okta.is_some() {
            providers.push(AuthProviderId::Okta);
        }
        providers
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 认证配置里的**一个**毛病。
///
/// 每个字段都是 `&'static str` —— 与 `openbot_application::ports::PortError` 同一条决定：
/// 错误会进日志，而这些变量的值里有 session secret、client secret、主加密密钥。
/// **类型上就装不进一个运行期字符串**，而不是靠每个构造点记得别塞。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthConfigProblem {
    /// 某家 provider 只配了 id 或只配了 secret。
    #[error("oauth_client_half_configured provider={provider}")]
    OAuthClientHalfConfigured {
        /// provider 的环境变量前缀（`GOOGLE` / `MICROSOFT` / `OKTA`）。
        provider: &'static str,
    },
    /// 配了 Okta issuer，却没有 Okta 凭据。
    #[error("okta_issuer_without_client")]
    OktaIssuerWithoutClient,
    /// 配了 Okta 凭据，却没有 issuer。
    #[error("okta_client_without_issuer")]
    OktaClientWithoutIssuer,
    /// Okta issuer 不是一个合法 URL。
    #[error("okta_issuer_malformed")]
    OktaIssuerMalformed,
    /// 有 provider，却没有 session secret。
    #[error("session_secret_missing")]
    SessionSecretMissing,
    /// session secret 短于 [`SESSION_SECRET_MIN_LENGTH`]。
    #[error("session_secret_too_short")]
    SessionSecretTooShort,
    /// 配了 session secret，却一家 provider 都没有。
    #[error("session_secret_without_provider")]
    SessionSecretWithoutProvider,
    /// 有 provider，却没有公共地址供 OAuth 回调落地。
    #[error("public_url_missing")]
    PublicUrlMissing,
    /// 有 provider，却没有指定任何管理员。
    #[error("initial_admin_emails_missing")]
    InitialAdminEmailsMissing,
    /// `TRUSTED_ORIGINS` 里有一条不是可解析的 origin。
    ///
    /// **整体失败，不静默丢弃那一条**（领域侧 [`TrustedOrigins::from_configured`] 的裁决）：
    /// 丢掉一条写错的可信来源之后，症状是"某些人的敏感写莫名其妙被拒"，而配置看起来是对的。
    #[error("trusted_origin_malformed")]
    TrustedOriginMalformed,
    /// session 三个时间窗口的关系不自洽。
    ///
    /// 只有调用方自己传了一份策略时才可能出现 —— [`default_session_lifetime`] 那一份
    /// 由测试钉住是自洽的。
    #[error("session_lifetime_invalid reason={reason}")]
    SessionLifetimeInvalid {
        /// 领域侧给出的稳定分类标识符（`SessionPolicyInvalid::code`）。
        reason: &'static str,
    },
    /// 没配 `KEY_ENCRYPTION_KEY`。
    #[error("key_encryption_key_missing")]
    KeyEncryptionKeyMissing,
    /// `KEY_ENCRYPTION_KEY` 不是 canonical base64。
    #[error("key_encryption_key_malformed")]
    KeyEncryptionKeyMalformed,
    /// `KEY_ENCRYPTION_KEY` 解出来的长度不是 AES 认识的三档（16 / 24 / 32 字节）。
    ///
    /// 与 [`Self::KeyEncryptionKeyMalformed`] **分开**：两者要运维做的事完全不同 ——
    /// 前者是"这串 base64 本身有问题"，后者是"base64 没问题，但这把密钥的尺寸 AES 用不了"。
    /// 压成一个 code，第二种情形的人会去反复检查自己的 base64，而那里什么问题都没有。
    #[error("key_encryption_key_length")]
    KeyEncryptionKeyLength,
    /// `KEY_ENCRYPTION_KEY` 还是 `.env.example` 里那把公开的示例密钥。
    #[error("key_encryption_key_is_example")]
    KeyEncryptionKeyIsExample,
    /// 一家 provider 都没有，也没有显式要求单用户模式。
    #[error("single_user_not_requested")]
    SingleUserNotRequested,
}

impl AuthConfigProblem {
    /// 稳定的问题 code。GUI / CLI 按它挑文案，日志按它做聚类。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OAuthClientHalfConfigured { .. } => "oauth_client_half_configured",
            Self::OktaIssuerWithoutClient => "okta_issuer_without_client",
            Self::OktaClientWithoutIssuer => "okta_client_without_issuer",
            Self::OktaIssuerMalformed => "okta_issuer_malformed",
            Self::SessionSecretMissing => "session_secret_missing",
            Self::SessionSecretTooShort => "session_secret_too_short",
            Self::SessionSecretWithoutProvider => "session_secret_without_provider",
            Self::PublicUrlMissing => "public_url_missing",
            Self::InitialAdminEmailsMissing => "initial_admin_emails_missing",
            Self::TrustedOriginMalformed => "trusted_origin_malformed",
            Self::SessionLifetimeInvalid { .. } => "session_lifetime_invalid",
            Self::KeyEncryptionKeyMissing => "key_encryption_key_missing",
            Self::KeyEncryptionKeyMalformed => "key_encryption_key_malformed",
            Self::KeyEncryptionKeyLength => "key_encryption_key_length",
            Self::KeyEncryptionKeyIsExample => "key_encryption_key_is_example",
            Self::SingleUserNotRequested => "single_user_not_requested",
        }
    }
}

/// 一次认证配置解析的**全部**失败。
///
/// 聚合而不是"抛第一个就停"，理由与 `openbot_server::config::error` 那边相同：
/// 运维改一行重启一次，一次只告诉他一个问题，一份有四处毛病的配置就是四轮重启。
/// 上游 `config.ts` 是逐个 `throw`，这里刻意不照搬 —— 这是本轮的改进，不是 parity 项。
///
/// 恒非空：只有确实有问题时才构造得出来。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthConfigError {
    problems: Vec<AuthConfigProblem>,
}

impl AuthConfigError {
    /// 由问题清单构造。空清单返回 `None` —— 见类型文档。
    #[must_use]
    pub fn new(problems: Vec<AuthConfigProblem>) -> Option<Self> {
        if problems.is_empty() {
            None
        } else {
            Some(Self { problems })
        }
    }

    /// 单条问题的快捷构造。
    #[must_use]
    pub fn single(problem: AuthConfigProblem) -> Self {
        Self {
            problems: vec![problem],
        }
    }

    /// 全部问题，按解析顺序。
    #[must_use]
    pub fn problems(&self) -> &[AuthConfigProblem] {
        &self.problems
    }

    /// 全部问题的稳定 code，按解析顺序。
    #[must_use]
    pub fn codes(&self) -> Vec<&'static str> {
        self.problems.iter().map(|problem| problem.code()).collect()
    }
}

impl fmt::Display for AuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "认证配置有 {} 处问题：", self.problems.len())?;
        for problem in &self.problems {
            write!(formatter, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl core::error::Error for AuthConfigError {}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

/// 读一家 provider 的 `<PREFIX>_OAUTH_CLIENT_ID` / `_CLIENT_SECRET`。
///
/// **两个都有或两个都没有。** 只配一半是一副"要到某人第一次点登录才失败"的配置，
/// 而那是发现它最贵的时刻（上游 `config.ts::oauthClient` 的注释原话）。
fn oauth_client(
    env: &EnvMap,
    provider: AuthProviderId,
    problems: &mut Vec<AuthConfigProblem>,
) -> Option<OAuthClient> {
    let prefix = provider.env_prefix();
    let client_id = optional(env, &format!("{prefix}_OAUTH_CLIENT_ID"));
    let client_secret = optional(env, &format!("{prefix}_OAUTH_CLIENT_SECRET"));

    match (client_id, client_secret) {
        (Some(id), Some(secret)) => Some(OAuthClient {
            client_id: id.to_owned(),
            client_secret: Secret::new(secret),
        }),
        (None, None) => None,
        _ => {
            problems.push(AuthConfigProblem::OAuthClientHalfConfigured { provider: prefix });
            None
        }
    }
}

/// Okta：凭据与 issuer 同设同缺，且 issuer 必须是合法 URL。
fn okta_auth(env: &EnvMap, problems: &mut Vec<AuthConfigProblem>) -> Option<OktaAuth> {
    let client = oauth_client(env, AuthProviderId::Okta, problems);
    let raw_issuer = optional(env, "OKTA_OAUTH_ISSUER");

    // 与上游 `config.ts::url()` 同判据：`new URL(value)` 解得开即可，不限 scheme。
    // 这里用 `url` crate —— 同一个 WHATWG 解析器，所以接受集逐字符相同。
    let issuer = match raw_issuer {
        None => None,
        Some(text) => match url::Url::parse(text) {
            Ok(_) => Some(text.to_owned()),
            Err(_) => {
                problems.push(AuthConfigProblem::OktaIssuerMalformed);
                None
            }
        },
    };

    match (client, issuer) {
        (Some(client), Some(issuer)) => Some(OktaAuth { client, issuer }),
        (None, Some(_)) => {
            problems.push(AuthConfigProblem::OktaIssuerWithoutClient);
            None
        }
        // issuer 写了但解不开时上面已经记过一条，再补"没有 issuer"只是噪音。
        (Some(_), None) if raw_issuer.is_none() => {
            problems.push(AuthConfigProblem::OktaClientWithoutIssuer);
            None
        }
        _ => None,
    }
}

/// 解析认证配置。`Ok(None)` = 这个部署没有任何 IdP。
///
/// # 入参 `public_url` 为什么是传进来的
///
/// 它是 `openbot_server::config::ServerConfig::public_url` 已经解析、校验、剥过尾斜杠的
/// 那一个值。本模块**不自己去读那个变量** —— 同一个变量两个解析器就是两个答案，
/// 而先坏掉的那个不会有人发现。
///
/// # 与上游的一条**有意偏差**：公共地址单独存在时不再拒绝
///
/// 上游 `authConfig` 里有 `if (secret || baseUrl) throw`：session secret **或**那个 auth 专用
/// 地址变量单独出现而没有 provider，一律拒绝启动。
///
/// 那条规则在上游成立，是因为那个地址变量是 **auth 专用**的 —— 它出现就意味着"有人想配
/// 登录"。v3 §15.4 把它并进了 `OPENBOT_PUBLIC_URL`，而后者**不是** auth 专用：上游
/// `.env.example` 逐字写着它 "Only needed for connectors that a person connects their own
/// account to, such as Google Drive"。一个单用户部署为了 Google Drive 连接器配了公共地址，
/// 是完全正常的形态；照搬那条规则会让它起不来。
///
/// 所以这里只保留 secret 那一半：**配了 session secret 却没有 provider** 仍然拒绝
/// （那把密钥没有任何用处，多半是配漏了 provider），公共地址单独存在则放行。
///
/// # 为什么 provider 出问题时就此打住
///
/// 一份写了 `GOOGLE_OAUTH_CLIENT_ID` 却漏了 secret 的配置，Google 会解析成 `None`。
/// 若继续往下走"没有 provider"那条分支，会再报一条 `session_secret_without_provider`
/// 或 `initial_admin_emails_missing` —— 两条都**指向错误的方向**，而真正要修的是那半副凭据。
/// 所以 provider 侧一旦有问题，就只报那些。
///
/// # 入参 `session_lifetime` 为什么不是从环境读的
///
/// §15.4 的处置表里没有这三个窗口，所以它们此刻不是环境变量（加变量是一次 §15.4 修订 +
/// 台账变更）。做成入参而不是写死在函数体里，是为了让"将来它们变成 env"只需要改启动层
/// 一行 —— 以及让测试能直接喂一份别的策略进来，不必去动全局常量。
///
/// 绝大多数调用方传 [`default_session_lifetime`]。
///
/// # Errors
///
/// 把该阶段所有毛病一次性收进 [`AuthConfigError`]。
pub fn auth_config(
    env: &EnvMap,
    public_url: Option<&str>,
    session_lifetime: SessionLifetimePolicy,
) -> Result<Option<AuthConfig>, AuthConfigError> {
    auth_config_with_dynamic_provider(env, public_url, session_lifetime, false)
}

/// 与 [`auth_config`] 相同，但把数据库里已存在的 deployment-owned IdP 纳入“有 provider”。
///
/// 该布尔值只能来自启动层对 `sso_providers` 的数据库查询，不能来自请求或环境自报。
pub fn auth_config_with_dynamic_provider(
    env: &EnvMap,
    public_url: Option<&str>,
    session_lifetime: SessionLifetimePolicy,
    has_dynamic_provider: bool,
) -> Result<Option<AuthConfig>, AuthConfigError> {
    let mut provider_problems = Vec::new();

    let google = oauth_client(env, AuthProviderId::Google, &mut provider_problems);
    let microsoft =
        oauth_client(env, AuthProviderId::Microsoft, &mut provider_problems).map(|client| {
            MicrosoftAuth {
                client,
                tenant_id: optional(env, "MICROSOFT_OAUTH_TENANT_ID")
                    .unwrap_or(DEFAULT_MICROSOFT_TENANT_ID)
                    .to_owned(),
            }
        });
    let okta = okta_auth(env, &mut provider_problems);

    if let Some(error) = AuthConfigError::new(provider_problems) {
        return Err(error);
    }

    let session_secret = optional(env, "OPENBOT_SESSION_SECRET").map(Secret::new);
    let has_provider =
        google.is_some() || microsoft.is_some() || okta.is_some() || has_dynamic_provider;

    if !has_provider {
        if session_secret.is_some() {
            return Err(AuthConfigError::single(
                AuthConfigProblem::SessionSecretWithoutProvider,
            ));
        }
        return Ok(None);
    }

    let mut problems = Vec::new();

    let session_secret = match session_secret {
        None => {
            problems.push(AuthConfigProblem::SessionSecretMissing);
            None
        }
        Some(secret) if secret.character_count() < SESSION_SECRET_MIN_LENGTH => {
            problems.push(AuthConfigProblem::SessionSecretTooShort);
            None
        }
        Some(secret) => Some(secret),
    };

    if public_url.is_none() {
        problems.push(AuthConfigProblem::PublicUrlMissing);
    }

    /*
     * 必须有人是管理员，而**只有这里**说得出是谁。
     *
     * 角色是从这份名单写进去的，而且没有任何路由能改一个角色 —— 所以一个配了登录却
     * 没写这一行的部署，会把所有人都收成普通用户、不给任何人看管理界面、并且没有任何
     * 办法事后提升谁。启动期是发现这件事唯一便宜的时刻；昂贵的那个时刻是第一个人
     * 登进来之后。（上游 `authConfig` 里那段注释的原意。）
     *
     * 逗号切分在本层（那是配置层的事），切完的条目交给 `AdminFloor` —— 规范化、
     * 丢空条目、以及"一条都不剩就失败"都在领域侧，本模块只把那次失败翻译成一条问题。
     */
    let admin_floor =
        match AdminFloor::from_configured(comma_separated(env, "INITIAL_ADMIN_EMAILS")) {
            Ok(floor) => Some(floor),
            Err(_) => {
                problems.push(AuthConfigProblem::InitialAdminEmailsMissing);
                None
            }
        };

    // 未设时的回落是**配置层**的裁决（领域侧 `TrustedOrigins` 的文档逐字说明它不复制
    // 这条回落：把一个主机名写死进领域层等于替部署做决定）。
    let configured_origins = comma_separated(env, "TRUSTED_ORIGINS");
    let origin_entries = if configured_origins.is_empty() {
        vec![DEFAULT_TRUSTED_ORIGIN.to_owned()]
    } else {
        configured_origins
    };
    let trusted_origins = match TrustedOrigins::from_configured(origin_entries) {
        Ok(origins) => Some(origins),
        Err(OriginMalformed) => {
            problems.push(AuthConfigProblem::TrustedOriginMalformed);
            None
        }
    };

    if let Some(error) = AuthConfigError::new(problems) {
        return Err(error);
    }

    Ok(Some(AuthConfig {
        public_url: public_url.expect("上面已判过 None").to_owned(),
        session_secret: session_secret.expect("上面已判过 None 与过短"),
        session_lifetime,
        trusted_origins: trusted_origins.expect("上面已把 Err 记成问题并返回"),
        admin_floor: admin_floor.expect("上面已把 Err 记成问题并返回"),
        google,
        microsoft,
        okta,
    }))
}

// ---------------------------------------------------------------------------
// 单用户模式（v3 §6.1）
// ---------------------------------------------------------------------------

/// 这个部署是不是"所有访客都是同一个管理员"。
///
/// 逐条对齐上游 `server/src/auth/dev-actor.ts::singleUserEnabled`：
///
/// 1. **有 provider 就恒为假**，无论旗标怎么写 —— provider 永远赢，一个部署不能"半登录"；
/// 2. 无 provider 且 `OPENBOT_SINGLE_USER` 经 `trim` 后**恒等** `"true"` → 真；
/// 3. 无 provider 且没这么写 → **拒绝启动**。
///
/// 第 3 条是整件事的全部意义。它不是警告也不是缺省：一个会把每个访客都当成管理员的部署
/// **不会起来**，并且说出该配什么。
///
/// 判据是字符串恒等，`"1"` / `"yes"` / `"TRUE"` 一律不算 —— 上游
/// `server/tests/single-user.test.ts` 把这批值逐个钉过。
///
/// # 与上游的一条**有意偏差**：本模块不认那个旧旗标名
///
/// 上游 `dev-actor.ts` 里那个 `||` 的右半边还认一个更早的旗标名，理由是"让既有 `.env`
/// 继续能跑"。本模块**不认**它：它是本仓最危险的那个开关（"每个访客都是管理员"）的
/// **第二个**入口，而第二个入口意味着以后每一次改这段逻辑都要有人同时记得两个名字。
///
/// **但"不认"不等于"不管"。** 那个旧名已被登记进
/// `openbot_server::config::migration::RENAMED_ENV_VARS`（rename → `OPENBOT_SINGLE_USER`），
/// 并且带**自己的**稳定 code `renamed_single_user_flag`，所以带着旧名的部署会在启动期被
/// 点名"这个旗标改名了，新名字是什么"，而不是走到这里以
/// [`AuthConfigProblem::SingleUserNotRequested`] 失败。
///
/// 后一种失败正是要避免的那种：它的意思是"你没配任何身份提供方，也没说要单用户模式"，
/// 而操作员**明明配了**（用的是旧名字）。那句话指向一个他已经做过的动作，于是他会去翻
/// IdP 配置、翻不出问题，最后大概率去做那个最危险的事 —— 随便找个旗标把它打开。
///
/// 两处分工因此是：**改名的识别与提示在 server 的迁移扫描，这里只负责不把旧名当成"是"。**
///
/// # Errors
///
/// 无 provider 且没有显式要求单用户模式时返回
/// [`AuthConfigProblem::SingleUserNotRequested`]。
pub fn single_user_enabled(env: &EnvMap, has_provider: bool) -> Result<bool, AuthConfigError> {
    if has_provider {
        return Ok(false);
    }
    if env
        .get("OPENBOT_SINGLE_USER")
        .is_some_and(|value| trim_ecmascript(value) == "true")
    {
        return Ok(true);
    }
    Err(AuthConfigError::single(
        AuthConfigProblem::SingleUserNotRequested,
    ))
}

/// 这个进程监听在什么范围上。
///
/// # 为什么是三态而不是"是不是 loopback"
///
/// v3 §6.1 逐字：单用户模式「只允许 loopback **或管理员明确配置的受控网络绑定**」。
/// 那个"或"后面的一档是真实需求 —— 有人在一台隔离的实验机上把它绑到内网地址，
/// 并且知道自己在干什么。把它压成布尔，就只剩"loopback 或非法"，
/// 于是那个合法用例会被逼着去关掉整条检查。
///
/// 三态里 [`BindingExposure::ControlledNetworkAcknowledged`] 的关键在 **Acknowledged**：
/// 它必须由一个显式的管理员动作产生，**不能由代码从地址形状推断出来** ——
/// "这是私网地址，那应该算受控吧"正是 §6.1 要挡住的那种推断。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingExposure {
    /// 只监听本机回环。
    Loopback,
    /// 监听在更宽的范围上，**且管理员明确声明这是受控网络**。
    ControlledNetworkAcknowledged,
    /// 监听在更宽的范围上，没有任何人声明过什么。
    Unrestricted,
}

/// 单用户模式在这个绑定范围上放不放行。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SingleUserAdmission {
    /// 放行。
    Admit,
    /// 拒绝：这是"把每个访客当管理员"的部署，绑在谁都能到的地方。
    Refuse,
}

/// §6.1 的绑定判据。**纯函数**，除入参外不看任何东西。
///
/// # 这个函数此刻还没有输入源，这是一个已登记的缺口
///
/// 上游没有任何环境变量描述绑定地址（`Bun.serve` 默认绑 `0.0.0.0`），
/// `parity/env.yaml` 的 70 条里也没有。所以 [`BindingExposure`] 现在只能由接线层构造，
/// 而"管理员明确配置"这件事**还没有承载它的配置项**。
///
/// 判据先落地、输入源随后补，是有意的顺序：把判据留到"等我们想好变量名"之后，
/// 结果通常是那条判据永远不出现。这一条已登记进交付报告，等一次
/// `OPENBOT_BIND_ADDR`（或等价物）的立项。
#[must_use]
pub const fn single_user_binding_verdict(binding: BindingExposure) -> SingleUserAdmission {
    match binding {
        BindingExposure::Loopback | BindingExposure::ControlledNetworkAcknowledged => {
            SingleUserAdmission::Admit
        }
        BindingExposure::Unrestricted => SingleUserAdmission::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use openbot_domain::identity::email::NormalizedEmail;
    use openbot_domain::identity::session::SessionPolicyInvalid;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn with(base: &EnvMap, pairs: &[(&str, &str)]) -> EnvMap {
        let mut map = base.clone();
        for (name, value) in pairs {
            map.insert((*name).to_owned(), (*value).to_owned());
        }
        map
    }

    fn without(base: &EnvMap, names: &[&str]) -> EnvMap {
        let mut map = base.clone();
        for name in names {
            map.remove(*name);
        }
        map
    }

    /// 一副能跑起来的最小认证配置。各条用例在它上面做增删。
    fn signed_in_env() -> EnvMap {
        env(&[
            ("GOOGLE_OAUTH_CLIENT_ID", "google-client-id"),
            ("GOOGLE_OAUTH_CLIENT_SECRET", "google-client-secret"),
            (
                "OPENBOT_SESSION_SECRET",
                "a-long-enough-local-development-auth-secret",
            ),
            ("INITIAL_ADMIN_EMAILS", "admin@openbot.test"),
        ])
    }

    /// 只留下 session 那三样，不带任何 provider。
    fn without_google(base: &EnvMap) -> EnvMap {
        without(
            base,
            &["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"],
        )
    }

    const PUBLIC: Option<&str> = Some("http://localhost:3001");

    // -----------------------------------------------------------------------
    // 正向对照组：这一组不绿，下面所有"拒绝"用例都不成立
    // -----------------------------------------------------------------------

    /// 一副完整的 Google 配置确实能起来，且每个缺省值都是上游实测到的那个。
    #[test]
    fn a_complete_configuration_starts() {
        let config = auth_config(&signed_in_env(), PUBLIC, default_session_lifetime())
            .expect("合法配置")
            .expect("有 provider 就该有 AuthConfig");

        assert_eq!(config.public_url, "http://localhost:3001");
        assert_eq!(
            config.session_secret.expose(),
            "a-long-enough-local-development-auth-secret"
        );
        // 上游 `authConfig` 的缺省是 3000（`.env.example` 里的 3010 是模板值，不是缺省）。
        assert_eq!(config.trusted_origins.len(), 1);
        assert!(config.trusted_origins.trusts("http://localhost:3000"));
        assert_eq!(config.admin_floor.len(), 1);
        assert!(
            config
                .admin_floor
                .contains(&NormalizedEmail::normalize("admin@openbot.test").expect("非空"))
        );
        assert_eq!(config.configured_providers(), vec![AuthProviderId::Google]);
        // 三个 session 窗口就是那三个常量，一个都没被路上某处改掉。
        assert_eq!(config.session_lifetime, default_session_lifetime());
    }

    /// 一家 provider 都没有、且显式要了单用户 → 没有 AuthConfig，也不是错误。
    #[test]
    fn no_provider_at_all_is_a_valid_deployment() {
        let bare = env(&[("OPENBOT_SINGLE_USER", "true")]);
        assert!(
            auth_config(&bare, None, default_session_lifetime())
                .expect("合法")
                .is_none()
        );
        assert!(single_user_enabled(&bare, false).expect("显式要了"));
    }

    #[test]
    fn a_database_owned_provider_makes_session_configuration_live_without_an_environment_idp() {
        let dynamic_only = without_google(&signed_in_env());
        let config = auth_config_with_dynamic_provider(
            &dynamic_only,
            PUBLIC,
            default_session_lifetime(),
            true,
        )
        .expect("数据库 provider 是权威启动事实")
        .expect("动态 provider 需要 multi-user auth 配置");
        assert!(config.configured_providers().is_empty());
        assert_eq!(
            config.session_secret.character_count(),
            "a-long-enough-local-development-auth-secret"
                .chars()
                .count()
        );
    }

    // -----------------------------------------------------------------------
    // provider
    // -----------------------------------------------------------------------

    /// 三家可以同时配置，且顺序固定。
    #[test]
    fn all_three_providers_can_be_configured_at_once_in_a_fixed_order() {
        let all = with(
            &signed_in_env(),
            &[
                ("MICROSOFT_OAUTH_CLIENT_ID", "entra-client-id"),
                ("MICROSOFT_OAUTH_CLIENT_SECRET", "entra-client-secret"),
                ("OKTA_OAUTH_CLIENT_ID", "okta-client-id"),
                ("OKTA_OAUTH_CLIENT_SECRET", "okta-client-secret"),
                (
                    "OKTA_OAUTH_ISSUER",
                    "https://example.okta.com/oauth2/default",
                ),
            ],
        );
        let config = auth_config(&all, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(
            config.configured_providers(),
            vec![
                AuthProviderId::Google,
                AuthProviderId::Microsoft,
                AuthProviderId::Okta,
            ]
        );
    }

    /// 每一家的"只配一半"都被拦住 —— 两个方向各来一次。
    #[test]
    fn half_a_client_is_refused_for_every_provider() {
        for (id_name, secret_name) in [
            ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"),
            ("MICROSOFT_OAUTH_CLIENT_ID", "MICROSOFT_OAUTH_CLIENT_SECRET"),
            ("OKTA_OAUTH_CLIENT_ID", "OKTA_OAUTH_CLIENT_SECRET"),
        ] {
            for only in [id_name, secret_name] {
                let half = env(&[(only, "value")]);
                let error = auth_config(&half, PUBLIC, default_session_lifetime())
                    .expect_err("只配一半必须拒绝");
                assert_eq!(
                    error.codes(),
                    vec!["oauth_client_half_configured"],
                    "{only}"
                );
            }
        }
    }

    /// 空串等同未设：`_SECRET=""` 就是"没配"，于是触发"只配一半"。
    #[test]
    fn a_blank_secret_counts_as_absent() {
        let blanked = with(&signed_in_env(), &[("GOOGLE_OAUTH_CLIENT_SECRET", "")]);
        let error =
            auth_config(&blanked, PUBLIC, default_session_lifetime()).expect_err("空串即未设");
        assert_eq!(
            error.codes(),
            vec!["oauth_client_half_configured"],
            "{error}"
        );
    }

    /// Entra 的目录缺省是 `common`，而 `common` **放行个人账号**。
    #[test]
    fn entra_defaults_to_a_directory_that_admits_personal_accounts() {
        let entra = with(
            &without_google(&signed_in_env()),
            &[
                ("MICROSOFT_OAUTH_CLIENT_ID", "entra-client-id"),
                ("MICROSOFT_OAUTH_CLIENT_SECRET", "entra-client-secret"),
            ],
        );
        let config = auth_config(&entra, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(config.microsoft.as_ref().expect("已配").tenant_id, "common");

        // 正向对照：写了目录 GUID 就用那个，否则上一条在"tenant_id 恒为 common"
        // 的世界里同样通过。
        let narrowed = with(
            &entra,
            &[(
                "MICROSOFT_OAUTH_TENANT_ID",
                "8f2c1e40-0000-0000-0000-000000000000",
            )],
        );
        let config = auth_config(&narrowed, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(
            config.microsoft.expect("已配").tenant_id,
            "8f2c1e40-0000-0000-0000-000000000000"
        );
    }

    /// Okta：凭据与 issuer 同设同缺，两个方向各拒一次。
    #[test]
    fn okta_needs_its_issuer_and_its_issuer_needs_okta() {
        let base = without_google(&signed_in_env());

        let no_issuer = with(
            &base,
            &[
                ("OKTA_OAUTH_CLIENT_ID", "okta-client-id"),
                ("OKTA_OAUTH_CLIENT_SECRET", "okta-client-secret"),
            ],
        );
        assert_eq!(
            auth_config(&no_issuer, PUBLIC, default_session_lifetime())
                .expect_err("有凭据没 issuer")
                .codes(),
            vec!["okta_client_without_issuer"]
        );

        let no_client = with(
            &base,
            &[(
                "OKTA_OAUTH_ISSUER",
                "https://example.okta.com/oauth2/default",
            )],
        );
        assert_eq!(
            auth_config(&no_client, PUBLIC, default_session_lifetime())
                .expect_err("有 issuer 没凭据")
                .codes(),
            vec!["okta_issuer_without_client"]
        );

        // 正向对照：两个都配齐就通过。
        let complete = with(
            &no_issuer,
            &[(
                "OKTA_OAUTH_ISSUER",
                "https://example.okta.com/oauth2/default",
            )],
        );
        let config = auth_config(&complete, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(
            config.okta.expect("已配").issuer,
            "https://example.okta.com/oauth2/default"
        );
    }

    /// issuer 必须是合法 URL。
    #[test]
    fn a_malformed_okta_issuer_is_refused() {
        let bad = with(
            &without_google(&signed_in_env()),
            &[
                ("OKTA_OAUTH_CLIENT_ID", "okta-client-id"),
                ("OKTA_OAUTH_CLIENT_SECRET", "okta-client-secret"),
                ("OKTA_OAUTH_ISSUER", "not a URL"),
            ],
        );
        assert_eq!(
            auth_config(&bad, PUBLIC, default_session_lifetime())
                .expect_err("issuer 解不开")
                .codes(),
            vec!["okta_issuer_malformed"]
        );
    }

    // -----------------------------------------------------------------------
    // session secret / 公共地址 / 管理员
    // -----------------------------------------------------------------------

    /// 有 provider 却没有 session secret → 拒绝。
    #[test]
    fn sign_in_needs_a_session_secret() {
        let no_secret = without(&signed_in_env(), &["OPENBOT_SESSION_SECRET"]);
        assert_eq!(
            auth_config(&no_secret, PUBLIC, default_session_lifetime())
                .expect_err("没密钥")
                .codes(),
            vec!["session_secret_missing"]
        );
    }

    /// 密钥太短 → 拒绝；恰好到线 → 通过（边界两侧各一条）。
    #[test]
    fn the_session_secret_has_a_length_floor() {
        let short = "x".repeat(SESSION_SECRET_MIN_LENGTH - 1);
        let too_short = with(
            &signed_in_env(),
            &[("OPENBOT_SESSION_SECRET", short.as_str())],
        );
        assert_eq!(
            auth_config(&too_short, PUBLIC, default_session_lifetime())
                .expect_err("太短")
                .codes(),
            vec!["session_secret_too_short"]
        );

        // 正向对照：恰好到线就通过 —— 否则上一条在"任何长度都判太短"的世界里同样通过。
        let exact_secret = "x".repeat(SESSION_SECRET_MIN_LENGTH);
        let exact = with(
            &signed_in_env(),
            &[("OPENBOT_SESSION_SECRET", exact_secret.as_str())],
        );
        assert!(
            auth_config(&exact, PUBLIC, default_session_lifetime())
                .expect("恰好到线")
                .is_some()
        );
    }

    /// 配了密钥却一家 provider 都没有 → 拒绝。
    #[test]
    fn a_session_secret_with_nothing_to_sign_in_is_refused() {
        let orphan = env(&[(
            "OPENBOT_SESSION_SECRET",
            "a-long-enough-local-development-auth-secret",
        )]);
        assert_eq!(
            auth_config(&orphan, PUBLIC, default_session_lifetime())
                .expect_err("没 provider")
                .codes(),
            vec!["session_secret_without_provider"]
        );
    }

    /// **有意偏差**：公共地址单独存在**不**拒绝 —— 它现在也服务连接器 redirect URI。
    #[test]
    fn a_public_url_alone_is_not_a_reason_to_refuse() {
        let single_user = env(&[("OPENBOT_SINGLE_USER", "true")]);
        assert!(
            auth_config(
                &single_user,
                Some("https://openbot.example.com"),
                default_session_lifetime()
            )
            .expect("应当放行")
            .is_none()
        );
    }

    /// 有 provider 却没有公共地址 → 拒绝（OAuth 回调没有落地处）。
    #[test]
    fn sign_in_needs_somewhere_for_the_callback_to_land() {
        assert_eq!(
            auth_config(&signed_in_env(), None, default_session_lifetime())
                .expect_err("没有公共地址")
                .codes(),
            vec!["public_url_missing"]
        );
    }

    /// 有 provider 却没写管理员 → 拒绝；单用户模式则不需要这份名单。
    #[test]
    fn sign_in_needs_at_least_one_administrator() {
        let nobody = without(&signed_in_env(), &["INITIAL_ADMIN_EMAILS"]);
        assert_eq!(
            auth_config(&nobody, PUBLIC, default_session_lifetime())
                .expect_err("没有管理员")
                .codes(),
            vec!["initial_admin_emails_missing"]
        );

        // 正向对照：单用户模式本来就只有一个管理员，不该被要求写名单。
        let single_user = env(&[("OPENBOT_SINGLE_USER", "true")]);
        assert!(auth_config(&single_user, None, default_session_lifetime()).is_ok());
    }

    /// 管理员名单：切分、trim、规范化大小写、丢空项。
    #[test]
    fn administrator_addresses_are_normalised_the_way_upstream_compares_them() {
        let listed = with(
            &signed_in_env(),
            &[(
                "INITIAL_ADMIN_EMAILS",
                " Admin@OpenBot.Test , ,OWNER@openbot.test ",
            )],
        );
        let config = auth_config(&listed, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(
            config
                .admin_floor
                .iter()
                .map(NormalizedEmail::as_str)
                .collect::<Vec<_>>(),
            vec!["admin@openbot.test", "owner@openbot.test"]
        );

        // 比对两侧都规范化：大小写与空白都不该把人挡在外面。
        let admin = NormalizedEmail::normalize("  ADMIN@OpenBot.TEST ").expect("非空");
        assert!(config.admin_floor.contains(&admin));
        // 负向对照：不在名单里的人确实不是管理员。
        let stranger = NormalizedEmail::normalize("stranger@openbot.test").expect("非空");
        assert!(!config.admin_floor.contains(&stranger));
    }

    /// **带 BOM 的 `.env` 不会让 admin floor 静默失效。**
    ///
    /// 这条是"复用领域侧规范化"这个决定的兑现证据。JS 的 `trim()` 按 ECMA-262 的
    /// `WhiteSpace` 产生式去空白，那个产生式包含 U+FEFF；Rust 的 `str::trim` 按 Unicode
    /// `White_Space` 属性去，而 U+FEFF 的类别是 `Cf`。于是一份带 BOM 保存的 `.env`，
    /// 它的 `INITIAL_ADMIN_EMAILS` **第一项**会以 U+FEFF 开头 —— 用 `str::trim` 写的
    /// 本地实现会把它原样留下，那条 floor 条目从此匹配不上任何人，**而且不报任何错**。
    #[test]
    fn a_byte_order_mark_does_not_silently_disable_the_admin_floor() {
        let with_bom = with(
            &signed_in_env(),
            &[("INITIAL_ADMIN_EMAILS", "\u{FEFF}admin@openbot.test")],
        );
        let config = auth_config(&with_bom, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        let admin = NormalizedEmail::normalize("admin@openbot.test").expect("非空");
        assert!(config.admin_floor.contains(&admin), "BOM 让 floor 失效了");

        // 正向对照：`str::trim` 单独确实**去不掉**那个码点 —— 没有这条，上面那条
        // 在"BOM 本来就会被 Rust 去掉"的世界里同样通过，于是证明不了任何事。
        assert_eq!(
            "\u{FEFF}admin@openbot.test".trim(),
            "\u{FEFF}admin@openbot.test"
        );
    }

    /// 可信来源：配了就用，没配落到上游那个缺省。
    #[test]
    fn trusted_origins_fall_back_to_the_upstream_default() {
        let configured = with(
            &signed_in_env(),
            &[("TRUSTED_ORIGINS", " http://app.test , http://alt.test ")],
        );
        let config = auth_config(&configured, PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(config.trusted_origins.len(), 2);
        assert!(config.trusted_origins.trusts("http://app.test"));
        assert!(config.trusted_origins.trusts("http://alt.test"));
        // 负向对照：没列进去的来源确实不被信任。
        assert!(!config.trusted_origins.trusts("http://evil.test"));

        // 另一半：没配时确实是那个缺省。两半都要，否则"恒返回缺省"或"恒返回配置值"
        // 各能骗过其中一条。
        let config = auth_config(&signed_in_env(), PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        assert_eq!(config.trusted_origins.len(), 1);
        assert!(config.trusted_origins.trusts(DEFAULT_TRUSTED_ORIGIN));
    }

    /// `TRUSTED_ORIGINS` 里有一条解不开 → 整体拒绝，**不静默丢弃那一条**。
    #[test]
    fn a_malformed_trusted_origin_refuses_rather_than_being_dropped() {
        let bad = with(
            &signed_in_env(),
            &[("TRUSTED_ORIGINS", "http://app.test,not an origin")],
        );
        assert_eq!(
            auth_config(&bad, PUBLIC, default_session_lifetime())
                .expect_err("坏条目必须拒绝启动")
                .codes(),
            vec!["trusted_origin_malformed"]
        );

        // 正向对照：去掉那条坏的就通过 —— 否则本条在"任何 TRUSTED_ORIGINS 都被拒"
        // 的世界里同样通过。
        let good = with(&signed_in_env(), &[("TRUSTED_ORIGINS", "http://app.test")]);
        assert!(
            auth_config(&good, PUBLIC, default_session_lifetime())
                .expect("合法")
                .is_some()
        );
    }

    /// 三个默认窗口的关系自洽 —— [`default_session_lifetime`] 的 `expect` 不会在生产触发。
    ///
    /// 顺带钉住那三个数字本身：改动它们是一次产品决定，会在这里显形。
    #[test]
    fn default_session_lifetime_is_self_consistent() {
        let policy = SessionLifetimePolicy::new(
            DEFAULT_SESSION_IDLE,
            DEFAULT_SESSION_ABSOLUTE,
            DEFAULT_SENSITIVE_WRITE_FRESHNESS,
        )
        .expect("三个默认窗口必须自洽");
        assert_eq!(policy, default_session_lifetime());

        assert_eq!(policy.idle(), Duration::hours(8));
        assert_eq!(policy.absolute(), Duration::days(7));
        assert_eq!(policy.fresh(), Duration::minutes(15));

        // fresh 必须**严格短于** idle，否则"敏感 admin 写要求 fresh session"这道闸门恒为真。
        assert!(policy.fresh() < policy.idle());
        assert!(policy.idle() <= policy.absolute());

        // 负向对照：那道构造期校验确实会说"不" —— 否则上面全部在
        // "SessionLifetimePolicy::new 恒 Ok"的世界里同样通过。
        assert_eq!(
            SessionLifetimePolicy::new(
                DEFAULT_SESSION_IDLE,
                DEFAULT_SESSION_ABSOLUTE,
                DEFAULT_SESSION_IDLE,
            )
            .expect_err("fresh == idle 必须被拒"),
            SessionPolicyInvalid::FreshNotShorterThanIdle
        );
    }

    /// 调用方可以喂一份自己的策略进来，而不必去动全局常量。
    #[test]
    fn a_caller_supplied_policy_wins_over_the_defaults() {
        let custom = SessionLifetimePolicy::new(
            Duration::hours(1),
            Duration::hours(12),
            Duration::minutes(5),
        )
        .expect("自洽");
        let config = auth_config(&signed_in_env(), PUBLIC, custom)
            .expect("合法")
            .expect("有 provider");
        assert_eq!(config.session_lifetime, custom);
        // 正向对照：它确实与默认那份不同，否则本条测不出"覆盖"这件事。
        assert_ne!(custom, default_session_lifetime());
    }

    /// **本 crate 不读任何旧名。**
    ///
    /// 一份只写了旧 session secret 变量名的配置，在这里的表现必须与"根本没配"
    /// 逐字节相同。旧名本身的拒绝由 `openbot_server::config::migration` 负责。
    #[test]
    fn a_legacy_variable_name_supplies_nothing_here() {
        let legacy = with(
            &without(&signed_in_env(), &["OPENBOT_SESSION_SECRET"]),
            &[(
                "BETTER_AUTH_SECRET",
                "a-long-enough-local-development-auth-secret",
            )],
        );
        assert_eq!(
            auth_config(&legacy, PUBLIC, default_session_lifetime())
                .expect_err("旧名什么都不提供")
                .codes(),
            vec!["session_secret_missing"]
        );

        // 正向对照：换成新名就读得到，否则本条在"永远读不到 secret"的世界里同样通过。
        assert!(
            auth_config(&signed_in_env(), PUBLIC, default_session_lifetime())
                .expect("合法")
                .is_some()
        );
    }

    /// 一次解析把该阶段所有毛病列全。
    #[test]
    fn every_problem_in_one_pass() {
        let messy = env(&[
            ("GOOGLE_OAUTH_CLIENT_ID", "google-client-id"),
            ("GOOGLE_OAUTH_CLIENT_SECRET", "google-client-secret"),
            ("OPENBOT_SESSION_SECRET", "too-short"),
        ]);
        let error = auth_config(&messy, None, default_session_lifetime()).expect_err("三处毛病");
        assert_eq!(
            error.codes(),
            vec![
                "session_secret_too_short",
                "public_url_missing",
                "initial_admin_emails_missing",
            ],
            "{error}"
        );
    }

    // -----------------------------------------------------------------------
    // KEY_ENCRYPTION_KEY
    // -----------------------------------------------------------------------

    /// `n` 个零字节的 canonical base64。
    ///
    /// 算出来而不是抄一串字面量：44 个 `A` 与 43 个 `A` 用肉眼分不开，而这一组用例的
    /// 全部意义就在那一个字符的差别上。本机 `base64` 对 16 / 20 / 24 / 31 / 32 / 33
    /// 六个取值实测过它的产出，与这里逐字符相同（由 `zero_key_base64_matches_base64_1`
    /// 钉住其中三个）。
    fn zero_key_base64(bytes: usize) -> String {
        let bits = bytes * 8;
        let data = bits / 6 + usize::from(!bits.is_multiple_of(6));
        let padding = (4 - data % 4) % 4;
        format!("{}{}", "A".repeat(data), "=".repeat(padding))
    }

    /// 上面那个助手确实产出 `base64(1)` 产出的东西。
    ///
    /// 三个取值取自本机实测（`printf '\0'*n | base64 -w0`）。没有这条，
    /// 整组长度用例都建立在一段没被验证过的算术上。
    #[test]
    fn zero_key_base64_matches_base64_1() {
        assert_eq!(zero_key_base64(16), "AAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(zero_key_base64(24), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(zero_key_base64(32), EXAMPLE_KEY_ENCRYPTION_KEY);
        // 20 字节那条是本组负向用例的输入，也一并钉住。
        assert_eq!(zero_key_base64(20), "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    /// 一把真密钥在两档下都通过。这是本组的正向对照。
    #[test]
    fn a_real_key_is_accepted_in_both_policies() {
        // 32 字节全 0xFF 的 canonical base64（本机 `base64` 实测产出）。
        let real = "//////////////////////////////////////////8=";
        let map = env(&[("KEY_ENCRYPTION_KEY", real)]);
        for policy in [ExampleKeyPolicy::Reject, ExampleKeyPolicy::Allow] {
            let key = KeyEncryptionKey::from_env_map(&map, policy).expect("合法密钥");
            assert_eq!(key.strength(), KeyEncryptionKeyStrength::Aes256);
            assert_eq!(key.wrapping_key().bits(), 256);
            assert!(key.advisory_code().is_none(), "AES-256 不该有告警");
        }
        // 解码器确实解出了那 32 个 0xFF —— `WrappingKey` 不肯把材料交出来，
        // 所以这一半在解码器这一层验。
        assert_eq!(
            decode_canonical_base64(real).expect("合法 base64"),
            vec![0xFF_u8; 32]
        );
    }

    /// **AES 认识的三档长度全部接受**，且弱于 256 位的两档带告警。
    ///
    /// 这条是对 v3 §15.4 那句"32 字节"的修订的执行面：上游
    /// `credentials.ts::aesKey` 走 WebCrypto 的 AES-GCM，实测 16 / 24 / 32 三档都能
    /// round-trip。硬要求 32 字节会让一个用 16 或 24 字节 KEK 跑着的现网部署起不来，
    /// 从而**永远迁不了自己的数据**。
    #[test]
    fn all_three_aes_key_lengths_start_and_the_weak_two_are_flagged() {
        let cases = [
            (16, KeyEncryptionKeyStrength::Aes128, 128, true),
            (24, KeyEncryptionKeyStrength::Aes192, 192, true),
            (32, KeyEncryptionKeyStrength::Aes256, 256, false),
        ];
        for (bytes, strength, bits, expects_advisory) in cases {
            let encoded = zero_key_base64(bytes);
            let map = env(&[("KEY_ENCRYPTION_KEY", encoded.as_str())]);
            let key = KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Allow)
                .unwrap_or_else(|error| panic!("{bytes} 字节必须能启动：{error}"));
            assert_eq!(key.strength(), strength, "{bytes} 字节");
            assert_eq!(key.wrapping_key().bits(), bits, "{bytes} 字节");
            assert_eq!(
                key.advisory_code().is_some(),
                expects_advisory,
                "{bytes} 字节的告警档位不对"
            );
            if expects_advisory {
                assert_eq!(
                    key.advisory_code(),
                    Some(KEY_ENCRYPTION_KEY_BELOW_AES_256),
                    "{bytes} 字节"
                );
            }
        }
        // 判据直接来自领域侧，不是本模块另写的一张表。
        assert_eq!(WrappingKey::ACCEPTED_BYTES, [16, 24, 32]);
    }

    /// 三档之外的长度一律拒绝启动 —— **不截断、不补零、不取最近的一档**。
    ///
    /// 每条负向断言都靠上面那条 `all_three_aes_key_lengths_start_and_the_weak_two_are_flagged`
    /// 做正向对照：没有它，一个恒拒绝的实现也能过这一整条。
    #[test]
    fn any_other_key_length_is_refused_rather_than_coerced() {
        for bytes in [1_usize, 4, 8, 15, 17, 20, 23, 25, 31, 33, 64] {
            let encoded = zero_key_base64(bytes);
            let map = env(&[("KEY_ENCRYPTION_KEY", encoded.as_str())]);
            assert_eq!(
                KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Allow)
                    .expect_err("三档之外的长度必须拒绝启动")
                    .codes(),
                vec!["key_encryption_key_length"],
                "{bytes} 字节不该被接受"
            );
        }
    }

    /// 缺失、非 canonical、URL-safe 变体：报的是 `malformed`，不是 `length`。
    ///
    /// 两个 code 分开是有意的：一个是"这串 base64 有问题"，另一个是"base64 没问题、
    /// 但这把密钥 AES 用不了"，运维要做的事完全不同。
    #[test]
    fn a_malformed_encoding_is_told_apart_from_a_wrong_length() {
        assert_eq!(
            KeyEncryptionKey::from_env_map(&EnvMap::new(), ExampleKeyPolicy::Allow)
                .expect_err("必填")
                .codes(),
            vec!["key_encryption_key_missing"]
        );

        let a = |count: usize| "A".repeat(count);
        let malformed = vec![
            // 根本不是 base64（长度也不是 4 的倍数）。
            "local-development-key".to_owned(),
            // 长度不是 4 的倍数。
            a(41),
            // **解得开但编不回去**：末尾剩余 2 位不为 0。上游那条回编比对拒绝它。
            format!("{}B=", a(42)),
            // URL-safe 变体不在标准字母表里。
            format!("{}_AA=", a(40)),
        ];
        for bad in malformed {
            let map = env(&[("KEY_ENCRYPTION_KEY", bad.as_str())]);
            assert_eq!(
                KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Allow)
                    .expect_err("应当拒绝")
                    .codes(),
                vec!["key_encryption_key_malformed"],
                "{bad:?}"
            );
        }

        // 对照：编码完全合法、只是尺寸不对时，报的是另一个 code。
        let wrong_size = zero_key_base64(20);
        let map = env(&[("KEY_ENCRYPTION_KEY", wrong_size.as_str())]);
        assert_eq!(
            KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Allow)
                .expect_err("20 字节 AES 用不了")
                .codes(),
            vec!["key_encryption_key_length"]
        );
    }

    /// 示例密钥：生产拒、开发放行。
    ///
    /// 两档都断言 —— 只断言"生产拒"的话，一个恒拒的实现也能过。
    #[test]
    fn the_example_key_is_refused_in_production_and_allowed_in_development() {
        let map = env(&[("KEY_ENCRYPTION_KEY", EXAMPLE_KEY_ENCRYPTION_KEY)]);
        assert_eq!(
            KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Reject)
                .expect_err("生产必须拒")
                .codes(),
            vec!["key_encryption_key_is_example"]
        );
        assert!(KeyEncryptionKey::from_env_map(&map, ExampleKeyPolicy::Allow).is_ok());
    }

    /// 示例密钥**本身是合法的** —— 这正是它危险的原因。
    ///
    /// 没有这条，"生产拒绝示例密钥"就可能只是"它恰好格式不合法"的副作用；
    /// 顺带也钉住了那个字面量没被抄错一个字符。
    #[test]
    fn the_example_key_passes_every_format_check() {
        let decoded =
            decode_canonical_base64(EXAMPLE_KEY_ENCRYPTION_KEY).expect("它是合法 canonical base64");
        assert_eq!(decoded.len(), 32, "而且长度正好对");
        assert_eq!(decoded, vec![0_u8; 32]);
    }

    // -----------------------------------------------------------------------
    // 单用户模式
    // -----------------------------------------------------------------------

    /// provider 永远赢：配了 provider 时旗标无效。
    #[test]
    fn a_provider_always_wins_over_the_flag() {
        let asked = env(&[("OPENBOT_SINGLE_USER", "true")]);
        assert!(!single_user_enabled(&asked, true).expect("有 provider 不报错"));
        assert!(!single_user_enabled(&EnvMap::new(), true).expect("有 provider 不报错"));
        // 正向对照：没有 provider 时同一个旗标确实生效。
        assert!(single_user_enabled(&asked, false).expect("显式要了"));
    }

    /// 没有 provider 也没有旗标 → 拒绝启动。这是整件事的全部意义。
    #[test]
    fn no_provider_and_no_flag_refuses_to_start() {
        assert_eq!(
            single_user_enabled(&EnvMap::new(), false)
                .expect_err("必须拒绝")
                .codes(),
            vec!["single_user_not_requested"]
        );
    }

    /// 旗标是字符串恒等 `"true"`，别的写法一律不算"是"。
    #[test]
    fn the_flag_is_read_exactly() {
        for not_true in ["false", "1", "yes", "TRUE", "", " True "] {
            let map = env(&[("OPENBOT_SINGLE_USER", not_true)]);
            assert!(
                single_user_enabled(&map, false).is_err(),
                "{not_true:?} 不该被当成 true"
            );
        }
        // 正向对照：两侧空白会被 trim 掉，`" true "` 仍然算是。
        let padded = env(&[("OPENBOT_SINGLE_USER", " true ")]);
        assert!(single_user_enabled(&padded, false).expect("trim 后恒等 true"));
    }

    /// **本模块不认那个旧旗标名。**
    ///
    /// 有意偏差，理由与两处分工见 [`single_user_enabled`] 文档。实际的操作员体验由
    /// `openbot_server::config::migration` 那条 `renamed_single_user_flag` 承担：
    /// 启动扫描先一步点名"这个旗标改名了"，所以现实中不会有人真的看到这里这条错误。
    #[test]
    fn the_older_flag_name_is_not_honoured() {
        let legacy = env(&[("OPENBOT_DEV_NO_AUTH", "true")]);
        assert_eq!(
            single_user_enabled(&legacy, false)
                .expect_err("旧旗标不再是第二个入口")
                .codes(),
            vec!["single_user_not_requested"]
        );
        // 正向对照：新名字确实有效，否则本条在"什么都打不开"的世界里同样通过。
        assert!(
            single_user_enabled(&env(&[("OPENBOT_SINGLE_USER", "true")]), false).expect("新名有效")
        );
    }

    /// 绑定判据：loopback 与"管理员声明过"放行，别的拒绝。
    #[test]
    fn single_user_mode_refuses_an_unrestricted_binding() {
        assert_eq!(
            single_user_binding_verdict(BindingExposure::Unrestricted),
            SingleUserAdmission::Refuse
        );
        // 正向对照两条：否则上一条在"恒 Refuse"的世界里同样通过，
        // 而那个世界里 §6.1 那个"或受控网络"的合法用例是跑不起来的。
        assert_eq!(
            single_user_binding_verdict(BindingExposure::Loopback),
            SingleUserAdmission::Admit
        );
        assert_eq!(
            single_user_binding_verdict(BindingExposure::ControlledNetworkAcknowledged),
            SingleUserAdmission::Admit
        );
    }

    // -----------------------------------------------------------------------
    // 机密不进日志
    // -----------------------------------------------------------------------

    /// `{:?}` 整个 [`AuthConfig`] 不泄漏任何机密。
    ///
    /// 真实的泄漏形态就是有人 `tracing::debug!("{config:?}")`，不是有人单独打印一个 secret。
    #[test]
    fn debugging_the_whole_config_leaks_no_secret() {
        let config = auth_config(&signed_in_env(), PUBLIC, default_session_lifetime())
            .expect("合法")
            .expect("有 provider");
        let printed = format!("{config:?}");
        assert!(!printed.contains("google-client-secret"), "{printed}");
        assert!(
            !printed.contains("a-long-enough-local-development-auth-secret"),
            "{printed}"
        );
        // 正向对照：非机密字段照常可见（client id 会出现在浏览器地址栏里，不是机密），
        // 否则本条在"Debug 什么都不印"的世界里同样通过。
        assert!(printed.contains("google-client-id"), "{printed}");

        let key = KeyEncryptionKey::from_env_map(
            &env(&[("KEY_ENCRYPTION_KEY", EXAMPLE_KEY_ENCRYPTION_KEY)]),
            ExampleKeyPolicy::Allow,
        )
        .expect("合法");
        let printed = format!("{key:?}");
        // 强度可见（它不是秘密，而且排障时最有用），材料不可见。
        assert_eq!(printed, "KeyEncryptionKey(aes_256, [redacted])");
        assert!(printed.contains("redacted"), "{printed}");
        // 负向对照：那把示例密钥解出来是 32 个零字节，它的 base64 前缀不该出现在渲染里。
        assert!(!printed.contains("AAAA"), "{printed}");
    }
}
