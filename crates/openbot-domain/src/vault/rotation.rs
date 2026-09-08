//! 迁移与轮换的状态机。
//!
//! # 迁移顺序是 §6.4 逐字定死的
//!
//! 「迁移顺序固定为：读 v1 → 解密 → 事务写 v2 → 校验回读 → 标记旧 envelope retired。」
//!
//! 本模块用**两套**表达同时钉住它，因为两套各自能挡住另一套挡不住的东西：
//!
//! | | 挡住什么 | 挡不住什么 |
//! | --- | --- | --- |
//! | 类型状态（[`MigrationPlan`] → … → [`VerifiedMigration`]） | 顺序写错时**编译不过** | 无法被单元测试穷举 —— 编译不过的代码写不进测试里 |
//! | 运行期枚举（[`advance`]） | 可以被穷举测试（5 阶段 × 4 步骤 = 20 种组合逐一断言） | 只有调用它的人才受约束 |
//!
//! 类型状态是主力：`retire_legacy` 这个方法**只存在于** [`VerifiedMigration`] 上，所以
//! "跳过校验回读直接 retire" 不是一次会被拒绝的调用，而是一句**写不出来的代码**。
//! [`advance`] 是同一张迁移图的可穷举投影，用来证明这张图本身是对的。
//!
//! 两套必须一致 —— `type_state_chain_matches_the_runtime_state_machine` 让类型状态的每一步
//! 都顺带跑一次 [`advance`]，两边对不上就红。
//!
//! # 为什么"校验回读"这一步不能省
//!
//! 它是整条链上唯一一次**证明落库的那份确实解得开**的机会。写入成功不代表读得回来：
//! 写进了另一个连接尚未提交的事务、列被截断、第二个写者插了一脚 —— 这三种都不会在写入
//! 那一刻报错，而下一步（retire）是**不可逆**的。少了这一步，"标记 retired" 就是在删掉
//! 唯一一份还读得出来的数据。
//!
//! 比较的是**解出来的明文**而不是列值字节：列值相同证明不了它解得开（密钥可能已经不对了），
//! 而"解得开且明文逐字节相同"蕴含前者的全部价值。比较走 [`super::secret::SecretBytes::ct_eq`]。
//!
//! # 轮换：上游缺陷 #53 在这里被做成写不出来的形状
//!
//! 上游 `server/src/credentials.ts::rotateCredential`：
//!
//! ```text
//! const credential = await persistCredential(service, input);
//! await service.store.revoke(input.previousCredentialId);
//! ```
//!
//! 两条独立语句，不在一个事务里。中间失败会留下一个**孤儿新凭据** —— 新的写进去了，旧的
//! 还活着，而 audit 事件压根没写。v3 §2.4 把它列为不得照译。
//!
//! 事务边界在 application / infra，领域层管不到。本模块能做的是把「轮换是一次**原子的
//! 替换**」变成一个类型：[`plan_rotation`] 只产出 [`RotationCommit`]，而它同时装着"装新的"
//! 与"撤旧的"两半，**没有任何构造器能单独造出其中一半**。想只做一半，调用方必须显式
//! [`RotationCommit::into_parts`] 拆开 —— 那一行在 review 和 grep 里都看得见，而上游那种
//! "两条语句碰巧没在一个事务里"的形态在这里写不出来。

use time::OffsetDateTime;

use super::aead::{decrypt_v1, open_v2, seal_v2};
use super::binding::{KeyVersion, RecordBinding, SecretId};
use super::envelope::{EnvelopeV1, EnvelopeV2};
use super::error::VaultError;
use super::key::{DataKey, Nonce, WrappingKey};
use super::metadata::SecretRecord;
use super::secret::SecretBytes;

// ───────────────────────────── 运行期状态机 ─────────────────────────────

/// 迁移走到了哪一步。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationStage {
    /// 已定位到一条 v1 信封，还没解。
    V1Located,
    /// 已解出明文。
    PlaintextRecovered,
    /// v2 信封已在事务里写下去了。
    V2Persisted,
    /// 已从库里读回来并校验过。
    ReadBackVerified,
    /// 旧信封已标记 retired。终态。
    LegacyRetired,
}

impl MigrationStage {
    /// 全部五个阶段。
    pub const ALL: [Self; 5] = [
        Self::V1Located,
        Self::PlaintextRecovered,
        Self::V2Persisted,
        Self::ReadBackVerified,
        Self::LegacyRetired,
    ];

    /// 稳定标识符。进 [`VaultError::IllegalMigrationStep`] 的载荷与审计。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::V1Located => "v1_located",
            Self::PlaintextRecovered => "plaintext_recovered",
            Self::V2Persisted => "v2_persisted",
            Self::ReadBackVerified => "read_back_verified",
            Self::LegacyRetired => "legacy_retired",
        }
    }
}

/// 迁移的一步动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationStep {
    /// 解 v1 信封。
    Decrypt,
    /// 在事务里写 v2。
    PersistV2,
    /// 从库里读回来校验。
    VerifyReadBack,
    /// 标记旧信封 retired。
    RetireLegacy,
}

impl MigrationStep {
    /// 全部四个步骤。
    pub const ALL: [Self; 4] = [
        Self::Decrypt,
        Self::PersistV2,
        Self::VerifyReadBack,
        Self::RetireLegacy,
    ];

    /// 稳定标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Decrypt => "decrypt",
            Self::PersistV2 => "persist_v2",
            Self::VerifyReadBack => "verify_read_back",
            Self::RetireLegacy => "retire_legacy",
        }
    }
}

/// 迁移图：给定阶段能走哪一步，走完到哪。
///
/// 合法跃迁恰好四条，与 §6.4 那句话的四个箭头一一对应。其余 16 种组合全部返回
/// [`VaultError::IllegalMigrationStep`]。
///
/// # Errors
///
/// 当前阶段不允许该步骤时返回 [`VaultError::IllegalMigrationStep`]，载荷是两个稳定标识符
/// （**我们自己写下的**静态字符串，不是输入数据 —— 见 [`super::error`] 的模块文档）。
pub const fn advance(
    stage: MigrationStage,
    step: MigrationStep,
) -> Result<MigrationStage, VaultError> {
    match (stage, step) {
        (MigrationStage::V1Located, MigrationStep::Decrypt) => {
            Ok(MigrationStage::PlaintextRecovered)
        }
        (MigrationStage::PlaintextRecovered, MigrationStep::PersistV2) => {
            Ok(MigrationStage::V2Persisted)
        }
        (MigrationStage::V2Persisted, MigrationStep::VerifyReadBack) => {
            Ok(MigrationStage::ReadBackVerified)
        }
        (MigrationStage::ReadBackVerified, MigrationStep::RetireLegacy) => {
            Ok(MigrationStage::LegacyRetired)
        }
        _ => Err(VaultError::IllegalMigrationStep {
            from: stage.code(),
            step: step.code(),
        }),
    }
}

// ───────────────────────────── 类型状态链 ─────────────────────────────

/// 第一步：手上有一条 v1 信封和它的目标绑定，还没解。
///
/// # 完整的合法链条长这样
///
/// ```
/// use openbot_contracts::ids::TenantId;
/// use openbot_domain::vault::{
///     DataKey, EnvelopeV1, KeyVersion, MigrationPlan, Nonce, RecordBinding, SecretId,
///     SecretKind, SecretPrincipal, VaultError, WrappingKey,
/// };
///
/// # fn main() -> Result<(), VaultError> {
/// // 上游 server/src/credentials.ts::encryptSecret 产出的一条真信封（密钥第 i 字节 = i）。
/// let column = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
/// let legacy_key = WrappingKey::from_bytes((0u8..32).collect())?;
/// let kek = WrappingKey::from_bytes(vec![0x5A; 32])?;
/// let dek = DataKey::from_bytes(vec![0xA5; 32])?;
/// let binding = RecordBinding::new(
///     TenantId::new("tenant-1"),
///     SecretId::new("secret-1"),
///     SecretKind::Model,
///     SecretPrincipal::Deployment,
///     SecretPrincipal::Deployment,
///     KeyVersion::new(1),
/// );
///
/// // 读 v1 → 解密 → 封 v2
/// let pending = MigrationPlan::begin(binding.clone(), EnvelopeV1::parse(column)?)
///     .recover(&legacy_key)?
///     .seal(&kek, &dek, Nonce::from_array([1; 12]), Nonce::from_array([2; 12]))?;
///
/// // 调用方在事务里把这段字节写下去，再把**从库里读回来的**那段交回来校验。
/// let to_persist = pending.column_value().to_owned();
/// let verified = pending.verify_read_back(&kek, &to_persist)?;
///
/// // 只有走到这里，retire 才存在。
/// let order = verified.retire_legacy();
/// assert_eq!(order.secret_id().as_str(), "secret-1");
/// # Ok(())
/// # }
/// ```
///
/// # 跳过"校验回读"直接 retire：**编译不过**
///
/// 下面这段与上面逐字相同，只有最后一行把 `verify_read_back` 换成直接 `retire_legacy`。
/// `PendingReadBack` 上没有这个方法，所以它连编译都过不去 —— 这不是一次会被拒绝的调用，
/// 是一句写不出来的代码。
///
/// ```compile_fail
/// use openbot_contracts::ids::TenantId;
/// use openbot_domain::vault::{
///     DataKey, EnvelopeV1, KeyVersion, MigrationPlan, Nonce, RecordBinding, SecretId,
///     SecretKind, SecretPrincipal, VaultError, WrappingKey,
/// };
///
/// # fn main() -> Result<(), VaultError> {
/// let column = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
/// let legacy_key = WrappingKey::from_bytes((0u8..32).collect())?;
/// let kek = WrappingKey::from_bytes(vec![0x5A; 32])?;
/// let dek = DataKey::from_bytes(vec![0xA5; 32])?;
/// let binding = RecordBinding::new(
///     TenantId::new("tenant-1"),
///     SecretId::new("secret-1"),
///     SecretKind::Model,
///     SecretPrincipal::Deployment,
///     SecretPrincipal::Deployment,
///     KeyVersion::new(1),
/// );
///
/// let pending = MigrationPlan::begin(binding.clone(), EnvelopeV1::parse(column)?)
///     .recover(&legacy_key)?
///     .seal(&kek, &dek, Nonce::from_array([1; 12]), Nonce::from_array([2; 12]))?;
///
/// // ↓ 没有这个方法。
/// let order = pending.retire_legacy();
/// # Ok(())
/// # }
/// ```
///
/// # 凭空造一个"已校验"：**编译不过**
///
/// [`VerifiedMigration`] 的字段是私有的，唯一的产出点是
/// [`PendingReadBack::verify_read_back`]。
///
/// ```compile_fail
/// use openbot_domain::vault::{KeyVersion, SecretId, VerifiedMigration};
///
/// let forged = VerifiedMigration {
///     secret_id: SecretId::new("secret-1"),
///     key_version: KeyVersion::new(1),
/// };
/// ```
#[derive(Debug)]
pub struct MigrationPlan {
    binding: RecordBinding,
    legacy: EnvelopeV1,
}

impl MigrationPlan {
    /// 起手：一条 v1 信封 + 它迁过去之后应有的绑定。
    ///
    /// binding 在**这里**就要定下来，而不是等到 [`RecoveredSecret::seal`]：绑定里的
    /// owner / consumer 决定了迁完之后谁能读这条记录，那是一个必须在解密之前就想清楚的问题。
    #[must_use]
    pub const fn begin(binding: RecordBinding, legacy: EnvelopeV1) -> Self {
        Self { binding, legacy }
    }

    /// 目标绑定。
    #[must_use]
    pub const fn binding(&self) -> &RecordBinding {
        &self.binding
    }

    /// 第一步：用旧的 `KEY_ENCRYPTION_KEY` 解开 v1 信封。
    ///
    /// # Errors
    ///
    /// [`VaultError::Decrypt`] —— 旧密钥不对，或这一行被改过。此时**什么都还没写**，
    /// 旧信封原封不动，这正是"先解密再写"的价值。
    pub fn recover(self, legacy_key: &WrappingKey) -> Result<RecoveredSecret, VaultError> {
        let plaintext = decrypt_v1(legacy_key, &self.legacy)?;
        Ok(RecoveredSecret {
            binding: self.binding,
            plaintext,
        })
    }
}

/// 第二步：明文已在手上，还没封成 v2。
///
/// 这个类型**持有明文**，所以它没有 `Debug` 之外的任何输出通道，而 `Debug` 只打占位
/// （[`SecretBytes`] 自己的 `Debug` 就是占位）。
#[derive(Debug)]
pub struct RecoveredSecret {
    binding: RecordBinding,
    plaintext: SecretBytes,
}

impl RecoveredSecret {
    /// 目标绑定。
    #[must_use]
    pub const fn binding(&self) -> &RecordBinding {
        &self.binding
    }

    /// 明文长度。用于日志与校验 —— 长度不是秘密（[`SecretBytes::len`]）。
    #[must_use]
    pub fn plaintext_len(&self) -> usize {
        self.plaintext.len()
    }

    /// 第二步：封成 v2。
    ///
    /// DEK 与两个 nonce 由 infra 铸好传进来（领域层不生成随机数）。
    ///
    /// # Errors
    ///
    /// 见 [`seal_v2`]。
    pub fn seal(
        self,
        kek: &WrappingKey,
        dek: &DataKey,
        dek_nonce: Nonce,
        record_nonce: Nonce,
    ) -> Result<PendingReadBack, VaultError> {
        let envelope = seal_v2(
            kek,
            dek,
            &self.binding,
            dek_nonce,
            record_nonce,
            self.plaintext.expose(),
        )?;
        Ok(PendingReadBack {
            column_value: envelope.to_column_value(),
            binding: self.binding,
            plaintext: self.plaintext,
        })
    }
}

/// 第三步：v2 已经封好，等着被写进事务、再读回来校验。
///
/// 这个类型**故意**同时持有明文与要写的列值：校验回读需要拿"写下去之前的明文"与"从库里
/// 读回来解出的明文"逐字节比。把明文在这一步丢掉，就只剩"列值一样"可比 —— 而那证明不了
/// 它解得开。
#[derive(Debug)]
pub struct PendingReadBack {
    binding: RecordBinding,
    plaintext: SecretBytes,
    column_value: String,
}

impl PendingReadBack {
    /// 要写进 `encrypted_value` 列的那段字节。
    ///
    /// 调用方负责把它写进**一个事务**（§6.4：「事务写 v2」）。事务边界不在领域层。
    #[must_use]
    pub fn column_value(&self) -> &str {
        &self.column_value
    }

    /// 目标绑定。
    #[must_use]
    pub const fn binding(&self) -> &RecordBinding {
        &self.binding
    }

    /// 第三步：校验回读。
    ///
    /// `persisted` 必须是**从数据库里重新读出来的**那一段，不是调用方手上的副本 —— 用副本
    /// 校验等于什么都没校验。这一点类型系统强制不了（两者都是 `&str`），所以它写在这里，
    /// 并且是本模块唯一一条靠文档而不是靠类型维持的约束，已记进交付报告。
    ///
    /// # Errors
    ///
    /// - 解析 / 解密类错误：见 [`EnvelopeV2::parse`] 与 [`open_v2`]。
    /// - [`VaultError::ReadBackMismatch`]：解出来了，但明文与写下去之前的不一致。这永远
    ///   意味着**停下** —— 继续走到 retire 会造成不可逆的数据丢失。
    pub fn verify_read_back(
        self,
        kek: &WrappingKey,
        persisted: &str,
    ) -> Result<VerifiedMigration, VaultError> {
        let envelope = EnvelopeV2::parse(persisted)?;
        let recovered = open_v2(kek, &self.binding, &envelope)?;
        if !recovered.ct_eq(&self.plaintext) {
            return Err(VaultError::ReadBackMismatch);
        }
        Ok(VerifiedMigration {
            secret_id: self.binding.secret_id().clone(),
            key_version: self.binding.key_version(),
        })
    }
}

/// 第四步：已校验回读。**只有这个类型上有 [`Self::retire_legacy`]。**
///
/// 字段私有且没有公开构造器 —— 唯一的产出点是 [`PendingReadBack::verify_read_back`]。
/// 这就是"在没校验时就标记 retired"写不出来的原因。
///
/// 它**不再持有明文**：走到这一步明文的使命已经完成，继续带着它只是延长一段不必要的
/// 驻留时间（[`SecretBytes`] 在上一步被 drop 时已经由 `zeroize` 清除当前 allocation）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMigration {
    secret_id: SecretId,
    key_version: KeyVersion,
}

impl VerifiedMigration {
    /// 被迁移的记录。
    #[must_use]
    pub const fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    /// 迁到了哪一代 KEK。
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    /// 第四步：产出"把旧信封标记 retired"这道指令。
    ///
    /// 返回的是一个**待执行的指令**而不是一次执行 —— 落盘归 infra。
    #[must_use]
    pub fn retire_legacy(self) -> RetirementOrder {
        RetirementOrder {
            secret_id: self.secret_id,
            key_version: self.key_version,
        }
    }
}

/// "把这条记录的旧 v1 信封标记 retired" 这道指令。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementOrder {
    secret_id: SecretId,
    key_version: KeyVersion,
}

impl RetirementOrder {
    /// 哪条记录。
    #[must_use]
    pub const fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    /// 迁到了哪一代 KEK。写进审计，好让"这一行是什么时候、迁到哪一代的"可回答。
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }
}

// ───────────────────────────── 轮换 ─────────────────────────────

/// "撤销这条记录" 这道指令。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationOrder {
    secret_id: SecretId,
    at: OffsetDateTime,
}

impl RevocationOrder {
    /// 撤哪一条。
    #[must_use]
    pub const fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    /// 撤销时刻。由调用方传入 —— 领域层不读时钟。
    #[must_use]
    pub const fn at(&self) -> OffsetDateTime {
        self.at
    }
}

/// 一次轮换的**不可分割**结果：装新的 + 撤旧的。
///
/// 上游把这两件事写成了两条独立语句（模块文档），于是"只做了一半"是一个正常程序状态。
/// 这里它不是：本类型没有公开字段，也没有任何构造器能单独造出其中一半 ——
/// [`plan_rotation`] 是唯一入口，它要么两半都给，要么什么都不给。
///
/// 领域层**不能**强制调用方把两半写进同一个事务（事务边界在 infra）。它能做的是让
/// "只写一半" 需要一次显式的 [`Self::into_parts`]，而那一行在 review 里看得见。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationCommit {
    install: SecretRecord,
    revoke: RevocationOrder,
}

impl RotationCommit {
    /// 要装进去的新记录。
    #[must_use]
    pub const fn install(&self) -> &SecretRecord {
        &self.install
    }

    /// 要撤掉的旧记录。
    #[must_use]
    pub const fn revoke(&self) -> &RevocationOrder {
        &self.revoke
    }

    /// 拆成两半。
    ///
    /// 名字刻意难听：它是**唯一**能把这两件事分开的入口，调用点应当就在事务里，而且
    /// 拆开之后两半必须都被写。grep `into_parts` 就能列出全部可疑位置。
    #[must_use]
    pub fn into_parts(self) -> (SecretRecord, RevocationOrder) {
        (self.install, self.revoke)
    }
}

/// 规划一次轮换。
///
/// # 三条前置校验，各挡一种"看起来成功了"的空操作
///
/// 1. **新旧不能是同一条 id**（[`VaultError::RotationTargetsItself`]）：否则后续会展开成
///    "撤销刚刚写进去的那一条"，即上游缺陷 #53 的另一种形态 —— 而且它一定会被当成成功。
/// 2. **旧记录不能已经处于撤销态**（[`VaultError::RotationPreviousAlreadyRevoked`]）：
///    允许它会让同一条旧记录被撤销两次，第二次覆盖第一次的撤销时刻，于是"它什么时候
///    失效的"这个审计问题就答不出来了。
/// 3. **generation 必须严格前进**（[`VaultError::RotationGenerationNotAdvanced`]）：
///    generation 不前进的"轮换"没有把任何旧凭据挤下去（§9.2 的连接身份靠它判 stale），
///    可调用方与审计都会记成一次成功轮换。
///
/// # Errors
///
/// 见上。
pub fn plan_rotation(
    previous: &SecretRecord,
    replacement: SecretRecord,
    at: OffsetDateTime,
) -> Result<RotationCommit, VaultError> {
    if previous.id == replacement.id {
        return Err(VaultError::RotationTargetsItself);
    }
    if previous.revocation.is_revoked() {
        return Err(VaultError::RotationPreviousAlreadyRevoked);
    }
    if replacement.generation <= previous.generation {
        return Err(VaultError::RotationGenerationNotAdvanced);
    }
    Ok(RotationCommit {
        revoke: RevocationOrder {
            secret_id: previous.id.clone(),
            at,
        },
        install: replacement,
    })
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::TenantId;
    use time::Duration;

    use super::super::binding::{SecretKind, SecretPrincipal};
    use super::super::key::{DATA_KEY_BYTES, NONCE_BYTES};
    use super::super::metadata::{
        CredentialGeneration, RevocationState, SecretResource, SecretScope,
    };
    use super::super::secret::SecretClass;
    use super::*;

    /// 上游 `encryptSecret` 产出的真信封（AES-256，密钥第 i 字节 = i，明文
    /// `sk-test-model-key-0001`）。生成方式见 `vault::aead` 的测试模块。
    const UPSTREAM_V1: &str = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
    const UPSTREAM_PLAINTEXT: &[u8] = b"sk-test-model-key-0001";

    fn legacy_key() -> WrappingKey {
        WrappingKey::from_bytes((0u8..32).collect()).expect("32 字节")
    }

    fn kek() -> WrappingKey {
        WrappingKey::from_bytes(vec![0x5Au8; 32]).expect("32 字节")
    }

    fn dek() -> DataKey {
        DataKey::from_bytes(vec![0xA5u8; DATA_KEY_BYTES]).expect("32 字节")
    }

    fn binding() -> RecordBinding {
        RecordBinding::new(
            TenantId::new("tenant-1"),
            SecretId::new("secret-1"),
            SecretKind::Model,
            SecretPrincipal::Deployment,
            SecretPrincipal::Deployment,
            KeyVersion::new(1),
        )
    }

    fn plan() -> MigrationPlan {
        MigrationPlan::begin(binding(), EnvelopeV1::parse(UPSTREAM_V1).expect("解析"))
    }

    /// 走完整条合法链条：读 v1 → 解密 → 写 v2 → 校验回读 → retire。
    ///
    /// 这是下面所有"必须失败"的正向对照。没有它，那些断言在"每一步都恒失败"的世界里
    /// 同样全绿。
    #[test]
    fn the_legal_chain_runs_end_to_end() {
        let recovered = plan().recover(&legacy_key()).expect("解 v1");
        assert_eq!(recovered.plaintext_len(), UPSTREAM_PLAINTEXT.len());

        let pending = recovered
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");

        // 模拟：调用方把这段写进事务，然后**重新读出来**。
        let persisted = pending.column_value().to_owned();
        let verified = pending
            .verify_read_back(&kek(), &persisted)
            .expect("校验回读");
        assert_eq!(verified.secret_id().as_str(), "secret-1");
        assert_eq!(verified.key_version(), KeyVersion::new(1));

        let order = verified.retire_legacy();
        assert_eq!(order.secret_id().as_str(), "secret-1");
        assert_eq!(order.key_version(), KeyVersion::new(1));
    }

    /// 迁完之后 v2 里躺的确实是上游那段明文 —— 迁移没有把内容换掉。
    #[test]
    fn migration_preserves_the_upstream_plaintext_byte_for_byte() {
        let pending = plan()
            .recover(&legacy_key())
            .expect("解 v1")
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");

        let envelope = EnvelopeV2::parse(pending.column_value()).expect("解析");
        let recovered = open_v2(&kek(), &binding(), &envelope).expect("解 v2");
        assert_eq!(recovered.expose(), UPSTREAM_PLAINTEXT);
    }

    /// 校验回读拿到的是**别的内容**时必须拒绝，而且是一条专门的错误码。
    #[test]
    fn read_back_rejects_a_row_that_holds_something_else() {
        let pending = plan()
            .recover(&legacy_key())
            .expect("解 v1")
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");

        // 库里躺的是另一条内容不同、但绑定与密钥都对的合法 v2 记录
        //（形态对应"第二个写者插了一脚"）。
        let intruder = seal_v2(
            &kek(),
            &dek(),
            &binding(),
            Nonce::from_array([9u8; NONCE_BYTES]),
            Nonce::from_array([8u8; NONCE_BYTES]),
            b"somebody-elses-value",
        )
        .expect("封装")
        .to_column_value();

        assert_eq!(
            pending.verify_read_back(&kek(), &intruder).unwrap_err(),
            VaultError::ReadBackMismatch,
            "解得开但内容不对 —— 必须停下，绝不能走到 retire"
        );
    }

    /// 校验回读读到的还是**旧的 v1 行**（写入其实没落库）时必须拒绝。
    #[test]
    fn read_back_rejects_a_row_that_is_still_v1() {
        let pending = plan()
            .recover(&legacy_key())
            .expect("解 v1")
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");

        assert_eq!(
            pending.verify_read_back(&kek(), UPSTREAM_V1).unwrap_err(),
            VaultError::EnvelopeVersionUnsupported,
            "写入没落库时读回来的还是 v1，必须当场判红"
        );
    }

    /// 用错的 KEK 校验回读也必须拒绝 —— 它模拟"写进去的那份根本解不开"。
    #[test]
    fn read_back_rejects_when_the_persisted_row_cannot_be_opened() {
        let pending = plan()
            .recover(&legacy_key())
            .expect("解 v1")
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");

        let persisted = pending.column_value().to_owned();
        let wrong_kek = WrappingKey::from_bytes(vec![0x5Bu8; 32]).expect("32 字节");
        assert_eq!(
            pending
                .verify_read_back(&wrong_kek, &persisted)
                .unwrap_err(),
            VaultError::Decrypt
        );
    }

    /// 用错的旧密钥解 v1 时，**什么都还没写** —— 链条停在第一步。
    #[test]
    fn a_wrong_legacy_key_stops_the_chain_before_anything_is_written() {
        let mut wrong = (0u8..32).collect::<Vec<u8>>();
        wrong[0] ^= 0x01;
        let wrong_key = WrappingKey::from_bytes(wrong).expect("32 字节");
        assert_eq!(plan().recover(&wrong_key).unwrap_err(), VaultError::Decrypt);
    }

    /// 运行期状态机：5 × 4 = 20 种组合逐一断言，合法的恰好 4 条。
    ///
    /// 这是类型状态**无法**被单元测试覆盖的那一半 —— 非法跃迁在类型层面编译不过，
    /// 所以写不进测试；这里用同一张图的运行期投影把它们全部走一遍。
    #[test]
    fn every_illegal_transition_is_rejected() {
        let legal = [
            (
                MigrationStage::V1Located,
                MigrationStep::Decrypt,
                MigrationStage::PlaintextRecovered,
            ),
            (
                MigrationStage::PlaintextRecovered,
                MigrationStep::PersistV2,
                MigrationStage::V2Persisted,
            ),
            (
                MigrationStage::V2Persisted,
                MigrationStep::VerifyReadBack,
                MigrationStage::ReadBackVerified,
            ),
            (
                MigrationStage::ReadBackVerified,
                MigrationStep::RetireLegacy,
                MigrationStage::LegacyRetired,
            ),
        ];

        let mut legal_hits = 0usize;
        for stage in MigrationStage::ALL {
            for step in MigrationStep::ALL {
                let expected = legal
                    .iter()
                    .find(|(from, action, _)| *from == stage && *action == step)
                    .map(|(_, _, to)| *to);
                match (advance(stage, step), expected) {
                    (Ok(actual), Some(want)) => {
                        assert_eq!(actual, want, "{} + {}", stage.code(), step.code());
                        legal_hits += 1;
                    }
                    (Err(error), None) => assert_eq!(
                        error,
                        VaultError::IllegalMigrationStep {
                            from: stage.code(),
                            step: step.code(),
                        },
                        "{} + {} 必须被拒并点名两端",
                        stage.code(),
                        step.code()
                    ),
                    (Ok(_), None) => panic!("{} + {} 本该被拒", stage.code(), step.code()),
                    (Err(error), Some(_)) => panic!(
                        "{} + {} 本该合法，却报 {}",
                        stage.code(),
                        step.code(),
                        error.code()
                    ),
                }
            }
        }
        assert_eq!(legal_hits, 4, "§6.4 那句话恰好四个箭头");
        assert_eq!(MigrationStage::ALL.len() * MigrationStep::ALL.len(), 20);
    }

    /// §6.4 点名的两条非法迁移各来一次，写成人话。
    #[test]
    fn the_two_forbidden_shortcuts_are_rejected_by_name() {
        // 「跳过校验回读」：写完 v2 直接 retire。
        assert_eq!(
            advance(MigrationStage::V2Persisted, MigrationStep::RetireLegacy).unwrap_err(),
            VaultError::IllegalMigrationStep {
                from: "v2_persisted",
                step: "retire_legacy",
            }
        );
        // 「在没校验时就标记 retired」：连 v2 都还没写。
        assert_eq!(
            advance(
                MigrationStage::PlaintextRecovered,
                MigrationStep::RetireLegacy
            )
            .unwrap_err(),
            VaultError::IllegalMigrationStep {
                from: "plaintext_recovered",
                step: "retire_legacy",
            }
        );
        // 正向对照：先校验再 retire 是合法的。
        assert_eq!(
            advance(
                MigrationStage::ReadBackVerified,
                MigrationStep::RetireLegacy
            ),
            Ok(MigrationStage::LegacyRetired)
        );
    }

    /// 类型状态链走过的每一步，在运行期状态机里都是一条合法跃迁。
    ///
    /// 两套表达必须描述**同一张图**。少了这条，它们可以各自正确却互相矛盾 ——
    /// 那正是"同一判据两份实现"的经典失效模式。
    #[test]
    fn type_state_chain_matches_the_runtime_state_machine() {
        let mut stage = MigrationStage::V1Located;

        let recovered = plan().recover(&legacy_key()).expect("解 v1");
        stage = advance(stage, MigrationStep::Decrypt).expect("解密是合法的第一步");
        assert_eq!(stage, MigrationStage::PlaintextRecovered);

        let pending = recovered
            .seal(
                &kek(),
                &dek(),
                Nonce::from_array([1u8; NONCE_BYTES]),
                Nonce::from_array([2u8; NONCE_BYTES]),
            )
            .expect("封 v2");
        stage = advance(stage, MigrationStep::PersistV2).expect("写 v2 是合法的第二步");
        assert_eq!(stage, MigrationStage::V2Persisted);

        let persisted = pending.column_value().to_owned();
        let verified = pending
            .verify_read_back(&kek(), &persisted)
            .expect("校验回读");
        stage = advance(stage, MigrationStep::VerifyReadBack).expect("校验是合法的第三步");
        assert_eq!(stage, MigrationStage::ReadBackVerified);

        let _order = verified.retire_legacy();
        stage = advance(stage, MigrationStep::RetireLegacy).expect("retire 是合法的第四步");
        assert_eq!(stage, MigrationStage::LegacyRetired);
    }

    // ───────────────────────────── 轮换 ─────────────────────────────

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    fn record(id: &str, generation: u64) -> SecretRecord {
        SecretRecord {
            id: SecretId::new(id),
            kind: SecretKind::Model,
            class: SecretClass::ModelKey,
            resource: SecretResource::new("https://api.example.invalid/v1"),
            scope: SecretScope::granted("read"),
            owner: SecretPrincipal::Deployment,
            consumer: SecretPrincipal::Deployment,
            generation: CredentialGeneration::new(generation),
            expires_at: None,
            revocation: RevocationState::Active,
        }
    }

    /// 正向对照：一次正常轮换同时给出"装新的"与"撤旧的"。
    #[test]
    fn a_valid_rotation_yields_both_halves() {
        let previous = record("secret-old", 4);
        let commit = plan_rotation(&previous, record("secret-new", 5), now()).expect("轮换");

        assert_eq!(commit.install().id.as_str(), "secret-new");
        assert_eq!(commit.revoke().secret_id().as_str(), "secret-old");
        assert_eq!(commit.revoke().at(), now());

        let (install, revoke) = commit.into_parts();
        assert_eq!(install.generation, CredentialGeneration::new(5));
        assert_eq!(revoke.secret_id().as_str(), "secret-old");
    }

    /// 三条前置校验各拒一次，错误码互不相同。
    #[test]
    fn rotation_refuses_the_three_no_op_shapes() {
        // 1. 新旧同一条 id —— 上游缺陷 #53 的另一种形态。
        let same = record("secret-1", 4);
        let mut bumped = record("secret-1", 5);
        bumped.generation = CredentialGeneration::new(5);
        assert_eq!(
            plan_rotation(&same, bumped, now()).unwrap_err(),
            VaultError::RotationTargetsItself
        );

        // 2. 旧记录已经撤过了。
        let mut revoked = record("secret-old", 4);
        revoked.revocation = RevocationState::Revoked { at: now() };
        assert_eq!(
            plan_rotation(&revoked, record("secret-new", 5), now()).unwrap_err(),
            VaultError::RotationPreviousAlreadyRevoked
        );

        // 3. generation 没前进（相等与倒退各一次）。
        assert_eq!(
            plan_rotation(&record("secret-old", 5), record("secret-new", 5), now()).unwrap_err(),
            VaultError::RotationGenerationNotAdvanced
        );
        assert_eq!(
            plan_rotation(&record("secret-old", 5), record("secret-new", 4), now()).unwrap_err(),
            VaultError::RotationGenerationNotAdvanced
        );

        // 三个错误码两两不同 —— 压成一个，运维就分不出该做什么。
        let mut codes = [
            VaultError::RotationTargetsItself.code(),
            VaultError::RotationPreviousAlreadyRevoked.code(),
            VaultError::RotationGenerationNotAdvanced.code(),
        ];
        codes.sort_unstable();
        let mut deduped = codes.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), 3);
    }

    /// 校验顺序：id 相同这条最先判。
    ///
    /// 一条"自己轮换自己"的请求同时满足另外两条（generation 不前进）；先报哪一条决定了
    /// 运维看到的是"你搞错对象了"还是"你忘了升代际"。前者才是真问题。
    #[test]
    fn self_targeting_is_reported_before_the_generation_check() {
        let previous = record("secret-1", 5);
        assert_eq!(
            plan_rotation(&previous, record("secret-1", 5), now()).unwrap_err(),
            VaultError::RotationTargetsItself
        );
    }
}
