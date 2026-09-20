//! 凭据信封、AEAD 与轮换（v3 §6.4）。
//!
//! # 这个模块在整条链路里的位置
//!
//! | 环境 | Master key 在哪 | Record key |
//! | --- | --- | --- |
//! | Desktop | Keychain / Windows Credential Manager / Secret Service | 每记录随机 DEK，由 master key 包装 |
//! | Server | KMS/HSM 或受控 secret manager 中的 tenant KEK | 每记录随机 DEK，由 tenant KEK 包装 |
//!
//! 上表逐字来自 §6.4。**左列全部在 infra**：Keychain、Credential Manager、Secret Service、
//! KMS 都是 I/O。本模块只拿到右列的结果 —— 一段已经在内存里的密钥材料 —— 然后做纯变换。
//!
//! # 领域层的三条硬约束在这里长什么样
//!
//! repository contract §4 与本 crate 的 `lib.rs` 写死了领域层「没有 I/O、没有时钟、没有随机数」。
//! vault 是全仓最容易违反这三条的模块，所以它们在这里是**构造性**的，不是纪律性的：
//!
//! - **没有随机数**：DEK、IV、nonce 全部由调用方传进来（[`aead::seal_v2`] 的签名就是证据），
//!   `getrandom` 不在依赖表里。代价是 nonce 唯一性本模块验证不了，见交付报告。
//! - **没有时钟**：过期判定收一个 `now` 参数（[`metadata::SecretRecord::usability`]），
//!   不调用 `OffsetDateTime::now_utc()`。
//! - **没有 I/O**：迁移状态机（[`rotation`]）只产出**要写什么**，不写；事务边界在
//!   application / infra。
//!
//! # 两代信封，以及为什么迁移顺序不能改
//!
//! §6.4 逐字：「迁移期必须兼容读取当前 AES-GCM v1 envelope（12 字节 IV、无 AAD）。迁移顺序
//! 固定为：读 v1 → 解密 → 事务写 v2 → 校验回读 → 标记旧 envelope retired。不能在同一 release
//! 同时更换 Auth、KEK 和 credential schema。」
//!
//! 这条顺序的每一步都在挡一种具体的数据丢失：
//!
//! 1. **先解密再写**：写不出来还有旧信封在。
//! 2. **事务写 v2**：新密文与"这一行现在是 v2 了"必须同生同死。
//! 3. **校验回读**：证明落库的那份**确实解得开**。少了它，"标记 retired"就是在删掉唯一
//!    一份还读得出来的数据 —— 而回读失败的常见原因（写进了另一个连接的事务、列被截断、
//!    第二个写者）都不会在写入那一刻报错。
//! 4. **最后才 retire**：retire 是唯一不可逆的一步。
//!
//! [`rotation`] 把这条顺序做成类型：`retire_legacy` 这个方法**只存在于**"已校验回读"那个
//! 类型上，跳过第 3 步在编译期就写不出来。
//!
//! # 一份永不外泄的值清单
//!
//! §6.4 点名六类值永不进入 Leptos state、Agent prompt、AG-UI、browser event、普通日志、
//! trace、metric、crash dump 或 screen URL。它们是 [`secret::SecretClass`] 的六个变体，
//! 封装容器是 [`secret::SealedSecret`]。
//!
//! # 上游那条不得照译的缺陷
//!
//! `server/src/credentials.ts::rotateCredential` 先 `persistCredential` 再
//! `store.revoke(previous)`，**两条独立语句不在一个事务里**；中间失败会留下一个孤儿新凭据，
//! 而调用方与审计都会认为轮换成功了。v3 §2.4 把它列为不得照译。
//!
//! 事务边界不归领域层，所以本模块能做的是把「轮换是一次**原子的替换**」变成一个类型：
//! [`rotation::plan_rotation`] 产出的 [`rotation::RotationCommit`] 同时装着"装新的"与
//! "撤旧的"，**没有任何构造器能单独造出其中一半**。调用方仍然可以只写一半 —— 但那需要它
//! 显式地把 `RotationCommit` 拆开，那一行在 review 里是看得见的，而上游那种"两条语句碰巧
//! 没在一个事务里"的形态在这里写不出来。

pub mod aead;
pub mod binding;
pub mod canary;
pub mod derivation;
pub mod envelope;
pub mod error;
pub mod key;
pub mod metadata;
pub mod rotation;
pub mod secret;

pub use aead::{decrypt_v1, open_v2, seal_v2, unwrap_data_key, wrap_data_key};
pub use binding::{KeyVersion, RecordBinding, SecretId, SecretKind, SecretPrincipal, ServiceId};
pub use canary::{
    DesktopVaultCanaryBinding, DesktopVaultCanaryEnvelope, open_desktop_vault_canary,
    seal_desktop_vault_canary,
};
pub use derivation::{ApplicationKeyPurpose, derive_application_key};
pub use envelope::{
    ColumnShape, EnvelopeV1, EnvelopeV2, V1_ENVELOPE_PREFIX, V2_ENVELOPE_PREFIX, classify_column,
};
pub use error::VaultError;
pub use key::{DATA_KEY_BYTES, DataKey, NONCE_BYTES, Nonce, TAG_BYTES, WrappingKey};
pub use metadata::{
    CredentialGeneration, RevocationState, SecretRecord, SecretResource, SecretScope,
    SecretUsability,
};
pub use rotation::{
    MigrationPlan, MigrationStage, MigrationStep, PendingReadBack, RecoveredSecret,
    RetirementOrder, RevocationOrder, RotationCommit, VerifiedMigration, advance, plan_rotation,
};
pub use secret::{SealedSecret, SecretBytes, SecretClass};
