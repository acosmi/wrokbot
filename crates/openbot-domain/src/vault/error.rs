//! [`VaultError`] —— vault 的**封闭**失败分类，且**永不携带被检查对象的数据**。
//!
//! # 为什么错误里一个字节的数据都不能带
//!
//! 这一条与 [`crate::policy::cel::CelFailure`] 同源，但在 vault 里更硬：CEL 那边泄漏的是策略
//! context，vault 这边一旦带值，泄漏的就是密文、IV、密钥长度之外的密钥材料，或者更糟 ——
//! 解到一半的明文。而错误对象天然会流向日志、审计、HTTP 响应体和 GUI，正是 v3 §6.4 那份
//! 「永不进入普通日志 / trace / metric / crash dump」清单点名的四个去处。
//!
//! 所以本模块的规矩是构造性的，不是纪律性的：
//!
//! - 变体只允许携带 `&'static str`（**我们自己**写下的阶段名、步骤名），不允许 `String`、
//!   `Vec<u8>`、`usize` 之类由输入决定的载荷；
//! - 于是整个枚举是 `Copy`，测试 [`tests::error_is_copy_so_it_cannot_carry_owned_data`] 把这条
//!   钉成编译期事实 —— 想加一个 `String` 字段的人会先撞上 `Copy` 编译失败。
//!
//! 代价是排障时少了几个数字（例如"你给的 IV 是 11 字节"）。这笔账是划算的：长度类信息可以
//! 从变体名本身读出来（[`VaultError::LegacyIvLength`] 就是"IV 长度不对"），而具体取值对运维
//! 没有增量价值 —— 那一行数据本来就在数据库里躺着，运维查得到。
//!
//! # 为什么解密失败只有一个变体
//!
//! [`VaultError::Decrypt`] 不区分「密钥不对」「AAD 不对」「密文被改过」。这不是偷懒：
//! **AES-GCM 本身就分不出来**，三种情形走到的是同一次 tag 校验失败。造三个变体出来，就是
//! 让类型系统撒一个实现兑现不了的谎，而下游一定会有人按那个谎写分支。
//!
//! 唯一的例外是 [`VaultError::KeyVersionMismatch`]：它在做任何密码学运算**之前**由一次明文
//! 比较判定（见 [`super::aead::open_v2`]），确实可分辨，所以它有资格单列。

/// vault 的封闭失败分类。
///
/// 每个变体只携带**我们自己写下的静态字符串**，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum VaultError {
    /// v1 信封的结构非法：不是 JSON、`version` 不是整数 1、`iv` / `ciphertext` 不是字符串，
    /// 或 base64 解不开。
    ///
    /// 对应上游 `server/src/credentials.ts::parseEnvelope` 抛出的
    /// `"Credential envelope is invalid"` —— 上游把 `JSON.parse` 失败与字段校验失败塞进同一个
    /// `try` / `catch`，压成同一条消息，本变体照搬这条合并（合并本身没有害处：两种情形的运维
    /// 动作相同，都是"这一行读不出来"）。
    #[error("vault_envelope_invalid")]
    EnvelopeInvalid,

    /// 列值看起来是信封，但版本号既不是 1 也不是 2。
    ///
    /// 与 [`Self::EnvelopeInvalid`] 分开，因为运维动作不同：前者是数据坏了，本变体是**这个
    /// 二进制太旧**，读不了一个更新的信封版本。fail-closed 的方向是拒绝，绝不能"当成认识的
    /// 那个版本试试看"。
    #[error("vault_envelope_version_unsupported")]
    EnvelopeVersionUnsupported,

    /// v1 信封的 IV 不是 [`super::key::NONCE_BYTES`] 字节。
    ///
    /// 上游**不做**这项检查（WebCrypto 的 AES-GCM 接受任意长度 IV），本项目做。理由与实证
    /// 见 [`super::envelope::EnvelopeV1::parse`]。
    #[error("vault_legacy_iv_length")]
    LegacyIvLength,

    /// 密文短于 AES-GCM 的 tag 长度，不可能是一段合法密文。
    ///
    /// `aes-gcm` 自己也会拒，但它给的是与"密钥错"同一个 `Error`。单列出来，是因为这一条是
    /// **结构性**的：它在任何密钥下都为真，所以换密钥重试没有意义 —— 运维需要看得出这一点。
    #[error("vault_ciphertext_too_short")]
    CiphertextTooShort,

    /// 包装密钥（master key / tenant KEK / 上游的 `KEY_ENCRYPTION_KEY`）长度不是
    /// AES 认识的 16 / 24 / 32 字节。
    ///
    /// 三档都接受的理由（以及"为什么不是只接受 32"）见 [`super::key::WrappingKey::from_bytes`]。
    #[error("vault_key_length")]
    KeyLength,

    /// nonce 不是 [`super::key::NONCE_BYTES`] 字节。
    #[error("vault_nonce_length")]
    NonceLength,

    /// 每记录 DEK 不是 [`super::key::DATA_KEY_BYTES`] 字节。
    ///
    /// 与 [`Self::KeyLength`] 分开：包装密钥是**别人给的**（env / KMS / Keychain），长度三档
    /// 都得认；DEK 是**我们自己铸的**，只有一个合法长度，出现别的长度说明铸造侧坏了。
    #[error("vault_data_key_length")]
    DataKeyLength,

    /// 信封自述的 `key_version` 与调用方 binding 里的不一致。
    ///
    /// 见 [`super::aead::open_v2`]：进 AAD 的 `key_version` 必须来自**调用方**，密文不许自述
    /// 身份。本变体就是那道检查的拒绝出口。
    #[error("vault_key_version_mismatch")]
    KeyVersionMismatch,

    /// AEAD 认证失败。密钥错、AAD 错、密文被改过 —— 三者不可分辨，理由见模块文档。
    #[error("vault_decrypt_failed")]
    Decrypt,

    /// 明文超出 AES-GCM 单条消息的上限。
    ///
    /// GCM 的计数器只有 32 bit，单条消息最多 `2^39 - 256` bit（约 64 GiB）。这是**加密**
    /// 侧唯一现实存在的失败模式；单列出来是因为它与 [`Self::Decrypt`] 的运维动作完全不同 ——
    /// 它说的是"这个值本来就不该走 vault"，重试多少次都一样。
    #[error("vault_plaintext_too_large")]
    PlaintextTooLarge,

    /// 迁移的「校验回读」这一步：从库里读回来的东西解出的明文与写下去之前的不一致。
    ///
    /// 这一条永远意味着**停下**：它要么说明写入没落库（读到的是旧行），要么说明有第二个写者。
    /// 两种情形下继续走到"标记旧信封 retired"都会造成不可逆的数据丢失。
    #[error("vault_read_back_mismatch")]
    ReadBackMismatch,

    /// 迁移状态机收到一个当前阶段不允许的步骤。
    ///
    /// 两个载荷都是**本模块自己写下的**静态阶段名 / 步骤名（见 [`super::rotation`]），不是
    /// 输入数据 —— 这是模块文档那条"只允许 `&'static str`"的唯一用法。
    #[error("vault_illegal_migration_step")]
    IllegalMigrationStep {
        /// 当前阶段的稳定名。
        from: &'static str,
        /// 被拒绝的步骤的稳定名。
        step: &'static str,
    },

    /// 轮换的新记录 generation 没有严格大于旧记录。
    ///
    /// 见 [`super::rotation::plan_rotation`]：generation 不前进的"轮换"没有把任何旧凭据挤下去，
    /// 而调用方与审计都会把它当成一次成功轮换 —— 那是一个**看起来完成了**的空操作。
    #[error("vault_rotation_generation_not_advanced")]
    RotationGenerationNotAdvanced,

    /// 被轮换的旧记录已经处于撤销态。
    ///
    /// 允许它会让同一条旧记录被撤销两次，第二次覆盖第一次的撤销时刻 —— 审计上"它什么时候
    /// 失效的"这个问题就答不出来了。
    #[error("vault_rotation_previous_already_revoked")]
    RotationPreviousAlreadyRevoked,

    /// 轮换的新旧记录是同一个 id。
    ///
    /// 它会被后续步骤展开成"撤销刚刚写进去的那一条"，即上游缺陷 #53 的另一种形态。
    #[error("vault_rotation_targets_itself")]
    RotationTargetsItself,
}

impl VaultError {
    /// 稳定的分类标识符，进审计与日志用。
    ///
    /// 它是**标识符**不是文案：不随 locale 变化（repository contract §4a「文案不进 domain」）。
    /// 与 `Display` 逐字相同，由 [`tests::display_and_code_agree`] 钉住。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EnvelopeInvalid => "vault_envelope_invalid",
            Self::EnvelopeVersionUnsupported => "vault_envelope_version_unsupported",
            Self::LegacyIvLength => "vault_legacy_iv_length",
            Self::CiphertextTooShort => "vault_ciphertext_too_short",
            Self::KeyLength => "vault_key_length",
            Self::NonceLength => "vault_nonce_length",
            Self::DataKeyLength => "vault_data_key_length",
            Self::KeyVersionMismatch => "vault_key_version_mismatch",
            Self::Decrypt => "vault_decrypt_failed",
            Self::PlaintextTooLarge => "vault_plaintext_too_large",
            Self::ReadBackMismatch => "vault_read_back_mismatch",
            Self::IllegalMigrationStep { .. } => "vault_illegal_migration_step",
            Self::RotationGenerationNotAdvanced => "vault_rotation_generation_not_advanced",
            Self::RotationPreviousAlreadyRevoked => "vault_rotation_previous_already_revoked",
            Self::RotationTargetsItself => "vault_rotation_targets_itself",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部变体，供两条机械核对使用。加了变体忘了加进来，下面的 `code()` `match` 也不会红 ——
    /// 所以这张表由 `all_variants_are_listed` 用一次穷举 `match` 反向钉住。
    fn all() -> Vec<VaultError> {
        vec![
            VaultError::EnvelopeInvalid,
            VaultError::EnvelopeVersionUnsupported,
            VaultError::LegacyIvLength,
            VaultError::CiphertextTooShort,
            VaultError::KeyLength,
            VaultError::NonceLength,
            VaultError::DataKeyLength,
            VaultError::KeyVersionMismatch,
            VaultError::Decrypt,
            VaultError::PlaintextTooLarge,
            VaultError::ReadBackMismatch,
            VaultError::IllegalMigrationStep {
                from: "from",
                step: "step",
            },
            VaultError::RotationGenerationNotAdvanced,
            VaultError::RotationPreviousAlreadyRevoked,
            VaultError::RotationTargetsItself,
        ]
    }

    /// 变体总数。与 [`variant_index`] 的最大返回值 + 1 相等，由 [`all_lists_every_variant_exactly_once`] 钉住。
    const VARIANT_COUNT: usize = 15;

    /// 每个变体一个稳定下标。**穷举 `match`**：新增变体不改这里就编译不过。
    const fn variant_index(error: VaultError) -> usize {
        match error {
            VaultError::EnvelopeInvalid => 0,
            VaultError::EnvelopeVersionUnsupported => 1,
            VaultError::LegacyIvLength => 2,
            VaultError::CiphertextTooShort => 3,
            VaultError::KeyLength => 4,
            VaultError::NonceLength => 5,
            VaultError::DataKeyLength => 6,
            VaultError::KeyVersionMismatch => 7,
            VaultError::Decrypt => 8,
            VaultError::PlaintextTooLarge => 9,
            VaultError::ReadBackMismatch => 10,
            VaultError::IllegalMigrationStep { .. } => 11,
            VaultError::RotationGenerationNotAdvanced => 12,
            VaultError::RotationPreviousAlreadyRevoked => 13,
            VaultError::RotationTargetsItself => 14,
        }
    }

    /// [`all`] 覆盖每个变体恰好一次。
    ///
    /// 这是把"[`all`] 是一份会悄悄过时的手抄件"这个风险关掉的那道闸：新增第 15 个变体时，
    /// [`variant_index`] 的穷举 `match` 先编译失败逼作者给它一个下标，随后本测试在
    /// [`all`] 里找不到它而判红。没有这一条，下面两条测试会在"新变体根本没被测到"的世界里
    /// 照样全绿。
    #[test]
    fn all_lists_every_variant_exactly_once() {
        let mut seen = [false; VARIANT_COUNT];
        for error in all() {
            let index = variant_index(error);
            assert!(!seen[index], "{} 在 all() 里出现了两次", error.code());
            seen[index] = true;
        }
        assert!(
            seen.iter().all(|hit| *hit),
            "all() 漏了变体；缺的下标：{:?}",
            seen.iter()
                .enumerate()
                .filter(|(_, hit)| !**hit)
                .map(|(index, _)| index)
                .collect::<Vec<_>>()
        );
    }

    /// `Display` 与 [`VaultError::code`] 是同一个字符串 —— 防止改了一处忘了另一处。
    #[test]
    fn display_and_code_agree() {
        for error in all() {
            assert_eq!(error.to_string(), error.code());
        }
    }

    /// 分类标识符两两不同：两个失效模式压成同一个字符串，审计就分不开它们。
    #[test]
    fn codes_are_pairwise_distinct() {
        let mut codes: Vec<&'static str> = all().into_iter().map(VaultError::code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "分类标识符必须两两不同");
    }

    /// 类型层面的封堵：一个 `Copy` 且不含堆载荷的枚举，构造上就带不出密钥材料或明文。
    ///
    /// 这比"记得别把值 format 进错误里"强一档 —— 想加 `String` 字段的人会先撞上编译失败。
    #[test]
    fn error_is_copy_so_it_cannot_carry_owned_data() {
        const fn assert_copy<T: Copy>() {}
        assert_copy::<VaultError>();
    }
}
