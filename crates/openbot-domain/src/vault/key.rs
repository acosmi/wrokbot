//! 密钥材料与 nonce 的类型：[`WrappingKey`]、[`DataKey`]、[`Nonce`]。
//!
//! # 领域层为什么只有"持有"没有"生成"
//!
//! repository contract §4 与 `crates/openbot-domain/src/lib.rs` 的所有权边界都写死了：领域层不做 I/O、
//! 不读时钟、**不生成随机数**。理由是可确定性重放（v3 §20.1 shadow Agent 重放录制 stream）
//! —— 一旦掺进环境依赖，golden trace 就不可信。
//!
//! 于是本模块的形状是被这条约束**决定**的，不是设计选择：DEK、IV、nonce 全部由调用方
//! （infra：Keychain / Windows Credential Manager / Secret Service / KMS / OS CSPRNG）**传进来**，
//! 领域层只做"给定密钥、给定 nonce 的纯变换"。`getrandom` 不在依赖表里，这条约束是构造性的
//! —— 写不出来才对。
//!
//! 直接的后果是：**nonce 唯一性由 infra 负责**，本模块无法验证。AES-GCM 在同一把密钥下重用
//! nonce 会同时丢掉机密性与完整性，这是 v2 设计里唯一一处"领域层看不见、但必须有人看着"的
//! 不变量，已记进交付报告。v2 的形状把这条风险压到了最小：每记录一个随机 DEK（v3 §6.4），
//! 于是 record nonce 只需要在**一把只用一次的密钥**下唯一。

use super::error::VaultError;
use super::secret::SecretBytes;

/// AES-GCM 的 nonce / IV 字节数。
///
/// **12。** 上游实测：`server/src/credentials.ts::encryptSecret` 里是
/// `crypto.getRandomValues(new Uint8Array(12))`，本轮跑出来的五条真信封 IV 长度全部是 12
/// （证据见 [`super::envelope`] 的模块文档）。`aes-gcm 0.10.3` 的 `Aes256Gcm` / `Aes128Gcm`
/// 也把 nonce 长度钉成 `U12`。两边同一个数，所以 v1 与 v2 共用这一个常量。
pub const NONCE_BYTES: usize = 12;

/// AES-GCM 的认证标签字节数。
///
/// **16。** 实测证据：上游 `crypto.subtle.encrypt` 的输出把 tag 追加在密文尾部 ——
/// 本轮跑出的五条真信封里，`ciphertext` 长度恒等于明文长度 + 16（22→38、0→16、37→53、
/// 39→55、22→38）。`aes-gcm` 的默认 `TagSize` 同样是 `U16`。
pub const TAG_BYTES: usize = 16;

/// 每记录 DEK 的字节数。
///
/// **32（AES-256）。** DEK 是**我们自己铸的**，所以只有一个合法长度 —— 与
/// [`WrappingKey`] 那种"别人给什么就得认什么"的处境相反。
pub const DATA_KEY_BYTES: usize = 32;

/// 包装密钥：Desktop 的 master key、Server 的 tenant KEK，以及迁移期上游的
/// `KEY_ENCRYPTION_KEY`。
///
/// # 为什么三档长度都收
///
/// 因为上游三档都收，而 v1 兼容读的判据是"上游写得出来的，我们必须读得出来"。
///
/// 实测（本轮用上游 `server/src/credentials.ts` 的原始字节在 Bun 1.3.11 上跑
/// `encryptSecret` 与 `decryptSecret`）：16 字节密钥 round-trip 成功；**24 字节密钥
/// round-trip 也成功**；20 字节密钥被 WebCrypto 拒绝，报 `DataError: Data provided to an
/// operation does not meet requirements`（这条是正向对照：说明这个探测确实能说"不"）。
///
/// 也就是说，一个把 `KEY_ENCRYPTION_KEY` 配成 24 字节的部署，数据在上游是**能读的**。
/// 如果 Rust 侧拒绝 192 位，那个部署就永远迁不过来 —— 兼容读兼容不到，等于数据丢失。
/// 所以本类型接受 16 / 24 / 32 三档，其余长度一律 [`VaultError::KeyLength`]，**绝不**
/// 截断、补零或"当成最接近的那一档"。
///
/// 交付报告里记了这条：任务书原文说"192 位在 `aes-gcm` crate 里没有对应类型"，实际上
/// `aes-gcm 0.10.3` 的确没有 `Aes192Gcm` **别名**（`grep 'pub type Aes' ` 只有 `Aes128Gcm`
/// 与 `Aes256Gcm` 两条），但它 `pub use aes;` 重导出了 `aes::Aes192`，`AesGcm<Aes192, U12>`
/// 编得出来（本轮实测编译 + 解开了上游产出的 192 位真信封）。
pub struct WrappingKey(SecretBytes);

impl WrappingKey {
    /// AES 认识的三档密钥长度。
    pub const ACCEPTED_BYTES: [usize; 3] = [16, 24, 32];

    /// 接管一段密钥材料。
    ///
    /// # Errors
    ///
    /// 长度不在 [`Self::ACCEPTED_BYTES`] 里时返回 [`VaultError::KeyLength`]。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, VaultError> {
        if !Self::ACCEPTED_BYTES.contains(&bytes.len()) {
            // 先把这段材料塞进会擦除的容器再丢掉，不要让一段长度不对的密钥原样留在堆上。
            drop(SecretBytes::new(bytes));
            return Err(VaultError::KeyLength);
        }
        Ok(Self(SecretBytes::new(bytes)))
    }

    /// 密钥位数（128 / 192 / 256）。**不是**秘密：它由密文之外的配置决定，运维要看得到。
    #[must_use]
    pub fn bits(&self) -> usize {
        self.0.len() * 8
    }

    /// 借出密钥材料。`pub(super)`：只有同模块的 AEAD 实现能拿到它，调用方拿不到。
    #[must_use]
    pub(super) fn material(&self) -> &[u8] {
        self.0.expose()
    }
}

impl core::fmt::Debug for WrappingKey {
    /// 只打位数，不打材料。位数不是秘密（见 [`Self::bits`]），而排障时它恰好是最有用的那一半
    /// —— "这台机器加载的是一把 128 位的 KEK" 是运维能据以行动的信息。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WrappingKey({} bits, [redacted])", self.bits())
    }
}

/// 每记录一次性的数据加密密钥。
///
/// v3 §6.4 的表逐字：Desktop「每记录随机 DEK，由 master key 包装」，Server「每记录随机 DEK，
/// 由 tenant KEK 包装」。两个环境的差别只在**包装密钥从哪来**，DEK 这一层完全相同 ——
/// 所以本类型不分环境。
///
/// 生成在 infra（模块文档）。
pub struct DataKey(SecretBytes);

impl DataKey {
    /// 接管一段 DEK 材料。
    ///
    /// # Errors
    ///
    /// 长度不是 [`DATA_KEY_BYTES`] 时返回 [`VaultError::DataKeyLength`]。与
    /// [`WrappingKey::from_bytes`] 用不同的错误码，理由见 [`VaultError::DataKeyLength`]。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, VaultError> {
        if bytes.len() != DATA_KEY_BYTES {
            drop(SecretBytes::new(bytes));
            return Err(VaultError::DataKeyLength);
        }
        Ok(Self(SecretBytes::new(bytes)))
    }

    /// 借出 DEK 材料。`pub(super)`，理由同 [`WrappingKey::material`]。
    #[must_use]
    pub(super) fn material(&self) -> &[u8] {
        self.0.expose()
    }
}

impl core::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DataKey([redacted])")
    }
}

/// 一个 [`NONCE_BYTES`] 字节的 nonce / IV。
///
/// # 为什么它可以 `Copy` / `Debug` / `PartialEq` 而密钥不行
///
/// nonce **不是秘密**：它明文躺在信封里（v1 的 `iv` 字段、v2 的 `nonce` / `dek_nonce`），
/// 任何能读到密文的人都能读到它。给它加上"不可打印"的包装只会在排障时碍事，同时制造一种
/// "这里有个秘密"的错觉 —— 而真正的不变量是**唯一性**，不是保密性（见模块文档）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce([u8; NONCE_BYTES]);

impl Nonce {
    /// 由定长数组构造。**不会失败** —— 长度由类型保证。
    #[must_use]
    pub const fn from_array(bytes: [u8; NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// 由切片构造。
    ///
    /// # Errors
    ///
    /// 长度不是 [`NONCE_BYTES`] 时返回 [`VaultError::NonceLength`]。这是解析 v1 信封里那个
    /// 长度不受约束的 base64 字段时唯一的入口。
    pub fn from_slice(bytes: &[u8]) -> Result<Self, VaultError> {
        <[u8; NONCE_BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| VaultError::NonceLength)
    }

    /// 借出 nonce 字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三档合法长度都收，其余一律拒。
    ///
    /// 正向对照（"收"那一半）与负向对照（"拒"那一半）在同一条测试里 —— 只有"拒"的那一半，
    /// 在"`from_bytes` 恒返回 Err"的世界里同样通过。
    #[test]
    fn wrapping_key_accepts_exactly_the_three_aes_lengths() {
        for length in [16usize, 24, 32] {
            let key = WrappingKey::from_bytes(vec![0u8; length])
                .unwrap_or_else(|_| panic!("{length} 字节必须被接受"));
            assert_eq!(key.bits(), length * 8);
        }
        for length in [0usize, 1, 15, 17, 20, 23, 25, 31, 33, 64] {
            assert_eq!(
                WrappingKey::from_bytes(vec![0u8; length]).unwrap_err(),
                VaultError::KeyLength,
                "{length} 字节必须被拒绝，绝不截断或补零"
            );
        }
    }

    /// DEK 只有一个合法长度，且用的是与包装密钥**不同**的错误码。
    #[test]
    fn data_key_accepts_only_32_bytes_with_its_own_error_code() {
        assert!(DataKey::from_bytes(vec![7u8; DATA_KEY_BYTES]).is_ok());
        for length in [0usize, 16, 24, 31, 33] {
            assert_eq!(
                DataKey::from_bytes(vec![0u8; length]).unwrap_err(),
                VaultError::DataKeyLength,
                "{length} 字节的 DEK 必须被拒"
            );
        }
        // 两个长度错误必须可分辨：DEK 长度不对说明**铸造侧**坏了，包装密钥长度不对说明
        // **配置**错了，运维动作完全不同。
        assert_ne!(VaultError::DataKeyLength, VaultError::KeyLength);
    }

    /// nonce 的两个构造入口在长度上一致。
    #[test]
    fn nonce_rejects_every_length_but_twelve() {
        assert!(Nonce::from_slice(&[0u8; NONCE_BYTES]).is_ok());
        for length in [0usize, 1, 11, 13, 16, 32] {
            let bytes = vec![0u8; length];
            assert_eq!(
                Nonce::from_slice(&bytes).unwrap_err(),
                VaultError::NonceLength,
                "{length} 字节的 nonce 必须被拒"
            );
        }
        assert_eq!(
            Nonce::from_array([3u8; NONCE_BYTES]).as_bytes(),
            &[3u8; NONCE_BYTES]
        );
    }

    /// 密钥的 `Debug` 不打材料，但打位数。
    #[test]
    fn key_debug_shows_size_but_not_material() {
        let key = WrappingKey::from_bytes(vec![0xABu8; 32]).expect("32 字节合法");
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "WrappingKey(256 bits, [redacted])");
        assert!(!rendered.contains("ab"), "{rendered}");
        // 正向对照：材料确实还在。
        assert_eq!(key.material(), &[0xABu8; 32]);

        let dek = DataKey::from_bytes(vec![0xCDu8; DATA_KEY_BYTES]).expect("32 字节合法");
        assert_eq!(format!("{dek:?}"), "DataKey([redacted])");
        assert_eq!(dek.material(), &[0xCDu8; DATA_KEY_BYTES]);
    }
}
