//! 信封的解析与序列化：v1（**只读**，迁移兼容）与 v2（读写）。
//!
//! # v1 信封是什么 —— 本轮实测，不是回忆
//!
//! 上游 `server/src/credentials.ts::encryptSecret` 产出一段 **JSON 字符串**。本轮把
//! `server/src/credentials.ts` 的原始字节（sha256
//! `407baae15245ff6376caa7978f2e74307c02181ea2abd8d9e9c83c4d2fe63cee`，逐字节复制，未改一行）
//! 放进一个只有依赖桩的目录，用 Bun 1.3.11 直接执行，跑出五条真信封。样本之一：
//!
//! ```text
//! {"version":1,"iv":"szoErpoKzwcaMoCm","ciphertext":"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA="}
//! ```
//!
//! 逐条读出来的事实：
//!
//! | 观察 | 数值 | 说明 |
//! | --- | --- | --- |
//! | `iv` 解 base64 后长度 | 恒 **12** | 与 `crypto.getRandomValues(new Uint8Array(12))` 一致 |
//! | `ciphertext` 长度 − 明文长度 | 恒 **16** | 22→38、0→16、37→53、39→55；即 tag **追加在密文尾部** |
//! | AAD | **无** | `crypto.subtle.encrypt({name:"AES-GCM", iv}, …)` 第一个参数里没有 `additionalData` |
//! | 密钥 | `Buffer.from(encodedKey, "base64")` 原样 `importKey` | 长度决定 AES-128/192/256 |
//!
//! 落库列是 `credentials.encrypted_value` + `credentials.key_id`；`parity/tables.yaml` 的
//! `tbl-credentials` notes 写明它是「唯一密文真源」，全仓仅 4 个写入点。**同一种信封**还用在
//! `sso_providers.oidc_config` / `saml_config` 两列上（`server/src/auth/encrypt-sso-config.ts`
//! 直接 `import { decryptSecret, encryptSecret } from "../credentials"`）。
//!
//! # 本模块比上游**严**的三处，以及为什么这三处严得起
//!
//! 1. **IV 必须是 12 字节。** WebCrypto 的 AES-GCM 接受任意长度 IV，上游 `decryptSecret` 把
//!    `Buffer.from(envelope.iv, "base64")` 原样递给它，**不查长度**。实测：把 IV 截成 8 字节
//!    再喂给上游，它没有报任何长度错误，而是一路走到 GCM 认证失败，报
//!    `OperationError`—— 也就是说"IV 长度不对"这件事在上游那里没有名字。但上游的**写侧**只产 12
//!    字节，而写侧是数据的唯一来源 —— 所以"库里存在非 12 字节 IV"这件事在上游数据里不可能
//!    发生。拒绝它因此不损失任何可读数据，却能把"有人手改了这一行"变成一条明确的
//!    [`VaultError::LegacyIvLength`]，而不是一次含义不明的解密失败。
//! 2. **base64 严格解码。** Node 的 `Buffer.from(x, "base64")` 会**忽略**非 base64 字符，
//!    于是一段被污染的 `iv` 在上游那里会静默解成别的字节。实测：`"AAAAAAAAAAAAAAAA"` 解出
//!    12 字节，把其中一个字符换成 `*` 后解出 **11** 字节且**不抛异常**。本模块用 `base64` crate 的
//!    `STANDARD` 引擎（严格、要求 padding），解不开就是 [`VaultError::EnvelopeInvalid`]。
//!    这只把"认证失败"提前成了"解析失败"，两条路都是拒绝，方向是 fail-closed。
//! 3. **`version` 必须是整数 1。** 上游写的是 `envelope.version !== 1`，而 JS 的 `Number`
//!    分不出 `1` 与 `1.0`。**实测**（Bun 跑上游原始字节）：
//!    `JSON.parse('{"version":1.0}').version === 1` 为 `true`，把一条 `"version":1.0` 的
//!    信封喂给 `decryptSecret` **解密成功**；而 `"version":"1"` 被拒，报
//!    `Error: Credential envelope is invalid`。本模块要求整数，于是 `1.0` 这一档被我们拒掉
//!    —— 上游的写侧只产 `1`（`JSON.stringify({version:1})` 出来就是 `{"version":1`），
//!    所以同样不损失可读数据。
//!
//! 三处的共同判据是同一句话：**上游写得出来的，我们必须读得出来；上游写不出来的，我们可以拒。**
//!
//! # v2 信封
//!
//! v2 在 v1 的基础上加两样：每记录一个随机 DEK（由 KEK 包装），以及绑定六元组的 AAD
//! （[`super::binding`]）。它是一段字段顺序固定的 JSON，第一个字段恒为 `"version":2` ——
//! 这不是审美，是为了让 [`classify_column`] 那条前缀判据对 v2 同样成立。

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::binding::KeyVersion;
use super::error::VaultError;
use super::key::{Nonce, TAG_BYTES};

/// 上游 `encrypt-sso-config.ts::isEnvelope` 用的那个前缀，逐字符相同。
///
/// 上游原文：`return value.startsWith('{"version":1');`，注释是「What `encryptSecret` produces.
/// Anything else is a value written before this wrapper existed.」
pub const V1_ENVELOPE_PREFIX: &str = "{\"version\":1";

/// v2 信封的对应前缀。
pub const V2_ENVELOPE_PREFIX: &str = "{\"version\":2";

/// 一个密文列里躺着的东西是哪一种。
///
/// # 为什么必须照搬上游那条前缀判据
///
/// 上游 `sso_providers.oidc_config` / `saml_config` 两列里**混着明文**：升级到
/// `encrypt-sso-config.ts` 之前注册的 provider 是明文写进去的，上游读侧刻意容忍
/// （原文：「Reading tolerates plaintext. A deployment that registered a provider before this
/// existed has plaintext in the column, and refusing to read it would lock that company out of
/// their own sign-in at the moment they upgraded.」），写侧再加密。
///
/// 迁移期两侧会**同时**读同一列。判据不一致意味着同一个列值在两个进程眼里是两种东西 ——
/// 一个当密文、一个当明文 —— 那是数据损坏，不是不兼容。所以这里不"改进"判据。
///
/// # 它的失效模式，以及为什么可以接受
///
/// 一段恰好以 `{"version":1` 开头的**明文**会被误判成信封。三条理由让它可以接受：
///
/// 1. **这个缺陷已经在数据里了。** 上游写侧的条件是 `!isEnvelope(value)` 才加密；一段以此
///    开头的明文在上游那里从一开始就不会被加密。Rust 侧换判据只会让两边不一致，不会让那行
///    数据变好。
/// 2. **误判不会静默产出垃圾。** 被误判的明文接着走 [`EnvelopeV1::parse`]，那里要求
///    `iv` / `ciphertext` 存在且是字符串、base64 解得开、IV 恰好 12 字节。任何一条不满足就是
///    一条明确的错误 —— 不存在"当成密文解出一段乱码然后当明文用"的路径。
/// 3. **修它需要改上游的数据模型**（加一个 `is_encrypted` 列或一个魔数前缀），那是 §14.3
///    "兼容期只允许 expand"框架下的一次独立迁移，不是 vault 模块能单方面决定的事。已记进
///    交付报告。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColumnShape {
    /// v1 信封（上游 `encryptSecret` 的产物）。
    LegacyEnvelope,
    /// v2 信封（本项目的 record AEAD）。
    RecordEnvelope,
    /// 历史明文。上游读侧容忍它，我们也必须容忍。
    Plaintext,
}

/// 判断一个密文列里躺着的是哪一种东西。
///
/// 判据与上游 `isEnvelope` 逐字符相同，理由与失效模式见 [`ColumnShape`]。
#[must_use]
pub fn classify_column(value: &str) -> ColumnShape {
    if value.starts_with(V2_ENVELOPE_PREFIX) {
        ColumnShape::RecordEnvelope
    } else if value.starts_with(V1_ENVELOPE_PREFIX) {
        ColumnShape::LegacyEnvelope
    } else {
        ColumnShape::Plaintext
    }
}

/// 上游 v1 信封，解析后的形态。
///
/// **只读**：本项目不产 v1 信封。产 v1 需要一个随机 IV，而随机数不进领域层
/// （[`super::key`] 的模块文档）；更重要的是，迁移的方向是**单向**的 —— 往回写 v1 等于
/// 把刚刚关掉的洞（无 AAD、密文可搬家）又打开。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeV1 {
    iv: Nonce,
    ciphertext: Vec<u8>,
}

impl EnvelopeV1 {
    /// 严格解析一段列值。
    ///
    /// # Errors
    ///
    /// - [`VaultError::EnvelopeInvalid`]：不是 JSON、不是对象、`version` 不是整数、
    ///   `iv` / `ciphertext` 缺失或不是字符串、base64 解不开。对应上游
    ///   `parseEnvelope` 的 `"Credential envelope is invalid"`。
    /// - [`VaultError::EnvelopeVersionUnsupported`]：`version` 是整数但不是 1。
    ///   与上一条分开，理由见 [`VaultError::EnvelopeVersionUnsupported`]。
    /// - [`VaultError::LegacyIvLength`]：IV 解出来不是 [`super::key::NONCE_BYTES`] 字节。
    /// - [`VaultError::CiphertextTooShort`]：密文短于 [`TAG_BYTES`]，不可能合法。
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        let json: serde_json::Value =
            serde_json::from_str(value).map_err(|_| VaultError::EnvelopeInvalid)?;
        let object = json.as_object().ok_or(VaultError::EnvelopeInvalid)?;

        // 上游是 `envelope.version !== 1`，即"是数字 1"。`as_u64` 顺带把字符串 "1" 挡在外面
        // （JS 那边 `"1" !== 1` 同样为真，两边一致）。
        let version = object
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(VaultError::EnvelopeInvalid)?;
        if version != 1 {
            return Err(VaultError::EnvelopeVersionUnsupported);
        }

        let iv = decode_base64_field(object, "iv")?;
        let ciphertext = decode_base64_field(object, "ciphertext")?;

        let iv = Nonce::from_slice(&iv).map_err(|_| VaultError::LegacyIvLength)?;
        if ciphertext.len() < TAG_BYTES {
            return Err(VaultError::CiphertextTooShort);
        }

        Ok(Self { iv, ciphertext })
    }

    /// 信封里的 IV。
    #[must_use]
    pub const fn iv(&self) -> Nonce {
        self.iv
    }

    /// 信封里的密文，**含尾部 16 字节 tag**（实测，见模块文档那张表）。
    ///
    /// 不把 tag 切出来单列：`aes-gcm` 的 `Aead::decrypt` 默认就按 postfix tag 处理，切开再拼
    /// 回去只会多一处能写错的地方。
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// v2 信封：每记录 DEK + KEK 包装 + AAD 绑定。
///
/// 字段顺序在 [`Self::to_column_value`] 里写死，第一个恒为 `version`，理由见模块文档末段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeV2 {
    key_version: KeyVersion,
    dek_nonce: Nonce,
    wrapped_dek: Vec<u8>,
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

impl EnvelopeV2 {
    /// 组装一个 v2 信封。`pub(super)`：唯一合法的产出点是 [`super::aead::seal_v2`] ——
    /// 允许调用方自由拼装信封，就等于允许它拼出一个 AAD 与内容不匹配的信封。
    pub(super) const fn new(
        key_version: KeyVersion,
        dek_nonce: Nonce,
        wrapped_dek: Vec<u8>,
        nonce: Nonce,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            key_version,
            dek_nonce,
            wrapped_dek,
            nonce,
            ciphertext,
        }
    }

    /// 严格解析一段 v2 列值。
    ///
    /// # Errors
    ///
    /// 与 [`EnvelopeV1::parse`] 同族；额外要求 `key_version` 是能放进 `u32` 的整数
    /// （放不下就说明这一行不是我们写的）。
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        let json: serde_json::Value =
            serde_json::from_str(value).map_err(|_| VaultError::EnvelopeInvalid)?;
        let object = json.as_object().ok_or(VaultError::EnvelopeInvalid)?;

        let version = object
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(VaultError::EnvelopeInvalid)?;
        if version != 2 {
            return Err(VaultError::EnvelopeVersionUnsupported);
        }

        let key_version = object
            .get("key_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|raw| u32::try_from(raw).ok())
            .ok_or(VaultError::EnvelopeInvalid)?;

        let dek_nonce = decode_base64_field(object, "dek_nonce")?;
        let wrapped_dek = decode_base64_field(object, "wrapped_dek")?;
        let nonce = decode_base64_field(object, "nonce")?;
        let ciphertext = decode_base64_field(object, "ciphertext")?;

        let dek_nonce = Nonce::from_slice(&dek_nonce)?;
        let nonce = Nonce::from_slice(&nonce)?;
        if wrapped_dek.len() < TAG_BYTES || ciphertext.len() < TAG_BYTES {
            return Err(VaultError::CiphertextTooShort);
        }

        Ok(Self {
            key_version: KeyVersion::new(key_version),
            dek_nonce,
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    /// 序列化成要写进列里的那段字符串。
    ///
    /// # 为什么是 `format!` 而不是 `serde_json::to_string`
    ///
    /// `serde_json` 的 `Map` 默认是 `BTreeMap`（`preserve_order` feature 没开），用它组装会把
    /// 字段按字典序排出来，`"version"` 会掉到**最后** —— [`classify_column`] 那条前缀判据当场
    /// 失效。用 `derive(Serialize)` 的结构体可以保住顺序，但那样就得为一段"只有五个字段、
    /// 全是 base64 与整数"的输出引入一层派生宏。
    ///
    /// 直接 `format!` 安全的理由是**取值范围**：base64 标准字母表是 `A-Za-z0-9+/=`，其中没有
    /// 任何一个字符需要 JSON 转义；`key_version` 是 `u32`。所以这里不存在转义遗漏的可能，
    /// 而且函数**没有失败路径**（`serde_json::to_string` 那条 `Result` 在这里恒为 `Ok`，
    /// 留着只会诱导调用方写一条永不命中的错误分支）。
    #[must_use]
    pub fn to_column_value(&self) -> String {
        format!(
            "{{\"version\":2,\"key_version\":{},\"dek_nonce\":\"{}\",\"wrapped_dek\":\"{}\",\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            self.key_version.get(),
            BASE64.encode(self.dek_nonce.as_bytes()),
            BASE64.encode(&self.wrapped_dek),
            BASE64.encode(self.nonce.as_bytes()),
            BASE64.encode(&self.ciphertext),
        )
    }

    /// 这条密文是用哪一代 KEK 封的。
    ///
    /// **它只是一条线索**，用来去找对应的密钥；进 AAD 的那个必须来自调用方的 binding，
    /// 见 [`super::aead::open_v2`]。
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    /// 包装 DEK 时用的 nonce。
    #[must_use]
    pub const fn dek_nonce(&self) -> Nonce {
        self.dek_nonce
    }

    /// 被 KEK 包装的 DEK（含尾部 tag）。
    #[must_use]
    pub fn wrapped_dek(&self) -> &[u8] {
        &self.wrapped_dek
    }

    /// record 密文用的 nonce。
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// record 密文（含尾部 tag）。
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// 取一个必须是 base64 字符串的字段并严格解码。
///
/// 严格性的理由（Node 的 `Buffer.from(x,"base64")` 会忽略非法字符）见模块文档条 2。
fn decode_base64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<u8>, VaultError> {
    let raw = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(VaultError::EnvelopeInvalid)?;
    BASE64.decode(raw).map_err(|_| VaultError::EnvelopeInvalid)
}

#[cfg(test)]
mod tests {
    use super::super::key::NONCE_BYTES;
    use super::*;

    /// 本轮由**上游原始字节**产出的一条真信封（AES-256，明文 `sk-test-model-key-0001`）。
    ///
    /// 生成方式与完整清单见本 crate 的 `vault::aead` 测试模块 —— 那里还有解密断言。
    /// 这里只用它验证解析层。
    const UPSTREAM_V1: &str = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";

    /// 解析上游真信封：IV 12 字节、密文 = 明文 22 + tag 16 = 38 字节。
    ///
    /// 这条同时是"解析器不是恒失败"的正向对照 —— 下面一整组拒绝用例都靠它撑着。
    #[test]
    fn parses_a_real_upstream_envelope() {
        let envelope = EnvelopeV1::parse(UPSTREAM_V1).expect("上游真信封必须解得开");
        assert_eq!(envelope.iv().as_bytes().len(), NONCE_BYTES);
        assert_eq!(envelope.ciphertext().len(), 22 + TAG_BYTES);
    }

    /// 逐条拒绝：结构、版本、字段类型、base64、IV 长度、密文长度。
    #[test]
    fn rejects_every_malformed_shape() {
        let cases: [(&str, VaultError); 10] = [
            ("not json at all", VaultError::EnvelopeInvalid),
            ("[1,2,3]", VaultError::EnvelopeInvalid),
            ("{}", VaultError::EnvelopeInvalid),
            // version 是字符串："1" !== 1，上游同样拒。
            (
                "{\"version\":\"1\",\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
                VaultError::EnvelopeInvalid,
            ),
            (
                "{\"version\":3,\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
                VaultError::EnvelopeVersionUnsupported,
            ),
            // iv 不是字符串。
            (
                "{\"version\":1,\"iv\":12,\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
                VaultError::EnvelopeInvalid,
            ),
            // ciphertext 缺失。
            (
                "{\"version\":1,\"iv\":\"AAAAAAAAAAAAAAAA\"}",
                VaultError::EnvelopeInvalid,
            ),
            // base64 里混了非法字符 —— Node 会忽略它，我们不。
            (
                "{\"version\":1,\"iv\":\"AAAA*AAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
                VaultError::EnvelopeInvalid,
            ),
            // IV 只有 11 字节。
            (
                "{\"version\":1,\"iv\":\"AAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
                VaultError::LegacyIvLength,
            ),
            // 密文只有 15 字节，装不下 tag。
            (
                "{\"version\":1,\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAA\"}",
                VaultError::CiphertextTooShort,
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(
                EnvelopeV1::parse(value).unwrap_err(),
                expected,
                "输入：{value}"
            );
        }
    }

    /// 上游接受 `"version":1.0`，我们不接受 —— 这条**分歧是刻意的**，钉在这里防回潮。
    ///
    /// 实测（Bun 跑上游 `server/src/credentials.ts` 原始字节）：一条 `"version":1.0` 的信封
    /// 被 `decryptSecret` 正常解开。JS 的 `Number` 分不出 `1` 与 `1.0`，而 `serde_json` 分得出。
    ///
    /// 拒绝它不损失任何可读数据：上游写侧走 `JSON.stringify({version:1,…})`，产出的恒是
    /// `{"version":1`（同一次实测确认），库里不可能存在 `1.0` 的行。
    #[test]
    fn upstream_accepts_a_float_version_and_we_deliberately_do_not() {
        let value = "{\"version\":1.0,\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}";
        assert_eq!(
            EnvelopeV1::parse(value).unwrap_err(),
            VaultError::EnvelopeInvalid,
            "1.0 不是整数 1"
        );
        // 正向对照：同一条信封把版本写成整数 1 就解析得开 —— 说明拒绝的原因确实是那个小数点，
        // 而不是这条样本本身有别的毛病。
        assert!(EnvelopeV1::parse(&value.replace("1.0", "1")).is_ok());
    }

    /// 未知版本与结构损坏必须给出**不同**的错误。
    ///
    /// 把两者压成一条，运维就分不出"数据坏了"和"这个二进制太旧"。
    #[test]
    fn unknown_version_is_distinguishable_from_broken_structure() {
        let unknown =
            EnvelopeV1::parse("{\"version\":7,\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}")
                .unwrap_err();
        let broken = EnvelopeV1::parse("{\"version\":1}").unwrap_err();
        assert_ne!(unknown, broken);
        assert_eq!(unknown, VaultError::EnvelopeVersionUnsupported);
        assert_eq!(broken, VaultError::EnvelopeInvalid);
    }

    /// 列值分类：v1 / v2 / 明文三档。
    #[test]
    fn classifies_columns_the_way_upstream_does() {
        assert_eq!(classify_column(UPSTREAM_V1), ColumnShape::LegacyEnvelope);
        assert_eq!(
            classify_column("{\"version\":2,\"key_version\":1}"),
            ColumnShape::RecordEnvelope
        );
        // 历史明文：升级前注册的 SSO provider 就是这样躺在列里的。
        assert_eq!(
            classify_column("{\"clientId\":\"abc\",\"clientSecret\":\"shh\"}"),
            ColumnShape::Plaintext
        );
        assert_eq!(classify_column(""), ColumnShape::Plaintext);
        // 空白开头不算信封 —— 上游的 startsWith 同样不容忍前导空白。
        assert_eq!(
            classify_column(" {\"version\":1,\"iv\":\"x\"}"),
            ColumnShape::Plaintext
        );
    }

    /// 已知失效模式：一段恰好以 `{"version":1` 开头的明文会被判成信封。
    ///
    /// 这条测试**把缺陷钉住**而不是假装它不存在：判据必须与上游逐字符相同（理由见
    /// [`ColumnShape`]），所以它不许被"顺手修好"。后半段是它可以接受的原因 —— 误判之后
    /// 解析层会明确拒绝，不存在"解出乱码当明文用"的路径。
    #[test]
    fn plaintext_that_starts_with_the_prefix_is_misclassified_but_fails_closed() {
        let plaintext = "{\"version\":1,\"note\":\"这其实是一段明文\"}";
        assert_eq!(classify_column(plaintext), ColumnShape::LegacyEnvelope);
        assert_eq!(
            EnvelopeV1::parse(plaintext).unwrap_err(),
            VaultError::EnvelopeInvalid,
            "误判必须落到一条明确的错误上，绝不能解出内容"
        );
    }

    /// v2 的列值必须以 `{"version":2` 开头，且能被自己解析回来。
    #[test]
    fn v2_round_trips_and_keeps_version_first() {
        let envelope = EnvelopeV2::new(
            KeyVersion::new(4_242),
            Nonce::from_array([1u8; NONCE_BYTES]),
            vec![2u8; DATA_KEY_WRAP_LEN],
            Nonce::from_array([3u8; NONCE_BYTES]),
            vec![4u8; 40],
        );

        let column = envelope.to_column_value();
        assert!(column.starts_with(V2_ENVELOPE_PREFIX), "{column}");
        assert_eq!(classify_column(&column), ColumnShape::RecordEnvelope);

        let parsed = EnvelopeV2::parse(&column).expect("自己写的必须自己读得回来");
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.key_version(), KeyVersion::new(4_242));
    }

    /// 包装后的 DEK 长度：32 字节 DEK + 16 字节 tag。只在测试里用，用来造形状合法的样本。
    const DATA_KEY_WRAP_LEN: usize = 32 + TAG_BYTES;

    /// 手工拼一段 v2 列值。
    ///
    /// 刻意**不**用 `to_column_value()` 再 `str::replace` 打补丁：本轮就是这么写的，结果
    /// `[1u8; 12]` 的 base64（`AQEBAQEBAQEBAQEB`）恰好是 `[4u8; 40]` 的 base64 的一段子串，
    /// `replace` 顺手把密文也改了，于是测试拿到 `EnvelopeInvalid` 而不是想测的
    /// `NonceLength` —— 一条**测错了东西**却看起来在测的断言。直接拼字段就没有这个面。
    fn v2_json(
        key_version: &str,
        dek_nonce: &[u8],
        wrapped_dek: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> String {
        format!(
            "{{\"version\":2,\"key_version\":{key_version},\"dek_nonce\":\"{}\",\"wrapped_dek\":\"{}\",\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            BASE64.encode(dek_nonce),
            BASE64.encode(wrapped_dek),
            BASE64.encode(nonce),
            BASE64.encode(ciphertext),
        )
    }

    /// v2 解析同样逐条拒绝坏形状。
    #[test]
    fn v2_rejects_malformed_shapes() {
        let good = v2_json(
            "1",
            &[0x11u8; NONCE_BYTES],
            &[0x33u8; DATA_KEY_WRAP_LEN],
            &[0x22u8; NONCE_BYTES],
            &[0x44u8; 40],
        );
        // 正向对照：这段样本本身是好的。没有它，下面每一条"必须拒绝"在
        // "v2_json 产出的东西压根解析不了"的世界里同样通过。
        assert!(EnvelopeV2::parse(&good).is_ok());

        let cases: [(&str, String, VaultError); 6] = [
            (
                "版本号是 1 —— 这是一条 v1 信封，不该走 v2 解析",
                v2_json(
                    "1",
                    &[0x11u8; NONCE_BYTES],
                    &[0x33u8; DATA_KEY_WRAP_LEN],
                    &[0x22u8; NONCE_BYTES],
                    &[0x44u8; 40],
                )
                .replace("\"version\":2", "\"version\":1"),
                VaultError::EnvelopeVersionUnsupported,
            ),
            (
                "负数版本号放不进 u32",
                v2_json(
                    "-1",
                    &[0x11u8; NONCE_BYTES],
                    &[0x33u8; DATA_KEY_WRAP_LEN],
                    &[0x22u8; NONCE_BYTES],
                    &[0x44u8; 40],
                ),
                VaultError::EnvelopeInvalid,
            ),
            (
                "超出 u32 的版本号说明这一行不是我们写的",
                v2_json(
                    "4294967296",
                    &[0x11u8; NONCE_BYTES],
                    &[0x33u8; DATA_KEY_WRAP_LEN],
                    &[0x22u8; NONCE_BYTES],
                    &[0x44u8; 40],
                ),
                VaultError::EnvelopeInvalid,
            ),
            (
                "dek_nonce 只有 11 字节",
                v2_json(
                    "1",
                    &[0x11u8; NONCE_BYTES - 1],
                    &[0x33u8; DATA_KEY_WRAP_LEN],
                    &[0x22u8; NONCE_BYTES],
                    &[0x44u8; 40],
                ),
                VaultError::NonceLength,
            ),
            (
                "record nonce 只有 11 字节",
                v2_json(
                    "1",
                    &[0x11u8; NONCE_BYTES],
                    &[0x33u8; DATA_KEY_WRAP_LEN],
                    &[0x22u8; NONCE_BYTES - 1],
                    &[0x44u8; 40],
                ),
                VaultError::NonceLength,
            ),
            (
                "wrapped_dek 装不下 tag",
                v2_json(
                    "1",
                    &[0x11u8; NONCE_BYTES],
                    &[0x33u8; TAG_BYTES - 1],
                    &[0x22u8; NONCE_BYTES],
                    &[0x44u8; 40],
                ),
                VaultError::CiphertextTooShort,
            ),
        ];

        for (label, value, expected) in cases {
            assert_eq!(EnvelopeV2::parse(&value).unwrap_err(), expected, "{label}");
        }

        // 缺字段与非法 base64 也各来一次。
        assert_eq!(
            EnvelopeV2::parse("{\"version\":2,\"key_version\":1}").unwrap_err(),
            VaultError::EnvelopeInvalid
        );
        assert_eq!(
            EnvelopeV2::parse(&good.replace("\"nonce\":\"", "\"nonce\":\"*")).unwrap_err(),
            VaultError::EnvelopeInvalid
        );
    }
}
