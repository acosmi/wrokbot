//! 审计链的两块底层积木：SHA-256 摘要类型，以及**无歧义**的规范编码写入器。
//!
//! # 为什么规范编码要单独成一层
//!
//! `row_hash = H(canonical(row) || prev_hash)` 这条式子里，真正决定链有没有价值的是
//! `canonical` 而不是 `H`。SHA-256 是抗碰撞的，但如果编码本身允许**两条不同的行编成同一串
//! 字节**，那么攻击者根本不需要碰撞 SHA-256 —— 他改一条行、让它编码成和原行相同的字节，
//! 链照样自洽。
//!
//! 最经典的失效形态是**朴素拼接**：把字段直接首尾相连，`("ab", "c")` 与 `("a", "bc")` 得到
//! 同一串 `abc`。分隔符也救不了它 —— 只要分隔符可以出现在值里（审计字段全是任意 UTF-8），
//! 就还能构造出两组不同的值编成同一串。
//!
//! 所以本模块采取**长度前缀 + 定宽**的框式编码：
//!
//! - 变长项（字符串、字节串、摘要以外的任何 `&[u8]`）一律写成 `u64 大端长度 || 原始字节`；
//! - 定宽项（`u64` / `i128` / 单字节标签 / 布尔 / 32 字节摘要）按固定宽度直接写入；
//! - `Option` 先写一个字节的存在标记（`0` = None，`1` = Some），再写内容。
//!
//! 由此得到的性质是：**在字段序列（schema）固定的前提下，字节流唯一确定各字段取值**。
//! 这一点足以排除上面那类攻击 —— 而"schema 固定"这个前提不是靠约定：每个被 hash 的对象都
//! 在头部写入一个**长度前缀的域名标签**（`CanonicalWriter::new` 的入参），不同用途的编码
//! 天然不共享前缀；枚举在写自己的字段之前必须先写一个变体标签（见 `chain` / `checkpoint`
//! 两个模块的编码器），于是"同一 schema"在每条编码路径内部都是成立的。
//!
//! # 为什么不用 JSON 做规范编码
//!
//! 因为 JSON 有太多种方式表达同一个值（`1` / `1.0` / `1e0`、`A` 与 `A`、键序、空白），
//! 而"规范 JSON"是一份需要逐条实现并逐条测试的规范。本项目对审计行的编码没有互操作需求
//! （只有本仓自己读写），所以选一个**构造上就无歧义**的二进制框式编码，比选一个需要靠纪律
//! 维持无歧义的文本编码便宜得多，也可测得多。
//!
//! 唯一一处仍要面对 JSON 的是工具实参（`crate::tool::args`）—— 那里的输入本身就是 JSON，
//! 处理办法写在那个模块里。

use core::fmt;

use sha2::{Digest, Sha256};

/// SHA-256 摘要的字节数。
pub const SHA256_DIGEST_BYTES: usize = 32;

/// 一个 SHA-256 摘要。
///
/// 定长数组而不是 `String`：十六进制串既可以大写也可以小写、还可以带前缀，比较两个"看起来
/// 一样"的串是一次每个调用点都要重新做对的判断。定长数组把这件事收敛成一次 `==`。
///
/// **不是秘密**：它是审计行的摘要，`Debug` / `Display` 直接输出十六进制是有意的 —— 链断在
/// 哪一行是运维必须能从日志里读出来的信息。真正需要常量时间比较的是 checkpoint 的
/// **签名**，那个类型在 [`super::checkpoint`]，与本类型刻意分开。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; SHA256_DIGEST_BYTES]);

impl Sha256Digest {
    /// 由原始字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// 直接对一段字节求摘要。
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// 借出原始字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.0
    }

    /// 渲染成 64 个**小写**十六进制字符。
    ///
    /// 大小写固定是契约的一部分：`prev_hash` / `row_hash` 两列在数据库里是文本，一半大写
    /// 一半小写会让链校验在字符串比较那一步凭空断掉。
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(SHA256_DIGEST_BYTES * 2);
        for byte in self.0 {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    /// 从十六进制串解析。
    ///
    /// 接受大小写混排（读的是别人写下的历史数据，不该因为大小写把一条完好的链判成损坏），
    /// 但 [`Self::to_hex`] 只产出小写。
    ///
    /// # Errors
    ///
    /// 长度不是 64、或出现非十六进制字符时返回 [`DigestParseError`]。
    pub fn parse_hex(text: &str) -> Result<Self, DigestParseError> {
        let bytes = text.as_bytes();
        if bytes.len() != SHA256_DIGEST_BYTES * 2 {
            return Err(DigestParseError::WrongLength { found: bytes.len() });
        }
        let mut out = [0u8; SHA256_DIGEST_BYTES];
        // `as_chunks::<2>()` 而不是 `chunks_exact(2)`：块大小是常量，编译器因此能拿到
        // `&[u8; 2]` 而不是一个长度未知的切片，下面两次索引不再需要边界检查。
        // 上方已经确认长度恰为 64，所以 remainder 恒为空。
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            let high = hex_nibble(pair[0]).ok_or(DigestParseError::NotHexadecimal)?;
            let low = hex_nibble(pair[1]).ok_or(DigestParseError::NotHexadecimal)?;
            out[index] = (high << 4) | low;
        }
        Ok(Self(out))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    // 默认 derive 会打印 32 个十进制数字，人眼没法把它和日志里的十六进制串对上。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

/// 十六进制摘要解析失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestParseError {
    /// 长度不是 64 个字符。
    #[error("digest_wrong_length found={found}")]
    WrongLength {
        /// 实际收到的字符数。
        found: usize,
    },
    /// 出现了非十六进制字符。**不回显那个字符** —— 它来自数据库里的不可信文本。
    #[error("digest_not_hexadecimal")]
    NotHexadecimal,
}

/// 规范编码写入器。
///
/// 用法固定：`new(域名标签)` → 按**固定顺序**调用各写入方法 → [`Self::finish`] 取字节，
/// 或 [`Self::digest`] 直接取摘要。顺序就是 schema，不同顺序 = 不同 schema，所以每条编码
/// 路径必须写死一个顺序（本仓的每个 `canonical_bytes` 实现都是一条直线，没有分支 —— 有
/// 分支的地方一律先写变体标签）。
pub struct CanonicalWriter {
    buffer: Vec<u8>,
}

impl CanonicalWriter {
    /// 以域名标签开头新建一个写入器。
    ///
    /// 标签本身按变长项写入（带长度前缀），所以 `"a" + "bc"` 与 `"ab" + "c"` 两个域不可能
    /// 撞在一起。这是**跨用途**的分隔：审计行、checkpoint、工具实参三者的摘要即使内容
    /// 恰好相同也不会相等。
    #[must_use]
    pub fn new(domain: &'static str) -> Self {
        let mut writer = Self {
            buffer: Vec::with_capacity(128),
        };
        writer.bytes(domain.as_bytes());
        writer
    }

    /// 写一个单字节标签（枚举变体判别式、存在标记等）。定宽 1 字节。
    pub fn tag(&mut self, tag: u8) {
        self.buffer.push(tag);
    }

    /// 写一段变长字节：`u64 大端长度 || 原始字节`。
    pub fn bytes(&mut self, value: &[u8]) {
        // `usize -> u64` 在本项目支持的目标上恒为无损（32 位是加宽，64 位是同宽）。
        // 这里刻意不用 `try_from().unwrap_or(u64::MAX)`：长度写错会直接毁掉单射性，
        // 而"悄悄写一个错的长度"比编译期就不支持的目标危险得多。
        let length = value.len() as u64;
        self.buffer.extend_from_slice(&length.to_be_bytes());
        self.buffer.extend_from_slice(value);
    }

    /// 写一个变长字符串。
    pub fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    /// 写一个可选字符串：存在标记 + （存在时）变长字符串。
    pub fn option_str(&mut self, value: Option<&str>) {
        match value {
            None => self.tag(0),
            Some(text) => {
                self.tag(1);
                self.str(text);
            }
        }
    }

    /// 写一个布尔值（单字节 `0` / `1`）。
    pub fn bool(&mut self, value: bool) {
        self.tag(u8::from(value));
    }

    /// 写一个 `u32`（定宽 4 字节大端）。
    pub fn u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    /// 写一个 `u64`（定宽 8 字节大端）。
    pub fn u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    /// 写一个 `i128`（定宽 16 字节大端）。时间戳走这条。
    pub fn i128(&mut self, value: i128) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    /// 写一个摘要（定宽 32 字节，无长度前缀 —— 宽度是常量）。
    pub fn digest(&mut self, value: &Sha256Digest) {
        self.buffer.extend_from_slice(value.as_bytes());
    }

    /// 写一个可选摘要：存在标记 + （存在时）32 字节。
    ///
    /// 这个方法是 genesis 语义的承重点：`None`（genesis，`prev_hash` 列为 NULL）编成
    /// `0x00`，而一个恰好全零的真实摘要编成 `0x01` + 32 个零字节。两者**不可能**混淆 ——
    /// 如果直接拿全零数组代表 genesis，那么"上一行的 row_hash 碰巧是全零"和"这是首行"
    /// 就是同一串字节，链的起点会变成可以伪造的位置。
    pub fn option_digest(&mut self, value: Option<&Sha256Digest>) {
        match value {
            None => self.tag(0),
            Some(digest) => {
                self.tag(1);
                self.digest(digest);
            }
        }
    }

    /// 取出已写入的字节。
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// 对已写入的字节求 SHA-256。
    #[must_use]
    pub fn digest_of_written(&self) -> Sha256Digest {
        Sha256Digest::of(&self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_is_lowercase() {
        let digest = Sha256Digest::of(b"openbot");
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "to_hex 必须只产出小写十六进制，实际是 {hex}"
        );
        assert_eq!(Sha256Digest::parse_hex(&hex).unwrap(), digest);
        // 读侧接受大写：历史数据不该因为大小写被判成损坏。
        assert_eq!(
            Sha256Digest::parse_hex(&hex.to_ascii_uppercase()).unwrap(),
            digest
        );
    }

    #[test]
    fn hex_parse_rejects_wrong_length_and_non_hex() {
        assert_eq!(
            Sha256Digest::parse_hex("abcd"),
            Err(DigestParseError::WrongLength { found: 4 })
        );
        let mut bad = Sha256Digest::of(b"x").to_hex();
        bad.replace_range(0..1, "z");
        assert_eq!(
            Sha256Digest::parse_hex(&bad),
            Err(DigestParseError::NotHexadecimal)
        );
    }

    /// 本模块存在的**唯一理由**的可执行形式：朴素拼接会把 `("ab","c")` 与 `("a","bc")`
    /// 编成同一串，长度前缀编码不会。
    ///
    /// 负向对照（朴素拼接确实撞）与正向对照（本编码确实不撞）写在同一条里，因为单独看
    /// 任何一半都可能在"编码器压根没实现"的世界里成立。
    #[test]
    fn length_prefixed_framing_is_injective_where_concatenation_is_not() {
        // 负向对照：朴素拼接的两组不同输入给出同一串字节。
        let naive_left = [b"ab".as_slice(), b"c".as_slice()].concat();
        let naive_right = [b"a".as_slice(), b"bc".as_slice()].concat();
        assert_eq!(
            naive_left, naive_right,
            "朴素拼接确实会撞 —— 这正是本模块存在的理由"
        );

        // 正向：同样两组输入过本编码器后不同。
        let mut left = CanonicalWriter::new("test");
        left.str("ab");
        left.str("c");
        let mut right = CanonicalWriter::new("test");
        right.str("a");
        right.str("bc");
        assert_ne!(left.finish(), right.finish());
    }

    /// 域名标签把不同用途的编码彻底隔开：字段内容完全相同，域不同即摘要不同。
    #[test]
    fn domain_tag_separates_otherwise_identical_encodings() {
        let mut row = CanonicalWriter::new("openbot.audit.row.v1");
        row.str("same");
        let mut checkpoint = CanonicalWriter::new("openbot.audit.checkpoint.v1");
        checkpoint.str("same");
        assert_ne!(row.digest_of_written(), checkpoint.digest_of_written());

        // 正向对照：同域同内容确实相等（否则上一条在"摘要永远不同"的世界里也成立）。
        let mut again = CanonicalWriter::new("openbot.audit.row.v1");
        again.str("same");
        assert_eq!(row.digest_of_written(), again.digest_of_written());
    }

    /// `None` 与"全零摘要"必须编成不同的字节 —— genesis 的起点不能被伪造。
    #[test]
    fn absent_digest_differs_from_an_all_zero_digest() {
        let zero = Sha256Digest::from_bytes([0u8; SHA256_DIGEST_BYTES]);

        let mut absent = CanonicalWriter::new("test");
        absent.option_digest(None);
        let mut present_zero = CanonicalWriter::new("test");
        present_zero.option_digest(Some(&zero));

        assert_ne!(absent.finish(), present_zero.finish());
    }

    /// `Option<&str>` 的存在标记同理：`None` 与 `Some("")` 不能同编码。
    #[test]
    fn absent_string_differs_from_empty_string() {
        let mut absent = CanonicalWriter::new("test");
        absent.option_str(None);
        let mut empty = CanonicalWriter::new("test");
        empty.option_str(Some(""));
        assert_ne!(absent.finish(), empty.finish());
    }

    /// 定宽项的宽度是常量，不随取值变化 —— 否则"定宽"这个前提就不成立，单射性随之失效。
    #[test]
    fn fixed_width_items_do_not_vary_in_length() {
        let mut small = CanonicalWriter::new("t");
        small.u64(0);
        small.i128(0);
        small.u32(0);
        let mut large = CanonicalWriter::new("t");
        large.u64(u64::MAX);
        large.i128(i128::MIN);
        large.u32(u32::MAX);
        assert_eq!(small.finish().len(), large.finish().len());
    }
}
