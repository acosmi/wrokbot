//! 签名值 —— 一句「这是本部署发出去的」的短期声明（上游 `auth/signed-value.ts`）。
//!
//! # 它解决的问题，以及为什么不是「一行数据库记录」
//!
//! 上游模块注释逐字给了理由：这些声明要**穿过我们控制不了的东西再回来** —— 举的例子是
//! 一条 run assertion 由客户自己的 Agent 进程带着走。可选方案是每条声明写一行库，但
//! 「这些声明短命且单一用途」，而那条路径上本来就已经有一次读和一次写，再加一对读写
//! 买不到任何东西。
//!
//! # 派生子密钥，以及 label 为什么必须分隔用途
//!
//! 签名用的**不是**部署的加密密钥本身，而是 `HMAC-SHA256(encryption_key, label)` 派生出来
//! 的子密钥。两件事因此成立：
//!
//! 1. **一个用途的签名不可能被当作另一个用途重放。** 这是本模块最重要的一条不变量。
//!    没有 label 的话，一条「这次 run 是我们批准的」的声明与一条「这个 OAuth connect
//!    是我们发起的」的声明用同一把密钥签，于是任何一方的持有者都可以把手里那条拿去
//!    冒充另一方 —— 而两者的权限完全不同。本轮实测：拿 `openbot:agent-run` 签出来的串
//!    去按 `mcp-oauth-connect` 验，`verify` 返回 `null`（`node -e` 直接跑上游那段代码）。
//! 2. **配置面只有一个 secret，用途却可以有很多个。** 运维不必为每个用途配一把密钥，
//!    而密钥又不会在用途之间借用。
//!
//! 正因为第 1 条的全部效力来自「两个用途的 label 不同」，[`SignatureLabel`] 做成封闭
//! 枚举而不是 `&str` 参数：自由字符串允许两个调用点**偶然**挑到同一个字面量，而那正是
//! 这套机制唯一的失效方式，且它不会报任何错。封闭枚举让「label 两两不同」变成一条可以
//! 被测试机械核对的事实（`labels_are_pairwise_distinct`）。
//!
//! # 与上游的两处差异，各自的理由
//!
//! - **`sign` 拒绝空 value（本项目收紧）。** 上游 `sign("")` 会产出 `".199bct…"`，而它
//!   自己的 `verify` 因为 `separator <= 0` 把这个串判成无效 —— 本轮 `node -e` 实测两条
//!   都跑过：`sign("")` 有输出，`verify(sign(""))` 返回 `null`。一个签出来自己验不了的
//!   东西是纯粹的陷阱：故障会出现在**使用**它的那一端，而错误的成因在**签发**的那一端。
//!   上游没有任何调用点会签空值（run id 与 OAuth state 都非空），所以在签发侧当场拒绝
//!   不会拦住任何本来能工作的路径。
//! - **`verify` 比较整个串**（与上游一致，但理由要写清楚）。上游比的是
//!   `Buffer.from(signed)` 与 `Buffer.from(expected)`，而不是只比签名段。因为
//!   `value` 是从 `signed` 里切出来的、`expected` 又是用同一个 `value` 重新签的，两串的
//!   前缀**在构造上**逐字节相同，所以「比整串」与「比签名段」此刻等价。本实现保留比整串
//!   的形态，理由是那个等价性依赖一个可以被将来的改动打破的构造事实（比如有朝一日
//!   `sign` 对 value 做了任何归一化）；比整串在那种情况下仍然正确，比签名段则会悄悄放行。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// 签名的用途标签。封闭枚举。
///
/// 取值是上游两个调用点的**逐字**常量，本轮 grep 得到：
/// `agents/callback-token.ts::RUN_LABEL = "openbot:agent-run"`、
/// `plugins/oauth.ts::CONNECT_LABEL = "mcp-oauth-connect"`。
///
/// 新增一个用途 = 在这里加一个变体。这看起来像摩擦，而它正是要的东西：加变体是一次
/// 会被 review 看见的动作，而挑一个字符串字面量不是。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureLabel {
    /// 一次 Agent run 的断言（上游 `RUN_LABEL`）。
    AgentRun,
    /// 一次 MCP OAuth connect 的发起凭证（上游 `CONNECT_LABEL`）。
    McpOauthConnect,
}

impl SignatureLabel {
    /// 全部用途。遍历它的测试负责核对「两两不同」。
    pub const ALL: [Self; 2] = [Self::AgentRun, Self::McpOauthConnect];

    /// 参与密钥派生的那个字节串。
    ///
    /// 它进的是密码学构造而不是界面，所以**永远不能**为了好看而改动：改一个字节，
    /// 全部在飞的签名当场失效。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentRun => "openbot:agent-run",
            Self::McpOauthConnect => "mcp-oauth-connect",
        }
    }
}

impl fmt::Display for SignatureLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 部署的签名用底层密钥（上游 `KEY_ENCRYPTION_KEY`）。
///
/// # 为什么 `Debug` 是打码的
///
/// §17.2 条 8：secret 不进模型、GUI state、browser event、普通日志、trace。派生 `Debug`
/// 会让一次 `dbg!`、一条 `tracing::debug!("{:?}", …)`、或者任何一个把入参打进错误上下文
/// 的库把整把密钥写进日志。手写的 `Debug` 让那条路径**根本不存在** —— 这比「记得别打印」
/// 强一档，因为后者要求每个调用点都记得。
///
/// 密钥的生成、轮换与从 keychain / KMS 读出来都不在这里（那是 I/O）。本类型只是一次
/// 借用，让「谁在签」这件事在类型上有名字。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigningSecret<'a>(&'a [u8]);

impl<'a> SigningSecret<'a> {
    /// 借一段密钥材料。
    #[must_use]
    pub const fn new(material: &'a [u8]) -> Self {
        Self(material)
    }
}

impl fmt::Debug for SigningSecret<'_> {
    /// 不打印任何字节，也不打印长度。
    ///
    /// 长度看着无害，但它是暴力破解的搜索空间上界，而且对一个由运维粘贴进配置的值来说
    /// 长度往往就足以认出是哪一把。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningSecret(<redacted>)")
    }
}

/// 一个签好的串：`<value>.<base64url 签名>`。
///
/// 上游同一形态。之所以是一个 newtype 而不是裸 `String`，是为了让「这东西已经签过了」
/// 在类型上看得见 —— 一个到处传 `String` 的 API 里，「传错了、传的是没签的原值」不会有
/// 任何征兆。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct SignedValue(String);

impl SignedValue {
    /// 借出线上表示。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// 交出线上表示的所有权。
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for SignedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// 拒绝签一个空 value。
///
/// 理由见模块文档「与上游的两处差异」。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_signed_value_empty")]
pub struct EmptySignedValue;

impl EmptySignedValue {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_signed_value_empty"
    }
}

/// 一个签名串验不过。
///
/// # 为什么只有一个变体
///
/// 「没有分隔符」「签名段对不上」「长度不对」在攻击者眼里必须是**同一个答案**：三个不同的
/// 错误码等于给了对方一台预言机，可以逐步问出「我这串哪里错了」。这与本模块用常量时间
/// 比较是同一条理由的两个面 —— 常量时间挡的是时间侧信道，单一错误码挡的是内容侧信道，
/// 只做一半没有意义。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_signature_invalid")]
pub struct SignatureInvalid;

impl SignatureInvalid {
    /// 稳定的分类标识符。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_signature_invalid"
    }
}

/// 派生某个用途的子密钥：`HMAC-SHA256(secret, label)`。
///
/// 单独抽出来只是为了让派生这一步在代码里有名字并能被单测钉住（`derived_subkeys_…`），
/// 调用方不需要它。
fn subkey(secret: SigningSecret<'_>, label: SignatureLabel) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret.0).expect("HMAC 接受任意长度密钥，构造不可能失败");
    mac.update(label.as_str().as_bytes());
    mac.finalize().into_bytes().into()
}

/// 签一个值。
///
/// # Errors
///
/// `value` 为空时返回 [`EmptySignedValue`]，理由见模块文档。
pub fn sign(
    value: &str,
    secret: SigningSecret<'_>,
    label: SignatureLabel,
) -> Result<SignedValue, EmptySignedValue> {
    if value.is_empty() {
        return Err(EmptySignedValue);
    }
    Ok(SignedValue(sign_unchecked(value, secret, label)))
}

/// 不做空值检查的签名，供 [`verify`] 重算期望值用。
///
/// 它是私有的：[`verify`] 已经在切分时排除了空 value（`separator == 0`），再走一次
/// 检查只会让「重算」与「原签」走上两条不同的路，那正是这种比较最不该有的东西。
fn sign_unchecked(value: &str, secret: SigningSecret<'_>, label: SignatureLabel) -> String {
    let mut mac = HmacSha256::new_from_slice(&subkey(secret, label))
        .expect("HMAC 接受任意长度密钥，构造不可能失败");
    mac.update(value.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let mut signed = String::with_capacity(value.len() + 1 + signature.len());
    signed.push_str(value);
    signed.push('.');
    signed.push_str(&signature);
    signed
}

/// 验一个签名串，通过则借出它承载的值。
///
/// 切分点是**最后一个** `.`（上游 `lastIndexOf`），所以 value 里可以有点号。
/// 比较是常量时间的：提前返回会泄漏「签名前几个字节对了」，而那足以让人有耐心地
/// 拼出一个有效签名（上游注释原文）。
///
/// # Errors
///
/// 任何形态的不匹配都返回同一个 [`SignatureInvalid`]，理由见该类型文档。
pub fn verify<'a>(
    signed: &'a str,
    secret: SigningSecret<'_>,
    label: SignatureLabel,
) -> Result<&'a str, SignatureInvalid> {
    let Some(separator) = signed.rfind('.') else {
        return Err(SignatureInvalid);
    };
    // `== 0` 即空 value，与上游 `separator <= 0` 同义（`rfind` 不会返回负数）。
    if separator == 0 {
        return Err(SignatureInvalid);
    }
    let value = &signed[..separator];
    let expected = sign_unchecked(value, secret, label);

    // 长度不等时直接拒绝。这一步确实泄漏「长度对不对」，但签名段长度是固定的
    // （32 字节摘要的 base64url = 43 字符），所以唯一可变的是 value 的长度 ——
    // 而 value 就在入参里，对方本来就知道。
    if expected.len() != signed.len() {
        return Err(SignatureInvalid);
    }
    if bool::from(expected.as_bytes().ct_eq(signed.as_bytes())) {
        Ok(value)
    } else {
        Err(SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与上游逐字节相同的参照值。
    ///
    /// 产出方式：本轮把上游 `auth/signed-value.ts` 的 `signingKey` / `sign` 两个函数原样
    /// 抄进 `node -e` 跑出来的（Node 在本机 PATH 上）。密钥是测试常量，不是任何真实凭据。
    const KEY: &[u8] = b"test-encryption-key-0123456789";

    fn secret() -> SigningSecret<'static> {
        SigningSecret::new(KEY)
    }

    /// 派生子密钥与上游逐字节相同 —— 这一条钉住的是**密钥派生**那一层，
    /// 光验最终签名相等的话，两层里任何一层写错都可能被另一层的错误抵消掉。
    #[test]
    fn derived_subkeys_match_upstream_byte_for_byte() {
        let expected = [
            (
                SignatureLabel::AgentRun,
                "c11baef81e43fd31a5e01efd7518a6016e2d7e8d50b6aeef21d6a8e9beea0a4b",
            ),
            (
                SignatureLabel::McpOauthConnect,
                "4cdd45c2ace93702c6efce0670e0f8a2b245ed9c19520bca3a88901d87846d45",
            ),
        ];
        for (label, hex) in expected {
            let derived = subkey(secret(), label);
            let rendered: String = derived.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(rendered, hex, "{label} 的子密钥必须与上游逐字节相同");
        }
    }

    /// 完整签名串与上游逐字节相同。
    #[test]
    fn signatures_match_upstream_byte_for_byte() {
        let cases = [
            (
                SignatureLabel::AgentRun,
                "run-42",
                "run-42.nUHBbY6g6_ZAuJntCUt5LEz1_NlZPkK9gaXzkykiCHU",
            ),
            (
                SignatureLabel::McpOauthConnect,
                "run-42",
                "run-42.5D-DlfsTyLffGY2dqg8w-VtUUTJjbe-DEk0wwkPva3s",
            ),
            (
                SignatureLabel::AgentRun,
                "value.with.dots",
                "value.with.dots.SVTUV6Qh8pZbBLa_HQZCATUO-9VOR8_VHBgioIi8zps",
            ),
        ];
        for (label, value, expected) in cases {
            assert_eq!(sign(value, secret(), label).unwrap().as_str(), expected);
        }
    }

    /// 本模块存在的理由：**一个用途的签名不能被当作另一个用途验过**。
    #[test]
    fn a_signature_for_one_label_never_verifies_under_another() {
        let signed = sign("run-42", secret(), SignatureLabel::AgentRun).unwrap();

        // 正向对照：同 label 验得过。没有它，下一条断言在「verify 恒失败」的世界里
        // 同样通过，而那样的部署没有任何一条 run 能回来。
        assert_eq!(
            verify(signed.as_str(), secret(), SignatureLabel::AgentRun),
            Ok("run-42")
        );

        // 负向：换 label 立刻失败。上游同一构造实测也是 null。
        assert_eq!(
            verify(signed.as_str(), secret(), SignatureLabel::McpOauthConnect),
            Err(SignatureInvalid)
        );
    }

    /// label 两两不同 —— 上一条不变量的全部效力都建在这上面。
    #[test]
    fn labels_are_pairwise_distinct() {
        let mut labels: Vec<&str> = SignatureLabel::ALL.iter().map(|l| l.as_str()).collect();
        assert_eq!(labels.len(), 2);
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            SignatureLabel::ALL.len(),
            "两个用途共用一个 label 就等于没有 label"
        );

        // 派生出来的子密钥也必须两两不同（label 不同但派生塌缩到同一把密钥同样致命）。
        let a = subkey(secret(), SignatureLabel::AgentRun);
        let b = subkey(secret(), SignatureLabel::McpOauthConnect);
        assert_ne!(a, b);
    }

    /// 换密钥就验不过 —— 签名确实绑定在部署的 secret 上。
    #[test]
    fn a_signature_does_not_survive_a_different_secret() {
        let signed = sign("run-42", secret(), SignatureLabel::AgentRun).unwrap();
        let other = SigningSecret::new(b"a-different-deployment-key");
        assert_eq!(
            verify(signed.as_str(), other, SignatureLabel::AgentRun),
            Err(SignatureInvalid)
        );
    }

    /// value 里含点号时切分点必须是**最后一个**点。
    #[test]
    fn the_value_may_contain_dots() {
        let signed = sign("value.with.dots", secret(), SignatureLabel::AgentRun).unwrap();
        assert_eq!(
            verify(signed.as_str(), secret(), SignatureLabel::AgentRun),
            Ok("value.with.dots")
        );
    }

    /// 各种坏形态一律给同一个答案。
    #[test]
    fn every_malformed_shape_gives_the_same_single_answer() {
        let good = sign("run-42", secret(), SignatureLabel::AgentRun).unwrap();
        let signed = good.as_str();

        let malformed = [
            "",                                                   // 空串
            "no-separator-at-all",                                // 没有点
            ".only-a-signature",                                  // 空 value（上游 separator <= 0）
            "run-42.",                                            // 空签名
            "run-42.AAAA",                                        // 签名长度不对
            "run-43.nUHBbY6g6_ZAuJntCUt5LEz1_NlZPkK9gaXzkykiCHU", // 换了 value
        ];
        for candidate in malformed {
            assert_eq!(
                verify(candidate, secret(), SignatureLabel::AgentRun),
                Err(SignatureInvalid),
                "{candidate:?} 必须被拒"
            );
        }

        // 改签名的最后一个字符也必须被拒（等长，只差一个字节）。
        let mut tampered = signed.to_owned();
        tampered.pop();
        tampered.push(if signed.ends_with('U') { 'V' } else { 'U' });
        assert_eq!(tampered.len(), signed.len());
        assert_eq!(
            verify(&tampered, secret(), SignatureLabel::AgentRun),
            Err(SignatureInvalid)
        );

        // 正向对照：原串仍然验得过 —— 上面那批不是靠「什么都验不过」通过的。
        assert_eq!(
            verify(signed, secret(), SignatureLabel::AgentRun),
            Ok("run-42")
        );
    }

    /// 签发侧拒绝空 value：不产出一个自己验不了的串（与上游的有意差异）。
    #[test]
    fn signing_an_empty_value_is_refused_at_the_producer() {
        assert_eq!(
            sign("", secret(), SignatureLabel::AgentRun),
            Err(EmptySignedValue)
        );

        // 上游那个串长什么样，以及它自己验不过 —— 两条都是本轮 node 实测的结果，
        // 这里把「验不过」这一半钉住，作为上面那条收紧的依据。
        assert_eq!(
            verify(
                ".199bctvt008EZtI1Zr0-g6tyn9waQDACwhllZ86wZxg",
                secret(),
                SignatureLabel::AgentRun
            ),
            Err(SignatureInvalid),
            "上游 sign(\"\") 的产物在上游自己的 verify 里就是无效的"
        );
    }

    /// 密钥不会经 `Debug` 泄漏出去。
    #[test]
    fn the_secret_never_renders_its_bytes() {
        let rendered = format!("{:?}", secret());
        assert_eq!(rendered, "SigningSecret(<redacted>)");
        assert!(!rendered.contains("test-encryption-key"));
        // 连长度都不给。
        assert!(!rendered.contains(&KEY.len().to_string()));
    }

    #[test]
    fn codes_agree_with_display() {
        assert_eq!(SignatureInvalid.to_string(), SignatureInvalid.code());
        assert_eq!(EmptySignedValue.to_string(), EmptySignedValue.code());
        assert_ne!(SignatureInvalid.code(), EmptySignedValue.code());
        assert_eq!(SignatureLabel::AgentRun.to_string(), "openbot:agent-run");
    }
}
