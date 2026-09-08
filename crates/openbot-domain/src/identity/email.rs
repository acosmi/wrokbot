//! [`NormalizedEmail`] —— 地址的**唯一**规范化入口。
//!
//! # 为什么必须是一个类型而不是一个函数
//!
//! 上游 `auth/roles.ts::isConfiguredAdmin` 与 `people/store.ts::normalize` 各自写了一遍
//! `email.trim().toLowerCase()`，而 `people/store.ts::list` 又在 SQL 里第三次写成
//! `lower(users.email)`。三处手写同一条规则，就有三次忘记的机会 ——
//! `parity/tables.yaml::tbl-revoked-access` 的 notes 逐字记着这条的后果：
//!
//! > 入库前必须 lower-case，否则大小写不同的两行 = 同一个人只有一行被强制
//!
//! 这件事的严重性来自 `revoked_access` 的主键是 **email 而不是 user id**（同一条 notes）：
//! 删掉 user 行不是移除，下一次 IdP 登录会用新 id 把这个人重建出来，地址是唯一活得下来的
//! 键。所以一个没规范化的键 = 一次没生效的撤权，而且从管理界面上看它**成功了**。
//!
//! 把规范化收进 newtype 的唯一构造入口之后，「忘了规范化」不再是纪律问题：拿不到
//! `NormalizedEmail` 就调不了 [`super::revocation`] 与 [`super::roles`] 的任何函数，
//! 编译期就停住。
//!
//! # 规范化到底做什么，以及**刻意不做**什么
//!
//! 做两件事，与上游逐字相同：按 ECMAScript `TrimString` **去首尾空白**，然后
//! **Unicode 小写**。
//!
//! 不做的每一件都必须写下理由，因为规范化规则就是「谁能登录」的定义，多做一步就是在没有
//! 产品裁决的情况下悄悄改变部署的准入名单：
//!
//! - **不做 plus-tag 剥离**（`a+admin@x.com` → `a@x.com`）。很多组织把 plus-tag 当成独立
//!   邮箱发给不同的人；剥掉它会让 `INITIAL_ADMIN_EMAILS` 里的 `ops+admin@x.com` 把管理员
//!   身份授予 `ops@x.com` 名下的**每一个** tag 变体。
//! - **不做点号折叠**（`a.b@gmail.com` → `ab@gmail.com`）。这是某一家邮件商的投递规则，
//!   不是地址的等价规则；对自建域名它直接是错的，会把两个不同的人当成一个。
//! - **不做 Unicode NFC/NFKC 归一化**。NFKC 会把全角字符、连字（`ﬀ` → `ff`）压平，于是两个
//!   在 IdP 那边确实不同的地址在这里变成同一个人。反向的风险同样在：上游不做，所以做了就
//!   与 IdP 的判定分叉。
//! - **不校验 `@`、不限长度**。上游 `isConfiguredAdmin` 是纯字符串比较，什么都不校验；
//!   `users.email` 是无长度上限的 `text` 列。这里加校验 = 让领域层变成第二个、更弱的认证器，
//!   而它与真正的 IdP 判定分歧时的表现是**静默锁死**（那个人在 IdP 那边验证通过，却被这里
//!   拒之门外，且没有任何一屏能解释）。地址长什么样归 IdP 校验层管（`auth/index.ts::
//!   mapEntraProfile` 就是那一层，它要求 claim 含 `@`）。
//!
//! 唯一被拒绝的取值是**空**（见 [`EmailBlank`]），理由见该类型的文档。
//!
//! # 一处与上游有意的字节级对齐：U+FEFF
//!
//! JS 的 `String.prototype.trim` 按 ECMA-262 的 `WhiteSpace` 产生式去空白，而该产生式
//! **包含 `<ZWNBSP>`（U+FEFF，即 BOM）**；Rust 的 [`str::trim`] 按 Unicode `White_Space`
//! 属性去空白，而 U+FEFF 的类别是 `Cf` 不是 `White_Space` —— 两者在这一个码点上不一致。
//!
//! 本轮实测（`node -e '…'`，Node 在本机 PATH 上）：
//!
//! ```text
//! JSON.stringify("﻿a@b.com".trim())  ==  "\"a@b.com\""
//! ```
//!
//! 而 Rust 的 `"\u{FEFF}a@b.com".trim()` 原样保留那个码点（负向对照在
//! `rust_trim_alone_does_not_remove_the_bom`）。这个差异不是学术问题：一个带 BOM 保存的
//! `.env` 会让 `INITIAL_ADMIN_EMAILS` 的**第一项**以 U+FEFF 开头，于是 admin floor 上的那
//! 个地址永远匹配不上任何登录者 —— 而 floor 正是「最后一个管理员误把自己降权之后的回来
//! 的路」（上游 `roles.ts::isConfiguredAdmin` 的注释原文）。所以这里显式把 U+FEFF 一并
//! 去掉：与上游行为对齐，而不是与 Rust 标准库的默认对齐。

use core::fmt;

use serde::Serialize;

use crate::text::trim_ecmascript;

/// 规范化后的 email 地址。
///
/// # 不变量
///
/// 任何一个 `NormalizedEmail` 的值都满足：非空、无 ECMAScript 首尾空白、已 Unicode 小写。
/// 这条不变量由「只有 [`NormalizedEmail::normalize`] 一个构造入口」承载 —— 元组字段是
/// 私有的，没有 `Default`，也没有 `From<String>`。
///
/// # 为什么实现了 `Serialize` 却**没有** `Deserialize`
///
/// 与 `openbot_contracts::auth::AuthContext` 同一条理由的弱化版：`Serialize` 是安全的
/// （写出去的一定是已规范化的值），而 `Deserialize` 会开出第二个构造入口 —— 一段
/// `{"email":"A@B.COM"}` 的 JSON 就能造出一个违反上述不变量的值，本模块存在的全部意义
/// 随即失效。需要从字节还原时走 [`NormalizedEmail::normalize`]：它对已经规范化的输入是
/// 幂等的（`normalize_is_idempotent`），所以这条限制不带来任何实际不便。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NormalizedEmail(String);

/// 规范化后为空 —— 唯一被拒绝的取值。
///
/// # 为什么这一条要拒，而 `@` 与长度不拒
///
/// 空串不是一个「奇怪但可能真实存在的地址」，它是一个**会把两条不变量同时打穿的键**：
///
/// 1. 它是 `revoked_access` 的主键取值。写进去之后 `is_revoked("")` 恒为真，而
///    「地址为空的人」不是一个人 —— 这条 deny 行永远拦不到任何人，却会让管理界面显示
///    撤权已经生效。
/// 2. 它是 `INITIAL_ADMIN_EMAILS` 逗号切分的自然产物（`"a@x.com,,b@x.com"` 或一个尾随
///    逗号）。一条空的 floor 条目如果被接受，就会与「地址为空」的登录者匹配 —— 而
///    admin floor 是**授予管理员**的路径，它上面任何一条永远为真或永远无法解释的条目
///    都是提权面。
///
/// 上游 `config.ts::commaSeparated` 用 `.filter(Boolean)` 把空条目丢掉，本类型是同一条
/// 判据的类型化表达：让空值根本构造不出来，而不是指望每个调用点都记得过滤。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identity_email_blank")]
pub struct EmailBlank;

impl EmailBlank {
    /// 稳定的分类标识符，进审计与错误响应用。
    ///
    /// 它是**标识符**不是文案：不随 locale 变化（repository contract §4a「文案不进 domain」）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        "identity_email_blank"
    }
}

impl NormalizedEmail {
    /// 唯一构造入口：按 ECMAScript `TrimString` 去首尾空白 + Unicode 小写。
    ///
    /// # Errors
    ///
    /// 规范化后为空时返回 [`EmailBlank`]，理由见该类型文档。除此之外**不拒绝任何输入**
    /// —— 不校验 `@`、不限长度、不做 NFC/NFKC，理由见模块文档。
    pub fn normalize(raw: &str) -> Result<Self, EmailBlank> {
        let trimmed = trim_ecmascript(raw);
        if trimmed.is_empty() {
            return Err(EmailBlank);
        }
        Ok(Self(trimmed.to_lowercase()))
    }

    /// 借出底层字符串。已满足本类型的全部不变量。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// 交出底层字符串的所有权。
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for NormalizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl AsRef<str> for NormalizedEmail {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 参照值全部取自本轮实测的 Node 输出（`node -e 'c.trim().toLowerCase()'`），
    /// 不是推断出来的。
    #[test]
    fn normalization_matches_upstream_trim_then_lowercase() {
        let cases = [
            ("A@B.COM", "a@b.com"),
            ("  Mixed@Case.Com  ", "mixed@case.com"),
            ("İSTANBUL@x.com", "i\u{307}stanbul@x.com"),
            ("ΣΣ@x.com", "σς@x.com"),
            ("STRASSE@x.com", "strasse@x.com"),
            // 连字不被拆开：不做 NFKC。上游同样不做。
            ("ﬀ@x.com", "ﬀ@x.com"),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                NormalizedEmail::normalize(raw).unwrap().as_str(),
                expected,
                "输入 {raw:?} 的规范化结果必须与上游逐字节相同"
            );
        }
    }

    /// U+FEFF 被当作首尾空白去掉 —— 与 JS `trim()` 对齐。
    #[test]
    fn leading_bom_is_trimmed_like_javascript_does() {
        let email = NormalizedEmail::normalize("\u{FEFF}a@b.com").unwrap();
        assert_eq!(email.as_str(), "a@b.com");

        // 带 BOM 的 .env 首项是这条规则真正的用武之地：floor 上的地址必须仍能匹配到
        // 一个从 IdP 来的普通地址。
        let from_idp = NormalizedEmail::normalize("A@B.com").unwrap();
        assert_eq!(email, from_idp);

        let next_line = NormalizedEmail::normalize("\u{0085}A@B.COM\u{0085}").unwrap();
        assert_eq!(
            next_line.as_str(),
            "\u{0085}a@b.com\u{0085}",
            "ECMAScript trim 不认 U+0085，不能借 Rust White_Space 擅自扩大身份等价类"
        );
    }

    /// 负向对照：Rust 标准库的 `trim()` **不**去掉 U+FEFF。
    ///
    /// 没有这一条，上一条测试在「`trim()` 本来就会去掉 BOM」的世界里同样通过 ——
    /// 那样的话 [`trim_ecmascript`] 就是一段没有作用的代码，而测试照绿。
    #[test]
    fn rust_trim_alone_does_not_remove_the_bom() {
        assert_eq!(
            "\u{FEFF}a@b.com".trim(),
            "\u{FEFF}a@b.com",
            "标准库 trim 保留 U+FEFF；这正是本模块要显式多去一个码点的原因"
        );
        assert!(!'\u{FEFF}'.is_whitespace());
        // 正向对照：普通空白确实被标准库 trim 掉，所以上一条不是「trim 什么都不做」。
        assert_eq!(" a@b.com\t".trim(), "a@b.com");
    }

    /// 只有空是错误。
    #[test]
    fn only_blank_input_is_rejected() {
        for blank in ["", "   ", "\t\n", "\u{FEFF}", " \u{FEFF} \u{00A0}"] {
            assert_eq!(
                NormalizedEmail::normalize(blank),
                Err(EmailBlank),
                "{blank:?} 规范化后为空，必须拒绝"
            );
        }
    }

    /// 正向对照：上游会接受的那些「奇怪但真实」的地址，这里一个都不拒。
    ///
    /// 没有这一条，上一条测试在「什么都构造不出来」的世界里同样通过。
    #[test]
    fn upstream_accepted_oddities_are_not_rejected_here() {
        // 没有 @：上游 isConfiguredAdmin 是纯字符串比较，不校验。
        assert_eq!(
            NormalizedEmail::normalize("no-at-sign").unwrap().as_str(),
            "no-at-sign"
        );
        // 内部空白只有首尾被去：中间的原样保留。
        assert_eq!(
            NormalizedEmail::normalize("  a b@c.com ").unwrap().as_str(),
            "a b@c.com"
        );
        // 超长地址不被截断也不被拒绝：任何长度上限都会改变谁能登录。
        let long = format!("{}@x.com", "a".repeat(4096));
        assert_eq!(
            NormalizedEmail::normalize(&long).unwrap().as_str().len(),
            long.len()
        );
        // plus-tag 与点号原样保留：不折叠。
        assert_eq!(
            NormalizedEmail::normalize("Ops+Admin@X.com")
                .unwrap()
                .as_str(),
            "ops+admin@x.com"
        );
        assert_eq!(
            NormalizedEmail::normalize("a.b@gmail.com")
                .unwrap()
                .as_str(),
            "a.b@gmail.com"
        );
        // 两个只差 plus-tag / 点号的地址仍然是两个不同的人。
        assert_ne!(
            NormalizedEmail::normalize("ops+admin@x.com").unwrap(),
            NormalizedEmail::normalize("ops@x.com").unwrap()
        );
        assert_ne!(
            NormalizedEmail::normalize("a.b@gmail.com").unwrap(),
            NormalizedEmail::normalize("ab@gmail.com").unwrap()
        );
    }

    /// 幂等：这是「没有 `Deserialize` 也不带来不便」的依据 —— 从数据库读回来的值
    /// 再走一遍构造入口，结果不变。
    #[test]
    fn normalize_is_idempotent() {
        for raw in ["A@B.COM", " Ops+Admin@X.com ", "ΣΣ@x.com", "\u{FEFF}q@w.e"] {
            let once = NormalizedEmail::normalize(raw).unwrap();
            let twice = NormalizedEmail::normalize(once.as_str()).unwrap();
            assert_eq!(once, twice);
        }
    }

    /// 大小写不同的两条输入必须是**同一个键** —— `tbl-revoked-access` 那条 notes 的直接兑现。
    #[test]
    fn case_variants_collapse_to_one_deny_list_key() {
        let written = NormalizedEmail::normalize("Removed.Person@Example.COM").unwrap();
        let signing_in = NormalizedEmail::normalize("removed.person@example.com").unwrap();
        assert_eq!(
            written, signing_in,
            "撤权写入用的键与下次登录查的键必须相等，否则撤权在界面上显示成功而实际没生效"
        );

        // 负向对照：真正不同的两个地址不会被折成一个。
        let other = NormalizedEmail::normalize("someone.else@example.com").unwrap();
        assert_ne!(written, other);
    }

    #[test]
    fn code_and_display_agree() {
        assert_eq!(EmailBlank.to_string(), EmailBlank.code());
        assert_eq!(EmailBlank.code(), "identity_email_blank");
    }

    #[test]
    fn serialization_is_transparent() {
        let email = NormalizedEmail::normalize("A@B.com").unwrap();
        assert_eq!(serde_json::to_string(&email).unwrap(), "\"a@b.com\"");
        assert_eq!(email.to_string(), "a@b.com");
        assert_eq!(email.clone().into_inner(), "a@b.com");
    }

    /// 探测某类型是否实现了 `DeserializeOwned`。
    ///
    /// 手法与 `openbot_contracts::auth` 里那一对探测器相同：inherent 方法优先于 trait
    /// 方法，where 子句不满足的 inherent 候选在方法探测阶段被剔除，于是回落到 trait 的
    /// 默认实现 —— 「有没有实现某 trait」因此成为一个可断言的运行期布尔值。
    struct DeserializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> DeserializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait DeserializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> DeserializeProbeFallback for DeserializeProbe<T> {}

    /// 负向对照：`NormalizedEmail` 不可反序列化 —— 没有第二个构造入口。
    #[test]
    fn normalized_email_cannot_be_deserialized_into_existence() {
        assert!(
            !DeserializeProbe::<NormalizedEmail>::new().is_implemented(),
            "一旦可反序列化，`{{\"email\":\"A@B.COM\"}}` 就能造出违反不变量的值"
        );
        // 正向对照：同一个探测器在确实实现了 Deserialize 的类型上返回 true，
        // 证明它不是一个恒 false 的坏探测器。
        assert!(DeserializeProbe::<String>::new().is_implemented());
    }
}
