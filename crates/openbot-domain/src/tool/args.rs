//! 工具实参的规范化摘要（§8.5 的 `canonical args hash`）。
//!
//! # 这个摘要在承重什么
//!
//! approval 绑定了 `canonical args hash`（§8.5），"任一字段变化…都使 approval 失效"。
//! 于是这个函数的**两个方向各自对应一种事故**：
//!
//! | 失效方向 | 后果 | 严重度 |
//! | --- | --- | --- |
//! | 同一组实参算出**不同**摘要 | 用户刚批准的操作又要再批一次 | 烦人 |
//! | 不同实参算出**相同**摘要 | 一份对 A 的批准被用来执行 B | **P0** |
//!
//! 两者不对称，所以设计取向也不对称：**宁可多判几次"变了"，绝不能判错一次"没变"。**
//! 下面每一处取舍都按这条来。
//!
//! # JSON 的歧义，以及为什么不能直接 `to_string()` 再 hash
//!
//! `serde_json::Value::to_string()` 的输出取决于键在 `Map` 里的迭代顺序。`serde_json`
//! 默认用 `BTreeMap`（键已排序），但**打开 `preserve_order` feature 后就变成插入序**。
//! 也就是说，"同一组实参不同键序是否同 hash"这个问题的答案，会取决于依赖树上某个别的 crate
//! 有没有顺手打开那个 feature —— 这正是本仓反复判定为"不是闸门"的形态：答案取决于环境。
//!
//! 所以本模块**显式排序**，不依赖 `Map` 的迭代顺序；并且不走 JSON 文本，而是走
//! [`crate::audit::hash::CanonicalWriter`] 的长度前缀框式编码，理由与审计行完全一致
//! （朴素拼接会让 `{"a":"bc"}` 与 `{"ab":"c"}` 撞在一起）。
//!
//! # 几处刻意**不做**归一化
//!
//! - **`1` 与 `1.0` 算不同。** JSON 文本里它们是两个不同的字面量，把它们归一成同一个值
//!   会往"不同实参同 hash"那个方向走一步。反方向的代价只是同一批参数换了写法要重批一次。
//! - **`0.0` 与 `-0.0` 算不同。** 同上，按位编码。
//! - **不做 Unicode 归一化（NFC/NFKC）。** 视觉相同而码点不同的两个字符串是两个不同的实参，
//!   NFKC 甚至会把 `"ﬁ"` 变成 `"fi"` —— 那是在制造碰撞。
//! - **不 trim、不改大小写。** 同上。
//!
//! 唯一做的归一化就是**对象键排序**，因为 JSON 对象在规范上是无序的，键序不携带语义。

use serde_json::Value;

use crate::audit::hash::{CanonicalWriter, Sha256Digest};

/// 实参规范编码的域名标签。与审计行、checkpoint 各不相同，见 [`crate::audit::hash`]。
pub const TOOL_ARGS_DOMAIN: &str = "openbot.tool.args.v1";

/// 一次工具调用的实参。
///
/// **必须是 JSON 对象**：工具的入参 schema 在 MCP 与各家 provider 的 function calling 里
/// 都是对象，一个顶层数组或裸标量说明调用方送错了东西。这条在构造时判，而不是留到执行时
/// 才发现 —— §15.3「malformed payload 不产生 acting decision」要求畸形输入在写任何
/// decision 之前就停下。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolArguments {
    value: Value,
    /// 缓存的 JSON 序列化字节数。
    ///
    /// 存下来而不是每次现算：它同时被大小闸门与审计 payload 消费，两处各算一次就会得到
    /// 两个可能不一致的数字，而"审计里记的长度不等于闸门判的长度"是排查时最难看出的一种
    /// 不一致。
    byte_len: usize,
}

impl ToolArguments {
    /// 由 JSON 值构造。
    ///
    /// # Errors
    ///
    /// 不是 JSON 对象时返回 [`ToolArgumentsError::NotAnObject`]。
    pub fn new(value: Value) -> Result<Self, ToolArgumentsError> {
        if !value.is_object() {
            return Err(ToolArgumentsError::NotAnObject);
        }
        let byte_len = value.to_string().len();
        Ok(Self { value, byte_len })
    }

    /// 借出底层 JSON。
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.value
    }

    /// 序列化后的字节数，用于 [`super::metadata::ToolLimits::max_input_bytes`] 判定。
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// 规范编码的字节。
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new(TOOL_ARGS_DOMAIN);
        write_value(&mut writer, &self.value);
        writer.finish()
    }

    /// 规范化摘要 —— §8.5 绑定进 approval 的那一个。
    #[must_use]
    pub fn canonical_hash(&self) -> Sha256Digest {
        let mut writer = CanonicalWriter::new(TOOL_ARGS_DOMAIN);
        write_value(&mut writer, &self.value);
        writer.digest_of_written()
    }
}

/// 实参构造失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolArgumentsError {
    /// 顶层不是 JSON 对象。
    #[error("tool_arguments_not_an_object")]
    NotAnObject,
}

/// JSON 类型标签。**先写标签再写值**，于是 `"1"`（字符串）与 `1`（数字）不可能同编码。
mod tag {
    pub const NULL: u8 = 0;
    pub const FALSE: u8 = 1;
    pub const TRUE: u8 = 2;
    pub const NUMBER_U64: u8 = 3;
    pub const NUMBER_I64: u8 = 4;
    pub const NUMBER_F64: u8 = 5;
    pub const STRING: u8 = 6;
    pub const ARRAY: u8 = 7;
    pub const OBJECT: u8 = 8;
}

fn write_value(writer: &mut CanonicalWriter, value: &Value) {
    match value {
        Value::Null => writer.tag(tag::NULL),
        Value::Bool(false) => writer.tag(tag::FALSE),
        Value::Bool(true) => writer.tag(tag::TRUE),
        Value::Number(number) => {
            // 三条分支按 u64 → i64 → f64 试。顺序固定，于是同一个字面量恒走同一条分支；
            // 分支各带自己的标签，于是 `1`（整数）与 `1.0`（浮点）编出的字节不同。
            if let Some(unsigned) = number.as_u64() {
                writer.tag(tag::NUMBER_U64);
                writer.u64(unsigned);
            } else if let Some(signed) = number.as_i64() {
                writer.tag(tag::NUMBER_I64);
                writer.i128(i128::from(signed));
            } else {
                writer.tag(tag::NUMBER_F64);
                // 按位编码：`0.0` 与 `-0.0` 因此不同。JSON 里不存在 NaN / Inf，
                // `as_f64` 在这条分支上必有值；真取不到时用 0.0 的位型兜底，那是一个
                // 确定性的值，不会引入"同一输入两次不同摘要"。
                let bits = number.as_f64().unwrap_or(0.0).to_bits();
                writer.u64(bits);
            }
        }
        Value::String(text) => {
            writer.tag(tag::STRING);
            writer.str(text);
        }
        Value::Array(items) => {
            writer.tag(tag::ARRAY);
            // 先写元素个数：`[[1],[2]]` 与 `[[1,2]]` 因此不同。
            writer.u64(items.len() as u64);
            for item in items {
                write_value(writer, item);
            }
        }
        Value::Object(map) => {
            writer.tag(tag::OBJECT);
            writer.u64(map.len() as u64);
            // **显式排序**，不依赖 Map 的迭代顺序 —— 理由见模块文档（`preserve_order`）。
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for key in keys {
                writer.str(key);
                write_value(writer, &map[key]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn args(value: Value) -> ToolArguments {
        ToolArguments::new(value).expect("测试用实参应当是对象")
    }

    #[test]
    fn arguments_must_be_a_json_object() {
        assert_eq!(
            ToolArguments::new(json!([1, 2])),
            Err(ToolArgumentsError::NotAnObject)
        );
        assert_eq!(
            ToolArguments::new(json!("text")),
            Err(ToolArgumentsError::NotAnObject)
        );
        assert_eq!(
            ToolArguments::new(Value::Null),
            Err(ToolArgumentsError::NotAnObject)
        );
        // 正向对照：空对象是合法实参（"这个工具不需要参数"）。
        assert!(ToolArguments::new(json!({})).is_ok());
    }

    /// **同一组实参、不同键序 → 同一个 hash。** §8.5 的第一条要求。
    #[test]
    fn key_order_does_not_change_the_hash() {
        let forward = args(json!({"a": 1, "b": 2, "c": {"x": 1, "y": 2}}));
        let backward = args(json!({"c": {"y": 2, "x": 1}, "b": 2, "a": 1}));
        assert_eq!(forward.canonical_hash(), backward.canonical_hash());
    }

    /// **不同实参 → 不同 hash。** §8.5 的第二条要求，也是两个方向里危险的那个。
    ///
    /// 逐类覆盖：值变、键变、类型变、嵌套结构变、数组序变、以及"把同样的字符切在不同
    /// 边界上"这一经典碰撞形态。
    #[test]
    fn different_arguments_never_share_a_hash() {
        let baseline = args(json!({"a": 1}));
        let variants = [
            (json!({"a": 2}), "值变了"),
            (json!({"b": 1}), "键变了"),
            (json!({"a": "1"}), "数字变字符串"),
            (json!({"a": 1.0}), "整数变浮点"),
            (json!({"a": true}), "变布尔"),
            (json!({"a": null}), "变 null"),
            (json!({"a": [1]}), "变数组"),
            (json!({"a": {"": 1}}), "变对象"),
            (json!({"a": 1, "b": null}), "多一个键"),
            (json!({}), "少一个键"),
        ];
        for (variant, why) in variants {
            assert_ne!(
                baseline.canonical_hash(),
                args(variant).canonical_hash(),
                "{why} 之后 hash 不该相同"
            );
        }
    }

    /// 框式编码的单射性：把同样的字符切在不同的键 / 值边界上。
    ///
    /// 朴素拼接会把这两组编成同一串，那样一份对 `{"ab": "c"}` 的批准就能拿去执行
    /// `{"a": "bc"}`。
    #[test]
    fn field_boundaries_cannot_be_shifted_without_changing_the_hash() {
        assert_ne!(
            args(json!({"ab": "c"})).canonical_hash(),
            args(json!({"a": "bc"})).canonical_hash()
        );
        assert_ne!(
            args(json!({"a": "b", "c": "d"})).canonical_hash(),
            args(json!({"a": "bc", "": "d"})).canonical_hash()
        );
    }

    /// 数组的结构变化必须改变 hash：元素个数前缀在承重。
    #[test]
    fn array_structure_is_part_of_the_hash() {
        assert_ne!(
            args(json!({"a": [[1], [2]]})).canonical_hash(),
            args(json!({"a": [[1, 2]]})).canonical_hash()
        );
        // 数组是**有序**的，换序即换实参。
        assert_ne!(
            args(json!({"a": [1, 2]})).canonical_hash(),
            args(json!({"a": [2, 1]})).canonical_hash()
        );
    }

    /// `0.0` 与 `-0.0`：按位编码，算不同。
    ///
    /// 方向是"多判一次变了"，属于安全的那一侧。
    #[test]
    fn signed_zero_is_not_normalised_away() {
        let positive = args(json!({"a": 0.0}));
        let negative = args(json!({"a": -0.0}));
        assert_ne!(positive.canonical_hash(), negative.canonical_hash());
    }

    /// 不做 Unicode 归一化：码点不同即实参不同。
    #[test]
    fn unicode_is_not_normalised() {
        // U+00E9 与 "e" + U+0301：NFC 下相等，这里必须不等。
        assert_ne!(
            args(json!({"a": "\u{e9}"})).canonical_hash(),
            args(json!({"a": "e\u{301}"})).canonical_hash()
        );
    }

    /// 同一份实参重复计算必须稳定 —— 否则每次都要重新批准。
    #[test]
    fn the_hash_is_stable_across_calls_and_clones() {
        let subject = args(json!({"url": "https://example.invalid/a", "deep": {"n": [1, 2, 3]}}));
        assert_eq!(subject.canonical_hash(), subject.canonical_hash());
        assert_eq!(subject.canonical_hash(), subject.clone().canonical_hash());
    }

    /// 域名标签把实参摘要与审计行摘要隔开：内容再像也撞不上。
    #[test]
    fn the_args_domain_is_separate_from_other_digests() {
        let subject = args(json!({}));
        let mut foreign = CanonicalWriter::new("openbot.audit.row.v1");
        write_value(&mut foreign, subject.as_value());
        assert_ne!(subject.canonical_hash(), foreign.digest_of_written());
    }

    #[test]
    fn byte_len_reflects_the_serialised_form() {
        assert_eq!(args(json!({})).byte_len(), 2);
        assert_eq!(
            args(json!({"a": 1})).byte_len(),
            json!({"a": 1}).to_string().len()
        );
    }
}
