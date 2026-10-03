//! R414 成果的固定预算、封闭取值与纯文本形状校验。
//!
//! 本模块不创建成果身份、不访问存储、不核当前 actor 权限。合法的身份、摘要或
//! [`ArtifactStatus::Available`] 取值都不能证明实际字节存在或当前可读；这些事实
//! 必须由后续存储、持久化和授权编排核验。预算是冻结上限，宿主只能收紧。

use serde::{Deserialize, Serialize};

/// R414 单成果冻结大小上限：64 MiB。
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
/// R414 单个读取块冻结大小上限：4 MiB。
pub const MAX_ARTIFACT_READ_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// R414 每个 Run 的成果数量上限。
pub const MAX_RUN_ARTIFACTS: u64 = 32;
/// R414 每个 workspace 的成果字节总量上限：16 GiB。
pub const MAX_WORKSPACE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// R414 一次性读取句柄的有效时长：600 秒；本常量不创建或验证句柄。
pub const ARTIFACT_READ_HANDLE_SECONDS: u64 = 600;
/// R414 单次后续工作引用的成果数量上限；重复成果须由领域校验拒绝。
pub const MAX_ARTIFACT_REFS: usize = 8;
/// R414 注入为不可信用户材料的单份文本字节上限：256 KiB。
pub const MAX_ARTIFACT_TEXT_BYTES: usize = 256 * 1024;
/// R414 注入为不可信用户材料的文本字节总量上限：1 MiB。
pub const MAX_ARTIFACT_TOTAL_TEXT_BYTES: usize = 1024 * 1024;
/// R414 opaque 身份文本的 UTF-8 字节上限；不包括任何 UUID 类型的另行形状约束。
pub const MAX_ARTIFACT_IDENTITY_BYTES: usize = 512;

/// R414 成果保留类别的封闭取值；类别本身不证明保存已获授权或提交。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionClass {
    /// 随所属 Run 历史保留合同处理的临时输出。
    RunOutput,
    /// 用户显式保存、保留至用户删除的成果。
    ExplicitSaved,
}

/// R414 成果记录状态的封闭取值；不作为实际可取字节或当前读取权的证据。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    /// 记录的可用状态；读取仍须重核实际存储对象和当前权限。
    Available,
    /// 未形成完整成果的失败状态，不发布可取链接。
    FailedPartial,
    /// 已删除，只保留合同允许的最小 tombstone。
    Deleted,
    /// 已到期，只保留合同允许的最小 tombstone。
    Expired,
}

/// 校验 opaque 身份的 1–512 UTF-8 字节与无 Unicode 控制字符规则。
///
/// 不修剪或规范化文本，不把 actor、Run 等 opaque 身份强制限定为 UUID，
/// 也不证明身份属于当前 deployment、workspace 或 actor。
#[must_use]
pub fn is_valid_artifact_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_IDENTITY_BYTES
        && !value.chars().any(char::is_control)
}

/// 校验标准 8-4-4-4-12 UUIDv7 文本形状与 RFC 变体位。
///
/// 接受合法大小写十六进制字符，不修剪或改写原文本。不接受紧凑、URN 或括号形式；
/// 本校验不铸造 UUID，不证明身份来自 Rust 生产者或具有成果读取权。
#[must_use]
pub fn is_uuid_v7_artifact_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    bytes[14] == b'7' && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

/// 校验恰好 64 个 ASCII 小写十六进制字符的 SHA-256 文本。
///
/// 不修剪、不折叠大小写；形状合法不表示摘要与实际字节一致。
#[must_use]
pub fn is_valid_artifact_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_storage_and_injection_budgets_match_r414_exactly() {
        assert_eq!(MAX_ARTIFACT_BYTES, 67_108_864);
        assert_eq!(MAX_ARTIFACT_READ_CHUNK_BYTES, 4_194_304);
        assert_eq!(MAX_RUN_ARTIFACTS, 32);
        assert_eq!(MAX_WORKSPACE_ARTIFACT_BYTES, 17_179_869_184);
        assert_eq!(ARTIFACT_READ_HANDLE_SECONDS, 600);
        assert_eq!(MAX_ARTIFACT_REFS, 8);
        assert_eq!(MAX_ARTIFACT_TEXT_BYTES, 262_144);
        assert_eq!(MAX_ARTIFACT_TOTAL_TEXT_BYTES, 1_048_576);
        assert_eq!(MAX_ARTIFACT_IDENTITY_BYTES, 512);
    }

    #[test]
    fn opaque_identity_bounds_use_utf8_bytes_including_the_inclusive_ceiling() {
        assert!(!is_valid_artifact_identity(""));
        for length in [1, 511, 512] {
            assert!(is_valid_artifact_identity(&"a".repeat(length)));
        }
        assert!(!is_valid_artifact_identity(&"a".repeat(513)));
        let chinese_boundary = format!("{}ab", "中".repeat(170));
        assert_eq!(chinese_boundary.len(), 512);
        assert!(is_valid_artifact_identity(&chinese_boundary));
        assert!(!is_valid_artifact_identity(&(chinese_boundary + "c")));
        let emoji_boundary = "😀".repeat(128);
        assert_eq!(emoji_boundary.len(), 512);
        assert_eq!(emoji_boundary.chars().count(), 128);
        assert!(is_valid_artifact_identity(&emoji_boundary));
        assert!(!is_valid_artifact_identity(&(emoji_boundary + "a")));
    }

    #[test]
    fn identities_reject_c0_del_and_unicode_c1_controls_in_every_position() {
        for code in (0..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            for value in [
                format!("{control}actor"),
                format!("act{control}or"),
                format!("actor{control}"),
            ] {
                assert!(!is_valid_artifact_identity(&value), "control U+{code:04X}");
            }
        }
    }

    #[test]
    fn opaque_actor_and_run_ids_remain_non_uuid_and_unmodified_text_values() {
        for value in [
            "actor:alice",
            "old/run-opaque",
            " run with spaces ",
            " ",
            "中😀",
            "é",
            "e\u{301}",
        ] {
            assert!(is_valid_artifact_identity(value));
            assert!(!is_uuid_v7_artifact_id(value));
        }
        // A format character is not a Unicode control character; the identity rule
        // does not introduce an additional normalization or format-character ban.
        assert!(is_valid_artifact_identity("emoji\u{200d}sequence"));
    }

    #[test]
    fn digest_shape_accepts_all_lowercase_hex_without_claiming_matching_bytes() {
        for value in ["0".repeat(64), "f".repeat(64), "09af".repeat(16)] {
            assert!(is_valid_artifact_sha256(&value));
        }
        // Both are syntactically valid even though they cannot both identify the
        // same content: equality to actual bytes belongs to the byte store.
        assert!(is_valid_artifact_sha256(&"0".repeat(64)));
        assert!(is_valid_artifact_sha256(&"1".repeat(64)));
    }

    #[test]
    fn digest_shape_rejects_length_aliases_and_does_not_trim_or_case_fold() {
        for value in [
            "".to_owned(),
            "a".repeat(63),
            "a".repeat(65),
            format!("0x{}", "a".repeat(64)),
            format!(" {}", "a".repeat(64)),
            format!("{} ", "a".repeat(64)),
            "A".repeat(64),
        ] {
            assert!(!is_valid_artifact_sha256(&value));
        }
    }

    #[test]
    fn digest_shape_rejects_non_ascii_and_non_hex_at_the_exact_byte_length() {
        for invalid in ['A', 'F', 'g', '-', ' ', '\n', '\0'] {
            let mut value = "a".repeat(64);
            value.replace_range(31..32, &invalid.to_string());
            assert_eq!(value.len(), 64);
            assert!(!is_valid_artifact_sha256(&value));
        }
        let lookalike = format!("{}a", "０".repeat(21));
        assert_eq!(lookalike.len(), 64);
        assert!(!is_valid_artifact_sha256(&lookalike));
        assert!(!is_valid_artifact_sha256(&"０".repeat(64)));
    }

    #[test]
    fn uuid_v7_text_accepts_mixed_hex_case_and_all_rfc_variant_nibbles() {
        for variant in ['8', '9', 'a', 'A', 'b', 'B'] {
            let value = format!("01890f3a-5B42-7aBc-{variant}123-012345aBcDef");
            assert!(is_uuid_v7_artifact_id(&value));
        }
    }

    #[test]
    fn uuid_v7_text_rejects_other_versions_nil_and_non_rfc_variants() {
        for value in [
            "00000000-0000-0000-0000-000000000000",
            "01890f3a-5b42-4abc-8123-012345abcdef",
            "01890f3a-5b42-8abc-8123-012345abcdef",
        ] {
            assert!(!is_uuid_v7_artifact_id(value));
        }
        for variant in [
            '0', '1', '2', '3', '4', '5', '6', '7', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F',
        ] {
            let value = format!("01890f3a-5b42-7abc-{variant}123-012345abcdef");
            assert!(!is_uuid_v7_artifact_id(&value));
        }
    }

    #[test]
    fn uuid_v7_text_rejects_non_standard_shapes_without_normalizing_them() {
        let valid = "01890f3a-5b42-7abc-8123-012345abcdef";
        for value in [
            "".to_owned(),
            valid.replace('-', ""),
            format!("urn:uuid:{valid}"),
            format!("{{{valid}}}"),
            format!(" {valid}"),
            format!("{valid} "),
            valid.replace("5b42", "5b4g"),
            valid.replacen('-', "f", 1),
            valid.replacen("5b42", "-b42", 1),
        ] {
            assert!(!is_uuid_v7_artifact_id(&value));
        }
        let non_ascii = valid.replacen("018", "中", 1);
        assert_eq!(non_ascii.len(), 36);
        assert!(!is_uuid_v7_artifact_id(&non_ascii));
    }

    #[test]
    fn retention_classes_roundtrip_with_only_the_two_registered_names() {
        for (value, text) in [
            (ArtifactRetentionClass::RunOutput, "run_output"),
            (ArtifactRetentionClass::ExplicitSaved, "explicit_saved"),
        ] {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(text)
            );
            assert_eq!(
                serde_json::from_value::<ArtifactRetentionClass>(serde_json::json!(text)).unwrap(),
                value
            );
        }
        for text in [
            "",
            "RunOutput",
            "runOutput",
            "run_output ",
            "saved",
            "permanent",
        ] {
            assert!(
                serde_json::from_value::<ArtifactRetentionClass>(serde_json::json!(text)).is_err()
            );
        }
    }

    #[test]
    fn artifact_statuses_roundtrip_with_only_the_four_registered_names() {
        for (value, text) in [
            (ArtifactStatus::Available, "available"),
            (ArtifactStatus::FailedPartial, "failed_partial"),
            (ArtifactStatus::Deleted, "deleted"),
            (ArtifactStatus::Expired, "expired"),
        ] {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(text)
            );
            assert_eq!(
                serde_json::from_value::<ArtifactStatus>(serde_json::json!(text)).unwrap(),
                value
            );
        }
        for text in [
            "",
            "Available",
            "failedPartial",
            "available ",
            "ready",
            "staging",
            "verified",
            "committed",
        ] {
            assert!(serde_json::from_value::<ArtifactStatus>(serde_json::json!(text)).is_err());
        }
    }

    #[test]
    fn enum_values_do_not_decode_as_actor_or_storage_proof_records() {
        for proof in [
            serde_json::json!({"status":"available", "actor":"alice"}),
            serde_json::json!({"available":{"sha256":"0".repeat(64), "path":"/untrusted"}}),
            serde_json::json!({"available":null,"verified":true}),
        ] {
            assert!(serde_json::from_value::<ArtifactStatus>(proof).is_err());
        }
        assert!(
            serde_json::from_value::<ArtifactRetentionClass>(
                serde_json::json!({"retention_class":"explicit_saved", "saved_by":"alice"})
            )
            .is_err()
        );
        // The plain enum value remains decodable without actor or storage context.
        // It therefore conveys only its closed value, never an authorization proof.
        assert_eq!(
            serde_json::from_value::<ArtifactStatus>(serde_json::json!("available")).unwrap(),
            ArtifactStatus::Available
        );
    }
}
