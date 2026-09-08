//! Thread ID 的 deployment fingerprint 布局（v3 §20.3）。
//!
//! 固定上游 `thread-identity.ts` 把 `SHA-256(DEPLOYMENT_ID)` 的前六字节写进 UUID，随后
//! 将 version/variant 位设成 RFC 9562 UUIDv8。随机数不属于契约层：调用方提供完整 16 字节
//! entropy，本模块只做纯布局与 `owns()` 判定，因此 native/WASM 得到逐字相同的答案。

use sha2::{Digest, Sha256};

use super::{DeploymentId, ThreadId};

const FINGERPRINT_BYTES: usize = 6;
const UUID_BYTES: usize = 16;
const UUID_V8: u8 = 0x80;
const UUID_VERSION_MASK: u8 = 0xf0;
const UUID_VARIANT_RFC: u8 = 0x80;
const UUID_VARIANT_MASK: u8 = 0x3f;

/// 一个 deployment 的 thread ID 布局器。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadIdentity {
    fingerprint: [u8; FINGERPRINT_BYTES],
}

impl ThreadIdentity {
    /// 从权威 deployment id 派生六字节公开 fingerprint。
    #[must_use]
    pub fn new(deployment: &DeploymentId) -> Self {
        let digest = Sha256::digest(deployment.as_str().as_bytes());
        let mut fingerprint = [0_u8; FINGERPRINT_BYTES];
        fingerprint.copy_from_slice(&digest[..FINGERPRINT_BYTES]);
        Self { fingerprint }
    }

    /// 把调用方提供的 16 字节 CSPRNG entropy 布局成 UUIDv8 thread id。
    ///
    /// 本函数不自行读取 OS 随机源；生产 issuer 必须在 infra 层以 CSPRNG 填满 `entropy`。
    #[must_use]
    pub fn mint_from_entropy(&self, mut entropy: [u8; UUID_BYTES]) -> ThreadId {
        entropy[..FINGERPRINT_BYTES].copy_from_slice(&self.fingerprint);
        entropy[6] = (entropy[6] & !UUID_VERSION_MASK) | UUID_V8;
        entropy[8] = (entropy[8] & UUID_VARIANT_MASK) | UUID_VARIANT_RFC;
        ThreadId::new(format_uuid(entropy))
    }

    /// 判断一个既有 string ID 是否是本 deployment 铸造的 UUIDv8。
    ///
    /// 非 UUID、非 v8 或 fingerprint 不同都返回 `false`；兼容端不会因此拒绝把该 string
    /// 作为普通 [`ThreadId`] 解码，只是不把它归为本 deployment 所有。
    #[must_use]
    pub fn owns(&self, thread: &ThreadId) -> bool {
        let Some(bytes) = parse_uuid(thread.as_str()) else {
            return false;
        };
        bytes[6] & UUID_VERSION_MASK == UUID_V8 && bytes[..FINGERPRINT_BYTES] == self.fingerprint
    }

    /// 只检查 thread ID 是否是标准的 8-4-4-4-12 UUID 文本，不要求由当前 deployment 铸造。
    ///
    /// 状态查询必须兼容另一个 deployment 或旧版铸造的 UUID；因此不能用 [`Self::owns`]
    /// 做输入校验。另一方面，完全不是 UUID 的字符串不应到达持久化查询（固定上游
    /// `PLAUSIBLE_THREAD_ID` 判据）。把解析器留在这里可避免 contracts/application 各写一份。
    #[must_use]
    pub fn is_plausible(thread: &ThreadId) -> bool {
        parse_uuid(thread.as_str()).is_some()
    }
}

fn format_uuid(bytes: [u8; UUID_BYTES]) -> String {
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            output.push('-');
        }
        use core::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("写 String 不失败");
    }
    output
}

fn parse_uuid(value: &str) -> Option<[u8; UUID_BYTES]> {
    if value.len() != 36 {
        return None;
    }
    let bytes = value.as_bytes();
    if [8, 13, 18, 23]
        .into_iter()
        .any(|index| bytes.get(index) != Some(&b'-'))
    {
        return None;
    }
    let mut decoded = [0_u8; UUID_BYTES];
    let mut nibble = 0usize;
    for byte in bytes.iter().copied().filter(|byte| *byte != b'-') {
        let value = hex_value(byte)?;
        let target = &mut decoded[nibble / 2];
        if nibble.is_multiple_of(2) {
            *target = value << 4;
        } else {
            *target |= value;
        }
        nibble += 1;
    }
    (nibble == UUID_BYTES * 2).then_some(decoded)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here() -> ThreadIdentity {
        ThreadIdentity::new(&DeploymentId::new("openbot-production"))
    }

    fn elsewhere() -> ThreadIdentity {
        ThreadIdentity::new(&DeploymentId::new("openbot-staging"))
    }

    fn entropy(index: u64) -> [u8; UUID_BYTES] {
        let mut value = [0_u8; UUID_BYTES];
        value[8..].copy_from_slice(&index.to_be_bytes());
        value
    }

    #[test]
    fn it_is_a_well_formed_uuid_which_is_all_the_platform_accepts() {
        let minted = here().mint_from_entropy(entropy(1));
        assert_eq!(minted.as_str().len(), 36);
        assert!(parse_uuid(minted.as_str()).is_some());
        // 独立 shell oracle：printf openbot-production | shasum -a 256 => b8484487c5e4…
        assert_eq!(
            here().mint_from_entropy([0; UUID_BYTES]).as_str(),
            "b8484487-c5e4-8000-8000-000000000000"
        );
    }

    #[test]
    fn it_declares_the_custom_layout_rather_than_claiming_to_be_random() {
        assert_eq!(
            here().mint_from_entropy(entropy(2)).as_str().as_bytes()[14],
            b'8'
        );
    }

    #[test]
    fn a_deployment_recognises_its_own() {
        for index in 0..50 {
            assert!(here().owns(&here().mint_from_entropy(entropy(index))));
        }
    }

    #[test]
    fn and_does_not_claim_another_deployments() {
        for index in 0..50 {
            assert!(!here().owns(&elsewhere().mint_from_entropy(entropy(index))));
            assert!(!elsewhere().owns(&here().mint_from_entropy(entropy(index))));
        }
    }

    #[test]
    fn the_same_name_recognises_threads_minted_by_another_process() {
        let minted = here().mint_from_entropy(entropy(7));
        assert!(ThreadIdentity::new(&DeploymentId::new("openbot-production")).owns(&minted));
    }

    #[test]
    fn ids_differ_so_the_tag_has_not_eaten_the_randomness() {
        let minted: std::collections::BTreeSet<_> = (0..1_000)
            .map(|index| here().mint_from_entropy(entropy(index)).into_inner())
            .collect();
        assert_eq!(minted.len(), 1_000);
    }

    #[test]
    fn a_thread_minted_before_deployments_had_names_is_not_claimed() {
        assert!(!here().owns(&ThreadId::new("550e8400-e29b-41d4-a716-446655440000")));
    }

    #[test]
    fn anything_that_is_not_a_uuid_is_refused_rather_than_parsed() {
        for value in [
            "",
            "not-a-uuid",
            "openbot-connection-test-123",
            "377529b0-9a52-4fe3-bfaa-b99a3886710",
            "377529b0-9a52-4fe3-bfaa-b99a3886710e-extra",
            "zzzzzzzz-9a52-4fe3-bfaa-b99a3886710e",
        ] {
            assert!(!here().owns(&ThreadId::new(value)));
        }
    }

    #[test]
    fn plausibility_accepts_legacy_and_foreign_uuid_without_claiming_ownership() {
        let legacy = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        assert!(ThreadIdentity::is_plausible(&legacy));
        assert!(!here().owns(&legacy));
        assert!(!ThreadIdentity::is_plausible(&ThreadId::new("not-a-uuid")));
    }
}
