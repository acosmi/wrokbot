//! 成果记录的纯输入形状、有界算术与 workspace 值（R414 / R423）。
//!
//! 本模块不读时钟、文件或数据库。来源序号、保存者和时间通过形状检查，不证明这些
//! 事实确实发生；标识检查也不证明对象存在、当前可见或可读。引用解析与当前授权必须
//! 由外层独立核验，不能把本模块的成功结果解释为读取许可。
//!
//! 配额投影只对调用方给出的计数与计费字节做算术。它不预留配额、不验证实际磁盘余量
//! 或字节，且不定义 failed_partial、孤立字节或 Unknown 应如何计费。
//! 文本预算只检查字节长度，不解码 UTF-8、不分类媒体类型，也不构造模型消息。

use openbot_contracts::artifacts::{
    ArtifactRetentionClass, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_REFS, MAX_ARTIFACT_TEXT_BYTES,
    MAX_ARTIFACT_TOTAL_TEXT_BYTES, MAX_RUN_ARTIFACTS, MAX_WORKSPACE_ARTIFACT_BYTES,
    is_valid_artifact_identity,
};
use time::OffsetDateTime;

/// 成果纯不变量的脱敏错误；不保存标识、路径、正文或权限事实，也不映射 HTTP 状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactInvariantError {
    /// Host policy 提供的单成果上限扩大了冻结预算。
    #[error("artifact policy exceeds byte ceiling")]
    ArtifactPolicyExceedsCeiling,
    /// Host policy 提供的每 Run 数量上限扩大了冻结预算。
    #[error("artifact policy exceeds run count ceiling")]
    RunPolicyExceedsCeiling,
    /// Host policy 提供的 workspace 字节上限扩大了冻结预算。
    #[error("artifact policy exceeds workspace byte ceiling")]
    WorkspacePolicyExceedsCeiling,
    /// 新成果的声明长度超过本 policy 的上限。
    #[error("artifact byte limit exceeded")]
    ArtifactByteLimitExceeded,
    /// Run 数量加一不能用 u64 表示。
    #[error("artifact run count overflow")]
    RunCountOverflow,
    /// Workspace 计费字节相加不能用 u64 表示。
    #[error("artifact workspace bytes overflow")]
    WorkspaceBytesOverflow,
    /// 投影后的 Run 数量超过本 policy 的上限。
    #[error("artifact run count limit exceeded")]
    RunCountLimitExceeded,
    /// 投影后的 workspace 计费字节超过本 policy 的上限。
    #[error("artifact workspace byte limit exceeded")]
    WorkspaceByteLimitExceeded,
    /// 工具产生的成果缺少完整来源序号。
    #[error("artifact tool source sequences required")]
    ToolSourceSequencesRequired,
    /// 来源 call/attempt 只提供了一个值。
    #[error("artifact source sequence pair incomplete")]
    IncompleteSourceSequencePair,
    /// 来源 call/attempt 中至少一个值为负数。
    #[error("artifact source sequence negative")]
    NegativeSourceSequence,
    /// run_output 不允许携带显式保存字段。
    #[error("artifact save provenance unexpected")]
    UnexpectedSaveProvenance,
    /// explicit_saved 缺少保存者或保存时间。
    #[error("artifact save provenance incomplete")]
    IncompleteSaveProvenance,
    /// 保存者标识不满足有界身份文本规则。
    #[error("artifact saving actor invalid")]
    InvalidSavingActor,
    /// Workspace 身份不满足有界身份文本规则。
    #[error("artifact workspace identity invalid")]
    InvalidWorkspaceIdentity,
    /// 引用列表超过冻结数量上限。
    #[error("artifact reference count limit exceeded")]
    ReferenceCountLimitExceeded,
    /// 引用标识不满足有界身份文本规则。
    #[error("artifact reference invalid")]
    InvalidReference,
    /// 引用列表出现逐字节相同的标识。
    #[error("artifact reference duplicate")]
    DuplicateReference,
    /// 文本长度列表超过成果引用数量上限。
    #[error("artifact text count limit exceeded")]
    TextCountLimitExceeded,
    /// 一项文本声明长度超过冻结单项上限。
    #[error("artifact text byte limit exceeded")]
    TextByteLimitExceeded,
    /// 文本字节合计不能用 usize 表示。
    #[error("artifact text total bytes overflow")]
    TextTotalOverflow,
    /// 文本字节合计超过冻结总上限。
    #[error("artifact text total byte limit exceeded")]
    TextTotalByteLimitExceeded,
}

/// R423 workspace 的封闭种类；同一身份文本在两个种类下属于不同键。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactWorkspaceKind {
    /// Channel 来源使用其当前 anchor_id。
    Channel,
    /// direct_bot 来源使用其当前 thread_id，不使用 Bot anchor_id。
    Thread,
}

impl ArtifactWorkspaceKind {
    /// 物理配额键中的封闭 kind 文本；不解析自由字符串。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Thread => "thread",
        }
    }
}

/// R423 的有界 workspace 值；相等、排序与 hash 同时包含 kind 和原始身份文本。
///
/// 只保证身份文本为 1–512 UTF-8 bytes 且无控制字符，不做 trim 或归一化。
/// 私有字段阻止绕过构造校验；本类型不实现 Serde，也不证明来源、dataset 或当前权限。
/// 来源种类和身份必须由外层按当前 PG 事实解析，不能从客户端提交值取得权限。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactWorkspaceKey {
    kind: ArtifactWorkspaceKind,
    id: String,
}

impl ArtifactWorkspaceKey {
    /// 先校验身份边界，再原样复制；kind 与文本共同组成键，不推断任何来源事实。
    pub fn new(kind: ArtifactWorkspaceKind, id: &str) -> Result<Self, ArtifactInvariantError> {
        if !is_valid_artifact_identity(id) {
            return Err(ArtifactInvariantError::InvalidWorkspaceIdentity);
        }
        Ok(Self {
            kind,
            id: id.to_owned(),
        })
    }

    /// 构造 Channel(anchor_id) 的有界值；不证明 anchor 属于当前可见来源。
    pub fn channel(anchor_id: &str) -> Result<Self, ArtifactInvariantError> {
        Self::new(ArtifactWorkspaceKind::Channel, anchor_id)
    }

    /// 构造 Thread(thread_id) 的有界值；不把 direct_bot 的 Bot anchor 当 workspace。
    pub fn thread(thread_id: &str) -> Result<Self, ArtifactInvariantError> {
        Self::new(ArtifactWorkspaceKind::Thread, thread_id)
    }

    /// 借出键的封闭种类。
    #[must_use]
    pub const fn kind(&self) -> ArtifactWorkspaceKind {
        self.kind
    }

    /// 借出原始身份文本；不附加 kind 前缀、不修剪、不归一化。
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Host 成果配额；私有字段保证构造时只能收紧 R414 冻结上限。
///
/// 零上限有效：单成果或 workspace 为零时仍允许零字节的算术投影，Run 数量为零时
/// 拒绝任何新增身份。该 policy 不决定具体状态如何计费，也不承担事务序列化。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactQuotaPolicy {
    max_artifact_bytes: u64,
    max_run_artifacts: u64,
    max_workspace_artifact_bytes: u64,
}

impl Default for ArtifactQuotaPolicy {
    fn default() -> Self {
        Self {
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            max_run_artifacts: MAX_RUN_ARTIFACTS,
            max_workspace_artifact_bytes: MAX_WORKSPACE_ARTIFACT_BYTES,
        }
    }
}

impl ArtifactQuotaPolicy {
    /// 按三个独立上限构造；任一值超过冻结预算即拒绝，不隐式裁剪。
    pub const fn new(
        max_artifact_bytes: u64,
        max_run_artifacts: u64,
        max_workspace_artifact_bytes: u64,
    ) -> Result<Self, ArtifactInvariantError> {
        if max_artifact_bytes > MAX_ARTIFACT_BYTES {
            return Err(ArtifactInvariantError::ArtifactPolicyExceedsCeiling);
        }
        if max_run_artifacts > MAX_RUN_ARTIFACTS {
            return Err(ArtifactInvariantError::RunPolicyExceedsCeiling);
        }
        if max_workspace_artifact_bytes > MAX_WORKSPACE_ARTIFACT_BYTES {
            return Err(ArtifactInvariantError::WorkspacePolicyExceedsCeiling);
        }
        Ok(Self {
            max_artifact_bytes,
            max_run_artifacts,
            max_workspace_artifact_bytes,
        })
    }

    /// 本 policy 的单成果声明字节上限。
    #[must_use]
    pub const fn max_artifact_bytes(self) -> u64 {
        self.max_artifact_bytes
    }

    /// 本 policy 的每 Run 成果身份数量上限。
    #[must_use]
    pub const fn max_run_artifacts(self) -> u64 {
        self.max_run_artifacts
    }

    /// 本 policy 的 workspace 计费字节上限。
    #[must_use]
    pub const fn max_workspace_artifact_bytes(self) -> u64 {
        self.max_workspace_artifact_bytes
    }

    /// 为一个新增身份计算数量和计费字节的纯投影；用 checked_add 拒绝溢出。
    ///
    /// 当前计数和新增字节均由调用方提供。本结果不证明输入来自权威存储或实际验证，
    /// 不代表数据库预留或提交；调用方必须在其事务边界内独立取得并消费这些事实。
    pub fn project_registration(
        self,
        current_run_identities: u64,
        current_workspace_charged_bytes: u64,
        new_bytes: u64,
    ) -> Result<ArtifactProjectedUsage, ArtifactInvariantError> {
        if new_bytes > self.max_artifact_bytes {
            return Err(ArtifactInvariantError::ArtifactByteLimitExceeded);
        }
        let run_identities = current_run_identities
            .checked_add(1)
            .ok_or(ArtifactInvariantError::RunCountOverflow)?;
        let workspace_charged_bytes = current_workspace_charged_bytes
            .checked_add(new_bytes)
            .ok_or(ArtifactInvariantError::WorkspaceBytesOverflow)?;
        if run_identities > self.max_run_artifacts {
            return Err(ArtifactInvariantError::RunCountLimitExceeded);
        }
        if workspace_charged_bytes > self.max_workspace_artifact_bytes {
            return Err(ArtifactInvariantError::WorkspaceByteLimitExceeded);
        }
        Ok(ArtifactProjectedUsage {
            run_identities,
            workspace_charged_bytes,
        })
    }
}

/// 配额算术的结果；不含事务、授权或实际字节核验凭据。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactProjectedUsage {
    run_identities: u64,
    workspace_charged_bytes: u64,
}

impl ArtifactProjectedUsage {
    /// 加入一个身份后的 Run 身份数。
    #[must_use]
    pub const fn run_identities(self) -> u64 {
        self.run_identities
    }

    /// 加入声明字节后的 workspace 计费字节数。
    #[must_use]
    pub const fn workspace_charged_bytes(self) -> u64 {
        self.workspace_charged_bytes
    }
}

/// 校验来源 call/attempt 的完整非负配对；工具来源必填，用户来源允许全空。
///
/// 来源类型独立于 retention_class，本函数不把 explicit_saved 推断为用户来源，
/// 也不核实序号对应的工具尝试确实存在。
pub fn validate_artifact_source_sequences(
    tool_produced: bool,
    source_call_seq: Option<i64>,
    source_attempt_seq: Option<i64>,
) -> Result<(), ArtifactInvariantError> {
    match (source_call_seq, source_attempt_seq) {
        (None, None) if tool_produced => Err(ArtifactInvariantError::ToolSourceSequencesRequired),
        (None, None) => Ok(()),
        (Some(call), Some(attempt)) if call >= 0 && attempt >= 0 => Ok(()),
        (Some(_), Some(_)) => Err(ArtifactInvariantError::NegativeSourceSequence),
        _ => Err(ArtifactInvariantError::IncompleteSourceSequencePair),
    }
}

/// 校验显式保存字段的形状；run_output 全空，explicit_saved 必须同时有合法保存者与时间。
///
/// 调用方提供的时间不与时钟比较；成功不证明实际 actor 身份、显式意图或保存动作。
pub fn validate_artifact_save_provenance(
    retention_class: ArtifactRetentionClass,
    saved_by: Option<&str>,
    saved_at: Option<OffsetDateTime>,
) -> Result<(), ArtifactInvariantError> {
    match (retention_class, saved_by, saved_at) {
        (ArtifactRetentionClass::RunOutput, None, None) => Ok(()),
        (ArtifactRetentionClass::RunOutput, _, _) => {
            Err(ArtifactInvariantError::UnexpectedSaveProvenance)
        }
        (ArtifactRetentionClass::ExplicitSaved, Some(actor), Some(_)) => {
            if is_valid_artifact_identity(actor) {
                Ok(())
            } else {
                Err(ArtifactInvariantError::InvalidSavingActor)
            }
        }
        (ArtifactRetentionClass::ExplicitSaved, _, _) => {
            Err(ArtifactInvariantError::IncompleteSaveProvenance)
        }
    }
}

/// 校验最多八个原始引用的有界标识形状，逐字节重复即拒绝。
///
/// 不 trim、不归一化、不替换标识；标识按有界 opaque 身份规则检查，不要求 UUID。
/// 同一 UUID 的大小写别名可通过本形状阶段；后续必须按解析后的真实成果身份再次去重。
/// 成功不证明引用存在、available 或当前可读；未知/无权对象仍须在后续查找时统一拒绝。
pub fn validate_artifact_refs(refs: &[String]) -> Result<(), ArtifactInvariantError> {
    if refs.len() > MAX_ARTIFACT_REFS {
        return Err(ArtifactInvariantError::ReferenceCountLimitExceeded);
    }
    for (index, id) in refs.iter().enumerate() {
        if !is_valid_artifact_identity(id) {
            return Err(ArtifactInvariantError::InvalidReference);
        }
        if refs[..index].iter().any(|previous| previous == id) {
            return Err(ArtifactInvariantError::DuplicateReference);
        }
    }
    Ok(())
}

/// 校验最多八项文本的声明字节长度，返回合计；超限拒绝，无截断。
///
/// 每项最多 256 KiB，合计最多 1 MiB。本函数不接触正文，不做 MIME/UTF-8 判定，
/// 也不证明模型端实际以不可信用户材料消息消费这些字节。
pub fn validate_artifact_text_budget(
    text_byte_lengths: &[usize],
) -> Result<usize, ArtifactInvariantError> {
    if text_byte_lengths.len() > MAX_ARTIFACT_REFS {
        return Err(ArtifactInvariantError::TextCountLimitExceeded);
    }
    let mut total = 0usize;
    for &length in text_byte_lengths {
        if length > MAX_ARTIFACT_TEXT_BYTES {
            return Err(ArtifactInvariantError::TextByteLimitExceeded);
        }
        total = total
            .checked_add(length)
            .ok_or(ArtifactInvariantError::TextTotalOverflow)?;
        if total > MAX_ARTIFACT_TOTAL_TEXT_BYTES {
            return Err(ArtifactInvariantError::TextTotalByteLimitExceeded);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_kind_separates_identical_channel_and_thread_ids() {
        let channel = ArtifactWorkspaceKey::channel("shared-text").unwrap();
        let thread = ArtifactWorkspaceKey::thread("shared-text").unwrap();
        assert_eq!(channel.id(), thread.id());
        assert_ne!(channel, thread);
        assert_eq!(channel.kind(), ArtifactWorkspaceKind::Channel);
        assert_eq!(thread.kind(), ArtifactWorkspaceKind::Thread);
        assert_eq!(channel.kind().as_str(), "channel");
        assert_eq!(thread.kind().as_str(), "thread");
        assert_eq!(
            channel,
            ArtifactWorkspaceKey::new(ArtifactWorkspaceKind::Channel, "shared-text").unwrap()
        );
        assert_eq!(
            thread,
            ArtifactWorkspaceKey::new(ArtifactWorkspaceKind::Thread, "shared-text").unwrap()
        );
        let distinct = std::collections::BTreeSet::from([channel.clone(), thread, channel]);
        assert_eq!(distinct.len(), 2);
    }

    #[test]
    fn workspace_identity_bounds_count_utf8_bytes_for_both_kinds() {
        let chinese_boundary = "界".repeat(170) + "ab";
        let emoji_boundary = "😀".repeat(128);
        assert_eq!(chinese_boundary.len(), 512);
        assert_eq!(emoji_boundary.len(), 512);
        for kind in [
            ArtifactWorkspaceKind::Channel,
            ArtifactWorkspaceKind::Thread,
        ] {
            for id in [
                "a".to_owned(),
                "a".repeat(511),
                "a".repeat(512),
                chinese_boundary.clone(),
                emoji_boundary.clone(),
            ] {
                let key = ArtifactWorkspaceKey::new(kind, &id).unwrap();
                assert_eq!(key.kind(), kind);
                assert_eq!(key.id(), id);
            }
            for id in [
                "".to_owned(),
                "a".repeat(513),
                "界".repeat(171),
                emoji_boundary.clone() + "a",
            ] {
                assert_eq!(
                    ArtifactWorkspaceKey::new(kind, &id),
                    Err(ArtifactInvariantError::InvalidWorkspaceIdentity)
                );
            }
        }
    }

    #[test]
    fn workspace_constructors_reject_unicode_controls_with_sanitized_errors() {
        for code in (0..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            let id = format!("private-workspace{control}private-path");
            for result in [
                ArtifactWorkspaceKey::channel(&id),
                ArtifactWorkspaceKey::thread(&id),
            ] {
                let error = result.unwrap_err();
                assert_eq!(error, ArtifactInvariantError::InvalidWorkspaceIdentity);
                assert_eq!(error.to_string(), "artifact workspace identity invalid");
                assert_eq!(format!("{error:?}"), "InvalidWorkspaceIdentity");
            }
        }
    }

    #[test]
    fn workspace_identity_remains_raw_without_normalization_or_inferred_kind() {
        for kind in [
            ArtifactWorkspaceKind::Channel,
            ArtifactWorkspaceKind::Thread,
        ] {
            for id in [
                " ",
                " anchor ",
                "opaque:not-uuid",
                "thread:anchor",
                "é",
                "e\u{301}",
                "值\u{200d}名",
            ] {
                let key = ArtifactWorkspaceKey::new(kind, id).unwrap();
                assert_eq!(key.id(), id);
                assert_eq!(key.kind(), kind);
            }
            assert_ne!(
                ArtifactWorkspaceKey::new(kind, "anchor").unwrap(),
                ArtifactWorkspaceKey::new(kind, " anchor ").unwrap()
            );
            assert_ne!(
                ArtifactWorkspaceKey::new(kind, "é").unwrap(),
                ArtifactWorkspaceKey::new(kind, "e\u{301}").unwrap()
            );
            assert_ne!(
                ArtifactWorkspaceKey::new(kind, "Anchor").unwrap(),
                ArtifactWorkspaceKey::new(kind, "anchor").unwrap()
            );
        }
    }

    #[test]
    fn quota_default_uses_frozen_budgets() {
        let policy = ArtifactQuotaPolicy::default();
        assert_eq!(policy.max_artifact_bytes(), 64 * 1024 * 1024);
        assert_eq!(policy.max_run_artifacts(), 32);
        assert_eq!(
            policy.max_workspace_artifact_bytes(),
            16 * 1024 * 1024 * 1024
        );
        assert_eq!(
            policy,
            ArtifactQuotaPolicy::new(
                MAX_ARTIFACT_BYTES,
                MAX_RUN_ARTIFACTS,
                MAX_WORKSPACE_ARTIFACT_BYTES,
            )
            .unwrap()
        );
    }

    #[test]
    fn quota_policy_cannot_widen_any_frozen_budget() {
        for (artifact, run, workspace, expected) in [
            (
                MAX_ARTIFACT_BYTES + 1,
                0,
                0,
                ArtifactInvariantError::ArtifactPolicyExceedsCeiling,
            ),
            (
                0,
                MAX_RUN_ARTIFACTS + 1,
                0,
                ArtifactInvariantError::RunPolicyExceedsCeiling,
            ),
            (
                0,
                0,
                MAX_WORKSPACE_ARTIFACT_BYTES + 1,
                ArtifactInvariantError::WorkspacePolicyExceedsCeiling,
            ),
            (
                u64::MAX,
                0,
                0,
                ArtifactInvariantError::ArtifactPolicyExceedsCeiling,
            ),
            (
                0,
                u64::MAX,
                0,
                ArtifactInvariantError::RunPolicyExceedsCeiling,
            ),
            (
                0,
                0,
                u64::MAX,
                ArtifactInvariantError::WorkspacePolicyExceedsCeiling,
            ),
        ] {
            assert_eq!(
                ArtifactQuotaPolicy::new(artifact, run, workspace),
                Err(expected)
            );
        }
    }

    #[test]
    fn tightened_quota_applies_all_three_limits() {
        let policy = ArtifactQuotaPolicy::new(8, 2, 10).unwrap();
        let exact = policy.project_registration(1, 2, 8).unwrap();
        assert_eq!(exact.run_identities(), 2);
        assert_eq!(exact.workspace_charged_bytes(), 10);
        assert_eq!(
            policy.project_registration(0, 0, 9),
            Err(ArtifactInvariantError::ArtifactByteLimitExceeded)
        );
        assert_eq!(
            policy.project_registration(2, 0, 0),
            Err(ArtifactInvariantError::RunCountLimitExceeded)
        );
        assert_eq!(
            policy.project_registration(0, 3, 8),
            Err(ArtifactInvariantError::WorkspaceByteLimitExceeded)
        );
    }

    #[test]
    fn quota_zero_limits_do_not_gain_an_identity_or_nonzero_bytes() {
        let all_zero = ArtifactQuotaPolicy::new(0, 0, 0).unwrap();
        assert_eq!(
            all_zero.project_registration(0, 0, 0),
            Err(ArtifactInvariantError::RunCountLimitExceeded)
        );
        let empty_only = ArtifactQuotaPolicy::new(0, 1, 0).unwrap();
        let usage = empty_only.project_registration(0, 0, 0).unwrap();
        assert_eq!(usage.run_identities(), 1);
        assert_eq!(usage.workspace_charged_bytes(), 0);
        assert_eq!(
            empty_only.project_registration(0, 0, 1),
            Err(ArtifactInvariantError::ArtifactByteLimitExceeded)
        );
    }

    #[test]
    fn quota_frozen_boundaries_accept_exactly_and_reject_one_over() {
        let policy = ArtifactQuotaPolicy::default();
        let exact = policy
            .project_registration(
                31,
                MAX_WORKSPACE_ARTIFACT_BYTES - MAX_ARTIFACT_BYTES,
                MAX_ARTIFACT_BYTES,
            )
            .unwrap();
        assert_eq!(exact.run_identities(), 32);
        assert_eq!(
            exact.workspace_charged_bytes(),
            MAX_WORKSPACE_ARTIFACT_BYTES
        );
        assert_eq!(
            policy.project_registration(0, 0, MAX_ARTIFACT_BYTES + 1),
            Err(ArtifactInvariantError::ArtifactByteLimitExceeded)
        );
        assert_eq!(
            policy.project_registration(32, 0, 0),
            Err(ArtifactInvariantError::RunCountLimitExceeded)
        );
        assert_eq!(
            policy.project_registration(0, MAX_WORKSPACE_ARTIFACT_BYTES, 1),
            Err(ArtifactInvariantError::WorkspaceByteLimitExceeded)
        );
    }

    #[test]
    fn quota_checked_arithmetic_rejects_extreme_supplied_usage() {
        let policy = ArtifactQuotaPolicy::default();
        assert_eq!(
            policy.project_registration(u64::MAX, 0, 0),
            Err(ArtifactInvariantError::RunCountOverflow)
        );
        assert_eq!(
            policy.project_registration(0, u64::MAX, 1),
            Err(ArtifactInvariantError::WorkspaceBytesOverflow)
        );
        assert_eq!(
            policy.project_registration(0, u64::MAX, 0),
            Err(ArtifactInvariantError::WorkspaceByteLimitExceeded)
        );
    }

    #[test]
    fn source_sequences_allow_zero_and_maximum_for_both_origins() {
        for tool_produced in [false, true] {
            assert_eq!(
                validate_artifact_source_sequences(tool_produced, Some(0), Some(0)),
                Ok(())
            );
            assert_eq!(
                validate_artifact_source_sequences(tool_produced, Some(i64::MAX), Some(i64::MAX)),
                Ok(())
            );
            assert_eq!(
                validate_artifact_source_sequences(tool_produced, Some(0), Some(i64::MAX)),
                Ok(())
            );
        }
        assert_eq!(
            validate_artifact_source_sequences(false, None, None),
            Ok(())
        );
        assert_eq!(
            validate_artifact_source_sequences(true, None, None),
            Err(ArtifactInvariantError::ToolSourceSequencesRequired)
        );
    }

    #[test]
    fn source_sequences_reject_half_pairs_and_either_negative_value() {
        for tool_produced in [false, true] {
            for (call, attempt) in [
                (Some(0), None),
                (None, Some(0)),
                (Some(-1), None),
                (None, Some(-1)),
            ] {
                assert_eq!(
                    validate_artifact_source_sequences(tool_produced, call, attempt),
                    Err(ArtifactInvariantError::IncompleteSourceSequencePair)
                );
            }
            for (call, attempt) in [(-1, 0), (0, -1), (i64::MIN, i64::MAX), (-1, -1)] {
                assert_eq!(
                    validate_artifact_source_sequences(tool_produced, Some(call), Some(attempt)),
                    Err(ArtifactInvariantError::NegativeSourceSequence)
                );
            }
        }
    }

    #[test]
    fn run_output_rejects_every_save_field_combination_except_all_empty() {
        assert_eq!(
            validate_artifact_save_provenance(ArtifactRetentionClass::RunOutput, None, None),
            Ok(())
        );
        for (actor, time) in [
            (Some("actor"), None),
            (None, Some(OffsetDateTime::UNIX_EPOCH)),
            (Some("actor"), Some(OffsetDateTime::UNIX_EPOCH)),
        ] {
            assert_eq!(
                validate_artifact_save_provenance(ArtifactRetentionClass::RunOutput, actor, time),
                Err(ArtifactInvariantError::UnexpectedSaveProvenance)
            );
        }
    }

    #[test]
    fn explicit_saved_requires_the_pair_and_bounded_actor_shape() {
        for (actor, time) in [
            (None, None),
            (Some("actor"), None),
            (None, Some(OffsetDateTime::UNIX_EPOCH)),
        ] {
            assert_eq!(
                validate_artifact_save_provenance(
                    ArtifactRetentionClass::ExplicitSaved,
                    actor,
                    time
                ),
                Err(ArtifactInvariantError::IncompleteSaveProvenance)
            );
        }
        let overlong = "a".repeat(513);
        for actor in ["", "actor\n", "actor\u{0085}", overlong.as_str()] {
            assert_eq!(
                validate_artifact_save_provenance(
                    ArtifactRetentionClass::ExplicitSaved,
                    Some(actor),
                    Some(OffsetDateTime::UNIX_EPOCH)
                ),
                Err(ArtifactInvariantError::InvalidSavingActor)
            );
        }
        let boundary = "界".repeat(170) + "ab";
        assert_eq!(boundary.len(), 512);
        assert_eq!(
            validate_artifact_save_provenance(
                ArtifactRetentionClass::ExplicitSaved,
                Some(&boundary),
                Some(OffsetDateTime::UNIX_EPOCH)
            ),
            Ok(())
        );
    }

    #[test]
    fn source_origin_and_retention_shape_are_independent() {
        // 工具来源可以显式保存；仅通过形状检查，不提供保存者或历史事实证明。
        assert_eq!(
            validate_artifact_source_sequences(true, Some(1), Some(2)),
            Ok(())
        );
        assert_eq!(
            validate_artifact_save_provenance(
                ArtifactRetentionClass::ExplicitSaved,
                Some("用户"),
                Some(OffsetDateTime::UNIX_EPOCH)
            ),
            Ok(())
        );
        // 用户来源可以带完整工具序号，也可以全空，不能按 retention 推断来源。
        assert_eq!(
            validate_artifact_source_sequences(false, Some(1), Some(2)),
            Ok(())
        );
        assert_eq!(
            validate_artifact_source_sequences(false, None, None),
            Ok(())
        );
        assert_eq!(
            validate_artifact_save_provenance(ArtifactRetentionClass::RunOutput, None, None),
            Ok(())
        );
    }

    #[test]
    fn refs_are_raw_opaque_identifiers_and_preserve_byte_distinctions() {
        let refs = [
            "成果:α",
            "α",
            " α",
            "α ",
            "é",
            "e\u{301}",
            "opaque:not-uuid",
            " ",
        ]
        .map(str::to_owned);
        let original = refs.clone();
        assert_eq!(validate_artifact_refs(&refs), Ok(()));
        assert_eq!(refs, original);
        assert_eq!(validate_artifact_refs(&[]), Ok(()));
        // 原始字节不同不证明成果不同；真实记录查找后的身份去重由后续编排负责。
        let lower_uuid = "01890f3a-5b42-7abc-8123-012345abcdef".to_owned();
        let uuid_aliases = [lower_uuid.clone(), lower_uuid.to_ascii_uppercase()];
        assert_eq!(validate_artifact_refs(&uuid_aliases), Ok(()));
    }

    #[test]
    fn refs_reject_exact_duplicate_and_ninth_item() {
        let duplicate = ["成果:α".to_owned(), "成果:α".to_owned()];
        assert_eq!(
            validate_artifact_refs(&duplicate),
            Err(ArtifactInvariantError::DuplicateReference)
        );
        let refs: Vec<String> = (0..9).map(|i| format!("opaque-{i}")).collect();
        assert_eq!(
            validate_artifact_refs(&refs),
            Err(ArtifactInvariantError::ReferenceCountLimitExceeded)
        );
    }

    #[test]
    fn refs_reject_empty_controls_and_utf8_bytes_over_the_boundary() {
        for id in [
            "".to_owned(),
            "id\0".to_owned(),
            "id\u{007f}".to_owned(),
            "id\u{009f}".to_owned(),
            "界".repeat(171),
        ] {
            assert_eq!(
                validate_artifact_refs(&[id]),
                Err(ArtifactInvariantError::InvalidReference)
            );
        }
        let boundary = "界".repeat(170) + "ab";
        assert_eq!(validate_artifact_refs(&[boundary]), Ok(()));
    }

    #[test]
    fn text_budget_accepts_zero_exact_item_total_and_count_boundaries() {
        assert_eq!(validate_artifact_text_budget(&[]), Ok(0));
        assert_eq!(validate_artifact_text_budget(&[0; 8]), Ok(0));
        assert_eq!(
            validate_artifact_text_budget(&[MAX_ARTIFACT_TEXT_BYTES]),
            Ok(256 * 1024)
        );
        assert_eq!(
            validate_artifact_text_budget(&[MAX_ARTIFACT_TEXT_BYTES; 4]),
            Ok(1024 * 1024)
        );
        assert_eq!(
            validate_artifact_text_budget(&[128 * 1024; 8]),
            Ok(1024 * 1024)
        );
    }

    #[test]
    fn text_budget_rejects_oversized_items_totals_and_counts_without_truncation() {
        assert_eq!(
            validate_artifact_text_budget(&[MAX_ARTIFACT_TEXT_BYTES + 1]),
            Err(ArtifactInvariantError::TextByteLimitExceeded)
        );
        assert_eq!(
            validate_artifact_text_budget(&[usize::MAX]),
            Err(ArtifactInvariantError::TextByteLimitExceeded)
        );
        let lengths = [
            MAX_ARTIFACT_TEXT_BYTES,
            MAX_ARTIFACT_TEXT_BYTES,
            MAX_ARTIFACT_TEXT_BYTES,
            MAX_ARTIFACT_TEXT_BYTES,
            1,
        ];
        assert_eq!(
            validate_artifact_text_budget(&lengths),
            Err(ArtifactInvariantError::TextTotalByteLimitExceeded)
        );
        assert_eq!(lengths[4], 1);
        assert_eq!(
            validate_artifact_text_budget(&[0; 9]),
            Err(ArtifactInvariantError::TextCountLimitExceeded)
        );
    }

    #[test]
    fn errors_contain_static_codes_without_the_rejected_input() {
        let private_actor = "private-actor\nprivate-path";
        let error = validate_artifact_save_provenance(
            ArtifactRetentionClass::ExplicitSaved,
            Some(private_actor),
            Some(OffsetDateTime::UNIX_EPOCH),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "artifact saving actor invalid");
        assert_eq!(format!("{error:?}"), "InvalidSavingActor");
        let private_ref = "private-reference\nprivate-body".to_owned();
        let error = validate_artifact_refs(&[private_ref]).unwrap_err();
        assert_eq!(error.to_string(), "artifact reference invalid");
        assert_eq!(format!("{error:?}"), "InvalidReference");
    }
}
