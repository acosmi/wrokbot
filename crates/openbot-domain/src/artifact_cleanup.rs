//! 已有成果记录的清理 fence 纯值；不执行或证明物理清理。
//!
//! 身份构造不证明 record 存在、当前权限或保留合同允许清理。`completed` 只是存储阶段
//! 的封闭表示，不能证明字节缺失、目录同步、reader 排空、退款或事务提交。

use openbot_contracts::artifacts::{
    ArtifactGoneStatus, canonical_artifact_uuid_v7, is_valid_artifact_identity,
};
use openbot_contracts::ids::{DeploymentId, TenantId};

use crate::artifact::ArtifactSaveOperationId;

/// 清理 fence 的脱敏形状错误，不携带身份、路径或数据库事实。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactCleanupFenceError {
    /// Namespace 不满足原 UTF-8 字节和全部 Cc 边界。
    #[error("artifact_cleanup_identity_invalid")]
    InvalidIdentity,
    /// UUID 形状错误，或存储文本不是规范小写 UUIDv7。
    #[error("artifact_cleanup_uuid_invalid")]
    InvalidUuid,
    /// 存储清理意图不在已有 deleted/expired 闭集中。
    #[error("artifact_cleanup_terminal_status_invalid")]
    InvalidTerminalStatus,
    /// 存储阶段不在 armed/completed 闭集中。
    #[error("artifact_cleanup_phase_invalid")]
    InvalidPhase,
    /// completed 不允许退回 armed。
    #[error("artifact_cleanup_phase_transition_invalid")]
    InvalidTransition,
}

/// 原 record 的完整五键；字段私有且不实现 Serde，不证明原 pair 存在。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactCleanupFenceKey {
    deployment_id: DeploymentId,
    tenant_id: TenantId,
    dataset_id: String,
    operation_id: ArtifactSaveOperationId,
    artifact_id: String,
}

impl core::fmt::Debug for ArtifactCleanupFenceKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArtifactCleanupFenceKey([redacted])")
    }
}

impl ArtifactCleanupFenceKey {
    /// 校验 namespace 并规范化 UUID 大小写；不铸造身份或观察权限。
    ///
    /// # Errors
    /// 身份必须为 1–512 UTF-8 bytes、无 Cc；artifact 必须是标准 UUIDv7。
    pub fn new(
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        dataset_id: &str,
        operation_id: ArtifactSaveOperationId,
        artifact_id: &str,
    ) -> Result<Self, ArtifactCleanupFenceError> {
        if ![deployment_id.as_str(), tenant_id.as_str(), dataset_id]
            .into_iter()
            .all(is_valid_artifact_identity)
        {
            return Err(ArtifactCleanupFenceError::InvalidIdentity);
        }
        let artifact_id = canonical_artifact_uuid_v7(artifact_id)
            .ok_or(ArtifactCleanupFenceError::InvalidUuid)?;
        Ok(Self {
            deployment_id,
            tenant_id,
            dataset_id: dataset_id.to_owned(),
            operation_id,
            artifact_id,
        })
    }

    /// 严格解码存储五键，先拒绝 UUID 别名，不将坏行规范化成好行。
    ///
    /// # Errors
    /// 返回身份形状或非规范 UUID 错误；namespace 文本原样保留。
    pub fn from_stored(
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        dataset_id: &str,
        operation_id: &str,
        artifact_id: &str,
    ) -> Result<Self, ArtifactCleanupFenceError> {
        if canonical_artifact_uuid_v7(operation_id).as_deref() != Some(operation_id)
            || canonical_artifact_uuid_v7(artifact_id).as_deref() != Some(artifact_id)
        {
            return Err(ArtifactCleanupFenceError::InvalidUuid);
        }
        let operation_id = ArtifactSaveOperationId::new(operation_id)
            .map_err(|_| ArtifactCleanupFenceError::InvalidUuid)?;
        Self::new(
            deployment_id,
            tenant_id,
            dataset_id,
            operation_id,
            artifact_id,
        )
    }

    /// 借出原 deployment 身份，不返回当前授权。
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    /// 借出原 tenant 身份，不证明归属。
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// 借出原 dataset 文本，不 trim 或归一化。
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// 借出已规范化的原 operation 值，不证明提交。
    #[must_use]
    pub const fn operation_id(&self) -> &ArtifactSaveOperationId {
        &self.operation_id
    }

    /// 借出规范 artifact 值，不证明记录或字节存在。
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
}

/// 内部存储阶段的封闭纯表示；不是新增成果 status 或清理成功回执。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCleanupFencePhase {
    /// 原清理意图待实际消费者落实。
    Armed,
    /// 数据库存储的完成阶段，不能据此证明物理缺失或退款。
    Completed,
}

impl ArtifactCleanupFencePhase {
    /// 严格解析存储阶段，不接受大小写、空白或自由扩展。
    ///
    /// # Errors
    /// 仅接受 armed 或 completed。
    pub fn from_stored(value: &str) -> Result<Self, ArtifactCleanupFenceError> {
        match value {
            "armed" => Ok(Self::Armed),
            "completed" => Ok(Self::Completed),
            _ => Err(ArtifactCleanupFenceError::InvalidPhase),
        }
    }

    /// 返回冻结的存储拼写，不构造公开 wire。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Completed => "completed",
        }
    }

    /// 纯阶段关系：允许完全 no-op 和 armed→completed，拒绝退回。
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        !matches!((self, next), (Self::Completed, Self::Armed))
    }
}

/// 不可重绑定的原清理意图；无 IO、时钟、随机、Serde 或删除权限。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactCleanupFence {
    key: ArtifactCleanupFenceKey,
    terminal_status: ArtifactGoneStatus,
    phase: ArtifactCleanupFencePhase,
}

impl ArtifactCleanupFence {
    /// 构造 armed 纯值，不写数据库或证明保留合同允许 expired。
    #[must_use]
    pub const fn armed(key: ArtifactCleanupFenceKey, terminal_status: ArtifactGoneStatus) -> Self {
        Self {
            key,
            terminal_status,
            phase: ArtifactCleanupFencePhase::Armed,
        }
    }

    /// 解码已校验五键上的封闭存储意图及阶段；不证明守卫实际执行。
    ///
    /// # Errors
    /// 清理意图或阶段文本必须恰为各自冻结拼写。
    pub fn from_stored(
        key: ArtifactCleanupFenceKey,
        terminal_status: &str,
        phase: &str,
    ) -> Result<Self, ArtifactCleanupFenceError> {
        let terminal_status = match terminal_status {
            "deleted" => ArtifactGoneStatus::Deleted,
            "expired" => ArtifactGoneStatus::Expired,
            _ => return Err(ArtifactCleanupFenceError::InvalidTerminalStatus),
        };
        Ok(Self {
            key,
            terminal_status,
            phase: ArtifactCleanupFencePhase::from_stored(phase)?,
        })
    }

    /// 借出不可变五键。
    #[must_use]
    pub const fn key(&self) -> &ArtifactCleanupFenceKey {
        &self.key
    }

    /// 借出不可变清理意图，复用既有 deleted/expired 枚举。
    #[must_use]
    pub const fn terminal_status(&self) -> ArtifactGoneStatus {
        self.terminal_status
    }

    /// 借出存储阶段，不返回真实清理结果。
    #[must_use]
    pub const fn phase(&self) -> ArtifactCleanupFencePhase {
        self.phase
    }

    /// 在原身份与意图上作纯阶段投影，不产生数据库或物理证明。
    ///
    /// # Errors
    /// completed→armed 返回错误；原值保持可用。
    pub fn with_phase(
        &self,
        next: ArtifactCleanupFencePhase,
    ) -> Result<Self, ArtifactCleanupFenceError> {
        if !self.phase.permits(next) {
            return Err(ArtifactCleanupFenceError::InvalidTransition);
        }
        Ok(Self {
            key: self.key.clone(),
            terminal_status: self.terminal_status,
            phase: next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION: &str = "018f03ae-1234-7abc-8def-123456789abc";
    const ARTIFACT: &str = "018f03ae-4321-7abc-9def-abcdef012345";

    fn key(deployment: &str, tenant: &str, dataset: &str) -> ArtifactCleanupFenceKey {
        ArtifactCleanupFenceKey::from_stored(
            DeploymentId::new(deployment),
            TenantId::new(tenant),
            dataset,
            OPERATION,
            ARTIFACT,
        )
        .unwrap()
    }

    #[test]
    fn identity_and_canonical_storage_boundaries() {
        let original = key(" d ", "t\u{200d}", "e\u{301}");
        assert_eq!(original.deployment_id().as_str(), " d ");
        assert_eq!(original.tenant_id().as_str(), "t\u{200d}");
        assert_eq!(original.dataset_id(), "e\u{301}");
        assert_ne!(original, key(" d ", "t\u{200d}", "é"));
        assert_eq!(original.operation_id().as_str(), OPERATION);
        assert_eq!(original.artifact_id(), ARTIFACT);
        assert!(!format!("{original:?}").contains(OPERATION));

        let unicode_boundary = "😀".repeat(128);
        let ascii_boundary = "x".repeat(512);
        for valid in [&unicode_boundary, &ascii_boundary] {
            assert_eq!(key(valid, valid, valid).dataset_id(), valid);
        }
        let oversized = unicode_boundary + "x";
        let mut invalid = vec![String::new(), oversized, "x".repeat(513)];
        invalid.extend(
            (0..=31)
                .chain(127..=159)
                .map(|code| format!("before{}after", char::from_u32(code).unwrap())),
        );
        for invalid in invalid {
            for part in 0..3 {
                let mut coordinates = ["d", "t", "dataset"];
                coordinates[part] = &invalid;
                assert_eq!(
                    ArtifactCleanupFenceKey::from_stored(
                        DeploymentId::new(coordinates[0]),
                        TenantId::new(coordinates[1]),
                        coordinates[2],
                        OPERATION,
                        ARTIFACT,
                    ),
                    Err(ArtifactCleanupFenceError::InvalidIdentity),
                );
            }
        }
        for invalid in [
            OPERATION.to_uppercase(),
            "018f03ae-1234-4abc-8def-123456789abc".to_owned(),
            "018f03ae12347abc8def123456789abc".to_owned(),
            format!(" {OPERATION}"),
        ] {
            assert_eq!(
                ArtifactCleanupFenceKey::from_stored(
                    DeploymentId::new("d"),
                    TenantId::new("t"),
                    "dataset",
                    &invalid,
                    ARTIFACT,
                ),
                Err(ArtifactCleanupFenceError::InvalidUuid),
            );
            assert_eq!(
                ArtifactCleanupFenceKey::from_stored(
                    DeploymentId::new("d"),
                    TenantId::new("t"),
                    "dataset",
                    OPERATION,
                    &invalid,
                ),
                Err(ArtifactCleanupFenceError::InvalidUuid),
            );
        }
        let canonicalized = ArtifactCleanupFenceKey::new(
            DeploymentId::new("d"),
            TenantId::new("t"),
            "dataset",
            ArtifactSaveOperationId::new(&OPERATION.to_uppercase()).unwrap(),
            &ARTIFACT.to_uppercase(),
        )
        .unwrap();
        assert_eq!(canonicalized, key("d", "t", "dataset"));
        assert_ne!(canonicalized, key("other", "t", "dataset"));
        assert_ne!(canonicalized, key("d", "other", "dataset"));
        assert_ne!(canonicalized, key("d", "t", "other"));
    }

    #[test]
    fn closed_phase_transition_preserves_intent() {
        for terminal in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
            let original = ArtifactCleanupFence::armed(key("d", "t", "dataset"), terminal);
            assert_eq!(original.phase(), ArtifactCleanupFencePhase::Armed);
            assert_eq!(
                original
                    .with_phase(ArtifactCleanupFencePhase::Armed)
                    .unwrap(),
                original
            );
            let completed = original
                .with_phase(ArtifactCleanupFencePhase::Completed)
                .unwrap();
            assert_eq!(completed.key(), original.key());
            assert_eq!(completed.terminal_status(), terminal);
            assert_eq!(
                completed
                    .with_phase(ArtifactCleanupFencePhase::Completed)
                    .unwrap(),
                completed
            );
            assert_eq!(
                completed.with_phase(ArtifactCleanupFencePhase::Armed),
                Err(ArtifactCleanupFenceError::InvalidTransition)
            );
            assert_eq!(
                ArtifactCleanupFence::from_stored(
                    original.key().clone(),
                    terminal.as_str(),
                    "armed"
                )
                .unwrap(),
                original
            );
            assert_eq!(
                ArtifactCleanupFence::from_stored(
                    original.key().clone(),
                    terminal.as_str(),
                    "completed"
                )
                .unwrap(),
                completed
            );
        }
        for invalid in ["", "Armed", "armed ", "pending", "complete"] {
            assert_eq!(
                ArtifactCleanupFencePhase::from_stored(invalid),
                Err(ArtifactCleanupFenceError::InvalidPhase)
            );
        }
        for invalid in ["", "Deleted", "deleted ", "failed_partial", "unresolved"] {
            assert_eq!(
                ArtifactCleanupFence::from_stored(key("d", "t", "dataset"), invalid, "armed"),
                Err(ArtifactCleanupFenceError::InvalidTerminalStatus)
            );
        }
        assert_eq!(ArtifactCleanupFencePhase::Armed.as_str(), "armed");
        assert_eq!(ArtifactCleanupFencePhase::Completed.as_str(), "completed");
    }
}
