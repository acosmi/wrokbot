//! R414/R425 私有实际读取的完整初始化 RAII 缓冲；不是公开 byte wire。

use crate::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES;
use crate::auth::AuthContext;
use crate::request_binding::{
    ArtifactReadCurrentError, ArtifactReadCurrentTarget, ArtifactReadTailWitness,
    VerifiedHostRequestBinding,
};
use zeroize::{Zeroize, Zeroizing};

/// 等待真实当前 handoff 的全4MiB清零缓冲；worker 不返回裸正文 Vec。
pub struct PendingArtifactReadBuffer {
    bytes: Zeroizing<Vec<u8>>,
    actual_length: Option<usize>,
    failed: bool,
}
impl PendingArtifactReadBuffer {
    /// 精确初始化冻结的4MiB；实际长度登记不截短清零范围。
    pub fn new_initialized() -> Result<Self, ArtifactReadCurrentError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_ARTIFACT_READ_CHUNK_BYTES)
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        bytes.resize(MAX_ARTIFACT_READ_CHUNK_BYTES, 0);
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            actual_length: None,
            failed: false,
        })
    }
    /// 只供受信实际 blocking reader 写入；不是出站正文 getter。
    #[doc(hidden)]
    pub fn initialized_mut(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }
    /// 登记当次真实 IO 长度，仅一次；错误永久拒绝这个 pending 缓冲。
    #[doc(hidden)]
    pub fn record_actual_length(&mut self, length: usize) -> Result<(), ArtifactReadCurrentError> {
        if self.failed || self.actual_length.is_some() || length > MAX_ARTIFACT_READ_CHUNK_BYTES {
            self.wipe();
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        self.actual_length = Some(length);
        Ok(())
    }
    /// 实际已完成 IO 的长度元数据；不公开正文。
    #[must_use]
    pub const fn actual_length(&self) -> Option<usize> {
        self.actual_length
    }
    /// 清零整个初始化 allocation 并永久拒绝复用；Drop 亦通过 Zeroizing 清零。
    pub fn wipe(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.actual_length = None;
        self.failed = true;
    }
    /// 唯一受信正文释放：原 binding/真实 FD/真实宿主尾检后同步移交。
    #[doc(hidden)]
    pub fn handoff(
        mut self,
        auth: &AuthContext,
        original: &VerifiedHostRequestBinding,
        target: &dyn ArtifactReadCurrentTarget,
        witness: &dyn ArtifactReadTailWitness,
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, ArtifactReadCurrentError> {
        let length = self
            .actual_length
            .filter(|_| !self.failed)
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        self.bytes[length..].zeroize();
        original.verify_artifact_read_tail(auth, target, witness, deadline)?;
        // All checks and suffix clearing precede the sole successful raw Vec extraction.
        let mut bytes = std::mem::take(&mut *self.bytes);
        bytes.truncate(length);
        Ok(bytes)
    }
}

/// 原allocation的生产库存凭证；成功交付仅改变phase，Drop才释放在途槽。
pub trait ArtifactReadAllocationLease: Send + Sync {
    /// Validate and mark the original pending allocation handed off without releasing its lease.
    fn mark_handed_off(&self) -> Result<(), ArtifactReadCurrentError>;
}

/// 保留完整初始化allocation的非Clone正文借用；无Vec提取或可变出口。
pub struct LeasedArtifactReadBlock {
    bytes: Zeroizing<Vec<u8>>,
    actual_length: usize,
    lease: Option<Box<dyn ArtifactReadAllocationLease>>,
}
impl LeasedArtifactReadBlock {
    /// Borrow the actual observed prefix while retaining the original full initialized allocation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.actual_length]
    }
    /// Return the actual observed prefix length, excluding the retained initialized suffix.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.actual_length
    }
    /// Report whether the actual observed prefix is empty; this does not release its allocation.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.actual_length == 0
    }
}
impl Drop for LeasedArtifactReadBlock {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        lifecycle_tests::observe_live_wiped(&self.bytes);
        // Observe only live wiped memory, then actually end allocation ownership before
        // releasing the slot. A concurrently admitted next block cannot overlap this owner.
        drop(std::mem::take(&mut self.bytes));
        drop(self.lease.take());
    }
}
impl PendingArtifactReadBuffer {
    /// 同一真实allocation先与lease共同入RAII，再执行所有可能失败的检查。
    #[doc(hidden)]
    pub fn handoff_leased(
        mut self,
        auth: &AuthContext,
        original: &VerifiedHostRequestBinding,
        target: &dyn ArtifactReadCurrentTarget,
        witness: &dyn ArtifactReadTailWitness,
        deadline: std::time::Instant,
        lease: Box<dyn ArtifactReadAllocationLease>,
    ) -> Result<LeasedArtifactReadBlock, ArtifactReadCurrentError> {
        let recorded = self.actual_length;
        let failed = self.failed;
        let mut block = LeasedArtifactReadBlock {
            bytes: Zeroizing::new(std::mem::take(&mut *self.bytes)),
            actual_length: 0,
            lease: Some(lease),
        };
        let length = recorded
            .filter(|length| !failed && *length <= MAX_ARTIFACT_READ_CHUNK_BYTES)
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        block.bytes[length..].zeroize();
        original.verify_artifact_read_tail(auth, target, witness, deadline)?;
        block
            .lease
            .as_ref()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .mark_handed_off()?;
        block.actual_length = length;
        Ok(block)
    }
}

#[cfg(test)]
#[path = "artifact_read/lifecycle_tests.rs"]
mod lifecycle_tests;
