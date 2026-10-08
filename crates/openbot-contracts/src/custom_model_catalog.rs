//! 当前用户自定义模型目录的封闭 DTO 与不可序列化的请求交付身份。

use std::fmt;
use std::sync::{Arc, Weak};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model_connections::{CustomModelProtocol, ModelConnectionSource};

/// 当前用户目录单页上限；仓储另读取一条 lookahead。
pub const CUSTOM_MODEL_CATALOG_PAGE_SIZE: usize = 100;
/// 目录响应编码的硬字节上限；不是数据库或进程总内存上限。
pub const MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES: usize = 256 * 1024;

/// 原始 UUID keyset 游标；typed 调用也必须重新验证。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomModelCatalogPageRequest {
    /// 排他的原 connection ID；`None` 表示首页。
    pub cursor: Option<String>,
}

impl CustomModelCatalogPageRequest {
    /// 只接受小写 canonical UUID36，不做归一化。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.cursor.as_deref().is_none_or(canonical_uuid)
    }
}

impl<'de> Deserialize<'de> for CustomModelCatalogPageRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            cursor: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            cursor: wire.cursor,
        };
        if !value.is_valid() {
            return Err(serde::de::Error::custom(
                "invalid_custom_model_catalog_cursor",
            ));
        }
        Ok(value)
    }
}

/// 一项已验证的版本化自定义模型定义；不携带凭据或 Ready。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomModelCatalogEntry {
    /// 只表达已实现的 custom 来源。
    pub source: ModelConnectionSource,
    /// 小写 canonical UUID36。
    pub connection_id: String,
    /// 原连接独立正版本。
    pub connection_revision: i64,
    /// 精确为 `custom:` 加原 connection ID。
    pub model_id: String,
    /// 原目录独立正版本。
    pub catalog_revision: i64,
    /// 用户显示名称，最多100 UTF-8字节。
    pub name: String,
    /// 已实现的三个兼容协议之一。
    pub protocol: CustomModelProtocol,
    /// Provider 模型名称，最多512 UTF-8字节。
    pub model: String,
    /// disabled 项仍显示，且不授予发送权限。
    pub enabled: bool,
}

impl CustomModelCatalogEntry {
    /// 重验原字节，不 trim、修复或合并两个版本。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.source == ModelConnectionSource::Custom
            && canonical_uuid(&self.connection_id)
            && self.connection_revision > 0
            && self.catalog_revision > 0
            && self.model_id.len() == 43
            && self.model_id.strip_prefix("custom:") == Some(self.connection_id.as_str())
            && bounded_text(&self.name, 100)
            && bounded_text(&self.model, 512)
    }
}

impl<'de> Deserialize<'de> for CustomModelCatalogEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            source: ModelConnectionSource,
            connection_id: String,
            connection_revision: i64,
            model_id: String,
            catalog_revision: i64,
            name: String,
            protocol: CustomModelProtocol,
            model: String,
            enabled: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            source: wire.source,
            connection_id: wire.connection_id,
            connection_revision: wire.connection_revision,
            model_id: wire.model_id,
            catalog_revision: wire.catalog_revision,
            name: wire.name,
            protocol: wire.protocol,
            model: wire.model,
            enabled: wire.enabled,
        };
        if !value.is_valid() {
            return Err(serde::de::Error::custom(
                "invalid_custom_model_catalog_entry",
            ));
        }
        Ok(value)
    }
}

/// 当前 owner 的有序目录页；本 DTO 自身不是交付见证。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomModelCatalogPage {
    /// 至多100项，connection ID 严格升序。
    pub models: Vec<CustomModelCatalogEntry>,
    /// 有 lookahead 时为本页第100项的原 ID，否则为 `None`。
    pub next_cursor: Option<String>,
}

impl CustomModelCatalogPage {
    /// 验证全部实际返回项、有序唯一性和游标关系。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.models.len() <= CUSTOM_MODEL_CATALOG_PAGE_SIZE
            && self.models.iter().all(CustomModelCatalogEntry::is_valid)
            && self
                .models
                .windows(2)
                .all(|pair| pair[0].connection_id < pair[1].connection_id)
            && self.next_cursor.as_deref().is_none_or(|cursor| {
                self.models.len() == CUSTOM_MODEL_CATALOG_PAGE_SIZE
                    && canonical_uuid(cursor)
                    && self
                        .models
                        .last()
                        .is_some_and(|last| last.connection_id == cursor)
            })
    }
}

impl<'de> Deserialize<'de> for CustomModelCatalogPage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            models: Vec<CustomModelCatalogEntry>,
            #[serde(deserialize_with = "deserialize_required_cursor")]
            next_cursor: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            models: wire.models,
            next_cursor: wire.next_cursor,
        };
        if !value.is_valid() {
            return Err(serde::de::Error::custom(
                "invalid_custom_model_catalog_page",
            ));
        }
        Ok(value)
    }
}

/// 私有实际 allocation 的只读借用端口；实现此 trait 不授予交付权限。
pub trait CustomModelCatalogReplyAllocation: Send + Sync {
    /// 借用原不可变页，不复制请求 proof。
    fn page(&self) -> &CustomModelCatalogPage;
}

/// 原 key 的有界同步取消 hook；真实实现只取消自己的 exact Entry。
pub trait CustomModelCatalogReplyCancel: Send + Sync {
    /// 不得持 registry 锁调用；真实生产 hook 必须 nonpanic。
    fn cancel(&self);
}

/// 保留原私有 key 的目录应答；Serde 仅投影不带 proof 的页。
pub struct CustomModelCatalogReply {
    allocation: Arc<dyn CustomModelCatalogReplyAllocation>,
    key: Option<CustomModelCatalogReplyKey>,
}

struct CustomModelCatalogReplyKey {
    identity: Arc<CustomModelCatalogReplyIdentity>,
    cancel: Box<dyn CustomModelCatalogReplyCancel>,
}

impl Drop for CustomModelCatalogReplyKey {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct CustomModelCatalogReplyIdentity;

/// 一次发行时配对的 opaque identity；不拥有取消权或 page 配额。
pub struct CustomModelCatalogReplyRegistration {
    identity: Weak<CustomModelCatalogReplyIdentity>,
    allocation: Weak<dyn CustomModelCatalogReplyAllocation>,
}

impl CustomModelCatalogReply {
    /// 新造一对身份；必须由 Application 独立登记实际端口结果才有交付权限。
    pub fn issue_for_delivery(
        allocation: Arc<dyn CustomModelCatalogReplyAllocation>,
        cancel: Box<dyn CustomModelCatalogReplyCancel>,
    ) -> (Self, CustomModelCatalogReplyRegistration) {
        let identity = Arc::new(CustomModelCatalogReplyIdentity);
        let registration = CustomModelCatalogReplyRegistration {
            identity: Arc::downgrade(&identity),
            allocation: Arc::downgrade(&allocation),
        };
        let reply = Self {
            allocation,
            key: Some(CustomModelCatalogReplyKey { identity, cancel }),
        };
        (reply, registration)
    }

    /// 借用原页；borrow 或 Serialize 本身不消费交付 proof。
    #[must_use]
    pub fn page(&self) -> &CustomModelCatalogPage {
        self.allocation.page()
    }
}

impl CustomModelCatalogReplyRegistration {
    /// 仅同时匹配原 identity 与原 allocation；DTO/bodyhash 不能替代。
    #[must_use]
    pub fn matches_reply(&self, reply: &CustomModelCatalogReply) -> bool {
        let Some(key) = reply.key.as_ref() else {
            return false;
        };
        self.identity
            .upgrade()
            .is_some_and(|identity| Arc::ptr_eq(&identity, &key.identity))
            && self
                .allocation
                .upgrade()
                .is_some_and(|allocation| Arc::ptr_eq(&allocation, &reply.allocation))
    }
}

impl fmt::Debug for CustomModelCatalogReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomModelCatalogReply(<redacted>)")
    }
}

impl fmt::Debug for CustomModelCatalogReplyRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomModelCatalogReplyRegistration(<redacted>)")
    }
}

impl PartialEq for CustomModelCatalogReply {
    fn eq(&self, other: &Self) -> bool {
        match (&self.key, &other.key) {
            (Some(left), Some(right)) => {
                Arc::ptr_eq(&left.identity, &right.identity)
                    && Arc::ptr_eq(&self.allocation, &other.allocation)
            }
            (None, None) => self.page() == other.page(),
            _ => false,
        }
    }
}

impl Eq for CustomModelCatalogReply {}

impl Serialize for CustomModelCatalogReply {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.page().serialize(serializer)
    }
}

struct UnprovedPage(CustomModelCatalogPage);

impl CustomModelCatalogReplyAllocation for UnprovedPage {
    fn page(&self) -> &CustomModelCatalogPage {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CustomModelCatalogReply {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let page = CustomModelCatalogPage::deserialize(deserializer)?;
        Ok(Self {
            allocation: Arc::new(UnprovedPage(page)),
            key: None,
        })
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

// `deserialize_with` keeps the nullable field required instead of defaulting a missing key.
fn deserialize_required_cursor<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
#[path = "custom_model_catalog_tests.rs"]
mod tests;
