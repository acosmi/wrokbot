//! 版本化模型选择的独立请求意图解码。
//!
//! 本模块不改变旧命令入口；解码不证明库存、权限、凭据或模型发送可用。

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model_connections::{MAX_MODEL_CONNECTION_MODEL_BYTES, RunModelSelection};

const INVALID_MODEL_SELECTION: &str = "invalid_model_selection";

/// 原始 JSON 入口的字节上限，包含首尾标准 JSON 空白。
pub const MAX_MODEL_SELECTION_JSON_BYTES: usize = 4096;

/// 解码失败的固定分类，不保存原输入或底层错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelSelectionDecodeError {
    /// 原始输入超过字节上限。
    TooLarge,
    /// 输入不符合固定对象、字段或值边界。
    InvalidInput,
}

impl fmt::Display for ModelSelectionDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "model_selection_json_too_large",
            Self::InvalidInput => INVALID_MODEL_SELECTION,
        })
    }
}

/// 请求中的模型来源意图，独立于已启用的生产连接来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelSelectionIntentSource {
    /// 自定义连接意图。
    Custom,
    /// SDK 网关连接意图。
    SdkGateway,
    /// 账户桥连接意图。
    AccountBridge,
}

impl ModelSelectionIntentSource {
    /// 返回固定请求拼写，不授予该来源的实际使用权限。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Custom => "custom",
            Self::SdkGateway => "sdk_gateway",
            Self::AccountBridge => "account_bridge",
        }
    }
}

impl Serialize for ModelSelectionIntentSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ModelSelectionIntentSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SourceVisitor;

        impl Visitor<'_> for SourceVisitor {
            type Value = ModelSelectionIntentSource;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(INVALID_MODEL_SELECTION)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "custom" => Ok(ModelSelectionIntentSource::Custom),
                    "sdk_gateway" => Ok(ModelSelectionIntentSource::SdkGateway),
                    "account_bridge" => Ok(ModelSelectionIntentSource::AccountBridge),
                    _ => Err(invalid()),
                }
            }
        }

        deserializer
            .deserialize_str(SourceVisitor)
            .map_err(|_| invalid())
    }
}

/// 六字段模型选择意图；私有字段仅由固定校验入口构造。
#[derive(Clone, PartialEq, Eq)]
pub struct RunModelSelectionV2 {
    source: ModelSelectionIntentSource,
    connection_id: String,
    expected_connection_revision: i64,
    model_id: String,
    expected_catalog_revision: i64,
}

impl RunModelSelectionV2 {
    /// 固定序列化版本，不是可变请求字段。
    pub const SCHEMA_VERSION: u8 = 2;

    /// 校验请求值并保留原文；不检查库存或当前授权。
    pub fn new(
        source: ModelSelectionIntentSource,
        connection_id: String,
        expected_connection_revision: i64,
        model_id: String,
        expected_catalog_revision: i64,
    ) -> Result<Self, ModelSelectionDecodeError> {
        let value = Self {
            source,
            connection_id,
            expected_connection_revision,
            model_id,
            expected_catalog_revision,
        };
        if !value.is_valid() {
            return Err(ModelSelectionDecodeError::InvalidInput);
        }
        Ok(value)
    }

    /// 返回原请求来源意图。
    pub fn source(&self) -> ModelSelectionIntentSource {
        self.source
    }

    /// 返回未归一化的原连接标识。
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// 返回原请求连接版本。
    pub fn expected_connection_revision(&self) -> i64 {
        self.expected_connection_revision
    }

    /// 返回尚未核对库存的原模型标识意图。
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// 返回原请求模型目录版本。
    pub fn expected_catalog_revision(&self) -> i64 {
        self.expected_catalog_revision
    }

    fn is_valid(&self) -> bool {
        valid_connection_id(&self.connection_id)
            && self.expected_connection_revision > 0
            && self.expected_catalog_revision > 0
            && !self.model_id.is_empty()
            && self.model_id.len() <= MAX_MODEL_CONNECTION_MODEL_BYTES
            && self.model_id.trim() == self.model_id
            && !self.model_id.chars().any(char::is_control)
    }
}

impl fmt::Debug for RunModelSelectionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunModelSelectionV2([redacted])")
    }
}

impl Serialize for RunModelSelectionV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("RunModelSelectionV2", 6)?;
        value.serialize_field("schemaVersion", &Self::SCHEMA_VERSION)?;
        value.serialize_field("source", &self.source)?;
        value.serialize_field("connectionId", &self.connection_id)?;
        value.serialize_field(
            "expectedConnectionRevision",
            &self.expected_connection_revision,
        )?;
        value.serialize_field("modelId", &self.model_id)?;
        value.serialize_field("expectedCatalogRevision", &self.expected_catalog_revision)?;
        value.end()
    }
}

impl<'de> Deserialize<'de> for RunModelSelectionV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match VersionedRunModelSelection::deserialize(deserializer)? {
            VersionedRunModelSelection::V2(value) => Ok(value),
            VersionedRunModelSelection::V1(_) => Err(invalid()),
        }
    }
}

/// 旧两字段与新六字段的版本化意图，不接入现有生产消费者。
#[derive(Clone, PartialEq, Eq)]
pub enum VersionedRunModelSelection {
    /// 保留旧值及旧校验规则；手工构造仍可能包含无效旧值。
    V1(RunModelSelection),
    /// 经过固定字段校验的新请求意图。
    V2(RunModelSelectionV2),
}

impl VersionedRunModelSelection {
    /// 从有界 UTF-8 原字节解析恰一个对象，返回固定错误分类。
    pub fn from_json_bytes(input: &[u8]) -> Result<Self, ModelSelectionDecodeError> {
        if input.len() > MAX_MODEL_SELECTION_JSON_BYTES {
            return Err(ModelSelectionDecodeError::TooLarge);
        }
        let text =
            std::str::from_utf8(input).map_err(|_| ModelSelectionDecodeError::InvalidInput)?;
        let mut deserializer = serde_json::Deserializer::from_str(text);
        let value = Self::deserialize(&mut deserializer)
            .map_err(|_| ModelSelectionDecodeError::InvalidInput)?;
        deserializer
            .end()
            .map_err(|_| ModelSelectionDecodeError::InvalidInput)?;
        Ok(value)
    }

    /// 重新核对当前变体的值边界；不证明实际库存或使用权限。
    pub fn is_valid(&self) -> bool {
        match self {
            Self::V1(value) => value.is_valid(),
            Self::V2(value) => value.is_valid(),
        }
    }
}

impl fmt::Debug for VersionedRunModelSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::V1(_) => "VersionedRunModelSelection::V1([redacted])",
            Self::V2(_) => "VersionedRunModelSelection::V2([redacted])",
        })
    }
}

impl Serialize for VersionedRunModelSelection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::V1(value) => value.serialize(serializer),
            Self::V2(value) => value.serialize(serializer),
        }
    }
}

fn invalid<E: de::Error>() -> E {
    E::custom(INVALID_MODEL_SELECTION)
}

fn valid_connection_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

enum Field {
    ConnectionId,
    ExpectedRevision,
    SchemaVersion,
    Source,
    ExpectedConnectionRevision,
    ModelId,
    ExpectedCatalogRevision,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldVisitor;

        impl Visitor<'_> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(INVALID_MODEL_SELECTION)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "connectionId" => Ok(Field::ConnectionId),
                    "expectedRevision" => Ok(Field::ExpectedRevision),
                    "schemaVersion" => Ok(Field::SchemaVersion),
                    "source" => Ok(Field::Source),
                    "expectedConnectionRevision" => Ok(Field::ExpectedConnectionRevision),
                    "modelId" => Ok(Field::ModelId),
                    "expectedCatalogRevision" => Ok(Field::ExpectedCatalogRevision),
                    _ => Err(invalid()),
                }
            }
        }

        deserializer
            .deserialize_identifier(FieldVisitor)
            .map_err(|_| invalid())
    }
}

impl<'de> Deserialize<'de> for VersionedRunModelSelection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SelectionVisitor;

        impl<'de> Visitor<'de> for SelectionVisitor {
            type Value = VersionedRunModelSelection;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(INVALID_MODEL_SELECTION)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut connection_id = None;
                let mut expected_revision = None;
                let mut schema_version = None;
                let mut source = None;
                let mut expected_connection_revision = None;
                let mut model_id = None;
                let mut expected_catalog_revision = None;

                macro_rules! read {
                    ($slot:ident, $kind:ty) => {{
                        if $slot.is_some() {
                            return Err(invalid::<A::Error>());
                        }
                        $slot = Some(
                            map.next_value::<$kind>()
                                .map_err(|_| invalid::<A::Error>())?,
                        );
                    }};
                }

                while let Some(field) =
                    map.next_key::<Field>().map_err(|_| invalid::<A::Error>())?
                {
                    match field {
                        Field::ConnectionId => read!(connection_id, String),
                        Field::ExpectedRevision => read!(expected_revision, i64),
                        Field::SchemaVersion => read!(schema_version, i64),
                        Field::Source => read!(source, ModelSelectionIntentSource),
                        Field::ExpectedConnectionRevision => {
                            read!(expected_connection_revision, i64)
                        }
                        Field::ModelId => read!(model_id, String),
                        Field::ExpectedCatalogRevision => read!(expected_catalog_revision, i64),
                    }
                }

                let connection_id = connection_id.ok_or_else(invalid::<A::Error>)?;
                if schema_version.is_some()
                    || source.is_some()
                    || expected_connection_revision.is_some()
                    || model_id.is_some()
                    || expected_catalog_revision.is_some()
                {
                    if expected_revision.is_some()
                        || schema_version != Some(i64::from(RunModelSelectionV2::SCHEMA_VERSION))
                    {
                        return Err(invalid());
                    }
                    let value = RunModelSelectionV2::new(
                        source.ok_or_else(invalid::<A::Error>)?,
                        connection_id,
                        expected_connection_revision.ok_or_else(invalid::<A::Error>)?,
                        model_id.ok_or_else(invalid::<A::Error>)?,
                        expected_catalog_revision.ok_or_else(invalid::<A::Error>)?,
                    )
                    .map_err(|_| invalid::<A::Error>())?;
                    Ok(VersionedRunModelSelection::V2(value))
                } else {
                    let value = RunModelSelection {
                        connection_id,
                        expected_revision: expected_revision.ok_or_else(invalid::<A::Error>)?,
                    };
                    if !value.is_valid() {
                        return Err(invalid());
                    }
                    Ok(VersionedRunModelSelection::V1(value))
                }
            }
        }

        deserializer
            .deserialize_map(SelectionVisitor)
            .map_err(|_| invalid())
    }
}

#[cfg(test)]
#[path = "versioned_model_selection/tests.rs"]
mod tests;
