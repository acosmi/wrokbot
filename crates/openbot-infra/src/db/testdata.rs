//! 仅测试可见：参照库 schema 事实的入仓副本。
//!
//! 单测里的"完整且正确的库"从这里来 —— 没有它，任何「不兼容会被拒绝」的断言都缺正向对照，
//! 在"检查函数恒拒绝"的世界里同样成立。
//!
//! 这份 fixture 的生成过程、复算命令与已登记的 PostgreSQL 版本差异见 `fixtures/db/README.md`。

use crate::db::schema_facts::SchemaFacts;

/// `fixtures/db/schema-0012.json` 的原文。
pub(crate) const REFERENCE_FACTS_JSON: &str =
    include_str!("../../../../fixtures/db/schema-0012.json");

/// 解析入仓的参照事实。
pub(crate) fn reference_facts() -> SchemaFacts {
    serde_json::from_str(REFERENCE_FACTS_JSON).expect("fixtures/db/schema-0012.json 应当能解析")
}
