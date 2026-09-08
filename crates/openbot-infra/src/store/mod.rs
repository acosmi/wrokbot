//! 面向 use case 的复合 PostgreSQL stores。
//!
//! `repo` 模块是一表一聚合或一条安全事务原语；本模块把多个既有表/vault 原语组合成一个
//! 产品级读取或写入边界。它仍不承载 transport framing，也不接受自由 SQL。

pub mod plugin_user_credential;
