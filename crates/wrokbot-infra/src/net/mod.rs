//! 统一出网边界（v3 §6.2 / §7.5 / §10.5）。
//!
//! OIDC discovery/JWKS/token、remote Agent 与 MCP 不得各自拥有 HTTP 客户端；它们只能把
//! 封闭请求计划交给 [`safe_http`]。这样 DNS/IP/redirect/header/size/time 规则只有一个真源。

pub mod safe_http;
pub mod scope_gateway;
