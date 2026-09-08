//! 切换前环境预检；当前只回答 `AUDIT_RETENTION_DAYS` 的跨运行时语义差异。
//!
//! 上游先做 JavaScript `Number(raw)`，再要求 `Number.isInteger(days) && days >= 1`；Rust
//! 生产配置只收 `openbot-domain` 定义的十进制正整数。于是一个正在上游正常运行的部署可能
//! 写着 `0x10`、`1e3`、`+7`、`7.0`，升级后才在启动期失败。这里必须在 cutover **之前**
//! 扫描并给出规范十进制替代值，而且报告绝不携带环境原值。
//!
//! 这不是完整 migration readiness 报告。policy 双引擎确认、deployment id、共享 callback
//! token、package/IdP 等仍由各自 preflight 承担；本模块的类型名刻意带 `AuditRetention`，避免
//! 一条局部检查被误读成“整个部署可以切换”。

use openbot_domain::{audit::retention::parse_retention_days, text::trim_ecmascript};
use serde::Serialize;

use super::env::{self, EnvMap};

const VARIABLE: &str = "AUDIT_RETENTION_DAYS";

/// 审计留存环境迁移的稳定问题码。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetentionPreflightCode {
    /// 上游借 JavaScript Number 强转后接受；应改写成报告里的十进制天数。
    CanonicalDecimalRequired,
    /// 上游 Number 接受，但值超过 Rust/数据库控制面支持的 `u32` 天数。
    ExceedsSupportedRange,
}

/// 一条不含原始环境值的迁移发现。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRetentionPreflightFinding {
    /// 固定变量名。
    pub variable: &'static str,
    /// 稳定问题码；CLI/GUI 自行本地化。
    pub code: AuditRetentionPreflightCode,
    /// 可无歧义替换的规范十进制天数；超范围时为 `None`，必须人工选新策略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_days: Option<u32>,
}

/// `AUDIT_RETENTION_DAYS` 的局部迁移兼容报告。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRetentionPreflightReport {
    /// 是否不存在“旧版接受、Rust 拒绝”的跨版本差异；不是整套 migration readiness。
    pub migration_compatible: bool,
    /// 0 或 1 条；用数组是为了让以后新增本变量的另一类发现不改 wire shape。
    pub findings: Vec<AuditRetentionPreflightFinding>,
}

impl AuditRetentionPreflightReport {
    /// 是否需要操作员在 cutover 前处理。
    #[must_use]
    pub const fn requires_action(&self) -> bool {
        !self.migration_compatible
    }
}

/// 扫描一张权威环境映射，但只投影稳定 code 与规范替代值，绝不投影原值。
#[must_use]
pub fn preflight_audit_retention(env_map: &EnvMap) -> AuditRetentionPreflightReport {
    // 与生产 Server 用同一条严格 parser。已经能读的值无需报告；非法且上游也拒绝的值不属于
    // “迁移语义翻转”（它在旧部署上本就无法运行），同样不制造假 finding。
    if parse_retention_days(env::optional(env_map, VARIABLE)).is_ok() {
        return compatible_report();
    }
    let Some(raw) = env_map.get(VARIABLE) else {
        return compatible_report();
    };
    let Some(upstream_days) = upstream_audit_retention_days(raw) else {
        return compatible_report();
    };

    let (code, replacement_days) = if upstream_days <= f64::from(u32::MAX) {
        (
            AuditRetentionPreflightCode::CanonicalDecimalRequired,
            Some(upstream_days as u32),
        )
    } else {
        (AuditRetentionPreflightCode::ExceedsSupportedRange, None)
    };
    AuditRetentionPreflightReport {
        migration_compatible: false,
        findings: vec![AuditRetentionPreflightFinding {
            variable: VARIABLE,
            code,
            replacement_days,
        }],
    }
}

fn compatible_report() -> AuditRetentionPreflightReport {
    AuditRetentionPreflightReport {
        migration_compatible: true,
        findings: Vec::new(),
    }
}

/// 固定上游 `Number(raw)` + `Number.isInteger` + `>= 1` 在本变量有效域内的实现。
///
/// 返回 `None` 同时覆盖“未设/空白”和“上游也拒绝”；调用方只关心旧版接受而新版拒绝。
fn upstream_audit_retention_days(raw: &str) -> Option<f64> {
    let text = trim_ecmascript(raw);
    if text.is_empty() {
        return None;
    }
    let days = parse_ecmascript_number(text)?;
    (days.is_finite() && days >= 1.0 && days.fract() == 0.0).then_some(days)
}

fn parse_ecmascript_number(text: &str) -> Option<f64> {
    for (lower, upper, radix) in [("0x", "0X", 16), ("0b", "0B", 2), ("0o", "0O", 8)] {
        if let Some(digits) = text
            .strip_prefix(lower)
            .or_else(|| text.strip_prefix(upper))
        {
            return parse_radix_number(digits, radix);
        }
    }
    text.parse::<f64>().ok()
}

fn parse_radix_number(digits: &str, radix: u32) -> Option<f64> {
    if digits.is_empty() {
        return None;
    }
    let mut value = 0.0f64;
    for character in digits.chars() {
        let digit = character.to_digit(radix)?;
        value = value.mul_add(f64::from(radix), f64::from(digit));
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(raw: Option<&str>) -> EnvMap {
        raw.map(|value| [(VARIABLE.to_owned(), value.to_owned())].into())
            .unwrap_or_default()
    }

    #[test]
    fn every_upstream_coercion_gets_a_canonical_decimal_without_echoing_raw_input() {
        for (raw, replacement) in [
            ("+7", 7),
            ("0x10", 16),
            ("0X10", 16),
            ("0b101", 5),
            ("0B101", 5),
            ("0o10", 8),
            ("1e3", 1000),
            ("1E+3", 1000),
            ("+1.e2", 100),
            ("01e2", 100),
            ("7.0", 7),
            ("1.", 1),
            ("\u{FEFF}\u{3000}+7\u{00A0}", 7),
        ] {
            let report = preflight_audit_retention(&environment(Some(raw)));
            assert!(report.requires_action(), "{raw}");
            assert_eq!(report.findings.len(), 1, "{raw}");
            assert_eq!(
                report.findings[0],
                AuditRetentionPreflightFinding {
                    variable: VARIABLE,
                    code: AuditRetentionPreflightCode::CanonicalDecimalRequired,
                    replacement_days: Some(replacement),
                },
                "{raw}"
            );
            let json = serde_json::to_string(&report).unwrap();
            assert!(!json.contains(raw), "报告泄漏了原始环境值: {raw}");
        }
    }

    #[test]
    fn compatible_or_already_invalid_upstream_values_do_not_create_false_migration_findings() {
        for raw in [None, Some(""), Some("   "), Some("7"), Some("007")] {
            assert_eq!(
                preflight_audit_retention(&environment(raw)),
                compatible_report(),
                "{raw:?}"
            );
        }
        for raw in [
            "0",
            "-1",
            "7.5",
            "abc",
            "Infinity",
            "1_000",
            "0b2",
            "+0x10",
            "-0x10",
            "1e",
            "--1",
            "\u{0085}+7\u{0085}",
        ] {
            assert_eq!(
                preflight_audit_retention(&environment(Some(raw))),
                compatible_report(),
                "旧版也拒绝的 {raw} 不应冒充迁移差异"
            );
        }
    }

    #[test]
    fn an_upstream_integer_beyond_u32_requires_a_human_policy_choice() {
        let raw = "4294967296";
        let report = preflight_audit_retention(&environment(Some(raw)));
        assert_eq!(
            report.findings,
            [AuditRetentionPreflightFinding {
                variable: VARIABLE,
                code: AuditRetentionPreflightCode::ExceedsSupportedRange,
                replacement_days: None,
            }]
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["code"], "exceeds_supported_range");
        assert!(json["findings"][0].get("replacementDays").is_none());
        assert!(!json.to_string().contains(raw));
    }
}
