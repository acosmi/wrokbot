//! R228：本机窗口系统确认的只读状态与回执，不承载可复用认证材料。

use serde::{Deserialize, Deserializer, Serialize};

/// Local-only 系统确认入口；不属于 Server session。
pub const LOCAL_CONFIRMATION_PATH: &str = "/api/me/local-confirmation";

/// R228 新增的本机敏感写确认最长有效秒数。
pub const MAX_LOCAL_CONFIRMATION_FRESHNESS_SECONDS: u32 = 900;

/// R228 新增的单次系统确认等待秒数；不承诺 OS 对话框同期限内消失。
pub const LOCAL_CONFIRMATION_WAIT_SECONDS: u32 = 120;

/// 当前调用窗口的确认状态，不证明其它窗口或产品账户已认证。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalConfirmationState {
    /// 需要主动进行系统确认。
    Required,
    /// 本窗口的确认尚在等待；不能共享另一个窗口的成功结果。
    Pending,
    /// 本窗口当前拥有尚未过期的宿主 grant。
    Fresh,
    /// 此宿主当前不能进行系统确认。
    Unavailable,
}

/// GET 的封闭状态投影；秒数只供显示，不可反向授予权限。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConfirmationStatus {
    /// 当前窗口状态。
    pub state: LocalConfirmationState,
    /// fresh 时为 1..=900；其它状态必须为零。
    pub remaining_seconds: u32,
}

impl<'de> Deserialize<'de> for LocalConfirmationStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Wire {
            state: LocalConfirmationState,
            remaining_seconds: u32,
        }
        let wire = Wire::deserialize(deserializer)?;
        let valid = match wire.state {
            LocalConfirmationState::Fresh => {
                (1..=MAX_LOCAL_CONFIRMATION_FRESHNESS_SECONDS).contains(&wire.remaining_seconds)
            }
            _ => wire.remaining_seconds == 0,
        };
        if !valid {
            return Err(serde::de::Error::custom(
                "invalid local confirmation status",
            ));
        }
        Ok(Self {
            state: wire.state,
            remaining_seconds: wire.remaining_seconds,
        })
    }
}

/// 本次主动系统确认的结果，不表示秘密业务操作已提交成功。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalConfirmationOutcome {
    /// 宿主已为原窗口安装本次有效 grant。
    Confirmed,
    /// 本次没有新 grant；仍有效的旧 grant 不因取消而延长。
    Cancelled,
}

/// POST 的封闭回执；不返回系统密码、proof、窗口身份或 token。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConfirmationReceipt {
    /// 本次确认结果。
    pub outcome: LocalConfirmationOutcome,
    /// confirmed 为 1..=900，cancelled 可为 0..=900 的旧 grant 剩余提示。
    pub remaining_seconds: u32,
}

impl<'de> Deserialize<'de> for LocalConfirmationReceipt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Wire {
            outcome: LocalConfirmationOutcome,
            remaining_seconds: u32,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.remaining_seconds > MAX_LOCAL_CONFIRMATION_FRESHNESS_SECONDS
            || (wire.outcome == LocalConfirmationOutcome::Confirmed && wire.remaining_seconds == 0)
        {
            return Err(serde::de::Error::custom(
                "invalid local confirmation receipt",
            ));
        }
        Ok(Self {
            outcome: wire.outcome,
            remaining_seconds: wire.remaining_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_rejects_unknown_authority_fields_and_inconsistent_deadlines() {
        for wire in [
            r#"{"state":"fresh","remainingSeconds":0}"#,
            r#"{"state":"fresh","remainingSeconds":901}"#,
            r#"{"state":"required","remainingSeconds":1}"#,
            r#"{"state":"pending","remainingSeconds":1}"#,
            r#"{"state":"unavailable","remainingSeconds":1}"#,
            r#"{"state":"fresh","remainingSeconds":900,"proof":"forged"}"#,
            r#"{"state":"fresh","remainingSeconds":900,"actor":"other"}"#,
            r#"{"state":"authenticated","remainingSeconds":900}"#,
            r#"{"state":"fresh","remainingSeconds":-1}"#,
        ] {
            assert!(serde_json::from_str::<LocalConfirmationStatus>(wire).is_err());
        }
        let status: LocalConfirmationStatus =
            serde_json::from_str(r#"{"state":"fresh","remainingSeconds":900}"#).unwrap();
        assert_eq!(status.state, LocalConfirmationState::Fresh);
        assert_eq!(status.remaining_seconds, 900);
    }

    #[test]
    fn receipt_keeps_cancelled_existing_grant_separate_from_new_confirmation() {
        for remaining_seconds in [0, 1, 900] {
            let receipt = LocalConfirmationReceipt {
                outcome: LocalConfirmationOutcome::Cancelled,
                remaining_seconds,
            };
            assert_eq!(
                serde_json::from_str::<LocalConfirmationReceipt>(
                    &serde_json::to_string(&receipt).unwrap()
                )
                .unwrap(),
                receipt
            );
        }
        for wire in [
            r#"{"outcome":"confirmed","remainingSeconds":0}"#,
            r#"{"outcome":"confirmed","remainingSeconds":901}"#,
            r#"{"outcome":"cancelled","remainingSeconds":901}"#,
            r#"{"outcome":"confirmed","remainingSeconds":1,"token":"forged"}"#,
            r#"{"outcome":"allowed","remainingSeconds":1}"#,
        ] {
            assert!(serde_json::from_str::<LocalConfirmationReceipt>(wire).is_err());
        }
    }
}
