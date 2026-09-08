//! keyset 游标 —— 铸造在这里，解析也在这里，中间任何一层原样搬运。
//!
//! # 排序键（parity）
//!
//! 上游 `server/src/routes/channels/routes.ts::list` 的排序是
//! `coalesce(last_message_at, created_at) DESC, id DESC`，翻页判据是 keyset 而不是 offset：
//!
//! ```text
//! (coalesce(last_message_at, created_at), id) < (cursor.recency, cursor.id)
//! ```
//!
//! 游标编码的就是这个二元组。keyset 而不是 offset 是**正确性**不是性能偏好：offset 在
//! 「翻页途中有新消息把某个 channel 顶到前面」时会漏掉一整行，而 keyset 不会。
//!
//! # 线上形态
//!
//! `base64url(JSON({recency, id}))`，`recency` 是 RFC 3339 字符串 —— 与上游
//! `channels/routes.ts::encodeChannelCursor` 同形。
//!
//! 沿用它的理由是**可运维**：运维在排障时 base64 解一下就能看见「这个客户端卡在哪个
//! 时间点」，换成紧凑二进制就只剩一串乱码。
//!
//! 但要说清楚一件事：游标是**不透明**的，它的字节形态不是对外契约。上游 TS 服务铸造的
//! 游标不会被喂进 Rust 服务（两者不同时在线），所以这里不做、也无法做逐字节的 wire
//! parity 验证 —— 本仓没有上游源码，这条形态描述来自方案与reviewer转述，**不是**本轮跑出来的
//! 证据。真正被测试钉死的是：本 crate 铸造的游标能被本 crate 解回同一个二元组，且任何
//! 篡改都被拒绝。
//!
//! # 解码 fail-closed —— 相对固定 commit 的**刻意行为变更**，不是 parity
//!
//! 上游 `decodeChannelCursor` 是 fail-open 的：JSON 解析失败或形状不对都返回 `undefined`，
//! 而 `undefined` 在下游意味着 where 子句整个省掉 = **静默回到第一页**。后果是客户端拿着
//! 一个坏游标无限重读第一页，而且永远收不到任何错误 —— 一个不会报警的死循环。
//!
//! 本实现改成：解码失败 → `AppError::MalformedPayload { field: "cursor" }`（400），
//! **绝不 fallback**。依据是 §15.3「malformed payload 400，不产生 acting decision」压过
//! 照译，与 repository contract §7「上游缺陷不得照译」同族。这条差异必须以「刻意变更」登记，
//! 不得写成 parity。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ChannelId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// 游标在错误里的静态字段名。`AppError::MalformedPayload::field` 是 `&'static str`，
/// 这个常量是它在本模块的唯一落点。
const CURSOR_FIELD: &str = "cursor";

/// 排序键的第一项：`coalesce(last_message_at, created_at)`。
///
/// 这是**定义**，不是便利函数：游标铸造、`openbot-infra` 的 SQL `ORDER BY` 与
/// `WHERE` 子句必须指向同一个表达式，任何一处漂移都会让翻页漏行或重行。放在这里
/// 是为了让「排序键是什么」在 Rust 侧只有一个可 grep 的答案。
#[must_use]
pub fn channel_recency(summary: &ChannelSummary) -> OffsetDateTime {
    summary.last_message_at.unwrap_or(summary.created_at)
}

/// keyset 游标：排序键二元组。
///
/// 它是**类型化**的（时间戳 + ID newtype），不是一段会被拼进 SQL 的文本。这一点是安全
/// 属性而不是风格：调用方能篡改的最大范围就是「换一个时间点和一个 channel id」，而那两个
/// 值最终作为参数化查询的绑定值出现，构造不出任何注入。可见性仍由 membership 判据裁决，
/// 所以伪造游标也看不到别人的 channel（`forged_cursor_cannot_widen_visibility` 钉住）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCursor {
    /// 上一页最后一行的 `coalesce(last_message_at, created_at)`。
    pub recency: OffsetDateTime,
    /// 上一页最后一行的 channel id，用来给同一时间戳的行定序（`id DESC`）。
    pub id: ChannelId,
}

/// 游标的线上载荷。
///
/// `deny_unknown_fields` 是 fail-closed 的一部分：多一个字段说明这不是本系统铸造的游标，
/// 静默忽略它等于接受一个来路不明的翻页锚点。
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    #[serde(with = "time::serde::rfc3339")]
    recency: OffsetDateTime,
    id: String,
}

/// 铸造游标失败。
///
/// 唯一成因：`recency` 落在 RFC 3339 能表示的范围（公元 0000–9999）之外。`timestamptz`
/// 的取值域比 RFC 3339 宽，所以这不是一个不可能事件，而是一行**无法在任何线上形态里
/// 表示**的数据 —— `ChannelSummary::created_at` 在 contracts 里同样是 RFC 3339 序列化，
/// 这样的行连应答都拼不出来。
///
/// 刻意不携带原值：数据库里的值是不可信数据，把它回显进错误就是日志注入面。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cursor_not_representable")]
pub struct CursorEncodeError;

impl ChannelCursor {
    /// 由一页的最后一行铸造下一页的游标。
    #[must_use]
    pub fn from_summary(summary: &ChannelSummary) -> Self {
        Self {
            recency: channel_recency(summary),
            id: summary.id.clone(),
        }
    }

    /// 编码成不透明字符串。
    ///
    /// # Errors
    ///
    /// `recency` 无法表示成 RFC 3339 时返回 [`CursorEncodeError`]，见该类型的文档。
    pub fn encode(&self) -> Result<String, CursorEncodeError> {
        let payload = CursorPayload {
            recency: self.recency,
            id: self.id.as_str().to_owned(),
        };
        let json = serde_json::to_vec(&payload).map_err(|_| CursorEncodeError)?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }

    /// 解析一个不透明字符串。
    ///
    /// **fail-closed**：base64 坏、JSON 坏、字段缺、字段多、时间戳不是 RFC 3339 —— 一律
    /// 400，绝不回落成「从头开始」。理由见模块文档。
    ///
    /// # Errors
    ///
    /// 任何解析失败都返回 `AppError::MalformedPayload { field: "cursor" }`。
    /// 刻意**不区分**失败原因：区分只会给探测者提供一个逐步凑出合法游标的信号，而对
    /// 正常客户端没有任何用处 —— 它拿到的游标只可能来自上一次应答。
    pub fn decode(raw: &str) -> Result<Self, AppError> {
        let malformed = || AppError::MalformedPayload {
            field: CURSOR_FIELD,
        };
        let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| malformed())?;
        let payload: CursorPayload = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
        if payload.id.is_empty() {
            // 空 id 排不出序：`(recency, "") < (recency, "")` 恒假，这一页会永远返回空。
            // 本系统铸造的游标不可能是空 id（它来自一行真实数据），所以这是篡改。
            return Err(malformed());
        }
        Ok(Self {
            recency: payload.recency,
            id: ChannelId::new(payload.id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{summary_at, summary_without_messages};
    use time::{Date, Month, Time};

    fn sample() -> ChannelCursor {
        ChannelCursor::from_summary(&summary_at("c-1", "2026-08-22T04:05:06Z"))
    }

    /// 排序键的定义：有 `last_message_at` 就用它，没有才回落 `created_at`。
    ///
    /// 这条不是抄件测试：`channel_recency` 是生产代码里唯一定义排序键的地方，fake 也
    /// 消费它 —— 所以必须单独把它的两个分支钉住，否则定义写反了两边会一起错、一起绿。
    #[test]
    fn channel_recency_prefers_last_message_at_and_falls_back_to_created_at() {
        let with_message = summary_at("c-1", "2026-08-22T04:05:06Z");
        assert_eq!(
            channel_recency(&with_message),
            with_message.last_message_at.unwrap()
        );
        assert_ne!(channel_recency(&with_message), with_message.created_at);

        // 正向对照：从未有过消息的行确实回落到 created_at。
        let without = summary_without_messages("c-2", "2026-01-02T03:04:05Z");
        assert!(without.last_message_at.is_none());
        assert_eq!(channel_recency(&without), without.created_at);
    }

    #[test]
    fn cursor_round_trips_through_the_opaque_wire_form() {
        let cursor = sample();
        let encoded = cursor.encode().unwrap();
        assert_eq!(ChannelCursor::decode(&encoded).unwrap(), cursor);
    }

    /// 线上形态确实是 `base64url(JSON({recency, id}))` —— 这条同时是「游标不透明」那句话的
    /// 正向对照：它证明编码器真的产出了内容，而不是一个恒定空串。
    #[test]
    fn wire_form_is_base64url_of_a_two_field_json_object() {
        let encoded = sample().encode().unwrap();
        assert!(
            !encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'),
            "必须是 URL-safe 且无 padding：{encoded}"
        );
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();
        assert!(
            json.contains(r#""recency":"2026-08-22T04:05:06Z""#),
            "{json}"
        );
        assert!(json.contains(r#""id":"c-1""#), "{json}");
    }

    /// 篡改游标一律 400，**绝不 fallback 成第一页**（本模块的刻意行为变更）。
    ///
    /// 正向对照在最后一行：未被篡改的同一个游标确实解析成功 —— 没有它，本条测试在
    /// 「`decode` 恒失败」的世界里同样通过。
    #[test]
    fn tampered_cursor_is_rejected_and_never_silently_reset() {
        let good = sample().encode().unwrap();

        let tampered: Vec<String> = vec![
            // 非 base64 字符。
            format!("{good}!!"),
            // 截断。
            good[..good.len() - 4].to_owned(),
            // 空串。
            String::new(),
            // 合法 base64，但内容不是 JSON。
            URL_SAFE_NO_PAD.encode(b"not json at all"),
            // 合法 JSON，但少字段。
            URL_SAFE_NO_PAD.encode(br#"{"id":"c-1"}"#),
            // 合法 JSON，但多字段（`deny_unknown_fields`）。
            URL_SAFE_NO_PAD
                .encode(br#"{"recency":"2026-08-22T04:05:06Z","id":"c-1","actor":"someone-else"}"#),
            // 时间戳不是 RFC 3339。
            URL_SAFE_NO_PAD.encode(br#"{"recency":"yesterday","id":"c-1"}"#),
            // 空 id：排不出序，本系统不会铸造它。
            URL_SAFE_NO_PAD.encode(br#"{"recency":"2026-08-22T04:05:06Z","id":""}"#),
            // 带 padding 的 base64（标准字母表），本编码器不产出这种形态。
            "eyJyZWNlbmN5IjoiIn0=".to_owned(),
        ];

        for raw in &tampered {
            let err = ChannelCursor::decode(raw).unwrap_err();
            assert_eq!(
                err,
                AppError::MalformedPayload { field: "cursor" },
                "被篡改的游标必须 400，实际拿到 {err:?}（输入 {raw:?}）"
            );
            assert_eq!(err.http_status(), 400);
        }

        // 正向对照。
        assert!(ChannelCursor::decode(&good).is_ok());
    }

    /// 无法表示成 RFC 3339 的时间戳不静默截断，也不 panic —— 返回可映射的错误。
    ///
    /// 负向 + 正向成对：同一条路径在正常年份上必须成功。
    #[test]
    fn timestamps_outside_rfc3339_are_reported_not_silently_mangled() {
        let year_minus_one = Date::from_calendar_date(-1, Month::January, 1)
            .unwrap()
            .with_time(Time::MIDNIGHT)
            .assume_utc();
        let unrepresentable = ChannelCursor {
            recency: year_minus_one,
            id: ChannelId::new("c-1"),
        };
        assert_eq!(unrepresentable.encode(), Err(CursorEncodeError));

        // 正向对照：正常年份编得出来。
        assert!(sample().encode().is_ok());
    }

    /// 伪造游标改不了可见性：游标只影响「从哪儿接着往下翻」，不参与判定「能看见谁」。
    ///
    /// 这里只钉类型层面的事实 —— 游标解出来只有 `recency` 与 `id` 两个字段，没有任何
    /// 位置能塞进 actor / tenant / SQL 片段。行为层面的证据在
    /// `use_cases::list_visible_channels` 的可见性测试里。
    #[test]
    fn forged_cursor_cannot_widen_visibility() {
        let forged =
            URL_SAFE_NO_PAD.encode(br#"{"recency":"2999-12-31T23:59:59Z","id":"' OR 1=1 --"}"#);
        let decoded = ChannelCursor::decode(&forged).unwrap();
        // 它就是一个普通的 ChannelId 值，作为绑定参数出现，不是 SQL 片段。
        assert_eq!(decoded.id.as_str(), "' OR 1=1 --");
        assert_eq!(decoded.recency.year(), 2999);
    }
}
