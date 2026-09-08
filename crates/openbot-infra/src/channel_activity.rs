//! Transactional channel roster projection and PostgreSQL wake notification.

use openbot_contracts::command::ChannelActivityEvent;
use openbot_contracts::ids::{BotId, ChannelId, ThreadId};
use time::OffsetDateTime;
use tokio_postgres::Transaction;

pub(crate) const CHANNEL_ACTIVITY_TOPIC: &str = "openbot_channel_activity";
const MAX_PREVIEW_CODE_POINTS: usize = 200;
const MAX_NOTIFY_BYTES: usize = 7_000;

pub(crate) async fn record_for_channel(
    transaction: &Transaction<'_>,
    channel_id: &ChannelId,
    text: &str,
    agent_id: Option<&BotId>,
    at: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
    update_and_notify(transaction, channel_id.as_str(), text, agent_id, at).await
}

pub(crate) async fn record_for_thread(
    transaction: &Transaction<'_>,
    thread_id: &ThreadId,
    text: &str,
    agent_id: Option<&BotId>,
    at: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
    let row = transaction
        .query_opt(
            "SELECT anchor_id FROM public.threads \
             WHERE thread_id=$1 AND anchor_kind='channel'",
            &[&thread_id.as_str()],
        )
        .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let channel_id: String = row.try_get("anchor_id")?;
    update_and_notify(transaction, &channel_id, text, agent_id, at).await
}

async fn update_and_notify(
    transaction: &Transaction<'_>,
    channel_id: &str,
    text: &str,
    agent_id: Option<&BotId>,
    at: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
    let preview = preview(text);
    let agent_id = agent_id.map(BotId::as_str);
    let row = transaction
        .query_opt(
            "UPDATE public.channels \
             SET last_message=$2,last_message_at=$3,last_message_agent_id=$4, \
                 updated_at=greatest(updated_at,$3) \
             WHERE id=$1 AND (last_message_at IS NULL OR last_message_at<$3) \
             RETURNING id",
            &[&channel_id, &preview, &at, &agent_id],
        )
        .await?;
    if row.is_none() {
        return Ok(());
    }
    let event = ChannelActivityEvent {
        channel_id: ChannelId::new(channel_id),
        last_message: Some(preview),
        last_message_at: Some(at),
        last_message_agent_id: agent_id.map(BotId::new),
    };
    let payload = serde_json::to_string(&event).expect("closed channel activity event serializes");
    if payload.len() > MAX_NOTIFY_BYTES {
        tracing::warn!(
            payload_bytes = payload.len(),
            "channel activity payload exceeds bounded NOTIFY budget; roster remains authoritative"
        );
        return Ok(());
    }
    transaction
        .query_one(
            "SELECT pg_notify('openbot_channel_activity',$1)",
            &[&payload],
        )
        .await?;
    Ok(())
}

fn preview(text: &str) -> String {
    let flattened = text
        .chars()
        .map(|character| {
            let value = character as u32;
            if value <= 0x1f || (0x7f..=0x9f).contains(&value) {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let collapsed = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_PREVIEW_CODE_POINTS {
        return collapsed;
    }
    let mut output = collapsed
        .chars()
        .take(MAX_PREVIEW_CODE_POINTS - 1)
        .collect::<String>();
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_is_one_line_control_free_and_code_point_bounded() {
        assert_eq!(preview("  hello\n\tworld\u{0085}!  "), "hello world !");
        let long = "张".repeat(250);
        let output = preview(&long);
        assert_eq!(output.chars().count(), 200);
        assert!(output.ends_with('…'));
        assert_eq!(preview("short"), "short");
    }
}
