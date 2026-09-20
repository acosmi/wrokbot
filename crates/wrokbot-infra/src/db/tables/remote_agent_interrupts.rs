//! `public.remote_agent_interrupts` durable AG-UI interrupt/resume state (native 0028).

crate::db::tables::define_table! {
    table = "remote_agent_interrupts";
    request_id: String = ("request_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    run_id: String = ("run_id", "text", true),
    actor_id: String = ("actor_id", "text", true),
    bot_id: String = ("bot_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    protocol_run_id: String = ("protocol_run_id", "text", true),
    interrupt_id: String = ("interrupt_id", "text", true),
    position: i16 = ("position", "smallint", true),
    descriptor: Option<serde_json::Value> = ("descriptor", "jsonb", false),
    state: String = ("state", "text", true),
    response_status: Option<String> = ("response_status", "text", false),
    response_payload: Option<serde_json::Value> = ("response_payload", "jsonb", false),
    resume_protocol_run_id: Option<String> = ("resume_protocol_run_id", "text", false),
    requested_at: time::OffsetDateTime = ("requested_at", "timestamp with time zone", true),
    expires_at: time::OffsetDateTime = ("expires_at", "timestamp with time zone", true),
    resolved_at: Option<time::OffsetDateTime> = ("resolved_at", "timestamp with time zone", false),
    resolved_by: Option<String> = ("resolved_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_descriptor_and_human_payload_never_render_in_debug() {
        let row = Row {
            request_id: "018f6f8a-5f4b-7c2d-8a31-111111111111".to_owned(),
            deployment_id: "deployment".to_owned(),
            tenant_id: "tenant".to_owned(),
            thread_id: "thread".to_owned(),
            run_id: "run".to_owned(),
            actor_id: "actor".to_owned(),
            bot_id: "bot".to_owned(),
            auth_generation: 0,
            protocol_run_id: "protocol".to_owned(),
            interrupt_id: "interrupt".to_owned(),
            position: 0,
            descriptor: Some(serde_json::json!({"message":"REMOTE-DESCRIPTOR-CANARY"})),
            state: "resolved".to_owned(),
            response_status: Some("resolved".to_owned()),
            response_payload: Some(serde_json::json!({"answer":"HUMAN-PAYLOAD-CANARY"})),
            resume_protocol_run_id: Some("next".to_owned()),
            requested_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
            resolved_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            resolved_by: Some("actor".to_owned()),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("REMOTE-DESCRIPTOR-CANARY"));
        assert!(!rendered.contains("HUMAN-PAYLOAD-CANARY"));
        assert_eq!(rendered.matches("<redacted>").count(), 2);
    }
}
