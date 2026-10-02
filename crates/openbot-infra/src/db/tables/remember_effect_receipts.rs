//! Same-commit remember evidence. Business objects may be deleted without deleting this snapshot.

crate::db::tables::define_table! {
    table = "remember_effect_receipts";
    receipt_id: String = ("receipt_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    run_id: String = ("run_id", "text", true),
    actor_id: String = ("actor_id", "text", true),
    bot_id: String = ("bot_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    tool_call_id: String = ("tool_call_id", "text", true),
    call_seq: i64 = ("call_seq", "bigint", true),
    attempt_id: String = ("attempt_id", "text", true),
    attempt_seq: i64 = ("attempt_seq", "bigint", true),
    decision_id: String = ("decision_id", "text", true),
    capability_id: String = ("capability_id", "text", true),
    args_hash: String = ("args_hash", "text", true),
    schema_hash: String = ("schema_hash", "text", true),
    catalog_generation: i64 = ("catalog_generation", "bigint", true),
    target_kind: String = ("target_kind", "text", true),
    target_id: String = ("target_id", "text", true),
    memory_id: String = ("memory_id", "text", true),
    memory_event_seq: i64 = ("memory_event_seq", "bigint", true),
    audit_event_id: String = ("audit_event_id", "text", true),
    recorded_at: time::OffsetDateTime = ("recorded_at", "timestamp with time zone", true),
}
