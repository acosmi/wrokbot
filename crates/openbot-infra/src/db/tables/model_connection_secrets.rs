//! `public.model_connection_secrets` private Vault records (native 0030).
//!
//! The connection/deployment/tenant/owner composite foreign key prevents one-sided rebinding;
//! `encrypted_value` is registered as a secret and never appears in the row's Debug output.

crate::db::tables::define_table! {
    table = "model_connection_secrets";
    id: uuid::Uuid = ("id", "uuid", true),
    connection_id: uuid::Uuid = ("connection_id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    encrypted_value: String = ("encrypted_value", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    retired_at: Option<time::OffsetDateTime> = ("retired_at", "timestamp with time zone", false),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_ciphertext_debug_is_redacted_but_relation_is_observable() {
        let row = Row {
            id: uuid::Uuid::from_u128(1),
            connection_id: uuid::Uuid::from_u128(2),
            deployment_id: "deployment-visible".to_owned(),
            tenant_id: "tenant".to_owned(),
            owner_user_id: "owner".to_owned(),
            encrypted_value: "MODEL-ROW-CIPHERTEXT-CANARY".to_owned(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            retired_at: None,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("MODEL-ROW-CIPHERTEXT-CANARY"));
        assert!(rendered.contains("deployment-visible"));
        assert!(rendered.contains("model_connection_secrets"));
        assert_eq!(rendered.matches("<redacted>").count(), 1);
    }
}
