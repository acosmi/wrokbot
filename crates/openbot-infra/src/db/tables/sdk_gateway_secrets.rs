//! SDK Gateway TokenSet Vault ciphertext generations (native 0033).

crate::db::tables::define_table! {
    table = "sdk_gateway_secrets";
    id: uuid::Uuid = ("id", "uuid", true),
    connection_id: uuid::Uuid = ("connection_id", "uuid", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    owner_user_id: String = ("owner_user_id", "text", true),
    credential_generation: i64 = ("credential_generation", "bigint", true),
    encrypted_value: String = ("encrypted_value", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    retired_at: Option<time::OffsetDateTime> = ("retired_at", "timestamp with time zone", false),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_ciphertext_debug_is_redacted() {
        let row = Row {
            id: uuid::Uuid::from_u128(1),
            connection_id: uuid::Uuid::from_u128(2),
            deployment_id: "deployment-visible".to_owned(),
            tenant_id: "tenant-visible".to_owned(),
            owner_user_id: "owner-visible".to_owned(),
            credential_generation: 1,
            encrypted_value: "SDK-GATEWAY-CIPHERTEXT-SENTINEL".to_owned(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            retired_at: None,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("SDK-GATEWAY-CIPHERTEXT-SENTINEL"));
        assert!(rendered.contains("deployment-visible"));
        assert_eq!(rendered.matches("<redacted>").count(), 1);
    }
}
