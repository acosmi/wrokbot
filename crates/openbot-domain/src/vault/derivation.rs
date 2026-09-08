//! Domain-separated application keys derived from one deployment/Desktop master key.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;

use super::{SecretBytes, VaultError};

type HmacSha256 = Hmac<Sha256>;

/// Closed consumers that derive persistent application keys from the same master.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationKeyPurpose {
    /// PostgreSQL audit-chain checkpoint signing.
    AuditCheckpoint,
    /// MCP OAuth state ticket authentication.
    McpOauthState,
}

impl ApplicationKeyPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::AuditCheckpoint => b"openbot:audit-checkpoint:v1",
            Self::McpOauthState => b"openbot:mcp-oauth-state:v1",
        }
    }
}

/// Derive one 256-bit key using the closed purpose label.
///
/// HMAC accepts any non-empty master. This deliberately preserves the Server compatibility path,
/// which historically derives from the raw `KEY_ENCRYPTION_KEY` configuration bytes (often base64
/// text), while Desktop supplies its fixed 32-byte OS-stored master. No caller can provide a
/// free-form label, preventing two assembly roots from silently inventing different key domains.
pub fn derive_application_key(
    master: &SecretBytes,
    purpose: ApplicationKeyPurpose,
) -> Result<SecretBytes, VaultError> {
    if master.is_empty() {
        return Err(VaultError::KeyLength);
    }
    let mut hmac =
        HmacSha256::new_from_slice(master.expose()).map_err(|_| VaultError::KeyLength)?;
    hmac.update(purpose.label());
    Ok(SecretBytes::new(hmac.finalize().into_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_preserve_server_vectors_and_are_deterministic_distinct() {
        let master = SecretBytes::new(b"master-key".to_vec());
        let audit =
            derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint).unwrap();
        let audit_again =
            derive_application_key(&master, ApplicationKeyPurpose::AuditCheckpoint).unwrap();
        let oauth = derive_application_key(&master, ApplicationKeyPurpose::McpOauthState).unwrap();
        assert_eq!(audit.expose(), audit_again.expose());
        assert_ne!(audit.expose(), oauth.expose());
        assert_eq!(audit.len(), 32);
        assert_eq!(
            encode_hex(audit.expose()),
            "00b5b31ffe77e84e80360040e125e18a1b98bde19f0e2cbb7e50b21ea416bb38"
        );
        assert_eq!(
            encode_hex(oauth.expose()),
            "ccfba00aaba50cae63f3d6f46cabb29c00ada7c7b2cef4d86330afe4b834219c"
        );

        assert!(
            derive_application_key(
                &SecretBytes::new(vec![0; 44]),
                ApplicationKeyPurpose::AuditCheckpoint,
            )
            .is_ok()
        );
        assert!(matches!(
            derive_application_key(
                &SecretBytes::new(Vec::new()),
                ApplicationKeyPurpose::AuditCheckpoint,
            ),
            Err(VaultError::KeyLength)
        ));
    }

    fn encode_hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }
}
