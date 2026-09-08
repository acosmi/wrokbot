//! Redacted dedicated PostgreSQL listener configuration shared by Server and Desktop Local.
//!
//! The value lives outside the Server-only thread runtime so Desktop can prepare the exact
//! configuration before it enables that runtime in the shared application composition root.

use std::time::Duration;

use openbot_application::ThreadDirectoryError;
use openbot_contracts::desktop::DESKTOP_LOCAL_POSTGRES_ADMIN_USER;

use crate::db::pool::DatabaseConfig;

/// Owned PostgreSQL configuration whose [`Debug`](core::fmt::Debug) output never exposes secrets.
#[derive(Clone)]
// With only `desktop-local`, this is intentionally an opaque hand-off value: the Server runtime
// feature is the sole in-crate consumer allowed to open the underlying config.
#[cfg_attr(not(feature = "server-runtime"), allow(dead_code))]
pub struct ThreadListenerDatabase(tokio_postgres::Config);

#[cfg_attr(not(feature = "server-runtime"), allow(dead_code))]
impl ThreadListenerDatabase {
    /// Build the exact numeric-loopback Desktop Local listener without a password `String`.
    pub fn desktop_local(port: u16, password: &[u8]) -> Result<Self, ThreadDirectoryError> {
        if port == 0
            || password.len() != 64
            || !password
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ThreadDirectoryError::Corrupt {
                field: "thread_listener_database",
            });
        }
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(port)
            .user(DESKTOP_LOCAL_POSTGRES_ADMIN_USER)
            .password(password)
            .dbname("openbot")
            .application_name("openbot-thread-events")
            .connect_timeout(Duration::from_secs(10));
        Ok(Self(config))
    }

    pub(crate) fn config(&self) -> tokio_postgres::Config {
        self.0.clone()
    }

    pub(crate) fn with_application_name(mut self, name: &str) -> Self {
        self.0.application_name(name);
        self
    }

    /// Clone the same redacted credentials for the durable run-control LISTEN connection.
    #[must_use]
    pub fn for_run_control(&self) -> Self {
        self.clone().with_application_name("openbot-run-control")
    }
}

impl From<DatabaseConfig> for ThreadListenerDatabase {
    fn from(database: DatabaseConfig) -> Self {
        Self(database.to_pg_config())
    }
}

impl core::fmt::Debug for ThreadListenerDatabase {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ThreadListenerDatabase(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_listener_is_exact_and_debug_redacted() {
        let secret = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let database = ThreadListenerDatabase::desktop_local(54321, secret).unwrap();
        let config = database.config();
        assert_eq!(
            config.get_hosts(),
            &[tokio_postgres::config::Host::Tcp("127.0.0.1".to_owned())]
        );
        assert_eq!(config.get_ports(), &[54321]);
        assert_eq!(config.get_user(), Some(DESKTOP_LOCAL_POSTGRES_ADMIN_USER));
        assert_eq!(config.get_dbname(), Some("openbot"));
        assert_eq!(config.get_password(), Some(secret.as_slice()));
        assert!(!format!("{database:?}").contains(std::str::from_utf8(secret).unwrap()));
    }

    #[test]
    fn desktop_listener_rejects_bad_port_or_secret_shape() {
        let secret = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ThreadListenerDatabase::desktop_local(0, secret).is_err());
        assert!(ThreadListenerDatabase::desktop_local(54321, &secret[..63]).is_err());
        let mut uppercase = secret.to_vec();
        uppercase[0] = b'A';
        assert!(ThreadListenerDatabase::desktop_local(54321, &uppercase).is_err());
    }
}
