//! `deadpool-postgres` 连接池。
//!
//! 连接参数由调用方以 [`DatabaseConfig`] **显式**传入。本模块一行 `std::env` 都不读：
//! env 的三档裁决（preserve / rename / remove，v3 §15.4）属于启动 / transport 层，
//! 被 remove 的变量出现在生产配置里要**启动报错**，那条判断做不到"库里顺手读一下"。
//!
//! TLS 走 [`tokio_postgres::NoTls`]：v3 §14.1 的部署形态是本机 / 同一信任域内的 PostgreSQL
//! （Desktop 由 Rust 监管本机 sidecar）。要跨网连库是另一件事，须连同证书校验一起立项，
//! 不在这里留一个"传 None 就明文"的开关。

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::db::InfraError;

/// Shared PostgreSQL pool type. Startup composition owns this value; transports only receive the
/// typed application service built from its adapters.
pub type DatabasePool = Pool;

/// 默认连接池上限。
pub const DEFAULT_MAX_POOL_SIZE: usize = 16;

/// 默认建连超时。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// PostgreSQL 连接参数与池参数。
///
/// [`Debug`] 是**手写**的：派生实现会把 `password` 原样打印，而 repository contract §5 不变量 8 要求
/// secret 不进普通日志与 trace，配置结构体恰恰是最容易被顺手 `tracing::debug!` 掉的东西。
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// 主机名或 IP。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 登录用户。
    pub user: String,
    /// 口令；无口令认证（peer / trust）时为 `None`。
    pub password: Option<String>,
    /// 数据库名。
    pub dbname: String,
    /// 写进 `application_name` 的标识，便于在 `pg_stat_activity` 里认出是谁。
    pub application_name: Option<String>,
    /// 池里最多同时存在多少连接。
    pub max_pool_size: usize,
    /// 单次建连超时。
    pub connect_timeout: Duration,
}

/// `DATABASE_URL` / libpq keyword 串无法映射成本项目单一 TCP 数据库配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DatabaseConfigParseError {
    /// libpq/URL 语法错误。
    #[error("database_url_malformed")]
    Malformed,
    /// 缺 host/user/dbname，或给了多个/Unix host。
    #[error("database_url_shape_unsupported")]
    UnsupportedShape,
    /// 连接串要求了本实现不能兑现且绝不能静默降级的 TLS/拓扑/会话选项。
    #[error("database_url_option_unsupported")]
    UnsupportedOption,
    /// password 不是 UTF-8。
    #[error("database_url_password_not_utf8")]
    PasswordNotUtf8,
}

impl DatabaseConfig {
    /// 用必填四项建配置，池参数取默认值。
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        dbname: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            password: None,
            dbname: dbname.into(),
            application_name: None,
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// 设置口令。
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// 设置 `application_name`。
    #[must_use]
    pub fn with_application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = Some(name.into());
        self
    }

    /// 设置池上限。
    #[must_use]
    pub fn with_max_pool_size(mut self, size: usize) -> Self {
        self.max_pool_size = size;
        self
    }

    /// 换一个库名，其余参数照抄。
    ///
    /// 建库 / 删库这类操作必须连到另一个库（通常是 `postgres`）上执行，这是那条路径的入口。
    #[must_use]
    pub fn with_dbname(mut self, dbname: impl Into<String>) -> Self {
        self.dbname = dbname.into();
        self
    }

    /// 翻译成 `tokio_postgres` 的连接配置。
    pub fn to_pg_config(&self) -> tokio_postgres::Config {
        let mut cfg = tokio_postgres::Config::new();
        cfg.host(&self.host)
            .port(self.port)
            .user(&self.user)
            .dbname(&self.dbname)
            .connect_timeout(self.connect_timeout);
        if let Some(password) = &self.password {
            cfg.password(password);
        }
        if let Some(name) = &self.application_name {
            cfg.application_name(name);
        }
        cfg
    }
}

impl FromStr for DatabaseConfig {
    type Err = DatabaseConfigParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = tokio_postgres::Config::from_str(value)
            .map_err(|_| DatabaseConfigParseError::Malformed)?;
        if parsed.get_hosts().len() != 1 {
            return Err(DatabaseConfigParseError::UnsupportedShape);
        }
        if !parsed.get_hostaddrs().is_empty() || parsed.get_ports().len() > 1 {
            return Err(DatabaseConfigParseError::UnsupportedShape);
        }
        let defaults = tokio_postgres::Config::new();
        if parsed.get_options().is_some()
            || matches!(
                parsed.get_ssl_mode(),
                tokio_postgres::config::SslMode::Require
            )
            || parsed.get_ssl_negotiation() != defaults.get_ssl_negotiation()
            || parsed.get_tcp_user_timeout().is_some()
            || parsed.get_keepalives() != defaults.get_keepalives()
            || parsed.get_keepalives_idle() != defaults.get_keepalives_idle()
            || parsed.get_keepalives_interval() != defaults.get_keepalives_interval()
            || parsed.get_keepalives_retries() != defaults.get_keepalives_retries()
            || parsed.get_target_session_attrs() != defaults.get_target_session_attrs()
            || matches!(
                parsed.get_channel_binding(),
                tokio_postgres::config::ChannelBinding::Require
            )
            || parsed.get_load_balance_hosts() != defaults.get_load_balance_hosts()
        {
            return Err(DatabaseConfigParseError::UnsupportedOption);
        }
        let host = match &parsed.get_hosts()[0] {
            tokio_postgres::config::Host::Tcp(host) if !host.is_empty() => host.clone(),
            _ => return Err(DatabaseConfigParseError::UnsupportedShape),
        };
        let user = parsed
            .get_user()
            .filter(|value| !value.is_empty())
            .ok_or(DatabaseConfigParseError::UnsupportedShape)?;
        let dbname = parsed
            .get_dbname()
            .filter(|value| !value.is_empty())
            .ok_or(DatabaseConfigParseError::UnsupportedShape)?;
        let port = parsed.get_ports().first().copied().unwrap_or(5432);
        let mut config = Self::new(host, port, user, dbname);
        if let Some(password) = parsed.get_password() {
            config = config.with_password(
                std::str::from_utf8(password)
                    .map_err(|_| DatabaseConfigParseError::PasswordNotUtf8)?,
            );
        }
        if let Some(application_name) = parsed.get_application_name() {
            config = config.with_application_name(application_name);
        }
        if let Some(connect_timeout) = parsed.get_connect_timeout() {
            config.connect_timeout = *connect_timeout;
        }
        Ok(config)
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("dbname", &self.dbname)
            .field("application_name", &self.application_name)
            .field("max_pool_size", &self.max_pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

/// 建池，并立刻取一次连接把参数验穿。
///
/// 不做这次取用的话，错口令 / 库不存在这类问题会推迟到第一条业务查询才暴露 ——
/// 那时候的调用栈已经在业务里了，报出来的是"查询失败"而不是"根本没连上"。
///
/// # Errors
///
/// 建池或首次取连接失败返回 [`InfraError::Connect`]。
pub async fn connect(config: &DatabaseConfig) -> Result<Pool, InfraError> {
    connect_config(
        config.to_pg_config(),
        config.max_pool_size,
        config.connect_timeout,
        format!("{} 数据库", config.dbname),
    )
    .await
}

/// Build and immediately probe one already-closed PostgreSQL driver configuration.
///
/// This is crate-private so callers cannot bypass [`DatabaseConfig`] for Server/network
/// connections. The Desktop Local adapter uses it with a fixed numeric-loopback topology and a
/// startup-only [`openbot_domain::vault::SecretBytes`] owner, avoiding a second public config path
/// that owns a password `String`.
pub(super) async fn connect_config(
    config: tokio_postgres::Config,
    max_pool_size: usize,
    connect_timeout: Duration,
    context: impl Into<String>,
) -> Result<Pool, InfraError> {
    let context = context.into();
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(manager)
        .max_size(max_pool_size)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(connect_timeout))
        .build()
        .map_err(|source| InfraError::connect(format!("建立{context}连接池"), source))?;
    let _probe = pool
        .get()
        .await
        .map_err(|source| InfraError::connect(format!("取{context}首个连接"), source))?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_password() {
        let config = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot")
            .with_password("hunter2-绝对不能出现在日志里")
            .with_application_name("openbot-test");
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("hunter2"),
            "口令泄漏进 Debug：{rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // 正向对照：非敏感字段确实被打印了，说明上面不是在一个空串上判"不含"。
        assert!(rendered.contains("openbot-test"));
        assert!(rendered.contains("5432"));
    }

    #[test]
    fn debug_distinguishes_no_password_from_a_redacted_one() {
        let without = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot");
        assert!(format!("{without:?}").contains("password: None"));
    }

    #[test]
    fn builders_keep_the_other_fields_untouched() {
        let base = DatabaseConfig::new("db.internal", 6432, "openbot", "openbot")
            .with_password("s3cret")
            .with_application_name("openbot-server")
            .with_max_pool_size(4);
        let switched = base.clone().with_dbname("postgres");
        assert_eq!(switched.dbname, "postgres");
        assert_eq!(switched.host, base.host);
        assert_eq!(switched.port, base.port);
        assert_eq!(switched.user, base.user);
        assert_eq!(switched.password, base.password);
        assert_eq!(switched.application_name, base.application_name);
        assert_eq!(switched.max_pool_size, 4);
    }

    #[test]
    fn defaults_are_the_documented_constants() {
        let config = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot");
        assert_eq!(config.max_pool_size, DEFAULT_MAX_POOL_SIZE);
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.password, None);
        assert_eq!(config.application_name, None);
    }

    #[test]
    fn pg_config_carries_every_field_that_was_set() {
        let config = DatabaseConfig::new("db.internal", 6432, "openbot", "openbot_main")
            .with_password("s3cret")
            .with_application_name("openbot-server");
        let pg = config.to_pg_config();
        assert_eq!(pg.get_ports(), &[6432]);
        assert_eq!(pg.get_user(), Some("openbot"));
        assert_eq!(pg.get_dbname(), Some("openbot_main"));
        assert_eq!(pg.get_password(), Some(&b"s3cret"[..]));
        assert_eq!(pg.get_application_name(), Some("openbot-server"));
        assert_eq!(pg.get_connect_timeout(), Some(&DEFAULT_CONNECT_TIMEOUT));
    }

    #[test]
    fn database_url_and_keyword_forms_share_one_parser_and_redact_password() {
        for raw in [
            "postgresql://openbot:secret@127.0.0.1:5544/openbot",
            "host=127.0.0.1 port=5544 user=openbot password=secret dbname=openbot",
        ] {
            let config: DatabaseConfig = raw.parse().unwrap();
            assert_eq!(config.host, "127.0.0.1");
            assert_eq!(config.port, 5544);
            assert_eq!(config.user, "openbot");
            assert_eq!(config.dbname, "openbot");
            assert_eq!(config.password.as_deref(), Some("secret"));
            assert!(!format!("{config:?}").contains("secret"));
        }
    }

    #[test]
    fn malformed_or_ambiguous_database_shapes_are_refused_not_guessed() {
        assert_eq!(
            "not a database url".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::Malformed),
        );
        assert_eq!(
            "host=a,b user=u dbname=d".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::UnsupportedShape),
        );
        assert_eq!(
            "host=127.0.0.1 dbname=d".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::UnsupportedShape),
        );
    }

    #[test]
    fn security_or_topology_options_are_never_silently_downgraded() {
        for raw in [
            "host=127.0.0.1 user=u dbname=d sslmode=require",
            "host=127.0.0.1 user=u dbname=d target_session_attrs=read-write",
            "host=127.0.0.1 user=u dbname=d channel_binding=require",
            "host=127.0.0.1 user=u dbname=d options=-cstatement_timeout=10s",
            "host=127.0.0.1 hostaddr=127.0.0.2 user=u dbname=d",
        ] {
            assert!(
                matches!(
                    raw.parse::<DatabaseConfig>(),
                    Err(DatabaseConfigParseError::UnsupportedOption
                        | DatabaseConfigParseError::UnsupportedShape)
                ),
                "不可兑现的连接要求被静默接受：{raw}",
            );
        }

        // 正向对照：显式 NoTls 与默认 prefer 在本实现里都能如实兑现，不应被误拒。
        assert!(
            "host=127.0.0.1 user=u dbname=d sslmode=disable"
                .parse::<DatabaseConfig>()
                .is_ok()
        );
        assert!(
            "host=127.0.0.1 user=u dbname=d sslmode=prefer"
                .parse::<DatabaseConfig>()
                .is_ok()
        );
    }
}
