//! 上游 28 张表的类型化行结构（`parity/tables.yaml` 里 28 条 `label: parity` 表条目的
//! `target: openbot-infra::db::tables::<表名>`）。
//!
//! 一张表一个 `pub mod`，模块里恒有四样东西，全部由 `define_table!` 从**同一份**列清单展开，
//! 所以「结构体字段」「`COLUMNS`」「`COLUMN_SPECS`」三者在构造上不可能各自漂开：
//!
//! - `TABLE_NAME: &str` —— 表名；
//! - `COLUMNS: &[&str]` —— 列名，按 `pg_attribute.attnum` 升序；
//! - `COLUMN_SPECS: &[ColumnSpec]` —— 逐列的 SQL 形态（列名 / `format_type()` 文本 / 是否 NOT NULL）；
//! - `struct Row` + `impl TryFrom<&tokio_postgres::Row>` —— 类型化行与解码。
//!
//! 上游 28 表的列真源是 `fixtures/db/schema-0012.json`；0013/0016 新增表各有 post-migration
//! fixture。与真库的一致性由集成测试机械核对，不靠人读。
//!
//! # 类型映射
//!
//! | `format_type()` | Rust（NOT NULL / 可空） |
//! | --- | --- |
//! | `text` | `String` / `Option<String>` |
//! | `boolean` | `bool` |
//! | `bigint` | `i64` |
//! | `integer` | `i32` |
//! | `jsonb` | `serde_json::Value` / `Option<serde_json::Value>` |
//! | `timestamp with time zone` | `time::OffsetDateTime` / `Option<_>` |
//! | `text[]` | `Vec<Option<String>>` |
//! | `uuid` | `uuid::Uuid` / `Option<uuid::Uuid>` |
//! | `agent_type` / `agent_visibility` / `credential_kind` / `role` | [`crate::db::types`] 的四个封闭枚举 |
//!
//! `text[]` 是 `Vec<Option<String>>` 而不是 `Vec<String>`：PostgreSQL 的数组**元素**可以是
//! NULL，列上的 `NOT NULL` 只管整个数组不为 NULL，管不到元素。写成 `Vec<String>` 的话，
//! 一个 `{NULL,x}` 会让整行在 `try_get` 时报错 —— 那是运行期某一行随机解不出来，
//! 不是启动期的确定性拒绝。`fixtures/db/seed-0012.sql` 里就有这种值，
//! 集成测试 `every_seeded_row_decodes_through_its_row_struct` 盯着它。
//!
//! # secret 列脱敏
//!
//! `Row` 的 `Debug` 是**手写**的（由 `define_table!` 机械展开），登记在 [`SECRET_COLUMNS`] 里的列
//! 一律渲染成 `<redacted>`。理由是 repository contract §5 不变量 8 逐字要求 secret 不进「普通日志、trace」，
//! 而 `#[derive(Debug)]` 会让任何一句 `tracing::debug!("{:?}", row)`、任何一次 `unwrap` 的 panic
//! 消息把明文令牌写进日志 —— 那是一条**默认打开**的泄漏路径，不是理论风险。
//!
//! 防漏登记由 `every_column_matching_a_secret_word_root_is_classified` 兜底：凡列名命中
//! [`SECRET_COLUMN_NAME_ROOTS`] 却既不在 [`SECRET_COLUMNS`] 也不在 [`SECRET_SCAN_EXEMPTIONS`]
//! 的，当场判红。将来有人加一列 `refresh_token` 而忘了登记，闸门会拦住。
//!
//! 0013、0016、0020、0021、0022、0023、0026、0028 与 0030 的 native 表分别登记在 [`NATIVE_0013_TABLES`] /
//! [`NATIVE_0016_TABLES`] / [`NATIVE_0020_TABLES`] / [`NATIVE_0021_TABLES`] /
//! [`NATIVE_0022_TABLES`] / [`NATIVE_0023_TABLES`] / [`NATIVE_0026_TABLES`] /
//! [`NATIVE_0028_TABLES`] 与 [`NATIVE_0030_TABLES`]，
//! 始终不混进只代表固定上游 0012 的 [`ALL_TABLES`]。

use std::fmt;

/// `Debug` 里 secret 列的占位。
///
/// 不带引号地写 `<redacted>`，好让「这一列被脱敏了」与「这一列的值恰好是字符串
/// `"<redacted>"`」在输出里区分得开。
pub struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// 承载凭据、明文令牌或密文的列，`(表名, 列名)`，按表名再列名升序。
///
/// 登记在册的列在 `Row` 的 `Debug` 里渲染成 `<redacted>`（repository contract §5 不变量 8）。
/// 逐条理由：
///
/// - `accounts` 的四列是上游 better-auth 直接落盘的**明文** OAuth 令牌与口令
///   （`parity/tables.yaml::tbl-accounts` 的 notes 逐字写明「加密=无：access_token /
///   refresh_token / id_token / password 是明文 text 列」）。
/// - `agent_profiles.callback_token_hash` 是回调令牌的散列。散列不是原文，但它是**验证物**：
///   泄漏之后可以离线爆破低熵令牌，所以按 secret 处理而不是按摘要处理。
/// - `credentials.encrypted_value` 是 vault 密文本体。
/// - `sessions.token` 是明文会话令牌，拿到即可冒充该用户。
/// - `sso_providers` 的两列是上游 `encrypt-sso-config.ts::ENCRYPTED_FIELDS` 点名要加密的字段，
///   即上游自己也认定它们承载凭据。
/// - `verifications.value` 是明文验证码 / 一次性令牌。
pub const SECRET_COLUMNS: &[(&str, &str)] = &[
    ("accounts", "access_token"),
    ("accounts", "id_token"),
    ("accounts", "password"),
    ("accounts", "refresh_token"),
    ("agent_profiles", "callback_token_hash"),
    ("audit_checkpoints", "signature"),
    ("component_human_decisions", "answer"),
    ("component_human_decisions", "arguments"),
    ("component_human_decisions", "arguments_hash"),
    ("credentials", "encrypted_value"),
    ("intelligence_import_cursors", "cursor"),
    ("intelligence_import_cursors", "provenance"),
    ("memories", "content"),
    ("memories", "tags"),
    ("memory_events", "metadata"),
    ("messages", "content"),
    ("messages", "search_text"),
    ("model_connection_secrets", "encrypted_value"),
    ("outbox", "payload"),
    ("remote_agent_interrupts", "descriptor"),
    ("remote_agent_interrupts", "response_payload"),
    ("run_events", "payload"),
    ("runs", "fencing_token"),
    ("sessions", "token"),
    ("sso_providers", "oidc_config"),
    ("sso_providers", "saml_config"),
    ("thread_leases", "fencing_token"),
    ("threads", "title"),
    ("tool_approvals", "args_hash"),
    ("tool_approvals", "arguments_summary"),
    ("tool_approvals", "change_summary"),
    ("tool_attempts", "capability_id"),
    ("tool_calls", "args_hash"),
    ("tool_calls", "idempotency_key"),
    ("verifications", "value"),
];

/// 防漏登记扫描用的列名词根，小写子串匹配。
///
/// 词根的取舍：
///
/// - `token` / `password` / `secret` / `encrypted` / `cipher` —— 直接以凭据物命名的列。
/// - `credential` / `key` —— 可能是凭据本体，也可能只是指向 vault 的**指针**，必须逐个裁决；
///   正因为两种都有，才不能靠词根自动判定，只能靠词根把它们**逼到台面上**。
/// - `config` —— 上游对 `oidc_config` / `saml_config` 做过加密适配，说明本仓的 `config` 类列
///   确实会装凭据。
/// - `hash` / `value` —— `agent_profiles.callback_token_hash` 之外，`verifications.value` 与
///   `credentials.encrypted_value` 这两个真凭据列名里没有前面任何词根，只有靠这两个词根才扫得到。
///
/// 刻意**不**收 `url`：`mcp_servers.url` 之类理论上能在 query string 里夹凭据，但把 URL 全列
/// 拉进来会让豁免名单膨胀到失去信噪比，而真凭据早已由 `credentials` 表承载。
pub const SECRET_COLUMN_NAME_ROOTS: &[&str] = &[
    "cipher",
    "config",
    "credential",
    "encrypted",
    "hash",
    "key",
    "password",
    "secret",
    "token",
    "value",
];

/// 命中 [`SECRET_COLUMN_NAME_ROOTS`] 但**不是**凭据的列，`(表名, 列名, 理由)`。
///
/// 每一项都必须给出书面理由 —— 豁免一条 secret 扫描而不说为什么，等于把闸门关掉。
pub const SECRET_SCAN_EXEMPTIONS: &[(&str, &str, &str)] = &[
    (
        "accounts",
        "access_token_expires_at",
        "timestamptz：令牌的过期时刻，不含令牌本身",
    ),
    (
        "accounts",
        "refresh_token_expires_at",
        "timestamptz：令牌的过期时刻，不含令牌本身",
    ),
    (
        "agent_profiles",
        "callback_token_issued_at",
        "timestamptz：令牌的签发时刻，不含令牌本身",
    ),
    (
        "audit_checkpoints",
        "first_row_hash",
        "SHA-256 链边界摘要是公开完整性证据，不是 secret 或可用认证物",
    ),
    (
        "audit_checkpoints",
        "last_row_hash",
        "SHA-256 链边界摘要是公开完整性证据，不是 secret 或可用认证物",
    ),
    (
        "agents",
        "configuration",
        // 这条豁免有上游写入侧的实证，不是"看着像公开配置"的推断。
        //
        // 上游 `server/src/agents/auth-header.ts` 刻意把凭据值挡在本列之外，理由与本仓
        // 关心的完全相同 —— 它的模块注释原文说：把 token 放进 `configuration` 会让
        // "anything that can read an agent, including the admin API that lists them"
        // 都读得到，而且无法在不编辑 agent 的情况下吊销。所以
        // "The vault holds the value. The agent's configuration holds only the
        // credential's id and the header name"。
        //
        // 类型也钉死了这件事：`auth-header.ts::AgentAuth` 恰有两个字段 —— `header`
        // （注释逐字 "Not secret."）与 `credentialId`（注释逐字 "The vault row holding
        // the value."）；`auth-header.ts::authFromConfiguration` 的文档注释逐字写着
        // "Value never appears here."
        //
        // **失效条件**：一旦 `configuration` 开始承载凭据**本体**（而不是
        // `{header, credentialId}` 这对指向 vault 的指针），本条豁免必须立即撤销、
        // 把该列登记进 SECRET_COLUMNS。改动 agent 配置写入侧的人请先看这里。
        "jsonb：agent 的公开配置。它承载的是 `{header, credentialId}` 这对指向 vault 的\
         **指针**，不是凭据本体（上游 auth-header.ts::AgentAuth 与 authFromConfiguration 逐字保证）；\
         凭据值在 credentials 表（kind='agent'）。遮掉整列只会让配置排障失去可观测性，\
         换不来任何 secret 保护",
    ),
    (
        "credentials",
        "key_id",
        "text：解密密钥的**标识符**，不是密钥本身；脱敏它会让密钥轮换的排障无从下手",
    ),
    (
        "mcp_servers",
        "credential_id",
        "uuid：指向 credentials 表的外键，是指针不是凭据",
    ),
    (
        "mcp_user_credentials",
        "credential_id",
        "uuid：指向 credentials 表的外键，是指针不是凭据",
    ),
    (
        "intelligence_import_cursors",
        "last_hash",
        "SHA-256 导入完整性摘要，不是 secret 或可用认证物",
    ),
    (
        "model_connections",
        "current_secret_id",
        "uuid：私有复合外键指针，不含凭据；密文位于model_connection_secrets.encrypted_value，引用不进入读DTO",
    ),
    (
        "run_model_selections",
        "secret_id",
        "uuid：私有历史密钥关系指针，不含凭据值，且本身不授予解封权限",
    ),
    (
        "runs",
        "budget_max_output_tokens",
        "bigint：run 输出 token 的数值上限，不含任何可认证 token 字节",
    ),
    (
        "runs",
        "cost_max_input_micro_units_per_million_tokens",
        "bigint：输入 token 的公开计价比率，不含 prompt 或可认证 token 字节",
    ),
    (
        "runs",
        "cost_max_output_micro_units_per_million_tokens",
        "bigint：输出 token 的公开计价比率，不含回复或可认证 token 字节",
    ),
    (
        "runs",
        "usage_input_tokens",
        "bigint：provider 输入 token 的累计数量，不含 prompt 或可认证 token 字节",
    ),
    (
        "runs",
        "usage_last_input_tokens",
        "bigint：最后一次 sampling 的输入 token 数量，不含 prompt 或可认证 token 字节",
    ),
    (
        "runs",
        "usage_last_output_tokens",
        "bigint：最后一次 sampling 的输出 token 数量，不含回复或可认证 token 字节",
    ),
    (
        "runs",
        "usage_last_total_tokens",
        "bigint：最后一次 sampling 的总 token 数量，不含内容或可认证 token 字节",
    ),
    (
        "runs",
        "usage_output_tokens",
        "bigint：provider 输出 token 的累计数量，不含回复或可认证 token 字节",
    ),
    (
        "runs",
        "usage_total_tokens",
        "bigint：provider 报告 token 的累计总数，不含内容或可认证 token 字节",
    ),
    (
        "tool_calls",
        "schema_hash",
        "SHA-256 catalog schema 摘要是公开版本标识，不由运行期 secret 输入派生",
    ),
];

/// 这一列是否登记在 [`SECRET_COLUMNS`] 里。
///
/// 由 `define_table!` 展开出来的 `Debug` 调用。线性扫 32 项 —— `Debug` 不在热路径上，
/// 换成完美哈希只会多一处可以和台账漂开的东西。
pub fn is_secret_column(table: &str, column: &str) -> bool {
    SECRET_COLUMNS
        .iter()
        .any(|(t, c)| *t == table && *c == column)
}

/// 一列的 SQL 形态。
///
/// `sql_type` 是 PostgreSQL `format_type(atttypid, atttypmod)` 的输出文本（例如 `text`、
/// `timestamp with time zone`、`text[]`、`uuid`、`role`），与 `schema_facts.sql` 取的是同一个值，
/// 所以两边可以逐字符比较，不需要任何"等价类型"表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnSpec {
    /// 列名。
    pub name: &'static str,
    /// `format_type()` 输出的类型文本。
    pub sql_type: &'static str,
    /// 是否 `NOT NULL`。
    pub not_null: bool,
}

impl ColumnSpec {
    /// 供 `define_table!` 展开使用。
    pub const fn new(name: &'static str, sql_type: &'static str, not_null: bool) -> Self {
        Self {
            name,
            sql_type,
            not_null,
        }
    }
}

/// 一张表的台账条目，供 [`crate::db::compat`] 与测试遍历 28 张表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSpec {
    /// 表名。
    pub name: &'static str,
    /// 列名，按 `attnum` 升序。
    pub columns: &'static [&'static str],
    /// 逐列的 SQL 形态，顺序同 `columns`。
    pub column_specs: &'static [ColumnSpec],
}

/// repository 层对所有类型化行的封闭公共面。
///
/// 实现只由 [`define_table!`] 展开；表名与列名因此都是编译期字面量，repo 可以机械生成 SQL，
/// 但 transport/application 没有传入自由表名、列名或 predicate 的入口。
pub trait TableRow: Sized {
    /// PostgreSQL public 表名。
    const TABLE_NAME: &'static str;
    /// 全部列，按 `attnum` 升序。
    const COLUMNS: &'static [&'static str];

    /// 按 [`Self::COLUMNS`] 顺序借出绑定参数。
    fn as_sql_params(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)>;

    /// 从 PostgreSQL 行解码。
    fn try_from_pg(row: &tokio_postgres::Row) -> Result<Self, crate::db::RowDecodeError>;
}

/// 从一份列清单同时展开行结构体与列台账。
///
/// 语法：
///
/// ```ignore
/// crate::db::tables::define_table! {
///     table = "users";
///     id: String = ("id", "text", true),
///     name: Option<String> = ("name", "text", false),
/// }
/// ```
///
/// 每行是 `<Rust 字段>: <Rust 类型> = ("<列名>", "<format_type() 文本>", <是否 NOT NULL>)`。
/// Rust 字段名与列名分开写，是因为 `type` / `ref` / `override` 这三个列名撞上 Rust 关键字，
/// 必须写成 raw identifier（`r#type` / `r#ref` / `r#override`）。
macro_rules! define_table {
    (
        table = $table:literal;
        $(
            $field:ident : $ty:ty = ($column:literal, $sql_type:literal, $not_null:literal)
        ),+ $(,)?
    ) => {
        /// PostgreSQL 表名。
        pub const TABLE_NAME: &str = $table;

        /// 列名，按 `pg_attribute.attnum` 升序。
        pub const COLUMNS: &[&str] = &[$($column),+];

        /// 逐列的 SQL 形态，顺序同 [`COLUMNS`]。
        pub const COLUMN_SPECS: &[$crate::db::tables::ColumnSpec] = &[
            $($crate::db::tables::ColumnSpec::new($column, $sql_type, $not_null)),+
        ];

        /// 本表的类型化行。
        ///
        /// 字段顺序即列顺序；可空列是 `Option<_>`。
        ///
        /// `Debug` 手写而非派生：登记在 [`crate::db::tables::SECRET_COLUMNS`] 里的列渲染成
        /// `<redacted>`。
        #[derive(Clone, PartialEq)]
        pub struct Row {
            $(
                #[doc = concat!("`", $column, " ", $sql_type, "`")]
                pub $field: $ty,
            )+
        }

        impl ::core::fmt::Debug for Row {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                // 字段名用**列名**而不是 Rust 字段名：本层是对数据库的保真映射，
                // 而且这样 `type` / `ref` / `override` 不会渲染成 `r#type` 这种噪声。
                let mut out = f.debug_struct(TABLE_NAME);
                $(
                    if $crate::db::tables::is_secret_column(TABLE_NAME, $column) {
                        out.field($column, &$crate::db::tables::Redacted);
                    } else {
                        out.field($column, &self.$field);
                    }
                )+
                out.finish()
            }
        }

        impl Row {
            /// 把各列按 [`COLUMNS`] 的顺序摊平成绑定参数。
            ///
            /// 唯一用途是 **read checksum**（v3 §24 G1「read checksum 0 差异」/
            /// §19.2 W5–10 退出闸门「DB read checksum 100%」）：把解码出来的值原样送回
            /// PostgreSQL 重新组装成同一个复合类型，由**同一个** PostgreSQL 在两侧各渲染一次
            /// 再比摘要。这样"值有没有在往返中变形"这件事，不依赖 Rust 侧的任何格式化 ——
            /// 跨语言规范化（浮点格式、时间戳渲染、数组转义）永远对不齐，拿它做判据的实现
            /// 要么恒绿要么恒红。
            ///
            /// 顺序与 [`COLUMNS`] 一致，所以可以直接喂给
            /// `ROW($1, …, $n)::public.<表名>`。
            pub fn as_sql_params(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
                <Self as $crate::db::tables::TableRow>::as_sql_params(self)
            }
        }

        impl TryFrom<&tokio_postgres::Row> for Row {
            type Error = $crate::db::RowDecodeError;

            fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
                Ok(Self {
                    $(
                        $field: row.try_get($column).map_err(|source| {
                            $crate::db::RowDecodeError::column(TABLE_NAME, $column, source)
                        })?,
                    )+
                })
            }
        }

        impl $crate::db::tables::TableRow for Row {
            const TABLE_NAME: &'static str = TABLE_NAME;
            const COLUMNS: &'static [&'static str] = COLUMNS;

            fn as_sql_params(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
                vec![$(&self.$field),+]
            }

            fn try_from_pg(
                row: &tokio_postgres::Row,
            ) -> Result<Self, $crate::db::RowDecodeError> {
                Self::try_from(row)
            }
        }
    };
}

pub(crate) use define_table;

/// 一次性声明 28 个表模块并建出 [`ALL_TABLES`] 台账。
///
/// 两者从同一份模块名清单展开，所以「有模块但没进台账」在构造上不可能发生 —— 那正是
/// 「新增一张表却忘了接进检查」这类漏网的形态。
macro_rules! table_registry {
    ($($module:ident),+ $(,)?) => {
        $(pub mod $module;)+

        /// 上游 28 张表的台账，按表名升序。
        pub const ALL_TABLES: &[TableSpec] = &[
            $(TableSpec {
                name: $module::TABLE_NAME,
                columns: $module::COLUMNS,
                column_specs: $module::COLUMN_SPECS,
            }),+
        ];
    };
}

table_registry!(
    accounts,
    action_policy,
    agent_preferences,
    agent_profiles,
    agents,
    audit_events,
    channel_agents,
    channel_memberships,
    channels,
    component_exclusions,
    component_functions,
    components,
    computer_snapshot,
    credentials,
    deployment_packages,
    intelligence_channel_mappings,
    mcp_servers,
    mcp_tools,
    mcp_user_credentials,
    plugin_grants,
    revoked_access,
    sandboxed_components,
    sessions,
    skills,
    sso_providers,
    user_roles,
    users,
    verifications,
);

pub mod audit_checkpoints;
pub mod tool_attempts;
pub mod tool_calls;

/// native 0013 新增的三张 public 表，按表名升序。
pub const NATIVE_0013_TABLES: &[TableSpec] = &[
    TableSpec {
        name: audit_checkpoints::TABLE_NAME,
        columns: audit_checkpoints::COLUMNS,
        column_specs: audit_checkpoints::COLUMN_SPECS,
    },
    TableSpec {
        name: tool_attempts::TABLE_NAME,
        columns: tool_attempts::COLUMNS,
        column_specs: tool_attempts::COLUMN_SPECS,
    },
    TableSpec {
        name: tool_calls::TABLE_NAME,
        columns: tool_calls::COLUMNS,
        column_specs: tool_calls::COLUMN_SPECS,
    },
];

pub mod intelligence_import_cursors;
pub mod memories;
pub mod memory_events;
pub mod messages;
pub mod outbox;
pub mod run_events;
pub mod runs;
pub mod thread_leases;
pub mod thread_memberships;
pub mod threads;

/// Native 0016 的十张 thread/realtime/memory 表，按表名升序；`runs` 的 typed row
/// 同步包含 0024 usage、0025 maximum-rate cost-upper-bound 与 0026 frozen user-cap suffix。
pub const NATIVE_0016_TABLES: &[TableSpec] = &[
    TableSpec {
        name: intelligence_import_cursors::TABLE_NAME,
        columns: intelligence_import_cursors::COLUMNS,
        column_specs: intelligence_import_cursors::COLUMN_SPECS,
    },
    TableSpec {
        name: memories::TABLE_NAME,
        columns: memories::COLUMNS,
        column_specs: memories::COLUMN_SPECS,
    },
    TableSpec {
        name: memory_events::TABLE_NAME,
        columns: memory_events::COLUMNS,
        column_specs: memory_events::COLUMN_SPECS,
    },
    TableSpec {
        name: messages::TABLE_NAME,
        columns: messages::COLUMNS,
        column_specs: messages::COLUMN_SPECS,
    },
    TableSpec {
        name: outbox::TABLE_NAME,
        columns: outbox::COLUMNS,
        column_specs: outbox::COLUMN_SPECS,
    },
    TableSpec {
        name: run_events::TABLE_NAME,
        columns: run_events::COLUMNS,
        column_specs: run_events::COLUMN_SPECS,
    },
    TableSpec {
        name: runs::TABLE_NAME,
        columns: runs::COLUMNS,
        column_specs: runs::COLUMN_SPECS,
    },
    TableSpec {
        name: thread_leases::TABLE_NAME,
        columns: thread_leases::COLUMNS,
        column_specs: thread_leases::COLUMN_SPECS,
    },
    TableSpec {
        name: thread_memberships::TABLE_NAME,
        columns: thread_memberships::COLUMNS,
        column_specs: thread_memberships::COLUMN_SPECS,
    },
    TableSpec {
        name: threads::TABLE_NAME,
        columns: threads::COLUMNS,
        column_specs: threads::COLUMN_SPECS,
    },
];

pub mod tool_approvals;

/// Native 0020 durable human approval table.
pub const NATIVE_0020_TABLES: &[TableSpec] = &[TableSpec {
    name: tool_approvals::TABLE_NAME,
    columns: tool_approvals::COLUMNS,
    column_specs: tool_approvals::COLUMN_SPECS,
}];

pub mod user_ui_preferences;

/// Native 0021 actor-scoped UI preference table.
pub const NATIVE_0021_TABLES: &[TableSpec] = &[TableSpec {
    name: user_ui_preferences::TABLE_NAME,
    columns: user_ui_preferences::COLUMNS,
    column_specs: user_ui_preferences::COLUMN_SPECS,
}];

pub mod user_memory_controls;

/// Native 0022 actor-scoped runtime memory control table.
pub const NATIVE_0022_TABLES: &[TableSpec] = &[TableSpec {
    name: user_memory_controls::TABLE_NAME,
    columns: user_memory_controls::COLUMNS,
    column_specs: user_memory_controls::COLUMN_SPECS,
}];

pub mod component_human_decisions;

/// Native 0023 durable compiled-component human decisions table.
pub const NATIVE_0023_TABLES: &[TableSpec] = &[TableSpec {
    name: component_human_decisions::TABLE_NAME,
    columns: component_human_decisions::COLUMNS,
    column_specs: component_human_decisions::COLUMN_SPECS,
}];

pub mod user_run_cost_budgets;

/// Native 0026 actor-scoped per-run cost budget table.
pub const NATIVE_0026_TABLES: &[TableSpec] = &[TableSpec {
    name: user_run_cost_budgets::TABLE_NAME,
    columns: user_run_cost_budgets::COLUMNS,
    column_specs: user_run_cost_budgets::COLUMN_SPECS,
}];

pub mod remote_agent_interrupts;

/// Native 0028 actor-scoped remote AG-UI interrupt/resume table.
pub const NATIVE_0028_TABLES: &[TableSpec] = &[TableSpec {
    name: remote_agent_interrupts::TABLE_NAME,
    columns: remote_agent_interrupts::COLUMNS,
    column_specs: remote_agent_interrupts::COLUMN_SPECS,
}];

pub mod model_connection_secrets;
pub mod model_connections;
pub mod run_model_selections;

/// Native 0031 private historical custom-model run selection.
pub const NATIVE_0031_TABLES: &[TableSpec] = &[TableSpec {
    name: run_model_selections::TABLE_NAME,
    columns: run_model_selections::COLUMNS,
    column_specs: run_model_selections::COLUMN_SPECS,
}];

/// Native 0030 personal model connections and their scoped Vault ciphertext records.
pub const NATIVE_0030_TABLES: &[TableSpec] = &[
    TableSpec {
        name: model_connection_secrets::TABLE_NAME,
        columns: model_connection_secrets::COLUMNS,
        column_specs: model_connection_secrets::COLUMN_SPECS,
    },
    TableSpec {
        name: model_connections::TABLE_NAME,
        columns: model_connections::COLUMNS,
        column_specs: model_connections::COLUMN_SPECS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn current_table_specs() -> impl Iterator<Item = &'static TableSpec> {
        ALL_TABLES
            .iter()
            .chain(NATIVE_0013_TABLES.iter())
            .chain(NATIVE_0016_TABLES.iter())
            .chain(NATIVE_0020_TABLES.iter())
            .chain(NATIVE_0021_TABLES.iter())
            .chain(NATIVE_0022_TABLES.iter())
            .chain(NATIVE_0023_TABLES.iter())
            .chain(NATIVE_0026_TABLES.iter())
            .chain(NATIVE_0028_TABLES.iter())
            .chain(NATIVE_0030_TABLES.iter())
            .chain(NATIVE_0031_TABLES.iter())
    }

    /// 每张表的列数。数值取自参照库（`fixtures/db/schema-0012.json`），合计必须是 204。
    ///
    /// 这是对 `COLUMN_SPECS` 的**独立复述**：宏保证了「字段数 == `COLUMNS.len()` ==
    /// `COLUMN_SPECS.len()`」，但保证不了这个数字本身是对的；对不上说明某张表的列清单被改过。
    const EXPECTED_COLUMN_COUNTS: &[(&str, usize)] = &[
        ("accounts", 14),
        ("action_policy", 6),
        ("agent_preferences", 3),
        ("agent_profiles", 11),
        ("agents", 8),
        ("audit_events", 7),
        ("channel_agents", 3),
        ("channel_memberships", 3),
        ("channels", 12),
        ("component_exclusions", 5),
        ("component_functions", 5),
        ("components", 10),
        ("computer_snapshot", 5),
        ("credentials", 9),
        ("deployment_packages", 5),
        ("intelligence_channel_mappings", 5),
        ("mcp_servers", 11),
        ("mcp_tools", 5),
        ("mcp_user_credentials", 6),
        ("plugin_grants", 6),
        ("revoked_access", 3),
        ("sandboxed_components", 19),
        ("sessions", 8),
        ("skills", 10),
        ("sso_providers", 8),
        ("user_roles", 3),
        ("users", 8),
        ("verifications", 6),
    ];

    #[test]
    fn registry_holds_exactly_the_28_upstream_tables_in_sorted_order() {
        assert_eq!(ALL_TABLES.len(), 28);
        let names: Vec<&str> = ALL_TABLES.iter().map(|t| t.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "ALL_TABLES 必须按表名升序且无重复");
    }

    #[test]
    fn every_table_column_count_matches_the_reference_schema() {
        assert_eq!(
            EXPECTED_COLUMN_COUNTS.len(),
            ALL_TABLES.len(),
            "期望表与台账表数量不一致",
        );
        for (table, expected) in EXPECTED_COLUMN_COUNTS {
            let spec = ALL_TABLES
                .iter()
                .find(|t| t.name == *table)
                .unwrap_or_else(|| panic!("台账里没有表 {table}"));
            assert_eq!(spec.columns.len(), *expected, "表 {table} 的列数对不上");
            assert_eq!(
                spec.column_specs.len(),
                *expected,
                "表 {table} 的 COLUMN_SPECS 长度对不上",
            );
        }
        let total: usize = ALL_TABLES.iter().map(|t| t.columns.len()).sum();
        assert_eq!(total, 204, "28 张表的列数合计必须是 204");
    }

    #[test]
    fn columns_and_column_specs_name_the_same_columns_in_the_same_order() {
        for table in ALL_TABLES {
            let from_specs: Vec<&str> = table.column_specs.iter().map(|c| c.name).collect();
            assert_eq!(
                table.columns,
                &from_specs[..],
                "表 {} 的 COLUMNS 与 COLUMN_SPECS 不一致",
                table.name,
            );
            let mut seen: Vec<&str> = table.columns.to_vec();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(
                seen.len(),
                table.columns.len(),
                "表 {} 有重名列",
                table.name
            );
        }
    }

    /// 每个 `sql_type` 都必须落在实测出来的类型里。
    ///
    /// 反面：写错成 `varchar` / `timestamptz` 这类"看起来对"的别名会被当场判红 ——
    /// `format_type()` 不会输出它们，比对时只会得到一堆"类型不符"。
    #[test]
    fn column_sql_types_are_drawn_from_the_reference_type_set() {
        const KNOWN: &[&str] = &[
            "agent_type",
            "agent_visibility",
            "bigint",
            "boolean",
            "credential_kind",
            "integer",
            "jsonb",
            "role",
            "smallint",
            "text",
            "text[]",
            "timestamp with time zone",
            "uuid",
        ];
        let mut unseen: Vec<&str> = KNOWN.to_vec();
        for table in current_table_specs() {
            for column in table.column_specs {
                assert!(
                    KNOWN.contains(&column.sql_type),
                    "表 {} 的列 {} 用了未知类型 {}",
                    table.name,
                    column.name,
                    column.sql_type,
                );
                unseen.retain(|t| *t != column.sql_type);
            }
        }
        // 正向对照：12 个类型每一个都真的被某一列用到，否则 KNOWN 里混进了不存在的类型。
        assert!(
            unseen.is_empty(),
            "KNOWN 里有没被任何列用到的类型：{unseen:?}"
        );
    }

    #[test]
    fn not_null_column_count_matches_the_reference_schema() {
        let not_null: usize = ALL_TABLES
            .iter()
            .flat_map(|t| t.column_specs.iter())
            .filter(|c| c.not_null)
            .count();
        // 0012 fixture 的 59 个 constraint 不重复计 NOT NULL；153 个非空事实在列上独立核对。
        assert_eq!(not_null, 153);
    }

    // ---------------------------------------------------------------------
    // secret 列脱敏
    // ---------------------------------------------------------------------

    /// 哨兵：只要它出现在 `Debug` 输出里，就说明该列没被脱敏。
    const SENTINEL: &str = "SENTINEL-DO-NOT-LOG";

    /// 非 secret 列的标记值。正向对照用 —— 只断言"不含哨兵"的测试，在
    /// "`Debug` 输出恒为空串"的世界里同样通过。
    const MARKER: &str = "MARKER-VISIBLE";

    fn epoch() -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH
    }

    /// 断言：脱敏生效（不含哨兵）**且** `Debug` 确实在输出内容（含标记与表名）。
    fn assert_redacted(table: &str, rendered: &str) {
        assert!(
            !rendered.contains(SENTINEL),
            "{table} 的 Debug 泄漏了 secret 列：{rendered}",
        );
        assert!(
            rendered.contains(MARKER),
            "{table} 的 Debug 连非 secret 列都没输出，上一条断言无意义：{rendered}",
        );
        assert!(
            rendered.contains("<redacted>"),
            "{table} 的 Debug 里没有 <redacted> 占位：{rendered}",
        );
        assert!(
            rendered.contains(table),
            "{table} 的 Debug 没写表名：{rendered}"
        );
    }

    #[test]
    fn accounts_debug_redacts_every_registered_secret_column() {
        let row = accounts::Row {
            id: MARKER.to_string(),
            account_id: "acc".to_string(),
            provider_id: "google".to_string(),
            user_id: "u1".to_string(),
            access_token: Some(SENTINEL.to_string()),
            refresh_token: Some(SENTINEL.to_string()),
            id_token: Some(SENTINEL.to_string()),
            access_token_expires_at: Some(epoch()),
            refresh_token_expires_at: Some(epoch()),
            scope: Some("openid".to_string()),
            password: Some(SENTINEL.to_string()),
            created_at: epoch(),
            updated_at: epoch(),
            issuer: Some("https://accounts.google.com".to_string()),
        };
        assert_redacted("accounts", &format!("{row:?}"));
    }

    #[test]
    fn sessions_debug_redacts_the_token() {
        let row = sessions::Row {
            id: MARKER.to_string(),
            user_id: "u1".to_string(),
            token: SENTINEL.to_string(),
            expires_at: epoch(),
            ip_address: None,
            user_agent: None,
            created_at: epoch(),
            updated_at: epoch(),
        };
        assert_redacted("sessions", &format!("{row:?}"));
    }

    #[test]
    fn verifications_debug_redacts_the_value() {
        let row = verifications::Row {
            id: MARKER.to_string(),
            identifier: "a@example.invalid".to_string(),
            value: SENTINEL.to_string(),
            expires_at: epoch(),
            created_at: epoch(),
            updated_at: epoch(),
        };
        assert_redacted("verifications", &format!("{row:?}"));
    }

    #[test]
    fn credentials_debug_redacts_the_ciphertext_but_keeps_the_key_id() {
        let row = credentials::Row {
            id: uuid::Uuid::nil(),
            kind: crate::db::types::CredentialKind::Model,
            provider: MARKER.to_string(),
            encrypted_value: SENTINEL.to_string(),
            key_id: "kms-key-2026-08".to_string(),
            metadata: serde_json::json!({}),
            revoked_at: None,
            created_at: epoch(),
            updated_at: epoch(),
        };
        let rendered = format!("{row:?}");
        assert_redacted("credentials", &rendered);
        // 具名豁免必须真的生效：key_id 是密钥标识符不是密钥，遮掉它会让轮换排障无从下手。
        assert!(
            rendered.contains("kms-key-2026-08"),
            "key_id 被误脱敏了：{rendered}",
        );
    }

    #[test]
    fn sso_providers_debug_redacts_both_config_columns() {
        let row = sso_providers::Row {
            id: MARKER.to_string(),
            issuer: "https://idp.example.invalid".to_string(),
            oidc_config: Some(SENTINEL.to_string()),
            saml_config: Some(SENTINEL.to_string()),
            user_id: None,
            provider_id: "idp".to_string(),
            organization_id: None,
            domain: "example.invalid".to_string(),
        };
        assert_redacted("sso_providers", &format!("{row:?}"));
    }

    #[test]
    fn agent_profiles_debug_redacts_the_callback_token_hash() {
        let row = agent_profiles::Row {
            agent_id: MARKER.to_string(),
            owner_user_id: None,
            title: "t".to_string(),
            role_description: "r".to_string(),
            avatar_seed: "s".to_string(),
            visibility: crate::db::types::AgentVisibility::Private,
            deleted_at: None,
            created_at: epoch(),
            updated_at: epoch(),
            callback_token_hash: Some(SENTINEL.to_string()),
            callback_token_issued_at: Some(epoch()),
        };
        assert_redacted("agent_profiles", &format!("{row:?}"));
    }

    /// 负向对照：脱敏不是全局把所有值都遮掉 —— 没登记 secret 列的表照常打印。
    ///
    /// 没有这一条，上面六条在"`Debug` 恒输出 `<redacted>`"的实现下同样通过。
    #[test]
    fn a_table_without_secret_columns_prints_its_values() {
        let row = users::Row {
            id: MARKER.to_string(),
            email: "a@example.invalid".to_string(),
            name: None,
            image: None,
            email_verified: true,
            groups: vec![Some("g1".to_string())],
            created_at: epoch(),
            updated_at: epoch(),
        };
        let rendered = format!("{row:?}");
        assert!(rendered.contains(MARKER));
        assert!(rendered.contains("a@example.invalid"));
        assert!(
            !rendered.contains("<redacted>"),
            "users 没有 secret 列，不该出现占位：{rendered}",
        );
    }

    /// 防漏登记：凡列名命中 secret 词根，就必须要么登记为 secret、要么带书面理由豁免。
    ///
    /// 这条是 `SECRET_COLUMNS` 的**保鲜**机制。没有它，脱敏只能保护今天想到的那几列 ——
    /// 将来有人加一列 `refresh_token` 而忘了登记，六条脱敏测试一条都不会红。
    #[test]
    fn every_column_matching_a_secret_word_root_is_classified() {
        let mut unclassified: Vec<String> = Vec::new();
        let mut hits = 0usize;
        for table in current_table_specs() {
            for column in table.columns {
                if !SECRET_COLUMN_NAME_ROOTS
                    .iter()
                    .any(|root| column.contains(root))
                {
                    continue;
                }
                hits += 1;
                let registered = SECRET_COLUMNS
                    .iter()
                    .any(|(t, c)| *t == table.name && c == column);
                let exempted = SECRET_SCAN_EXEMPTIONS
                    .iter()
                    .any(|(t, c, _)| *t == table.name && c == column);
                if !registered && !exempted {
                    unclassified.push(format!("{}.{}", table.name, column));
                }
            }
        }
        assert!(
            unclassified.is_empty(),
            "这些列命中 secret 词根却既没登记也没豁免，请补进 SECRET_COLUMNS 或 \
             SECRET_SCAN_EXEMPTIONS（豁免必须带书面理由）：{unclassified:?}",
        );
        // signature/capability_id、component arguments/answer 与 remote descriptor 不含词根但仍是主动登记项，
        // 所以只比较会命中词根的子集。
        let registered_root_hits = SECRET_COLUMNS
            .iter()
            .filter(|(_, column)| {
                SECRET_COLUMN_NAME_ROOTS
                    .iter()
                    .any(|root| column.contains(root))
            })
            .count();
        let exemption_root_hits = SECRET_SCAN_EXEMPTIONS
            .iter()
            .filter(|(_, column, _)| {
                SECRET_COLUMN_NAME_ROOTS
                    .iter()
                    .any(|root| column.contains(root))
            })
            .count();
        assert_eq!(hits, registered_root_hits + exemption_root_hits);
        assert_eq!(SECRET_COLUMNS.len(), 35);
        assert_eq!(SECRET_SCAN_EXEMPTIONS.len(), 22);
    }

    /// 两张名单都必须指向真实存在的 `(表, 列)`，且互不重叠。
    ///
    /// 一个拼错的列名会让 `is_secret_column` 静默返回 false —— 脱敏看起来配了，实际没生效。
    #[test]
    fn secret_registry_entries_all_name_real_columns() {
        let exists = |table: &str, column: &str| {
            current_table_specs()
                .find(|t| t.name == table)
                .is_some_and(|t| t.columns.contains(&column))
        };
        for (table, column) in SECRET_COLUMNS {
            assert!(
                exists(table, column),
                "SECRET_COLUMNS 里的 {table}.{column} 不存在"
            );
            assert!(
                is_secret_column(table, column),
                "is_secret_column 认不出自己名单里的 {table}.{column}",
            );
        }
        for (table, column, reason) in SECRET_SCAN_EXEMPTIONS {
            assert!(
                exists(table, column),
                "SECRET_SCAN_EXEMPTIONS 里的 {table}.{column} 不存在",
            );
            assert!(!reason.trim().is_empty(), "{table}.{column} 的豁免没写理由",);
            assert!(
                !is_secret_column(table, column),
                "{table}.{column} 同时出现在登记与豁免两张名单里",
            );
        }
        // 正向对照：同一个存在性判据在一个确实不存在的列上必须为假。
        assert!(!exists("users", "no_such_column"));
        assert!(!exists("no_such_table", "id"));
        // 正向对照：is_secret_column 不是恒真。
        assert!(!is_secret_column("users", "email"));
    }

    /// 每一条豁免都必须**真的**命中词根 —— 不命中的豁免是死条目，
    /// 说明词根表变了而豁免没清，下次扫描时它挡不住任何东西。
    #[test]
    fn every_exemption_actually_matches_a_word_root() {
        for (table, column, _) in SECRET_SCAN_EXEMPTIONS {
            assert!(
                SECRET_COLUMN_NAME_ROOTS
                    .iter()
                    .any(|root| column.contains(root)),
                "{table}.{column} 的豁免是死条目：它压根不命中任何 secret 词根",
            );
        }
    }
}
