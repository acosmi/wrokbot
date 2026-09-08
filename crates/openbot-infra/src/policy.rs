//! `action_policy` 的持久化内存缓存与 PostgreSQL LISTEN/NOTIFY fanout。
//!
//! 行是记录、内存是热路径缓存。写入与空 payload `NOTIFY` 同事务提交；通知只负责唤醒，
//! 每个 replica 都重读完整行。监听首次建立以及断线重连后也先重读，覆盖离线期间漏掉的通知。

use std::future::poll_fn;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use openbot_application::{PolicyAdministration, PolicyAdministrationError};
use openbot_contracts::ids::ActorId;
use openbot_domain::policy::{ActionPolicy, CompiledActionPolicy, PolicyMode};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_postgres::{AsyncMessage, Client, Connection, NoTls, Socket};

use crate::db::InfraError;
use crate::db::pool::DatabaseConfig;

/// 固定上游 policy fanout channel；payload 恒为空，只表示“请重读”。
pub const ACTION_POLICY_TOPIC: &str = "action_policy_changed";
const CURRENT_POLICY_ID: &str = "current";
const RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// 启动加载出的策略来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOrigin {
    /// 来自 `action_policy` 唯一 current 行。
    Database,
    /// 表无行，回到显式配置。
    Configuration,
    /// 表无行且没有配置；按第一真源保持未配置/default-deny。
    Unconfigured,
}

/// 一个 replica 的 action policy 热缓存。
#[derive(Clone)]
pub struct PolicyStore {
    configured: Option<ActionPolicy>,
    current: watch::Sender<PolicyState>,
    database: Option<Pool>,
    operation: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct PolicyState {
    raw: Option<ActionPolicy>,
    compiled: Arc<CompiledActionPolicy>,
}

impl PolicyState {
    fn new(raw: Option<ActionPolicy>) -> Self {
        let compiled = Arc::new(raw.as_ref().map_or_else(
            CompiledActionPolicy::unconfigured,
            CompiledActionPolicy::compile,
        ));
        Self { raw, compiled }
    }
}

impl core::fmt::Debug for PolicyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyStore")
            .field("configured", &self.configured.is_some())
            .field("database", &self.database.is_some())
            .field("current", &self.current.borrow().raw.is_some())
            .finish()
    }
}

impl PolicyStore {
    /// 无数据库模式；用于纯 decision 单测，不创建伪数据库依赖。
    #[must_use]
    pub fn in_memory(configured: Option<ActionPolicy>) -> Self {
        Self::new(None, configured)
    }

    /// PostgreSQL-backed store；调用方必须在使用前 [`Self::load`]。
    #[must_use]
    pub fn postgres(pool: Pool, configured: Option<ActionPolicy>) -> Self {
        Self::new(Some(pool), configured)
    }

    fn new(database: Option<Pool>, configured: Option<ActionPolicy>) -> Self {
        let (current, _) = watch::channel(PolicyState::new(configured.clone()));
        Self {
            configured,
            current,
            database,
            operation: Arc::new(Mutex::new(())),
        }
    }

    /// 同步读取当前原始 policy；acting 热路径不得每次访问 PostgreSQL。
    #[must_use]
    pub fn current(&self) -> Option<ActionPolicy> {
        self.current.borrow().raw.clone()
    }

    /// 同步取得预编译 policy；读取只 clone `Arc`，不在 acting 热路径重新解析 CEL。
    #[must_use]
    pub fn compiled(&self) -> Arc<CompiledActionPolicy> {
        self.current.borrow().compiled.clone()
    }

    /// 启动加载。返回来源，供 boot audit 明确记录实际边界。
    pub async fn load(&self) -> Result<PolicyOrigin, InfraError> {
        let _guard = self.operation.lock().await;
        self.reload_locked().await
    }

    /// 收到 NOTIFY 或监听重连后整行重读。
    pub async fn refresh(&self) -> Result<(), InfraError> {
        if self.database.is_none() {
            return Ok(());
        }
        let _guard = self.operation.lock().await;
        self.reload_locked().await.map(|_| ())
    }

    async fn reload_locked(&self) -> Result<PolicyOrigin, InfraError> {
        let Some(pool) = &self.database else {
            self.current
                .send_replace(PolicyState::new(self.configured.clone()));
            return Ok(if self.configured.is_some() {
                PolicyOrigin::Configuration
            } else {
                PolicyOrigin::Unconfigured
            });
        };
        let client = pool
            .get()
            .await
            .map_err(|source| InfraError::connect("为 action policy load 获取连接", source))?;
        let rows = client
            .query(
                "SELECT id,mode,deny,allow FROM public.action_policy ORDER BY id",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("读取 action policy", source))?;
        match rows.as_slice() {
            [] => {
                self.current
                    .send_replace(PolicyState::new(self.configured.clone()));
                Ok(if self.configured.is_some() {
                    PolicyOrigin::Configuration
                } else {
                    PolicyOrigin::Unconfigured
                })
            }
            [row] => {
                let id: String = row.try_get("id").map_err(|source| {
                    crate::db::RowDecodeError::column("action_policy", "id", source)
                })?;
                if id != CURRENT_POLICY_ID {
                    return Err(InfraError::repository_invariant(
                        "action_policy_non_current_row",
                    ));
                }
                let mode: String = row.try_get("mode").map_err(|source| {
                    crate::db::RowDecodeError::column("action_policy", "mode", source)
                })?;
                let mode = PolicyMode::from_str(&mode)
                    .map_err(|_| InfraError::repository_invariant("action_policy_mode_invalid"))?;
                let deny = string_array(row, "deny")?;
                let allow = string_array(row, "allow")?;
                self.current
                    .send_replace(PolicyState::new(Some(ActionPolicy { mode, deny, allow })));
                Ok(PolicyOrigin::Database)
            }
            _ => Err(InfraError::repository_invariant(
                "action_policy_multiple_rows",
            )),
        }
    }

    /// 原子 upsert current 行并唤醒所有 replica；commit 后才改变本进程缓存。
    pub async fn set(
        &self,
        policy: ActionPolicy,
        updated_by: Option<&str>,
    ) -> Result<(), InfraError> {
        let _guard = self.operation.lock().await;
        if let Some(pool) = &self.database {
            let mut client = pool
                .get()
                .await
                .map_err(|source| InfraError::connect("为 action policy set 获取连接", source))?;
            let transaction = client
                .transaction()
                .await
                .map_err(|source| InfraError::query("开始 action policy set 事务", source))?;
            transaction
                .execute(
                    "INSERT INTO public.action_policy(id,mode,deny,allow,updated_by,updated_at) \
                     VALUES($1,$2,$3,$4,$5,clock_timestamp()) \
                     ON CONFLICT(id) DO UPDATE SET mode=excluded.mode,deny=excluded.deny, \
                       allow=excluded.allow,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                    &[
                        &CURRENT_POLICY_ID,
                        &policy.mode.as_str(),
                        &policy.deny,
                        &policy.allow,
                        &updated_by,
                    ],
                )
                .await
                .map_err(|source| InfraError::query("写 action policy", source))?;
            announce(&transaction).await?;
            transaction
                .commit()
                .await
                .map_err(|source| InfraError::query("提交 action policy set", source))?;
        }
        self.current.send_replace(PolicyState::new(Some(policy)));
        Ok(())
    }

    /// 删除 current 行并回到配置；删除与唤醒同事务。
    pub async fn reset(&self) -> Result<(), InfraError> {
        let _guard = self.operation.lock().await;
        if let Some(pool) = &self.database {
            let mut client = pool
                .get()
                .await
                .map_err(|source| InfraError::connect("为 action policy reset 获取连接", source))?;
            let transaction = client
                .transaction()
                .await
                .map_err(|source| InfraError::query("开始 action policy reset 事务", source))?;
            transaction
                .execute(
                    "DELETE FROM public.action_policy WHERE id=$1",
                    &[&CURRENT_POLICY_ID],
                )
                .await
                .map_err(|source| InfraError::query("删除 action policy", source))?;
            announce(&transaction).await?;
            transaction
                .commit()
                .await
                .map_err(|source| InfraError::query("提交 action policy reset", source))?;
        }
        self.current
            .send_replace(PolicyState::new(self.configured.clone()));
        Ok(())
    }
}

#[async_trait]
impl PolicyAdministration for PolicyStore {
    async fn current_policy(&self) -> Result<Option<ActionPolicy>, PolicyAdministrationError> {
        Ok(self.current())
    }

    async fn set_policy(
        &self,
        updated_by: &ActorId,
        policy: ActionPolicy,
    ) -> Result<(), PolicyAdministrationError> {
        PolicyStore::set(self, policy, Some(updated_by.as_str()))
            .await
            .map_err(policy_port_error)
    }
}

fn policy_port_error(error: InfraError) -> PolicyAdministrationError {
    tracing::error!(error = %error, "policy administration adapter 失败");
    match error {
        InfraError::RowDecode(_) | InfraError::RepositoryInvariant { .. } => {
            PolicyAdministrationError::Corrupt
        }
        InfraError::Connect { .. }
        | InfraError::Query { .. }
        | InfraError::IncompatibleDatabase(_)
        | InfraError::NativeMigration(_) => PolicyAdministrationError::Unavailable,
    }
}

fn string_array(
    row: &tokio_postgres::Row,
    column: &'static str,
) -> Result<Vec<String>, InfraError> {
    let values: Vec<Option<String>> = row
        .try_get(column)
        .map_err(|source| crate::db::RowDecodeError::column("action_policy", column, source))?;
    values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| InfraError::repository_invariant("action_policy_array_contains_null"))
}

async fn announce(transaction: &tokio_postgres::Transaction<'_>) -> Result<(), InfraError> {
    transaction
        .query_one("SELECT pg_notify($1,'')", &[&ACTION_POLICY_TOPIC])
        .await
        .map(|_| ())
        .map_err(|source| InfraError::query("通知 action policy 变化", source))
}

/// 专用 LISTEN 连接的生命周期句柄。
pub struct PolicyListener {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl core::fmt::Debug for PolicyListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyListener").finish_non_exhaustive()
    }
}

impl PolicyListener {
    /// 建立专用连接、LISTEN 并在返回前重读一次，防止启动窗口漏通知。
    pub async fn start(
        config: DatabaseConfig,
        store: Arc<PolicyStore>,
    ) -> Result<Self, InfraError> {
        let (stop, stop_rx) = watch::channel(false);
        let initial = listen_once(&config, store.clone(), stop_rx.clone()).await?;
        let task = tokio::spawn(supervise_listener(config, store, stop_rx, Some(initial)));
        Ok(Self { stop, task })
    }

    /// 停止专用连接并等待 supervisor 退出。
    pub async fn stop(self) {
        self.stop.send_replace(true);
        let _ = self.task.await;
    }
}

type PgConnection = Connection<Socket, tokio_postgres::tls::NoTlsStream>;
type ActiveListener = (Client, JoinHandle<Result<(), tokio_postgres::Error>>);

async fn listen_once(
    config: &DatabaseConfig,
    store: Arc<PolicyStore>,
    stop: watch::Receiver<bool>,
) -> Result<ActiveListener, InfraError> {
    let (client, connection) = config
        .to_pg_config()
        .connect(NoTls)
        .await
        .map_err(|source| InfraError::connect("建立 action policy LISTEN 连接", source))?;
    let driver = tokio::spawn(drive_notifications(connection, store.clone(), stop));
    if let Err(source) = client.batch_execute("LISTEN action_policy_changed").await {
        driver.abort();
        return Err(InfraError::query("订阅 action policy channel", source));
    }
    if let Err(error) = store.refresh().await {
        driver.abort();
        return Err(error);
    }
    Ok((client, driver))
}

async fn drive_notifications(
    mut connection: PgConnection,
    store: Arc<PolicyStore>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), tokio_postgres::Error> {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            message = poll_fn(|cx| connection.poll_message(cx)) => {
                match message {
                    Some(Ok(AsyncMessage::Notification(notification)))
                        if notification.channel() == ACTION_POLICY_TOPIC =>
                    {
                        if let Err(error) = store.refresh().await {
                            tracing::error!(code = "action_policy_refresh_failed", error = %error,
                                "action policy 通知后重读失败；保持上一份边界并等待重连/下次通知");
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn supervise_listener(
    config: DatabaseConfig,
    store: Arc<PolicyStore>,
    mut stop: watch::Receiver<bool>,
    mut active: Option<ActiveListener>,
) {
    loop {
        if *stop.borrow() {
            return;
        }
        if let Some((_client, driver)) = active.take() {
            match driver.await {
                Ok(Ok(())) if *stop.borrow() => return,
                Ok(Ok(())) => tracing::warn!(
                    code = "action_policy_listener_closed",
                    "action policy LISTEN 连接关闭，准备重连"
                ),
                Ok(Err(error)) => {
                    tracing::error!(code = "action_policy_listener_failed", error = %error,
                    "action policy LISTEN 连接失败，准备重连")
                }
                Err(error) => {
                    tracing::error!(code = "action_policy_listener_task_failed", error = %error,
                    "action policy LISTEN task 失败，准备重连")
                }
            }
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
        }
        let listener_stop = stop.clone();
        tokio::select! {
            result = listen_once(&config, store.clone(), listener_stop) => match result {
                Ok(listener) => active = Some(listener),
                Err(error) => {
                    tracing::error!(code = "action_policy_listener_reconnect_failed", error = %error,
                    "action policy LISTEN 重连失败；保持上一份边界并继续重试")
                }
            },
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
        }
    }
}
