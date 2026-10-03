//! New journal-only test support: owned wire frames and one-statement RC durable facts.
use super::{BOUND, TABLES, require};
use openbot_infra::db::pool::DatabaseConfig;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use tokio_postgres::{Client, IsolationLevel, NoTls};

pub(super) struct Observer {
    client: tokio::sync::Mutex<Option<Client>>,
    connection: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    pub(super) pid: i32,
}

impl Observer {
    pub(super) async fn new(config: &DatabaseConfig) -> Result<Arc<Self>, String> {
        let (client, connection) = config
            .to_pg_config()
            .connect(NoTls)
            .await
            .map_err(|e| e.to_string())?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        Ok(Arc::new(Self {
            client: tokio::sync::Mutex::new(Some(client)),
            connection: tokio::sync::Mutex::new(Some(connection)),
            pid,
        }))
    }

    pub(super) async fn snapshot(&self) -> Result<Value, String> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or("owned observer closed")?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .read_only(true)
            .start()
            .await
            .map_err(|e| e.to_string())?;
        let isolation: String = tx
            .query_one("SHOW transaction_isolation", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            isolation == "read committed",
            "observer must explicitly use RC",
        )?;
        let fields = TABLES.into_iter().map(|table| format!("'{table}',coalesce((SELECT jsonb_agg(to_jsonb(t)||jsonb_build_object('_xmin',t.xmin::text,'_ctid',t.ctid::text) ORDER BY to_jsonb(t)::text) FROM public.{table} t),'[]'::jsonb)")).collect::<Vec<_>>().join(",");
        let snapshot = tx
            .query_one(&format!("SELECT jsonb_build_object({fields})"), &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(snapshot)
    }

    pub(super) async fn close(&self) -> Result<(), String> {
        self.client.lock().await.take();
        if let Some(connection) = self.connection.lock().await.take() {
            tokio::time::timeout(BOUND, connection)
                .await
                .map_err(|_| "observer connection did not stop")?
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct WireEvidence {
    journal_phase: AtomicBool,
    drop_commit: AtomicBool,
    pub(super) suppressed: AtomicUsize,
    opened: AtomicUsize,
    finished: AtomicUsize,
    events: Mutex<Vec<Value>>,
}

impl WireEvidence {
    fn record(&self, event: Value) {
        self.events.lock().expect("owned wire mutex").push(event);
    }
    pub(super) fn events(&self) -> Vec<Value> {
        self.events.lock().expect("owned wire mutex").clone()
    }
    pub(super) fn begin_phase(&self, phase: &str, lose_response: bool) {
        self.record(json!({"phase":phase,"suppress_commit":lose_response}));
        self.drop_commit.store(lose_response, Ordering::SeqCst);
        self.journal_phase.store(true, Ordering::SeqCst);
    }
}

pub(super) struct OwnedFrameProxy {
    pub(super) port: u16,
    pub(super) evidence: Arc<WireEvidence>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Drop for OwnedFrameProxy {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl OwnedFrameProxy {
    pub(super) async fn start(config: &DatabaseConfig) -> Result<Self, String> {
        require(
            config.host == "127.0.0.1" || config.host == "localhost" || config.host == "::1",
            "frame proxy requires the explicitly supplied owned loopback PG",
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let host = config.host.clone();
        let server_port = config.port;
        let evidence = Arc::new(WireEvidence::default());
        let captured = evidence.clone();
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    changed = stopping.changed() => { if changed.is_err() || *stopping.borrow() { break; } }
                    child = children.join_next(), if !children.is_empty() => { let _ = child; }
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { break; };
                        let Ok(server) = tokio::net::TcpStream::connect((host.as_str(),server_port)).await else { break; };
                        let wire = captured.clone();
                        wire.opened.fetch_add(1, Ordering::SeqCst);
                        children.spawn(async move {
                            let (mut cr, mut cw) = client.into_split();
                            let (mut sr, mut sw) = server.into_split();
                            let frontend = async {
                                // NoTls sends one startup packet, then framed client messages.
                                let length = cr.read_u32().await?;
                                let mut startup = frame_payload(length)?;
                                cr.read_exact(&mut startup).await?;
                                sw.write_u32(length).await?;
                                sw.write_all(&startup).await?;
                                loop {
                                    let kind = cr.read_u8().await?;
                                    let length = cr.read_u32().await?;
                                    let mut payload = frame_payload(length)?;
                                    cr.read_exact(&mut payload).await?;
                                    if wire.journal_phase.load(Ordering::SeqCst) && matches!(kind,b'Q'|b'P') {
                                        let sql = if kind == b'P' { payload.splitn(2, |b| *b == 0).nth(1).unwrap_or_default() } else { &payload };
                                        let sql = sql.split(|b| *b == 0).next().unwrap_or_default();
                                        wire.record(json!({"frontend_sql":String::from_utf8_lossy(sql)}));
                                    }
                                    sw.write_u8(kind).await?;
                                    sw.write_u32(length).await?;
                                    sw.write_all(&payload).await?;
                                    if kind == b'X' {
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                            };
                            let backend = async {
                                loop {
                                    let kind = sr.read_u8().await?;
                                    let length = sr.read_u32().await?;
                                    let mut payload = frame_payload(length)?;
                                    sr.read_exact(&mut payload).await?;
                                    if kind == b'K' && payload.len() == 8 {
                                        let pid = i32::from_be_bytes(payload[..4].try_into().expect("four pid bytes"));
                                        wire.record(json!({"backend_pid":pid})); // Never record the cancellation secret.
                                    }
                                    if wire.journal_phase.load(Ordering::SeqCst) && kind == b'E' {
                                        let mut fields = serde_json::Map::new();
                                        let mut remaining = payload.as_slice();
                                        while let Some((&field, rest)) = remaining.split_first() {
                                            if field == 0 { break; }
                                            let Some(end) = rest.iter().position(|b| *b == 0) else { break; };
                                            if matches!(field,b'C'|b'M') { fields.insert((field as char).to_string(), json!(String::from_utf8_lossy(&rest[..end]))); }
                                            remaining = &rest[end+1..];
                                        }
                                        wire.record(json!({"backend_error":fields}));
                                    }
                                    if wire.journal_phase.load(Ordering::SeqCst) && kind == b'C' && payload == b"COMMIT\0" {
                                        let suppressed = wire.drop_commit.swap(false,Ordering::SeqCst);
                                        wire.record(json!({"backend_command":"COMMIT","suppressed":suppressed}));
                                        if suppressed {
                                            wire.suppressed.fetch_add(1, Ordering::SeqCst);
                                            return Ok::<(), std::io::Error>(());
                                        }
                                    }
                                    cw.write_u8(kind).await?;
                                    cw.write_u32(length).await?;
                                    cw.write_all(&payload).await?;
                                }
                            };
                            tokio::select! { _ = frontend => {}, _ = backend => {} }
                            wire.finished.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }
            }
            // Runtime pool has been closed before normal stop. Every connection child must finish;
            // do not leave detached forwarding tasks behind when the listener exits.
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port,
            evidence,
            stop,
            task: Some(task),
        })
    }

    pub(super) async fn close(mut self) -> Result<(), String> {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            tokio::time::timeout(BOUND, task)
                .await
                .map_err(|_| "owned proxy children did not stop")?
                .map_err(|e| e.to_string())?;
        }
        require(
            self.evidence.opened.load(Ordering::SeqCst)
                == self.evidence.finished.load(Ordering::SeqCst),
            "owned proxy forwarding child leaked",
        )
    }
}

fn frame_payload(length: u32) -> Result<Vec<u8>, std::io::Error> {
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(std::io::Error::other("invalid owned PG frame"));
    }
    Ok(vec![0; (length - 4) as usize])
}
