use super::*;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Same PostgreSQL wire boundary as plugin_user_credential/commit_proxy.rs: suppress exactly one
// backend COMMIT CommandComplete only after PostgreSQL has actually committed the transaction.
struct CommitAckProxy {
    port: u16,
    arm: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for CommitAckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl CommitAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let proxy_port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let arm = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (next, count) = (arm.clone(), dropped.clone());
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let (next, count) = (next.clone(), count.clone());
                children.spawn(async move {
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = sr.read_u8().await?;
                            let len = sr.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&len) {
                                return Err(std::io::Error::other("invalid owned proxy frame"));
                            }
                            let mut payload = vec![0; (len - 4) as usize];
                            sr.read_exact(&mut payload).await?;
                            if kind == b'C'
                                && payload == b"COMMIT\0"
                                && next.swap(false, Ordering::SeqCst)
                            {
                                count.fetch_add(1, Ordering::SeqCst);
                                return Ok::<(), std::io::Error>(());
                            }
                            cw.write_u8(kind).await?;
                            cw.write_u32(len).await?;
                            cw.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {_ = tokio::io::copy(&mut cr,&mut sw)=>{},_ = backend=>{}}
                });
            }
        });
        Ok(Self {
            port: proxy_port,
            arm,
            dropped,
            task,
        })
    }
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_commit_ack_loss_retains_positive_receipt_and_never_becomes_not_committed() {
    fixture("rememberackloss", |f| async move {
        let request = f.capture(0).await?;
        let proxy = CommitAckProxy::start(f.config.host.clone(), f.config.port).await?;
        let mut config = f.config.clone().with_max_pool_size(1);
        config.host = "127.0.0.1".into();
        config.port = proxy.port;
        let proxied = pool::connect(&config).await.map_err(|e| e.to_string())?;
        proxy.arm.store(true, Ordering::SeqCst);
        assert_eq!(
            store(&proxied).remember_from_tool(request.clone()).await,
            Err(MemoryError::CommitUnknown)
        );
        assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
        proxied.close();
        let snapshot = effects(&f.pool).await?;
        for field in ["memories", "events", "receipts"] {
            assert_eq!(snapshot[field].as_array().unwrap().len(), 1);
        }
        let historical = store(&f.pool)
            .remember_from_tool(request)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(effects(&f.pool).await?, snapshot);
        f.terminal().await?;
        let read = f.read().await?;
        assert_eq!(read.receipts[0].receipt_id, historical.receipt_id);
        assert!(read.foreground_blocked);
        let row = f
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one("SELECT status,commit_state FROM public.tool_attempts", &[])
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(row.get::<_, String>(0), "executing");
        assert_eq!(row.get::<_, Option<String>>(1), None);
        Ok(())
    })
    .await;
}

async fn dataset(pool: &Pool) -> Result<BTreeMap<String, Value>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    for row in c.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname IN ('public','openbot_internal','drizzle') ORDER BY schemaname,tablename",&[]).await.map_err(|e|e.to_string())? {
        let schema:String=row.get(0);let table:String=row.get(1);
        let sql=format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM \"{}\".\"{}\" t",schema.replace('"',"\"\""),table.replace('"',"\"\""));
        let value=c.query_one(&sql,&[]).await.map_err(|e|e.to_string())?.get(0);
        result.insert(format!("{schema}.{table}"),value);
    }
    Ok(result)
}

struct OwnedArchive(PathBuf);
impl Drop for OwnedArchive {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pg_utility(
    bin: &Path,
    kind: &str,
    config: &DatabaseConfig,
    archive: &Path,
) -> Result<(), String> {
    let mut command = std::process::Command::new(bin.join(kind));
    command.args([
        "--host",
        &config.host,
        "--port",
        &config.port.to_string(),
        "--username",
        &config.user,
        "--dbname",
        &config.dbname,
        "--no-password",
    ]);
    command.env_remove("PGPASSWORD");
    if let Some(password) = &config.password {
        command.env("PGPASSWORD", password);
    }
    if kind == "pg_dump" {
        command.args(["--format=custom", "--file"]).arg(archive);
    } else {
        command
            .args(["--no-owner", "--no-privileges", "--exit-on-error"])
            .arg(archive);
    }
    let result = command
        .output()
        .map_err(|_| format!("owned {kind} failed to start"))?;
    if !result.status.success() {
        return Err(format!(
            "owned {kind} failed: exit {:?}",
            result.status.code()
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL and OPENBOT_TEST_PG_BIN containing pg_dump/pg_restore"]
async fn whole_database_consistent_restore_retains_receipt_original_unknown_and_foreground_block() {
    let bin = PathBuf::from(
        std::env::var_os("OPENBOT_TEST_PG_BIN")
            .expect("explicit owned PG binary directory required"),
    );
    assert!(bin.is_absolute());
    assert!(bin.join("pg_dump").is_file());
    assert!(bin.join("pg_restore").is_file());
    fixture("rememberbackup",|f|async move {
        // Execute the real producer and fail the real ordinary audit transaction afterwards.
        f.sql("CREATE FUNCTION public.owned_reject_late_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='memory.remember_succeeded' THEN RAISE EXCEPTION 'owned late audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_reject_late_audit BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_reject_late_audit();").await?;
        let (result,request,_) = support::pipeline(&f.pool,&f.auth(),f.invocation(0,"thread"),Some(store(&f.pool)),false).await?;
        assert!(matches!(result,Err(AppError::ReconciliationRequired {..})));
        f.sql("DROP TRIGGER owned_reject_late_audit ON public.audit_events; DROP FUNCTION public.owned_reject_late_audit();").await?;
        f.terminal().await?;let expected=f.read().await?;let original=dataset(&f.pool).await?;
        let archive=OwnedArchive(std::env::temp_dir().join(format!("openbot-owned-075-{}.dump",uuid::Uuid::now_v7())));
        pg_utility(&bin,"pg_dump",&f.config,&archive.0)?;
        // A newly created, unrelated disposable database receives the complete consistent archive.
        // No runtime relay, dispatcher, replay or retry process is started after restore.
        let query=f.query();let mut competing=f.begin.clone();competing.command.run_id=RunId::new("restore-must-stay-blocked");
        harness::with_temp_database(&harness::admin_config("remember restore"),"rememberrestored",|config|async move {
            pg_utility(&bin,"pg_restore",&config,&archive.0)?;
            let restored=pool::connect(&config).await.map_err(|e|e.to_string())?;
            let outcome=async {
                assert_eq!(dataset(&restored).await?,original);
                let directory=PostgresThreadDirectory::with_runtime(restored.clone(),config,"restored-query-only".into(),time::Duration::minutes(10)).map_err(|e|e.to_string())?;
                let actual=directory.run_effect_receipts(query).await.map_err(|e|e.to_string())?;
                assert_eq!(actual.receipts,expected.receipts);assert_eq!(actual.terminal_event_sequence,expected.terminal_event_sequence);assert!(actual.foreground_blocked);assert!(actual.available_actions.is_empty());
                assert!(matches!(directory.begin_thread_run(competing).await,Err(ThreadDirectoryError::LeaseConflict)));
                let historical=store(&restored).remember_from_tool(request).await.map_err(|e|e.to_string())?;
                assert_eq!(historical.receipt_id,expected.receipts[0].receipt_id);
                assert_eq!(dataset(&restored).await?,original);Ok(())
            }.await;
            restored.close();outcome
        }).await;
        Ok(())
    }).await;
}
