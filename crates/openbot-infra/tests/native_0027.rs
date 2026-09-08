//! Native 0027 terminal reasoning retention PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};
use serde_json::{Value, json};

const POST_0026: &str = include_str!("../../../fixtures/db/schema-0026.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

fn post_0027_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0027.json")
}

async fn seed_reasoning_retention_rows(client: &tokio_postgres::Client) -> Result<(), String> {
    client
        .batch_execute(
            "INSERT INTO public.threads(
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_event_seq
             ) VALUES
               ('thread-completed','tenant-a','dep-a','actor-a','direct_bot','bot-a',4),
               ('thread-failed','tenant-a','dep-a','actor-a','direct_bot','bot-a',4),
               ('thread-cancelled','tenant-a','dep-a','actor-a','direct_bot','bot-a',4),
               ('thread-reconciliation','tenant-a','dep-a','actor-a','direct_bot','bot-a',4),
               ('thread-running','tenant-a','dep-a','actor-a','direct_bot','bot-a',3);

             INSERT INTO public.runs(
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,
               terminal_event_seq,error_code,started_at,finished_at
             ) VALUES
               ('run-completed','thread-completed','bot-a','actor-a',false,'completed',1,4,3,NULL,now(),now()),
               ('run-failed','thread-failed','bot-a','actor-a',false,'failed',1,4,3,'provider_generation_failed',now(),now()),
               ('run-cancelled','thread-cancelled','bot-a','actor-a',false,'cancelled',1,4,3,NULL,now(),now()),
               ('run-reconciliation','thread-reconciliation','bot-a','actor-a',false,'reconciliation_required',1,4,3,'runtime_lease_expired',now(),now()),
               ('run-running','thread-running','bot-a','actor-a',false,'running',1,3,NULL,NULL,now(),NULL);

             INSERT INTO public.run_events(
               run_id,seq,thread_id,event_seq,event_type,payload,terminal
             ) VALUES
               ('run-completed',0,'thread-completed',0,'started','{}',false),
               ('run-completed',1,'thread-completed',1,'semantic_chunk','{\"channel\":\"reasoning\",\"delta\":\"REASONING_COMPLETED_CANARY\",\"untrusted\":\"remove-me\"}',false),
               ('run-completed',2,'thread-completed',2,'semantic_chunk','{\"channel\":\"text\",\"delta\":\"keep-completed\"}',false),
               ('run-completed',3,'thread-completed',3,'completed','{}',true),
               ('run-failed',0,'thread-failed',0,'started','{}',false),
               ('run-failed',1,'thread-failed',1,'semantic_chunk','{\"channel\":\"reasoning\",\"delta\":\"REASONING_FAILED_CANARY\"}',false),
               ('run-failed',2,'thread-failed',2,'semantic_chunk','{\"channel\":\"text\",\"delta\":\"keep-failed\"}',false),
               ('run-failed',3,'thread-failed',3,'failed','{}',true),
               ('run-cancelled',0,'thread-cancelled',0,'started','{}',false),
               ('run-cancelled',1,'thread-cancelled',1,'semantic_chunk','{\"channel\":\"reasoning\",\"delta\":\"REASONING_CANCELLED_CANARY\"}',false),
               ('run-cancelled',2,'thread-cancelled',2,'semantic_chunk','{\"channel\":\"text\",\"delta\":\"keep-cancelled\"}',false),
               ('run-cancelled',3,'thread-cancelled',3,'cancelled','{}',true),
               ('run-reconciliation',0,'thread-reconciliation',0,'started','{}',false),
               ('run-reconciliation',1,'thread-reconciliation',1,'semantic_chunk','{\"channel\":\"reasoning\",\"delta\":\"REASONING_RECONCILIATION_CANARY\"}',false),
               ('run-reconciliation',2,'thread-reconciliation',2,'semantic_chunk','{\"channel\":\"text\",\"delta\":\"keep-reconciliation\"}',false),
               ('run-reconciliation',3,'thread-reconciliation',3,'reconciliation_required','{}',true),
               ('run-running',0,'thread-running',0,'started','{}',false),
               ('run-running',1,'thread-running',1,'semantic_chunk','{\"channel\":\"reasoning\",\"delta\":\"REASONING_ACTIVE_CANARY\",\"untrusted\":\"keep-until-terminal\"}',false),
               ('run-running',2,'thread-running',2,'semantic_chunk','{\"channel\":\"text\",\"delta\":\"keep-running\"}',false);",
        )
        .await
        .map_err(|error| error.to_string())
}

async fn event_identity(client: &tokio_postgres::Client) -> Result<Value, String> {
    client
        .query_one(
            "SELECT jsonb_agg(jsonb_build_array(
               run_id,seq,thread_id,event_seq,event_type,terminal,created_at
             ) ORDER BY run_id,seq) FROM public.run_events",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0027_keeps_schema_exact_and_redacts_only_terminal_reasoning() {
    let admin = admin_config("post_0027_keeps_schema_exact_and_redacts_only_terminal_reasoning");
    with_temp_database(&admin, "native0027", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0026_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before_schema = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before_schema != facts(POST_0026) {
                return Err("0027 prerequisite fixture drift".to_owned());
            }
            seed_reasoning_retention_rows(&client).await?;
            let before_identity = event_identity(&client).await?;

            if native::apply_through(&mut client, native::NATIVE_0027_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0027 should apply exactly once".to_owned());
            }

            let after_schema = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if after_schema != before_schema {
                return Err("0027 data retention migration changed schema facts".to_owned());
            }
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0027").is_some() {
                let mut encoded =
                    serde_json::to_string_pretty(&after_schema).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(post_0027_path(), encoded).map_err(|error| error.to_string())?;
            } else {
                let expected = std::fs::read_to_string(post_0027_path())
                    .map_err(|error| format!("schema-0027 fixture missing: {error}"))?;
                if after_schema != facts(&expected) {
                    return Err("0027 live schema differs from fixture".to_owned());
                }
            }

            if event_identity(&client).await? != before_identity {
                return Err("0027 changed run-event identity, sequence, terminal, or time facts".to_owned());
            }
            let marker = json!({"channel":"reasoning","delta":"","retained":false});
            let terminal_markers: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events AS event \
                     JOIN public.runs AS run ON run.run_id=event.run_id \
                     WHERE run.status IN ('completed','failed','cancelled','reconciliation_required') \
                       AND event.event_type='semantic_chunk' \
                       AND event.payload=$1",
                    &[&marker],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if terminal_markers != 4 {
                return Err(format!("expected four terminal reasoning markers, got {terminal_markers}"));
            }
            let leaked: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM public.run_events AS event \
                     JOIN public.runs AS run ON run.run_id=event.run_id \
                     WHERE run.status IN ('completed','failed','cancelled','reconciliation_required') \
                       AND event.payload::text LIKE '%REASONING_%_CANARY%')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if leaked {
                return Err("historical terminal reasoning canary survived 0027".to_owned());
            }
            let active: Value = client
                .query_one(
                    "SELECT payload FROM public.run_events WHERE run_id='run-running' AND seq=1",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if active
                != json!({
                    "channel":"reasoning",
                    "delta":"REASONING_ACTIVE_CANARY",
                    "untrusted":"keep-until-terminal"
                })
            {
                return Err(format!("0027 redacted active-run reasoning: {active}"));
            }
            let text_rows: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events \
                     WHERE event_type='semantic_chunk' AND payload->>'channel'='text' \
                       AND payload->>'delta' LIKE 'keep-%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if text_rows != 5 {
                return Err(format!("0027 changed visible text chunks: {text_rows}"));
            }
            let ledger: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if ledger != 15 {
                return Err(format!("native ledger expected 15, got {ledger}"));
            }
            if native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::AlreadyApplied
            {
                return Err("0027 ledger replay must be exact".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
