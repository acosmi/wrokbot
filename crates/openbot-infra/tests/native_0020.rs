//! Native 0020 durable tool-approval PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::{baseline, pool, schema_facts};

const POST_0019: &str = include_str!("../../../fixtures/db/schema-0019.json");
const POST_0020: &str = include_str!("../../../fixtures/db/schema-0020.json");

fn facts(raw: &str) -> SchemaFacts {
    serde_json::from_str(raw).expect("schema fixture must be valid")
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn post_0020_is_exact_expand_only_tool_approval_schema() {
    let admin = admin_config("post_0020_is_exact_expand_only_tool_approval_schema");
    with_temp_database(&admin, "native0020facts", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0019_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if before != facts(POST_0019) {
                return Err("0020 prerequisite fixture drift".to_owned());
            }
            if native::apply_through(&mut client, native::NATIVE_0020_VERSION)
                .await
                .map_err(|error| error.to_string())?
                != ApplyOutcome::Applied
            {
                return Err("0020 should apply exactly once".to_owned());
            }
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|error| error.to_string())?;
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0020").is_some() {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/db/schema-0020.json");
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|error| error.to_string())?;
                encoded.push('\n');
                std::fs::write(path, encoded).map_err(|error| error.to_string())?;
                return Ok(());
            }
            if after != facts(POST_0020) {
                return Err("0020 live schema differs from fixture".to_owned());
            }
            for old in &before.tables {
                let current = after
                    .table(&old.name)
                    .ok_or_else(|| format!("0020 dropped table {}", old.name))?;
                for column in &old.columns {
                    if current.column(&column.name) != Some(column) {
                        return Err(format!(
                            "0020 rewrote old column {}.{}",
                            old.name, column.name
                        ));
                    }
                }
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
            if ledger != 8 {
                return Err(format!("native ledger expected 8, got {ledger}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn pending_and_resolved_shapes_are_closed_and_actor_owned() {
    let admin = admin_config("pending_and_resolved_shapes_are_closed_and_actor_owned");
    with_temp_database(&admin, "native0020constraints", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0020_VERSION)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('approval-owner','approval-owner@example.test',1);
                     INSERT INTO public.user_roles(user_id,role) VALUES('approval-owner','user');
                     INSERT INTO public.agents(id,name,type,configuration)
                       VALUES('approval-bot','Approval Bot','built_in','{}');
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES('approval-bot',NULL,'Approval Bot','role','seed','public');
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status
                     ) VALUES('approval-thread','tenant','deployment','approval-owner',
                              'direct_bot','approval-bot','active');
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('approval-thread','approval-owner');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at
                     ) VALUES('approval-run','approval-thread','approval-bot','approval-owner',
                              true,'running',1,clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.tool_approvals(
                       approval_id,tool_call_id,deployment_id,tenant_id,thread_id,run_id,actor_id,
                       bot_id,auth_generation,tool_name,args_hash,target_kind,target_id,effect,
                       approval_class,computer_generation,catalog_generation,policy_version,
                       arguments_summary,requested_at,expires_at
                     ) VALUES('approval-1','call-1','deployment','tenant','approval-thread',
                              'approval-run','approval-owner','approval-bot',1,'mcp__x__write',
                              repeat('a',64),'mcp_tool','x/write','write','every_call',0,1,
                              repeat('b',64),'{\"value\":\"shown\"}',clock_timestamp(),
                              clock_timestamp()+interval '5 minutes')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.tool_approvals SET state='granted',
                       decided_at=clock_timestamp(),decided_by=actor_id,
                       arguments_summary=NULL,change_summary=NULL,updated_at=clock_timestamp()
                      WHERE approval_id='approval-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            for invalid in [
                "UPDATE public.tool_approvals SET effect='read' WHERE approval_id='approval-1'",
                "UPDATE public.tool_approvals SET auth_generation=-1 WHERE approval_id='approval-1'",
                "UPDATE public.tool_approvals SET arguments_summary='{}' WHERE approval_id='approval-1'",
                "UPDATE public.tool_approvals SET decided_by='somebody-else' WHERE approval_id='approval-1'",
            ] {
                client
                    .execute(invalid, &[])
                    .await
                    .expect_err("invalid approval shape must be rejected");
            }
            client
                .execute("DELETE FROM public.users WHERE id='approval-owner'", &[])
                .await
                .map_err(|error| error.to_string())?;
            let remaining: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.tool_approvals
                      WHERE approval_id='approval-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if remaining != 0 {
                return Err("actor deletion did not retire approval row".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
