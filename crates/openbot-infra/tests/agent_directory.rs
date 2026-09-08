//! Agent roster/detail access, hidden state and secret-free projection PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{AgentDirectory, AgentReadScope};
use openbot_contracts::ids::{ActorId, BotId};
use openbot_infra::db::{baseline, pool};
use openbot_infra::repo::PostgresAgentDirectory;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn roster_and_detail_apply_access_hidden_delete_and_server_decided_flags() {
    let admin =
        admin_config("roster_and_detail_apply_access_hidden_delete_and_server_decided_flags");
    with_temp_database(&admin, "agentdirectory", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email) VALUES
                       ('actor-a','a@example.test'),('actor-b','b@example.test'),
                       ('actor-admin','admin@example.test');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES
                       ('tenant-package','/fixture','checksum'),
                       ('tenant-other','/other','other-checksum');
                     INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
                       ('agent-public','Public','remote_ag_ui',
                        '{\"endpoint\":\"https://agent.example.test/ag-ui\",\"auth\":{\"header\":\"Authorization\",\"credentialId\":\"018f47d2-2c00-7000-8000-000000000001\"}}',NULL),
                       ('agent-private-a','Private A','built_in','{}',NULL),
                       ('agent-private-b','Private B','built_in','{}',NULL),
                       ('agent-private-admin','Private Admin','built_in','{}',NULL),
                       ('agent-system','System','built_in','{}',
                        (SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-package')),
                       ('agent-other-tenant','Other Tenant','built_in','{}',
                        (SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-other')),
                       ('agent-hidden','Hidden','built_in','{}',NULL),
                       ('agent-deleted','Deleted','built_in','{}',NULL);
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,
                       deleted_at,callback_token_hash
                     ) VALUES
                       ('agent-public','actor-a','Public title','Public role','public-seed','public',NULL,'hash-only'),
                       ('agent-private-a','actor-a','Private A title','Private A role','a-seed','private',NULL,NULL),
                       ('agent-private-b','actor-b','Private B title','Private B role','b-seed','private',NULL,NULL),
                       ('agent-private-admin','actor-admin','Private Admin title','Private Admin role','admin-seed','private',NULL,NULL),
                       ('agent-system',NULL,'System title','System role','system-seed','public',NULL,NULL),
                       ('agent-other-tenant',NULL,'Other title','Other role','other-seed','public',NULL,NULL),
                       ('agent-hidden','actor-b','Hidden title','Hidden role','hidden-seed','public',NULL,NULL),
                       ('agent-deleted','actor-a','Deleted title','Deleted role','deleted-seed','public',now(),NULL);
                     INSERT INTO public.agent_preferences(user_id,agent_id,hidden_at)
                       VALUES('actor-a','agent-hidden',now());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let directory = PostgresAgentDirectory::new(pool.clone());
            let actor_a = AgentReadScope {
                tenant: openbot_contracts::ids::TenantId::new("tenant-package"),
                actor: ActorId::new("actor-a"),
                admin: false,
            };
            let visible = directory
                .list_visible_agents(&actor_a, false)
                .await
                .map_err(|error| error.to_string())?;
            let ids: Vec<&str> = visible.iter().map(|agent| agent.id.as_str()).collect();
            if ids != ["agent-private-a", "agent-public", "agent-system"] {
                return Err(format!("actor-a visible roster drifted: {ids:?}"));
            }
            let public = visible
                .iter()
                .find(|agent| agent.id.as_str() == "agent-public")
                .ok_or_else(|| "public profile missing".to_owned())?;
            if public.endpoint.as_deref() != Some("https://agent.example.test/ag-ui")
                || !public.has_auth
                || !public.has_callback_token
                || !public.mine
                || !public.can_manage
                || public.system_owned
                || public.hidden
            {
                return Err(format!("public projection/flags drifted: {public:?}"));
            }
            let system = visible
                .iter()
                .find(|agent| agent.id.as_str() == "agent-system")
                .ok_or_else(|| "system profile missing".to_owned())?;
            if !system.system_owned || system.can_manage || system.mine {
                return Err(format!("system ownership flags drifted: {system:?}"));
            }
            let own_private = directory
                .get_visible_agent(&actor_a, &BotId::new("agent-private-a"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "owner private detail missing".to_owned())?;
            if !own_private.mine || !own_private.can_manage {
                return Err(format!("owner private flags drifted: {own_private:?}"));
            }
            let hidden = directory
                .list_visible_agents(&actor_a, true)
                .await
                .map_err(|error| error.to_string())?;
            if hidden.len() != 1 || hidden[0].id.as_str() != "agent-hidden" || !hidden[0].hidden {
                return Err(format!("per-user hidden roster drifted: {hidden:?}"));
            }
            if directory
                .get_visible_agent(&actor_a, &BotId::new("agent-private-b"))
                .await
                .map_err(|error| error.to_string())?
                .is_some()
                || directory
                    .get_visible_agent(&actor_a, &BotId::new("agent-deleted"))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some()
                || directory
                    .get_visible_agent(&actor_a, &BotId::new("agent-other-tenant"))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("private-other/deleted/cross-tenant detail was exposed".to_owned());
            }
            let hidden_detail = directory
                .get_visible_agent(&actor_a, &BotId::new("agent-hidden"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "hidden direct detail should remain accessible".to_owned())?;
            if !hidden_detail.hidden {
                return Err("hidden direct detail lost current-user state".to_owned());
            }

            let admin_scope = AgentReadScope {
                tenant: openbot_contracts::ids::TenantId::new("tenant-package"),
                actor: ActorId::new("actor-admin"),
                admin: true,
            };
            let admin_roster = directory
                .list_visible_agents(&admin_scope, false)
                .await
                .map_err(|error| error.to_string())?;
            let admin_theirs = admin_roster
                .iter()
                .find(|agent| agent.id.as_str() == "agent-private-b")
                .ok_or_else(|| "admin list omitted another user's private profile".to_owned())?;
            let admin_own = admin_roster
                .iter()
                .find(|agent| agent.id.as_str() == "agent-private-admin")
                .ok_or_else(|| "admin list omitted its own private profile".to_owned())?;
            if !admin_theirs.can_manage
                || admin_theirs.mine
                || !admin_own.can_manage
                || !admin_own.mine
            {
                return Err(format!(
                    "admin list permission/ownership split drifted: theirs={admin_theirs:?} own={admin_own:?}"
                ));
            }
            let admin = directory
                .get_visible_agent(&admin_scope, &BotId::new("agent-private-b"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "admin should see private profile".to_owned())?;
            if !admin.can_manage || admin.mine || admin.system_owned {
                return Err(format!("admin permission/ownership split drifted: {admin:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
