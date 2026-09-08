//! PostgreSQL evidence that fresh component grants become provider tool definitions.

mod harness;

use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AgentContextSource, ComponentAdministration, ProviderBillingFamily, ProviderRateCard,
    ProviderRateCardInput, ProviderRoute, RunCostCap, RunExecutionLease,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::components::{
    SHOW_NOTICE_COMPONENT_NAME, SHOW_QUOTE_COMPONENT_NAME, compiled_component_manifest,
    compiled_component_parameter_schema,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::thread::FencingToken;
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::provider::context::PostgresAgentContextSource;
use time::macros::datetime;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn fresh_component_grants_are_exact_provider_definitions_and_revocation_is_immediate() {
    let admin = admin_config(
        "fresh_component_grants_are_exact_provider_definitions_and_revocation_is_immediate",
    );
    with_temp_database(&admin, "componentcontext", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('actor-a','actor-a@example.test',0);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('actor-a','user'),('actor-a','admin');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('tenant-a','/fixture',repeat('a',64));
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'bot-1','Bot 1','built_in',
                              '{\"systemPrompt\":\"Test role.\",\"providerSource\":\"package\"}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant-a';
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES('bot-1',NULL,'Bot 1','role','seed','public',NULL);
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES('thread-1','tenant-a','deployment-a','actor-a','direct_bot','bot-1',
                              'active',1,0,clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-1','actor-a');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at,budget_cost_currency,
                       budget_max_cost_micro_units
                     ) VALUES('run-1','thread-1','bot-1','actor-a',true,'running',1,0,
                              clock_timestamp(),clock_timestamp(),'USD',250000);
                     INSERT INTO public.messages(
                       message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                     ) VALUES('message-1','thread-1',0,'user','{\"text\":\"Show it.\"}',
                              'Show it.','run-1','actor-a',clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User, Role::Admin])
            .build();
            let components = Arc::new(
                PostgresComponentAdministration::new(pool.clone(), vec![0x45; 32])
                    .map_err(|error| error.to_string())?,
            );
            components
                .sync_catalogue(&auth, &compiled_component_manifest())
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "UPDATE public.components SET published=false WHERE name='showNotice';
                     INSERT INTO public.component_exclusions(component_name,agent_id,withheld_by)
                       VALUES('showQuote','bot-1','actor-a');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let package_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: "package-model".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 1,
                max_output_micro_units_per_million_tokens: 2,
                source_url: "https://prices.example.test/package".to_owned(),
                source_sha256: "a".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            let managed_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::Anthropic,
                model: "managed-model".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 3,
                max_output_micro_units_per_million_tokens: 4,
                source_url: "https://prices.example.test/managed".to_owned(),
                source_sha256: "b".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                Some(256),
            )
            .map_err(|error| error.to_string())?
            .with_rate_cards(Some(package_rate.clone()), Some(managed_rate.clone()))
            .with_components(components);
            let lease = RunExecutionLease::new(
                RunId::new("run-1"),
                ThreadId::new("thread-1"),
                BotId::new("bot-1"),
                ActorId::new("actor-a"),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let first = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if first.rate_card.as_ref() != Some(&package_rate) {
                return Err("package provider did not receive its exact rate snapshot".to_owned());
            }
            if first.cost_cap
                != Some(
                    RunCostCap::new("USD".to_owned(), 250_000)
                        .map_err(|error| error.to_string())?,
                )
            {
                return Err("context did not load the frozen run cost cap".to_owned());
            }
            let expected = compiled_component_manifest()
                .into_iter()
                .filter(|entry| {
                    !matches!(
                        entry.name.as_str(),
                        SHOW_NOTICE_COMPONENT_NAME | SHOW_QUOTE_COMPONENT_NAME
                    )
                })
                .collect::<Vec<_>>();
            if first.tools.len() != expected.len() {
                return Err(format!("provider component count drifted: {:?}", first.tools));
            }
            for (tool, expected) in first.tools.iter().zip(&expected) {
                if tool.name != expected.name
                    || tool.description != expected.description
                    || tool.input_schema
                        != compiled_component_parameter_schema(&tool.name)
                            .ok_or_else(|| "provider schema missing".to_owned())?
                {
                    return Err(format!("provider component definition drifted: {tool:?}"));
                }
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.component_exclusions(component_name,agent_id,withheld_by)
                     VALUES('showBarChart','bot-1','actor-a')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let second = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if second.tools.len() + 1 != first.tools.len()
                || second.tools.iter().any(|tool| tool.name == "showBarChart")
            {
                return Err(format!("component revocation was not fresh: {:?}", second.tools));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.agents SET configuration= \
                       '{\"systemPrompt\":\"Test role.\",\"providerSource\":\"managed\"}' \
                     WHERE id='bot-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let managed = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if managed.route != ProviderRoute::Managed
                || managed.rate_card.as_ref() != Some(&managed_rate)
            {
                return Err("managed provider did not receive its exact rate snapshot".to_owned());
            }
            let future_rate = ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::Anthropic,
                model: "managed-model".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 3,
                max_output_micro_units_per_million_tokens: 4,
                source_url: "https://prices.example.test/future".to_owned(),
                source_sha256: "c".repeat(64),
                observed_at: datetime!(9999-01-01 0:00 UTC),
            })
            .map_err(|error| error.to_string())?;
            let future_context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                Some(256),
            )
            .map_err(|error| error.to_string())?
            .with_rate_cards(None, Some(future_rate));
            if future_context.load(&lease).await
                != Err(openbot_application::AgentContextError::Corrupt {
                    field: "provider_rate_observed_at",
                })
            {
                return Err("future rate snapshot must fail before provider start".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
