//! Owned PostgreSQL v2 acceptance. These tests use the real shared assembly's binding,
//! original registry and ThreadDirectory; they do not fabricate a dataset grant.
#![cfg(feature = "server-runtime")]

mod harness;

use async_trait::async_trait;
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{BeginThreadRunV2Request, ThreadDirectory, ThreadDirectoryError};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRunV2, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    model_connections::{
        CreateModelConnection, CustomModelProtocol, DeleteModelConnection, ModelApiKey,
        ModelConnection, UpdateModelConnection,
    },
    versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
};
use openbot_domain::{
    remote_callback::RemoteRunAssertionSigner,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::{
    application_assembly::{
        ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
        assemble_postgres_application,
    },
    artifact_registry::ArtifactDatasetRegistry,
    db::{fresh, pool},
    model_connections::PostgresModelConnections,
    model_dataset::PostgresModelDatasetBinding,
    policy::PolicyStore,
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const DEP: &str = "owned-v2-dataset-deployment";
const TENANT: &str = "owned-v2-dataset-tenant";
struct ClosedProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}
fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}
struct Fixture {
    pool: pool::DatabasePool,
    config: pool::DatabaseConfig,
    assembly: PostgresApplicationAssembly,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    binding: Arc<PostgresModelDatasetBinding>,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
}
impl Fixture {
    async fn new(config: pool::DatabaseConfig, size: usize) -> Self {
        let config = config.with_max_pool_size(size);
        let p = pool::connect(&config).await.unwrap();
        let mut c = p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-v2-alice@example.test',7),('bob','owned-v2-bob@example.test',7);
            INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
            INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
            INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');
            INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
            INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
            INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).unwrap(),
        );
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                p.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .unwrap(),
        );
        let policy_store = PolicyStore::postgres(p.clone(), None);
        policy_store.load().await.unwrap();
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: p.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault.clone(),
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap()),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .unwrap();
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            config.clone(),
            "owned-v2-runtime".into(),
            time::Duration::seconds(30),
        )
        .unwrap()
        .with_model_dataset_binding(binding.clone())
        .unwrap();
        let models = PostgresModelConnections::new(
            p.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .unwrap();
        Self {
            pool: p,
            config,
            assembly,
            registry: Some(registry),
            binding,
            directory,
            models,
        }
    }
    async fn model(&self, protocol: CustomModelProtocol) -> ModelConnection {
        self.models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Owned choice".into(),
                    protocol,
                    endpoint: "https://owned-v2.example.test/v1".into(),
                    model: "owned-selected-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_V2_SYNTHETIC_KEY".into()))
                        .unwrap(),
                },
            )
            .await
            .unwrap()
    }
    fn request(
        &self,
        index: u64,
        channel: bool,
        model: &ModelConnection,
    ) -> BeginThreadRunV2Request {
        let mut entropy = [0u8; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-v2-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "Exact owned words".into(),
                selected_skill_slugs: vec![],
                model_selection: RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    model.id.clone(),
                    model.revision,
                    format!("custom:{}", model.id),
                    1,
                )
                .unwrap(),
            },
        }
    }
    async fn counts(&self) -> Vec<i64> {
        let c = self.pool.get().await.unwrap();
        let mut out = Vec::new();
        for table in [
            "public.threads",
            "public.thread_memberships",
            "public.thread_leases",
            "public.runs",
            "public.messages",
            "public.run_events",
            "public.outbox",
            "public.run_model_selections",
            "openbot_internal.run_model_selection_v2_snapshots",
        ] {
            out.push(
                c.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                    .await
                    .unwrap()
                    .get(0),
            );
        }
        out
    }
    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
        let observations = self.pool.connection_observations();
        self.pool.close();
        let deadline = Instant::now() + Duration::from_secs(10);
        for o in observations {
            assert_eq!(
                o.wait_for_destruction_before(deadline).await.unwrap(),
                pool::ConnectionDestruction::ConnectionDestroyed
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_dataset_accepts_both_anchors_three_protocols_and_exact_replay() {
    let admin = harness::admin_config("v2_dataset_matrix");
    harness::with_temp_database(&admin,"v2datasetmatrix",|config|async move{
        let f=Fixture::new(config,4).await;let mut index=1;
        for channel in [false,true]{for protocol in [CustomModelProtocol::OpenaiChatCompletions,CustomModelProtocol::OpenaiResponses,CustomModelProtocol::AnthropicMessages]{
            let model=f.model(protocol).await;let req=f.request(index,channel,&model);index+=1;
            let receipt=f.directory.begin_thread_run_v2(req.clone()).await.unwrap();assert!(!receipt.replayed);
            let c=f.pool.get().await.unwrap();
            let s=c.query_one("SELECT s.*,r.created_at AS actual_run_time,m.content,e.event_seq,o.outbox_id,
                d.dataset_id AS actual_dataset,d.created_at AS actual_dataset_time,d.initial_origin AS actual_origin
                FROM openbot_internal.run_model_selection_v2_snapshots s JOIN public.runs r ON r.run_id=s.run_id
                JOIN public.messages m ON m.message_id=r.run_id||':input' JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0
                JOIN public.outbox o ON o.outbox_id=r.run_id||':agent_run_dispatch'
                JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=s.deployment_id AND d.tenant_id=s.tenant_id
                WHERE s.run_id=$1",&[&req.command.run_id.as_str()]).await.unwrap();
            let typed=openbot_infra::db::tables::run_model_selection_v2_snapshots::Row::try_from(&s).unwrap();
            assert_eq!(typed.run_id,req.command.run_id.as_str());assert_eq!(typed.deployment_id,DEP);assert_eq!(typed.tenant_id,TENANT);
            assert_eq!(typed.owner_user_id,"alice");assert_eq!(typed.auth_generation,7);assert_eq!(typed.connection_id,Uuid::parse_str(&model.id).unwrap());
            assert_eq!(typed.connection_revision,model.revision);assert_eq!(typed.protocol,protocol.as_str());assert_eq!(typed.endpoint,model.endpoint);
            assert_eq!(typed.model,model.model);assert_eq!(typed.created_at,s.get::<_,time::OffsetDateTime>("actual_run_time"));assert_eq!(typed.snapshot_schema,2);
            assert_eq!(typed.source,"custom");assert_eq!(typed.model_id,format!("custom:{}",model.id));assert_eq!(typed.catalog_revision,1);
            assert_eq!(typed.dataset_id,s.get::<_,String>("actual_dataset"));assert_eq!(typed.dataset_binding_schema,1);
            assert_eq!(typed.dataset_initial_origin,s.get::<_,String>("actual_origin"));assert_eq!(typed.dataset_binding_created_at,s.get::<_,time::OffsetDateTime>("actual_dataset_time"));
            assert_eq!(typed.credential_policy,"custom_fixed_secret_revision_v1");
            assert_eq!(s.get::<_,Value>("content"),json!({"text":req.command.message,"modelSelection":req.command.model_selection,"runAnchor":req.command.anchor}));
            assert!(c.query_opt("SELECT 1 FROM public.run_model_selections WHERE run_id=$1",&[&req.command.run_id.as_str()]).await.unwrap().is_none());drop(c);
            let before=f.counts().await;assert!(f.directory.begin_thread_run_v2(req.clone()).await.unwrap().replayed);assert_eq!(f.counts().await,before);
        }}f.finish().await;Ok(())
    }).await;
}

fn update(model: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: model.revision,
        name: model.name.clone(),
        protocol: model.protocol,
        endpoint: model.endpoint.clone(),
        model: model.model.clone(),
        enabled: model.enabled,
        api_key: None,
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn durable_receipt_keeps_original_definition_and_rejects_complete_intent_drift() {
    let admin = harness::admin_config("v2_dataset_replay");
    harness::with_temp_database(&admin, "v2datasetreplay", |config| async move {
        let f = Fixture::new(config, 4).await;
        let model = f.model(CustomModelProtocol::OpenaiResponses).await;
        let req = f.request(20, false, &model);
        f.directory.begin_thread_run_v2(req.clone()).await.unwrap();
        let mut edit = update(&model);
        edit.model = "changed-owned-model".into();
        edit.enabled = false;
        let changed = f.models.update(&auth(), &model.id, &edit).await.unwrap();
        f.models
            .delete(
                &auth(),
                &changed.id,
                &DeleteModelConnection {
                    expected_revision: changed.revision,
                },
            )
            .await
            .unwrap();
        let before = f.counts().await;
        assert!(
            f.directory
                .begin_thread_run_v2(req.clone())
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(f.counts().await, before);
        let mut altered = req.clone();
        altered.command.message.push('!');
        assert_eq!(
            f.directory.begin_thread_run_v2(altered).await,
            Err(ThreadDirectoryError::RequestConflict)
        );
        let mut altered = req.clone();
        altered.command.model_selection = RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            model.id.to_uppercase(),
            model.revision,
            format!("custom:{}", model.id),
            1,
        )
        .unwrap();
        // Uppercase UUID text is valid but a different original accepted intent.
        if model.id.to_uppercase() != model.id {
            assert_eq!(
                f.directory.begin_thread_run_v2(altered).await,
                Err(ThreadDirectoryError::RequestConflict)
            );
        }
        let mut altered = req.clone();
        altered.command.model_selection = RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            model.id.clone(),
            model.revision,
            format!("custom:{}", model.id),
            2,
        )
        .unwrap();
        assert_eq!(
            f.directory.begin_thread_run_v2(altered).await,
            Err(ThreadDirectoryError::RequestConflict)
        );
        let mut other = f.request(21, false, &model);
        other.command.run_id = req.command.run_id.clone();
        assert_eq!(
            f.directory.begin_thread_run_v2(other).await,
            Err(ThreadDirectoryError::RequestConflict)
        );
        assert_eq!(f.counts().await, before);
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_pool_scope_once_enrollment_and_owner_lifetime_are_closed() {
    let admin = harness::admin_config("v2_dataset_identity");
    harness::with_temp_database(&admin, "v2datasetidentity", |config| async move {
        let f = Fixture::new(config, 4).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let _req = f.request(30, false, &model);
        let before = f.counts().await;
        let other = pool::connect(&f.config).await.unwrap();
        assert!(!f.binding.matches_pool_scope(
            &other,
            &DeploymentId::new(DEP),
            &TenantId::new(TENANT)
        ));
        assert!(
            PostgresThreadDirectory::with_runtime(
                other.clone(),
                f.config.clone(),
                "other".into(),
                time::Duration::seconds(30)
            )
            .unwrap()
            .with_model_dataset_binding(f.binding.clone())
            .is_err()
        );
        other.close();
        assert!(f.binding.matches_pool_scope(
            &f.pool.clone(),
            &DeploymentId::new(DEP),
            &TenantId::new(TENANT)
        ));
        assert!(!f.binding.matches_pool_scope(
            &f.pool,
            &DeploymentId::new("wrong"),
            &TenantId::new(TENANT)
        ));
        assert!(
            f.binding
                .enroll_original_registry(f.registry.as_ref().unwrap())
                .is_err()
        );
        // The actual host propagates a duplicate enrollment failure and stops assembly.
        // This assertion does not pretend that ignoring that error is an authorized host.
        assert_eq!(f.counts().await, before);
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn dataset_and_snapshot_acl_drift_refuse_before_any_business_commit() {
    let admin = harness::admin_config("v2_dataset_drift");
    harness::with_temp_database(&admin,"v2datasetdrift",|config|async move{
        let f=Fixture::new(config,4).await;let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let before=f.counts().await;let c=f.pool.get().await.unwrap();
        c.batch_execute("GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC").await.unwrap();drop(c);
        assert!(f.directory.begin_thread_run_v2(f.request(40,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        let c=f.pool.get().await.unwrap();c.batch_execute("REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM PUBLIC").await.unwrap();drop(c);
        // Explicit owner-only ACL is an allowed physical state, not a repair by production.
        f.directory.begin_thread_run_v2(f.request(41,false,&model)).await.unwrap();
        let before=f.counts().await;let c=f.pool.get().await.unwrap();
        c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id='owned-tampered-dataset' WHERE deployment_id=$1 AND tenant_id=$2",&[&DEP,&TENANT]).await.unwrap();drop(c);
        assert!(f.directory.begin_thread_run_v2(f.request(42,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn original_registry_owner_drop_and_pool_close_refuse_successor_accepts() {
    let admin = harness::admin_config("v2_dataset_owner_end");
    harness::with_temp_database(&admin, "v2datasetownerend", |config| async move {
        let mut f = Fixture::new(config, 4).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let before = f.counts().await;
        drop(f.registry.take());
        assert!(
            f.directory
                .begin_thread_run_v2(f.request(50, false, &model))
                .await
                .is_err()
        );
        assert_eq!(f.counts().await, before);
        f.pool.close();
        assert!(
            f.directory
                .begin_thread_run_v2(f.request(51, false, &model))
                .await
                .is_err()
        );
        f.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn independent_snapshot_acl_policy_accepts_null_and_equivalent_owner_only_and_rejects_complete_drift()
 {
    let admin = harness::admin_config("v2_dataset_acl");
    harness::with_temp_database(&admin,"v2datasetacl",|config|async move{
        let f=Fixture::new(config,4).await;let model=f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        let c=f.pool.get().await.unwrap();
        c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=NULL WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
        let null=openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap();
        c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.model_connections'::regclass)) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
        let explicit=openbot_infra::db::custom_model_v2_schema::capture(&c).await.unwrap();
        assert_eq!(null["schema"],explicit["schema"]);assert_ne!(null["tableAclState"],explicit["tableAclState"]);drop(c);
        let before=f.counts().await;
        let challenges=[
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC",
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO pg_monitor",
            "GRANT SELECT ON openbot_internal.run_model_selection_v2_snapshots TO CURRENT_USER WITH GRANT OPTION",
            "REVOKE SELECT ON openbot_internal.run_model_selection_v2_snapshots FROM CURRENT_USER",
            "UPDATE pg_catalog.pg_class SET relacl=relacl||relacl WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "UPDATE pg_catalog.pg_class SET relacl='{}'::aclitem[] WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",0::oid) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass",
            "GRANT SELECT(model) ON openbot_internal.run_model_selection_v2_snapshots TO PUBLIC",
            "ALTER TABLE openbot_internal.run_model_selection_v2_snapshots OWNER TO pg_monitor",
        ];
        for(index,challenge)in challenges.into_iter().enumerate(){
            let c=f.pool.get().await.unwrap();
            c.batch_execute("UPDATE pg_catalog.pg_class SET relacl=pg_catalog.acldefault('r'::pg_catalog.\"char\",(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.model_connections'::regclass)) WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass;
                UPDATE pg_catalog.pg_attribute SET attacl=NULL WHERE attrelid='openbot_internal.run_model_selection_v2_snapshots'::regclass AND attnum>0").await.unwrap();
            // Each challenged fixture starts from a separately observed positive oracle.
            openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();
            c.batch_execute(challenge).await.unwrap();
            assert!(openbot_infra::db::custom_model_v2_schema::verify(&c).await.is_err(),"ACL challenge {index} must be observed and refused");drop(c);
            assert!(f.directory.begin_thread_run_v2(f.request(60+index as u64,false,&model)).await.is_err());assert_eq!(f.counts().await,before);
        }
        let c=f.pool.get().await.unwrap();
        c.batch_execute("DO $$ DECLARE actual_owner text; BEGIN
            SELECT r.rolname INTO STRICT actual_owner FROM pg_catalog.pg_roles r
              JOIN pg_catalog.pg_class c ON c.relowner=r.oid WHERE c.oid='public.model_connections'::regclass;
            EXECUTE format('ALTER TABLE openbot_internal.run_model_selection_v2_snapshots OWNER TO %I',actual_owner);
            END $$;
            UPDATE pg_catalog.pg_class SET relacl=NULL WHERE oid='openbot_internal.run_model_selection_v2_snapshots'::regclass;
            UPDATE pg_catalog.pg_attribute SET attacl=NULL WHERE attrelid='openbot_internal.run_model_selection_v2_snapshots'::regclass AND attnum>0").await.unwrap();
        openbot_infra::db::custom_model_v2_schema::verify(&c).await.unwrap();drop(c);
        f.finish().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn extra_owner_default_privileges_roll_back_native0047_without_repair_or_partial_ledger() {
    let admin = harness::admin_config("v2_dataset_default_acl");
    harness::with_temp_database(&admin,"v2datasetdefaultacl",|config|async move{
        let p=pool::connect(&config).await.unwrap();let mut c=p.get().await.unwrap();
        openbot_infra::db::baseline::apply(&c).await.unwrap();openbot_infra::db::native::apply_through(&mut c,46).await.unwrap();
        let before:String=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);
        c.batch_execute("ALTER DEFAULT PRIVILEGES IN SCHEMA openbot_internal GRANT SELECT ON TABLES TO PUBLIC").await.unwrap();
        assert!(openbot_infra::db::native::apply(&mut c).await.is_err());
        // This original-connection barrier observes the DB after native's queued rollback;
        // it is not a fabricated per-frame C/Z witness or a claim about driver joins.
        c.simple_query("SELECT 1").await.unwrap();
        let clean:bool=c.query_one("SELECT to_regclass('openbot_internal.run_model_selection_v2_snapshots') IS NULL AND NOT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=47)",&[]).await.unwrap().get(0);assert!(clean);
        let after:String=c.query_one("SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text FROM openbot_internal.schema_migrations m",&[]).await.unwrap().get(0);assert_eq!(before,after);
        let unchanged:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a WHERE d.defaclnamespace='openbot_internal'::regnamespace AND a.grantee=0 AND a.privilege_type='SELECT')",&[]).await.unwrap().get(0);assert!(unchanged);
        drop(c);let observations=p.connection_observations();p.close();let deadline=Instant::now()+Duration::from_secs(10);
        for o in observations{assert_eq!(o.wait_for_destruction_before(deadline).await.unwrap(),pool::ConnectionDestruction::ConnectionDestroyed);}Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL 17; selected include-ignored only"]
async fn v2_accept_rechecks_current_revocation_after_original_connection_lock_wait() {
    let admin = harness::admin_config("v2_accept_current_wait");
    harness::with_temp_database(&admin, "v2acceptcurrentwait", |config| async move {
        let f = Fixture::new(config, 6).await;
        let model = f.model(CustomModelProtocol::OpenaiChatCompletions).await;
        for channel in [false, true] {
            let request = f.request(110 + u64::from(channel), channel, &model);
            let before = f.counts().await;
            let mut blocker = f.pool.get().await.unwrap();
            let blocker_pid: i32 = blocker
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let barrier = blocker.transaction().await.unwrap();
            barrier
                .query_one(
                    "SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE",
                    &[&Uuid::parse_str(&model.id).unwrap()],
                )
                .await
                .unwrap();
            let checker = f.pool.get().await.unwrap();
            let (result, ()) = tokio::join!(f.directory.begin_thread_run_v2(request), async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let waiter = checker
                            .query_opt(
                                "SELECT pid FROM pg_stat_activity
                                WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))
                                  AND query LIKE '%FROM public.model_connections c%' LIMIT 1",
                                &[&blocker_pid],
                            )
                            .await
                            .unwrap();
                        if waiter.is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("actual accept reached its original connection lock");
                // No positive row lock can lock a revoked_access absence. This commits
                // while acceptance is waiting and must be observed by the final conjunction.
                checker
                    .execute(
                        "INSERT INTO public.revoked_access(email,revoked_by)
                        VALUES('owned-v2-alice@example.test','bob')",
                        &[],
                    )
                    .await
                    .unwrap();
                barrier.commit().await.unwrap();
            });
            assert!(matches!(result, Err(ThreadDirectoryError::NotVisible)));
            // A known refusal is not an ACK witness; this separately checks visible business rows.
            assert_eq!(
                f.counts().await,
                before,
                "no new thread/lease/run/input/event/outbox/snapshot survives"
            );
            checker
                .execute(
                    "DELETE FROM public.revoked_access WHERE email='owned-v2-alice@example.test'",
                    &[],
                )
                .await
                .unwrap();
            drop(checker);
            drop(blocker);
        }
        f.finish().await;
        Ok(())
    })
    .await;
}
