//! Production PostgreSQL memory recall baseline; synthetic data only.
//! Explicitly saved User/Bot facts retain their selected scope when their source becomes hidden.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    CorrectMemoryRequest, MemoryAdministration, MemoryAdministrationError, MutateMemoryRequest,
    RecallMemoriesRequest, RememberMemoryRequest,
};
use openbot_contracts::ids::{ActorId, BotId, TenantId, ThreadId};
use openbot_contracts::memory::{
    CorrectMemory, MemoryKind, MemoryMutation, MemoryRecord, MemoryScope, MemorySensitivity,
    MemorySource, RecallMemories, RememberMemory,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;

const THREAD_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const THREAD_B: &str = "550e8400-e29b-41d4-a716-446655440001";

async fn provision(pool: &deadpool_postgres::Pool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&client).await.map_err(|e| e.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|e| e.to_string())?;
    client.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
          ('actor-a','a@example.test',0),('actor-b','b@example.test',0);
         INSERT INTO public.user_roles(user_id,role) VALUES ('actor-a','user'),('actor-b','user');
         INSERT INTO public.agents(id,name,type,configuration) VALUES
          ('bot-1','Bot 1','built_in','{}'::jsonb),('bot-2','Bot 2','built_in','{}'::jsonb);
         INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
          VALUES ('bot-1',NULL,'Bot 1','test role','one','public'),
                 ('bot-2','actor-b','Bot 2','test role','two','private');
         INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_message_seq)
          VALUES ('550e8400-e29b-41d4-a716-446655440000','tenant-a','dep-a','actor-a','direct_bot','bot-1',1),
                 ('550e8400-e29b-41d4-a716-446655440001','tenant-b','dep-b','actor-b','direct_bot','bot-2',1);
         INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
          ('550e8400-e29b-41d4-a716-446655440000','actor-a'),
          ('550e8400-e29b-41d4-a716-446655440001','actor-b');
         INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,actor_id)
          VALUES ('message-a','550e8400-e29b-41d4-a716-446655440000',0,'user','{\"text\":\"synthetic source\"}'::jsonb,'synthetic source','actor-a'),
                 ('message-b','550e8400-e29b-41d4-a716-446655440001',0,'user','{\"text\":\"synthetic source\"}'::jsonb,'synthetic source','actor-b');"
    ).await.map_err(|e| e.to_string())?;
    Ok(())
}

fn preference(content: &str) -> RememberMemory {
    RememberMemory {
        memory_kind: MemoryKind::Preference,
        scope: MemoryScope::User,
        content: content.to_owned(),
        tags: Vec::new(),
        sensitivity: MemorySensitivity::Normal,
        source: None,
        expires_at: None,
    }
}

async fn save(
    store: &PostgresMemoryAdministration,
    tenant: &str,
    actor: &str,
    input: RememberMemory,
) -> Result<MemoryRecord, String> {
    store
        .remember(RememberMemoryRequest {
            auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
            tenant: TenantId::new(tenant),
            actor: ActorId::new(actor),
            input,
        })
        .await
        .map_err(|e| e.to_string())
}

fn request(query: &str) -> RecallMemoriesRequest {
    RecallMemoriesRequest {
        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
        deployment: openbot_contracts::ids::DeploymentId::new("dep-a"),
        tenant: TenantId::new("tenant-a"),
        actor: ActorId::new("actor-a"),
        input: RecallMemories {
            query: query.to_owned(),
            tags: Vec::new(),
            bot_id: None,
            thread_id: None,
            limit: Some(100),
        },
    }
}

async fn ids(
    store: &PostgresMemoryAdministration,
    request: RecallMemoriesRequest,
) -> Result<Vec<String>, String> {
    let started = std::time::Instant::now();
    let query = request.input.query.clone();
    let result = store.recall(request).await.map_err(|e| e.to_string())?;
    let found: Vec<_> = result.memories.into_iter().map(|m| m.memory_id).collect();
    eprintln!(
        "BASELINE_OBSERVATION {}",
        serde_json::json!({"query":query,"ids":found,"elapsed_us":started.elapsed().as_micros(),"path":"PostgresMemoryAdministration::recall"})
    );
    Ok(found)
}

fn check(case: &str, actual: &[String], expected: &[&str]) -> Result<(), String> {
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(format!("{case}: expected {expected:?}, actual {actual:?}"))
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn english_terms_tags_rank_and_recency_are_deterministic() {
    with_temp_database(&admin_config("english recall baseline"), "recallenglish", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let old = save(&store,"tenant-a","actor-a",preference("Prefer concise answers with oolong tea")).await?;
            let mut tagged = preference("Prefer concise answers with oolong tea");
            tagged.tags = vec!["style".to_owned(),"drink".to_owned()];
            let new = save(&store,"tenant-a","actor-a",tagged).await?;
            let rank = save(&store,"tenant-a","actor-a",preference("concise concise concise answers answers answers")).await?;
            let client = pool.get().await.map_err(|e| e.to_string())?;
            client.execute("UPDATE public.memories SET created_at=now()-interval '2 days' WHERE memory_id=$1", &[&old.memory_id]).await.map_err(|e| e.to_string())?;
            client.execute("UPDATE public.memories SET created_at=now()-interval '3 days' WHERE memory_id=$1", &[&rank.memory_id]).await.map_err(|e| e.to_string())?;
            drop(client);
            for query in ["concise answers", "ANSWERS CONCISE", "concise answers concise"] {
                check(query,&ids(&store,request(query)).await?,&[&rank.memory_id,&new.memory_id,&old.memory_id])?;
            }
            check("all query terms required",&ids(&store,request("concise unavailableword")).await?,&[])?;
            check("simple dictionary does not stem",&ids(&store,request("answer")).await?,&[])?;
            let mut req = request("concise answers");
            req.input.tags = vec!["style".to_owned(),"drink".to_owned()];
            check("tags AND",&ids(&store,req.clone()).await?,&[&new.memory_id])?;
            req.input.tags.push("missing".to_owned());
            check("missing tag",&ids(&store,req).await?,&[])?;
            let mut req = request("concise answers"); req.input.limit = Some(1);
            check("top one",&ids(&store,req).await?,&[&rank.memory_id])?;
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn chinese_words_in_continuous_sentences_should_be_recalled() {
    with_temp_database(&admin_config("Chinese recall baseline"), "recallchinese", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let whole = save(&store,"tenant-a","actor-a",preference("我喜欢乌龙茶并偏好简洁回答")).await?;
            let spaced = save(&store,"tenant-a","actor-a",preference("偏好 简洁 回答 以及 乌龙茶")).await?;
            check("whole Chinese lexeme",&ids(&store,request("我喜欢乌龙茶并偏好简洁回答")).await?,&[&whole.memory_id])?;
            let mut missing = Vec::new();
            for query in ["乌龙茶", "简洁 回答", "回答 简洁"] {
                let found = ids(&store,request(query)).await?;
                if !found.contains(&spaced.memory_id) { return Err(format!("positive spaced Chinese control failed: {query}")); }
                if !found.contains(&whole.memory_id) { missing.push(query); }
            }
            if missing.is_empty() { Ok(()) } else { Err(format!("continuous Chinese expected-keyword misses: {missing:?}; spaced and whole-lexeme controls passed")) }
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn mixed_han_queries_preserve_english_and_reject_symbol_widening() {
    with_temp_database(&admin_config("mixed Han recall"), "recallmixed", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let preferred = save(&store,"tenant-a","actor-a",preference("常喝乌龙茶并偏好简洁回答 Rust tea alpha beta")).await?;
            let decoy = save(&store,"tenant-a","actor-a",preference("常喝乌龙茶并偏好简洁回答 Rust steak alphabet betamax")).await?;
            let traditional = save(&store,"tenant-a","actor-a",preference("常喝烏龍茶 Rust tea")).await?;
            let extension = save(&store,"tenant-a","actor-a",preference("这是𠀀扩展字以及㐀字和﨑字")).await?;
            for query in ["Rust 乌龙茶 tea", "Rust乌龙茶 tea", "tea，乌龙茶；Rust", "乌龙茶 tea tea", "乌龙茶 alpha beta"] {
                check(query,&ids(&store,request(query)).await?,&[&preferred.memory_id])?;
            }
            for query in ["乌龙茶%简洁_回答", "回答，简洁。乌龙茶"] {
                let found = ids(&store,request(query)).await?;
                if found.len()!=2 || !found.contains(&preferred.memory_id) || !found.contains(&decoy.memory_id) { return Err(format!("Han punctuation AND mismatch: {query}")); }
            }
            for query in ["乌龙茶%不存在", "乌龙茶' OR 'x'='x", "乌龙茶 tea unavailableword", "乌龙茶 alpha bet", " %_，。 ", "   "] {
                check(query,&ids(&store,request(query)).await?,&[])?;
            }
            check("no simplified/traditional conversion",&ids(&store,request("烏龍茶")).await?,&[&traditional.memory_id])?;
            for query in ["𠀀", "㐀", "﨑"] { check(query,&ids(&store,request(query)).await?,&[&extension.memory_id])?; }
            // Force the fallback candidate to be newer than an exact FTS match; original rank wins.
            let exact = save(&store,"tenant-a","actor-a",preference("乌龙茶")).await?;
            pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.memories SET created_at=now()-interval '1 day' WHERE memory_id=$1", &[&exact.memory_id]).await.map_err(|e|e.to_string())?;
            let mut limited = request("乌龙茶"); limited.input.limit=Some(1);
            check("original rank before fallback recency",&ids(&store,limited).await?,&[&exact.memory_id])?;
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn han_fallback_keeps_authority_tags_and_lifecycle_filters() {
    with_temp_database(&admin_config("Han fallback authority"), "recallhanauth", |config| async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let outcome=async {
            provision(&pool).await?;
            let store=PostgresMemoryAdministration::new(pool.clone());
            let mut tagged=preference("我喜欢乌龙茶"); tagged.tags=vec!["drink".to_owned()];
            let own=save(&store,"tenant-a","actor-a",tagged).await?;
            let foreign_actor=save(&store,"tenant-a","actor-b",preference("我喜欢乌龙茶")).await?;
            let foreign_tenant=save(&store,"tenant-b","actor-a",preference("我喜欢乌龙茶")).await?;
            let mut scoped=preference("我喜欢乌龙茶"); scoped.scope=MemoryScope::Thread{thread_id:ThreadId::new(THREAD_A)};
            let thread=save(&store,"tenant-a","actor-a",scoped).await?;
            check("fallback owner",&ids(&store,request("乌龙茶")).await?,&[&own.memory_id])?;
            let mut req=request("乌龙茶"); req.actor=ActorId::new("actor-b");
            check("fallback actor positive",&ids(&store,req).await?,&[&foreign_actor.memory_id])?;
            let mut req=request("乌龙茶"); req.tenant=TenantId::new("tenant-b");
            check("fallback tenant positive",&ids(&store,req).await?,&[&foreign_tenant.memory_id])?;
            let mut req=request("乌龙茶"); req.input.thread_id=Some(ThreadId::new(THREAD_A));
            let found=ids(&store,req.clone()).await?;
            if found.len()!=2 || !found.contains(&thread.memory_id) || !found.contains(&own.memory_id) { return Err("fallback thread scope mismatch".to_owned()); }
            req.input.tags=vec!["drink".to_owned()];
            check("fallback tag",&ids(&store,req.clone()).await?,&[&own.memory_id])?;
            req.input.tags.push("missing".to_owned());
            check("fallback tag AND",&ids(&store,req).await?,&[])?;
            for status in ["deleted", "forbidden", "expired", "superseded"] {
                let record=save(&store,"tenant-a","actor-a",preference("我喜欢乌龙茶")).await?;
                match status {
                    "deleted"|"forbidden" => {
                        store.mutate(MutateMemoryRequest{auth_generation:openbot_contracts::auth::AuthGeneration::new(0),tenant:TenantId::new("tenant-a"),actor:ActorId::new("actor-a"),memory_id:record.memory_id,mutation:if status=="deleted"{MemoryMutation::Delete}else{MemoryMutation::Forbid}}).await.map_err(|e|e.to_string())?;
                    }
                    "expired" => {
                        pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.memories SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE memory_id=$1", &[&record.memory_id]).await.map_err(|e|e.to_string())?;
                    }
                    _ => {
                        store.correct(CorrectMemoryRequest{auth_generation:openbot_contracts::auth::AuthGeneration::new(0),tenant:TenantId::new("tenant-a"),actor:ActorId::new("actor-a"),memory_id:record.memory_id,correction:CorrectMemory{content:"改喝白水".to_owned(),tags:Vec::new(),sensitivity:MemorySensitivity::Normal,expires_at:None}}).await.map_err(|e|e.to_string())?;
                    }
                }
                check(status,&ids(&store,request("乌龙茶")).await?,&[&own.memory_id])?;
            }
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn direct_adapter_rejects_malformed_and_excessive_han_queries() {
    with_temp_database(
        &admin_config("Han query bounds"),
        "recallhanbounds",
        |config| async move {
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let outcome = async {
                provision(&pool).await?;
                let store = PostgresMemoryAdministration::new(pool.clone());
                let boundary = format!("{} ", "茶".repeat(1365));
                if boundary.len() != 4096 {
                    return Err("invalid test boundary".to_owned());
                }
                save(&store, "tenant-a", "actor-a", preference(&boundary)).await?;
                if ids(&store, request(&boundary)).await?.len() != 1 {
                    return Err("4 KiB Han query positive control failed".to_owned());
                }
                let terms: Vec<String> = (0..33_u32)
                    .map(|i| char::from_u32(0x4E00 + i).unwrap().to_string())
                    .collect();
                let content = terms.join(" ");
                save(&store, "tenant-a", "actor-a", preference(&content)).await?;
                if ids(&store, request(&terms[..32].join(" "))).await?.len() != 1 {
                    return Err("32 Han terms positive control failed".to_owned());
                }
                for query in [
                    String::new(),
                    "茶\0".to_owned(),
                    format!("{boundary}x"),
                    content,
                ] {
                    if store.recall(request(&query)).await
                        != Err(MemoryAdministrationError::InvalidInput { field: "query" })
                    {
                        return Err("adapter must reject query without truncation".to_owned());
                    }
                }
                // Malformed input is rejected before even trying to acquire a database connection.
                pool.close();
                if store.recall(request("")).await
                    != Err(MemoryAdministrationError::InvalidInput { field: "query" })
                {
                    return Err("adapter validation depends on database availability".to_owned());
                }
                Ok(())
            }
            .await;
            pool.close();
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn expiration_delete_forbid_and_correction_do_not_resurrect() {
    with_temp_database(&admin_config("memory lifecycle recall baseline"), "recalllifecycle", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let store = PostgresMemoryAdministration::new(pool.clone());
            let expired = save(&store,"tenant-a","actor-a",preference("lifecycle expired")).await?;
            let deleted = save(&store,"tenant-a","actor-a",preference("lifecycle deleted")).await?;
            let forbidden = save(&store,"tenant-a","actor-a",preference("lifecycle forbidden")).await?;
            let old = save(&store,"tenant-a","actor-a",preference("lifecycle old")).await?;
            let before = ids(&store,request("lifecycle")).await?;
            if before.len()!=4 { return Err("lifecycle positive control did not return all four".to_owned()); }
            // Fixture clock-state injection only; expiry filtering itself still runs production recall.
            pool.get().await.map_err(|e| e.to_string())?.execute(
                "UPDATE public.memories SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE memory_id=$1", &[&expired.memory_id]
            ).await.map_err(|e| e.to_string())?;
            for (record,mutation) in [(deleted,MemoryMutation::Delete),(forbidden,MemoryMutation::Forbid)] {
                let erased=store.mutate(MutateMemoryRequest { auth_generation: openbot_contracts::auth::AuthGeneration::new(0),tenant:TenantId::new("tenant-a"),actor:ActorId::new("actor-a"),memory_id:record.memory_id,mutation}).await.map_err(|e| e.to_string())?;
                if erased.content.is_some() { return Err("erasure retained content".to_owned()); }
            }
            let new=store.correct(CorrectMemoryRequest { auth_generation: openbot_contracts::auth::AuthGeneration::new(0), tenant:TenantId::new("tenant-a"),actor:ActorId::new("actor-a"),memory_id:old.memory_id.clone(),correction:CorrectMemory {content:"lifecycle corrected".to_owned(),tags:Vec::new(),sensitivity:MemorySensitivity::Normal,expires_at:None} }).await.map_err(|e| e.to_string())?;
            if new.supersedes_id.as_deref()!=Some(old.memory_id.as_str()) { return Err("correction lost lineage".to_owned()); }
            for _ in 0..3 { check("active replacement only",&ids(&store,request("lifecycle")).await?,&[&new.memory_id])?; }
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn owner_tenant_context_and_source_writes_are_isolated() {
    with_temp_database(
        &admin_config("memory isolation baseline"),
        "recallisolation",
        |config| async move {
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let outcome = async {
                provision(&pool).await?;
                let store = PostgresMemoryAdministration::new(pool.clone());
                let own = save(&store, "tenant-a", "actor-a", preference("isolation own")).await?;
                let actor_b = save(
                    &store,
                    "tenant-a",
                    "actor-b",
                    preference("isolation actorb"),
                )
                .await?;
                let tenant_b = save(
                    &store,
                    "tenant-b",
                    "actor-a",
                    preference("isolation tenantb"),
                )
                .await?;
                let mut scoped = preference("isolation bot");
                scoped.scope = MemoryScope::Bot {
                    bot_id: BotId::new("bot-1"),
                };
                let bot = save(&store, "tenant-a", "actor-a", scoped).await?;
                let mut scoped = preference("isolation thread");
                scoped.scope = MemoryScope::Thread {
                    thread_id: ThreadId::new(THREAD_A),
                };
                let thread = save(&store, "tenant-a", "actor-a", scoped).await?;
                check(
                    "owner default",
                    &ids(&store, request("isolation")).await?,
                    &[&own.memory_id],
                )?;
                let mut req = request("isolation");
                req.actor = ActorId::new("actor-b");
                check(
                    "other actor positive control",
                    &ids(&store, req).await?,
                    &[&actor_b.memory_id],
                )?;
                let mut req = request("isolation");
                req.tenant = TenantId::new("tenant-b");
                check(
                    "other tenant positive control",
                    &ids(&store, req).await?,
                    &[&tenant_b.memory_id],
                )?;
                let mut req = request("isolation");
                req.input.bot_id = Some(BotId::new("bot-1"));
                req.input.thread_id = Some(ThreadId::new(THREAD_A));
                let found = ids(&store, req).await?;
                if found.len() != 3
                    || !found.contains(&own.memory_id)
                    || !found.contains(&bot.memory_id)
                    || !found.contains(&thread.memory_id)
                {
                    return Err("explicit contextual scope set wrong".to_owned());
                }
                for (thread_id, bot_id) in [(Some(THREAD_B), None), (None, Some("bot-2"))] {
                    let mut req = request("isolation");
                    req.input.thread_id = thread_id.map(ThreadId::new);
                    req.input.bot_id = bot_id.map(BotId::new);
                    if store.recall(req).await != Err(MemoryAdministrationError::NotVisible) {
                        return Err("invisible context was accepted".to_owned());
                    }
                }
                let mut stolen = preference("isolation stolen");
                stolen.memory_kind = MemoryKind::Fact;
                stolen.source = Some(MemorySource {
                    thread_id: ThreadId::new(THREAD_B),
                    message_id: "message-b".to_owned(),
                });
                if store
                    .remember(RememberMemoryRequest {
                        auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                        tenant: TenantId::new("tenant-a"),
                        actor: ActorId::new("actor-a"),
                        input: stolen,
                    })
                    .await
                    != Err(MemoryAdministrationError::NotVisible)
                {
                    return Err("cross tenant source accepted".to_owned());
                }
                Ok(())
            }
            .await;
            pool.close();
            outcome
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn saved_fact_snapshots_survive_source_revocation_but_remain_erasable() {
    with_temp_database(&admin_config("saved memory source snapshots"), "recallsource", |config| async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let outcome=async {
            provision(&pool).await?;
            let store=PostgresMemoryAdministration::new(pool.clone());
            let mut snapshots=Vec::new();
            for scope in [MemoryScope::User,MemoryScope::Bot{bot_id:BotId::new("bot-1")}] {
                let mut input=preference("sourceboundary confidential"); input.scope=scope; input.memory_kind=MemoryKind::Fact;
                input.source=Some(MemorySource{thread_id:ThreadId::new(THREAD_A),message_id:"message-a".to_owned()});
                snapshots.push(save(&store,"tenant-a","actor-a",input).await?);
            }
            let mut req=request("sourceboundary"); req.input.bot_id=Some(BotId::new("bot-1"));
            if ids(&store,req.clone()).await?.len()!=2 { return Err("source access positive control failed".to_owned()); }
            pool.get().await.map_err(|e|e.to_string())?.execute("DELETE FROM public.thread_memberships WHERE thread_id=$1 AND user_id='actor-a'", &[&THREAD_A]).await.map_err(|e|e.to_string())?;
            let revoked=store.recall(req.clone()).await.map_err(|e|e.to_string())?.memories;
            if revoked.len()!=snapshots.len() || !snapshots.iter().all(|record|revoked.contains(record)) { return Err("source revocation changed explicitly saved snapshots".to_owned()); }
            let mut exact=req.clone(); exact.input.thread_id=Some(ThreadId::new(THREAD_A));
            if store.recall(exact.clone()).await!=Err(MemoryAdministrationError::NotVisible) { return Err("explicit revoked thread control failed".to_owned()); }
            pool.get().await.map_err(|e|e.to_string())?.batch_execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES ('550e8400-e29b-41d4-a716-446655440000','actor-a'); UPDATE public.threads SET status='deleted',deleted_at=now() WHERE thread_id='550e8400-e29b-41d4-a716-446655440000';").await.map_err(|e|e.to_string())?;
            let deleted=store.recall(req.clone()).await.map_err(|e|e.to_string())?.memories;
            if deleted.len()!=snapshots.len() || !snapshots.iter().all(|record|deleted.contains(record)) { return Err("source deletion changed explicitly saved snapshots".to_owned()); }
            if store.recall(exact).await!=Err(MemoryAdministrationError::NotVisible) { return Err("explicit deleted thread control failed".to_owned()); }
            for record in snapshots {
                let erased=store.mutate(MutateMemoryRequest{auth_generation:openbot_contracts::auth::AuthGeneration::new(0),tenant:TenantId::new("tenant-a"),actor:ActorId::new("actor-a"),memory_id:record.memory_id,mutation:MemoryMutation::Delete}).await.map_err(|e|e.to_string())?;
                if erased.content.is_some() { return Err("manual erasure retained saved content".to_owned()); }
            }
            check("manual deletion erases source snapshots",&ids(&store,req).await?,&[])?;
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}
