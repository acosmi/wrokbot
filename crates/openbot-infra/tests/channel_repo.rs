//! 需要真实 PostgreSQL 的集成测试：`ChannelRepo` 的可见性、定序、分页与 `active`。
//!
//! 这是 G1「首个 vertical slice」读侧的执行面 —— `openbot_application::ChannelReader`
//! 第一次接到真库上。
//!
//! # 怎么跑
//!
//! 默认 `cargo test` 按 `#[ignore]` 跳过并逐条打印理由。要真跑：
//!
//! ```text
//! OPENBOT_TEST_DATABASE_URL="host=127.0.0.1 port=5432 user=postgres password=... dbname=postgres" \
//!   cargo test -p openbot-infra --all-features -- --include-ignored
//! ```
//!
//! # 数据从哪来
//!
//! 每个用例自己插最小行集。**刻意不用** `fixtures/db/seed-0012.sql` —— 那是类型映射的
//! 对抗夹具（每个可空列第 2 行填 NULL），不是业务场景数据；拿它当业务夹具，
//! 断言就会跟着夹具的对抗值走，而不是跟着被测语义走。

mod harness;

use harness::{admin_config, with_temp_database};

use openbot_application::{ChannelCursor, ChannelReader};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::ids::{ActorId, ChannelId};
use openbot_infra::db::{baseline, pool};
use openbot_infra::repo::ChannelRepo;

/// 建库 → 应用 baseline → 灌 `seed` → 把 [`ChannelRepo`] 交给 `body`。
async fn with_repo<F, Fut>(tag: &str, test_name: &str, seed: &'static str, body: F)
where
    F: FnOnce(ChannelRepo) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(test_name);
    with_temp_database(&admin, tag, |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|e| format!("连接临时库失败：{e}"))?;
        let outcome = async {
            {
                let client = pool.get().await.map_err(|e| format!("取连接失败：{e}"))?;
                baseline::apply(&client)
                    .await
                    .map_err(|e| format!("应用 baseline 失败：{e}"))?;
                if !seed.trim().is_empty() {
                    client
                        .batch_execute(seed)
                        .await
                        .map_err(|e| format!("灌入场景数据失败：{e}"))?;
                }
            }
            body(ChannelRepo::new(pool.clone())).await
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

fn ids(page: &[ChannelSummary]) -> Vec<&str> {
    page.iter().map(|c| c.id.as_str()).collect()
}

/// 两个用户各有一个 channel，各自只有自己的 membership。
const TWO_ACTORS: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid'), ('ub', 'b@example.invalid');
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-a', 'A 的频道', '', '2026-08-22T04:00:00Z'),
  ('c-b', 'B 的频道', '', '2026-08-22T05:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES ('c-a', 'ua'), ('c-b', 'ub');";

/// 可见性：A 看得见自己的（正向对照），看不见 B 的（负向）。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn an_actor_sees_only_channels_it_has_a_membership_for() {
    with_repo(
        "chvis",
        "an_actor_sees_only_channels_it_has_a_membership_for",
        TWO_ACTORS,
        |repo| async move {
            let a = repo
                .list_visible_channels(&ActorId::new("ua"), 50, None)
                .await
                .map_err(|e| format!("A 的查询失败：{e}"))?;
            if ids(&a) != ["c-a"] {
                return Err(format!("A 应当只看到 c-a，实际 {:?}", ids(&a)));
            }

            // 负向对照在同一条里：B 的 channel 确实存在且对 B 可见，
            // 所以「A 看不到 c-b」不是在「c-b 压根不存在」的世界里成立的。
            let b = repo
                .list_visible_channels(&ActorId::new("ub"), 50, None)
                .await
                .map_err(|e| format!("B 的查询失败：{e}"))?;
            if ids(&b) != ["c-b"] {
                return Err(format!("B 应当只看到 c-b，实际 {:?}", ids(&b)));
            }

            // 没有任何 membership 的第三方，什么都看不到。
            let nobody = repo
                .list_visible_channels(&ActorId::new("uc"), 50, None)
                .await
                .map_err(|e| format!("陌生人的查询失败：{e}"))?;
            if !nobody.is_empty() {
                return Err(format!(
                    "无 membership 的 actor 不该看到任何东西：{:?}",
                    ids(&nobody)
                ));
            }
            Ok(())
        },
    )
    .await;
}

/// 有 membership、**没有** `intelligence_channel_mappings` 行的 channel 必须可见。
const NO_MAPPING: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-mapped',   '有 mapping',  '', '2026-08-22T04:00:00Z'),
  ('c-unmapped', '没有 mapping', '', '2026-08-22T05:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES ('c-mapped', 'ua'), ('c-unmapped', 'ua');
INSERT INTO public.intelligence_channel_mappings (user_id, channel_id, thread_id)
  VALUES ('ua', 'c-mapped', 't-1');";

/// **本次最重要的一条**：R22 —— 可见性不得 join `intelligence_channel_mappings`。
///
/// 上游 hydration 段 INNER JOIN 了它，于是没有 mapping 行的 channel（例如刚 provision、
/// 还没人打开过的包 channel）对所有人不可达。这里显式构造"有 membership、无 mapping"
/// 的场景并断言它出现在结果里；同一份数据里另有一个**有** mapping 的 channel 作对照，
/// 证明这条断言不是在"mapping 表压根没数据"的世界里成立的。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_channel_without_an_intelligence_mapping_is_still_visible() {
    with_repo(
        "chr22",
        "a_channel_without_an_intelligence_mapping_is_still_visible",
        NO_MAPPING,
        |repo| async move {
            let page = repo
                .list_visible_channels(&ActorId::new("ua"), 50, None)
                .await
                .map_err(|e| format!("查询失败：{e}"))?;
            // 定序：c-unmapped 的 created_at 更晚，排在前面。
            if ids(&page) != ["c-unmapped", "c-mapped"] {
                return Err(format!(
                    "无 mapping 的 channel 必须可见，且两者都在：实际 {:?}",
                    ids(&page),
                ));
            }
            // 前提自检：mapping 表里确实**只有**一行，即两个 channel 的 mapping 状态不同。
            // 否则「无 mapping 也可见」可能只是因为两个 channel 恰好都有 mapping。
            let mapped = page
                .iter()
                .find(|c| c.id.as_str() == "c-mapped")
                .ok_or_else(|| "c-mapped 应当在结果里".to_string())?;
            // thread_id 恒 None：G1 没有 native threads 表，mapping 表只读且不进判据。
            if mapped.thread_id.is_some() {
                return Err(format!(
                    "thread_id 在 G1 必须恒为 None：{:?}",
                    mapped.thread_id
                ));
            }
            Ok(())
        },
    )
    .await;
}

/// `last_message_at` 有 NULL 有非 NULL，`created_at` 各不相同。
///
/// 期望序（`coalesce(last_message_at, created_at) DESC, id DESC`）：
/// c-late(06:00) > c-null-new(05:00) > c-early(03:00) > c-null-old(02:00)
const ORDERING: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.channels (id, name, description, created_at, last_message_at) VALUES
  ('c-late',     '有消息且最新', '', '2026-08-22T01:00:00Z', '2026-08-22T06:00:00Z'),
  ('c-null-new', '无消息但新建', '', '2026-08-22T05:00:00Z', NULL),
  ('c-early',    '有消息但较早', '', '2026-08-22T00:30:00Z', '2026-08-22T03:00:00Z'),
  ('c-null-old', '无消息且很旧', '', '2026-08-22T02:00:00Z', NULL);
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES
  ('c-late', 'ua'), ('c-null-new', 'ua'), ('c-early', 'ua'), ('c-null-old', 'ua');";

/// 定序按 `coalesce(last_message_at, created_at) DESC, id DESC`。
///
/// 造混合数据的意义：只用非 NULL 的 `last_message_at` 排序，与用 `coalesce` 排序，
/// 在那种数据上结果相同 —— 那样的测试证明不了 `coalesce` 真的生效。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rows_are_ordered_by_coalesced_recency_then_id_descending() {
    with_repo(
        "chord",
        "rows_are_ordered_by_coalesced_recency_then_id_descending",
        ORDERING,
        |repo| async move {
            let page = repo
                .list_visible_channels(&ActorId::new("ua"), 50, None)
                .await
                .map_err(|e| format!("查询失败：{e}"))?;
            let expected = ["c-late", "c-null-new", "c-early", "c-null-old"];
            if ids(&page) != expected {
                return Err(format!(
                    "定序不对：期望 {expected:?}，实际 {:?}",
                    ids(&page)
                ));
            }
            // 无消息的行，其 last_message_at 必须原样是 NULL —— coalesce 只用于排序，
            // 不得把 created_at 写回这个字段。
            let null_new = &page[1];
            if null_new.last_message_at.is_some() {
                return Err(format!(
                    "c-null-new 的 last_message_at 应当仍是 None：{:?}",
                    null_new.last_message_at,
                ));
            }
            Ok(())
        },
    )
    .await;
}

/// 同一时间戳的两个 channel，用来验 `id DESC` 这一半定序键。
const TIE: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-1', '一', '', '2026-08-22T04:00:00Z'),
  ('c-2', '二', '', '2026-08-22T04:00:00Z'),
  ('c-3', '三', '', '2026-08-22T04:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES ('c-1', 'ua'), ('c-2', 'ua'), ('c-3', 'ua');";

/// 翻完全部页：并集 == 全集，且无重复。
///
/// 时间戳全相同，所以这条同时把 `id DESC` 这一半定序键与游标的二元组判据一起钉住 ——
/// 只按时间戳做 keyset 的实现会在这里漏行或死循环。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn paging_through_every_page_yields_each_channel_exactly_once() {
    with_repo(
        "chpage",
        "paging_through_every_page_yields_each_channel_exactly_once",
        TIE,
        |repo| async move {
            let actor = ActorId::new("ua");
            let mut seen: Vec<String> = Vec::new();
            let mut cursor: Option<ChannelCursor> = None;

            for _ in 0..10 {
                let page = repo
                    .list_visible_channels(&actor, 1, cursor.clone())
                    .await
                    .map_err(|e| format!("查询失败：{e}"))?;
                let Some(last) = page.last() else { break };
                for channel in &page {
                    seen.push(channel.id.as_str().to_owned());
                }
                cursor = Some(ChannelCursor {
                    recency: last.last_message_at.unwrap_or(last.created_at),
                    id: ChannelId::new(last.id.as_str()),
                });
            }

            if seen != ["c-3", "c-2", "c-1"] {
                return Err(format!("翻页结果不对（应当逆序且不重不漏）：{seen:?}"));
            }
            let mut deduped = seen.clone();
            deduped.sort();
            deduped.dedup();
            if deduped.len() != seen.len() {
                return Err(format!("翻页出现重复：{seen:?}"));
            }
            Ok(())
        },
    )
    .await;
}

/// 一个挂了 3 个 agent 的 channel，另加一个只挂 1 个的，用来验"限的是 channel 不是行"。
const THREE_AGENTS: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.agents (id, name, type, configuration) VALUES
  ('ag-1', '一', 'built_in', '{}'::jsonb),
  ('ag-2', '二', 'built_in', '{}'::jsonb),
  ('ag-3', '三', 'built_in', '{}'::jsonb),
  ('ag-9', '九', 'built_in', '{}'::jsonb);
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-fat',  '挂三个',  '', '2026-08-22T05:00:00Z'),
  ('c-thin', '挂一个',  '', '2026-08-22T04:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES ('c-fat', 'ua'), ('c-thin', 'ua');
INSERT INTO public.channel_agents (channel_id, agent_id) VALUES
  ('c-fat', 'ag-3'), ('c-fat', 'ag-1'), ('c-fat', 'ag-2'),
  ('c-thin', 'ag-9');";

/// `limit=1` 时，挂了 3 个 agent 的 channel 整个返回，不被劈成两页。
///
/// 上游注释点名过这个失效模式："a limit on rows would cut a channel in half: its second Bot
/// would arrive on the next page as a separate entry with the same id"。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_channel_with_three_agents_is_never_split_across_pages() {
    with_repo(
        "chfat",
        "a_channel_with_three_agents_is_never_split_across_pages",
        THREE_AGENTS,
        |repo| async move {
            let page = repo
                .list_visible_channels(&ActorId::new("ua"), 1, None)
                .await
                .map_err(|e| format!("查询失败：{e}"))?;
            if page.len() != 1 {
                return Err(format!(
                    "limit=1 应当恰好返回 1 个 channel，实际 {}",
                    page.len()
                ));
            }
            let fat = &page[0];
            if fat.id.as_str() != "c-fat" {
                return Err(format!("第一页应当是 c-fat，实际 {}", fat.id.as_str()));
            }
            // 三个 agent 全在，且按 agent_id 升序（上游 asc(channelAgents.agentId)）。
            let agents: Vec<&str> = fat.agent_ids.iter().map(|a| a.as_str()).collect();
            if agents != ["ag-1", "ag-2", "ag-3"] {
                return Err(format!("agent 被劈开或顺序不对：{agents:?}"));
            }
            // 正向对照：第二页是另一个 channel，而不是 c-fat 的剩余 agent。
            let next = repo
                .list_visible_channels(
                    &ActorId::new("ua"),
                    1,
                    Some(ChannelCursor {
                        recency: fat.last_message_at.unwrap_or(fat.created_at),
                        id: ChannelId::new(fat.id.as_str()),
                    }),
                )
                .await
                .map_err(|e| format!("第二页查询失败：{e}"))?;
            if ids(&next) != ["c-thin"] {
                return Err(format!("第二页应当是 c-thin，实际 {:?}", ids(&next)));
            }
            Ok(())
        },
    )
    .await;
}

/// 两个 channel：一个的某个 agent_profile 被软删，另一个全都活着。
const ACTIVE: &str = "\
INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.agents (id, name, type, configuration) VALUES
  ('ag-live', '活的', 'built_in', '{}'::jsonb),
  ('ag-dead', '删的', 'built_in', '{}'::jsonb);
INSERT INTO public.agent_profiles (agent_id, title, role_description, avatar_seed, visibility, deleted_at) VALUES
  ('ag-live', '活', 'r', 's', 'public', NULL),
  ('ag-dead', '删', 'r', 's', 'public', '2026-08-22T03:00:00Z');
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-alive', '全活', '', '2026-08-22T05:00:00Z'),
  ('c-dead',  '有删', '', '2026-08-22T04:00:00Z'),
  ('c-bare',  '没挂', '', '2026-08-22T03:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES
  ('c-alive', 'ua'), ('c-dead', 'ua'), ('c-bare', 'ua');
INSERT INTO public.channel_agents (channel_id, agent_id) VALUES
  ('c-alive', 'ag-live'),
  ('c-dead',  'ag-live'),
  ('c-dead',  'ag-dead');";

/// `active` = 该 channel 全部 `agent_profiles.deleted_at IS NULL`。
///
/// 三个场景一次覆盖：全活 ⇒ true（正向对照）、有一个被软删 ⇒ false（负向）、
/// 一个 agent 都没挂 ⇒ true（上游 `[].every(...) === true`，也是最容易被
/// `bool_and` 的 NULL 语义写错的一档）。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn active_is_false_only_when_some_agent_profile_is_soft_deleted() {
    with_repo(
        "chact",
        "active_is_false_only_when_some_agent_profile_is_soft_deleted",
        ACTIVE,
        |repo| async move {
            let page = repo
                .list_visible_channels(&ActorId::new("ua"), 50, None)
                .await
                .map_err(|e| format!("查询失败：{e}"))?;
            let by = |id: &str| {
                page.iter()
                    .find(|c| c.id.as_str() == id)
                    .ok_or_else(|| format!("结果里没有 {id}：{:?}", ids(&page)))
            };

            if !by("c-alive")?.active {
                return Err("全部 profile 都活着，active 应当是 true".to_string());
            }
            if by("c-dead")?.active {
                return Err("有 profile 被软删，active 应当是 false".to_string());
            }
            let bare = by("c-bare")?;
            if !bare.active {
                return Err("没挂任何 agent 的 channel，active 应当是 true".to_string());
            }
            if !bare.agent_ids.is_empty() {
                return Err(format!("c-bare 不该有 agent：{:?}", bare.agent_ids));
            }
            Ok(())
        },
    )
    .await;
}

/// `channel_agents` 里有、`agent_profiles` 里没有的 agent（"孤儿 agent"）。
///
/// `c-orphan` 的**全部** agent 都缺 profile —— 上游那条 INNER JOIN 会让整个 channel 从
/// 结果里消失；`c-mixed` 一半缺一半有，INNER JOIN 会把缺的那个从 agent_ids 里静默删掉。
/// 两种失效模式一次覆盖。
const ORPHAN_AGENT: &str = "INSERT INTO public.users (id, email) VALUES ('ua', 'a@example.invalid');
INSERT INTO public.agents (id, name, type, configuration) VALUES
  ('ag-orphan',  '没有档案', 'built_in', '{}'::jsonb),
  ('ag-profiled', '有档案',  'built_in', '{}'::jsonb);
INSERT INTO public.agent_profiles (agent_id, title, role_description, avatar_seed, visibility)
  VALUES ('ag-profiled', '有档案', 'r', 's', 'public');
INSERT INTO public.channels (id, name, description, created_at) VALUES
  ('c-orphan', '全是孤儿', '', '2026-08-22T05:00:00Z'),
  ('c-mixed',  '一半孤儿', '', '2026-08-22T04:00:00Z');
INSERT INTO public.channel_memberships (channel_id, user_id) VALUES ('c-orphan', 'ua'), ('c-mixed', 'ua');
INSERT INTO public.channel_agents (channel_id, agent_id) VALUES
  ('c-orphan', 'ag-orphan'),
  ('c-mixed',  'ag-orphan'),
  ('c-mixed',  'ag-profiled');";

/// 缺 `agent_profiles` 行的 agent 仍然出现在 `agent_ids` 里，且不会带走整个 channel。
///
/// 这条钉的是 `LEFT JOIN agent_profiles` 这个刻意偏离（上游是 INNER）。在由上游代码产生的库上
/// 两者等价（`agent_profiles` 只软删、且与 `agents` 同事务创建，实证见 SQL 常量的注释），
/// 所以这不是 parity 风险；选 LEFT 是为了让"不变量被破坏"这件事失败得看得见。
/// 不钉住的话，下一个人把它改回 INNER 不会有任何东西变红。
#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn an_agent_without_a_profile_row_still_appears_and_keeps_its_channel() {
    with_repo(
        "chorph",
        "an_agent_without_a_profile_row_still_appears_and_keeps_its_channel",
        ORPHAN_AGENT,
        |repo| async move {
            let page = repo
                .list_visible_channels(&ActorId::new("ua"), 50, None)
                .await
                .map_err(|e| format!("查询失败：{e}"))?;

            // INNER JOIN 会让 c-orphan 整个消失（它的 agent 全都没有 profile）。
            if ids(&page) != ["c-orphan", "c-mixed"] {
                return Err(format!(
                    "全部 agent 都缺 profile 的 channel 必须仍然可见：实际 {:?}",
                    ids(&page),
                ));
            }

            let by = |id: &str| {
                page.iter()
                    .find(|c| c.id.as_str() == id)
                    .ok_or_else(|| format!("结果里没有 {id}"))
            };

            let orphan = by("c-orphan")?;
            let orphan_agents: Vec<&str> = orphan.agent_ids.iter().map(|a| a.as_str()).collect();
            if orphan_agents != ["ag-orphan"] {
                return Err(format!("孤儿 agent 被丢掉了：{orphan_agents:?}"));
            }
            // profile 缺失 ⇒ `deleted_at IS NULL` 为真 ⇒ active，与上游 rows.every() 在零行上
            // 取真一致。
            if !orphan.active {
                return Err("缺 profile 不该让 channel 变成 inactive".to_string());
            }

            // INNER JOIN 会把 ag-orphan 从这里静默删掉，只剩 ag-profiled。
            let mixed = by("c-mixed")?;
            let mixed_agents: Vec<&str> = mixed.agent_ids.iter().map(|a| a.as_str()).collect();
            if mixed_agents != ["ag-orphan", "ag-profiled"] {
                return Err(format!(
                    "混合 channel 的 agent 不全或顺序不对：{mixed_agents:?}"
                ));
            }
            if !mixed.active {
                return Err("c-mixed 的 profile 都没软删，active 应当是 true".to_string());
            }
            Ok(())
        },
    )
    .await;
}
