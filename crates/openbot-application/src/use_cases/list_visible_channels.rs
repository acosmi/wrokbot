//! `ListVisibleChannels` 用例（parity：`server/src/routes/channels/routes.ts::list`）。
//!
//! # 三条硬约束
//!
//! 1. **可见性判据只有 materialized membership**，绝不 join `intelligence_channel_mappings`
//!    （§28.1 R22）。判据落在 [`crate::ports::ChannelReader`] 的文档里，本文件负责的是
//!    另一半：**分页与 hydration 共用同一判据**。做法很朴素 —— 这条链路上只有一次端口
//!    调用，返回的行原样成为应答的行，application 侧**不做任何二次过滤**。
//!
//!    上游正是在这里出的事：它的分页段只 join membership、hydration 段额外 join mapping，
//!    两处判据不一致 ⇒ `nextCursor` 可以非空而本页为空。所以这不是「少写一层」的风格
//!    选择，而是被测契约本身：`rows_are_never_post_filtered_after_the_visibility_query`
//!    与 `next_cursor_never_promises_a_page_that_is_empty` 两条测试把它钉住。
//!
//!    **给后人的一句话**：如果你打算在这里加一次"补全/过滤/富化"的查询，先回答一个问题
//!    —— 新查询的可见性判据与第一次那次一致吗？不一致就是在复刻上游那个缺陷。
//!
//! 2. **排序与游标必须与上游一致**：`coalesce(last_message_at, created_at) DESC, id DESC`，
//!    keyset 而非 offset。定义在 [`crate::cursor`]。
//!
//! 3. **游标不透明且解码 fail-closed**：解不开就是 400，绝不回落第一页。理由见
//!    [`crate::cursor`] 的模块文档（这是相对上游的**刻意行为变更**）。

use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{ChannelDetail, ChannelPage, ChannelSummary, MAX_CHANNEL_PAGE};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ChannelId;

use crate::cursor::ChannelCursor;
use crate::ports::{ChannelReadScope, ChannelReader};

/// 未指定 `limit` 时的页大小。
///
/// **parity 值**（不是新增）：出处是上游 `server/src/routes/channels/routes.ts` 的
/// `DEFAULT_CHANNEL_PAGE` 常量。上限 `MAX_CHANNEL_PAGE` 在
/// `openbot_contracts::command`，两者合起来复现上游那一行钳制：
///
/// ```text
/// const limit = Math.min(Math.max(query.limit ?? DEFAULT_CHANNEL_PAGE, 1), MAX_CHANNEL_PAGE);
/// ```
pub const DEFAULT_CHANNEL_PAGE: u32 = 50;

/// 列出当前 actor 可见的 channel。
///
/// # 参数
///
/// - `auth`：权威身份。actor 从这里取，**绝不**从调用方载荷里取 —— 那等于把访问控制的
///   判定权交给调用方（§5.2 逐字禁止 renderer 自报身份）。
/// - `limit` / `cursor`：来自 `AppCommand::ListVisibleChannels`，都是不可信输入。
///
/// # Errors
///
/// - 游标解不开 → `AppError::MalformedPayload { field: "cursor" }`（400），且**不产生任何
///   acting decision**：端口一次都不会被调用（§15.3；由
///   `malformed_cursor_never_reaches_the_port` 钉住）。
/// - 端口失败 → `AppError::DependencyUnavailable`（503），映射见
///   [`crate::ports::PortError::into_app_error`]。
/// - 铸造下一页游标时时间戳无法表示 → 同样 503，理由见
///   [`crate::cursor::CursorEncodeError`]。
///
/// **空结果不是错误**：返回 `Ok` + 空 `channels` + `next_cursor: None`（§15.3 末条，
/// 上游缺陷 #72「空 history 500」的同族）。
pub async fn list_visible_channels<R>(
    reader: &R,
    auth: &AuthContext,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> Result<ChannelPage, AppError>
where
    R: ChannelReader + ?Sized,
{
    // 一、钳制页大小。**先于**一切读操作，因为它决定要读多少行。
    let page_size = clamp_page_size(limit);

    // 二、解析游标。fail-closed，且必须**在调用端口之前** —— §15.3 要求 malformed
    // payload 不产生 acting decision，"先读一把再报错"就已经产生了。
    let cursor = cursor.map(ChannelCursor::decode).transpose()?;

    // 三、唯一一次可见性查询。多要一行用来探测"还有没有下一页"。
    //
    // 这个 `+1` 的技巧来自上游 `channels/routes.ts::list`：它避免了第二次 `count(*)`。
    // 技巧留在 application 侧 —— 端口拿到的 `limit` 就是要读的行数，实现不必知道其中
    // 有一行是探针（`ChannelReader` 的文档里写明了）。
    let probe_size = page_size.saturating_add(1);
    let scope = channel_read_scope(auth);
    let mut rows = reader
        .list_visible_channels_scoped(&scope, probe_size, cursor)
        .await
        .map_err(crate::ports::PortError::into_app_error)?;

    // 四、探测结果 → 是否还有下一页。
    //
    // 注意这里**没有第二次查询、没有第二个判据、没有任何过滤**：`rows` 里的每一行都
    // 已经通过了唯一那次可见性判定，它们原样进应答。截断只按行数，不按内容。
    let has_more = rows.len() > page_size as usize;
    rows.truncate(page_size as usize);

    let next_cursor = if has_more {
        // `has_more` 为真意味着端口至少返回了 `page_size + 1` 行，而 `page_size >= 1`，
        // 所以 `rows` 截断后必然非空 —— `next_cursor` 非空时本页不可能为空。
        // 这正是上游那个"翻过去什么都没有"的反面，由
        // `next_cursor_never_promises_a_page_that_is_empty` 钉住。
        Some(mint_next_cursor(rows.last())?)
    } else {
        None
    };

    Ok(ChannelPage {
        channels: rows,
        next_cursor,
    })
}

/// Read one membership-visible channel and project only its current scope-matching native thread.
pub async fn get_visible_channel<R>(
    reader: &R,
    auth: &AuthContext,
    channel_id: ChannelId,
) -> Result<ChannelDetail, AppError>
where
    R: ChannelReader + ?Sized,
{
    if channel_id.as_str().is_empty()
        || channel_id.as_str().len() > 512
        || channel_id.as_str().chars().any(char::is_control)
    {
        return Err(AppError::MalformedPayload {
            field: "channel_id",
        });
    }
    let summary = reader
        .get_visible_channel(&channel_read_scope(auth), &channel_id)
        .await
        .map_err(crate::ports::PortError::into_app_error)?
        .ok_or(AppError::NotVisible)?;
    Ok(ChannelDetail {
        id: summary.id,
        name: summary.name,
        agent_ids: summary.agent_ids,
        thread_id: summary.thread_id,
        active: summary.active,
    })
}

fn channel_read_scope(auth: &AuthContext) -> ChannelReadScope {
    ChannelReadScope {
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
    }
}

/// 复现上游 `Math.min(Math.max(limit ?? DEFAULT, 1), MAX)`。
///
/// # `limit = 0` 的处置：提到 1，不报错
///
/// 与上游同值，理由也站得住：`0` 不是"畸形载荷"（它是合法 `u32`，schema 也没有下界），
/// 而且它的两种可能意图 —— "只探测有没有下一页"和"手滑" —— 都不该以 400 收场。返回一条
/// 也让 `next_cursor` 的语义保持可用：返回零条又给非空 `next_cursor`，就又制造了一次
/// "翻过去什么都没有"。
///
/// # 负数呢
///
/// 线上类型是 `Option<u32>`，负数在**反序列化阶段**就被 serde 拒绝成 400，压根到不了
/// 这里 —— 上游那个 `Math.max(…, 1)` 里防负数的那一半，在 Rust 侧由类型承担。
/// 由 `negative_limit_is_rejected_by_the_type_not_by_clamping` 配正向对照钉住。
fn clamp_page_size(limit: Option<u32>) -> u32 {
    limit
        .unwrap_or(DEFAULT_CHANNEL_PAGE)
        .clamp(1, MAX_CHANNEL_PAGE)
}

/// 由本页最后一行铸造下一页游标。
fn mint_next_cursor(last: Option<&ChannelSummary>) -> Result<String, AppError> {
    let last = last.ok_or(AppError::DependencyUnavailable {
        // 走到这里说明 `has_more` 为真却没有最后一行 —— 在当前实现下不可达
        // （`page_size >= 1` 保证截断后非空）。不 `unwrap()`：一条永远不该发生的路径
        // 该以可诊断的失败收场，而不是把整个进程打死。
        dependency: "channel_reader",
    })?;
    ChannelCursor::from_summary(last)
        .encode()
        .map_err(|_| AppError::DependencyUnavailable {
            dependency: "database",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FakeChannelReader, auth_for, summary_at, summary_without_messages};
    use crate::ports::PortError;
    use openbot_contracts::error::ErrorCode;
    use openbot_contracts::ids::ChannelId;

    /// 造 n 行，recency 递减（`c-00` 最新），于是期望顺序就是构造顺序。
    fn descending_rows(count: usize) -> Vec<ChannelSummary> {
        (0..count)
            .map(|i| {
                let minute = 59 - i;
                summary_at(
                    &format!("c-{i:02}"),
                    &format!("2026-08-22T04:{minute:02}:00Z"),
                )
            })
            .collect()
    }

    fn ids(page: &ChannelPage) -> Vec<String> {
        page.channels
            .iter()
            .map(|row| row.id.as_str().to_owned())
            .collect()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("构建当前线程运行时")
            .block_on(future)
    }

    use core::future::Future;

    #[test]
    fn detail_injects_full_scope_and_projects_only_detail_fields() {
        let mut summary = summary_at("channel-1", "2026-08-22T04:59:00Z");
        summary.agent_ids = vec![openbot_contracts::ids::BotId::new("bot-1")];
        summary.thread_id = Some(openbot_contracts::ids::ThreadId::new("thread-1"));
        summary.active = false;
        let reader = FakeChannelReader::empty().with_visible("actor-a", [summary.clone()]);
        let detail = block_on(get_visible_channel(
            &reader,
            &auth_for("actor-a"),
            ChannelId::new("channel-1"),
        ))
        .unwrap();
        assert_eq!(detail.id, summary.id);
        assert_eq!(detail.name, summary.name);
        assert_eq!(detail.agent_ids, summary.agent_ids);
        assert_eq!(detail.thread_id, summary.thread_id);
        assert!(!detail.active);
        assert_eq!(
            reader.detail_calls(),
            vec![(
                ChannelReadScope {
                    deployment: openbot_contracts::ids::DeploymentId::new("dep-g1"),
                    tenant: openbot_contracts::ids::TenantId::new("tenant-g1"),
                    actor: openbot_contracts::ids::ActorId::new("actor-a"),
                },
                ChannelId::new("channel-1"),
            )]
        );
    }

    #[test]
    fn detail_unknown_or_invisible_is_not_visible_and_malformed_never_calls_port() {
        let reader = FakeChannelReader::empty();
        assert_eq!(
            block_on(get_visible_channel(
                &reader,
                &auth_for("actor-a"),
                ChannelId::new("missing"),
            )),
            Err(AppError::NotVisible)
        );
        let before = reader.detail_calls().len();
        for invalid in ["", "bad\nchannel"] {
            assert_eq!(
                block_on(get_visible_channel(
                    &reader,
                    &auth_for("actor-a"),
                    ChannelId::new(invalid),
                )),
                Err(AppError::MalformedPayload {
                    field: "channel_id"
                })
            );
        }
        assert_eq!(reader.detail_calls().len(), before);
    }

    // -----------------------------------------------------------------------
    // 空列表：成功 + 空页，不是 404、不是错误（§15.3 末条 / 上游 #72 同族）
    // -----------------------------------------------------------------------

    #[test]
    fn empty_result_is_success_with_an_empty_page() {
        let reader = FakeChannelReader::empty();
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-1"),
            None,
            None,
        ))
        .expect("空结果必须是 Ok，不是错误");
        assert!(page.channels.is_empty());
        assert!(page.next_cursor.is_none());
    }

    /// 正向对照：同一条路径在有数据时确实返回条目 —— 否则上一条在
    /// 「这个用例永远返回空页」的世界里同样通过。
    #[test]
    fn non_empty_result_actually_carries_rows() {
        let reader = FakeChannelReader::empty().with_visible("actor-1", descending_rows(3));
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-1"),
            None,
            None,
        ))
        .expect("有数据时必须成功");
        assert_eq!(ids(&page), ["c-00", "c-01", "c-02"]);
        assert!(page.next_cursor.is_none(), "一共 3 行、页大小 50，已是末页");
    }

    // -----------------------------------------------------------------------
    // 分页
    // -----------------------------------------------------------------------

    #[test]
    fn page_is_capped_and_probes_with_limit_plus_one() {
        let reader = FakeChannelReader::empty().with_visible("actor-1", descending_rows(5));
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-1"),
            Some(2),
            None,
        ))
        .expect("分页必须成功");

        assert_eq!(ids(&page), ["c-00", "c-01"], "本页恰好 limit 条");
        assert!(
            page.next_cursor.is_some(),
            "还有 3 行没发，必须给下一页游标"
        );

        let calls = reader.calls();
        assert_eq!(calls.len(), 1, "一次请求只允许一次可见性查询");
        assert_eq!(calls[0].limit, 3, "limit+1 探测：要 2 条就读 3 行");
        assert_eq!(calls[0].actor.as_str(), "actor-1");
        assert!(calls[0].cursor.is_none(), "首页不带游标");
    }

    /// 用返回的游标翻完整本，断言**不重不漏**且顺序与一次性全取一致。
    #[test]
    fn walking_every_page_yields_each_row_exactly_once_in_order() {
        let all = descending_rows(7);
        let reader = FakeChannelReader::empty().with_visible("actor-1", all.clone());
        let auth = auth_for("actor-1");

        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let page = block_on(list_visible_channels(
                &reader,
                &auth,
                Some(3),
                cursor.as_deref(),
            ))
            .expect("翻页必须成功");
            walked.extend(ids(&page));
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        let expected: Vec<String> = all.iter().map(|row| row.id.as_str().to_owned()).collect();
        assert_eq!(walked, expected, "不重不漏，且顺序与全量一致");
    }

    #[test]
    fn last_page_has_no_next_cursor() {
        let reader = FakeChannelReader::empty().with_visible("actor-1", descending_rows(4));
        let auth = auth_for("actor-1");

        // 第一页 3 条 + 游标。
        let first = block_on(list_visible_channels(&reader, &auth, Some(3), None)).unwrap();
        assert_eq!(first.channels.len(), 3);
        let cursor = first.next_cursor.expect("还有第 4 行");

        // 第二页 1 条，且**没有**游标 —— 恰好取完时不能再许诺下一页。
        let second = block_on(list_visible_channels(
            &reader,
            &auth,
            Some(3),
            Some(&cursor),
        ))
        .unwrap();
        assert_eq!(ids(&second), ["c-03"]);
        assert!(second.next_cursor.is_none(), "取完了就不能再给游标");
    }

    /// 边界：总数**恰好等于**页大小时不得给出游标。
    ///
    /// 这是 `limit+1` 探测最容易写错的一格：探测读到 limit 行（不是 limit+1 行），
    /// 说明没有下一页。
    #[test]
    fn exactly_full_page_does_not_promise_a_next_page() {
        let reader = FakeChannelReader::empty().with_visible("actor-1", descending_rows(3));
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-1"),
            Some(3),
            None,
        ))
        .unwrap();
        assert_eq!(page.channels.len(), 3);
        assert!(page.next_cursor.is_none(), "恰好取完，不许诺下一页");
    }

    /// §28.1 R22 那个症状的直接闸门：`next_cursor` 非空 ⇒ 本页非空。
    ///
    /// 上游的两段判据不一致会让这条为假（分页段说"还有"，hydration 段把本页过滤空了）。
    #[test]
    fn next_cursor_never_promises_a_page_that_is_empty() {
        let reader = FakeChannelReader::empty().with_visible("actor-1", descending_rows(9));
        let auth = auth_for("actor-1");

        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = block_on(list_visible_channels(
                &reader,
                &auth,
                Some(2),
                cursor.as_deref(),
            ))
            .unwrap();
            if page.next_cursor.is_some() {
                assert!(
                    !page.channels.is_empty(),
                    "许诺了下一页就必须给出本页内容 —— 这正是上游 list 的缺陷形态"
                );
            }
            pages += 1;
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
            assert!(pages < 20, "翻页不收敛");
        }
        assert_eq!(pages, 5, "9 行 / 每页 2 条 = 5 页");
    }

    /// 排序键回落：从未有过消息的行按 `created_at` 参与定序，不被排到最后、也不消失。
    #[test]
    fn rows_without_messages_sort_by_created_at() {
        let reader = FakeChannelReader::empty().with_visible(
            "actor-1",
            vec![
                summary_at("c-new", "2026-08-22T04:00:00Z"),
                summary_without_messages("c-mid", "2026-08-22T03:00:00Z"),
                summary_at("c-old", "2026-08-22T02:00:00Z"),
            ],
        );
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-1"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(ids(&page), ["c-new", "c-mid", "c-old"]);
    }

    // -----------------------------------------------------------------------
    // limit 的四种边界
    // -----------------------------------------------------------------------

    #[test]
    fn limit_none_falls_back_to_the_upstream_default_of_fifty() {
        assert_eq!(clamp_page_size(None), 50);
        let reader = FakeChannelReader::empty();
        block_on(list_visible_channels(&reader, &auth_for("a"), None, None)).unwrap();
        assert_eq!(reader.calls()[0].limit, 51, "50 + 1 行探针");
    }

    #[test]
    fn limit_zero_is_raised_to_one_not_rejected() {
        assert_eq!(clamp_page_size(Some(0)), 1);
        let reader = FakeChannelReader::empty().with_visible("a", descending_rows(3));
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("a"),
            Some(0),
            None,
        ))
        .expect("limit=0 是钳制不是错误");
        assert_eq!(page.channels.len(), 1);
        assert!(page.next_cursor.is_some());
        assert_eq!(reader.calls()[0].limit, 2);
    }

    #[test]
    fn limit_above_max_is_truncated_to_the_cap() {
        assert_eq!(
            clamp_page_size(Some(MAX_CHANNEL_PAGE + 1)),
            MAX_CHANNEL_PAGE
        );
        assert_eq!(clamp_page_size(Some(u32::MAX)), MAX_CHANNEL_PAGE);
        let reader = FakeChannelReader::empty();
        block_on(list_visible_channels(
            &reader,
            &auth_for("a"),
            Some(u32::MAX),
            None,
        ))
        .unwrap();
        assert_eq!(
            reader.calls()[0].limit,
            MAX_CHANNEL_PAGE + 1,
            "截断到上限之后才加探针，探针不得把上限顶破成 u32::MAX+1"
        );
    }

    #[test]
    fn limit_exactly_at_the_cap_is_kept() {
        assert_eq!(clamp_page_size(Some(MAX_CHANNEL_PAGE)), MAX_CHANNEL_PAGE);
        assert_eq!(clamp_page_size(Some(1)), 1);
        assert_eq!(clamp_page_size(Some(7)), 7);
    }

    /// 负数不是被钳制掉的，是**类型上不存在**：线上是 `Option<u32>`。
    ///
    /// 负向断言（`-1` 解析失败）配正向对照（`1` 解析成功），否则它在
    /// 「什么都解析不了」的世界里同样通过。
    #[test]
    fn negative_limit_is_rejected_by_the_type_not_by_clamping() {
        use openbot_contracts::command::AppCommand;
        assert!(
            serde_json::from_str::<AppCommand>(
                r#"{"kind":"list_visible_channels","limit":-1,"cursor":null}"#
            )
            .is_err(),
            "负 limit 必须在反序列化阶段就 400"
        );
        assert!(
            serde_json::from_str::<AppCommand>(
                r#"{"kind":"list_visible_channels","limit":1,"cursor":null}"#
            )
            .is_ok(),
            "正向对照：合法 limit 确实解析得出来"
        );
    }

    // -----------------------------------------------------------------------
    // 游标畸形：400 且不产生 acting decision
    // -----------------------------------------------------------------------

    #[test]
    fn malformed_cursor_never_reaches_the_port() {
        let reader = FakeChannelReader::empty().with_visible("a", descending_rows(3));
        let err = block_on(list_visible_channels(
            &reader,
            &auth_for("a"),
            None,
            Some("not-a-cursor!!"),
        ))
        .expect_err("畸形游标必须报错");

        assert_eq!(err, AppError::MalformedPayload { field: "cursor" });
        assert_eq!(err.http_status(), 400);
        assert_eq!(
            reader.call_count(),
            0,
            "§15.3：malformed payload 不产生 acting decision —— 端口一次都不能被调用"
        );
    }

    /// 正向对照：合法游标确实**会**到达端口 —— 证明上一条不是靠「端口永远不被调用」成立。
    #[test]
    fn well_formed_cursor_does_reach_the_port() {
        let reader = FakeChannelReader::empty().with_visible("a", descending_rows(3));
        let auth = auth_for("a");
        let first = block_on(list_visible_channels(&reader, &auth, Some(1), None)).unwrap();
        let cursor = first.next_cursor.expect("还有行");

        block_on(list_visible_channels(
            &reader,
            &auth,
            Some(1),
            Some(&cursor),
        ))
        .unwrap();

        let calls = reader.calls();
        assert_eq!(calls.len(), 2);
        let passed = calls[1].cursor.as_ref().expect("游标必须原样传到端口");
        assert_eq!(passed.id, ChannelId::new("c-00"));
    }

    /// 畸形游标绝不静默回落成第一页 —— 上游 `decodeChannelCursor` 的 fail-open 形态。
    ///
    /// 负向（坏游标不返回首页数据）+ 正向（同一请求不带游标时确实返回首页数据）成对。
    #[test]
    fn malformed_cursor_does_not_silently_restart_from_page_one() {
        let reader = FakeChannelReader::empty().with_visible("a", descending_rows(3));
        let auth = auth_for("a");

        let bad = block_on(list_visible_channels(&reader, &auth, None, Some("@@@")));
        assert!(bad.is_err(), "坏游标必须报错，不能返回第一页");

        let good = block_on(list_visible_channels(&reader, &auth, None, None)).unwrap();
        assert_eq!(good.channels.len(), 3, "正向对照：不带游标确实拿得到第一页");
    }

    // -----------------------------------------------------------------------
    // 端口故障
    // -----------------------------------------------------------------------

    #[test]
    fn port_unavailable_maps_to_503() {
        let reader = FakeChannelReader::failing(PortError::Unavailable {
            dependency: "database",
        });
        let err = block_on(list_visible_channels(&reader, &auth_for("a"), None, None))
            .expect_err("依赖不可用必须报错");
        assert_eq!(err.code(), ErrorCode::DEPENDENCY_UNAVAILABLE);
        assert_eq!(err.http_status(), 503);
    }

    #[test]
    fn corrupt_row_also_maps_to_503_not_to_the_caller() {
        let reader = FakeChannelReader::failing(PortError::Corrupt {
            dependency: "database",
            field: "created_at",
        });
        let err = block_on(list_visible_channels(&reader, &auth_for("a"), None, None))
            .expect_err("解不开的行必须报错");
        assert_eq!(err.http_status(), 503);
        assert_ne!(err.code(), ErrorCode::MALFORMED_PAYLOAD, "不是调用方的锅");
    }

    // -----------------------------------------------------------------------
    // 可见性
    // -----------------------------------------------------------------------

    /// 负向：A 看不到 B 的 channel。
    #[test]
    fn one_actor_cannot_see_another_actors_channels() {
        let reader = FakeChannelReader::empty()
            .with_visible("actor-a", vec![summary_at("c-a", "2026-08-22T04:00:00Z")])
            .with_visible("actor-b", vec![summary_at("c-b", "2026-08-22T05:00:00Z")]);

        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-a"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(ids(&page), ["c-a"]);
        assert!(
            !ids(&page).contains(&"c-b".to_owned()),
            "B 的 channel 不得出现在 A 的列表里"
        );
    }

    /// 正向对照：A 确实看得见自己的 —— 否则上一条在「谁都看不见任何东西」的世界里同样通过。
    #[test]
    fn an_actor_does_see_their_own_channels() {
        let reader = FakeChannelReader::empty()
            .with_visible("actor-a", vec![summary_at("c-a", "2026-08-22T04:00:00Z")])
            .with_visible("actor-b", vec![summary_at("c-b", "2026-08-22T05:00:00Z")]);

        let a = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-a"),
            None,
            None,
        ))
        .unwrap();
        let b = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-b"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(ids(&a), ["c-a"]);
        assert_eq!(ids(&b), ["c-b"], "B 看得见自己的那条");
    }

    /// 伪造游标扩不了可见性：即使把游标指到很远的将来，也只看得到自己的行。
    #[test]
    fn a_forged_cursor_cannot_widen_visibility() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let reader = FakeChannelReader::empty()
            .with_visible("actor-a", vec![summary_at("c-a", "2026-08-22T04:00:00Z")])
            .with_visible("actor-b", vec![summary_at("c-b", "2026-08-22T05:00:00Z")]);

        let forged = URL_SAFE_NO_PAD.encode(br#"{"recency":"2999-12-31T23:59:59Z","id":"zzzz"}"#);
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("actor-a"),
            None,
            Some(&forged),
        ))
        .expect("形状合法的游标会被接受");
        assert_eq!(
            ids(&page),
            ["c-a"],
            "游标只影响从哪儿接着翻，不影响能看见谁"
        );
    }

    /// §28.1 R22 在 application 侧的另一半：**唯一一次可见性查询，零二次过滤**。
    ///
    /// 端口返回什么，应答里就有什么（页大小之内）。上游的 hydration 段就是在这一步把行
    /// 过滤没的，所以这里断言的是"没有那一步"。
    #[test]
    fn rows_are_never_post_filtered_after_the_visibility_query() {
        let rows = descending_rows(4);
        let reader = FakeChannelReader::empty().with_visible("a", rows.clone());
        let page = block_on(list_visible_channels(
            &reader,
            &auth_for("a"),
            Some(10),
            None,
        ))
        .unwrap();

        assert_eq!(reader.call_count(), 1, "只允许一次可见性查询");
        assert_eq!(
            page.channels, rows,
            "端口返回的每一行都必须原样进应答：不丢行、不改字段、不 join 第二张表"
        );
    }

    /// 权威 actor 来自 `AuthContext`，不是调用方给的。
    ///
    /// 这条是构造性的（签名里压根没有可以传 actor 的位置），测试固定"传下去的确实是
    /// 上下文里的那个"。
    #[test]
    fn the_actor_passed_to_the_port_comes_from_the_auth_context() {
        let reader = FakeChannelReader::empty();
        block_on(list_visible_channels(
            &reader,
            &auth_for("actor-authoritative"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(reader.calls()[0].actor.as_str(), "actor-authoritative");
        assert_eq!(
            reader.scoped_calls(),
            vec![ChannelReadScope {
                deployment: openbot_contracts::ids::DeploymentId::new("dep-g1"),
                tenant: openbot_contracts::ids::TenantId::new("tenant-g1"),
                actor: openbot_contracts::ids::ActorId::new("actor-authoritative"),
            }]
        );
    }
}
