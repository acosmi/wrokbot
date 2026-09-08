//! 测试替身。**只在 `cfg(test)` 下编译**，不进任何发行物。
//!
//! 本 crate 的全部测试都跑在内存里，一行 SQL、一个数据库连接都不需要 —— 这不是图省事，
//! 而是端口方向正确的可观察后果（见 crate 文档〈端口在这里定义〉）。
//!
//! [`FakeChannelReader`] 刻意**模拟数据库该有的行为**（按排序键定序、按 keyset 判据裁剪、
//! 按 `limit` 截断），而不是「返回我准备好的那几行」。区别很实在：后者会让分页测试变成
//! 「断言 fake 返回了我塞进去的东西」，那种测试在翻页逻辑写反的时候照样绿。

use std::sync::Mutex;

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::ids::{ActorId, ChannelId, DeploymentId, TenantId};
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cursor::{ChannelCursor, channel_recency};
use crate::ports::{
    ChannelReadScope, ChannelReader, PeopleAdministration, PeoplePageRequest, PeoplePortError,
    PortError,
};

/// 解析测试里用的 RFC 3339 字面量。解析不了就是测试写错了，直接 panic。
pub(crate) fn ts(raw: &str) -> OffsetDateTime {
    OffsetDateTime::parse(raw, &Rfc3339).expect("测试里的时间戳字面量必须是合法 RFC 3339")
}

/// 造一行「有过消息」的 channel。
///
/// `created_at` 刻意比 `last_message_at` 早一天：两个时间戳相同的话，
/// `channel_recency` 取错字段也测不出来。
pub(crate) fn summary_at(id: &str, last_message_at: &str) -> ChannelSummary {
    let last = ts(last_message_at);
    ChannelSummary {
        id: ChannelId::new(id),
        name: format!("channel {id}"),
        agent_ids: Vec::new(),
        last_message: Some("hi".to_owned()),
        last_message_at: Some(last),
        last_message_agent_id: None,
        created_at: last - time::Duration::days(1),
        // `None` 模拟尚未开始 native thread 的合法 channel；production scoped reader 在 G3
        // 已从 native threads 投影，不读取 legacy Intelligence mapping。
        thread_id: None,
        active: true,
    }
}

/// 造一行「从未有过消息」的 channel —— 排序键回落到 `created_at`。
pub(crate) fn summary_without_messages(id: &str, created_at: &str) -> ChannelSummary {
    ChannelSummary {
        id: ChannelId::new(id),
        name: format!("channel {id}"),
        agent_ids: Vec::new(),
        last_message: None,
        last_message_at: None,
        last_message_agent_id: None,
        created_at: ts(created_at),
        thread_id: None,
        active: true,
    }
}

/// 造一个已认证上下文。
///
/// `auth_generation` 用一个显眼的哨兵值：tracing 测试要断言它**没有**出现在 span 里，
/// 哨兵值让那条断言不会被别的数字偶然满足。
pub(crate) const SENTINEL_AUTH_GENERATION: u64 = 424_242;

/// 造一个已认证上下文（`AuthContext::for_test` 只在 contracts 的 `testkit` feature 下存在）。
pub(crate) fn auth_for(actor: &str) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-g1"),
        TenantId::new("tenant-g1"),
        ActorId::new(actor),
        [Role::Admin, Role::User],
        openbot_contracts::auth::AuthGeneration::new(SENTINEL_AUTH_GENERATION),
        false,
    )
}

/// 一次落到端口上的调用。测试用它断言 application 传下去的到底是什么。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PortCall {
    pub actor: ActorId,
    pub limit: u32,
    pub cursor: Option<ChannelCursor>,
}

/// 内存版 [`ChannelReader`]。
///
/// 「可见性」由构造时给定的 `(actor, row)` 关联表承载 —— 它就是 materialized membership
/// 在测试里的替身。**没有任何别的过滤维度**，这正是被测契约：可见性只有一个判据。
pub(crate) struct FakeChannelReader {
    rows: Vec<(ActorId, ChannelSummary)>,
    failure: Option<PortError>,
    calls: Mutex<Vec<PortCall>>,
    scoped_calls: Mutex<Vec<ChannelReadScope>>,
    detail_calls: Mutex<Vec<(ChannelReadScope, ChannelId)>>,
}

impl FakeChannelReader {
    /// 空库。
    pub(crate) fn empty() -> Self {
        Self {
            rows: Vec::new(),
            failure: None,
            calls: Mutex::new(Vec::new()),
            scoped_calls: Mutex::new(Vec::new()),
            detail_calls: Mutex::new(Vec::new()),
        }
    }

    /// 给某个 actor 挂上若干可见行（= 给他建 membership）。
    pub(crate) fn with_visible(
        mut self,
        actor: &str,
        rows: impl IntoIterator<Item = ChannelSummary>,
    ) -> Self {
        let actor = ActorId::new(actor);
        self.rows
            .extend(rows.into_iter().map(|row| (actor.clone(), row)));
        self
    }

    /// 让端口恒定失败。
    pub(crate) fn failing(failure: PortError) -> Self {
        Self {
            rows: Vec::new(),
            failure: Some(failure),
            calls: Mutex::new(Vec::new()),
            scoped_calls: Mutex::new(Vec::new()),
            detail_calls: Mutex::new(Vec::new()),
        }
    }

    /// 迄今为止收到的全部调用。
    pub(crate) fn calls(&self) -> Vec<PortCall> {
        self.calls.lock().expect("fake 的互斥锁不会中毒").clone()
    }

    /// 调用次数。
    pub(crate) fn call_count(&self) -> usize {
        self.calls.lock().expect("fake 的互斥锁不会中毒").len()
    }

    pub(crate) fn scoped_calls(&self) -> Vec<ChannelReadScope> {
        self.scoped_calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .clone()
    }

    pub(crate) fn detail_calls(&self) -> Vec<(ChannelReadScope, ChannelId)> {
        self.detail_calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .clone()
    }
}

#[async_trait]
impl ChannelReader for FakeChannelReader {
    async fn list_visible_channels(
        &self,
        actor: &ActorId,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        self.calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .push(PortCall {
                actor: actor.clone(),
                limit,
                cursor: cursor.clone(),
            });

        if let Some(failure) = self.failure {
            return Err(failure);
        }

        // 一、可见性：只认关联表（= materialized membership）。
        let mut visible: Vec<ChannelSummary> = self
            .rows
            .iter()
            .filter(|(owner, _)| owner == actor)
            .map(|(_, row)| row.clone())
            .collect();

        // 二、定序：coalesce(last_message_at, created_at) DESC, id DESC。
        visible.sort_by(|a, b| (channel_recency(b), &b.id).cmp(&(channel_recency(a), &a.id)));

        // 三、keyset 裁剪：(recency, id) < (cursor.recency, cursor.id)。
        if let Some(cursor) = cursor {
            visible.retain(|row| (channel_recency(row), &row.id) < (cursor.recency, &cursor.id));
        }

        // 四、截断到调用方要的行数（调用方已经把探测用的 +1 算进来了）。
        visible.truncate(limit as usize);
        Ok(visible)
    }

    async fn list_visible_channels_scoped(
        &self,
        scope: &ChannelReadScope,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        self.scoped_calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .push(scope.clone());
        self.list_visible_channels(&scope.actor, limit, cursor)
            .await
    }

    async fn get_visible_channel(
        &self,
        scope: &ChannelReadScope,
        channel_id: &ChannelId,
    ) -> Result<Option<ChannelSummary>, PortError> {
        self.detail_calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .push((scope.clone(), channel_id.clone()));
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        Ok(self
            .rows
            .iter()
            .find(|(owner, row)| owner == &scope.actor && &row.id == channel_id)
            .map(|(_, row)| row.clone()))
    }
}

/// people port 收到的调用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeopleCall {
    Current(ActorId),
    List(PeoplePageRequest),
    Role {
        actor: ActorId,
        subject: ActorId,
        role: Role,
    },
    Access {
        actor: ActorId,
        subject: ActorId,
        revoked: bool,
    },
}

/// 内存 people adapter；只模拟 port 事务的可观察结果，domain 拒绝另由 use case 映射测试覆盖。
pub(crate) struct FakePeopleAdministration {
    people: Mutex<Vec<Person>>,
    failure: Option<PeoplePortError>,
    calls: Mutex<Vec<PeopleCall>>,
}

impl FakePeopleAdministration {
    pub(crate) fn seeded(people: impl IntoIterator<Item = Person>) -> Self {
        Self {
            people: Mutex::new(people.into_iter().collect()),
            failure: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn failing(failure: PeoplePortError) -> Self {
        Self {
            people: Mutex::new(Vec::new()),
            failure: Some(failure),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn calls(&self) -> Vec<PeopleCall> {
        self.calls.lock().expect("fake 锁不应中毒").clone()
    }
}

#[async_trait]
impl PeopleAdministration for FakePeopleAdministration {
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        self.calls
            .lock()
            .expect("fake 锁不应中毒")
            .push(PeopleCall::Current(actor.clone()));
        if let Some(error) = self.failure {
            return Err(error);
        }
        let people = self.people.lock().expect("fake 锁不应中毒");
        let person = people
            .iter()
            .find(|person| &person.id == actor)
            .ok_or(PeoplePortError::NotFound)?;
        Ok(CurrentUser {
            id: person.id.clone(),
            email: person.email.clone(),
            name: person.name.clone(),
            image: person.image.clone(),
            role: person.role,
        })
    }

    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError> {
        self.calls
            .lock()
            .expect("fake 锁不应中毒")
            .push(PeopleCall::List(request.clone()));
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut people = self.people.lock().expect("fake 锁不应中毒").clone();
        people.truncate(request.limit as usize);
        Ok(PeoplePage {
            people,
            next_cursor: None,
        })
    }

    async fn change_role(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        desired: Role,
    ) -> Result<Person, PeoplePortError> {
        self.calls
            .lock()
            .expect("fake 锁不应中毒")
            .push(PeopleCall::Role {
                actor: actor.clone(),
                subject: subject.clone(),
                role: desired,
            });
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut people = self.people.lock().expect("fake 锁不应中毒");
        let person = people
            .iter_mut()
            .find(|person| &person.id == subject)
            .ok_or(PeoplePortError::NotFound)?;
        person.role = desired;
        Ok(person.clone())
    }

    async fn change_access(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        revoked: bool,
    ) -> Result<Person, PeoplePortError> {
        self.calls
            .lock()
            .expect("fake 锁不应中毒")
            .push(PeopleCall::Access {
                actor: actor.clone(),
                subject: subject.clone(),
                revoked,
            });
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut people = self.people.lock().expect("fake 锁不应中毒");
        let person = people
            .iter_mut()
            .find(|person| &person.id == subject)
            .ok_or(PeoplePortError::NotFound)?;
        person.revoked = revoked;
        Ok(person.clone())
    }
}

pub(crate) fn sample_person(id: &str, role: Role) -> Person {
    Person {
        id: ActorId::new(id),
        email: format!("{id}@example.invalid"),
        name: Some(id.to_owned()),
        image: None,
        role,
        providers: vec!["google".to_owned()],
        last_signed_in_at: Some(ts("2026-08-23T00:00:00Z")),
        revoked: false,
        configured_admin: false,
    }
}
