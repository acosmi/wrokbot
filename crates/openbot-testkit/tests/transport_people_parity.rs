//! W-4 people 五命令经 Axum 与 typed in-process 的同实例对拍。

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PeopleAdministration,
    PeoplePageRequest, PeoplePortError, PortError,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::{SessionLifetimePolicy, TrustedOrigins};
use openbot_server::{
    SINGLE_USER_ACTOR_ID, SensitiveWriteSecurity, ServerBuilder, SingleUserAuthResolver, router,
};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

#[derive(Clone, Default)]
struct EmptyChannels;

#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _actor: &ActorId,
        _limit: u32,
        _cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct FakePeople {
    rows: Arc<Mutex<Vec<Person>>>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakePeople {
    fn new() -> Self {
        Self {
            rows: Arc::new(Mutex::new(vec![
                person(SINGLE_USER_ACTOR_ID, Role::Admin),
                person("target", Role::User),
            ])),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl PeopleAdministration for FakePeople {
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        self.calls.lock().unwrap().push(format!("me:{actor}"));
        let person = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| &row.id == actor)
            .cloned()
            .ok_or(PeoplePortError::NotFound)?;
        Ok(CurrentUser {
            id: person.id,
            email: person.email,
            name: person.name,
            image: person.image,
            role: person.role,
        })
    }

    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError> {
        self.calls.lock().unwrap().push(format!(
            "list:{:?}:{:?}:{}",
            request.search, request.cursor, request.limit
        ));
        Ok(PeoplePage {
            people: self.rows.lock().unwrap().clone(),
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
            .unwrap()
            .push(format!("role:{actor}:{subject}:{desired}"));
        let mut rows = self.rows.lock().unwrap();
        let person = rows
            .iter_mut()
            .find(|row| &row.id == subject)
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
            .unwrap()
            .push(format!("access:{actor}:{subject}:{revoked}"));
        let mut rows = self.rows.lock().unwrap();
        let person = rows
            .iter_mut()
            .find(|row| &row.id == subject)
            .ok_or(PeoplePortError::NotFound)?;
        person.revoked = revoked;
        Ok(person.clone())
    }
}

fn person(id: &str, role: Role) -> Person {
    Person {
        id: ActorId::new(id),
        email: format!("{id}@example.test"),
        name: Some(id.to_owned()),
        image: None,
        role,
        providers: vec!["test".to_owned()],
        last_signed_in_at: Some(OffsetDateTime::UNIX_EPOCH),
        revoked: false,
        configured_admin: false,
    }
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-1"),
        TenantId::new("tenant-1"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        [Role::Admin],
        openbot_contracts::auth::AuthGeneration::new(0),
        true,
    )
}

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(Duration::hours(8), Duration::days(7), Duration::minutes(15))
        .unwrap()
}

struct Fixture {
    service: Arc<dyn ApplicationService>,
    transport: InProcessTransport,
    router: axum::Router,
    people: FakePeople,
}

impl Fixture {
    fn new() -> Self {
        let people = FakePeople::new();
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_people(people.clone()));
        let transport = InProcessTransport::new(Arc::clone(&service));
        let resolver = SingleUserAuthResolver::new(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new(SINGLE_USER_ACTOR_ID),
            lifetime(),
        );
        let security = SensitiveWriteSecurity::new(
            lifetime(),
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        );
        let state = ServerBuilder::new(Arc::clone(&service), Arc::new(resolver))
            .with_sensitive_write_security(security)
            .build();
        assert!(core::ptr::addr_eq(
            Arc::as_ptr(&service),
            state.application()
        ));
        Self {
            service,
            transport,
            router: router(state),
            people,
        }
    }

    async fn typed(&self, command: AppCommand) -> AppReply {
        assert!(Arc::ptr_eq(&self.service, self.transport.service()));
        self.transport.execute(auth(), command).await.unwrap()
    }

    async fn http(&self, request: Request<Body>) -> (axum::http::StatusCode, serde_json::Value) {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn post(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(axum::http::header::ORIGIN, "https://app.example.test")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn five_people_commands_match_between_http_and_typed_in_process() {
    let fx = Fixture::new();

    let (status, body) = fx.http(get("/api/me")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let AppReply::CurrentUser(typed) = fx.typed(AppCommand::GetCurrentUser).await else {
        panic!("typed me reply 不符");
    };
    assert_eq!(body["user"], serde_json::to_value(typed).unwrap());

    let (status, body) = fx.http(get("/api/admin/status")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let AppReply::AdminStatus(typed) = fx.typed(AppCommand::AdminStatus).await else {
        panic!("typed status reply 不符");
    };
    assert_eq!(body, serde_json::to_value(typed).unwrap());

    let list = AppCommand::ListPeople {
        search: Some(" target ".to_owned()),
        cursor: None,
        limit: Some(2),
    };
    let (status, body) = fx
        .http(get("/api/admin/people?search=%20target%20&limit=2"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let AppReply::People(typed) = fx.typed(list).await else {
        panic!("typed list reply 不符");
    };
    assert_eq!(body, serde_json::to_value(typed).unwrap());

    let role = AppCommand::ChangePersonRole {
        user_id: ActorId::new("target"),
        role: Role::Admin,
    };
    let (status, body) = fx
        .http(post("/api/admin/people/target/role", r#"{"role":"admin"}"#))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let AppReply::Person(typed) = fx.typed(role).await else {
        panic!("typed role reply 不符");
    };
    assert_eq!(body["person"], serde_json::to_value(typed).unwrap());

    let access = AppCommand::ChangePersonAccess {
        user_id: ActorId::new("target"),
        revoked: true,
    };
    let (status, body) = fx
        .http(post(
            "/api/admin/people/target/access",
            r#"{"revoked":true}"#,
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let AppReply::Person(typed) = fx.typed(access).await else {
        panic!("typed access reply 不符");
    };
    assert_eq!(body["person"], serde_json::to_value(typed).unwrap());

    let calls = fx.people.calls.lock().unwrap();
    for prefix in ["me:", "list:", "role:", "access:"] {
        assert_eq!(
            calls.iter().filter(|call| call.starts_with(prefix)).count(),
            2,
            "{prefix} 两条 transport 应各触达端口一次：{calls:?}",
        );
    }
}
