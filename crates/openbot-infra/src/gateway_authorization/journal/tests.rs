//! Private clock and typed-transition vectors; these do not count as actual Host/PG cases.
use super::super::InitialClock;
use super::*;
use std::sync::Mutex;

struct Clock(Mutex<ClockSample>);
impl InitialClock for Clock {
    fn sample(&self) -> ClockSample {
        *self.0.lock().unwrap()
    }
}
impl Clock {
    fn at(wall: DateTime<Utc>, mono: Instant) -> Arc<Self> {
        Arc::new(Self(Mutex::new(ClockSample { wall, mono })))
    }
    fn set(&self, wall: DateTime<Utc>, mono: Instant) {
        *self.0.lock().unwrap() = ClockSample { wall, mono };
    }
}
fn wall(seconds: i64, nanos: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, nanos).unwrap()
}
fn source_row() -> Row {
    let created = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
    Row {
        attempt_id: Uuid::parse_str("019a0300-0000-7000-8000-000000000028").unwrap(),
        journal_schema: 1,
        deployment_id: "typed-deployment".into(),
        tenant_id: "typed-tenant".into(),
        owner_user_id: "typed-owner".into(),
        auth_generation: 7,
        installation_id: "28".repeat(32),
        runtime_epoch: "29".repeat(32),
        issuer: "https://idp.test:48481".into(),
        redirect_uri: "http://127.0.0.1:48281/callback".into(),
        phase: "created".into(),
        client_id: None,
        enrollment_id: None,
        registration_admitted_at: None,
        code_admitted_at: None,
        created_at: created,
        expires_at: created + time::Duration::seconds(180),
        updated_at: created,
        finished_at: None,
        outcome_code: None,
    }
}

#[test]
fn t01_microseconds_floor_negative_epoch_and_full_time_range() {
    for (seconds, nanos, expected) in [
        (0, 1, 0),
        (0, 999, 0),
        (0, 1_001, 1_000),
        (-1, 999_999_999, -1_000),
        (-1, 1, -1_000_000_000),
    ] {
        assert_eq!(
            canonical_microseconds(wall(seconds, nanos))
                .unwrap()
                .unix_timestamp_nanos(),
            expected
        );
    }
    // This valid year is outside chrono's optional i64-nanosecond shortcut range.
    let year9999 = wall(253_402_300_799, 999_999_999);
    assert_eq!(
        canonical_microseconds(year9999)
            .unwrap()
            .unix_timestamp_nanos(),
        253_402_300_799_999_999_000
    );
    assert_eq!(
        canonical_microseconds(wall(253_402_300_800, 0))
            .unwrap_err()
            .kind(),
        Kind::Deadline
    );
}

#[test]
fn t02_original_first_sample_caller_cap_and_raw_wall_boundaries() {
    let mono = Instant::now();
    let start = wall(1_000, 123);
    let clock = Clock::at(start, mono);
    let owned: ClockOwner = clock.clone();
    let flow = SavedFlow::new(
        owned,
        CancellationToken::new(),
        (mono + Duration::from_secs(1)).into_std(),
    )
    .unwrap();
    assert_eq!(flow.deadline, mono + Duration::from_secs(1));
    assert_eq!(flow.created_at.unix_timestamp_nanos(), 1_000_000_000_000);
    assert_eq!(flow.expires_at.unix_timestamp_nanos(), 1_001_000_000_000);
    assert!(flow.check(None).is_ok());
    clock.set(
        start - chrono::Duration::nanoseconds(1),
        mono + Duration::from_millis(1),
    );
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Deadline);
    clock.set(start, mono - Duration::from_nanos(1));
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Deadline);
    clock.set(
        start + chrono::Duration::milliseconds(900),
        mono + Duration::from_secs(1),
    );
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Deadline);
    // Even just before the raw expiry, reaching canonical PG expiry is refused.
    clock.set(wall(1_001, 1), mono + Duration::from_millis(999));
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Deadline);
    let wide = Clock::at(start, mono);
    let flow = SavedFlow::new(
        wide,
        CancellationToken::new(),
        (mono + Duration::from_secs(500)).into_std(),
    )
    .unwrap();
    assert_eq!(flow.deadline, mono + Duration::from_secs(180));
    let below_micro = Clock::at(wall(0, 1), mono);
    assert_eq!(
        SavedFlow::new(
            below_micro,
            CancellationToken::new(),
            (mono + Duration::from_nanos(100)).into_std()
        )
        .err()
        .unwrap()
        .kind(),
        Kind::Deadline
    );
}

#[test]
fn t03_original_parent_and_capture_cap_never_restart() {
    let mono = Instant::now();
    let start = wall(1_000, 0);
    let parent = CancellationToken::new();
    let clock = Clock::at(start, mono);
    let owned: ClockOwner = clock.clone();
    let flow = SavedFlow::new(
        owned,
        parent.clone(),
        (mono + Duration::from_secs(60)).into_std(),
    )
    .unwrap();
    let budget = InitialBudget {
        original_parent: parent.clone(),
        owner_deadline: flow.deadline,
        http_entered_at: mono + Duration::from_secs(2),
        deadline: mono + Duration::from_secs(12),
    };
    clock.set(
        start + chrono::Duration::seconds(11),
        mono + Duration::from_secs(11),
    );
    assert!(flow.check(Some(&budget)).is_ok());
    clock.set(
        start + chrono::Duration::seconds(12),
        mono + Duration::from_secs(12),
    );
    assert_eq!(
        flow.check(Some(&budget)).err().unwrap().kind(),
        Kind::Deadline
    );
    assert!(
        flow.check(None).is_ok(),
        "flow remains live while original captured HTTP cap ends"
    );
    parent.cancel();
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Cancelled);
    assert_eq!(
        flow.check(Some(&budget)).err().unwrap().kind(),
        Kind::Cancelled
    );
    assert!(
        !CancellationToken::new().is_cancelled(),
        "a new token cannot replace the saved original parent"
    );
}

#[test]
fn t04_admission_preserves_seventeen_original_typed_facts() {
    let old = source_row();
    let stamp = old.created_at + time::Duration::microseconds(23);
    let actual = admitted_row(&old, stamp).unwrap();
    let expected = Row {
        phase: "registration_admitted".into(),
        registration_admitted_at: Some(stamp),
        updated_at: stamp,
        ..old.clone()
    };
    assert_eq!(actual, expected);
    assert_eq!(old.phase, "created");
    for invalid in [
        old.created_at - time::Duration::microseconds(1),
        old.expires_at,
    ] {
        assert_eq!(
            admitted_row(&old, invalid).unwrap_err().kind(),
            Kind::Refused
        );
    }
    let mut prefix = old.clone();
    prefix.registration_admitted_at = Some(stamp);
    assert_eq!(
        admitted_row(&prefix, stamp).unwrap_err().kind(),
        Kind::Refused
    );
    prefix = old.clone();
    prefix.client_id = Some("already-registered".into());
    assert_eq!(
        admitted_row(&prefix, stamp).unwrap_err().kind(),
        Kind::Refused
    );
    for phase in ["registered", "code_admitted", "enrolled", "closed"] {
        prefix = old.clone();
        prefix.phase = phase.into();
        assert_eq!(
            admitted_row(&prefix, stamp).unwrap_err().kind(),
            Kind::Refused
        );
    }
}

#[test]
fn t05_two_controlled_closes_preserve_prefix_and_original_deadline() {
    for admitted in [false, true] {
        let original = source_row();
        let old = if admitted {
            admitted_row(
                &original,
                original.created_at + time::Duration::microseconds(1),
            )
            .unwrap()
        } else {
            original
        };
        for reason in [
            ControlledCloseReason::Refused,
            ControlledCloseReason::DependencyUnknown,
        ] {
            let mut template = old.clone();
            template.outcome_code = Some(reason.as_str().into());
            let stamp = old.updated_at + time::Duration::microseconds(5);
            let actual = closed_row(&old, &template, stamp).unwrap();
            let expected = Row {
                phase: "closed".into(),
                updated_at: stamp,
                finished_at: Some(stamp),
                outcome_code: Some(reason.as_str().into()),
                ..old.clone()
            };
            assert_eq!(actual, expected);
            assert_eq!(
                actual.registration_admitted_at,
                old.registration_admitted_at
            );
            assert_eq!(
                closed_row(&old, &template, old.expires_at)
                    .unwrap_err()
                    .kind(),
                Kind::Refused
            );
        }
        for reason in [
            "cancelled",
            "expired",
            "host_revoked",
            "registration_unknown",
            "code_unknown",
            "enrollment_unknown",
            "restart_denied",
        ] {
            let mut template = old.clone();
            template.outcome_code = Some(reason.into());
            assert_eq!(
                closed_row(&old, &template, old.updated_at)
                    .unwrap_err()
                    .kind(),
                Kind::Refused
            );
        }
    }
}

#[test]
fn t06_static_error_facts_are_separate_from_ack_and_resources_are_owned() {
    for kind in [
        Kind::Refused,
        Kind::Unavailable,
        Kind::Cancelled,
        Kind::Deadline,
        Kind::LedgerInvalid,
        Kind::SchemaInvalid,
        Kind::ObservationUnknown,
        Kind::CommitUnknown,
        Kind::CommitAcknowledgedAfterDeadline,
        Kind::RollbackUnproven,
        Kind::RollbackAcknowledgedAfterDeadline,
        Kind::ReadbackUnproven,
    ] {
        for ack in [Ack::NotAttempted, Ack::Unknown, Ack::Timely, Ack::Late] {
            let error = Error::new(kind).with_acks(Ack::Timely, ack);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.write_ack(), Ack::Timely);
            assert_eq!(error.readback_ack(), ack);
            assert!(format!("{error:?}").len() < 256);
            assert!(
                error
                    .to_string()
                    .starts_with("gateway_authorization_journal_")
            );
        }
    }
    fn assert_send<T: Send>() {}
    assert_send::<CreatedAttemptOwner>();
    assert_send::<RegistrationAdmissionReceipt>();
    assert_send::<ClosedAttemptReceipt>();
    for invalid in ["", "ABCDEF", " ", "é"] {
        assert!(!canonical_hex64(invalid));
    }
    assert!(canonical_hex64(&"28".repeat(32)));
}
