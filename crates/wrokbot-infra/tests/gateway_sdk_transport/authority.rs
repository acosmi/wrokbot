#[derive(Clone)]
enum State {
    Ready(TokenSet),
    Missing,
    Pending,
}

// Test fixture only: proves SDK ordering, not real PG durability or user authority.
struct Authority {
    gate: Arc<tokio::sync::Mutex<()>>,
    state: Mutex<State>,
    fail_commit: AtomicBool,
    mismatch_readback: AtomicBool,
    fail_clear: AtomicBool,
    begins: AtomicUsize,
    commits: AtomicUsize,
}
impl Authority {
    fn new(base: &str, expired: bool) -> Arc<Self> {
        Arc::new(Self {
            gate: Arc::new(tokio::sync::Mutex::new(())),
            state: Mutex::new(State::Ready(TokenSet {
                access_token: "QA_FAKE_ACCESS".into(),
                refresh_token: "QA_FAKE_REFRESH".into(),
                expires_at: if expired {
                    "2000-01-01T00:00:00Z"
                } else {
                    "2099-01-01T00:00:00Z"
                }
                .into(),
                scope: "ai".into(),
                client_id: "qa-client".into(),
                server_url: base.into(),
            })),
            fail_commit: AtomicBool::new(false),
            mismatch_readback: AtomicBool::new(false),
            fail_clear: AtomicBool::new(false),
            begins: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
        })
    }
}
#[async_trait]
impl StrictTokenAuthority for Authority {
    async fn lock(&self) -> AuthorityResult<Box<dyn Send>> {
        Ok(Box::new(self.gate.clone().lock_owned().await))
    }
    async fn load(&self) -> AuthorityResult<AuthorityState> {
        assert!(
            self.gate.try_lock().is_err(),
            "SDK must hold authority lock"
        );
        match self.state.lock().unwrap().clone() {
            State::Ready(t) => Ok(AuthorityState::Ready(t)),
            State::Missing => Ok(AuthorityState::Missing),
            State::Pending => Ok(AuthorityState::RotationPending),
        }
    }
    async fn begin_rotation(&self) -> AuthorityResult<()> {
        assert!(self.gate.try_lock().is_err());
        self.begins.fetch_add(1, Ordering::SeqCst);
        *self.state.lock().unwrap() = State::Pending;
        Ok(())
    }
    async fn commit_rotation(&self, tokens: &TokenSet) -> AuthorityResult<()> {
        assert!(self.gate.try_lock().is_err());
        self.commits.fetch_add(1, Ordering::SeqCst);
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(TokenAuthorityError::ReconciliationRequired);
        }
        let mut tokens = tokens.clone();
        if self.mismatch_readback.load(Ordering::SeqCst) {
            tokens.scope = "different-scope".into();
        }
        *self.state.lock().unwrap() = State::Ready(tokens);
        Ok(())
    }
    async fn clear(&self) -> AuthorityResult<()> {
        assert!(self.gate.try_lock().is_err());
        if self.fail_clear.load(Ordering::SeqCst) {
            return Err(TokenAuthorityError::Unavailable);
        }
        *self.state.lock().unwrap() = State::Missing;
        Ok(())
    }
}

struct PoisonLegacyStore;
#[async_trait]
impl TokenStore for PoisonLegacyStore {
    async fn load(&self) -> acosmi::Result<Option<TokenSet>> {
        panic!("strict path used legacy load")
    }
    async fn save(&self, _: &TokenSet) -> acosmi::Result<()> {
        panic!("strict path used legacy save")
    }
    async fn clear(&self) -> acosmi::Result<()> {
        panic!("strict path used legacy clear")
    }
}
fn config(base: &str) -> Config {
    Config {
        server_url: Some(base.into()),
        store: Some(Arc::new(PoisonLegacyStore)),
        ..Default::default()
    }
}
