//! Read-only capabilities over the original native window and the actual Local assembly.

use super::{
    AppCommand, AppError, AppReply, DesktopTauriProtocol, Method, Request, Response, StatusCode,
    WindowAuthority, empty_response, error_response, json_response,
};

impl DesktopTauriProtocol {
    pub(super) async fn runtime_capabilities_request(
        &self,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.uri().query().is_some() || !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload {
                field: "runtime_capabilities",
            });
        }
        match self
            .transport
            .execute(authority.auth, AppCommand::GetRuntimeCapabilities)
            .await
        {
            Ok(AppReply::RuntimeCapabilities(response)) => json_response(&response),
            Ok(_) => error_response(AppError::DependencyUnavailable {
                dependency: "runtime_capabilities",
            }),
            Err(error) => error_response(error),
        }
    }
}

#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
mod local {
    use super::super::{DesktopTauriProtocol, WindowBindingRegistry};
    use crate::local_confirmation_service::LocalCapabilityStatusObservation;
    use openbot_application::runtime_capabilities::{
        CapabilityDeadline, RuntimeCapabilitiesCollectionError as Error,
        RuntimeCapabilitiesCollector, RuntimeCapabilitiesFuture, RuntimeCapabilityHostScope,
        RuntimeCapabilityObservationResult, RuntimeCapabilityTailWitness,
    };
    use openbot_contracts::auth::AuthContext;
    use openbot_contracts::request_binding::RequestBindingIssuer;
    use openbot_domain::runtime_capabilities::{LocalConfirmationFact, WindowBindingClaim};
    use openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority;
    use openbot_infra::db::pool::DatabasePool as Pool;
    use openbot_infra::runtime_capability_facts::{
        PostgresRuntimeCapabilityFacts, RuntimeCapabilityCollectorFactory,
        RuntimeCapabilityRevisionOwner,
    };
    use std::sync::{Arc, OnceLock, Weak};

    struct Host {
        registry: Weak<WindowBindingRegistry>,
        issuer: RequestBindingIssuer,
    }
    /// Pending actual composition capability; installation observes the protocol weakly.
    pub(crate) struct DesktopRuntimeCapabilityFactory {
        pool: Pool,
        installation: DesktopLocalAuthority,
        host: Arc<OnceLock<Host>>,
        facts: OnceLock<Weak<PostgresRuntimeCapabilityFacts>>,
        revision: Arc<RuntimeCapabilityRevisionOwner>,
    }
    impl DesktopRuntimeCapabilityFactory {
        pub(crate) fn new(
            pool: Pool,
            installation: DesktopLocalAuthority,
        ) -> Result<Arc<Self>, Error> {
            Ok(Arc::new(Self {
                pool,
                installation,
                host: Arc::new(OnceLock::new()),
                facts: OnceLock::new(),
                revision: Arc::new(RuntimeCapabilityRevisionOwner::new()?),
            }))
        }
        pub(crate) fn install(&self, protocol: &DesktopTauriProtocol) -> Result<(), Error> {
            let source = protocol
                .local_capability_authority
                .as_ref()
                .ok_or(Error::MissingHostSource)?;
            if !source.matches_runtime_scope(&self.pool, &self.installation) {
                return Err(Error::MissingHostSource);
            }
            if !protocol.request_binding_issuer.observation().is_current() {
                return Err(Error::NotCurrent);
            }
            let facts = self
                .facts
                .get()
                .and_then(Weak::upgrade)
                .ok_or(Error::MissingHostSource)?;
            protocol
                .window_registry
                .runtime_capability_facts
                .set(Arc::downgrade(&facts))
                .map_err(|_| Error::MissingHostSource)?;
            self.host
                .set(Host {
                    registry: Arc::downgrade(&protocol.window_registry),
                    issuer: protocol.request_binding_issuer.clone(),
                })
                .map_err(|_| Error::MissingHostSource)
        }
    }
    struct LocalCollector {
        installation: DesktopLocalAuthority,
        host: Arc<OnceLock<Host>>,
        facts: Arc<PostgresRuntimeCapabilityFacts>,
        revision: Arc<RuntimeCapabilityRevisionOwner>,
    }
    impl RuntimeCapabilityCollectorFactory for DesktopRuntimeCapabilityFactory {
        fn build(
            &self,
            facts: Arc<PostgresRuntimeCapabilityFacts>,
        ) -> Result<Arc<dyn RuntimeCapabilitiesCollector>, Error> {
            let auth = self.installation.auth_context();
            if !facts.matches_pool_scope(&self.pool, auth.deployment(), auth.tenant()) {
                return Err(Error::MissingHostSource);
            }
            self.facts
                .set(Arc::downgrade(&facts))
                .map_err(|_| Error::MissingHostSource)?;
            Ok(Arc::new(LocalCollector {
                installation: self.installation.clone(),
                host: self.host.clone(),
                facts,
                revision: self.revision.clone(),
            }))
        }
    }
    struct WindowWitness {
        registry: Weak<WindowBindingRegistry>,
        issuer: RequestBindingIssuer,
        scope: RuntimeCapabilityHostScope,
        local: Option<LocalCapabilityStatusObservation>,
        expected_confirmation: LocalConfirmationFact,
    }
    impl WindowWitness {
        fn check(
            &self,
            auth: &AuthContext,
            deadline: CapabilityDeadline,
        ) -> Result<LocalConfirmationFact, Error> {
            deadline.check()?;
            if !self.scope.matches_auth(auth) || !self.issuer.observation().is_current() {
                return Err(Error::NotCurrent);
            }
            let window = self
                .scope
                .binding_claim()
                .window()
                .ok_or(Error::MissingHostSource)?;
            let registry = self.registry.upgrade().ok_or(Error::NotCurrent)?;
            let map = registry
                .windows
                .try_read()
                .map_err(|_| Error::Unavailable)?;
            let current = map
                .get(window.label())
                .filter(|current| {
                    current.binding_id == window.nonce().get() && !current.closed.is_cancelled()
                })
                .ok_or(Error::NotCurrent)?;
            if current.auth != *auth
                || !current
                    .auth
                    .request_binding()
                    .zip(auth.request_binding())
                    .is_some_and(|(left, right)| left.identity().same_binding(right.identity()))
            {
                return Err(Error::NotCurrent);
            }
            let fact = match &self.local {
                Some(local) => {
                    let admitted = current
                        .local_confirmation
                        .as_ref()
                        .ok_or(Error::NotCurrent)?;
                    let slot = registry
                        .local_confirmation_slot
                        .get()
                        .and_then(Weak::upgrade)
                        .ok_or(Error::NotCurrent)?;
                    if !Arc::ptr_eq(&slot, &admitted.service) || !local.matches_service(&slot) {
                        return Err(Error::NotCurrent);
                    }
                    local.current_fact(auth, deadline, self.expected_confirmation)?
                }
                None => LocalConfirmationFact::Unavailable,
            };
            deadline.check()?;
            Ok(fact)
        }
    }
    impl RuntimeCapabilityTailWitness for WindowWitness {
        fn verify_current(
            &self,
            auth: &AuthContext,
            deadline: CapabilityDeadline,
        ) -> Result<(), Error> {
            let current = self.check(auth, deadline)?;
            if self.local.is_some() && current != self.expected_confirmation {
                return Err(Error::Unavailable);
            }
            Ok(())
        }
    }
    impl LocalCollector {
        fn admit(
            &self,
            auth: &AuthContext,
            deadline: CapabilityDeadline,
            prior: LocalConfirmationFact,
        ) -> Result<WindowWitness, Error> {
            deadline.check()?;
            let host = self.host.get().ok_or(Error::MissingHostSource)?;
            let registry = host.registry.upgrade().ok_or(Error::NotCurrent)?;
            if !host.issuer.observation().is_current() {
                return Err(Error::NotCurrent);
            }
            let binding = auth.request_binding().ok_or(Error::MissingHostSource)?;
            let map = registry
                .windows
                .try_read()
                .map_err(|_| Error::Unavailable)?;
            let (label, current) = map
                .iter()
                .find(|(_, current)| {
                    current.auth == *auth
                        && current.auth.request_binding().is_some_and(|candidate| {
                            candidate.identity().same_binding(binding.identity())
                        })
                })
                .ok_or(Error::NotCurrent)?;
            if current.closed.is_cancelled() {
                return Err(Error::NotCurrent);
            }
            let window = WindowBindingClaim::declare(label, current.binding_id)
                .map_err(|_| Error::InvalidFacts)?;
            let scope = RuntimeCapabilityHostScope::for_desktop_local(
                &host.issuer,
                auth,
                self.revision.runtime_epoch(),
                window,
            )?;
            let local = current
                .local_confirmation
                .as_ref()
                .map(|local| {
                    let slot = registry
                        .local_confirmation_slot
                        .get()
                        .and_then(Weak::upgrade)
                        .ok_or(Error::MissingHostSource)?;
                    if !Arc::ptr_eq(&slot, &local.service) {
                        return Err(Error::NotCurrent);
                    }
                    slot.capability_status_observation(
                        &local.grant,
                        auth,
                        &current.closed,
                        deadline,
                    )
                })
                .transpose()?;
            Ok(WindowWitness {
                registry: host.registry.clone(),
                issuer: host.issuer.clone(),
                scope,
                local,
                expected_confirmation: prior,
            })
        }
    }
    impl RuntimeCapabilitiesCollector for LocalCollector {
        fn observe<'a>(
            &'a self,
            auth: &'a AuthContext,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilitiesFuture<'a> {
            Box::pin(async move {
                let mut witness = self.admit(auth, deadline, LocalConfirmationFact::Unknown)?;
                let mut snapshot = self
                    .facts
                    .observe_desktop_local(auth, &self.installation, &witness.scope, deadline)
                    .await?;
                witness.expected_confirmation = witness.check(auth, deadline)?;
                snapshot = snapshot.with_local_confirmation(witness.expected_confirmation);
                let scope = witness.scope.clone();
                snapshot
                    .with_host_tail(Arc::new(witness))
                    .into_observation(scope, &self.revision.next()?)
            })
        }
        fn finalize<'a>(
            &'a self,
            auth: &'a AuthContext,
            observed: RuntimeCapabilityObservationResult,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilitiesFuture<'a> {
            Box::pin(async move {
                let prior = observed
                    .as_ref()
                    .map_or(LocalConfirmationFact::Unknown, |observation| {
                        observation.facts().local_confirmation
                    });
                let mut witness = self.admit(auth, deadline, prior)?;
                let mut snapshot = self
                    .facts
                    .observe_desktop_local(auth, &self.installation, &witness.scope, deadline)
                    .await?;
                let observed = observed?;
                if !observed.scope().matches_auth(auth) {
                    return Err(Error::NotCurrent);
                }
                witness.expected_confirmation = witness.check(auth, deadline)?;
                snapshot = snapshot.with_local_confirmation(witness.expected_confirmation);
                Ok(snapshot.with_host_tail(Arc::new(witness)).apply(observed))
            })
        }
        fn tail_current(
            &self,
            auth: &AuthContext,
            finalized: RuntimeCapabilityObservationResult,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilityObservationResult {
            deadline.check()?;
            if !self.facts.is_current() {
                return Err(Error::NotCurrent);
            }
            let host = self.host.get().ok_or(Error::MissingHostSource)?;
            if !host.issuer.observation().is_current() {
                return Err(Error::NotCurrent);
            }
            // Do not expose an old error after its real original window disappeared.
            let current = self.admit(auth, deadline, LocalConfirmationFact::Unknown)?;
            current.check(auth, deadline)?;
            let observation = finalized?;
            observation.verify_tail_witness(auth, deadline)?;
            Ok(observation)
        }
    }
}
#[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
pub(crate) use local::DesktopRuntimeCapabilityFactory;
