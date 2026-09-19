use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::mcp::{McpAdminPage, McpConnections};

use crate::api::ApiError;

/// App-owned write state survives route unmount; it holds no credentials or request payload.
#[derive(Clone, Copy)]
pub(crate) struct PluginActions {
    pub busy: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub failed: RwSignal<bool>,
    pub target: RwSignal<Option<String>>,
    #[cfg(target_arch = "wasm32")]
    focus: RwSignal<Option<(String, String)>>,
}

impl PluginActions {
    pub fn new() -> Self {
        Self {
            busy: RwSignal::new(false),
            revision: RwSignal::new(0),
            failed: RwSignal::new(false),
            target: RwSignal::new(None),
            #[cfg(target_arch = "wasm32")]
            focus: RwSignal::new(None),
        }
    }

    pub fn launch(
        self,
        target: String,
        work: impl std::future::Future<Output = Result<(), ApiError>> + 'static,
        finished: impl FnOnce(bool) + 'static,
    ) {
        if self.busy.get_untracked() {
            return;
        }
        #[cfg(target_arch = "wasm32")]
        self.focus.set(capture_focus());
        self.busy.set(true);
        self.failed.set(false);
        self.target.set(Some(target));
        // A write is not a mount-scoped read: dropping the page must not pretend the submitted
        // operation was cancelled. Completion only updates app-owned state and guarded UI signals.
        leptos::task::spawn_local(async move {
            let success = work.await.is_ok();
            self.failed.try_set(!success);
            finished(success);
            self.revision
                .try_update(|revision| *revision = revision.saturating_add(1));
            self.busy.try_set(false);
        });
    }

    pub fn return_to(self, id: &str) {
        #[cfg(target_arch = "wasm32")]
        if let Some(window) = web_sys::window()
            && let Ok(path) = window.location().pathname()
        {
            self.focus.set(Some((path, id.to_owned())));
            if !self.busy.get_untracked() {
                self.restore_focus();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = id;
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn restore_focus(self) {
        let saved = self.focus.get_untracked();
        self.focus.set(None);
        if let Some((path, id)) = saved {
            use wasm_bindgen::JsCast;
            leptos::task::spawn_local(async move {
                leptos::task::tick().await;
                let Some(window) = web_sys::window() else {
                    return;
                };
                if window.location().pathname().ok().as_deref() != Some(&path) {
                    return;
                }
                let Some(document) = window.document() else {
                    return;
                };
                // Do not steal focus if the person moved to a different surviving control.
                if document.active_element().is_some_and(|active| {
                    active.tag_name() != "BODY"
                        && active.id() != id
                        && active.closest("[hidden]").ok().flatten().is_none()
                }) {
                    return;
                }
                let target = document
                    .get_element_by_id(&id)
                    .filter(|element| {
                        !element.has_attribute("disabled")
                            && element.closest("[hidden]").ok().flatten().is_none()
                    })
                    .or_else(|| document.query_selector("main h1").ok().flatten());
                if let Some(target) =
                    target.and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    if target.tag_name() == "H1" {
                        target.set_tab_index(-1);
                    }
                    let _ = target.focus();
                }
            });
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn capture_focus() -> Option<(String, String)> {
    let window = web_sys::window()?;
    let element = window.document()?.active_element()?;
    Some((window.location().pathname().ok()?, element.id()))
}

#[derive(Clone)]
pub struct PluginData {
    pub page: McpAdminPage,
    pub connections: McpConnections,
    pub agents: Vec<AgentProfile>,
}

#[derive(Clone, Copy)]
pub struct PluginPageState {
    pub data: RwSignal<Option<PluginData>>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<bool>,
    pub serial: RwSignal<u64>,
}

impl PluginPageState {
    pub fn new() -> Self {
        Self {
            data: RwSignal::new(None),
            loading: RwSignal::new(true),
            error: RwSignal::new(false),
            serial: RwSignal::new(0),
        }
    }

    pub fn reload(self) {
        self.serial
            .update(|serial| *serial = serial.saturating_add(1));
        let serial = self.serial.get_untracked();
        self.loading.set(true);
        self.error.set(false);
        self.data.set(None);
        #[cfg(target_arch = "wasm32")]
        let actions = expect_context::<PluginActions>();
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load().await;
            if self.serial.try_get_untracked() != Some(serial) {
                return;
            }
            match result {
                Ok(data) => {
                    self.data.set(Some(data));
                }
                Err(_) => {
                    self.error.set(true);
                }
            }
            self.loading.set(false);
            if !actions.busy.get_untracked() {
                actions.restore_focus();
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = serial;
            self.error.set(true);
            self.loading.set(false);
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn load() -> Result<PluginData, ApiError> {
    crate::api::require_admin_status().await?;
    let page = crate::api::plugins::load_page().await?;
    let connections = crate::api::load_mcp_connections().await?;
    let mut agents = crate::api::list_agents(false).await?;
    agents.extend(crate::api::list_agents(true).await?);
    agents.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if agents.len() > 4096 || agents.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(PluginData {
        page,
        connections,
        agents,
    })
}
