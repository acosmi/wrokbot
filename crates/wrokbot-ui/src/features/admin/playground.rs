//! Browser-authored sandbox component editor using the production Web renderer.

use core::fmt::Write as _;
use std::collections::BTreeMap;

use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::sandboxed::SaveSandboxedComponentRequest;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, SandboxedComponentRecord, is_sandboxed_component_name,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    delete_sandboxed_component, load_sandboxed_components, publish_sandboxed_component,
    save_sandboxed_component_draft,
};
use crate::features::gallery::SandboxedComponentFrame;
use crate::features::layout::{PageHeader, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Dialog, DialogBody, DialogContent, DialogFooter, Field,
    Input, Textarea,
};

const STARTER_HTML: &str = concat!(
    "<div cl",
    "ass=\"card\">\n  <h3 id=\"title\">Untitled</h3>\n  <p id=\"body\"></p>\n</div>"
);
const STARTER_CSS: &str = ".card { font: 14px system-ui; border: 1px solid #e5e5e5; border-radius: 8px; padding: 12px; }\n.card h3 { margin: 0 0 4px; font-size: 15px; }";
const STARTER_JS: &str = "// The arguments are on window.__args by the time this runs.\nconst args = window.__args || {};\ndocument.getElementById(\"title\").textContent = args.title || \"Untitled\";\ndocument.getElementById(\"body\").textContent = args.body || \"\";";
const STARTER_SCHEMA: &str = "{\n  \"type\": \"object\",\n  \"properties\": {\n    \"title\": { \"type\": \"string\" },\n    \"body\": { \"type\": \"string\" }\n  }\n}";
const STARTER_SAMPLE: &str = "{\n  \"title\": \"A worked example\",\n  \"body\": \"Edit the panels on the left and this redraws.\"\n}";

#[derive(Clone, Copy)]
struct DraftSignals {
    slug: RwSignal<String>,
    title: RwSignal<String>,
    description: RwSignal<String>,
    html: RwSignal<String>,
    css: RwSignal<String>,
    js_functions: RwSignal<String>,
    argument_schema: RwSignal<String>,
    sample_arguments: RwSignal<String>,
}

impl DraftSignals {
    fn starter() -> Self {
        Self {
            slug: RwSignal::new(String::new()),
            title: RwSignal::new(String::new()),
            description: RwSignal::new(String::new()),
            html: RwSignal::new(STARTER_HTML.to_owned()),
            css: RwSignal::new(STARTER_CSS.to_owned()),
            js_functions: RwSignal::new(STARTER_JS.to_owned()),
            argument_schema: RwSignal::new(STARTER_SCHEMA.to_owned()),
            sample_arguments: RwSignal::new(STARTER_SAMPLE.to_owned()),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn request(self) -> Option<SaveSandboxedComponentRequest> {
        if !is_sandboxed_component_name(&format!("custom_{}", self.slug.get_untracked()))
            || self.title.get_untracked().is_empty()
        {
            return None;
        }
        Some(SaveSandboxedComponentRequest {
            slug: self.slug.get_untracked(),
            title: self.title.get_untracked(),
            description: self.description.get_untracked(),
            html: self.html.get_untracked(),
            css: self.css.get_untracked(),
            js_functions: self.js_functions.get_untracked(),
            argument_schema: parse_object(&self.argument_schema.get_untracked())?,
            sample_arguments: parse_object(&self.sample_arguments.get_untracked())?,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn snapshot(self) -> [String; 8] {
        [
            self.slug,
            self.title,
            self.description,
            self.html,
            self.css,
            self.js_functions,
            self.argument_schema,
            self.sample_arguments,
        ]
        .map(|field| field.get_untracked())
    }

    fn load(self, component: &SandboxedComponentRecord) {
        self.slug.set(
            component
                .name
                .strip_prefix("custom_")
                .unwrap_or_default()
                .to_owned(),
        );
        self.title.set(component.title.clone());
        self.description.set(component.draft_description.clone());
        self.html.set(component.draft_html.clone());
        self.css.set(component.draft_css.clone());
        self.js_functions.set(component.draft_js_functions.clone());
        self.argument_schema.set(
            serde_json::to_string_pretty(&component.draft_argument_schema)
                .unwrap_or_else(|_| "{}".to_owned()),
        );
        self.sample_arguments.set(
            serde_json::to_string_pretty(&component.sample_arguments)
                .unwrap_or_else(|_| "{}".to_owned()),
        );
    }
}

#[derive(Clone, PartialEq)]
struct PreviewItem {
    key: String,
    component: PublishedSandboxedComponent,
    arguments: Value,
}

#[derive(Clone, Copy)]
struct MutationState {
    pending: RwSignal<bool>,
    error: RwSignal<bool>,
    reload: RwSignal<u64>,
    write_lock: Signal<bool>,
    worker_owner: StoredValue<Option<Owner>>,
}

/// Fresh-admin draft/save/publish/delete journey with the same renderer used by conversations.
#[component]
pub fn SandboxPlaygroundPage() -> impl IntoView {
    let i18n = use_i18n();
    let draft = DraftSignals::starter();
    let components = RwSignal::new(Vec::<SandboxedComponentRecord>::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(None::<ApiError>);
    let action_error = RwSignal::new(false);
    let pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::family_lock(
        crate::configuration_writes::ConfigurationKind::Sandbox,
    );
    let reload_generation = RwSignal::new(0_u64);
    let delete_open = RwSignal::new(false);
    let deleting = RwSignal::new(None::<String>);
    let worker_owner = StoredValue::new(Owner::current());
    let state = MutationState {
        pending,
        error: action_error,
        reload: reload_generation,
        write_lock,
        worker_owner,
    };
    install_loader(
        reload_generation,
        components,
        loading,
        load_error,
        worker_owner,
    );

    let schema_valid = Memo::new(move |_| parse_object(&draft.argument_schema.get()).is_some());
    let sample = Memo::new(move |_| parse_object(&draft.sample_arguments.get()));
    let identity_valid = Memo::new(move |_| {
        is_sandboxed_component_name(&format!("custom_{}", draft.slug.get()))
            && !draft.title.get().is_empty()
    });
    let draft_valid =
        Memo::new(move |_| identity_valid.get() && schema_valid.get() && sample.get().is_some());
    let preview = Memo::new(move |_| {
        let arguments = Value::Object(sample.get()?.into_iter().collect());
        let html = draft.html.get();
        let css = draft.css.get();
        let js_functions = draft.js_functions.get();
        let sample_text = draft.sample_arguments.get();
        Some(PreviewItem {
            key: format!("{html}\u{0}{css}\u{0}{js_functions}\u{0}{sample_text}"),
            component: PublishedSandboxedComponent {
                name: "custom_preview".to_owned(),
                html,
                css,
                js_functions,
                argument_schema: BTreeMap::new(),
            },
            arguments,
        })
    });

    let submit = move |publish| {
        if draft_valid.get_untracked() {
            dispatch_draft(draft, state, publish);
        }
    };
    let confirm_delete = move || {
        let Some(_name) = deleting.get_untracked() else {
            return;
        };
        if pending.get_untracked() || write_lock.get_untracked() {
            return;
        }
        pending.set(true);
        action_error.set(false);
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = worker_owner.get_value() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    match delete_sandboxed_component(&_name).await {
                        Ok(()) => {
                            if deleting.try_get_untracked().flatten().as_deref() == Some(&_name) {
                                delete_open.try_set(false);
                                deleting.try_set(None);
                            }
                            reload_generation.try_update(|generation| {
                                *generation = generation.saturating_add(1)
                            });
                        }
                        Err(_) => {
                            action_error.try_set(!write_lock.get_untracked());
                        }
                    }
                    pending.try_set(false);
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        pending.set(false);
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="sandbox-playground-title"
                title=move || t_string!(i18n, admin.playground_title).to_owned()
                description=move || t_string!(i18n, admin.playground_intro).to_owned()
            />
            <div class="ob-playground-actions">
                <Button
                    variant=ButtonVariant::Chip
                    size=ButtonSize::Small
                    disabled=Signal::derive(move || !draft_valid.get() || pending.get() || write_lock.get())
                    loading=pending
                    on_activate=move || submit(false)
                >{move || t!(i18n, admin.playground_save)}</Button>
                <Button
                    variant=ButtonVariant::Primary
                    size=ButtonSize::Small
                    disabled=Signal::derive(move || !draft_valid.get() || pending.get() || write_lock.get())
                    loading=pending
                    on_activate=move || submit(true)
                >{move || t!(i18n, admin.playground_publish)}</Button>
            </div>
            <Show when=move || action_error.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, admin.playground_action_error)}</p>
            </Show>
            <Show when=move || load_error.get().is_some()>
                <p class="ob-alert" role="alert">{move || if load_error.get() == Some(ApiError::Forbidden) {
                    t_string!(i18n, admin.playground_forbidden).to_owned()
                } else {
                    t_string!(i18n, admin.playground_load_error).to_owned()
                }}</p>
            </Show>
            <div class="ob-playground-grid">
                <section class="ob-playground-editor" aria-labelledby="sandbox-editor-title">
                    <h2 id="sandbox-editor-title">{move || t!(i18n, admin.playground_editor)}</h2>
                    <div class="ob-playground-identity">
                        <EditorField
                            id="sandbox-name"
                            label=move || t_string!(i18n, admin.playground_name).to_owned()
                            placeholder=move || t_string!(i18n, admin.playground_name_placeholder).to_owned()
                            value=draft.slug
                        />
                        <EditorField
                            id="sandbox-title"
                            label=move || t_string!(i18n, admin.playground_component_title).to_owned()
                            placeholder=move || t_string!(i18n, admin.playground_title_placeholder).to_owned()
                            value=draft.title
                        />
                    </div>
                    <EditorField
                        id="sandbox-description"
                        label=move || t_string!(i18n, admin.playground_description).to_owned()
                        placeholder=move || t_string!(i18n, admin.playground_description_placeholder).to_owned()
                        value=draft.description
                    />
                    <CodeField id="sandbox-html" label="HTML".to_owned() value=draft.html />
                    <CodeField id="sandbox-css" label="CSS".to_owned() value=draft.css />
                    <CodeField id="sandbox-js" label="JavaScript".to_owned() value=draft.js_functions />
                    <CodeField
                        id="sandbox-schema"
                        label=move || t_string!(i18n, admin.playground_schema).to_owned()
                        value=draft.argument_schema
                        invalid=Signal::derive(move || !schema_valid.get())
                    />
                    <CodeField
                        id="sandbox-sample"
                        label=move || t_string!(i18n, admin.playground_sample).to_owned()
                        value=draft.sample_arguments
                        invalid=Signal::derive(move || sample.get().is_none())
                    />
                </section>
                <section class="ob-playground-preview" aria-labelledby="sandbox-preview-title">
                    <h2 id="sandbox-preview-title">{move || t!(i18n, admin.playground_preview)}</h2>
                    <Show when=move || sample.get().is_none()>
                        <p class="ob-alert" role="alert">
                            {move || t!(i18n, admin.playground_sample_invalid)}
                        </p>
                    </Show>
                    <For
                        each=move || preview.get()
                        key=|item| item.key.clone()
                        children=move |item| view! {
                            <SandboxedComponentFrame
                                component=item.component
                                arguments=item.arguments
                                title=t_string!(i18n, admin.playground_preview).to_owned()
                            />
                        }
                    />
                    <div class="ob-playground-saved">
                        <h2>{move || t!(i18n, admin.playground_saved)}</h2>
                        <Show when=move || loading.get()>
                            <p class="ob-loading" role="status">{move || t!(i18n, common.loading)}</p>
                        </Show>
                        <Show when=move || !loading.get() && components.get().is_empty()>
                            <p class="ob-empty-body">{move || t!(i18n, admin.playground_empty)}</p>
                        </Show>
                        <ul class="ob-playground-list">
                            <For
                                each=move || components.get()
                                key=sandboxed_component_row_key
                                children=move |component| {
                                    let open_component = component.clone();
                                    let delete_name = component.name.clone();
                                    let status = if component.published {
                                        t_string!(i18n, admin.playground_published, revision = component.revision).to_owned()
                                    } else {
                                        t_string!(i18n, admin.playground_draft_only).to_owned()
                                    };
                                    let status = if component.has_unpublished_changes {
                                        format!("{status} · {}", t_string!(i18n, admin.playground_edited))
                                    } else {
                                        status
                                    };
                                    view! {
                                        <li>
                                            <div>
                                                <code>{component.name}</code>
                                                <p>{status}</p>
                                            </div>
                                            <div class="ob-playground-row-actions">
                                                <Button
                                                    size=ButtonSize::Small
                                                    variant=ButtonVariant::Chip
                                                    disabled=pending
                                                    on_activate=move || draft.load(&open_component)
                                                >{t!(i18n, admin.playground_open)}</Button>
                                                <Button
                                                    size=ButtonSize::Small
                                                    variant=ButtonVariant::DangerText
                                                    on_activate=move || {
                                                        deleting.set(Some(delete_name.clone()));
                                                        delete_open.set(true);
                                                    }
                                                >{t!(i18n, common.delete)}</Button>
                                            </div>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    </div>
                </section>
            </div>
        </PageShell>
        <Dialog
            id="sandbox-delete-dialog"
            open=delete_open
            on_close=UnsyncCallback::new(move |_| deleting.set(None))
        >
            <DialogContent
                title=move || t_string!(i18n, admin.playground_delete_title).to_owned()
                description=move || t_string!(i18n, admin.playground_delete_description).to_owned()
            >
                <DialogBody>
                    <code>{move || deleting.get().unwrap_or_default()}</code>
                </DialogBody>
                <DialogFooter>
                    <Button
                        variant=ButtonVariant::Ghost
                        on_activate=move || {
                            delete_open.set(false);
                            deleting.set(None);
                        }
                    >{move || t!(i18n, common.cancel)}</Button>
                    <Button
                        variant=ButtonVariant::DangerText
                        loading=pending disabled=write_lock
                        on_activate=confirm_delete
                    >{move || t!(i18n, common.delete)}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}

fn dispatch_draft(draft: DraftSignals, state: MutationState, publish: bool) {
    if state.pending.get_untracked() || state.write_lock.get_untracked() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let Some(request) = draft.request() else {
            return;
        };
        let snapshot = draft.snapshot();
        state.pending.set(true);
        state.error.set(false);
        if let Some(owner) = state.worker_owner.get_value() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result = if publish {
                        publish_sandboxed_component(&request).await
                    } else {
                        save_sandboxed_component_draft(&request).await
                    };
                    match result {
                        Ok(saved) => {
                            if draft.snapshot() == snapshot {
                                draft.load(&saved.component);
                            }
                            state.reload.try_update(|generation| {
                                *generation = generation.saturating_add(1)
                            });
                        }
                        Err(_) => {
                            state.error.try_set(!state.write_lock.get_untracked());
                        }
                    }
                    state.pending.try_set(false);
                });
            });
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        draft,
        publish,
        state.error,
        state.reload,
        state.worker_owner,
    );
}

#[component]
fn EditorField(
    #[prop(into)] id: String,
    #[prop(into)] label: TextProp,
    #[prop(into)] placeholder: TextProp,
    value: RwSignal<String>,
) -> impl IntoView {
    view! {
        <Field control_id=id label>
            <Input value placeholder />
        </Field>
    }
}

#[component]
fn CodeField(
    #[prop(into)] id: String,
    #[prop(into)] label: TextProp,
    value: RwSignal<String>,
    #[prop(optional, into)] invalid: MaybeProp<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-playground-code">
            <Field
                control_id=id
                label
                invalid
                error=move || t_string!(i18n, admin.playground_json_invalid).to_owned()
            >
                <Textarea value />
            </Field>
        </div>
    }
}

fn parse_object(raw: &str) -> Option<BTreeMap<String, Value>> {
    serde_json::from_str(raw).ok()
}

fn sandboxed_component_row_key(component: &SandboxedComponentRecord) -> String {
    let encoded = serde_json::to_vec(component).unwrap_or_default();
    let mut key = String::from("sandboxed-row-");
    for byte in Sha256::digest(encoded) {
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

fn install_loader(
    generation: RwSignal<u64>,
    components: RwSignal<Vec<SandboxedComponentRecord>>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<ApiError>>,
    worker_owner: StoredValue<Option<Owner>>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let observed = generation.get();
        loading.set(true);
        error.set(None);
        if let Some(owner) = worker_owner.get_value() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    match load_sandboxed_components().await {
                        Ok(loaded) if generation.try_get_untracked() == Some(observed) => {
                            components.try_set(loaded.components);
                        }
                        Err(failure) if generation.try_get_untracked() == Some(observed) => {
                            error.try_set(Some(failure));
                        }
                        Ok(_) | Err(_) => {}
                    }
                    if generation.try_get_untracked() == Some(observed) {
                        loading.try_set(false);
                    }
                })
            });
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (generation, components, worker_owner);
        loading.set(false);
        error.set(Some(ApiError::Unavailable));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_json_requires_an_object_and_starter_contract_is_valid() {
        assert!(parse_object(STARTER_SCHEMA).is_some());
        assert!(parse_object(STARTER_SAMPLE).is_some());
        for invalid in ["", "[]", "null", "true", "{"] {
            assert!(parse_object(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn saved_row_identity_changes_with_draft_and_publication_state() {
        let mut component = SandboxedComponentRecord {
            name: "custom_card".to_owned(),
            title: "Card".to_owned(),
            draft_description: "draft".to_owned(),
            draft_html: "<p>draft</p>".to_owned(),
            draft_css: "p{}".to_owned(),
            draft_js_functions: "document.body.dataset.ready='1';".to_owned(),
            draft_argument_schema: BTreeMap::new(),
            published_html: None,
            published_css: None,
            published_js_functions: None,
            published_argument_schema: None,
            sample_arguments: BTreeMap::new(),
            revision: 0,
            published: false,
            published_at: None,
            authored_by: Some("admin".to_owned()),
            has_unpublished_changes: false,
        };
        let draft_key = sandboxed_component_row_key(&component);
        component.published = true;
        component.revision = 1;
        component.published_html = Some(component.draft_html.clone());
        component.published_css = Some(component.draft_css.clone());
        component.published_js_functions = Some(component.draft_js_functions.clone());
        component.published_argument_schema = Some(BTreeMap::new());
        assert_ne!(sandboxed_component_row_key(&component), draft_key);
    }
}
