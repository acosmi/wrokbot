//! Skill editor and separately acknowledged grant changes; instruction text is data, never code.

use super::state::SkillData;
use crate::api::skills as api;
use crate::features::admin::plugins::PluginActions;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonVariant, Dialog, DialogBody, DialogContent, DialogFooter, Field, Input, Textarea,
};
use leptos::prelude::*;
use openbot_contracts::mcp::PluginSkillMutation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkillDialog {
    Create,
    Edit(String),
    Grants(String),
    Delete(String),
}

impl SkillDialog {
    fn slug(&self) -> Option<&str> {
        match self {
            Self::Create => None,
            Self::Edit(s) | Self::Grants(s) | Self::Delete(s) => Some(s),
        }
    }
    fn return_id(&self) -> String {
        match self {
            Self::Create => "skill-create".into(),
            Self::Edit(s) => format!("skill-edit-{s}"),
            Self::Grants(s) => format!("skill-grants-{s}"),
            Self::Delete(s) => format!("skill-delete-{s}"),
        }
    }
}

#[component]
pub fn SkillDialogs(
    dialog: RwSignal<Option<SkillDialog>>,
    data: RwSignal<Option<SkillData>>,
    deployment: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let open = RwSignal::new(false);
    let slug = RwSignal::new(String::new());
    let title = RwSignal::new(String::new());
    let summary = RwSignal::new(String::new());
    let instructions = RwSignal::new(String::new());
    let invalid = RwSignal::new(false);
    let collision = RwSignal::new(false);
    let attempted = RwSignal::new(false);
    Effect::new(move |_| {
        let selected = dialog.get();
        open.set(selected.is_some());
        invalid.set(false);
        collision.set(false);
        attempted.set(false);
        slug.set(String::new());
        title.set(String::new());
        summary.set(String::new());
        instructions.set(String::new());
        if let Some(selected) = selected
            && let Some(selected_slug) = selected.slug()
        {
            slug.set(selected_slug.to_owned());
            if let Some(row) = data
                .get_untracked()
                .and_then(|d| d.selected(selected_slug, deployment))
            {
                title.set(row.title);
                summary.set(row.summary);
                instructions.set(row.instructions);
            }
        }
    });
    let close = UnsyncCallback::new(move |_| {
        let Some(selected) = dialog.get_untracked() else {
            return;
        };
        dialog.set(None);
        actions.return_to(&selected.return_id());
    });
    let save = move |_| {
        if actions.busy.get_untracked() {
            return;
        }
        let Some(selected) = dialog.get_untracked() else {
            return;
        };
        let Some(current) = data.get_untracked() else {
            invalid.set(true);
            return;
        };
        invalid.set(false);
        collision.set(false);
        let finish = move |ok| {
            if ok {
                dialog.try_set(None);
            }
        };
        match selected {
            SkillDialog::Create | SkillDialog::Edit(_) => {
                let mutation = PluginSkillMutation {
                    slug: slug.get_untracked().trim().to_owned(),
                    title: title.get_untracked(),
                    summary: summary.get_untracked(),
                    instructions: instructions.get_untracked(),
                    deployment_wide: deployment,
                };
                if api::validate_mutation(&mutation).is_err() {
                    invalid.set(true);
                    return;
                }
                if matches!(selected, SkillDialog::Create)
                    && current.all.iter().any(|row| row.slug == mutation.slug)
                {
                    collision.set(true);
                    return;
                }
                if let SkillDialog::Edit(ref original) = selected
                    && (original != &mutation.slug
                        || current.selected(original, deployment).is_none())
                {
                    invalid.set(true);
                    return;
                }
                let expected_owner = (!deployment).then_some(current.actor_id);
                attempted.set(true);
                actions.launch(
                    format!("skill:{}", mutation.slug),
                    async move { api::save(mutation, expected_owner).await },
                    finish,
                );
            }
            SkillDialog::Delete(target) => {
                if current.selected(&target, deployment).is_none() {
                    invalid.set(true);
                    return;
                }
                attempted.set(true);
                actions.launch(
                    format!("skill:{target}"),
                    async move { api::remove(&target).await },
                    finish,
                );
            }
            SkillDialog::Grants(_) => {}
        }
    };
    view! {
        <Dialog id="skills-dialog" open on_close=close>
            <DialogContent title=move || match dialog.get(){Some(SkillDialog::Create)=>t_string!(i18n,skills.create).to_owned(),Some(SkillDialog::Edit(_))=>t_string!(i18n,skills.edit).to_owned(),Some(SkillDialog::Delete(_))=>t_string!(i18n,skills.delete).to_owned(),Some(SkillDialog::Grants(_))=>t_string!(i18n,skills.grants).to_owned(),None=>String::new()}>
                <DialogBody>
                    <Show when=move || invalid.get()><p class="ob-alert" role="alert">{move ||t!(i18n,skills.invalid)}</p></Show>
                    <Show when=move || collision.get()><p class="ob-alert" role="alert">{move ||t!(i18n,skills.collision)}</p></Show>
                    <Show when=move || attempted.get() && actions.failed.get()><p class="ob-alert" role="alert">{move ||t!(i18n,skills.write_error)}</p></Show>
                    <Show when=move || matches!(dialog.get(),Some(SkillDialog::Create|SkillDialog::Edit(_)))>
                        <Field control_id="skill-slug" label=move ||t_string!(i18n,skills.slug).to_owned() description=move ||t_string!(i18n,skills.slug_help).to_owned()>
                            <Input value=slug disabled=Signal::derive(move ||actions.busy.get()||!matches!(dialog.get(),Some(SkillDialog::Create))) />
                        </Field>
                        <Field control_id="skill-title-input" label=move ||t_string!(i18n,skills.title_label).to_owned() disabled=actions.busy><Input value=title /></Field>
                        <Field control_id="skill-summary" label=move ||t_string!(i18n,skills.summary).to_owned() disabled=actions.busy><Input value=summary /></Field>
                        <Field control_id="skill-instructions" label=move ||t_string!(i18n,skills.instructions).to_owned() description=move ||t_string!(i18n,skills.instructions_help).to_owned() disabled=actions.busy><Textarea value=instructions /></Field>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Delete(_)))>
                        <p>{move ||t_string!(i18n,skills.delete_confirm,slug=slug.get()).to_owned()}</p>
                        <p class="text-fg-secondary">{move ||t!(i18n,skills.delete_help)}</p>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Grants(_)))>
                        <p>{move ||t!(i18n,skills.grants_intro)}</p>
                        {move || {
                            let Some(d)=data.get() else{return view!{<p role="status">{move ||t!(i18n,common.loading)}</p>}.into_any();};
                            if !d.agents_available{return view!{<p class="ob-alert" role="alert">{move ||t!(i18n,skills.agents_error)}</p>}.into_any();}
                            let Some(skill)=d.selected(&slug.get(),deployment) else{return view!{<p role="status">{move ||t!(i18n,skills.no_longer_available)}</p>}.into_any();};
                            let grant_set=skill.granted_to.into_iter().collect::<std::collections::BTreeSet<_>>();
                            let unavailable_count=grant_set.iter().filter(|id|!d.agents.iter().any(|a|a.id.as_str()==id.as_str())).count();
                            view!{
                                <div class="ob-page-rows">
                                    {d.agents.into_iter().map(|agent|{
                                        let allowed = super::state::may_grant_to_agent(d.actor_is_admin, agent.mine);
                                        let granted=grant_set.contains(agent.id.as_str());
                                        let current_slug=skill.slug.clone();let agent_id=agent.id.as_str().to_owned();

                                        view!{<div class="ob-plugin-grant"><div class="ob-plugin-copy"><strong>{agent.name}</strong><Show when=move ||!allowed><span class="text-fg-secondary">{move ||t!(i18n,skills.agent_read_only)}</span></Show></div>
                                            <Button selected=granted disabled=Signal::derive(move || actions.busy.get() || !allowed) on_activate=move |_|{
                                                let target=current_slug.clone();let id=agent_id.clone();attempted.set(true);
                                                actions.launch(format!("skill-grant:{target}:{id}"),async move{api::set_grant(&target,&id,!granted).await},move |_|{});
                                            }>{move ||if granted{t_string!(i18n,skills.revoke).to_owned()}else{t_string!(i18n,skills.grant).to_owned()}}</Button>
                                        </div>}
                                    }).collect_view()}
                                </div>
                                <Show when=move || { unavailable_count > 0 }><p class="text-fg-muted">{move ||t_string!(i18n,skills.unavailable_grants,count=unavailable_count).to_owned()}</p></Show>
                            }.into_any()
                        }}
                    </Show>
                </DialogBody>
                <DialogFooter>
                    <Button on_activate=move |_|close.run(())>{move ||t!(i18n,common.close)}</Button>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Create|SkillDialog::Edit(_)))>
                        <Button id="skill-save" variant=ButtonVariant::Primary disabled=actions.busy on_activate=save>{move ||t!(i18n,common.save)}</Button>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Delete(_)))>
                        <Button id="skill-confirm-delete" variant=ButtonVariant::DangerText disabled=actions.busy on_activate=save>{move ||t!(i18n,skills.confirm_delete)}</Button>
                    </Show>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}
