//! Optional form location on existing routes; selection is never an authorization grant.

use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate, use_query_map};

const EDITOR: &str = "ui_editor";
const TARGET: &str = "ui_target";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EditorSelection {
    pub kind: &'static str,
    pub target: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct EditorLocation {
    pub selection: Memo<Option<EditorSelection>>,
    change: UnsyncCallback<Option<EditorSelection>>,
}

impl EditorLocation {
    pub fn new(allowed: &'static [&'static str]) -> Self {
        let query = use_query_map();
        let selection = Memo::new(move |_| {
            let query = query.get();
            let kind = query.get(EDITOR)?;
            let kind = *allowed.iter().find(|value| **value == kind)?;
            let target = query.get(TARGET);
            if target.as_deref().is_some_and(|id| {
                id.is_empty() || id.len() > 512 || id.chars().any(char::is_control)
            }) {
                return None;
            }
            Some(EditorSelection { kind, target })
        });
        let location = use_location();
        let navigate = use_navigate();
        let change = UnsyncCallback::new(move |selected: Option<EditorSelection>| {
            if selected.as_ref().is_some_and(|s| {
                !allowed.contains(&s.kind)
                    || s.target.as_deref().is_some_and(|id| {
                        id.is_empty() || id.len() > 512 || id.chars().any(char::is_control)
                    })
            }) {
                return;
            }
            let mut href = editor_href(
                &location.pathname.get_untracked(),
                query
                    .get_untracked()
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v))
                    .collect(),
                selected.as_ref(),
            );
            let hash = location.hash.get_untracked();
            if !hash.is_empty() {
                href.push('#');
                href.push_str(hash.trim_start_matches('#'));
            }
            navigate(&href, Default::default());
        });
        Self { selection, change }
    }

    pub fn open(self, kind: &'static str, target: Option<String>) {
        self.change.run(Some(EditorSelection { kind, target }));
    }

    pub fn close(self) {
        self.change.run(None);
    }
}

fn editor_href(
    path: &str,
    mut query: Vec<(String, String)>,
    selected: Option<&EditorSelection>,
) -> String {
    query.retain(|(key, _)| key != EDITOR && key != TARGET);
    if let Some(selected) = selected {
        query.push((EDITOR.to_owned(), selected.kind.to_owned()));
        if let Some(id) = &selected.target {
            query.push((TARGET.to_owned(), id.clone()));
        }
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    if encoded.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locating_editor_preserves_existing_identity_and_repeated_query_values() {
        let query = [
            ("agent", "original"),
            ("thread", "original-thread"),
            ("filter", "one"),
            ("filter", "two"),
            (EDITOR, "old"),
            (TARGET, "old-id"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect::<Vec<_>>();
        let selected = EditorSelection {
            kind: "model-edit",
            target: Some("new-id".into()),
        };
        let href = editor_href("/settings/models", query.clone(), Some(&selected));
        for value in [
            "agent=original",
            "thread=original-thread",
            "filter=one",
            "filter=two",
            "ui_editor=model-edit",
            "ui_target=new-id",
        ] {
            assert!(href.contains(value));
        }
        assert!(!href.contains("old"));
        let closed = editor_href("/settings/models", query, None);
        assert!(!closed.contains("ui_editor") && !closed.contains("ui_target"));
        assert!(closed.contains("agent=original") && closed.contains("thread=original-thread"));
    }
}
