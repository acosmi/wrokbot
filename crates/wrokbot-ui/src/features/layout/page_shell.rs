//! Consistent configuration-page frame and section anatomy.

use leptos::prelude::*;

/// Closed content measure from the GUI first source, never an arbitrary pixel width.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PageWidth {
    /// Configuration pages, 960px maximum.
    #[default]
    Content,
    /// Dense tables, 1200px maximum.
    Table,
    /// Transcript-like reading columns, 880px maximum.
    Chat,
}

impl PageWidth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Table => "table",
            Self::Chat => "chat",
        }
    }
}

/// Centered page frame with one closed content measure.
#[component]
pub fn PageShell(
    /// One first-source content measure.
    #[prop(optional)]
    width: PageWidth,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="ob-page-shell" data-width=width.as_str()>
            {children()}
        </div>
    }
}

/// Fixed-height page topbar for breadcrumbs, back navigation and the page-level action.
#[component]
pub fn PageTopbar(children: Children) -> impl IntoView {
    view! { <div class="ob-page-topbar">{children()}</div> }
}

/// Same-origin back navigation used inside a PageTopbar.
#[component]
pub fn PageBackLink(
    /// Bounded same-origin destination.
    #[prop(into)]
    href: String,
    /// Visible localized link label.
    #[prop(into)]
    label: TextProp,
) -> impl IntoView {
    assert_same_origin_href(&href);
    assert!(
        !label.get().trim().is_empty(),
        "back label must be nonempty"
    );
    view! {
        <a class="ob-page-back" href=href>
            <span aria-hidden="true">"‹"</span>
            <span>{move || label.get()}</span>
        </a>
    }
}

/// The page's unique h1 and optional explanatory sentence.
#[component]
pub fn PageHeader(
    /// Stable h1 DOM token.
    #[prop(into)]
    heading_id: String,
    /// Visible localized h1 text.
    #[prop(into)]
    title: TextProp,
    /// Optional localized explanatory sentence.
    #[prop(optional, into)]
    description: TextProp,
) -> impl IntoView {
    assert_dom_id(&heading_id);
    assert!(
        !title.get().trim().is_empty(),
        "page title must be nonempty"
    );
    let visible_description = description.clone();
    view! {
        <header class="ob-page-header">
            <h1 id=heading_id class="ob-page-title">{move || title.get()}</h1>
            <p
                class="ob-page-intro"
                hidden=move || visible_description.get().trim().is_empty()
            >
                {move || description.get()}
            </p>
        </header>
    }
}

/// A named h2 section with an optional explanatory sentence.
#[component]
pub fn PageSection(
    /// Stable h2 DOM token used to name the section.
    #[prop(into)]
    heading_id: String,
    /// Visible localized h2 text.
    #[prop(into)]
    title: TextProp,
    /// Optional localized explanatory sentence.
    #[prop(optional, into)]
    description: TextProp,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&heading_id);
    assert!(
        !title.get().trim().is_empty(),
        "section title must be nonempty"
    );
    let labelled_by = heading_id.clone();
    let visible_description = description.clone();
    view! {
        <section class="ob-page-section" aria-labelledby=labelled_by>
            <h2 id=heading_id>{move || title.get()}</h2>
            <p
                class="ob-page-section-description"
                hidden=move || visible_description.get().trim().is_empty()
            >
                {move || description.get()}
            </p>
            {children()}
        </section>
    }
}

/// Bordered row group; callers omit this component when the collection is empty.
#[component]
pub fn PageRows(children: Children) -> impl IntoView {
    view! { <div class="ob-page-rows">{children()}</div> }
}

/// Sentence-level empty fact for an already named configuration section.
#[component]
pub fn PageEmpty(children: Children) -> impl IntoView {
    view! { <p class="ob-page-empty">{children()}</p> }
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "layout id must be one bounded DOM token"
    );
}

fn assert_same_origin_href(href: &str) {
    assert!(
        href.starts_with('/')
            && !href.starts_with("//")
            && href.len() <= 2048
            && !href
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\'),
        "PageBackLink href must be one bounded same-origin absolute path"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_ids_and_back_links_are_closed() {
        assert_eq!(PageWidth::Content.as_str(), "content");
        assert_eq!(PageWidth::Table.as_str(), "table");
        assert_eq!(PageWidth::Chat.as_str(), "chat");
        assert_dom_id("settings-connected-accounts");
        assert_same_origin_href("/settings?tab=general#theme");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn page_back_rejects_external_destinations() {
        assert_same_origin_href("https://attacker.example/settings");
    }
}
