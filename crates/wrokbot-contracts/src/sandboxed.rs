//! Sandboxed component authoring, publication, and published-source projections.
//!
//! These contracts deliberately contain source and sample arguments but no data-function grant or
//! host callback. Sandboxed source is untrusted input; execution belongs to the isolated renderer,
//! not to this module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Namespace reserved for browser-authored components.
pub const SANDBOXED_COMPONENT_PREFIX: &str = "custom_";
/// Maximum slug bytes accepted by the fixed-upstream naming grammar.
pub const SANDBOXED_COMPONENT_SLUG_MAX_BYTES: usize = 40;
/// Exact fixed-upstream model-visible success reply for one sandboxed renderer call.
pub const SANDBOXED_COMPONENT_CONFIRMATION: &str = "It is now on screen for the person.";

/// Whether a name is exactly in the server-owned browser-authored namespace.
#[must_use]
pub fn is_sandboxed_component_name(name: &str) -> bool {
    let Some(slug) = name.strip_prefix(SANDBOXED_COMPONENT_PREFIX) else {
        return false;
    };
    let bytes = slug.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (2..=SANDBOXED_COMPONENT_SLUG_MAX_BYTES).contains(&bytes.len())
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && bytes.iter().copied().all(|byte| edge(byte) || byte == b'_')
}

/// Closed draft accepted from the administrator playground.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveSandboxedComponentRequest {
    /// Lower-case letters, digits, and underscores before the server-owned `custom_` prefix.
    pub slug: String,
    /// Administrator-facing component title.
    pub title: String,
    /// Draft model-facing description.
    #[serde(default)]
    pub description: String,
    /// Draft authored markup.
    #[serde(default)]
    pub html: String,
    /// Draft authored styles.
    #[serde(default)]
    pub css: String,
    /// Draft authored JavaScript functions for the isolated renderer.
    #[serde(default)]
    pub js_functions: String,
    /// Draft JSON argument schema. An object is structural, not a convention.
    #[serde(default)]
    pub argument_schema: BTreeMap<String, Value>,
    /// Administrator-only arguments persisted for playground preview.
    #[serde(default)]
    pub sample_arguments: BTreeMap<String, Value>,
}

/// One administrator-visible sandboxed component draft and publication state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxedComponentRecord {
    /// Server-namespaced stable tool/component identity.
    pub name: String,
    /// Administrator-facing title.
    pub title: String,
    /// Current editable model-facing description.
    pub draft_description: String,
    /// Current editable authored markup.
    pub draft_html: String,
    /// Current editable authored styles.
    pub draft_css: String,
    /// Current editable authored JavaScript functions.
    pub draft_js_functions: String,
    /// Current editable argument schema.
    pub draft_argument_schema: BTreeMap<String, Value>,
    /// Published markup; absent until the first publication.
    pub published_html: Option<String>,
    /// Published styles; absent until the first publication.
    pub published_css: Option<String>,
    /// Published JavaScript functions; absent until the first publication.
    pub published_js_functions: Option<String>,
    /// Published argument schema; absent until the first publication.
    pub published_argument_schema: Option<BTreeMap<String, Value>>,
    /// Persisted administrator-only preview arguments.
    pub sample_arguments: BTreeMap<String, Value>,
    /// Monotonic publication revision; saving a draft does not increment it.
    pub revision: u32,
    /// Whether at least one complete source revision has been published.
    pub published: bool,
    /// Database-clock time of the latest publication.
    pub published_at: Option<OffsetDateTime>,
    /// Public actor identifier of the latest draft author, when known.
    pub authored_by: Option<String>,
    /// Derived fixed-upstream comparison of draft HTML/CSS/JS against published source.
    pub has_unpublished_changes: bool,
}

/// Administrator draft-list response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxedComponents {
    /// All sandboxed drafts in stable title/name order.
    pub components: Vec<SandboxedComponentRecord>,
}

/// Published source that an authenticated renderer may request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishedSandboxedComponent {
    /// Stable server-namespaced component identity.
    pub name: String,
    /// Published markup only; draft markup never crosses this boundary.
    pub html: String,
    /// Published styles only.
    pub css: String,
    /// Published JavaScript functions only.
    pub js_functions: String,
    /// Published argument schema only.
    pub argument_schema: BTreeMap<String, Value>,
}

/// Authenticated published-source response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedSandboxedComponents {
    /// Complete published sources in stable name order.
    pub components: Vec<PublishedSandboxedComponent>,
}

/// Save/publish response envelope preserved from the fixed upstream API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxedComponentResponse {
    /// Authoritative component state after the operation commits.
    pub component: SandboxedComponentRecord,
}

/// Delete response envelope preserved from the fixed upstream API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxedComponentDeleted {
    /// Always true; failures are represented by the stable application error taxonomy.
    pub ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_defaults_optional_source_and_json_objects_without_accepting_unknown_fields() {
        let draft: SaveSandboxedComponentRequest =
            serde_json::from_str(r#"{"slug":"delivery_eta","title":"Delivery ETA"}"#).unwrap();
        assert!(draft.description.is_empty());
        assert!(draft.argument_schema.is_empty());
        assert!(draft.sample_arguments.is_empty());
        assert!(
            serde_json::from_str::<SaveSandboxedComponentRequest>(
                r#"{"slug":"delivery_eta","title":"Delivery ETA","actor":"admin"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn wire_names_match_fixed_upstream_contract() {
        let draft: SaveSandboxedComponentRequest = serde_json::from_value(serde_json::json!({
            "slug": "delivery_eta",
            "title": "Delivery ETA",
            "jsFunctions": "function draw() {}",
            "argumentSchema": {"type": "object"},
            "sampleArguments": {"days": 2}
        }))
        .unwrap();
        let value = serde_json::to_value(draft).unwrap();
        assert!(value.get("jsFunctions").is_some());
        assert!(value.get("argumentSchema").unwrap().is_object());
        assert!(value.get("sampleArguments").unwrap().is_object());
        assert!(value.get("authoredBy").is_none());
    }

    #[test]
    fn namespaced_identity_is_exact_not_a_prefix_guess() {
        for valid in ["custom_ab", "custom_delivery_eta", "custom_a0"] {
            assert!(is_sandboxed_component_name(valid), "{valid}");
        }
        for invalid in [
            "custom_a",
            "custom__ab",
            "custom_ab_",
            "custom_A1",
            "showQuote",
            "custom_ab/extra",
        ] {
            assert!(!is_sandboxed_component_name(invalid), "{invalid}");
        }
    }
}
