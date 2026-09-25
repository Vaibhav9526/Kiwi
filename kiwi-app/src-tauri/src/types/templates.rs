//! Template wire views (T-288). Templates are composer boilerplate —
//! content, not policy: a flat named list, no account scoping. Bounds
//! are enforced at `Template::validate` on every store write; the IPC
//! layer only camelCases the envelope.

use serde::{Deserialize, Serialize};

/// A stored template as the renderer sees it. `kiwi_templates_list`
/// emits it; `kiwi_templates_update` consumes it (full replace — the id
/// selects the row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateView {
    /// `tpl-N`, store-assigned on create.
    pub id: String,
    pub name: String,
    /// Subject line; `{{var}}` placeholders allowed, resolved at render.
    pub subject: String,
    /// Plain-text body — always present (may be empty).
    pub body_text: String,
    /// Optional HTML body; `null`/absent for text-only templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    pub created_unix: i64,
    pub updated_unix: i64,
}

impl From<kiwi_mail::templates::Template> for TemplateView {
    fn from(t: kiwi_mail::templates::Template) -> Self {
        Self {
            id: t.id,
            name: t.name,
            subject: t.subject,
            body_text: t.body_text,
            body_html: t.body_html,
            created_unix: t.created_unix,
            updated_unix: t.updated_unix,
        }
    }
}

impl From<TemplateView> for kiwi_mail::templates::Template {
    fn from(v: TemplateView) -> Self {
        kiwi_mail::templates::Template {
            id: v.id,
            name: v.name,
            subject: v.subject,
            body_text: v.body_text,
            body_html: v.body_html,
            created_unix: 0,
            updated_unix: 0,
        }
    }
}

/// `kiwi_templates_create` payload — id and timestamps are
/// store-assigned; the renderer never supplies them.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateInput {
    pub name: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
}

/// `kiwi_templates_render` result — `{{var}}` substituted fields plus
/// the well-formed placeholders that had no supplied value (left
/// verbatim in the text so the composer can flag them).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedTemplateView {
    pub subject: String,
    pub body_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// Sorted, deduped placeholder names with no supplied value.
    pub missing_vars: Vec<String>,
}

impl From<kiwi_mail::templates::RenderedTemplate> for RenderedTemplateView {
    fn from(r: kiwi_mail::templates::RenderedTemplate) -> Self {
        Self {
            subject: r.subject,
            body_text: r.body_text,
            body_html: r.body_html,
            missing_vars: r.missing_vars,
        }
    }
}
