//! Message-template IPC (T-288). All commands are gated — templates are
//! mailbox-adjacent content, closed while the endpoint is locked.
//!
//! Writes are audited with the template id only — name/body are user
//! content and never enter the tamper-evident log. `Template::validate`
//! runs at the store boundary on every write, so malformed or oversized
//! fields fail with `invalid-input` regardless of renderer behavior.

use std::collections::BTreeMap;
use std::sync::Arc;

use tauri::State;

use kiwi_mail::templates::Template;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{RenderedTemplateView, TemplateInput, TemplateView};

fn bounded_id(name: &str, id: &str) -> CmdResult<()> {
    bounded(name, id, 64)
}

async fn audit(state: &AppState, event: &'static str, detail: &str) -> CmdResult<()> {
    state.audit.lock().await.record(event, detail, now_unix())
}

/// `kiwi_templates_list()` → `TemplateView[]`, ordered by name then id.
#[tauri::command]
pub async fn kiwi_templates_list(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<TemplateView>> {
    gate(state.inner()).await?;
    templates_list_impl(state.inner()).await
}

async fn templates_list_impl(state: &AppState) -> CmdResult<Vec<TemplateView>> {
    let store = state.store.lock().await;
    Ok(store
        .list_templates()?
        .into_iter()
        .map(TemplateView::from)
        .collect())
}

/// `kiwi_templates_create(template)` → `TemplateView` — the store
/// assigns `tpl-N` and timestamps; the renderer supplies only content.
#[tauri::command]
pub async fn kiwi_templates_create(
    state: State<'_, Arc<AppState>>,
    template: TemplateInput,
) -> CmdResult<TemplateView> {
    gate(state.inner()).await?;
    templates_create_impl(state.inner(), template).await
}

async fn templates_create_impl(state: &AppState, input: TemplateInput) -> CmdResult<TemplateView> {
    let template = Template {
        id: String::new(),
        name: input.name,
        subject: input.subject,
        body_text: input.body_text,
        body_html: input.body_html,
        created_unix: 0,
        updated_unix: 0,
    };
    let stored = state
        .store
        .lock()
        .await
        .insert_template(&template, now_unix())?;
    audit(state, "template-created", &stored.id).await?;
    Ok(TemplateView::from(stored))
}

/// `kiwi_templates_update(template)` → `TemplateView` — full replace by
/// `id` (`not-found` when absent); `createdUnix` is preserved.
#[tauri::command]
pub async fn kiwi_templates_update(
    state: State<'_, Arc<AppState>>,
    template: TemplateView,
) -> CmdResult<TemplateView> {
    gate(state.inner()).await?;
    templates_update_impl(state.inner(), template).await
}

async fn templates_update_impl(state: &AppState, view: TemplateView) -> CmdResult<TemplateView> {
    bounded_id("id", &view.id)?;
    let template = Template::from(view);
    let now = now_unix();
    let exists = state.store.lock().await.update_template(&template, now)?;
    if !exists {
        return Err(IpcError::not_found("unknown template"));
    }
    let stored = state
        .store
        .lock()
        .await
        .get_template(&template.id)?
        .ok_or_else(|| IpcError::not_found("template disappeared"))?;
    audit(state, "template-updated", &template.id).await?;
    Ok(TemplateView::from(stored))
}

/// `kiwi_templates_delete(templateId)` → `{ removed }` — idempotent for
/// the UI's delete-and-forget flow.
#[tauri::command]
pub async fn kiwi_templates_delete(
    state: State<'_, Arc<AppState>>,
    template_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    templates_delete_impl(state.inner(), &template_id).await
}

async fn templates_delete_impl(
    state: &AppState,
    template_id: &str,
) -> CmdResult<serde_json::Value> {
    bounded_id("templateId", template_id)?;
    let removed = state.store.lock().await.delete_template(template_id)?;
    if removed {
        audit(state, "template-deleted", template_id).await?;
    }
    Ok(serde_json::json!({ "removed": removed }))
}

/// `kiwi_templates_render(templateId, vars?)` → `RenderedTemplateView`.
///
/// Server-side `{{var}}` substitution is the contract (ipc.md): the
/// composer gets ready-to-use subject/body plus `missingVars` — the
/// well-formed placeholders with no supplied value, left verbatim.
/// `vars` is a flat JSON object of string values; bounds live in
/// `Template::render` (`invalid-input` on violation, not partial render).
#[tauri::command]
pub async fn kiwi_templates_render(
    state: State<'_, Arc<AppState>>,
    template_id: String,
    vars: Option<BTreeMap<String, String>>,
) -> CmdResult<RenderedTemplateView> {
    gate(state.inner()).await?;
    templates_render_impl(state.inner(), &template_id, vars.unwrap_or_default()).await
}

async fn templates_render_impl(
    state: &AppState,
    template_id: &str,
    vars: BTreeMap<String, String>,
) -> CmdResult<RenderedTemplateView> {
    bounded_id("templateId", template_id)?;
    let template = state
        .store
        .lock()
        .await
        .get_template(template_id)?
        .ok_or_else(|| IpcError::not_found("unknown template"))?;
    Ok(RenderedTemplateView::from(template.render(&vars)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(tag: &str) -> (Arc<AppState>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-tpl-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        (Arc::new(state), dir)
    }

    async fn state_with_template(name: &str) -> (Arc<AppState>, String) {
        let (state, _dir) = state("tpl");
        let stored = templates_create_impl(
            &state,
            TemplateInput {
                name: name.into(),
                subject: "Re: {{topic}}".into(),
                body_text: "Hi {{name}}".into(),
                body_html: None,
            },
        )
        .await
        .unwrap();
        (state, stored.id)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn templates_crud_roundtrip() {
        let (state, id) = state_with_template("Intro").await;
        assert_eq!(id, "tpl-1");

        let listed = templates_list_impl(&state).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Intro");

        let updated = templates_update_impl(
            &state,
            TemplateView {
                id: id.clone(),
                name: "Renamed".into(),
                subject: "s".into(),
                body_text: "b".into(),
                body_html: Some("<p>b</p>".into()),
                created_unix: 0,
                updated_unix: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert!(updated.body_html.is_some());
        assert!(updated.created_unix > 0, "created preserved from store");

        let gone = templates_update_impl(
            &state,
            TemplateView {
                id: "tpl-404".into(),
                name: "x".into(),
                subject: String::new(),
                body_text: String::new(),
                body_html: None,
                created_unix: 0,
                updated_unix: 0,
            },
        )
        .await;
        assert!(matches!(gone, Err(e) if e.code == "not-found"));

        let del = templates_delete_impl(&state, &id).await.unwrap();
        assert_eq!(del["removed"], true);
        let del2 = templates_delete_impl(&state, &id).await.unwrap();
        assert_eq!(del2["removed"], false);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn render_resolves_vars_and_reports_missing() {
        let (state, id) = state_with_template("Intro").await;
        let mut vars = BTreeMap::new();
        vars.insert("name".to_string(), "Ada".to_string());
        let r = templates_render_impl(&state, &id, vars).await.unwrap();
        assert_eq!(r.subject, "Re: {{topic}}");
        assert_eq!(r.body_text, "Hi Ada");
        assert_eq!(r.missing_vars, vec!["topic"]);

        let err = templates_render_impl(&state, "tpl-404", BTreeMap::new()).await;
        assert!(matches!(err, Err(e) if e.code == "not-found"));

        // Vars bounds are enforced at the render boundary.
        let mut big = BTreeMap::new();
        for i in 0..=kiwi_mail::templates::MAX_RENDER_VARS {
            big.insert(format!("v{i}"), "x".to_string());
        }
        let err = templates_render_impl(&state, &id, big).await;
        assert!(matches!(err, Err(e) if e.code == "invalid-input"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_rejects_oversized_and_blank_name() {
        let (state, _dir) = state("tpl-bad");
        let err = templates_create_impl(
            &state,
            TemplateInput {
                name: "   ".into(),
                subject: String::new(),
                body_text: "x".into(),
                body_html: None,
            },
        )
        .await;
        assert!(matches!(err, Err(e) if e.code == "invalid-input"));
        let err = templates_create_impl(
            &state,
            TemplateInput {
                name: "ok".into(),
                subject: String::new(),
                body_text: "x".repeat(kiwi_mail::templates::MAX_TEMPLATE_TEXT_LEN + 1),
                body_html: None,
            },
        )
        .await;
        assert!(matches!(err, Err(e) if e.code == "invalid-input"));
    }
}
