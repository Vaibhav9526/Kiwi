//! Lock-gated sandbox-open IPC for hostile links and stored attachments.

use std::sync::Arc;

use kiwi_sandbox::{AnalysisReport, Availability, Sandbox, SandboxProvider, SandboxSpec};
use serde::Serialize;
use tauri::State;
use url::Url;

use crate::commands::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, MAX_SANDBOX_SESSIONS, SandboxSessionRecord, now_unix};
use crate::types::SandboxOpenView;

const MAX_LINK_CHARS: usize = 2048;
const MAX_FILENAME_CHARS: usize = 512;
const MAX_SANDBOX_BYTES: usize = 64 * 1024 * 1024;
const SANDBOX_TIMEOUT_SECS: u64 = 120;
const SANDBOX_MEMORY_MB: u32 = 512;

#[tauri::command]
pub async fn kiwi_sandbox_open_link(
    state: State<'_, Arc<AppState>>,
    url: String,
) -> CmdResult<SandboxOpenView> {
    gate(state.inner()).await?;
    open_link_impl(state.inner(), url).await
}

#[tauri::command]
pub async fn kiwi_sandbox_open_attachment(
    state: State<'_, Arc<AppState>>,
    folder_id: i64,
    uid: i64,
    filename: String,
) -> CmdResult<SandboxOpenView> {
    gate(state.inner()).await?;
    open_attachment_impl(state.inner(), folder_id, uid, filename).await
}

fn validate_link(raw: &str) -> CmdResult<Url> {
    bounded("url", raw, MAX_LINK_CHARS)?;
    let url = Url::parse(raw).map_err(|_| IpcError::invalid("url is invalid"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(IpcError::invalid(
            "url must be an absolute http:// or https:// URL",
        ));
    }
    Ok(url)
}

fn sanitized_link_target(url: &Url) -> String {
    let mut clean = url.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);
    clean.set_query(None);
    clean.set_fragment(None);
    clean.as_str().chars().take(256).collect()
}

fn reason_codes<T: Serialize>(reasons: &[T]) -> Vec<String> {
    reasons
        .iter()
        .filter_map(|reason| serde_json::to_value(reason).ok())
        .filter_map(|value| value.as_str().map(str::to_string))
        .take(16)
        .collect()
}

fn require_available(provider: &dyn SandboxProvider) -> CmdResult<kiwi_sandbox::SandboxCapabilities> {
    match provider.availability() {
        Availability::Available(capabilities) | Availability::Degraded(capabilities, _) => {
            Ok(capabilities)
        }
        Availability::Unavailable(why) => Err(IpcError::sandbox_unavailable(why)),
    }
}

async fn run_sandbox(
    state: &AppState,
    spec: SandboxSpec,
    target: String,
) -> CmdResult<SandboxOpenView> {
    let capabilities = require_available(state.sandbox.as_ref())?;
    if spec.artifact_path.is_file() {
        let size = std::fs::metadata(&spec.artifact_path)?.len();
        if size > capabilities.max_artifact_bytes {
            return Err(IpcError::invalid(
                "attachment exceeds sandbox capability bound",
            ));
        }
    }
    let mut sandbox: Box<dyn Sandbox> = state.sandbox.create(spec.clone()).await?;
    let analyze = sandbox.analyze().await;
    let teardown = sandbox.teardown().await;
    let mut report: AnalysisReport = analyze?;
    teardown?;
    report.evidence_reasons = spec.evidence_reasons.clone();
    let session_id = state.next_sandbox_session_id();
    let view = SandboxOpenView {
        session_id: session_id.clone(),
        target: target.clone(),
        evidence_reasons: spec.evidence_reasons.clone(),
        report: report.clone(),
    };
    let mut sessions = state.sandbox_sessions.lock().await;
    if sessions.len() >= MAX_SANDBOX_SESSIONS {
        sessions.pop_front();
    }
    sessions.push_back(SandboxSessionRecord {
        session_id,
        target,
        evidence_reasons: spec.evidence_reasons,
        report,
    });
    drop(sessions);
    state.audit.lock().await.record(
        "sandbox-opened",
        &format!(
            "{}; reasons={}",
            view.target,
            view.evidence_reasons.join(",")
        ),
        now_unix(),
    )?;
    Ok(view)
}

pub(crate) async fn open_link_impl(state: &AppState, raw: String) -> CmdResult<SandboxOpenView> {
    let url = validate_link(&raw)?;
    let reasons = link_reasons_for_url(state, &url).await?;
    run_sandbox(
        state,
        SandboxSpec {
            artifact_path: Default::default(),
            link_url: Some(url.to_string()),
            evidence_reasons: reasons,
            timeout_secs: SANDBOX_TIMEOUT_SECS,
            max_memory_mb: SANDBOX_MEMORY_MB,
            allow_egress: true,
        },
        sanitized_link_target(&url),
    )
    .await
}

async fn link_reasons_for_url(state: &AppState, url: &Url) -> CmdResult<Vec<String>> {
    // Prefer the message-level stored evidence when a matching link is found;
    // otherwise conservatively classify the supplied URL itself.
    let index = state.index.lock().await;
    let folders = index
        .folders
        .values()
        .flatten()
        .map(|folder| folder.id)
        .collect::<Vec<_>>();
    drop(index);
    let store = state.store.lock().await;
    let mut message_budget = 512usize;
    for folder_id in folders.into_iter().take(128) {
        let Ok(messages) = store.list_messages(folder_id, 500) else {
            continue;
        };
        for message in messages {
            if message_budget == 0 {
                break;
            }
            message_budget -= 1;
            let Some(path) = store.body_file(folder_id, message.uid).ok().flatten() else {
                continue;
            };
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > 2 * 1024 * 1024 {
                continue;
            }
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let body = String::from_utf8_lossy(&bytes);
            if body.contains(url.as_str()) {
                return Ok(message
                    .link_risk
                    .map(|evidence| reason_codes(&evidence.reasons))
                    .unwrap_or_else(|| vec!["evidence-unavailable".into()]));
            }
        }
    }
    Ok(vec!["unmatched-link".into()])
}

pub(crate) async fn open_attachment_impl(
    state: &AppState,
    folder_id: i64,
    uid: i64,
    filename: String,
) -> CmdResult<SandboxOpenView> {
    bounded("filename", &filename, MAX_FILENAME_CHARS)?;
    if folder_id < 0 || uid < 0 {
        return Err(IpcError::invalid("folderId and uid must be >= 0"));
    }
    require_available(state.sandbox.as_ref())?;
    let (path, _content_type) = {
        let store = state.store.lock().await;
        store.stage_attachment(folder_id, uid as u64, &filename, MAX_SANDBOX_BYTES)?
    };
    let reasons = {
        let store = state.store.lock().await;
        store
            .get_attachment_risk(folder_id, uid as u64)?
            .map(|evidence| reason_codes(&evidence.reasons))
            .unwrap_or_else(|| vec!["evidence-unavailable".into()])
    };
    let result = run_sandbox(
        state,
        SandboxSpec {
            artifact_path: path.clone(),
            link_url: None,
            evidence_reasons: reasons,
            timeout_secs: SANDBOX_TIMEOUT_SECS,
            max_memory_mb: SANDBOX_MEMORY_MB,
            allow_egress: false,
        },
        format!("attachment:f{folder_id}/u{uid}"),
    )
    .await;
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use kiwi_sandbox::SandboxCapabilities;

    struct FakeProvider {
        seen: std::sync::Mutex<Vec<SandboxSpec>>,
    }
    struct FakeSandbox;

    #[async_trait]
    impl SandboxProvider for FakeProvider {
        fn availability(&self) -> Availability {
            Availability::Available(SandboxCapabilities {
                dedicated_kernel: true,
                snapshot_revert: true,
                egress_control: kiwi_sandbox::EgressControl::FilteredPcap,
                monitors: Default::default(),
                max_artifact_bytes: MAX_SANDBOX_BYTES as u64,
            })
        }

        async fn create(
            &self,
            spec: SandboxSpec,
        ) -> kiwi_sandbox::Result<Box<dyn Sandbox>> {
            self.seen.lock().unwrap().push(spec);
            Ok(Box::new(FakeSandbox))
        }
    }

    #[async_trait]
    impl Sandbox for FakeSandbox {
        async fn analyze(&mut self) -> kiwi_sandbox::Result<AnalysisReport> {
            Ok(AnalysisReport {
                exit_code: Some(0),
                ..AnalysisReport::default()
            })
        }

        async fn revert(&mut self) -> kiwi_sandbox::Result<()> {
            Ok(())
        }

        async fn teardown(self: Box<Self>) -> kiwi_sandbox::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn link_validation_allows_hostile_http_but_rejects_other_schemes() {
        assert!(validate_link("http://1.2.3.4/login").is_ok());
        assert!(validate_link("https://evil.example").is_ok());
        for bad in [
            "file:///C:/x",
            "javascript:alert(1)",
            "mailto:a@b",
            "not a url",
        ] {
            assert_eq!(validate_link(bad).unwrap_err().code, "invalid-input");
        }
    }

    #[test]
    fn audit_target_redacts_credentials_query_and_fragment() {
        let url =
            validate_link("https://user:pass@evil.example/login?token=x#frag").unwrap();
        let target = sanitized_link_target(&url);
        assert_eq!(target, "https://evil.example/login");
        assert!(!target.contains("pass"));
        assert!(!target.contains("token"));
    }

    #[tokio::test]
    async fn unavailable_is_typed_and_never_falls_back() {
        let state = AppState::open_test_with_sandbox(
            std::env::temp_dir().join(format!("kiwi-sbx-null-{}", std::process::id())),
            Arc::new(kiwi_sandbox::NullProvider::new("none")),
        )
        .unwrap();
        let err = open_link_impl(&state, "http://evil.example".into())
            .await
            .unwrap_err();
        assert_eq!(err.code, "sandbox-unavailable");
    }

    #[tokio::test]
    async fn fake_provider_receives_reason_handoff_and_audits() {
        let dir = std::env::temp_dir().join(format!("kiwi-sbx-fake-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let provider = Arc::new(FakeProvider {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let state = AppState::open_test_with_sandbox(dir.clone(), provider.clone()).unwrap();
        let view = open_link_impl(&state, "http://evil.example/?secret=x".into())
            .await
            .unwrap();
        assert_eq!(view.evidence_reasons, ["unmatched-link"]);
        assert_eq!(view.report.evidence_reasons, ["unmatched-link"]);
        assert!(!view.target.contains("secret"));
        assert!(state.audit.lock().await.len() >= 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
