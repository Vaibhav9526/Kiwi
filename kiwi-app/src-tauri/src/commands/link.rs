use tauri::State;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::LinkClickVerdict;

const MAX_LINK_CHARS: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkPolicy {
    Allow,
    RequireConfirm,
    RequireSandbox,
    Deny,
}

#[derive(Debug, Clone)]
pub(crate) struct LinkPolicyDecision {
    pub action: LinkPolicy,
    pub reasons: Vec<String>,
}

fn reason_strings<T: serde::Serialize>(reasons: &[T]) -> Vec<String> {
    reasons
        .iter()
        .filter_map(|reason| serde_json::to_value(reason).ok())
        .filter_map(|value| value.as_str().map(str::to_string))
        .take(16)
        .collect()
}

fn decision_for(evidence: kiwi_mail::linkrisk::LinkRiskEvidence) -> LinkPolicyDecision {
    let action = match evidence.risk {
        kiwi_mail::linkrisk::LinkRisk::Clean => LinkPolicy::Allow,
        kiwi_mail::linkrisk::LinkRisk::Noted => LinkPolicy::RequireConfirm,
        kiwi_mail::linkrisk::LinkRisk::Failed => LinkPolicy::RequireSandbox,
    };
    LinkPolicyDecision {
        action,
        reasons: reason_strings(&evidence.reasons),
    }
}

fn deny(reason: &str) -> LinkPolicyDecision {
    LinkPolicyDecision {
        action: LinkPolicy::Deny,
        reasons: vec![reason.into()],
    }
}

/// Fresh exact-URL classification. Stored message evidence is deliberately not
/// consulted here because `kiwi_open_external` has no message coordinates.
pub(crate) fn evaluate_external_sources(
    url: &str,
    source_url: Option<&str>,
) -> CmdResult<LinkPolicyDecision> {
    bounded("url", url, MAX_LINK_CHARS)?;
    let destination = url::Url::parse(url).map_err(|_| IpcError::invalid("url is invalid"))?;
    if !matches!(destination.scheme(), "http" | "https") {
        return Ok(deny("non-http-scheme"));
    }
    let Some(source_url) = source_url else {
        return Ok(LinkPolicyDecision {
            action: LinkPolicy::Allow,
            reasons: Vec::new(),
        });
    };
    bounded("sourceUrl", source_url, MAX_LINK_CHARS)?;
    let source =
        url::Url::parse(source_url).map_err(|_| IpcError::invalid("sourceUrl is invalid"))?;
    if !matches!(source.scheme(), "http" | "https") {
        return Ok(deny("non-http-scheme"));
    }
    let mut evidence = kiwi_mail::linkrisk::inspect_url(url, None);
    evidence.merge(kiwi_mail::linkrisk::inspect_url(source_url, None));
    Ok(decision_for(evidence))
}

async fn evaluate_message_link(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: i64,
    url: &str,
) -> CmdResult<LinkPolicyDecision> {
    bounded("accountId", account_id, 128)?;
    bounded("url", url, MAX_LINK_CHARS)?;
    if folder_id < 0 || uid < 0 {
        return Err(IpcError::invalid("folderId and uid must be >= 0"));
    }
    let parsed = url::Url::parse(url).map_err(|_| IpcError::invalid("url is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Ok(deny("non-http-scheme"));
    }

    let store = state.store.lock().await;
    let folder = store
        .folder_meta(folder_id)?
        .ok_or_else(|| IpcError::not_found("unknown folder"))?;
    if folder.account_id != account_id {
        return Err(IpcError::not_found("folder not on account"));
    }
    if !store.message_exists(folder_id, uid as u64)? {
        return Err(IpcError::not_found("unknown message"));
    }
    let stored = store.get_link_risk(folder_id, uid as u64)?;
    drop(store);

    let fresh = kiwi_mail::linkrisk::inspect_url(url, None);
    let Some(stored) = stored else {
        return Ok(if fresh.risk == kiwi_mail::linkrisk::LinkRisk::Clean {
            LinkPolicyDecision {
                action: LinkPolicy::RequireConfirm,
                reasons: vec!["stored-evidence-unavailable".into()],
            }
        } else {
            decision_for(fresh)
        });
    };
    let mut evidence = fresh;
    evidence.merge(stored);
    Ok(decision_for(evidence))
}

#[tauri::command]
pub async fn kiwi_link_click(
    state: State<'_, std::sync::Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    url: String,
) -> CmdResult<LinkClickVerdict> {
    gate(state.inner()).await?;
    link_click_impl(state.inner(), &account_id, folder_id, uid, &url).await
}

pub(crate) async fn link_click_impl(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: i64,
    url: &str,
) -> CmdResult<LinkClickVerdict> {
    let decision = evaluate_message_link(state, account_id, folder_id, uid, url).await?;
    let action = match decision.action {
        LinkPolicy::Allow => "allow",
        LinkPolicy::RequireConfirm => "requireConfirm",
        LinkPolicy::RequireSandbox => "requireSandbox",
        LinkPolicy::Deny => "deny",
    };
    state.audit.lock().await.record(
        "link-clicked",
        &format!(
            "{account_id}/f{folder_id}/u{uid}; verdict={action}; reasons={}",
            decision.reasons.join(",")
        ),
        now_unix(),
    )?;
    Ok(LinkClickVerdict {
        action: action.into(),
        reasons: decision.reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> kiwi_mail::account::MailAccount {
        use kiwi_mail::account::{
            AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
        };
        use kiwi_mail::transport::SocketSecurity;
        MailAccount {
            account_id: "a".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Pop3,
                server: ServerConfig {
                    host: "x.test".into(),
                    port: 995,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
        }
    }

    async fn state_with_message(tag: &str) -> (std::sync::Arc<AppState>, i64) {
        use kiwi_mail::store::NewMessageMeta;
        let dir = std::env::temp_dir().join(format!("kiwi-link-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = std::sync::Arc::new(AppState::open_test(dir.clone()).unwrap());
        let store = state.store.lock().await;
        store.upsert_account(&test_account()).unwrap();
        let folder_id = store.ensure_folder("a", "INBOX").unwrap();
        store
            .upsert_message(
                folder_id,
                &NewMessageMeta {
                    uid: 7,
                    message_id: None,
                    subject: None,
                    from_addr: None,
                    to_addrs: None,
                    date_unix: None,
                    size: None,
                    flags: vec![],
                    has_attachments: false,
                    snippet: None,
                    category: Default::default(),
                    unsub_http: None,
                    unsub_mailto: None,
                    unsub_oneclick: false,
                },
                0,
            )
            .unwrap();
        drop(store);
        (state, folder_id)
    }

    #[tokio::test]
    async fn stored_and_fresh_risk_use_failure_first_precedence() {
        use kiwi_mail::linkrisk::{LinkRisk, LinkRiskEvidence, LinkRiskReason};
        let (state, folder_id) = state_with_message("precedence").await;
        state
            .store
            .lock()
            .await
            .set_link_risk(
                folder_id,
                7,
                &LinkRiskEvidence {
                    risk: LinkRisk::Clean,
                    reasons: vec![],
                },
            )
            .unwrap();
        let allowed = link_click_impl(&state, "a", folder_id, 7, "https://safe.example/path")
            .await
            .unwrap();
        assert_eq!(allowed.action, "allow");
        assert!(allowed.reasons.is_empty());

        state
            .store
            .lock()
            .await
            .set_link_risk(
                folder_id,
                7,
                &LinkRiskEvidence {
                    risk: LinkRisk::Noted,
                    reasons: vec![LinkRiskReason::KnownShortener],
                },
            )
            .unwrap();

        let clean = link_click_impl(&state, "a", folder_id, 7, "https://safe.example/path")
            .await
            .unwrap();
        assert_eq!(clean.action, "requireConfirm");
        assert_eq!(clean.reasons, ["knownShortener"]);

        let failed = link_click_impl(&state, "a", folder_id, 7, "https://1.2.3.4/login")
            .await
            .unwrap();
        assert_eq!(failed.action, "requireSandbox");
        assert!(failed.reasons.contains(&"ipLiteralHost".into()));
    }

    #[tokio::test]
    async fn schemes_ownership_and_missing_evidence_fail_closed() {
        let (state, folder_id) = state_with_message("guards").await;
        let denied = link_click_impl(&state, "a", folder_id, 7, "javascript:alert(1)")
            .await
            .unwrap();
        assert_eq!(denied.action, "deny");
        assert_eq!(denied.reasons, ["non-http-scheme"]);
        assert_eq!(
            link_click_impl(&state, "other", folder_id, 7, "https://safe.example")
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        let unknown = link_click_impl(&state, "a", folder_id, 99, "https://safe.example")
            .await
            .unwrap_err();
        assert_eq!(unknown.code, "not-found");
        let missing = link_click_impl(&state, "a", folder_id, 7, "https://safe.example")
            .await
            .unwrap();
        assert_eq!(missing.action, "requireConfirm");
        assert_eq!(missing.reasons, ["stored-evidence-unavailable"]);
    }

    #[tokio::test]
    async fn external_gate_defaults_allow_but_refuses_message_risk() {
        assert_eq!(
            evaluate_external_sources("https://oauth.example", None)
                .unwrap()
                .action,
            LinkPolicy::Allow
        );
        let noted =
            evaluate_external_sources("https://safe.example", Some("http://safe.example")).unwrap();
        assert_eq!(noted.action, LinkPolicy::RequireConfirm);
        let failed =
            evaluate_external_sources("https://safe.example", Some("https://1.2.3.4/login"))
                .unwrap();
        assert_eq!(failed.action, LinkPolicy::RequireSandbox);
        let denied =
            evaluate_external_sources("https://safe.example", Some("file:///C:/x")).unwrap();
        assert_eq!(denied.action, LinkPolicy::Deny);
    }

    #[tokio::test]
    async fn click_is_audited_with_verdict_and_reasons() {
        let (state, folder_id) = state_with_message("audit").await;
        let verdict = link_click_impl(&state, "a", folder_id, 7, "http://short.example")
            .await
            .unwrap();
        assert_eq!(verdict.action, "requireConfirm");
        let audit = std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("link-clicked"));
        assert!(audit.contains("verdict=requireConfirm"));
    }
}
