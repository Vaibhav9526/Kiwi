//! Security data commands: findings feed, event journal, per-session
//! detail (finding dialog / cert viewer), and the deterministic report.

use std::sync::Arc;

use tauri::State;

use kiwi_forensics::findings::Finding;
use kiwi_forensics::report::{Limitation, ReportBuilder};

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::AppState;
use crate::types::{EventRow, SessionDetailView, SessionView, SignalView};

/// All retained deterministic findings (`kiwi.forensics/1` shape — the
/// finding objects pass through verbatim, evidence included). Filter by
/// `accountId` matches `finding.subject.account_id`.
#[tauri::command]
pub async fn kiwi_security_findings(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
) -> CmdResult<Vec<Finding>> {
    gate(state.inner()).await?;
    security_findings_impl(state.inner(), account_id).await
}

pub(crate) async fn security_findings_impl(
    state: &AppState,
    account_id: Option<String>,
) -> CmdResult<Vec<Finding>> {
    let map = state.findings.lock().await;
    let mut out: Vec<Finding> = map
        .values()
        .filter(|f| {
            account_id.as_ref().is_none_or(|a| {
                f.subject.account_id.as_ref().map(|s| s.as_str()) == Some(a.as_str())
            })
        })
        .cloned()
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.observed_at_unix_ms));
    Ok(out)
}

/// Security-center event journal — one row per observed session,
/// newest first. Severity = worst session signal, summary = the transport
/// fact line the UI surfaces (KIWI-UI-010).
#[tauri::command]
pub async fn kiwi_security_events(
    state: State<'_, Arc<AppState>>,
    limit: Option<u32>,
) -> CmdResult<Vec<EventRow>> {
    gate(state.inner()).await?;
    security_events_impl(state.inner(), limit).await
}

pub(crate) async fn security_events_impl(
    state: &AppState,
    limit: Option<u32>,
) -> CmdResult<Vec<EventRow>> {
    let limit = super::clamp_u32(limit, 100, 1000) as usize;
    let sessions = state.sessions.lock().await;
    let rows = sessions
        .iter()
        .rev()
        .take(limit)
        .map(|r| {
            let s = &r.session;
            let worst = r
                .signals
                .iter()
                .map(|x| x.severity)
                .max()
                .unwrap_or(kiwi_core::trust::SignalSeverity::Info);
            let summary = format!(
                "{} {}:{} {} {}",
                crate::types::protocol(s.protocol).to_uppercase(),
                s.server_host,
                s.server_port,
                crate::types::transport(s.transport),
                s.tls_version
                    .map(|v| crate::types::tls_version(v).to_string())
                    .unwrap_or_default()
            )
            .trim_end()
            .to_string();
            EventRow {
                id: s.session_id.clone(),
                ts_unix: s.established_unix,
                account_id: s.account_id.clone(),
                category: r.label.clone(),
                severity: crate::types::severity(worst).to_string(),
                summary,
                detail_ref: format!("session:{}", s.session_id),
            }
        })
        .collect();
    Ok(rows)
}

/// One session's full detail: the `SecuritySession` record + its signals +
/// its findings (cert viewer KIWI-UI-008, finding dialog KIWI-UI-004).
#[tauri::command]
pub async fn kiwi_session_detail(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> CmdResult<SessionDetailView> {
    gate(state.inner()).await?;
    bounded("sessionId", &session_id, 128)?;
    let sessions = state.inner().sessions.lock().await;
    let record = sessions
        .iter()
        .find(|r| r.session.session_id == session_id)
        .ok_or_else(|| IpcError::not_found("unknown session id"))?;
    Ok(SessionDetailView {
        session: SessionView::from(&record.session),
        signals: record.signals.iter().map(SignalView::from).collect(),
        findings: record.findings.clone(),
        label: record.label.clone(),
    })
}

/// Deterministic security report over the retained findings —
/// `kiwi.forensics/1` shape with score + limitations (KIWI-UI-010 export).
#[tauri::command]
pub async fn kiwi_security_report(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
) -> CmdResult<kiwi_forensics::report::Report> {
    gate(state.inner()).await?;
    let state = state.inner();
    let findings = security_findings_impl(state, account_id.clone()).await?;
    let sessions_observed = {
        let sessions = state.sessions.lock().await;
        sessions
            .iter()
            .filter(|r| {
                account_id
                    .as_ref()
                    .is_none_or(|a| r.session.account_id.as_deref() == Some(a.as_str()))
            })
            .count() as u32
    };
    let scope = account_id
        .as_ref()
        .map(|a| format!("account:{a}"))
        .unwrap_or_else(|| "client".into());
    let report = ReportBuilder::new(&scope, "live")
        .add_session_findings(sessions_observed, findings)
        .limitation(Limitation::new(
            "scope",
            "covers live client observations only; no pcap, logs, or fixture input",
        ))
        .build();
    Ok(report)
}
