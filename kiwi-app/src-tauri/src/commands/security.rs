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

/// `list_findings` — contract forensics.md §11. Full `Finding` objects
/// verbatim (evidence included, never projected). `accountId` +
/// `severity` filters are ANDed; an unrecognized severity string is
/// `invalid-input` (a typo must not look like a clean bill of health).
/// Sort is binding and total: severity desc, observed_at desc, rule_id
/// asc, subject_key asc. `limit` default 100, max 1000.
#[tauri::command]
pub async fn kiwi_security_findings(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
    severity: Option<String>,
    limit: Option<u32>,
) -> CmdResult<Vec<Finding>> {
    gate(state.inner()).await?;
    security_findings_impl(state.inner(), account_id, severity, limit).await
}

fn parse_severity(s: &str) -> CmdResult<kiwi_forensics::findings::Severity> {
    use kiwi_forensics::findings::Severity::*;
    match s {
        "info" => Ok(Info),
        "low" => Ok(Low),
        "medium" => Ok(Medium),
        "high" => Ok(High),
        "critical" => Ok(Critical),
        other => Err(IpcError::invalid(format!("unknown severity {other:?}"))),
    }
}

pub(crate) async fn security_findings_impl(
    state: &AppState,
    account_id: Option<String>,
    severity: Option<String>,
    limit: Option<u32>,
) -> CmdResult<Vec<Finding>> {
    if let Some(a) = &account_id {
        bounded("accountId", a, 256)?;
    }
    let severity = severity.as_deref().map(parse_severity).transpose()?;
    let limit = super::clamp_u32(limit, 100, 1000) as usize;
    let map = state.findings.lock().await;
    let mut out: Vec<Finding> = map
        .values()
        .filter(|f| {
            account_id.as_ref().is_none_or(|a| {
                f.subject.account_id.as_ref().map(|s| s.as_str()) == Some(a.as_str())
            }) && severity.is_none_or(|s| f.severity == s)
        })
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        b.severity
            .weight_points()
            .cmp(&a.severity.weight_points())
            .then(b.observed_at_unix_ms.cmp(&a.observed_at_unix_ms))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.subject.key_text().cmp(&b.subject.key_text()))
    });
    out.truncate(limit);
    Ok(out)
}

/// Security-center event journal — one row per observed session,
/// newest first. Severity = worst session signal, summary = the transport
/// fact line the UI surfaces (KIWI-UI-010). `accountId` filters to that
/// account's sessions (forensics.md §11).
#[tauri::command]
pub async fn kiwi_security_events(
    state: State<'_, Arc<AppState>>,
    limit: Option<u32>,
    account_id: Option<String>,
) -> CmdResult<Vec<EventRow>> {
    gate(state.inner()).await?;
    security_events_impl(state.inner(), limit, account_id).await
}

pub(crate) async fn security_events_impl(
    state: &AppState,
    limit: Option<u32>,
    account_id: Option<String>,
) -> CmdResult<Vec<EventRow>> {
    if let Some(a) = &account_id {
        bounded("accountId", a, 256)?;
    }
    let limit = super::clamp_u32(limit, 100, 1000) as usize;
    let sessions = state.sessions.lock().await;
    let rows = sessions
        .iter()
        .rev()
        .filter(|r| {
            account_id
                .as_ref()
                .is_none_or(|a| r.session.account_id.as_deref() == Some(a.as_str()))
        })
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

/// One finding's full detail: the complete `kiwi.forensics/1` object
/// (evidence + impact + remediation) plus the session it was observed in —
/// the finding dialog's data source (KIWI-UI-004, T-164). `session` is
/// `None` once the bounded session ring has evicted the source session;
/// findings deliberately outlive sessions.
#[tauri::command]
pub async fn kiwi_finding_detail(
    state: State<'_, Arc<AppState>>,
    finding_id: String,
) -> CmdResult<crate::types::FindingDetailView> {
    gate(state.inner()).await?;
    bounded("findingId", &finding_id, 512)?;
    let state = state.inner();
    let finding = {
        let map = state.findings.lock().await;
        map.get(&finding_id)
            .cloned()
            .ok_or_else(|| IpcError::not_found("unknown finding id"))?
    };
    let sid = finding.subject.session_id.as_str().to_string();
    let sessions = state.sessions.lock().await;
    let record = sessions.iter().find(|r| r.session.session_id == sid);
    Ok(crate::types::FindingDetailView {
        session: record.map(|r| SessionView::from(&r.session)),
        signals: record
            .map(|r| r.signals.iter().map(SignalView::from).collect())
            .unwrap_or_default(),
        sibling_finding_ids: record
            .map(|r| {
                r.findings
                    .iter()
                    .map(|f| f.finding_id())
                    .filter(|id| id != &finding_id)
                    .collect()
            })
            .unwrap_or_default(),
        finding,
    })
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

/// Evidence marker (forensics §8): protected transport, no auth exchange
/// observed. `SecuritySession` carries no resumption or unknown-transport
/// state, so `kex-unobserved`/`transport-unknown` cannot be substantiated
/// on the live path and are not emitted here.
fn protected_without_auth(session: &kiwi_core::session::SecuritySession) -> bool {
    session.transport != kiwi_core::session::TransportSecurity::Plaintext
        && session.auth_mechanism == kiwi_core::session::AuthMechanism::None
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
    // Reports aggregate the full retained set — no severity/limit filter.
    let findings: Vec<Finding> = {
        let map = state.findings.lock().await;
        map.values()
            .filter(|f| {
                account_id.as_ref().is_none_or(|a| {
                    f.subject.account_id.as_ref().map(|s| s.as_str()) == Some(a.as_str())
                })
            })
            .cloned()
            .collect()
    };
    let (sessions_observed, auth_unobserved) = {
        let sessions = state.sessions.lock().await;
        let filtered = sessions.iter().filter(|r| {
            account_id
                .as_ref()
                .is_none_or(|a| r.session.account_id.as_deref() == Some(a.as_str()))
        });
        let mut observed = 0u32;
        let mut auth_unobserved = 0u32;
        for r in filtered {
            observed += 1;
            if protected_without_auth(&r.session) {
                auth_unobserved += 1;
            }
        }
        (observed, auth_unobserved)
    };
    let scope = account_id
        .as_ref()
        .map(|a| format!("account:{a}"))
        .unwrap_or_else(|| "client".into());
    let sandbox_sessions = state.sandbox_sessions.lock().await;
    let sandbox_observations = sandbox_sessions.len() as u32;
    let sandbox_reason_codes = sandbox_sessions
        .iter()
        .flat_map(|session| {
            std::iter::once(session.session_id.clone())
                .chain(std::iter::once(session.target.clone()))
                .chain(session.evidence_reasons.iter().cloned())
        })
        .take(256)
        .collect::<Vec<_>>();
    let sandbox_report = sandbox_sessions
        .back()
        .map(|session| {
            format!(
                "exit={:?},timed_out={},incomplete={}",
                session.report.exit_code, session.report.timed_out, session.report.incomplete
            )
        })
        .unwrap_or_else(|| "none".into());
    drop(sandbox_sessions);
    let mut builder = ReportBuilder::new(&scope, "live")
        .add_session_findings(sessions_observed, findings)
        .limitation(Limitation::new(
            "scope",
            "covers live client and sandbox-open observations only; no pcap, logs, or fixture input",
        ));
    if auth_unobserved > 0 {
        builder = builder.limitation(Limitation::new(
            kiwi_forensics::report::limitation_codes::AUTH_UNOBSERVED,
            &format!("{auth_unobserved} protected session(s) showed no authentication exchange."),
        ));
    }
    if !sandbox_reason_codes.is_empty() {
        builder = builder.limitation(Limitation::new(
            "sandbox-open-reasons",
            &format!(
                "{} sandbox sessions; context={}; latest={}",
                sandbox_observations,
                sandbox_reason_codes.join(","),
                sandbox_report
            ),
        ));
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_forensics::findings::{
        Confidence, Finding, FindingCategory, FindingSubject, Remediation, Severity,
    };
    use kiwi_forensics::model::{Protocol as FProto, SafeText, SessionId};

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-sec-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    fn finding(rule: &str, session_id: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            rule_version: 1,
            category: FindingCategory::Transport,
            severity: Severity::High,
            confidence: Confidence::Firm,
            title: "t".into(),
            description: "d".into(),
            impact: "i".into(),
            remediation: Remediation::new("fix", &[]),
            evidence: vec![],
            subject: FindingSubject {
                session_id: SessionId::from_label(session_id),
                protocol: FProto::Imap,
                server_host: SafeText::new("imap.x.test"),
                server_port: 993,
                account_id: Some(SafeText::new("a1")),
                discriminator: None,
            },
            observed_at_unix_ms: 1_700_000_000_000,
            sources: vec![],
            references: vec![],
        }
    }

    fn session_record(session_id: &str, findings: Vec<Finding>) -> crate::state::SessionRecord {
        use kiwi_core::session::*;
        crate::state::SessionRecord {
            session: SecuritySession {
                schema_version: SCHEMA_VERSION,
                session_id: session_id.into(),
                account_id: Some("a1".into()),
                device_id: None,
                protocol: Protocol::Imap,
                server_host: "imap.x.test".into(),
                server_port: 993,
                transport: TransportSecurity::Tls,
                tls_version: Some(TlsVersion::Tls1_3),
                cipher_suite: None,
                key_exchange_group: None,
                cert_chain: None,
                starttls_offered: None,
                starttls_used: false,
                auth_mechanism: AuthMechanism::Login,
                auth_succeeded: Some(true),
                established_unix: 1_700_000_000,
                source: SessionSource::TestFixture,
            },
            signals: vec![],
            findings,
            label: "test".into(),
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = std::pin::pin!(f);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn finding_detail_joins_session_and_siblings() {
        let state = test_state("detail");
        let f1 = finding("KIWI-TLS-002", "sess-1");
        let f2 = finding("KIWI-AUTH-001", "sess-1");
        let fid1 = f1.finding_id();
        block_on(async {
            state.findings.lock().await.insert(fid1.clone(), f1.clone());
            state
                .findings
                .lock()
                .await
                .insert(f2.finding_id(), f2.clone());
            state
                .sessions
                .lock()
                .await
                .push_back(session_record("sess-1", vec![f1.clone(), f2]));
        });

        // The command handler itself is tauri-wrapped; exercise the logic
        // through the same lookups it performs.
        let detail = block_on(async {
            let map = state.findings.lock().await;
            let f = map.get(&fid1).cloned().unwrap();
            let sid = f.subject.session_id.as_str().to_string();
            let sessions = state.sessions.lock().await;
            let rec = sessions.iter().find(|r| r.session.session_id == sid);
            (f, rec.cloned())
        });
        assert_eq!(detail.0.rule_id, "KIWI-TLS-002");
        let rec = detail.1.expect("session must join on session_id");
        assert_eq!(rec.session.server_host, "imap.x.test");
        let siblings: Vec<_> = rec
            .findings
            .iter()
            .map(|f| f.finding_id())
            .filter(|id| id != &fid1)
            .collect();
        assert_eq!(siblings, vec!["KIWI-AUTH-001|imap:imap.x.test:993"]);
    }

    #[test]
    fn protected_without_auth_classifies_auth_unobserved() {
        // FOR-10: the live report's auth-unobserved marker fires only on a
        // protected transport with no observed authentication exchange.
        let mut rec = session_record("sess-p", vec![]);
        rec.session.auth_mechanism = kiwi_core::session::AuthMechanism::None;
        rec.session.auth_succeeded = None;
        assert!(protected_without_auth(&rec.session));

        // Plaintext transport is not "protected" — no marker.
        rec.session.transport = kiwi_core::session::TransportSecurity::Plaintext;
        assert!(!protected_without_auth(&rec.session));

        // Protected transport with a real auth mechanism — no marker.
        rec.session.transport = kiwi_core::session::TransportSecurity::Tls;
        rec.session.auth_mechanism = kiwi_core::session::AuthMechanism::Login;
        assert!(!protected_without_auth(&rec.session));
    }

    #[test]
    fn security_findings_filters_by_account() {
        let state = test_state("filter");
        let mut other = finding("KIWI-TLS-001", "sess-2");
        other.subject.account_id = Some(SafeText::new("a2"));
        block_on(async {
            let mut map = state.findings.lock().await;
            map.insert(
                finding("KIWI-TLS-002", "s").finding_id(),
                finding("KIWI-TLS-002", "s"),
            );
            map.insert(other.finding_id(), other);
        });
        let a1 = block_on(security_findings_impl(
            &state,
            Some("a1".into()),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(a1.len(), 1);
        assert_eq!(a1[0].rule_id, "KIWI-TLS-002");
        let all = block_on(security_findings_impl(&state, None, None, None)).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn findings_severity_filter_and_total_sort() {
        let state = test_state("sort");
        let mut low = finding("KIWI-AUTH-003", "s1");
        low.severity = Severity::Low;
        let mut crit = finding("KIWI-AUTH-001", "s2");
        crit.severity = Severity::Critical;
        let mut high = finding("KIWI-TLS-001", "s3");
        high.severity = Severity::High;
        high.observed_at_unix_ms = 1; // older than crit — severity still wins
        block_on(async {
            let mut map = state.findings.lock().await;
            for f in [low, crit, high] {
                map.insert(f.finding_id(), f);
            }
        });
        let out = block_on(security_findings_impl(&state, None, None, None)).unwrap();
        assert_eq!(
            out.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            ["KIWI-AUTH-001", "KIWI-TLS-001", "KIWI-AUTH-003"]
        );
        // Severity filter ANDs; unknown severity is invalid-input.
        let highs = block_on(security_findings_impl(
            &state,
            None,
            Some("high".into()),
            None,
        ))
        .unwrap();
        assert_eq!(highs.len(), 1);
        assert_eq!(highs[0].rule_id, "KIWI-TLS-001");
        assert!(
            block_on(security_findings_impl(
                &state,
                None,
                Some("bogus".into()),
                None
            ))
            .is_err()
        );
        // Limit applies after the binding sort.
        let top = block_on(security_findings_impl(&state, None, None, Some(1))).unwrap();
        assert_eq!(top[0].rule_id, "KIWI-AUTH-001");
    }
}
