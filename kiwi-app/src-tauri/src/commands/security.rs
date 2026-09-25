//! Security data commands: findings feed, event journal, per-session
//! detail (finding dialog / cert viewer), and the deterministic report.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::State;

use kiwi_forensics::findings::Finding;
use kiwi_forensics::report::{Limitation, ReportBuilder};

use super::{bounded, gate};
use crate::audit::AuditEventView;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
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

/// App audit trail (T-324): real rows from the hash-chained `audit.jsonl`
/// store, newest first. The audit log is device-owner sensitive, so this
/// reader is lock-gated like every other §8 command.
#[tauri::command]
pub async fn kiwi_audit_events(
    state: State<'_, Arc<AppState>>,
    before_unix: Option<i64>,
    limit: Option<u32>,
) -> CmdResult<Vec<AuditEventView>> {
    gate(state.inner()).await?;
    audit_events_impl(state.inner(), before_unix, limit).await
}

pub(crate) async fn audit_events_impl(
    state: &AppState,
    before_unix: Option<i64>,
    limit: Option<u32>,
) -> CmdResult<Vec<AuditEventView>> {
    if before_unix.is_some_and(|value| value < 0) {
        return Err(IpcError::invalid("beforeUnix must be >= 0"));
    }
    let limit = super::clamp_u32(limit, 100, 500) as usize;
    let audit = state.audit.lock().await;
    audit.read_recent(before_unix, limit as u32)
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

/// Serialized artifact ceiling. The report builder's own bounds keep real
/// reports far below this; it exists so a pathological report cannot produce
/// an unbounded write.
const MAX_REPORT_EXPORT_BYTES: usize = 32 * 1024 * 1024;

/// `kiwi_forensics_export { sessionId, destPath }` → `ForensicsExportView`.
///
/// Save the deterministic `kiwi_forensics` report for one retained session to
/// a caller-chosen path, wrapped in a **self-verifying integrity envelope**
/// (T-320): the artifact carries the SHA-256 of its own canonical report
/// bytes, plus the versions those bytes were produced under, so a reader can
/// detect tampering with no external trust store — re-serialize `report`, hash,
/// compare (`kiwi_forensics::report::ExportEnvelope::verify_bytes`).
///
/// Deliberate semantics, matching the mbox-export sibling (T-316):
/// - **Atomic.** Built beside the destination and renamed over it, so a crash
///   never leaves a truncated artifact at the chosen path.
/// - **Bounded.** `MAX_REPORT_EXPORT_BYTES` caps the serialized artifact
///   (report-builder inputs are already bounded; this guards the file write);
///   destination must be a writable file inside an existing directory — a
///   directory, missing parent, or the app's own data dir is `invalid-input`
///   rather than an io-detail leak.
/// - **Audited as ids + counts only.** Never the path, never a subject, never
///   a finding-id list.
/// - `sessionId` must name a retained session; an unknown id is `not-found`,
///   never an empty report that would read as a clean bill of health.
#[tauri::command]
pub async fn kiwi_forensics_export(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    dest_path: String,
) -> CmdResult<crate::types::ForensicsExportView> {
    gate(state.inner()).await?;
    forensics_export_impl(state.inner(), &session_id, &dest_path).await
}

pub(crate) async fn forensics_export_impl(
    state: &AppState,
    session_id: &str,
    dest_path: &str,
) -> CmdResult<crate::types::ForensicsExportView> {
    bounded("sessionId", session_id, 128)?;
    bounded("destPath", dest_path, 4096)?;
    if dest_path.trim().is_empty() {
        return Err(IpcError::invalid("destPath is empty"));
    }

    // The session must be real. A missing id is `not-found`, not an empty
    // report: an empty artifact would read as "nothing was found".
    let exists = {
        let sessions = state.sessions.lock().await;
        sessions.iter().any(|r| r.session.session_id == session_id)
    };
    if !exists {
        return Err(IpcError::not_found("unknown session id"));
    }

    // Scope the report to this one session's findings, using the same builder
    // the live report uses — so the exported bytes are a real `Report`.
    let findings: Vec<Finding> = {
        let map = state.findings.lock().await;
        map.values()
            .filter(|f| f.subject.session_id.as_str() == session_id)
            .cloned()
            .collect()
    };
    let report = ReportBuilder::new(&format!("session:{session_id}"), "live-session-export")
        .add_session_findings(1, findings.clone())
        .limitation(Limitation::new(
            "scope",
            "covers one retained client session and its findings only; no pcap, logs, or fixture input",
        ))
        .build();

    let generated_at_unix = now_unix();
    let envelope = kiwi_forensics::report::ExportEnvelope::seal(report, generated_at_unix);
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| IpcError::new("internal", format!("report serialize: {e}")))?;
    if bytes.len() > MAX_REPORT_EXPORT_BYTES {
        return Err(IpcError::invalid("report export exceeds 32 MiB bound"));
    }

    write_export_atomically(state, dest_path, &bytes)?;

    let size = bytes.len() as u64;
    state.audit.lock().await.record(
        "forensics-exported",
        &format!(
            "session {session_id}: findings {} bytes {size} sha256 {}",
            findings.len(),
            envelope.sha256,
        ),
        now_unix(),
    )?;
    Ok(crate::types::ForensicsExportView {
        path: dest_path.to_string(),
        bytes: size,
        sha256: envelope.sha256,
        report_contract_version: envelope.report_contract_version,
        findings: findings.len(),
        generated_at_unix,
    })
}

/// Destination validation + temp→rename. Split out so the path rules read as
/// one block: directory, existing parent, a real file name, and never inside
/// the app's own data dir (mail store, audit log, bodies).
fn write_export_atomically(state: &AppState, dest_path: &str, bytes: &[u8]) -> CmdResult<()> {
    let dest = Path::new(dest_path);
    if dest.is_dir() {
        return Err(IpcError::invalid("destPath is a directory"));
    }
    match dest.parent() {
        Some(p) if p.as_os_str().is_empty() => {}
        Some(p) if p.is_dir() => {}
        Some(_) => return Err(IpcError::not_found("destination directory not found")),
        None => return Err(IpcError::invalid("destPath has no parent directory")),
    }
    if dest.file_name().is_none() {
        return Err(IpcError::invalid("destPath names no file"));
    }
    let canon_data = state
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| state.data_dir.clone());
    // Resolve the *parent* (the file need not exist yet) and refuse anything
    // under the app data dir, so an export can never overwrite mail.db, the
    // audit log, or a stored body.
    let parent = dest.parent().unwrap_or(dest);
    let resolved_parent = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    if resolved_parent.starts_with(&canon_data) {
        return Err(IpcError::invalid(
            "destPath inside the app data dir is refused",
        ));
    }

    let tmp = PathBuf::from(format!("{dest_path}.kiwi-part"));
    if let Err(e) = std::fs::write(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(IpcError::invalid(format!("write: {e}")));
    }
    // Temp → destination. On Windows rename refuses an existing target; the
    // user chose this path, so a prior export is replaced — remove and retry
    // once (the only portable overwrite path).
    if let Err(e) = std::fs::rename(&tmp, dest) {
        if dest.exists() {
            let _ = std::fs::remove_file(dest);
            if let Err(e2) = std::fs::rename(&tmp, dest) {
                let _ = std::fs::remove_file(&tmp);
                return Err(IpcError::invalid(format!("rename: {e2}")));
            }
        } else {
            let _ = std::fs::remove_file(&tmp);
            return Err(IpcError::invalid(format!("rename: {e}")));
        }
    }
    Ok(())
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

    // -- T-324 audit read IPC ---------------------------------------------

    #[test]
    fn audit_read_is_empty_bounded_and_keyset_paged() {
        let state = test_state("audit-read");
        block_on(async {
            assert!(
                audit_events_impl(&state, None, None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let mut log = state.audit.lock().await;
            for i in 0..600 {
                log.record("test-event", &format!("row={i}"), 1_000 + i)
                    .unwrap();
            }
        });
        let rows = block_on(audit_events_impl(&state, None, Some(9_000))).unwrap();
        assert_eq!(rows.len(), 500, "renderer limit clamps to 500");
        assert_eq!(rows[0].at_unix, 1_599, "newest real row first");
        assert_eq!(rows[0].detail_json.as_deref(), Some("row=599"));
        assert!(rows[0].actor.is_none(), "no invented actor");
        let older = block_on(audit_events_impl(&state, Some(1_100), Some(500))).unwrap();
        assert_eq!(older.len(), 100);
        assert_eq!(older.last().unwrap().at_unix, 1_000);
        let err = block_on(audit_events_impl(&state, Some(-1), None)).unwrap_err();
        assert_eq!(err.code, "invalid-input");
    }

    #[test]
    fn audit_read_respects_lock_gate() {
        let state = test_state("audit-lock");
        block_on(async {
            state
                .audit
                .lock()
                .await
                .record("sensitive", "real", 10)
                .unwrap();
            state.trust.lock().await.force_lock();
            assert!(
                super::super::gate(&state)
                    .await
                    .is_err_and(|e| e.code == "locked")
            );
        });
    }

    // -- T-320 forensic report export -------------------------------------

    fn export_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-fx-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seeded(tag: &str) -> (AppState, PathBuf) {
        let state = test_state(tag);
        let dir = export_dir(tag);
        let f = finding("KIWI-TLS-001", "sess-x");
        block_on(async {
            state
                .findings
                .lock()
                .await
                .insert(f.finding_id(), f.clone());
            state
                .sessions
                .lock()
                .await
                .push_back(session_record("sess-x", vec![f]));
        });
        (state, dir)
    }

    /// Verify-by-construction: the file the command writes round-trips through
    /// the crate's own reader and verifies with no external trust store.
    #[test]
    fn export_writes_a_self_verifying_artifact() {
        use kiwi_forensics::report::{ExportEnvelope, ExportVerification};
        let (state, dir) = seeded("ok");
        let dest = dir.join("report.json");
        let view = block_on(forensics_export_impl(
            &state,
            "sess-x",
            dest.to_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(view.findings, 1);
        assert_eq!(view.sha256.len(), 64);
        assert!(view.bytes > 0);

        // No temp file left behind.
        assert!(!PathBuf::from(format!("{}.kiwi-part", dest.display())).exists());

        let bytes = std::fs::read(&dest).unwrap();
        match ExportEnvelope::verify_bytes(&bytes) {
            ExportVerification::Valid(env) => {
                // The payload is a real Report with this session's finding.
                assert_eq!(env.report.findings.len(), 1);
                assert_eq!(env.report.scope, "session:sess-x");
                assert_eq!(env.report.generated_from, "live-session-export");
                assert_eq!(env.sha256, view.sha256);
                // And the report round-trips through the existing parser.
                let back = kiwi_forensics::report::Report::from_json(&env.report.to_json())
                    .expect("embedded report parses");
                assert_eq!(back, env.report);
            }
            other => panic!("exported artifact must self-verify, got {other:?}"),
        }
        // Audit recorded ids + counts, never the path.
        let audited = std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap();
        assert!(audited.contains("forensics-exported"));
        assert!(audited.contains("sess-x"));
        assert!(!audited.contains(&dir.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_refuses_unknown_session_and_bad_destinations() {
        let (state, dir) = seeded("bad");

        // Unknown session is not-found — never a clean-looking empty report.
        let err = block_on(forensics_export_impl(
            &state,
            "sess-nope",
            dir.join("r.json").to_str().unwrap(),
        ))
        .unwrap_err();
        assert_eq!(err.code, "not-found");

        // A directory.
        assert_eq!(
            block_on(forensics_export_impl(
                &state,
                "sess-x",
                &dir.display().to_string()
            ))
            .unwrap_err()
            .code,
            "invalid-input"
        );
        // Missing parent directory.
        assert_eq!(
            block_on(forensics_export_impl(
                &state,
                "sess-x",
                dir.join("no-such-dir/r.json").to_str().unwrap()
            ))
            .unwrap_err()
            .code,
            "not-found"
        );
        // Empty path.
        assert_eq!(
            block_on(forensics_export_impl(&state, "sess-x", "  "))
                .unwrap_err()
                .code,
            "invalid-input"
        );
        // Inside the app data dir — must never overwrite mail.db/audit log.
        let inside = state.data_dir.join("pwned.json");
        assert_eq!(
            block_on(forensics_export_impl(
                &state,
                "sess-x",
                inside.to_str().unwrap()
            ))
            .unwrap_err()
            .code,
            "invalid-input"
        );
        assert!(!inside.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_overwrites_a_previous_artifact_at_the_same_path() {
        let (state, dir) = seeded("over");
        let dest = dir.join("r.json");
        std::fs::write(&dest, b"stale").unwrap();
        let v = block_on(forensics_export_impl(
            &state,
            "sess-x",
            dest.to_str().unwrap(),
        ))
        .unwrap();
        assert!(v.bytes > 0);
        let bytes = std::fs::read(&dest).unwrap();
        assert!(kiwi_forensics::report::ExportEnvelope::verify_bytes(&bytes).verify_ok());
        assert_ne!(bytes, b"stale");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
