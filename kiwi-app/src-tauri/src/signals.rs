//! T-121 — endpoint signal collector (Phase 3 foundation).
//!
//! Bounded, measurable indicators only (SECURITY.md §1.3: "detection of
//! measurable indicators/anomalies and trust reduction, not perfect
//! compromise detection"). Windows-focused. Explicit non-goals: no process
//! scanning, no kernel/driver checks, no network telemetry, no behavioral
//! EDR claims.
//!
//! Current indicators:
//! - **Remote session**: `SESSIONNAME` != `Console` (RDP/ICA/etc. session
//!   names are `RDP-Tcp#n`/`ICA-CGP#n`/…), or SSH context env vars present
//!   (`SSH_CLIENT`, `SSH_CONNECTION`, `SSH_TTY`). Both are observable facts;
//!   the signal says "this session is remote or non-console", nothing more.
//! - **Process integrity (TOFU baseline)**: SHA-256 + path of the running
//!   executable vs a baseline recorded on first run. Mismatch →
//!   `endpoint-integrity-failure`. This detects post-baseline binary
//!   tamper/replacement — it is not a supply-chain guarantee.
//!
//! Each observation is persisted to `endpoint-evidence.jsonl` so every
//! `TrustSignal` carries a real `evidence_ref` (contract §1: never a
//! free-text-only conclusion). Collection is a pure function over
//! [`ProbeInput`] — production gathers the probe, tests inject it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use kiwi_core::trust::{SignalKind, SignalSeverity, TrustSignal};

use crate::error::CmdResult;

/// Everything the collector measures — supplied by the caller so the
/// decision logic stays pure and unit-testable.
#[derive(Debug, Clone)]
pub struct ProbeInput {
    /// Windows `%SESSIONNAME%` — `Console` = local interactive session.
    pub session_name: Option<String>,
    /// Names of SSH-context env vars present (values never collected —
    /// they can carry remote addresses).
    pub ssh_envs_present: Vec<String>,
    /// Path of the running executable.
    pub exe_path: PathBuf,
    /// SHA-256 (hex) of the executable image, when it could be read.
    pub exe_sha256: Option<String>,
    pub now_unix: i64,
}

/// First-run executable baseline, persisted to `endpoint-baseline.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExeBaseline {
    pub exe_path: PathBuf,
    pub sha256: String,
    pub recorded_unix: i64,
}

/// One measured indicator, pre-signal. `detail` is display-safe text.
/// camelCase wire names like every other IPC view (ipc.md §10).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointObservation {
    pub id: String,
    pub kind: SignalKindView,
    pub severity: &'static str,
    pub penalty: u32,
    pub detail: String,
    /// Pointer at the JSONL evidence record (`endpoint:<id>`).
    pub evidence_ref: String,
}

/// Stable wire names for the kinds this collector can emit
/// (kiwi-core `SignalKind` has no serde — ipc.md owns the spelling).
/// Device-status kinds are produced via `observe::device_signal`, not here.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalKindView {
    RemoteSessionIndicator,
    EndpointIntegrityFailure,
}

impl EndpointObservation {
    pub fn as_signal(&self) -> (SignalKind, TrustSignal) {
        let kind = match self.kind {
            SignalKindView::RemoteSessionIndicator => SignalKind::RemoteSessionIndicator,
            SignalKindView::EndpointIntegrityFailure => SignalKind::EndpointIntegrityFailure,
        };
        (
            kind,
            TrustSignal {
                kind,
                severity: match self.severity {
                    "info" => SignalSeverity::Info,
                    "low" => SignalSeverity::Low,
                    "medium" => SignalSeverity::Medium,
                    "high" => SignalSeverity::High,
                    _ => SignalSeverity::Critical,
                },
                penalty: self.penalty,
                evidence_ref: self.evidence_ref.clone(),
            },
        )
    }
}

/// Gather the real probe for this process (production path).
pub fn probe_now() -> ProbeInput {
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown"));
    let exe_sha256 = std::fs::read(&exe_path).ok().map(|bytes| {
        let mut h = Sha256::new();
        h.update(&bytes);
        crate::audit::hex(&h.finalize())
    });
    let ssh_envs_present = ["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"]
        .iter()
        .filter(|k| std::env::var(k).is_ok())
        .map(|k| k.to_string())
        .collect();
    ProbeInput {
        session_name: std::env::var("SESSIONNAME").ok(),
        ssh_envs_present,
        exe_path,
        exe_sha256,
        now_unix: crate::state::now_unix(),
    }
}

/// Pure collector: probe + baseline → bounded observation set + updated
/// baseline to persist (None = unchanged).
pub fn collect(
    input: &ProbeInput,
    baseline: Option<&ExeBaseline>,
    counter: &AtomicU64,
) -> (Vec<EndpointObservation>, Option<ExeBaseline>) {
    let mut out = Vec::new();
    let mut next = |kind: SignalKindView, severity: &'static str, penalty: u32, detail: String| {
        if out.len() >= 32 {
            return;
        }
        let seq = counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("ep-{}-{seq}", input.now_unix);
        out.push(EndpointObservation {
            evidence_ref: format!("endpoint:{id}"),
            id,
            kind,
            severity,
            penalty,
            detail,
        });
    };

    // --- Remote-session indicators ---------------------------------------
    if let Some(name) = &input.session_name
        && !name.is_empty()
        && !name.eq_ignore_ascii_case("console")
    {
        next(
            SignalKindView::RemoteSessionIndicator,
            "medium",
            20,
            format!("non-console session name: {name}"),
        );
    }
    if !input.ssh_envs_present.is_empty() {
        next(
            SignalKindView::RemoteSessionIndicator,
            "medium",
            20,
            format!(
                "SSH session markers present: {}",
                input.ssh_envs_present.join(",")
            ),
        );
    }

    // --- Process integrity (TOFU baseline) --------------------------------
    let new_baseline = match baseline {
        None => Some(ExeBaseline {
            exe_path: input.exe_path.clone(),
            sha256: input.exe_sha256.clone().unwrap_or_default(),
            recorded_unix: input.now_unix,
        }),
        Some(b) => {
            if b.exe_path != input.exe_path {
                next(
                    SignalKindView::EndpointIntegrityFailure,
                    "high",
                    40,
                    format!(
                        "executable path changed since baseline ({} -> {})",
                        b.exe_path.display(),
                        input.exe_path.display()
                    ),
                );
            }
            if !b.sha256.is_empty()
                && let Some(h) = &input.exe_sha256
                && h != &b.sha256
            {
                next(
                    SignalKindView::EndpointIntegrityFailure,
                    "high",
                    40,
                    "executable image hash changed since baseline".to_string(),
                );
            }
            None
        }
    };

    (out, new_baseline)
}

/// Persist the baseline (first run / explicit re-baseline).
pub fn save_baseline(dir: &Path, b: &ExeBaseline) -> CmdResult<()> {
    let bytes = serde_json::to_vec_pretty(b)
        .map_err(|e| crate::error::IpcError::new("internal", format!("baseline: {e}")))?;
    std::fs::write(dir.join("endpoint-baseline.json"), bytes)?;
    Ok(())
}

pub fn load_baseline(dir: &Path) -> Option<ExeBaseline> {
    let text = std::fs::read_to_string(dir.join("endpoint-baseline.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Append observations to the evidence journal (JSONL) so every emitted
/// signal's `evidence_ref` resolves to a persisted record.
pub fn persist_evidence(dir: &Path, observations: &[EndpointObservation]) -> CmdResult<()> {
    if observations.is_empty() {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("endpoint-evidence.jsonl"))?;
    for o in observations {
        let line = serde_json::to_string(o)
            .map_err(|e| crate::error::IpcError::new("internal", format!("evidence: {e}")))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(session: Option<&str>) -> ProbeInput {
        ProbeInput {
            session_name: session.map(String::from),
            ssh_envs_present: vec![],
            exe_path: PathBuf::from("C:\\Program Files\\Kiwi\\kiwi.exe"),
            exe_sha256: Some("aa".repeat(32)),
            now_unix: 1_758_000_000,
        }
    }

    #[test]
    fn console_session_is_quiet() {
        let c = AtomicU64::new(0);
        let (obs, baseline) = collect(&probe(Some("Console")), None, &c);
        assert!(obs.is_empty());
        assert!(baseline.is_some(), "first run records a baseline");
    }

    #[test]
    fn rdp_session_flags_remote_indicator() {
        let c = AtomicU64::new(0);
        let mut p = probe(Some("RDP-Tcp#3"));
        p.exe_sha256 = Some("aa".repeat(32));
        let baseline = ExeBaseline {
            exe_path: p.exe_path.clone(),
            sha256: "aa".repeat(32),
            recorded_unix: 1,
        };
        let (obs, _) = collect(&p, Some(&baseline), &c);
        assert!(obs.iter().any(|o| o.penalty == 20));
    }

    #[test]
    fn ssh_markers_flag_remote_indicator() {
        let c = AtomicU64::new(0);
        let mut p = probe(Some("Services"));
        p.ssh_envs_present = vec!["SSH_CONNECTION".into()];
        let baseline = ExeBaseline {
            exe_path: p.exe_path.clone(),
            sha256: "aa".repeat(32),
            recorded_unix: 1,
        };
        let (obs, _) = collect(&p, Some(&baseline), &c);
        assert!(obs.len() >= 2, "session name + ssh marker");
    }

    #[test]
    fn changed_binary_flags_integrity_failure() {
        let c = AtomicU64::new(0);
        let p = probe(Some("Console"));
        let baseline = ExeBaseline {
            exe_path: p.exe_path.clone(),
            sha256: "bb".repeat(32),
            recorded_unix: 1,
        };
        let (obs, _) = collect(&p, Some(&baseline), &c);
        let (kind, sig) = obs[0].as_signal();
        assert_eq!(kind, SignalKind::EndpointIntegrityFailure);
        assert_eq!(sig.severity, SignalSeverity::High);
        assert!(sig.evidence_ref.starts_with("endpoint:ep-"));
    }
}
