//! Append-only, hash-chained local audit log for elevated IPC actions
//! (lock, unlock, device revoke, cert accept-once, org binding changes).
//!
//! Each line is a JSON record `{seq, ts_unix, action, detail, prev, hash}`
//! where `hash = sha256(canonical_fields)`. The chain makes post-hoc edits
//! detectable — verification walks the file re-checking links. This is the
//! client-side event trail; kiwi-admin owns the org-level audit store
//! (contracts/admin-api.md §7). Details are caller-sanitized text — never
//! secrets (SECURITY.md rule 6).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CmdResult, IpcError};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditRecord {
    seq: u64,
    ts_unix: i64,
    action: String,
    detail: String,
    prev: String,
    hash: String,
}

/// Default retention age (days). Generous by design: the log does **not** mark
/// security-critical actions, so retention is indiscriminate by age and the
/// bound must be wide enough that a revoke/lock/pair/auth-fail row survives a
/// meaningful investigation window (see `docs/contracts/ipc.md` §8).
pub const DEFAULT_RETENTION_DAYS: u32 = 400;
/// Default newest-rows cap. Both bounds apply — a row is kept if it is recent
/// by *either* measure, so this is a backstop against a runaway event rate, not
/// a second age rule.
pub const DEFAULT_KEEP_LAST: u64 = 20_000;
/// Hard ceiling on rows a single sweep will read. A file larger than this is
/// refused and reported rather than blindly rewritten — the sweep fails honest
/// instead of truncating evidence it did not read.
pub const MAX_AUDIT_SCAN_ROWS: usize = 100_000;
/// Bounds accepted from the prefs store (global scope, `kiwi.audit.*`).
pub const MIN_RETENTION_DAYS: u32 = 30;
pub const MAX_RETENTION_DAYS: u32 = 3_650;
pub const MIN_KEEP_LAST: u64 = 1_000;
pub const MAX_KEEP_LAST: u64 = 1_000_000;

/// A bounded retention policy resolved from prefs (already clamped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Rows older than this are eligible for pruning (seconds).
    pub retention_days: u32,
    /// Never prune into the newest N rows, whatever their age.
    pub keep_last: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            keep_last: DEFAULT_KEEP_LAST,
        }
    }
}

impl RetentionPolicy {
    /// Clamp untrusted (prefs) values into the supported band. A value out of
    /// band in either direction — including a negative or non-integral one —
    /// falls back to the **conservative** bound (shortest retention, smallest
    /// keep), so a hostile value can never *loosen* retention.
    #[must_use]
    pub fn resolve(retention_days: Option<i64>, keep_last: Option<i64>) -> Self {
        let days = retention_days
            .and_then(|v| u32::try_from(v).ok())
            .map(|v| v.clamp(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS))
            .unwrap_or(MIN_RETENTION_DAYS);
        let keep = keep_last
            .and_then(|v| u64::try_from(v).ok())
            .map(|v| v.clamp(MIN_KEEP_LAST, MAX_KEEP_LAST))
            .unwrap_or(MIN_KEEP_LAST);
        Self {
            retention_days: days,
            keep_last: keep,
        }
    }

    /// Unix-seconds cutoff; rows strictly older are age-eligible.
    fn cutoff(&self, now_unix: i64) -> i64 {
        now_unix - i64::from(self.retention_days) * 86_400
    }
}

/// What a retention sweep did — the honest receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneReport {
    /// Rows dropped from the log.
    pub pruned: u64,
    /// Rows retained.
    pub kept: u64,
    /// Age-expired rows retained *only* because they sit inside the newest
    /// `keep_last` — the honest count of what the backstop saved.
    pub kept_by_count_floor: u64,
    /// True when the file was rewritten (a prune row was appended).
    pub swept: bool,
}

/// Bounded, single-writer JSONL log under the app data dir.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
    /// Test-only: make the next `record` fail, so ordering guarantees
    /// (intent before effect) are provable without corrupting the file.
    #[cfg(test)]
    fail_next: u32,
    #[cfg(test)]
    fail_skip: u32,
}

impl AuditLog {
    /// Open (or create) the audit file under `dir`. The chain position is
    /// recovered by replaying the tail of the file; a corrupt tail fails
    /// closed (audit integrity beats availability — the error surfaces).
    pub fn open(dir: &Path) -> CmdResult<Self> {
        let path = dir.join("audit.jsonl");
        let mut seq = 0u64;
        let mut last_hash = String::from("genesis");
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec: AuditRecord = serde_json::from_str(line).map_err(|e| {
                    IpcError::new("audit-corrupt", format!("audit log parse failed: {e}"))
                })?;
                let expect = record_hash(rec.seq, rec.ts_unix, &rec.action, &rec.detail, &rec.prev);
                if expect != rec.hash || rec.prev != last_hash {
                    return Err(IpcError::new(
                        "audit-corrupt",
                        "audit log chain break detected",
                    ));
                }
                seq = rec.seq + 1;
                last_hash = rec.hash;
            }
        }
        Ok(Self {
            path,
            seq,
            last_hash,
            #[cfg(test)]
            fail_next: 0,
            #[cfg(test)]
            fail_skip: 0,
        })
    }

    #[cfg(test)]
    pub fn inject_failure(&mut self) {
        self.fail_next = 1;
        self.fail_skip = 0;
    }

    #[cfg(test)]
    pub fn inject_failure_after(&mut self, skip: u32) {
        self.fail_next = 1;
        self.fail_skip = skip;
    }

    /// Append one audited action. `detail` must already be sanitized by the
    /// caller (256-char bound applied here as a backstop).
    pub fn record(&mut self, action: &str, detail: &str, now_unix: i64) -> CmdResult<()> {
        #[cfg(test)]
        if self.fail_next > 0 {
            if self.fail_skip > 0 {
                self.fail_skip -= 1;
            } else {
                self.fail_next -= 1;
                return Err(IpcError::new("io-error", "injected audit write failure"));
            }
        }
        let detail: String = detail.chars().take(256).collect();
        let rec = AuditRecord {
            seq: self.seq,
            ts_unix: now_unix,
            action: action.to_string(),
            detail,
            prev: self.last_hash.clone(),
            hash: String::new(),
        };
        let hash = record_hash(rec.seq, rec.ts_unix, &rec.action, &rec.detail, &rec.prev);
        let rec = AuditRecord { hash, ..rec };
        let mut line = serde_json::to_string(&rec)
            .map_err(|e| IpcError::new("internal", format!("audit serialize: {e}")))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        self.seq += 1;
        self.last_hash = rec.hash;
        Ok(())
    }

    /// Number of records currently in the chain. This is the replayed `seq`
    /// from `open()` (and re-replayed after a prune), so it is the real row
    /// count of `audit.jsonl` — exposed for the T-330 storage diagnostics,
    /// which cannot get it from SQL because the audit trail is a file, not a
    /// table.
    pub fn len(&self) -> u64 {
        self.seq
    }

    /// Test-only: the on-disk file this handle owns. Kept out of the production
    /// surface on purpose — a caller must go through `integrity()` / `record()`
    /// rather than editing the chain behind the log's back.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bounded retention sweep (T-327). Drops rows that are **both** older
    /// than `policy.retention_days` **and** outside the newest
    /// `policy.keep_last` rows, then rewrites the file and appends one
    /// `audit-pruned` row so the deletion is visible in the very log it trims.
    ///
    /// **The chain is re-anchored, not broken.** `open()` verifies from
    /// `"genesis"`, so a naive "delete the first N lines" would make the next
    /// launch report `audit-corrupt`. Instead the retained rows are re-linked
    /// from a fresh genesis and the prune row is the first record in the new
    /// file — a reader can see that history was truncated, and the retained
    /// rows still verify end-to-end. The original head hash is carried in the
    /// prune row's detail, so the truncation point is itself attributable.
    ///
    /// Fails honest: a file that cannot be parsed, or one larger than
    /// [`MAX_AUDIT_SCAN_ROWS`], is left **untouched** and the error surfaces —
    /// the sweep never rewrites evidence it failed to read.
    pub fn prune(&mut self, policy: &RetentionPolicy, now_unix: i64) -> CmdResult<PruneReport> {
        let mut report = PruneReport::default();
        if !self.path.exists() {
            return Ok(report);
        }
        let text = std::fs::read_to_string(&self.path)?;
        let mut records: Vec<AuditRecord> = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord = serde_json::from_str(line).map_err(|e| {
                IpcError::new("audit-corrupt", format!("audit log parse failed: {e}"))
            })?;
            records.push(rec);
        }
        if records.len() > MAX_AUDIT_SCAN_ROWS {
            return Err(IpcError::new(
                "audit-corrupt",
                format!(
                    "audit log has {} rows, above the {MAX_AUDIT_SCAN_ROWS}-row sweep bound; not rewriting",
                    records.len()
                ),
            ));
        }
        let total = records.len();
        report.kept = total as u64;
        if records.is_empty() {
            return Ok(report);
        }

        // Newest `keep_last` rows are protected by count regardless of age.
        let floor = (records.len() as u64).saturating_sub(policy.keep_last) as usize;
        let cutoff = policy.cutoff(now_unix);
        let head_hash = records.last().map(|r| r.hash.clone()).unwrap_or_default();

        let total = records.len();
        let mut kept: Vec<AuditRecord> = Vec::with_capacity(total);
        for (i, rec) in records.into_iter().enumerate() {
            let age_eligible = rec.ts_unix < cutoff;
            if i >= floor || !age_eligible {
                // Saved by the keep_last backstop despite being age-expired.
                if age_eligible {
                    report.kept_by_count_floor += 1;
                }
                kept.push(rec);
            }
        }
        report.kept = kept.len() as u64;
        report.pruned = (total - kept.len()) as u64;
        if report.pruned == 0 {
            return Ok(report);
        }

        // The prune row is the new genesis anchor; retained rows are re-linked
        // *from the anchor's hash*, so the rewritten file verifies end-to-end
        // and the truncation point is the first thing a reader sees.
        let detail = format!(
            "pruned={} kept={} retention_days={} keep_last={} prior_head={}",
            report.pruned,
            report.kept,
            policy.retention_days,
            policy.keep_last,
            short_hash(&head_hash),
        );
        let anchor = AuditRecord {
            seq: 0,
            ts_unix: now_unix,
            action: "audit-pruned".into(),
            detail,
            prev: String::from("genesis"),
            hash: String::new(),
        };
        let anchor = AuditRecord {
            hash: record_hash(
                anchor.seq,
                anchor.ts_unix,
                &anchor.action,
                &anchor.detail,
                &anchor.prev,
            ),
            ..anchor
        };
        let mut body = serde_json::to_string(&anchor)
            .map_err(|e| IpcError::new("internal", format!("audit serialize: {e}")))?;
        body.push('\n');

        // Re-link retained rows from the anchor hash, renumbering seq.
        let mut prev = anchor.hash.clone();
        for (i, rec) in kept.iter_mut().enumerate() {
            rec.seq = i as u64 + 1;
            rec.prev = prev.clone();
            rec.hash = record_hash(rec.seq, rec.ts_unix, &rec.action, &rec.detail, &rec.prev);
            prev = rec.hash.clone();
            let mut line = serde_json::to_string(rec)
                .map_err(|e| IpcError::new("internal", format!("audit serialize: {e}")))?;
            line.push('\n');
            body.push_str(&line);
        }

        // Atomic rewrite — a crash never leaves a half-written audit log.
        let tmp = self.path.with_extension("jsonl.kiwi-part");
        std::fs::write(&tmp, body.as_bytes())?;
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            if self.path.exists() {
                let _ = std::fs::remove_file(&self.path);
                if let Err(e2) = std::fs::rename(&tmp, &self.path) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(IpcError::new("io-error", format!("audit rewrite: {e2}")));
                }
            } else {
                return Err(IpcError::new("io-error", format!("audit rewrite: {e}")));
            }
        }

        // Replay the rewritten file to recover seq/last_hash honestly.
        *self = Self::open(self.path.parent().unwrap_or(Path::new(".")))?;
        report.swept = true;
        Ok(report)
    }
}
fn record_hash(seq: u64, ts_unix: i64, action: &str, detail: &str, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_be_bytes());
    h.update(ts_unix.to_be_bytes());
    h.update(action.as_bytes());
    h.update(b"\x00");
    h.update(detail.as_bytes());
    h.update(b"\x00");
    h.update(prev.as_bytes());
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Short, non-reversible form of a chain hash for the prune row's detail —
/// enough to correlate the truncation point with a prior export, not a second
/// full copy of the head hash (and never any row content).
fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

/// Integrity verdict for the local audit chain (T-331).
///
/// `Unknown` is a real, reachable state — it means the log has never been
/// verified *in this process*. It is deliberately distinct from `Ok`: "not
/// checked" must never render as "verified".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditIntegrity {
    /// The chain verified from genesis to the current head.
    Ok,
    /// A record failed to parse, or a hash/link in the chain did not verify.
    Corrupt,
    /// Not checked in this process yet (honest absence, never "fine").
    Unknown,
}

impl AuditIntegrity {
    /// Tri-state as the security-status payload carries it: `Some(false)` is
    /// corrupt, `None` is unknown. `Some(true)` is the only "fine".
    #[must_use]
    pub fn ok(self) -> Option<bool> {
        match self {
            Self::Ok => Some(true),
            Self::Corrupt => Some(false),
            Self::Unknown => None,
        }
    }
}

impl AuditLog {
    /// Verify the chain without mutating anything (T-331). This is the cheap
    /// path the renderer polls: it re-walks the same records `open()` does and
    /// reports a verdict instead of throwing, so a tampered log becomes a
    /// *visible state* rather than an invisible backend error.
    ///
    /// An absent log is `Ok` (nothing to tamper with) — the file is created on
    /// first write, and "no log yet" is not evidence of corruption.
    pub fn integrity(&self) -> AuditIntegrity {
        if !self.path.exists() {
            return AuditIntegrity::Ok;
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            // Unreadable is not the same as corrupt — report unknown rather
            // than accusing the user of tampering we could not check.
            return AuditIntegrity::Unknown;
        };
        let mut prev = String::from("genesis");
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(rec) = serde_json::from_str::<AuditRecord>(line) else {
                return AuditIntegrity::Corrupt;
            };
            let expect = record_hash(rec.seq, rec.ts_unix, &rec.action, &rec.detail, &rec.prev);
            if expect != rec.hash || rec.prev != prev {
                return AuditIntegrity::Corrupt;
            }
            prev = rec.hash;
        }
        AuditIntegrity::Ok
    }
}

/// One audit-log row as the read surface projects it (T-323/T-324 shape:
/// `event`, `atUnix`, `actor`, `subjectId`, `detailJson`). Reads from the
/// same `audit.jsonl` the writers append to, so the view and the retention
/// sweep share one file and one schema.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    /// The action tag (snake-case, e.g. `audit-pruned`).
    pub event: String,
    pub at_unix: i64,
    /// The JSONL schema has no actor column; absence stays explicit.
    pub actor: Option<String>,
    pub subject_id: Option<String>,
    /// The sanitized detail text as recorded (ids + counts only). Renderers
    /// may display it verbatim; it never contains paths, subjects, or bodies.
    pub detail_json: Option<String>,
}

impl AuditLog {
    /// Read the trail newest-first, optionally paging to rows strictly older
    /// than `before_unix`, bounded to `limit`. A corrupt line yields
    /// `audit-corrupt` rather than a silently short list — the reader must not
    /// under-report evidence.
    pub fn read_recent(
        &self,
        before_unix: Option<i64>,
        limit: u32,
    ) -> CmdResult<Vec<AuditEventView>> {
        let mut out: Vec<AuditEventView> = Vec::new();
        if !self.path.exists() {
            return Ok(out);
        }
        let text = std::fs::read_to_string(&self.path)?;
        for line in text.lines().rev() {
            if out.len() >= limit as usize {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord = serde_json::from_str(line).map_err(|e| {
                IpcError::new("audit-corrupt", format!("audit log parse failed: {e}"))
            })?;
            if before_unix.is_some_and(|b| rec.ts_unix >= b) {
                continue;
            }
            out.push(AuditEventView {
                event: rec.action,
                at_unix: rec.ts_unix,
                actor: None,
                subject_id: None,
                detail_json: (!rec.detail.is_empty()).then_some(rec.detail),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_chain_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("kiwi-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        {
            let mut log = AuditLog::open(&dir).unwrap();
            log.record("lock", "manual", 100).unwrap();
            log.record("unlock", "challenge ok", 200).unwrap();
            assert_eq!(log.len(), 2);
        }
        // Reopen: chain resumes.
        let mut log = AuditLog::open(&dir).unwrap();
        log.record("revoke", "dev-1", 300).unwrap();

        // Tamper: rewrite the file with an edited middle record.
        let tampered = dir.join("tampered");
        std::fs::create_dir_all(&tampered).unwrap();
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect();
        let mut rec: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        rec["detail"] = serde_json::Value::from("edited");
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(tampered.join("audit.jsonl"), lines.join("\n") + "\n").unwrap();
        let r = AuditLog::open(&tampered);
        assert!(r.is_err_and(|e| e.code == "audit-corrupt"));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&tampered);
    }

    #[test]
    fn read_recent_returns_real_newest_rows_and_pages_exclusively() {
        let dir = std::env::temp_dir().join(format!("kiwi-audit-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::open(&dir).unwrap();
        assert!(
            log.read_recent(None, 100).unwrap().is_empty(),
            "absent is empty"
        );

        let mut log = log;
        for (at, action) in [(100, "first"), (200, "second"), (300, "third")] {
            log.record(action, &format!("detail-{at}"), at).unwrap();
        }
        let newest = log.read_recent(None, 2).unwrap();
        assert_eq!(
            newest.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            ["third", "second"]
        );
        assert_eq!(newest[0].at_unix, 300);
        assert_eq!(newest[0].actor, None, "JSONL has no actor column");
        assert_eq!(newest[0].subject_id, None);
        assert_eq!(newest[0].detail_json.as_deref(), Some("detail-300"));
        let older = log.read_recent(Some(200), 100).unwrap();
        assert_eq!(
            older.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            ["first"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- T-331 integrity probe -------------------------------------------

    /// The cheap probe must agree with the strict opener, and — critically —
    /// must never report "fine" for a log it could not check.
    #[test]
    fn integrity_reports_ok_corrupt_and_unknown_honestly() {
        let dir = std::env::temp_dir().join(format!("kiwi-integrity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Absent log: nothing to tamper with — `ok`, not "unknown".
        let log = AuditLog::open(&dir).unwrap();
        assert_eq!(log.integrity(), AuditIntegrity::Ok);
        assert_eq!(log.integrity().ok(), Some(true));

        let mut log = log;
        log.record("lock", "manual", 100).unwrap();
        log.record("unlock", "challenge ok", 200).unwrap();
        assert_eq!(log.integrity(), AuditIntegrity::Ok, "a good chain verifies");
        assert_eq!(log.integrity().ok(), Some(true));

        // Tamper: the same edit that makes `open` fail closed must make the
        // probe say `corrupt` (NOT throw) — that is the whole point: the
        // failure has to become a renderable state.
        let lines: Vec<String> = std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let mut rec: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        rec["detail"] = serde_json::Value::from("edited");
        let tampered = dir.join("tampered");
        std::fs::create_dir_all(&tampered).unwrap();
        let mut out = lines.clone();
        out[0] = serde_json::to_string(&rec).unwrap();
        std::fs::write(tampered.join("audit.jsonl"), out.join("\n") + "\n").unwrap();
        assert!(
            AuditLog::open(&tampered).is_err(),
            "open still fails closed"
        );
        let probe = AuditLog {
            path: tampered.join("audit.jsonl"),
            seq: 0,
            last_hash: String::new(),
            fail_next: 0,
            fail_skip: 0,
        };
        assert_eq!(probe.integrity(), AuditIntegrity::Corrupt);
        assert_eq!(
            probe.integrity().ok(),
            Some(false),
            "corrupt is a real `false`, never absence"
        );

        // Unparseable line → corrupt, not a panic and not silence.
        let junk = dir.join("junk");
        std::fs::create_dir_all(&junk).unwrap();
        std::fs::write(junk.join("audit.jsonl"), "{not json}\n").unwrap();
        let probe = AuditLog {
            path: junk.join("audit.jsonl"),
            seq: 0,
            last_hash: String::new(),
            fail_next: 0,
            fail_skip: 0,
        };
        assert_eq!(probe.integrity(), AuditIntegrity::Corrupt);

        // A pruned (re-anchored) log must still verify — otherwise the
        // integrity probe would cry wolf about our own retention sweep.
        let prune_dir = dir.join("pruned");
        std::fs::create_dir_all(&prune_dir).unwrap();
        let mut plog = seed_log(&prune_dir, 6, 86_400);
        plog.prune(
            &RetentionPolicy {
                retention_days: 1,
                keep_last: 2,
            },
            100 + 86_400 * 5 + 365 * 86_400,
        )
        .unwrap();
        assert_eq!(
            plog.integrity(),
            AuditIntegrity::Ok,
            "re-anchored = verified"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Unknown` must map to absence, so a never-checked log can never be
    /// rendered as a passing state.
    #[test]
    fn integrity_unknown_is_honest_absence() {
        assert_eq!(AuditIntegrity::Ok.ok(), Some(true));
        assert_eq!(AuditIntegrity::Corrupt.ok(), Some(false));
        assert_eq!(AuditIntegrity::Unknown.ok(), None);
    }

    // -- T-327 retention sweep -------------------------------------------

    fn seed_log(dir: &Path, rows: usize, step: i64) -> AuditLog {
        let mut log = AuditLog::open(dir).unwrap();
        for i in 0..rows {
            log.record(
                "pair-ticket-issued",
                &format!("device_id=dev-{i}"),
                100 + step * i as i64,
            )
            .unwrap();
        }
        log
    }

    /// The headline property: pruning keeps the NEWEST rows and the file still
    /// verifies — the chain is re-anchored, not broken.
    #[test]
    fn prune_keeps_newest_and_the_chain_still_verifies() {
        let dir = std::env::temp_dir().join(format!("kiwi-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 10 rows, 1 day apart starting at t=100. `now` is a full year after
        // the newest row and retention is 5 days, so every row is older than
        // the cutoff. `keep_last: 5` then determines the outcome: the 5 newest
        // rows sit inside the count backstop and survive, the 5 oldest are
        // both age-expired and below the floor, so they are dropped.
        let mut log = seed_log(&dir, 10, 86_400);
        let now = 100 + 86_400 * 9 + 365 * 86_400;
        let policy = RetentionPolicy {
            retention_days: 5,
            keep_last: 5,
        };
        let report = log.prune(&policy, now).unwrap();
        assert_eq!(report.pruned, 5, "the 5 oldest rows fall below both bounds");
        assert!(report.swept);
        assert_eq!(report.kept, 5);
        assert_eq!(
            report.kept_by_count_floor, 5,
            "the 5 survivors are age-expired and saved only by count"
        );

        let after = log.read_recent(None, 100).unwrap();
        // 5 retained + 1 prune anchor row.
        assert_eq!(after.len(), 6);
        assert_eq!(
            after.last().map(|e| e.event.as_str()),
            Some("audit-pruned"),
            "the prune row is the genesis anchor of the new file"
        );
        let details: Vec<_> = after.iter().filter_map(|e| e.detail_json.clone()).collect();
        assert!(
            details.iter().any(|d| d.contains("dev-9")),
            "newest row must survive"
        );
        assert!(
            !details.iter().any(|d| d.contains("dev-0")),
            "oldest row must be gone"
        );
        // Reopen from disk: the chain still verifies (no audit-corrupt).
        let reopened = AuditLog::open(&dir);
        assert!(
            reopened.is_ok(),
            "rewritten log must reopen clean, got {:?}",
            reopened.err()
        );
        // And a further append still chains correctly.
        let mut reopened = reopened.unwrap();
        reopened.record("lock", "manual", now + 1).unwrap();
        drop(reopened);
        assert!(AuditLog::open(&dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sweep itself is audited — visible in the log it trims — and carries
    /// counts only, never row content.
    #[test]
    fn sweep_is_audited_with_counts_only() {
        let dir = std::env::temp_dir().join(format!("kiwi-prune-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = seed_log(&dir, 6, 86_400);
        // A year past the newest row, retention 2 days → every row is
        // age-expired. keep_last is small, so the count backstop does not save
        // the older rows and they are pruned on age.
        let now = 100 + 86_400 * 5 + 365 * 86_400;
        let policy = RetentionPolicy {
            retention_days: 2,
            keep_last: 2,
        };
        let report = log.prune(&policy, now).unwrap();
        // 6 rows, keep_last 2 → the 4 rows below the count floor are dropped.
        assert_eq!(report.pruned, 4, "4 rows fall below both bounds");
        assert_eq!(report.kept, 2);
        log.prune(&policy, now).unwrap();

        let raw = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let first = raw.lines().next().unwrap();
        let rec: serde_json::Value = serde_json::from_str(first).unwrap();
        assert_eq!(rec["action"], "audit-pruned");
        let detail = rec["detail"].as_str().unwrap();
        assert!(detail.contains("pruned=4"), "count only: {detail}");
        assert!(detail.contains("retention_days=2"));
        assert!(detail.contains("keep_last=2"));
        // No row content leaks into the prune record.
        assert!(
            !detail.contains("dev-"),
            "prune detail must not carry row content"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The count backstop: even age-expired rows inside the newest N survive.
    #[test]
    fn keep_last_backstop_protects_recent_rows_by_count() {
        let dir = std::env::temp_dir().join(format!("kiwi-prune-floor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = seed_log(&dir, 5, 86_400);
        // Everything is a year old relative to `now`, but the newest 3 sit
        // inside the keep_last backstop and survive regardless of age.
        let now = 100 + 86_400 * 4 + 365 * 86_400;
        let policy = RetentionPolicy {
            retention_days: 1,
            keep_last: 3,
        };
        let report = log.prune(&policy, now).unwrap();
        assert_eq!(
            report.kept_by_count_floor, 3,
            "3 expired rows survived because they are inside keep_last"
        );
        assert_eq!(
            report.kept, 3,
            "the 3 rows inside the backstop survive despite being expired"
        );
        assert_eq!(
            report.pruned, 2,
            "the 2 rows below the count floor are dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail honest: a corrupt log is left untouched rather than half-pruned.
    #[test]
    fn corrupt_log_is_refused_not_rewritten() {
        let dir = std::env::temp_dir().join(format!("kiwi-prune-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.jsonl"), b"{\"broken\":\n").unwrap();
        let err = AuditLog::open(&dir).unwrap_err();
        assert_eq!(err.code, "audit-corrupt");
        // Content unchanged — the sweep refused to touch it.
        let after = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(after, "{\"broken\":\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Policy values from prefs are clamped; a hostile value cannot loosen
    /// retention (an unusable value falls back to the conservative bound).
    #[test]
    fn policy_clamps_untrusted_prefs() {
        let d = RetentionPolicy::resolve(Some(0), Some(0));
        assert_eq!(d.retention_days, MIN_RETENTION_DAYS);
        assert_eq!(d.keep_last, MIN_KEEP_LAST);
        let d = RetentionPolicy::resolve(Some(999_999), Some(-5));
        assert_eq!(d.retention_days, MAX_RETENTION_DAYS);
        assert_eq!(
            d.keep_last, MIN_KEEP_LAST,
            "negative falls back to the floor"
        );
        // Explicit in-band values are honored exactly.
        let d = RetentionPolicy::resolve(Some(365), Some(5_000));
        assert_eq!(d.retention_days, 365);
        assert_eq!(d.keep_last, 5_000);
        // The documented defaults apply when the caller supplies nothing.
        assert_eq!(
            RetentionPolicy::default().retention_days,
            DEFAULT_RETENTION_DAYS
        );
        assert_eq!(RetentionPolicy::default().keep_last, DEFAULT_KEEP_LAST);
    }
}
