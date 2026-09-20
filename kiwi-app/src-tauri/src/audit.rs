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

/// Bounded, single-writer JSONL log under the app data dir.
pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
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
        })
    }

    /// Append one audited action. `detail` must already be sanitized by the
    /// caller (256-char bound applied here as a backstop).
    pub fn record(&mut self, action: &str, detail: &str, now_unix: i64) -> CmdResult<()> {
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

    #[cfg(test)]
    pub fn len(&self) -> u64 {
        self.seq
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
}
