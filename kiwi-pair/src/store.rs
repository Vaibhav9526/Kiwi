//! Persistent pairing records — SQLite, kiwi-mail store pattern.
//!
//! Layout (`root` = per-profile data dir): `pair.db` holding devices,
//! pairing tickets, challenges, and the seen-nonce replay ledger.
//!
//! Replay protection persists across restarts — a nonce or consumed
//! challenge replayed after a process restart still fails. All queries
//! are parameterized; schema version lives in `PRAGMA user_version`;
//! consumption is a single `UPDATE ... WHERE consumed=0` so double-use
//! is impossible even under racing callers.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{PairError, Result};

const SCHEMA_VERSION: u32 = 2;
/// Replay-ledger retention: nonces older than this may be pruned.
/// Covers the max challenge TTL (300s) with generous headroom.
const NONCE_RETENTION_SECS: i64 = 3600;
const MAX_NONCES: i64 = 4096;
const MAX_CHALLENGES: i64 = 4096;
/// Live (unexpired, unclaimed) pairing tickets per profile (§9d.11 bound).
/// A QR flow needs a handful at most; an unbounded pile of live bearer
/// tickets is a leak surface.
const MAX_LIVE_TICKETS: i64 = 32;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    algorithm       TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    keystore_ref    TEXT,
    status          TEXT NOT NULL,
    registered_unix INTEGER NOT NULL,
    last_seen_unix  INTEGER NOT NULL,
    revoked_unix    INTEGER
);
CREATE TABLE IF NOT EXISTS pairing_tickets (
    ticket        TEXT PRIMARY KEY,
    device_label  TEXT NOT NULL,
    issued_unix   INTEGER NOT NULL,
    expires_unix  INTEGER NOT NULL,
    consumed      INTEGER NOT NULL DEFAULT 0,
    -- v2: set by claim_ticket_and_register — the device row this ticket
    -- was claimed into. NULL while awaiting/invalid/expired-unclaimed.
    device_id     TEXT REFERENCES devices(device_id)
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(device_id),
    session_id   TEXT NOT NULL,
    event        TEXT NOT NULL,
    nonce        BLOB NOT NULL,
    issued_unix  INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL,
    consumed     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce       BLOB PRIMARY KEY,
    issued_unix INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub device_id: String,
    pub label: String,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub keystore_ref: Option<String>,
    /// `pending` | `active` | `suspended` | `revoked` — terminal.
    pub status: String,
    pub registered_unix: i64,
    pub last_seen_unix: i64,
    pub revoked_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRow {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    /// `unlock` | `device-pairing` | `recovery` | `elevated-action`
    pub event: String,
    pub nonce: Vec<u8>,
    pub issued_unix: i64,
    pub expires_unix: i64,
    pub consumed: bool,
}

/// Read-only snapshot of a `pairing_tickets` row (ipc.md §9d.3). The poll
/// path must never consume — `PairEngine::ticket_status` maps this to the
/// wire state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRow {
    pub ticket: String,
    pub device_label: String,
    pub issued_unix: i64,
    pub expires_unix: i64,
    pub consumed: bool,
    /// v2 link column: the device this ticket claimed into, if any.
    pub device_id: Option<String>,
}

/// Arguments for the atomic claim transaction — the device's full record
/// minus the fields the transaction derives (label comes from the ticket,
/// status/registered/last_seen from `now`).
pub struct ClaimDevice<'a> {
    pub device_id: &'a str,
    pub algorithm: &'a str,
    pub public_key: &'a [u8],
    pub keystore_ref: Option<&'a str>,
}

pub struct PairStore {
    conn: Connection,
}

fn device_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRow> {
    Ok(DeviceRow {
        device_id: r.get(0)?,
        label: r.get(1)?,
        algorithm: r.get(2)?,
        public_key: r.get(3)?,
        keystore_ref: r.get(4)?,
        status: r.get(5)?,
        registered_unix: r.get(6)?,
        last_seen_unix: r.get(7)?,
        revoked_unix: r.get(8)?,
    })
}

impl PairStore {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        Self::from_conn(Connection::open(root.join("pair.db"))?)
    }

    /// In-memory store — deterministic tests.
    pub fn open_memory() -> Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.execute_batch(DDL)?;
        // v1 → v2: the ticket→device link column. `device_id` is nullable so
        // existing rows upgrade in place; they simply have no link.
        let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < 2 {
            let has_col = conn
                .prepare("SELECT device_id FROM pairing_tickets LIMIT 0")
                .is_ok();
            if !has_col {
                conn.execute_batch(
                    "ALTER TABLE pairing_tickets ADD COLUMN device_id TEXT
                     REFERENCES devices(device_id)",
                )?;
            }
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    // ---- devices -------------------------------------------------------

    pub fn insert_device(&mut self, d: &DeviceRow) -> Result<()> {
        let n = self.conn.execute(
            "INSERT INTO devices
             (device_id, label, algorithm, public_key, keystore_ref, status,
              registered_unix, last_seen_unix, revoked_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                d.device_id,
                d.label,
                d.algorithm,
                d.public_key,
                d.keystore_ref,
                d.status,
                d.registered_unix,
                d.last_seen_unix,
                d.revoked_unix
            ],
        )?;
        if n == 0 {
            return Err(PairError::DeviceExists(d.device_id.clone()));
        }
        Ok(())
    }

    pub fn get_device(&self, device_id: &str) -> Result<Option<DeviceRow>> {
        self.conn
            .query_row(
                "SELECT device_id,label,algorithm,public_key,keystore_ref,status,
                        registered_unix,last_seen_unix,revoked_unix
                 FROM devices WHERE device_id=?1",
                params![device_id],
                device_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Whether any non-revoked device already holds this label (normalized:
    /// trim + lowercase). Duplicate live names are a `conflict` at the IPC
    /// boundary — revoked devices do not hold their old name.
    pub fn live_label_taken(&self, label: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM devices
                 WHERE lower(trim(label)) = lower(trim(?1)) AND status != 'revoked'
                 LIMIT 1",
                params![label],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn set_device_status(&self, device_id: &str, status: &str, at_unix: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE devices SET status=?1, last_seen_unix=?2,
                revoked_unix = CASE WHEN ?1='revoked' THEN ?2 ELSE revoked_unix END
             WHERE device_id=?3",
            params![status, at_unix, device_id],
        )?)
    }

    /// Devices in the contract's total order — `registered_unix` ascending,
    /// `device_id` ascending as the same-second tie-breaker (ipc.md §9d.5).
    /// `limit` bounds the scan (§9d.11 resource gate).
    pub fn list_devices(&self, limit: u32) -> Result<Vec<DeviceRow>> {
        let mut st = self.conn.prepare(
            "SELECT device_id,label,algorithm,public_key,keystore_ref,status,
                    registered_unix,last_seen_unix,revoked_unix
             FROM devices ORDER BY registered_unix, device_id LIMIT ?1",
        )?;
        let rows = st
            .query_map(params![limit as i64], device_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---- pairing tickets (single-use, ≤5min per contract §3.1) ----------

    pub fn insert_ticket(
        &mut self,
        ticket: &str,
        label: &str,
        now: i64,
        expires: i64,
    ) -> Result<()> {
        // Housekeeping + bound (§9d.11): drop expired UNLINKED rows (linked
        // rows keep their ticket→device claim evidence until the device row
        // itself is gone), then refuse to grow a pile of live bearer
        // tickets.
        self.conn.execute(
            "DELETE FROM pairing_tickets
             WHERE expires_unix <= ?1 AND device_id IS NULL",
            params![now],
        )?;
        let live: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pairing_tickets
             WHERE expires_unix > ?1 AND device_id IS NULL",
            params![now],
            |r| r.get(0),
        )?;
        if live >= MAX_LIVE_TICKETS {
            return Err(PairError::InvalidField {
                field: "pairing_ticket",
                reason: "too many live pairing tickets".into(),
            });
        }
        self.conn.execute(
            "INSERT INTO pairing_tickets (ticket,device_label,issued_unix,expires_unix)
             VALUES (?1,?2,?3,?4)",
            params![ticket, label, now, expires],
        )?;
        Ok(())
    }

    /// Read-only ticket lookup for `pair_status` — NEVER mutates
    /// (consuming here would destroy the bearer credential being polled).
    pub fn ticket_row(&self, ticket: &str) -> Result<Option<TicketRow>> {
        self.conn
            .query_row(
                "SELECT ticket,device_label,issued_unix,expires_unix,consumed,device_id
                 FROM pairing_tickets WHERE ticket=?1",
                params![ticket],
                |r| {
                    Ok(TicketRow {
                        ticket: r.get(0)?,
                        device_label: r.get(1)?,
                        issued_unix: r.get(2)?,
                        expires_unix: r.get(3)?,
                        consumed: r.get::<_, i64>(4)? != 0,
                        device_id: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Atomic single-use consume: succeeds only when the ticket exists,
    /// is unconsumed, and is unexpired — then marks it consumed.
    /// Returns the device_label bound at issue time.
    pub fn consume_ticket(&mut self, ticket: &str, now: i64) -> Result<String> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "UPDATE pairing_tickets SET consumed=1 WHERE ticket=?1 AND consumed=0
                 RETURNING device_label, expires_unix",
                params![ticket],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Err(PairError::InvalidTicket), // unknown or already used
            Some((_, exp)) if now >= exp => Err(PairError::TicketExpired),
            Some((label, _)) => Ok(label),
        }
    }

    /// The §9d.3 atomic claim: consume ticket + insert the device row +
    /// write the ticket→device link in ONE transaction. A crash between
    /// steps leaves nothing behind — the ticket is either fully claimed
    /// (linked device row exists) or still claimable.
    ///
    /// Expiry is checked BEFORE the consume write, so claiming an expired
    /// ticket fails `TicketExpired` and leaves `consumed=0` — matching the
    /// status rule that expiry outranks a consumed-but-unlinked flag.
    pub fn claim_ticket_and_register(
        &mut self,
        ticket: &str,
        device: &ClaimDevice<'_>,
        now: i64,
    ) -> Result<DeviceRow> {
        let tx = self.conn.transaction()?;
        // Lock the ticket row's current state inside the transaction.
        let row: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT device_label, expires_unix, consumed
                 FROM pairing_tickets WHERE ticket=?1",
                params![ticket],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (label, expires, consumed) = row.ok_or(PairError::InvalidTicket)?;
        if consumed != 0 {
            // Linked claims are idempotent-replayable information only via
            // pair_status; re-claiming any consumed ticket is refused.
            return Err(PairError::TicketConsumed);
        }
        if now >= expires {
            return Err(PairError::TicketExpired);
        }
        // Duplicate normalized label among live devices → conflict.
        let label_taken = tx
            .query_row(
                "SELECT 1 FROM devices
                 WHERE lower(trim(label)) = lower(trim(?1)) AND status != 'revoked'
                 LIMIT 1",
                params![label],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if label_taken {
            return Err(PairError::DeviceLabelConflict(label));
        }
        let inserted = DeviceRow {
            device_id: device.device_id.to_string(),
            label,
            algorithm: device.algorithm.to_string(),
            public_key: device.public_key.to_vec(),
            keystore_ref: device.keystore_ref.map(str::to_string),
            status: "pending".into(),
            registered_unix: now,
            last_seen_unix: now,
            revoked_unix: None,
        };
        tx.execute(
            "INSERT INTO devices
             (device_id, label, algorithm, public_key, keystore_ref, status,
              registered_unix, last_seen_unix, revoked_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                inserted.device_id,
                inserted.label,
                inserted.algorithm,
                inserted.public_key,
                inserted.keystore_ref,
                inserted.status,
                inserted.registered_unix,
                inserted.last_seen_unix,
                inserted.revoked_unix
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                PairError::DeviceExists(device.device_id.to_string())
            }
            other => PairError::Store(other),
        })?;
        // Consume + link — guaranteed to still be unconsumed: we hold the
        // write transaction.
        tx.execute(
            "UPDATE pairing_tickets SET consumed=1, device_id=?1 WHERE ticket=?2",
            params![device.device_id, ticket],
        )?;
        tx.commit()?;
        Ok(inserted)
    }

    // ---- challenges -----------------------------------------------------

    pub fn insert_challenge(&mut self, c: &ChallengeRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO challenges
             (challenge_id,device_id,session_id,event,nonce,issued_unix,expires_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                c.challenge_id,
                c.device_id,
                c.session_id,
                c.event,
                c.nonce,
                c.issued_unix,
                c.expires_unix
            ],
        )?;
        // Bound the table — oldest first (bounded storage, invariant).
        self.conn.execute(
            "DELETE FROM challenges WHERE challenge_id NOT IN
             (SELECT challenge_id FROM challenges ORDER BY issued_unix DESC LIMIT ?1)",
            params![MAX_CHALLENGES],
        )?;
        Ok(())
    }

    /// Nonce record + challenge insert in ONE transaction (PAIR-8): a
    /// failed challenge insert can no longer burn a nonce, and a replayed
    /// nonce cannot leave a half-written challenge.
    /// Returns false when the nonce was already recorded (replay).
    pub fn record_nonce_and_insert_challenge(
        &mut self,
        nonce: &[u8; 32],
        now: i64,
        c: &ChallengeRow,
    ) -> Result<bool> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM nonces WHERE issued_unix < ?1",
            params![now - NONCE_RETENTION_SECS],
        )?;
        let fresh = tx.execute(
            "INSERT OR IGNORE INTO nonces (nonce,issued_unix) VALUES (?1,?2)",
            params![nonce.as_slice(), now],
        )? == 1;
        if !fresh {
            // Nothing persists — the replay attempt records nothing.
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO challenges
             (challenge_id,device_id,session_id,event,nonce,issued_unix,expires_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                c.challenge_id,
                c.device_id,
                c.session_id,
                c.event,
                c.nonce,
                c.issued_unix,
                c.expires_unix
            ],
        )?;
        tx.execute(
            "DELETE FROM challenges WHERE challenge_id NOT IN
             (SELECT challenge_id FROM challenges ORDER BY issued_unix DESC LIMIT ?1)",
            params![MAX_CHALLENGES],
        )?;
        tx.execute(
            "DELETE FROM nonces WHERE nonce NOT IN
             (SELECT nonce FROM nonces ORDER BY issued_unix DESC LIMIT ?1)",
            params![MAX_NONCES],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn get_challenge(&self, challenge_id: &str) -> Result<Option<ChallengeRow>> {
        self.conn
            .query_row(
                "SELECT challenge_id,device_id,session_id,event,nonce,
                        issued_unix,expires_unix,consumed
                 FROM challenges WHERE challenge_id=?1",
                params![challenge_id],
                |r| {
                    Ok(ChallengeRow {
                        challenge_id: r.get(0)?,
                        device_id: r.get(1)?,
                        session_id: r.get(2)?,
                        event: r.get(3)?,
                        nonce: r.get(4)?,
                        issued_unix: r.get(5)?,
                        expires_unix: r.get(6)?,
                        consumed: r.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Atomic consume — returns false if already consumed.
    pub fn consume_challenge(&mut self, challenge_id: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE challenges SET consumed=1 WHERE challenge_id=?1 AND consumed=0",
            params![challenge_id],
        )? == 1)
    }

    /// Atomic consume + optional activation in one transaction (PAIR-5 /
    /// §9d.11.3): two engine instances racing one challenge cannot both
    /// observe success — the losing UPDATE touches no row.
    /// Returns false if the challenge was already consumed.
    pub fn consume_challenge_and_activate(
        &mut self,
        challenge_id: &str,
        activate_device: Option<(&str, i64)>,
    ) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let consumed = tx.execute(
            "UPDATE challenges SET consumed=1 WHERE challenge_id=?1 AND consumed=0",
            params![challenge_id],
        )? == 1;
        if !consumed {
            return Ok(false);
        }
        if let Some((device_id, now)) = activate_device {
            tx.execute(
                "UPDATE devices SET status='active', last_seen_unix=?2
                 WHERE device_id=?1",
                params![device_id, now],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    // ---- nonce replay ledger ---------------------------------------------

    /// Record a nonce; false if already seen (replay indicator).
    /// Prefer `record_nonce_and_insert_challenge` — this standalone path
    /// remains for direct store tests.
    pub fn record_nonce(&mut self, nonce: &[u8; 32], now: i64) -> Result<bool> {
        // Prune first so a full table can't false-positive on old entries.
        self.conn.execute(
            "DELETE FROM nonces WHERE issued_unix < ?1",
            params![now - NONCE_RETENTION_SECS],
        )?;
        let fresh = self.conn.execute(
            "INSERT OR IGNORE INTO nonces (nonce,issued_unix) VALUES (?1,?2)",
            params![nonce.as_slice(), now],
        )? == 1;
        self.conn.execute(
            "DELETE FROM nonces WHERE nonce NOT IN
             (SELECT nonce FROM nonces ORDER BY issued_unix DESC LIMIT ?1)",
            params![MAX_NONCES],
        )?;
        Ok(fresh)
    }
}
