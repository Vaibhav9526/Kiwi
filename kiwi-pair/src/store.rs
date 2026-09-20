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

const SCHEMA_VERSION: u32 = 1;
/// Replay-ledger retention: nonces older than this may be pruned.
/// Covers the max challenge TTL (300s) with generous headroom.
const NONCE_RETENTION_SECS: i64 = 3600;
const MAX_NONCES: i64 = 4096;
const MAX_CHALLENGES: i64 = 4096;

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
    consumed      INTEGER NOT NULL DEFAULT 0
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

pub struct PairStore {
    conn: Connection,
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
                |r| {
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
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_device_status(&self, device_id: &str, status: &str, at_unix: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE devices SET status=?1, last_seen_unix=?2,
                revoked_unix = CASE WHEN ?1='revoked' THEN ?2 ELSE revoked_unix END
             WHERE device_id=?3",
            params![status, at_unix, device_id],
        )?)
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRow>> {
        let mut st = self.conn.prepare(
            "SELECT device_id,label,algorithm,public_key,keystore_ref,status,
                    registered_unix,last_seen_unix,revoked_unix
             FROM devices ORDER BY registered_unix",
        )?;
        let rows = st
            .query_map([], |r| {
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
            })?
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
        self.conn.execute(
            "INSERT INTO pairing_tickets (ticket,device_label,issued_unix,expires_unix)
             VALUES (?1,?2,?3,?4)",
            params![ticket, label, now, expires],
        )?;
        Ok(())
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

    // ---- nonce replay ledger ---------------------------------------------

    /// Record a nonce; false if already seen (replay indicator).
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
