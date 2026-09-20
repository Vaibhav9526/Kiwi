//! SMTP command helpers + the in-memory send queue (T-142).
//!
//! Reply parsing (`parse_ehlo_reply`), envelope validation (CRLF/
//! header-injection guards), dot-stuffing, and auth-reply mapping
//! live here; queue durability is `MailStore`'s `outbox` table.

use crate::error::{MailError, Result};

use super::*;

/// Parse an EHLO reply into `EhloInfo`. Per RFC 5321 §4.1.1.1 the first
/// 250 line is `domain [SP greeting]` — never an extension. Continuation
/// lines are `KEYWORD[ SP params]`.
pub(crate) fn parse_ehlo_reply(reply: &SmtpReply) -> EhloInfo {
    let mut info = EhloInfo::default();
    for (i, line) in reply.lines.iter().enumerate() {
        if i == 0 {
            info.greeting = line.clone();
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("").to_ascii_uppercase();
        let val = parts.next().unwrap_or("").trim().to_string();
        if !key.is_empty() {
            info.extensions.insert(key, val);
        }
    }
    info
}

pub(crate) fn auth_result(r: SmtpReply) -> Result<()> {
    match r.code {
        235 => Ok(()),
        // 503 "already authenticated" — treat as success state.
        503 => Ok(()),
        _ if r.is_permanent() || r.is_transient() => Err(MailError::Auth(format!(
            "code {} {}",
            r.code,
            r.enhanced.clone().unwrap_or_default()
        ))),
        _ => Err(MailError::Auth(format!("unexpected reply {}", r.code))),
    }
}

/// Reject CRLF/control injection and empty envelopes (SECURITY.md rule 9).
pub(crate) fn validate_envelope(from: &str, to: &[String]) -> Result<()> {
    fn bad(addr: &str) -> bool {
        addr.is_empty()
            || addr.bytes().any(|b| b < 0x20 || b == 0x7F)
            || addr.contains('<')
            || addr.contains('>')
    }
    if bad(from) {
        return Err(MailError::Protocol {
            protocol: PROTO,
            detail: "invalid/envelope-injection sender address".into(),
        });
    }
    if to.is_empty() {
        return Err(MailError::Protocol {
            protocol: PROTO,
            detail: "send request with no recipients".into(),
        });
    }
    for rcpt in to {
        if bad(rcpt) {
            return Err(MailError::Protocol {
                protocol: PROTO,
                detail: format!("invalid/envelope-injection recipient: {rcpt:?}"),
            });
        }
    }
    Ok(())
}

/// RFC 5321 §4.5.2 transparency: double any leading-dot line.
/// Input must already use CRLF line endings (our `mime` builder does).
pub(crate) fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 64);
    let mut at_line_start = true;
    for &b in body {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}

// ---------------------------------------------------------------------------
// Send queue — undo-send + send-later (Mailspring-style, T-142).
// In-memory dispatch order lives here; durability lives in MailStore's
// `outbox` table — callers persist at enqueue and rebuild on open.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct QueuedSend {
    pub queue_id: String,
    pub request: SendRequest,
    /// Earliest dispatch time (send-later). `0` = immediately eligible.
    pub not_before_unix: i64,
    /// Dispatch is frozen until this point (undo-send grace window).
    /// Cancelling before it expires is a true undo.
    pub undo_window_until_unix: i64,
    pub attempts: u32,
}

#[derive(Default)]
pub struct SendQueue {
    pending: Vec<QueuedSend>,
}

impl std::fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendRequest")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl SendQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, item: QueuedSend) {
        self.pending.push(item);
    }

    /// Undo-send / unschedule: remove a queued item. Succeeds while the
    /// send is still recallable — inside its undo window, OR awaiting a
    /// future send-later slot (`now < not_before`). Once committed AND due
    /// it belongs to the dispatcher; once dispatched it isn't in `pending`
    /// at all, so cancel naturally fails.
    pub fn cancel(&mut self, queue_id: &str, now: i64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|q| {
            !(q.queue_id == queue_id && (now < q.undo_window_until_unix || now < q.not_before_unix))
        });
        self.pending.len() != before
    }

    /// Move a pending send's dispatch time (send-later reschedule).
    /// Returns false when the item is gone — already due/dispatched or
    /// cancelled. Does not touch the undo window.
    pub fn reschedule(&mut self, queue_id: &str, not_before_unix: i64) -> bool {
        match self.pending.iter_mut().find(|q| q.queue_id == queue_id) {
            Some(q) => {
                q.not_before_unix = not_before_unix;
                true
            }
            None => false,
        }
    }

    /// Drain sends whose `not_before` has arrived. Callers run `send_mail`
    /// on each; a transient failure should re-enqueue with backoff.
    pub fn due(&mut self, now: i64) -> Vec<QueuedSend> {
        let (due, pending): (Vec<_>, Vec<_>) = self
            .pending
            .drain(..)
            .partition(|q| q.not_before_unix <= now);
        self.pending = pending;
        due
    }

    /// Iterate pending items — lets callers build outbox views/reload
    /// bookkeeping without a parallel index.
    pub fn pending(&self) -> impl Iterator<Item = &QueuedSend> {
        self.pending.iter()
    }

    /// Earliest `not_before` among pending sends (scheduler wake-up hint).
    pub fn next_due_at(&self) -> Option<i64> {
        self.pending.iter().map(|q| q.not_before_unix).min()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
