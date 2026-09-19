//! POP3 analyzer.
//!
//! Recognizes `CAPA` capabilities (`STLS`, `SASL …`), the `STLS` upgrade and its
//! `+OK`/`-ERR` reply, and the three credential paths: `USER`/`PASS` (cleartext),
//! `APOP` (MD5 challenge-response) and `AUTH <mechanism>`.
//!
//! `APOP` maps to [`AuthMechanism::CramMd5`] because both are MD5-based
//! challenge-response exchanges. The mapping is recorded here so the rule engine
//! sees one consistent vocabulary, and `KIWI-AUTH-005` (MD5-based mechanism) fires
//! for either.

use super::{
    AnalysisOutcome, AnalyzerLimits, Direction, ProtocolTrace, TraceFacts, bounded_line,
    command_verb, finalize, redacted_exchange, tokens,
};
use crate::model::{AuthMechanism, Protocol};

/// Analyze a POP3 session trace. See `smtp::analyze` for the
/// `analyzed_as` contract.
pub fn analyze(
    trace: &ProtocolTrace,
    limits: &AnalyzerLimits,
    analyzed_as: Protocol,
) -> AnalysisOutcome {
    let mut facts = TraceFacts::default();
    let mut awaiting_starttls_reply = false;
    let mut awaiting_auth_reply = false;
    let mut awaiting_capabilities = false;
    let mut upgrade_accepted_at: Option<usize> = None;
    let mut examined = 0usize;

    for (index, line) in trace.lines.iter().enumerate() {
        if index >= limits.max_lines {
            break;
        }
        examined += 1;
        let text = bounded_line(line.text.as_str(), limits.max_line_chars);

        match line.direction {
            Direction::Client => {
                facts.plaintext_application_lines =
                    facts.plaintext_application_lines.saturating_add(1);
                let Some(verb) = command_verb(&text) else {
                    continue;
                };
                match verb.as_str() {
                    "STLS" => {
                        facts.starttls_requested = true;
                        awaiting_starttls_reply = true;
                        facts.note_excerpt("STLS");
                    }
                    "CAPA" => {
                        awaiting_capabilities = true;
                    }
                    // Credentials themselves are never retained — only the fact
                    // that a cleartext mechanism was used.
                    "PASS" => {
                        facts.note_auth_attempt(AuthMechanism::Login, limits);
                        awaiting_auth_reply = true;
                        if facts.starttls_requested {
                            facts.auth_after_starttls_request = true;
                        }
                        facts.note_excerpt("PASS");
                    }
                    "APOP" => {
                        facts.note_auth_attempt(AuthMechanism::CramMd5, limits);
                        awaiting_auth_reply = true;
                        if facts.starttls_requested {
                            facts.auth_after_starttls_request = true;
                        }
                        facts.note_excerpt("APOP");
                    }
                    "AUTH" => {
                        let mechanism_token =
                            tokens(&text, 3).into_iter().nth(1).unwrap_or_default();
                        facts
                            .note_auth_attempt(AuthMechanism::from_token(&mechanism_token), limits);
                        awaiting_auth_reply = true;
                        if facts.starttls_requested {
                            facts.auth_after_starttls_request = true;
                        }
                        facts.note_excerpt("AUTH");
                    }
                    _ => {}
                }
            }
            Direction::Server => {
                if awaiting_starttls_reply {
                    let outcome = pop3_outcome(&text);
                    facts.starttls_reply = outcome;
                    if outcome == Some(true) {
                        upgrade_accepted_at = Some(index);
                    }
                    awaiting_starttls_reply = false;
                    facts.note_excerpt(&redacted_exchange(
                        "STLS",
                        Some(if outcome == Some(true) { "+OK" } else { "-ERR" }),
                    ));
                    continue;
                }
                if awaiting_capabilities {
                    let trimmed = text.trim();
                    if trimmed == "." {
                        awaiting_capabilities = false;
                        continue;
                    }
                    if trimmed.starts_with("+OK") || trimmed.starts_with("-ERR") {
                        continue;
                    }
                    for token in tokens(trimmed, 8) {
                        facts.add_capability(&token, limits);
                    }
                    continue;
                }
                if awaiting_auth_reply && let Some(outcome) = pop3_outcome(&text) {
                    facts.note_auth_outcome(outcome);
                    awaiting_auth_reply = false;
                    facts.note_excerpt(&redacted_exchange(
                        "AUTH",
                        Some(if outcome { "+OK" } else { "-ERR" }),
                    ));
                }
            }
        }
    }

    // Positive downgrade indicator: STLS accepted, no handshake observed, yet the
    // client continued the POP3 conversation in the clear.
    if let Some(accepted_index) = upgrade_accepted_at
        && trace.tls.is_none()
        && trace
            .lines
            .iter()
            .skip(accepted_index.saturating_add(1))
            .any(|line| {
                line.direction == Direction::Client
                    && command_verb(line.text.as_str())
                        .map(|verb| verb != "QUIT")
                        .unwrap_or(false)
            })
    {
        facts.application_data_after_accepted_upgrade = true;
    }

    finalize(trace, analyzed_as, facts, limits, examined)
}

/// POP3 status outcome: `+OK` is success, `-ERR` is failure.
fn pop3_outcome(line: &str) -> Option<bool> {
    let upper = line.trim_start().to_ascii_uppercase();
    if upper.starts_with("+OK") {
        Some(true)
    } else if upper.starts_with("-ERR") {
        Some(false)
    } else {
        None
    }
}
