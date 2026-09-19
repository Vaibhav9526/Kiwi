//! IMAP4rev1/rev2 analyzer.
//!
//! Recognizes the `CAPABILITY` token list, `STARTTLS` and its tagged reply, and
//! `LOGIN`/`AUTHENTICATE` with the tagged outcome. Tagged replies are matched
//! against the tag of the command that is actually pending, so an unrelated
//! `NO` cannot be read as an upgrade failure.

use super::{
    AnalysisOutcome, AnalyzerLimits, Direction, ProtocolTrace, TraceFacts, bounded_line,
    command_verb, finalize, redacted_exchange, reply_code, tokens,
};
use crate::model::{AuthMechanism, Protocol};

/// Analyze an IMAP session trace. See `smtp::analyze` for the
/// `analyzed_as` contract.
pub fn analyze(
    trace: &ProtocolTrace,
    limits: &AnalyzerLimits,
    analyzed_as: Protocol,
) -> AnalysisOutcome {
    let mut facts = TraceFacts::default();
    let mut pending_starttls_tag: Option<String> = None;
    let mut pending_auth_tag: Option<String> = None;
    let mut upgrade_accepted_at: Option<usize> = None;
    let mut examined = 0usize;

    for (index, line) in trace.lines.iter().enumerate() {
        if index >= limits.max_lines {
            break;
        }
        examined += 1;
        let text = bounded_line(line.text.as_str(), limits.max_line_chars);
        let upper = text.to_ascii_uppercase();

        match line.direction {
            Direction::Client => {
                facts.plaintext_application_lines =
                    facts.plaintext_application_lines.saturating_add(1);
                let parts = tokens(&text, 3);
                let tag = parts.first().cloned().unwrap_or_default();
                let verb =
                    command_verb(&parts.get(1).cloned().unwrap_or_default()).unwrap_or_default();
                match verb.as_str() {
                    "STARTTLS" => {
                        facts.starttls_requested = true;
                        pending_starttls_tag = Some(tag);
                        facts.note_excerpt("STARTTLS");
                    }
                    "LOGIN" => {
                        // `LOGIN <user> <password>` — arguments are never retained.
                        facts.note_auth_attempt(AuthMechanism::Login, limits);
                        pending_auth_tag = Some(tag);
                        facts.note_excerpt("LOGIN");
                    }
                    "AUTHENTICATE" => {
                        let mechanism_token = parts.get(2).cloned().unwrap_or_default();
                        facts
                            .note_auth_attempt(AuthMechanism::from_token(&mechanism_token), limits);
                        pending_auth_tag = Some(tag);
                        facts.note_excerpt("AUTHENTICATE");
                    }
                    _ => {}
                }
                if (verb == "LOGIN" || verb == "AUTHENTICATE") && facts.starttls_requested {
                    facts.auth_after_starttls_request = true;
                }
            }
            Direction::Server => {
                if upper.starts_with("* CAPABILITY") {
                    let capability_tokens = tokens(&text, 16);
                    for token in capability_tokens.into_iter().skip(2) {
                        facts.add_capability(&token, limits);
                    }
                    continue;
                }
                if pending_starttls_tag.is_some() {
                    if let Some(outcome) = tagged_outcome(&text, pending_starttls_tag.as_deref()) {
                        facts.starttls_reply = Some(outcome);
                        if outcome {
                            upgrade_accepted_at = Some(index);
                        }
                        if let Some(code) = reply_code(&text) {
                            facts.note_excerpt(&redacted_exchange("STARTTLS", Some(&code)));
                        }
                        pending_starttls_tag = None;
                    }
                    continue;
                }
                if pending_auth_tag.is_some() {
                    if let Some(outcome) = tagged_outcome(&text, pending_auth_tag.as_deref()) {
                        facts.note_auth_outcome(outcome);
                        if let Some(code) = reply_code(&text) {
                            facts.note_excerpt(&redacted_exchange("AUTH", Some(&code)));
                        }
                        pending_auth_tag = None;
                    }
                    continue;
                }
            }
        }
    }

    // Positive downgrade indicator: upgrade accepted, no handshake, yet the
    // client kept issuing IMAP commands in the clear.
    if let Some(accepted_index) = upgrade_accepted_at
        && trace.tls.is_none()
        && trace
            .lines
            .iter()
            .skip(accepted_index.saturating_add(1))
            .any(|line| {
                line.direction == Direction::Client
                    && command_verb(line.text.as_str())
                        .map(|verb| verb != "LOGOUT")
                        .unwrap_or(false)
            })
    {
        facts.application_data_after_accepted_upgrade = true;
    }

    finalize(trace, analyzed_as, facts, limits, examined)
}

/// Interpret a tagged reply for `pending_tag`: `Some(true)` for `OK`,
/// `Some(false)` for `NO`/`BAD`.
fn tagged_outcome(line: &str, pending_tag: Option<&str>) -> Option<bool> {
    let expected = pending_tag?;
    let parts = tokens(line, 3);
    let tag = parts.first()?;
    if !tag.eq_ignore_ascii_case(expected) {
        return None;
    }
    match parts.get(1).map(|status| status.to_ascii_uppercase()) {
        Some(status) if status == "OK" => Some(true),
        Some(status) if status == "NO" || status == "BAD" => Some(false),
        _ => None,
    }
}
