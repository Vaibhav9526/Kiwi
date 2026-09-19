//! SMTP / ESMTP analyzer.
//!
//! Recognizes the parts of the protocol the security rules depend on: the `AUTH`
//! capability list, the `STARTTLS` capability, the upgrade request and its reply,
//! the authentication mechanism actually used and its outcome.
//!
//! Only command verbs and reply codes leave this module — never credentials.

use super::{
    AnalysisOutcome, AnalyzerLimits, Direction, ProtocolTrace, TraceFacts, bounded_line,
    command_verb, finalize, redacted_exchange, reply_code, smtp_reply_outcome, tokens,
};
use crate::model::{AuthMechanism, Protocol};

/// Analyze an SMTP session trace.
///
/// `analyzed_as` is the dispatch decision (post-sniffing) and is what the
/// resulting session carries — never re-derive it here.
pub fn analyze(
    trace: &ProtocolTrace,
    limits: &AnalyzerLimits,
    analyzed_as: Protocol,
) -> AnalysisOutcome {
    let mut facts = TraceFacts::default();
    let mut awaiting_starttls_reply = false;
    let mut awaiting_auth_reply = false;
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
                let Some(verb) = command_verb(&text) else {
                    continue;
                };
                match verb.as_str() {
                    "STARTTLS" => {
                        facts.starttls_requested = true;
                        awaiting_starttls_reply = true;
                        facts.note_excerpt("STARTTLS");
                    }
                    "AUTH" => {
                        // `AUTH <mechanism> [initial-response]` — the initial
                        // response is a credential and is deliberately dropped.
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
                    let outcome = smtp_reply_outcome(&text);
                    facts.starttls_reply = outcome;
                    if outcome == Some(true) {
                        upgrade_accepted_at = Some(index);
                    }
                    awaiting_starttls_reply = false;
                    if let Some(code) = reply_code(&text) {
                        facts.note_excerpt(&redacted_exchange("STARTTLS", Some(&code)));
                    }
                    continue;
                }
                if awaiting_auth_reply {
                    if let Some(outcome) = smtp_reply_outcome(&text) {
                        facts.note_auth_outcome(outcome);
                        awaiting_auth_reply = false;
                        if let Some(code) = reply_code(&text) {
                            facts.note_excerpt(&redacted_exchange("AUTH", Some(&code)));
                        }
                    }
                    continue;
                }
                if upper.starts_with("250") {
                    collect_ehlo_keywords(&text, &mut facts, limits);
                }
            }
        }
    }

    // Positive downgrade indicator: the server accepted the upgrade, no TLS
    // handshake was observed, and the mail conversation continued in the clear.
    if let Some(accepted_index) = upgrade_accepted_at
        && trace.tls.is_none()
        && trace
            .lines
            .iter()
            .skip(accepted_index.saturating_add(1))
            .any(|line| match line.direction {
                Direction::Client => command_verb(line.text.as_str())
                    .map(|verb| verb != "QUIT")
                    .unwrap_or(false),
                Direction::Server => line.text.as_str().trim_start().starts_with("250"),
            })
    {
        facts.application_data_after_accepted_upgrade = true;
    }

    finalize(trace, analyzed_as, facts, limits, examined)
}

/// Collect `EHLO` keywords from a `250-…` capability line.
fn collect_ehlo_keywords(text: &str, facts: &mut TraceFacts, limits: &AnalyzerLimits) {
    let remainder = match text.get(3..) {
        Some(rest) => rest.trim_start_matches(['-', ' ']),
        None => return,
    };
    let mut parts = tokens(remainder, 10).into_iter();
    let Some(keyword) = parts.next() else {
        return;
    };
    if keyword.eq_ignore_ascii_case("AUTH") {
        facts.add_capability("AUTH", limits);
        for mechanism in parts {
            facts.add_capability(&mechanism, limits);
        }
    } else {
        facts.add_capability(&keyword, limits);
    }
}
