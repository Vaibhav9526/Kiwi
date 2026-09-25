//! Transcript scripts — fixture loading + `S:`/`C:` line parsing
//! plus the protocol-aware matchers `server.rs` replays against.

#[derive(Debug)]
pub enum Step {
    /// `S:` line — bytes the server puts on the wire.
    Server(Vec<u8>),
    /// `C:` line — the client is expected to emit this.
    Client(String),
    /// Mid-transcript TLS upgrade point.
    TlsBoundary,
    /// `# EOF` — the client must go silent: no further line may arrive
    /// before the peer closes or the step timeout elapses. Fail-closed
    /// proofs (e.g. STARTTLS refusal) end the script with this so a
    /// wrongly-proceeding client can't leak bytes past the last `S:`.
    ExpectEof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Smtp,
    Imap,
    Pop3,
}

/// Load + parse a fixture by filename from `tests/fixtures/transcripts/`.
pub fn load(name: &str) -> Vec<Step> {
    let path = format!(
        "{}/../tests/fixtures/transcripts/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
    parse(&text)
}

pub fn parse(text: &str) -> Vec<Step> {
    let mut steps = Vec::new();
    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix("S:") {
            let mut line = rest.strip_prefix(' ').unwrap_or(rest).as_bytes().to_vec();
            line.extend_from_slice(b"\r\n");
            steps.push(Step::Server(line));
        } else if let Some(rest) = raw.strip_prefix("C:") {
            steps.push(Step::Client(
                rest.strip_prefix(' ').unwrap_or(rest).to_string(),
            ));
        } else if raw.contains("TLS handshake") {
            steps.push(Step::TlsBoundary);
        } else if raw.trim() == "# EOF" {
            steps.push(Step::ExpectEof);
        }
    }
    steps
}

/// Command verb of a client line (IMAP: token after the tag).
pub(crate) fn verb_of(proto: Proto, line: &str) -> &str {
    match proto {
        Proto::Imap => line.split_whitespace().nth(1).unwrap_or(""),
        _ => line.split_whitespace().next().unwrap_or(""),
    }
}

/// Does the actual client line satisfy the transcript's `C:` expectation?
pub(crate) fn client_matches(proto: Proto, expected: &str, actual: &str) -> bool {
    if actual == expected {
        return true;
    }
    // Verb-matched lines: creds carry dummies; EHLO/HELO args are the
    // client's configured name, not the fixture's.
    if expected.contains("REDACTED")
        || matches!(
            verb_of(proto, expected),
            "AUTH" | "PASS" | "AUTHENTICATE" | "LOGIN" | "EHLO" | "HELO"
        )
    {
        return verb_of(proto, expected) == verb_of(proto, actual);
    }
    match proto {
        Proto::Imap => {
            // Strip the tag and normalize parens/spacing for compare.
            let norm = |s: &str| {
                s.split_once(' ')
                    .map(|x| x.1)
                    .unwrap_or(s)
                    .replace(['(', ')', ' ', '"'], "")
            };
            norm(expected) == norm(actual)
        }
        _ => {
            // Tolerate extra params our client adds (e.g. MAIL FROM SIZE=).
            // An empty fixture line is an exact empty wire line, never a
            // wildcard that can consume the next SMTP DATA terminator.
            !expected.is_empty() && actual.starts_with(expected)
        }
    }
}

/// Generic answers for client probes not scripted by the transcript.
pub(crate) fn offscript_reply(proto: Proto, actual: &str) -> Option<Vec<u8>> {
    match proto {
        Proto::Pop3 if actual.trim() == "CAPA" => Some(b"-ERR unsupported\r\n".to_vec()),
        Proto::Imap if verb_of(Proto::Imap, actual) == "CAPABILITY" => {
            let tag = actual.split_whitespace().next().unwrap_or("A0000");
            Some(
                format!(
                    "* CAPABILITY IMAP4rev2 UIDPLUS LITERAL+ IDLE\r\n{tag} OK CAPABILITY completed\r\n"
                )
                .into_bytes(),
            )
        }
        _ => None,
    }
}

/// IMAP replies must echo the tag the client actually used — rewrite the
/// fixture's literal tag on tagged `S:` lines (untagged `*`/`+` untouched).
pub(crate) fn rewrite_tag(line: &[u8], tag: &str) -> Vec<u8> {
    if line.first().is_some_and(|b| b.is_ascii_alphabetic())
        && let Some(sp) = line.iter().position(|b| *b == b' ')
    {
        let mut out = tag.as_bytes().to_vec();
        out.extend_from_slice(&line[sp..]);
        return out;
    }
    line.to_vec()
}
