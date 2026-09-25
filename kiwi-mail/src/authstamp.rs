//! Authentication-Results stamping (T-232).
//!
//! Runs the deterministic `kiwi-mailauth` verdict set (SPF / DKIM / DMARC)
//! against a received message and produces the two artefacts the rest of the
//! system consumes:
//!
//! 1. an RFC 8601 `Authentication-Results` header value, and
//! 2. an [`AuthStamp`] record holding the parsed verdicts + evidence refs,
//!    persisted by the store so the UI security pill renders real values.
//!
//! ## Determinism and trust
//!
//! - The DNS seam is **injected** ([`kiwi_mailauth::dns::DnsResolver`]). This
//!   module never constructs a live resolver, so the whole path is testable
//!   offline with `MockResolver` and `kiwi-mail` stays free of network I/O.
//! - `now_unix` is a **parameter**, never the system clock (contract Â§1).
//! - Per `docs/SECURITY.md` rules 1/2: this stamps **evidence**, not findings.
//!   `temperror` means "could not check" and must never render as a failure;
//!   `none` means "no record published" and is explicitly not a failure.
//! - SPF needs a *connection* IP that an IMAP/POP3 fetch does not have. We
//!   therefore stamp SPF as `none` with an explicit comment unless the caller
//!   supplies receipt context. Inventing a sender IP would be fabricating a
//!   security finding.

use std::net::IpAddr;

use kiwi_mailauth::DomainName;
use kiwi_mailauth::dkim::{DkimInput, DkimOutput, DkimResult};
use kiwi_mailauth::dmarc::{DmarcInput, DmarcOutput, DmarcVerdict};
use kiwi_mailauth::dns::DnsResolver;
use kiwi_mailauth::spf::{SpfInput, SpfResult};

use crate::authrisk::{AuthRisk, derive_auth_risk};
use crate::mime::ParsedMessage;
use crate::store::{AuthVerdictComparison, UpstreamAuthEvidence, UpstreamAuthVerdict};

/// Value KIWI advertises in the `authserv-id` position of the stamped header.
pub const AUTH_SERV_ID: &str = "kiwi";

/// Cap on the stamped header value. RFC 5322 line length is 998 octets; we
/// stay well under it and truncate evidence comments rather than emit a
/// folded or over-long header.
const MAX_HEADER_LEN: usize = 900;

/// Cap on a single evidence comment embedded in the header.
const MAX_COMMENT_LEN: usize = 120;

/// Caps for untrusted upstream A-R evidence. Captured header values are already
/// bounded, but repeated fields/methods must not grow memory or the UI row.
const MAX_UPSTREAM_HEADERS: usize = 32;
const MAX_UPSTREAM_VERDICTS_PER_METHOD: usize = 32;
const MAX_AUTHSERV_ID_LEN: usize = 128;
const MAX_UPSTREAM_VERDICT_LEN: usize = 32;

/// Authentication-Results method verdict values defined by RFC 8601 §2.5.
const RFC8601_VERDICTS: &[&str] = &[
    "none",
    "pass",
    "fail",
    "softfail",
    "neutral",
    "temperror",
    "permerror",
    "hardfail",
];

/// Per-message verdicts + evidence, persisted alongside the message row.
///
/// Field names are stable wire spellings; `spf`/`dkim`/`dmarc` use the
/// contract vocabulary (`pass`/`fail`/`softfail`/`neutral`/`none`/
/// `temperror`/`permerror`) so the UI can map them without a second lookup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthStamp {
    /// SPF verdict string. `none` when no SMTP receipt context is available.
    pub spf: String,
    /// DKIM verdict string.
    pub dkim: String,
    /// DMARC verdict string.
    pub dmarc: String,
    /// DMARC policy that would apply (`none` when aligned or no record).
    pub dmarc_policy: String,
    /// DKIM signing domain (`d=`) when a signature parsed.
    pub dkim_domain: Option<String>,
    /// Key query actually used (`selector._domainkey.sdid`), evidence ref.
    pub dkim_key_query: Option<String>,
    /// DMARC record that decided, when one was found.
    pub dmarc_record: Option<String>,
    /// Bounded evidence strings (never a finding, never a body).
    pub spf_explanation: String,
    pub dkim_explanation: String,
    pub dmarc_explanation: String,
    /// Full RFC 8601 header value that was stamped (or would be).
    pub header_value: String,
    /// Authentication-Results received from upstream MTAs before this stamp
    /// (T-240). Evidence only; never treated as trusted or as a finding.
    pub upstream: UpstreamAuthEvidence,
    /// Deterministic per-message UI hint (T-249), computed at stamp time and
    /// persisted atomically with the verdicts. Never a finding or mail action.
    pub auth_risk: AuthRisk,
}

impl AuthStamp {
    /// True when a verdict is a *check failure* â€” the only state the UI pill
    /// should colour as a warning. `temperror` and `none` are explicitly not
    /// failures (contract Â§1: never invent findings).
    pub fn has_failure(&self) -> bool {
        matches!(self.dkim.as_str(), "fail" | "permerror")
            || matches!(self.dmarc.as_str(), "fail" | "permerror")
            || matches!(self.spf.as_str(), "fail" | "permerror")
    }

    /// True when a check could not be completed (`temperror`) â€” renders as
    /// "unknown", never as pass or fail.
    pub fn is_inconclusive(&self) -> bool {
        matches!(self.dkim.as_str(), "temperror")
            || matches!(self.dmarc.as_str(), "temperror")
            || matches!(self.spf.as_str(), "temperror")
    }
}

/// SMTP receipt context needed to evaluate SPF. Absent on IMAP/POP3 fetch,
/// where the connection IP and envelope sender are simply not knowable.
#[derive(Debug, Clone)]
pub struct SmtpReceipt {
    /// IP the message was received from.
    pub client_ip: IpAddr,
    /// RFC 5321 MAIL FROM domain (null sender â†’ HELO domain).
    pub mail_from_domain: Option<String>,
    /// HELO/EHLO hostname, for `%h`.
    pub helo: String,
    /// Envelope sender localpart, for `%l`.
    pub sender_local: String,
}

/// Truncate an evidence string to the per-comment budget, on a char boundary.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// Sanitize an explanation for safe inclusion in a header comment: collapse
/// whitespace and strip CR/LF so a hostile explanation can never inject a
/// header (SECURITY.md rule 9 — everything inbound is untrusted).
fn comment_safe(s: &str) -> String {
    let flat = s
        .replace(['\r', '\n'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    clip(&flat, MAX_COMMENT_LEN)
}

fn domain_of(addr: &str) -> Option<DomainName> {
    // Accept `user@host`, `<user@host>`, or a bare domain.
    let trimmed = addr.trim().trim_matches(|c| c == '<' || c == '>');
    let host = match trimmed.rsplit_once('@') {
        Some((_, h)) => h,
        None => trimmed,
    };
    DomainName::parse(host).ok()
}

fn first_dkim_header(parsed: &ParsedMessage) -> Option<String> {
    parsed
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("dkim-signature"))
        .map(|(_, v)| format!("DKIM-Signature: {v}"))
}

/// Whether the SPF identifier domain aligns with From under the discovered
/// DMARC `aspf` mode. Unlike DMARC authorization, this deliberately does not
/// require SPF to pass, so the T-249 failed rule can retain that evidence.
fn spf_identifier_aligned(
    spf_domain: Option<&DomainName>,
    from_domain: Option<&DomainName>,
    dmarc: &DmarcOutput,
) -> bool {
    let (Some(spf), Some(from), Some(record)) = (spf_domain, from_domain, dmarc.record.as_ref())
    else {
        return false;
    };
    match record.spf_align {
        kiwi_mailauth::dmarc::AlignMode::Strict => spf.as_str() == from.as_str(),
        kiwi_mailauth::dmarc::AlignMode::Relaxed => {
            kiwi_mailauth::org_domain_heuristic(spf) == kiwi_mailauth::org_domain_heuristic(from)
        }
    }
}

/// Split an RFC 8601 field on semicolons outside comments and quoted strings.
/// This prevents a hostile comment/value from manufacturing extra methods.
fn split_auth_results(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut comment_depth = 0_u32;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && c == '\\' {
            escaped = true;
            continue;
        }
        match c {
            '"' if comment_depth == 0 => quoted = !quoted,
            '(' if !quoted => comment_depth = comment_depth.saturating_add(1),
            ')' if !quoted => comment_depth = comment_depth.saturating_sub(1),
            ';' if !quoted && comment_depth == 0 => {
                parts.push(value[start..i].trim().to_string());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim().to_string());
    parts
}

fn verdict_token(value: &str) -> Option<String> {
    let token = value
        .split_whitespace()
        .next()?
        .trim_matches('"')
        .to_ascii_lowercase();
    (RFC8601_VERDICTS.contains(&token.as_str()) && token.len() <= MAX_UPSTREAM_VERDICT_LEN)
        .then_some(token)
}

/// Parse every top-level Authentication-Results field captured before KIWI's
/// own in-memory stamp. The parser intentionally makes no trust decision: any
/// authserv-id may contribute evidence, while malformed/unknown values remain
/// bounded absence-of-evidence.
pub fn parse_upstream_auth_results(headers: &[(String, String)]) -> UpstreamAuthEvidence {
    let mut out = UpstreamAuthEvidence {
        untrusted_relay: true,
        ..Default::default()
    };
    for (_name, value) in headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("authentication-results"))
        .take(MAX_UPSTREAM_HEADERS)
    {
        out.present = true;
        let parts = split_auth_results(value);
        let id = parts
            .first()
            .and_then(|s| s.split_whitespace().next())
            .filter(|s| {
                !s.is_empty() && s.len() <= MAX_AUTHSERV_ID_LEN && !s.contains(['\r', '\n'])
            });
        let Some(id) = id else {
            out.malformed_headers = out.malformed_headers.saturating_add(1);
            continue;
        };
        let owned = id.eq_ignore_ascii_case(AUTH_SERV_ID);
        let mut recognized = owned;
        if !out.authserv_ids.iter().any(|known| known == id) {
            out.authserv_ids.push(id.to_string());
        }
        for part in parts.iter().skip(1) {
            let Some((method, result)) = part.split_once('=') else {
                continue;
            };
            let method = method.trim().to_ascii_lowercase();
            if !matches!(method.as_str(), "spf" | "dkim" | "dmarc") {
                continue;
            }
            let Some(verdict) = verdict_token(result) else {
                continue;
            };
            if owned {
                continue;
            }
            recognized = true;
            let target = match method.as_str() {
                "spf" => &mut out.spf,
                "dkim" => &mut out.dkim,
                "dmarc" => &mut out.dmarc,
                _ => unreachable!(),
            };
            if target.len() < MAX_UPSTREAM_VERDICTS_PER_METHOD {
                target.push(UpstreamAuthVerdict {
                    authserv_id: id.to_string(),
                    verdict,
                });
            }
        }
        if !recognized {
            out.malformed_headers = out.malformed_headers.saturating_add(1);
        }
    }
    if out.present {
        out.untrusted_relay = false;
    }
    out
}

/// Add one comparison row for each upstream result. Only exact pass/fail
/// opposites are discrepancies; `none`, softfail, and errors are not silently
/// promoted to pass or failure.
pub fn compare_upstream_verdicts(
    upstream: &mut UpstreamAuthEvidence,
    local_spf: &str,
    local_dkim: &str,
    local_dmarc: &str,
) {
    for (method, verdicts, local) in [
        ("spf", &upstream.spf, local_spf),
        ("dkim", &upstream.dkim, local_dkim),
        ("dmarc", &upstream.dmarc, local_dmarc),
    ] {
        for result in verdicts {
            upstream.comparisons.push(AuthVerdictComparison {
                method: method.to_string(),
                upstream_verdict: result.verdict.clone(),
                local_verdict: local.to_string(),
                discrepancy: matches!(
                    (result.verdict.as_str(), local),
                    ("pass", "fail") | ("fail", "pass")
                ),
            });
        }
    }
}

/// Evaluate SPF/DKIM/DMARC for one message and build the stamp.
///
/// `raw` is the received bytes (used for the DKIM body hash and header set);
/// `parsed` is the bounded summary from [`crate::mime::parse_message`].
/// `receipt` is optional â€” without it SPF is stamped `none` with an explicit
/// comment (see module docs).
pub fn evaluate<R: DnsResolver>(
    dns: &R,
    parsed: &ParsedMessage,
    raw: &[u8],
    now_unix: i64,
    receipt: Option<&SmtpReceipt>,
) -> AuthStamp {
    // --- SPF -------------------------------------------------------------
    let (spf_result, spf_expl) = match receipt {
        None => (
            SpfResult::None,
            "no SMTP receipt context at IMAP/POP3 ingest; not evaluated".to_string(),
        ),
        Some(r) => match r.mail_from_domain.as_deref().and_then(domain_of) {
            None => (
                SpfResult::None,
                "no usable MAIL FROM domain; not evaluated".to_string(),
            ),
            Some(check_domain) => {
                let input = SpfInput {
                    check_domain,
                    sender_ip: r.client_ip,
                    helo: r.helo.clone(),
                    sender_local: r.sender_local.clone(),
                };
                match kiwi_mailauth::spf::evaluate(dns, &input) {
                    Ok(o) => (o.result, o.explanation),
                    // A record that will not parse is a permanent error, not a
                    // crash: the verdict vocabulary has a slot for it.
                    Err(_) => (
                        SpfResult::PermError,
                        "SPF record malformed or unusable".to_string(),
                    ),
                }
            }
        },
    };
    let spf_domain = receipt
        .and_then(|r| r.mail_from_domain.as_deref())
        .and_then(domain_of);
    let spf_pass = spf_result == SpfResult::Pass;

    // --- DKIM ------------------------------------------------------------
    let dkim_out: DkimOutput = match first_dkim_header(parsed) {
        None => DkimOutput {
            result: DkimResult::None,
            signature: None,
            key_query: None,
            explanation: "no DKIM-Signature header present".to_string(),
        },
        Some(signature_header) => {
            let input = DkimInput {
                signature_header,
                headers: parsed.headers.clone(),
                body: raw.to_vec(),
                now_unix,
            };
            kiwi_mailauth::dkim::verify(dns, &input)
        }
    };
    let dkim_pass = dkim_out.result == DkimResult::Pass;
    let dkim_domain = dkim_out
        .signature
        .as_ref()
        .and_then(|s| DomainName::parse(&s.sdid).ok());

    // --- DMARC -----------------------------------------------------------
    // Absent From domain → no identifier to protect → `none`, never a guess.
    let from_domain = parsed.from.first().and_then(|a| domain_of(&a.email));
    let (dmarc_out, dmarc_expl) = match from_domain.clone() {
        None => (
            DmarcOutput {
                result: DmarcVerdict::None,
                policy_applied: kiwi_mailauth::dmarc::DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: "no parsable From domain; DMARC not evaluated".to_string(),
            },
            "no parsable From domain; DMARC not evaluated".to_string(),
        ),
        Some(from_domain) => {
            let input = DmarcInput {
                from_domain: from_domain.clone(),
                // Without receipt context there is no SPF identity to align.
                spf_domain: spf_domain.clone().unwrap_or_else(|| from_domain.clone()),
                spf_pass,
                dkim_domain: dkim_domain.clone(),
                dkim_pass,
                org_override: None,
                // Caller-supplied determinism: no RNG, no clock.
                sample_roll: None,
            };
            let o = kiwi_mailauth::dmarc::evaluate(dns, &input);
            let expl = o.explanation.clone();
            (o, expl)
        }
    };

    let header_value = render_header(
        &spf_result,
        &dkim_out,
        &dmarc_out,
        dkim_domain.as_ref().map(|d| d.as_str()),
        &spf_expl,
        &dkim_out.explanation,
        &dmarc_expl,
    );
    // Parse the pre-existing A-R fields before constructing KIWI's in-memory
    // stamp. Raw .eml bytes are never rewritten, so DKIM-covered bytes remain
    // byte-for-byte intact.
    let mut upstream = parse_upstream_auth_results(&parsed.headers);
    compare_upstream_verdicts(
        &mut upstream,
        spf_result.as_str(),
        dkim_out.result.as_str(),
        dmarc_out.result.as_str(),
    );
    let discrepancy = upstream.has_discrepancy();
    let auth_risk = derive_auth_risk(
        spf_result.as_str(),
        dkim_out.result.as_str(),
        dmarc_out.result.as_str(),
        spf_identifier_aligned(spf_domain.as_ref(), from_domain.as_ref(), &dmarc_out),
        upstream.present && !upstream.authserv_ids.is_empty(),
        upstream.untrusted_relay,
        discrepancy,
    );

    AuthStamp {
        spf: spf_result.as_str().to_string(),
        dkim: dkim_out.result.as_str().to_string(),
        dmarc: dmarc_out.result.as_str().to_string(),
        dmarc_policy: dmarc_out.policy_applied.as_str().to_string(),
        dkim_domain: dkim_domain.map(|d| d.as_str().to_string()),
        dkim_key_query: dkim_out.key_query.clone(),
        dmarc_record: dmarc_out.record.as_ref().map(|r| r.raw.clone()),
        spf_explanation: clip(&spf_expl, 500),
        dkim_explanation: clip(&dkim_out.explanation, 500),
        dmarc_explanation: clip(&dmarc_expl, 500),
        header_value,
        upstream,
        auth_risk,
    }
}

/// Seam that lets an ingest path stamp messages without `kiwi-mail` ever
/// constructing a resolver itself.
///
/// Implemented for every [`DnsResolver`]. Passing `None` to an ingest path
/// means "no DNS available" and the path then **writes no stamp at all** —
/// it does not run the evaluation against an empty resolver, because a stub
/// resolver's `NXDOMAIN` is an artefact of the stub, not evidence that a DKIM
/// key is missing. A missing stamp reads as "not evaluated", which is
/// distinct from a `none` verdict.
pub trait AuthSealer {
    /// Evaluate and return the stamp for one received message.
    fn evaluate_and_stamp(
        &self,
        parsed: &ParsedMessage,
        raw: &[u8],
        now_unix: i64,
        receipt: Option<&SmtpReceipt>,
    ) -> AuthStamp;
}

impl<R: DnsResolver> AuthSealer for R {
    fn evaluate_and_stamp(
        &self,
        parsed: &ParsedMessage,
        raw: &[u8],
        now_unix: i64,
        receipt: Option<&SmtpReceipt>,
    ) -> AuthStamp {
        evaluate(self, parsed, raw, now_unix, receipt)
    }
}

fn render_header(
    spf: &SpfResult,
    dkim: &DkimOutput,
    dmarc: &DmarcOutput,
    dkim_domain: Option<&str>,
    spf_expl: &str,
    dkim_expl: &str,
    dmarc_expl: &str,
) -> String {
    let mut v = format!("{AUTH_SERV_ID}; spf={}", spf.as_str());
    if let Some(d) = dkim_domain {
        v.push_str(&format!(" header.d={d}"));
    }
    v.push_str(&format!("; dkim={}", dkim.result.as_str()));
    v.push_str(&format!("; dmarc={}", dmarc.result.as_str()));
    if dmarc.result == DmarcVerdict::Fail {
        v.push_str(&format!(" (p={})", dmarc.policy_applied.as_str()));
    }
    // One bounded comment per method keeps the line useful without growing
    // past MAX_HEADER_LEN.
    v.push_str(&format!("; spf_comment={}", comment_safe(spf_expl)));
    v.push_str(&format!("; dkim_comment={}", comment_safe(dkim_expl)));
    v.push_str(&format!("; dmarc_comment={}", comment_safe(dmarc_expl)));
    clip(&v, MAX_HEADER_LEN)
}

/// Prepend KIWI's `Authentication-Results` to a copy of the raw message.
///
/// Existing upstream A-R fields are deliberately preserved. KIWI's field goes
/// first, so consumers applying RFC 8601 precedence encounter our stamp before
/// upstream claims. An attacker pre-seeded A-R field can never suppress ours.
/// The ingest path does not call this on stored `.eml` bytes; it persists the
/// returned header value as evidence and leaves the received bytes untouched.
pub fn stamp_raw_bytes(raw: &[u8], header_value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + header_value.len() + 32);
    let mut rest = raw;
    // Preserve an mbox `From ` separator line if present.
    if rest.starts_with(b"From ")
        && let Some(nl) = rest.iter().position(|b| *b == b'\n')
    {
        out.extend_from_slice(&rest[..=nl]);
        rest = &rest[nl + 1..];
    }
    out.extend_from_slice(format!("Authentication-Results: {header_value}\r\n").as_bytes());
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mailauth::dns::MockResolver;

    fn raw_with(headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut s = String::new();
        for (k, v) in headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s.push_str(body);
        s.into_bytes()
    }

    fn parsed_of(raw: &[u8]) -> ParsedMessage {
        crate::mime::parse_message(raw).expect("fixture parses")
    }

    const NOW: i64 = 1_760_000_000;

    fn receipt(ip: &str) -> SmtpReceipt {
        SmtpReceipt {
            client_ip: ip.parse().unwrap(),
            mail_from_domain: Some("example.com".into()),
            helo: "mail.example.com".into(),
            sender_local: "a".into(),
        }
    }

    #[test]
    fn parses_authserv_id_and_all_supported_verdicts() {
        let headers = vec![(
            "authentication-results".into(),
            "mx.example.net; spf=pass smtp.mailfrom=a.example; dkim=pass header.d=a.example; dmarc=fail (p=reject)".into(),
        )];
        let got = parse_upstream_auth_results(&headers);
        assert!(got.present);
        assert!(!got.untrusted_relay);
        assert_eq!(got.authserv_ids, ["mx.example.net"]);
        assert_eq!(got.spf[0].verdict, "pass");
        assert_eq!(got.dkim[0].verdict, "pass");
        assert_eq!(got.dmarc[0].verdict, "fail");
        assert_eq!(got.malformed_headers, 0);
    }

    #[test]
    fn pass_fail_conflicts_are_evidence_rows_not_findings() {
        let headers = vec![
            (
                "Authentication-Results".into(),
                "mx.one; spf=fail; dkim=pass".into(),
            ),
            (
                "authentication-results".into(),
                "mx.two; dkim=fail; dmarc=pass".into(),
            ),
        ];
        let mut got = parse_upstream_auth_results(&headers);
        compare_upstream_verdicts(&mut got, "none", "pass", "fail");
        assert_eq!(got.authserv_ids, ["mx.one", "mx.two"]);
        let conflicts: Vec<_> = got.comparisons.iter().filter(|c| c.discrepancy).collect();
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.iter().any(|c| c.method == "dkim"
            && c.upstream_verdict == "fail"
            && c.local_verdict == "pass"));
        assert!(conflicts.iter().any(|c| c.method == "dmarc"
            && c.upstream_verdict == "pass"
            && c.local_verdict == "fail"));
        assert!(got.has_discrepancy());
    }

    #[test]
    fn honest_none_temperror_and_softfail_are_not_discrepancies() {
        let headers = vec![(
            "authentication-results".into(),
            "mx.example; spf=pass; dkim=temperror; dmarc=softfail".into(),
        )];
        let mut got = parse_upstream_auth_results(&headers);
        compare_upstream_verdicts(&mut got, "none", "temperror", "fail");
        assert!(!got.has_discrepancy());
        assert_eq!(got.comparisons.len(), 3, "both verdicts remain visible");
    }

    #[test]
    fn missing_header_is_notable_untrusted_relay_evidence() {
        let got = parse_upstream_auth_results(&[]);
        assert!(!got.present);
        assert!(got.untrusted_relay);
        assert!(got.comparisons.is_empty());
        assert!(!got.has_discrepancy());
    }

    #[test]
    fn malformed_and_comment_injection_are_bounded() {
        let headers = vec![
            ("authentication-results".into(), "; spf=pass".into()),
            (
                "authentication-results".into(),
                "mx.example; dkim=not-a-verdict; comment=(ignored; text); dmarc=fail; spf=pass"
                    .into(),
            ),
        ];
        let got = parse_upstream_auth_results(&headers);
        assert!(got.present);
        assert_eq!(got.malformed_headers, 1, "one header had no authserv-id");
        assert_eq!(got.spf.len(), 1, "comment semicolon did not split");
        assert_eq!(got.dkim.len(), 0);
        assert_eq!(got.dmarc[0].verdict, "fail");
    }

    #[test]
    fn evaluate_preserves_raw_bytes_while_parsing_existing_header() {
        let raw = raw_with(
            &[
                ("Authentication-Results", "mx.example; spf=pass"),
                ("From", "a@example.com"),
            ],
            "body\n",
        );
        let stamp = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.spf, "none");
        assert_eq!(stamp.upstream.spf[0].verdict, "pass");
        assert!(
            !stamp.upstream.has_discrepancy(),
            "client SPF none must not contradict MTA SPF pass"
        );
        let original = raw.clone();
        let stamped = stamp_raw_bytes(&raw, &stamp.header_value);
        assert_eq!(raw, original, "received bytes are not rewritten");
        let stamped = String::from_utf8(stamped).unwrap();
        assert!(stamped.starts_with("Authentication-Results: kiwi;"));
        assert!(stamped.contains("\r\nAuthentication-Results: mx.example; spf=pass\r\n"));
    }

    #[test]
    fn no_records_stamps_none_not_fail() {
        let raw = raw_with(&[("From", "a@example.com"), ("Subject", "hi")], "body\n");
        let stamp = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.spf, "none");
        assert_eq!(stamp.dkim, "none");
        assert_eq!(stamp.dmarc, "none");
        assert!(!stamp.has_failure(), "absent records are not failures");
        assert!(!stamp.is_inconclusive());
        assert!(stamp.header_value.starts_with("kiwi; spf=none"));
    }

    #[test]
    fn spf_is_none_without_receipt_never_fabricated() {
        let raw = raw_with(&[("From", "a@example.com")], "x\n");
        let stamp = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.spf, "none");
        assert!(stamp.spf_explanation.contains("no SMTP receipt context"));
    }

    #[test]
    fn spf_evaluated_when_receipt_supplied() {
        let raw = raw_with(&[("From", "a@example.com")], "x\n");
        let dns = MockResolver::new().with_txt("example.com", &["v=spf1 ip4:10.0.0.1 -all"]);
        let r = receipt("10.0.0.1");
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, Some(&r));
        assert_eq!(stamp.spf, "pass");
        assert!(!stamp.has_failure());
    }

    #[test]
    fn spf_fail_is_reported_as_failure() {
        let raw = raw_with(&[("From", "a@example.com")], "x\n");
        let dns = MockResolver::new().with_txt("example.com", &["v=spf1 -all"]);
        let r = receipt("203.0.113.9");
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, Some(&r));
        assert_eq!(stamp.spf, "fail");
        assert!(stamp.has_failure());
    }

    #[test]
    fn dmarc_none_without_record_is_not_a_failure() {
        let raw = raw_with(
            &[("From", "a@example.com"), ("Subject", "s")],
            "body line\n",
        );
        let stamp = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.dmarc, "none");
        assert!(!stamp.has_failure());
    }

    #[test]
    fn dmarc_fails_on_published_reject_with_no_aligned_identifier() {
        let raw = raw_with(
            &[("From", "a@example.com"), ("Subject", "s")],
            "body line\n",
        );
        let dns = MockResolver::new().with_txt(
            "_dmarc.example.com",
            &["v=DMARC1; p=reject; rua=mailto:r@example.com"],
        );
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.dmarc, "fail");
        assert_eq!(stamp.dmarc_policy, "reject");
        assert!(stamp.dmarc_record.is_some(), "evidence ref recorded");
        assert!(stamp.has_failure());
    }

    #[test]
    fn aligned_spf_failure_with_dmarc_failure_is_failed_hint() {
        let raw = raw_with(&[("From", "a@example.com")], "body\n");
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 -all"])
            .with_txt("_dmarc.example.com", &["v=DMARC1; p=reject; aspf=s"]);
        let stamp = evaluate(
            &dns,
            &parsed_of(&raw),
            &raw,
            NOW,
            Some(&receipt("203.0.113.9")),
        );
        assert_eq!(stamp.spf, "fail");
        assert_eq!(stamp.dmarc, "fail");
        assert_eq!(stamp.auth_risk, AuthRisk::Failed);
    }

    #[test]
    fn no_records_and_dmarc_fail_without_aligned_spf_fail_are_noted() {
        let raw = raw_with(&[("From", "a@example.com")], "body\n");
        let no_records = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(no_records.auth_risk, AuthRisk::Noted);

        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 -all"])
            .with_txt("other.test", &["v=spf1 -all"])
            .with_txt("_dmarc.example.com", &["v=DMARC1; p=reject; aspf=s"]);
        let unaligned = SmtpReceipt {
            mail_from_domain: Some("other.test".into()),
            ..receipt("203.0.113.9")
        };
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, Some(&unaligned));
        assert_eq!(stamp.spf, "fail");
        assert_eq!(stamp.dmarc, "fail");
        assert_eq!(stamp.auth_risk, AuthRisk::Noted);
    }

    #[test]
    fn dns_temporary_error_is_inconclusive_not_failure() {
        let raw = raw_with(&[("From", "a@example.com")], "x\n");
        let dns = MockResolver::new().with_temp_fail("_dmarc.example.com");
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.dmarc, "temperror");
        assert!(stamp.is_inconclusive());
        assert!(!stamp.has_failure(), "temperror must never render as fail");
    }

    #[test]
    fn unparsable_from_domain_is_not_evaluated() {
        let raw = raw_with(&[("From", "not-an-address")], "x\n");
        let stamp = evaluate(&MockResolver::new(), &parsed_of(&raw), &raw, NOW, None);
        assert_eq!(stamp.dmarc, "none");
        assert!(stamp.dmarc_explanation.contains("no parsable From domain"));
    }

    #[test]
    fn header_is_bounded_and_crlf_safe() {
        let raw = raw_with(&[("From", "a@example.com")], "x\n");
        let dns = MockResolver::new().with_temp_fail("_dmarc.example.com");
        let stamp = evaluate(&dns, &parsed_of(&raw), &raw, NOW, None);
        assert!(stamp.header_value.len() <= MAX_HEADER_LEN);
        assert!(!stamp.header_value.contains('\r'));
        assert!(!stamp.header_value.contains('\n'));
    }

    #[test]
    fn stamp_prepends_header_and_preserves_mbox_from() {
        let raw = b"From alice@example.com Mon Jan  1 00:00:00 2024\r\nSubject: x\r\n\r\nbody\r\n";
        let out = stamp_raw_bytes(raw, "kiwi; spf=none; dkim=none; dmarc=none");
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("From alice@example.com"));
        assert!(s.contains("\r\nAuthentication-Results: kiwi;"));
        assert!(s.ends_with("body\r\n"), "body preserved verbatim");
    }

    #[test]
    fn preseeded_ar_cannot_suppress_our_stamp() {
        let raw = b"Authentication-Results: attacker; spf=pass\r\nSubject: x\r\n\r\nbody\r\n";
        let out = stamp_raw_bytes(raw, "kiwi; spf=none");
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("Authentication-Results: kiwi; spf=none\r\n"));
        assert!(s.contains("\r\nAuthentication-Results: attacker; spf=pass\r\n"));
        assert!(s.ends_with("body\r\n"), "body preserved verbatim");
    }

    #[test]
    fn stamp_precedes_existing_headers() {
        let raw = b"Subject: x\r\nFrom: a@example.com\r\n\r\nbody\r\n";
        let out = stamp_raw_bytes(raw, "kiwi; dkim=none");
        let s = String::from_utf8(out).unwrap();
        let ari = s.find("Authentication-Results:").unwrap();
        let subj = s.find("Subject:").unwrap();
        assert!(ari < subj, "stamp is a top-level header");
    }

    #[test]
    fn hostile_explanation_cannot_inject_a_header() {
        let dirty = "bad\r\nX-Injected: yes";
        let safe = comment_safe(dirty);
        assert!(!safe.contains('\r'));
        assert!(!safe.contains('\n'));
    }
}
