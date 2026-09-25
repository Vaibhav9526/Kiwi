//! DKIM (RFC 6376): tag-list parse, header/body canonicalization
//! (simple/relaxed), RSA-SHA256 + Ed25519 verify, `s._domainkey.d` key fetch.
//!
//! Verification is deterministic: the caller supplies `now_unix` for expiry
//! checks (never the system clock). Unknown tags are ignored, never fatal.

use serde::{Deserialize, Serialize};

use crate::dns::{DnsError, DnsResolver};
use crate::{DomainName, Error, MAX_CANON_BYTES};

/// Max raw DKIM-Signature header length (bounded evidence).
pub const MAX_SIG_HEADER_LEN: usize = 16 * 1024;
/// Max signed-header (`h=`) entries (bounded evidence).
pub const MAX_SIGNED_HEADERS: usize = 64;
/// Max signature age in seconds before `expired` (caller clock: `now_unix`).
pub const MAX_SIG_AGE_SECS: i64 = 14 * 24 * 3600;

/// DKIM verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DkimResult {
    /// Signature cryptographically valid.
    Pass,
    /// Signature present but invalid (bad crypto, wrong key, tampered).
    Fail,
    /// No usable DKIM signature on the message.
    None,
    /// Transient DNS failure fetching the key.
    TempError,
    /// Permanent error (bad tag-list, unsupported algorithm, bad key).
    PermError,
}

impl DkimResult {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Header canonicalization selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CanonHeader {
    /// RFC 6376 §3.4.1 — no changes except removing the b= value.
    Simple,
    /// RFC 6376 §3.4.2 — unfolding, lowercase field name, WSP compression.
    Relaxed,
}

/// Body canonicalization selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CanonBody {
    /// RFC 6376 §3.4.3 — CRLF-preserving, trailing empty lines stripped.
    Simple,
    /// RFC 6376 §3.4.4 — WSP compression, trailing empty lines stripped.
    Relaxed,
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigAlgorithm {
    /// `rsa-sha256` (the only rsa-sha variant this crate verifies).
    RsaSha256,
    /// `ed25519-sha256`.
    Ed25519Sha256,
}

/// Parsed DKIM-Signature tag-list (evidence fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimSignature {
    /// Signing Domain Identifier (`d=`).
    pub sdid: String,
    /// Selector (`s=`).
    pub selector: String,
    /// Algorithm (`a=`).
    pub algorithm: SigAlgorithm,
    /// Header canon (`c=` first token).
    pub header_canon: CanonHeader,
    /// Body canon (`c=` second token, default simple).
    pub body_canon: CanonBody,
    /// Signed header field names in order (`h=`).
    pub signed_headers: Vec<String>,
    /// Body hash (`bh=`, raw bytes).
    pub body_hash: Vec<u8>,
    /// Signature value (`b=`, raw bytes).
    pub signature: Vec<u8>,
    /// Body length limit (`l=`, optional).
    pub body_length: Option<u64>,
    /// Signature timestamp (`t=`, optional).
    pub timestamp: Option<i64>,
    /// Signature expiry (`x=`, optional).
    pub expiry: Option<i64>,
}

/// Input to one DKIM verification.
#[derive(Debug, Clone)]
pub struct DkimInput {
    /// Full raw DKIM-Signature header line(s) including the field name.
    pub signature_header: String,
    /// Raw message headers (name + value pairs, unfolded or not — the
    /// canonicalizer handles folding; first element SHOULD be the
    /// DKIM-Signature header itself for self-reference handling).
    pub headers: Vec<(String, String)>,
    /// Raw message body bytes (as received, any line endings).
    pub body: Vec<u8>,
    /// Unix seconds for expiry checks (caller-supplied clock).
    pub now_unix: i64,
}

/// Typed DKIM outcome (serializable into forensics evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimOutput {
    /// Verdict.
    pub result: DkimResult,
    /// Parsed signature fields (present when the tag-list parsed).
    pub signature: Option<DkimSignature>,
    /// Key-query name (`selector._domainkey.sdid`) when fetched.
    pub key_query: Option<String>,
    /// Evidence-grounded explanation (never a finding).
    pub explanation: String,
}

/// Parse a DKIM-Signature header value (everything after the colon).
/// Returns the parsed tag-list or a `Malformed` error (caller: permerror).
pub fn parse_signature(header_value: &str) -> Result<DkimSignature, Error> {
    if header_value.len() > MAX_SIG_HEADER_LEN {
        return Err(Error::TooLong);
    }
    let tags = split_tag_list(header_value)?;
    let get = |k: &str| -> Option<&str> {
        tags.iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.as_str())
    };
    let v = get("v").ok_or(Error::Malformed("dkim: missing v="))?;
    if v.trim() != "1" {
        return Err(Error::Malformed("dkim: unsupported version"));
    }
    let a = get("a").ok_or(Error::Malformed("dkim: missing a="))?;
    let algorithm = match a.trim() {
        "rsa-sha256" => SigAlgorithm::RsaSha256,
        "ed25519-sha256" => SigAlgorithm::Ed25519Sha256,
        _ => return Err(Error::Malformed("dkim: unsupported algorithm")),
    };
    let sdid_raw = get("d").ok_or(Error::Malformed("dkim: missing d="))?;
    let sdid = DomainName::parse(sdid_raw).map_err(|_| Error::Malformed("dkim: bad d="))?;
    let selector_raw = get("s").ok_or(Error::Malformed("dkim: missing s="))?;
    if selector_raw.is_empty()
        || selector_raw.len() > 63
        || !selector_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Malformed("dkim: bad s="));
    }
    let (header_canon, body_canon) = match get("c") {
        None => (CanonHeader::Simple, CanonBody::Simple),
        Some(c) => {
            let mut parts = c.split('/');
            let h = parts.next().unwrap_or("simple").trim();
            let b = parts.next().unwrap_or("simple").trim();
            if parts.next().is_some() {
                return Err(Error::Malformed("dkim: bad c="));
            }
            let hc = match h {
                "simple" => CanonHeader::Simple,
                "relaxed" => CanonHeader::Relaxed,
                _ => return Err(Error::Malformed("dkim: bad c=")),
            };
            let bc = match b {
                "simple" => CanonBody::Simple,
                "relaxed" => CanonBody::Relaxed,
                _ => return Err(Error::Malformed("dkim: bad c=")),
            };
            (hc, bc)
        }
    };
    let h_raw = get("h").ok_or(Error::Malformed("dkim: missing h="))?;
    let signed_headers: Vec<String> = h_raw
        .split(':')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .take(MAX_SIGNED_HEADERS + 1)
        .collect();
    if signed_headers.is_empty() || signed_headers.len() > MAX_SIGNED_HEADERS {
        return Err(Error::Malformed("dkim: bad h="));
    }
    for name in &signed_headers {
        if name.len() > 128 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Error::Malformed("dkim: bad h= name"));
        }
    }
    let bh_b64 = get("bh").ok_or(Error::Malformed("dkim: missing bh="))?;
    let body_hash = decode_b64_ws(bh_b64).map_err(|_| Error::Malformed("dkim: bad bh="))?;
    let b_b64 = get("b").ok_or(Error::Malformed("dkim: missing b="))?;
    let signature = decode_b64_ws(b_b64).map_err(|_| Error::Malformed("dkim: bad b="))?;
    if body_hash.is_empty()
        || body_hash.len() > 128
        || signature.is_empty()
        || signature.len() > 1024
    {
        return Err(Error::Malformed("dkim: bad hash/signature length"));
    }
    let body_length = match get("l") {
        None => None,
        Some(s) => {
            let n: u64 = s
                .trim()
                .parse()
                .map_err(|_| Error::Malformed("dkim: bad l="))?;
            Some(n)
        }
    };
    let timestamp = match get("t") {
        None => None,
        Some(s) => {
            let n: i64 = s
                .trim()
                .parse()
                .map_err(|_| Error::Malformed("dkim: bad t="))?;
            if n < 0 {
                return Err(Error::Malformed("dkim: bad t="));
            }
            Some(n)
        }
    };
    let expiry = match get("x") {
        None => None,
        Some(s) => {
            let n: i64 = s
                .trim()
                .parse()
                .map_err(|_| Error::Malformed("dkim: bad x="))?;
            if n < 0 {
                return Err(Error::Malformed("dkim: bad x="));
            }
            Some(n)
        }
    };
    if let (Some(t), Some(x)) = (timestamp, expiry)
        && x <= t
    {
        return Err(Error::Malformed("dkim: x must be after t"));
    }
    // q= defaults to dns/txt; anything else is permerror (no alternate
    // query method implemented).
    if let Some(q) = get("q")
        && q.trim() != "dns/txt"
    {
        return Err(Error::Malformed("dkim: unsupported q="));
    }
    Ok(DkimSignature {
        sdid: sdid.as_str().to_string(),
        selector: selector_raw.to_string(),
        algorithm,
        header_canon,
        body_canon,
        signed_headers,
        body_hash,
        signature,
        body_length,
        timestamp,
        expiry,
    })
}

/// Split a `tag=value; …` list. First `=` per `;`-part is the separator.
fn split_tag_list(s: &str) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or(Error::Malformed("dkim: bad tag"))?;
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() || key.len() > 32 || !key.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(Error::Malformed("dkim: bad tag name"));
        }
        if out.len() >= 32 {
            return Err(Error::Malformed("dkim: too many tags"));
        }
        if out.iter().any(|(ek, _): &(String, String)| *ek == key) {
            return Err(Error::Malformed("dkim: duplicate tag"));
        }
        let val = v.trim().to_string();
        if val.len() > MAX_SIG_HEADER_LEN {
            return Err(Error::TooLong);
        }
        out.push((key, val));
    }
    if out.is_empty() {
        return Err(Error::Malformed("dkim: empty tag list"));
    }
    Ok(out)
}

fn decode_b64_ws(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || clean.len() > 4096 {
        return Err(());
    }
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .map_err(|_| ())
}

/// Verify one message: parse → expiry (`now_unix`) → body-hash → key
/// fetch (`selector._domainkey.sdid`) → signature verify. DNS errors give
/// `temperror`; unparseable/unsupported gives `permerror`; bad crypto or
/// tampered content gives `fail`.
pub fn verify<R: DnsResolver>(dns: &R, input: &DkimInput) -> DkimOutput {
    let (field_name, field_value) = match input.signature_header.split_once(':') {
        Some((name, value)) if name.trim().eq_ignore_ascii_case("DKIM-Signature") => {
            (name.trim().to_string(), value.to_string())
        }
        _ => {
            return DkimOutput {
                result: DkimResult::None,
                signature: None,
                key_query: None,
                explanation: "no DKIM-Signature header present".to_string(),
            };
        }
    };
    let sig = match parse_signature(&field_value) {
        Ok(s) => s,
        Err(_) => {
            return DkimOutput {
                result: DkimResult::PermError,
                signature: None,
                key_query: None,
                explanation: "DKIM-Signature tag-list unparseable".to_string(),
            };
        }
    };
    if let Some(x) = sig.expiry {
        if input.now_unix > x {
            return DkimOutput {
                result: DkimResult::Fail,
                signature: Some(sig),
                key_query: None,
                explanation: "DKIM signature expired (x= passed)".to_string(),
            };
        }
    } else if let Some(t) = sig.timestamp
        && input.now_unix.saturating_sub(t) > MAX_SIG_AGE_SECS
    {
        return DkimOutput {
            result: DkimResult::Fail,
            signature: Some(sig),
            key_query: None,
            explanation: "DKIM signature too old".to_string(),
        };
    }
    let canon_body = canon_body_bytes(sig.body_canon, &input.body, sig.body_length);
    let body_digest = sha256(&canon_body);
    if body_digest.as_slice() != sig.body_hash.as_slice() {
        return DkimOutput {
            result: DkimResult::Fail,
            signature: Some(sig),
            key_query: None,
            explanation: "DKIM body hash mismatch".to_string(),
        };
    }
    let query = format!("{}._domainkey.{}", sig.selector, sig.sdid);
    let query_name = match DomainName::parse(&query) {
        Ok(d) => d,
        Err(_) => {
            return DkimOutput {
                result: DkimResult::PermError,
                signature: Some(sig),
                key_query: None,
                explanation: "DKIM key query name invalid".to_string(),
            };
        }
    };
    let txts = match dns.lookup_txt(&query_name) {
        Ok(t) => t,
        Err(DnsError::NxDomain) => {
            return DkimOutput {
                result: DkimResult::Fail,
                signature: Some(sig),
                key_query: Some(query),
                explanation: "DKIM key not found".to_string(),
            };
        }
        Err(DnsError::Temp(e)) => {
            return DkimOutput {
                result: DkimResult::TempError,
                signature: Some(sig),
                key_query: Some(query),
                explanation: format!("DKIM key fetch DNS error: {e}"),
            };
        }
    };
    let key_txt = match select_dkim_key(&txts) {
        Some(k) => k,
        None => {
            return DkimOutput {
                result: DkimResult::PermError,
                signature: Some(sig),
                key_query: Some(query),
                explanation: "DKIM key record missing or revoked".to_string(),
            };
        }
    };
    let key = match parse_key_record(&key_txt, sig.algorithm) {
        Ok(k) => k,
        Err(_) => {
            return DkimOutput {
                result: DkimResult::PermError,
                signature: Some(sig),
                key_query: Some(query),
                explanation: "DKIM key record unparseable".to_string(),
            };
        }
    };
    let signed = header_hash_input(
        sig.header_canon,
        &input.headers,
        &sig.signed_headers,
        &field_name,
        &field_value,
    );
    let ok = match (sig.algorithm, key) {
        (SigAlgorithm::RsaSha256, KeyMaterial::Rsa(pubkey)) => {
            verify_rsa_sha256(&pubkey, &signed, &sig.signature)
        }
        (SigAlgorithm::Ed25519Sha256, KeyMaterial::Ed25519(vk)) => {
            verify_ed25519(&vk, &signed, &sig.signature)
        }
        _ => false,
    };
    if ok {
        DkimOutput {
            result: DkimResult::Pass,
            signature: Some(sig),
            key_query: Some(query),
            explanation: "DKIM signature valid".to_string(),
        }
    } else {
        DkimOutput {
            result: DkimResult::Fail,
            signature: Some(sig),
            key_query: Some(query),
            explanation: "DKIM signature verification failed".to_string(),
        }
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Canonicalize the body and apply the `l=` (body length count) limit.
///
/// RFC 6376 §3.7 (normative): the body is "canonicalized using the body
/// canonicalization algorithm specified in the `c=` tag **and then
/// truncated** to the length specified in the `l=` tag"; §3.4.5 repeats
/// that "the body length count MUST be calculated following the
/// canonicalization algorithm; for example, any whitespace ignored by a
/// canonicalization algorithm is not included as part of the body length
/// count". Truncation therefore happens here, *after* canonicalization —
/// `l=0` leaves a completely unsigned body (§3.4.5). Checked against the
/// RFC 6376 errata list (2026-09-25): no verified erratum changes this
/// ordering.
///
/// Canonicalization proper:
/// - [`CanonBody::Simple`] (§3.4.3): trailing empty lines are removed and
///   exactly one CRLF terminates the body — an empty body becomes a
///   single CRLF (SHA-256 `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=`).
/// - [`CanonBody::Relaxed`] (§3.4.4): WSP runs collapse to a single SP,
///   trailing WSP per line and trailing empty lines are removed, and a
///   CRLF is added only when the result is non-empty — an empty body
///   becomes the **null input** (SHA-256
///   `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`).
///
/// Bare LF/CR line endings are normalized to CRLF first (total handling
/// of non-conformant transports; see the module docs).
fn canon_body_bytes(canon: CanonBody, body: &[u8], length: Option<u64>) -> Vec<u8> {
    let mut out = canon_body_untruncated(canon, body);
    if let Some(n) = length {
        let n = (n as usize).min(out.len());
        out.truncate(n);
    }
    out
}

/// Body canonicalization proper (RFC 6376 §3.4.3 / §3.4.4) without `l=`.
fn canon_body_untruncated(canon: CanonBody, body: &[u8]) -> Vec<u8> {
    let mut capped: &[u8] = body;
    if capped.len() > MAX_CANON_BYTES {
        capped = &capped[..MAX_CANON_BYTES];
    }
    // Normalize all line endings to CRLF first.
    let text = String::from_utf8_lossy(capped);
    let mut norm = String::with_capacity(text.len().saturating_add(64));
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\r' {
            if it.peek() == Some(&'\n') {
                it.next();
            }
            norm.push_str("\r\n");
        } else if c == '\n' {
            norm.push_str("\r\n");
        } else {
            norm.push(c);
        }
    }
    let mut bytes = norm.into_bytes();
    match canon {
        CanonBody::Simple => {
            // Strip trailing empty lines; ensure exactly one CRLF at end
            // (empty body becomes a single CRLF).
            while bytes.ends_with(b"\r\n\r\n") {
                bytes.truncate(bytes.len().saturating_sub(2));
            }
            if !bytes.ends_with(b"\r\n") {
                bytes.extend_from_slice(b"\r\n");
            }
            bytes
        }
        CanonBody::Relaxed => {
            let s = String::from_utf8_lossy(&bytes);
            let mut lines: Vec<String> = Vec::new();
            for line in s.split("\r\n") {
                // Compress WSP runs to single SP, strip trailing WSP.
                let mut o = String::with_capacity(line.len());
                let mut in_ws = false;
                for c in line.chars() {
                    if c == ' ' || c == '\t' {
                        if !in_ws {
                            o.push(' ');
                        }
                        in_ws = true;
                    } else {
                        o.push(c);
                        in_ws = false;
                    }
                }
                while o.ends_with(' ') {
                    o.pop();
                }
                lines.push(o);
            }
            // Strip trailing empty lines.
            while lines.last().is_some_and(|l| l.is_empty()) {
                lines.pop();
            }
            let mut out = String::new();
            for l in &lines {
                out.push_str(l);
                out.push_str("\r\n");
            }
            out.into_bytes()
        }
    }
}

/// Canonicalize the hash-step-2 input (RFC 6376 §3.7).
///
/// The verifier MUST pass, **in this order**:
///
/// 1. the header fields named in `h=`, *in `h=` order*, each
///    canonicalized and terminated with a single CRLF; a repeated name
///    selects the **last unused** occurrence (bottom-up, §5.4.2) and a
///    name with no occurrence contributes nothing (null input, §3.5 —
///    "nonexistent header fields do not contribute to the signature
///    computation");
/// 2. the DKIM-Signature field **under verification** (`dkim_name` /
///    `dkim_value`), `b=` value emptied, canonicalized and **without** a
///    trailing CRLF.
///
/// The field under verification is never selected by step 1 — §3.5
/// forbids listing it in its own `h=`, so an `h=` entry naming
/// `dkim-signature` refers to *other* DKIM-Signature fields in the
/// message (§3.5 "may include others").
fn header_hash_input(
    canon: CanonHeader,
    headers: &[(String, String)],
    signed: &[String],
    dkim_name: &str,
    dkim_value: &str,
) -> Vec<u8> {
    let self_value = dkim_value.trim();
    let mut used = vec![false; headers.len()];
    let mut out = Vec::new();
    for name in signed {
        // Last unused match, scanning from the bottom (§5.4.2).
        let mut found: Option<usize> = None;
        for (i, (hn, hv)) in headers.iter().enumerate().rev() {
            if used[i] || !hn.trim().eq_ignore_ascii_case(name) {
                continue;
            }
            // Never the DKIM-Signature field being verified (§3.7 step 2).
            if hv.trim() == self_value {
                continue;
            }
            found = Some(i);
            break;
        }
        if let Some(i) = found {
            used[i] = true;
            push_canon_header(&mut out, canon, &headers[i].0, &headers[i].1, true);
        }
    }
    // Bound the accumulated `h=` part, then append the field under
    // verification so the §3.7 tail can never be truncated away.
    let cap = MAX_CANON_BYTES.saturating_sub(MAX_SIG_HEADER_LEN + 2);
    if out.len() > cap {
        out.truncate(cap);
    }
    let emptied = empty_b_value(dkim_value);
    push_canon_header(&mut out, canon, dkim_name, &emptied, false);
    out
}

/// Append one canonicalized header field (RFC 6376 §3.4.1 / §3.4.2).
///
/// `value` is the raw text that followed the field-name colon as
/// transmitted — internal folding (CRLF + WSP) included, any terminating
/// CRLF excluded. `trailing_crlf` adds the field terminator: required for
/// `h=`-listed fields (§3.7 step 1), forbidden for the DKIM-Signature
/// field hashed in step 2.
fn push_canon_header(
    out: &mut Vec<u8>,
    canon: CanonHeader,
    name: &str,
    value: &str,
    trailing_crlf: bool,
) {
    match canon {
        CanonHeader::Simple => {
            // §3.4.1: "does not change header fields in any way. Header
            // fields MUST be presented ... exactly as they are in the
            // message ... header field names MUST NOT be case folded and
            // whitespace MUST NOT be changed" — so the field name (case and
            // any WSP before the colon included), the colon and the value
            // (including its folding) are copied verbatim; only the single
            // terminating CRLF is normalized. See §3.4.5 Example 2, where
            // the folded `B <SP> : <SP> Y <HTAB>` form is preserved.
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b":");
            out.extend_from_slice(value.trim_end_matches(['\r', '\n']).as_bytes());
        }
        CanonHeader::Relaxed => {
            // §3.4.2 in order: lowercase the field name; unfold (a CRLF
            // followed by WSP is removed); collapse WSP runs — including
            // those spanning a fold boundary — to a single SP; delete WSP
            // at the end of the value and around the colon.
            let mut o = String::with_capacity(value.len());
            let mut in_ws = false;
            for c in value.chars() {
                if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
                    in_ws = true;
                } else {
                    if in_ws {
                        o.push(' ');
                        in_ws = false;
                    }
                    o.push(c);
                }
            }
            out.extend_from_slice(name.trim().to_ascii_lowercase().as_bytes());
            out.extend_from_slice(b":");
            out.extend_from_slice(o.trim().as_bytes());
        }
    }
    if trailing_crlf {
        out.extend_from_slice(b"\r\n");
    }
}

/// Empty the `b=` tag value in a DKIM-Signature field value (for hashing).
///
/// RFC 6376 §3.7: the value of the `b=` tag "(including all surrounding
/// whitespace) deleted (i.e., treated as the empty string)". The tag name,
/// the optional FWS after it (`sig-b-tag = %x62 [FWS] "=" [FWS] …`) and
/// the `=` are kept exactly as transmitted so that the hash covers the
/// signature's own structure.
fn empty_b_value(field_value: &str) -> String {
    let bytes = field_value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'b' && bytes[i] != b'B' {
            i += 1;
            continue;
        }
        // Tag start iff the previous non-WSP char is ';' or the value start.
        let mut j = i;
        while j > 0 && (bytes[j - 1] == b' ' || bytes[j - 1] == b'\t') {
            j -= 1;
        }
        if j != 0 && bytes[j - 1] != b';' {
            i += 1;
            continue;
        }
        // Skip FWS between the tag name and '='. The `b` in `bh=` is not a
        // tag start (the next non-WSP char is 'h', not '=').
        let mut eq = i + 1;
        while eq < bytes.len() && (bytes[eq] == b' ' || bytes[eq] == b'\t') {
            eq += 1;
        }
        if eq >= bytes.len() || bytes[eq] != b'=' {
            i += 1;
            continue;
        }
        // Delete the value (and its surrounding WSP) through the tag end.
        let mut end = eq + 1;
        while end < bytes.len() && bytes[end] != b';' {
            end += 1;
        }
        let mut o = String::with_capacity(field_value.len());
        o.push_str(&field_value[..eq + 1]);
        o.push_str(&field_value[end..]);
        return o;
    }
    field_value.to_string()
}

/// Parsed public-key material from a `v=DKIM1` TXT record.
enum KeyMaterial {
    Rsa(rsa::RsaPublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// Select the key record: concatenate multi-string TXT handling is done
/// by the resolver; here join all TXT strings and require `v=DKIM1`.
/// Revoked keys (`p=` empty) return None (caller: permerror, never pass).
fn select_dkim_key(txts: &[String]) -> Option<String> {
    for t in txts {
        let flat: String = t
            .chars()
            .filter(|c| !c.is_whitespace() || *c == ' ')
            .collect();
        let trimmed = flat.trim();
        if trimmed == "v=DKIM1;"
            || trimmed.starts_with("v=DKIM1;")
            || trimmed.starts_with("v=DKIM1 ")
        {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn parse_key_record(txt: &str, alg: SigAlgorithm) -> Result<KeyMaterial, ()> {
    let tags = split_tag_list_key(txt)?;
    let get = |k: &str| {
        tags.iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.as_str())
    };
    if get("v").is_some_and(|v| v.trim() != "DKIM1") {
        return Err(());
    }
    let k = get("k").unwrap_or("rsa").trim();
    let p = get("p").ok_or(())?.trim();
    if p.is_empty() {
        return Err(()); // revoked
    }
    let raw = decode_b64_ws(p).map_err(|_| ())?;
    if raw.is_empty() || raw.len() > 2048 {
        return Err(());
    }
    match (k, alg) {
        ("rsa", SigAlgorithm::RsaSha256) => {
            // Try PKCS#1 DER first, then SPKI DER.
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::pkcs8::DecodePublicKey;
            if let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(&raw) {
                return Ok(KeyMaterial::Rsa(key));
            }
            rsa::RsaPublicKey::from_public_key_der(&raw)
                .map(KeyMaterial::Rsa)
                .map_err(|_| ())
        }
        ("ed25519", SigAlgorithm::Ed25519Sha256) => {
            if raw.len() != 32 {
                return Err(());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map(KeyMaterial::Ed25519)
                .map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn split_tag_list_key(s: &str) -> Result<Vec<(String, String)>, ()> {
    let mut out = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').ok_or(())?;
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() || key.len() > 16 {
            return Err(());
        }
        if out.len() >= 16 {
            return Err(());
        }
        out.push((key, v.trim().to_string()));
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MockResolver;

    const NOW: i64 = 1_786_000_000;

    #[test]
    fn parse_all_tags() {
        let v = "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=sel1; \
                 h=from:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; \
                 b=AAECAw==";
        let s = parse_signature(v).unwrap();
        assert_eq!(s.sdid, "example.com");
        assert_eq!(s.selector, "sel1");
        assert_eq!(s.algorithm, SigAlgorithm::RsaSha256);
        assert_eq!(
            s.signed_headers,
            vec!["from".to_string(), "subject".to_string()]
        );
    }

    #[test]
    fn parse_rejects_bad_algorithm_and_dup_tags() {
        assert!(
            parse_signature("v=1; a=rsa-sha1; d=ex.com; s=s; h=from; bh=eA==; b=AQ==").is_err()
        );
        assert!(
            parse_signature("v=1; a=rsa-sha256; d=ex.com; d=o.com; s=s; h=from; bh=eA==; b=AQ==")
                .is_err()
        );
        assert!(parse_signature("v=1; d=ex.com; s=s; h=from; bh=eA==; b=AQ==").is_err());
    }

    #[test]
    fn canon_vectors() {
        let body = b"Hello  \tworld  \r\n\r\n\r\n";
        let out = canon_body_bytes(CanonBody::Relaxed, body, None);
        assert_eq!(out, b"Hello world\r\n");
        let out = canon_body_bytes(CanonBody::Simple, b"", None);
        assert_eq!(out, b"\r\n");
        let out = canon_body_bytes(CanonBody::Simple, b"Hi\r\n\r\n", None);
        assert_eq!(out, b"Hi\r\n");
    }

    /// RFC 6376 §3.4.3 / §3.4.4 published vectors: the canonicalized EMPTY
    /// body is a single CRLF under `simple` and the **null input** under
    /// `relaxed` (whose SHA-256 is the RFC's published "empty body" value).
    #[test]
    fn canon_body_empty_matches_rfc_vectors() {
        use base64::Engine;
        use sha2::Digest;
        let b64 = |b: &[u8]| {
            let mut h = sha2::Sha256::new();
            h.update(b);
            base64::engine::general_purpose::STANDARD.encode(h.finalize())
        };
        // §3.4.3: "a completely empty or missing body is canonicalized as a
        // single 'CRLF'; that is, the canonicalized length will be 2 octets".
        let simple = canon_body_bytes(CanonBody::Simple, b"", None);
        assert_eq!(simple, b"\r\n");
        assert_eq!(b64(&simple), "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
        // §3.4.4: an empty body is the null input (the RFC publishes its
        // SHA-256 as 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=).
        let relaxed = canon_body_bytes(CanonBody::Relaxed, b"", None);
        assert_eq!(relaxed, b"");
        assert_eq!(b64(&relaxed), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    /// Empty-body / whitespace-only body variants (RFC 6376 §3.4.3, §3.4.4)
    #[test]
    fn canon_body_empty_variants() {
        // simple: an empty body becomes exactly one CRLF.
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"", None), b"\r\n");
        // relaxed: the null input — §3.4.4 adds a CRLF only when the body is
        // *non-empty*.
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"", None), b"");
        // Whitespace-only lines collapse: relaxed drops trailing WSP per line
        // and then the trailing empty line, leaving nothing.
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"   \t  \r\n", None), b"");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"\t\r\n \r\n", None), b"");
        // simple changes nothing but trailing empty lines: WSP is data.
        assert_eq!(
            canon_body_bytes(CanonBody::Simple, b"   \t  \r\n", None),
            b"   \t  \r\n"
        );
        // CRLF-only bodies.
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"\r\n", None), b"\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"\r\n", None), b"");
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"\r\n\r\n\r\n", None), b"\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"\r\n\r\n\r\n", None), b"");
        // Multiple trailing empty lines are stripped by both algorithms.
        assert_eq!(
            canon_body_bytes(CanonBody::Simple, b"Hi\r\n\r\n\r\n", None),
            b"Hi\r\n"
        );
        assert_eq!(
            canon_body_bytes(CanonBody::Relaxed, b"Hi\r\n\r\n\r\n", None),
            b"Hi\r\n"
        );
    }

    /// Trailing CRLF handling edge cases
    #[test]
    fn canon_body_trailing_crlf() {
        // Simple: ensure exactly one trailing CRLF
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"NoCRLF", None), b"NoCRLF\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"HasCRLF\r\n", None), b"HasCRLF\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"Multiple\r\n\r\n", None), b"Multiple\r\n");
        
        // Relaxed: exactly one trailing CRLF after WSP compression
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"NoCRLF", None), b"NoCRLF\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"HasCRLF\r\n", None), b"HasCRLF\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"Multiple\r\n\r\n", None), b"Multiple\r\n");
        
        // Mixed line endings normalization
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"LF\nonly", None), b"LF\r\nonly\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"CR\ronly", None), b"CR\r\nonly\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Simple, b"CRLF\r\nonly", None), b"CRLF\r\nonly\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"LF\nonly", None), b"LF\r\nonly\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"CR\ronly", None), b"CR\r\nonly\r\n");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, b"CRLF\r\nonly", None), b"CRLF\r\nonly\r\n");
    }

    /// `l=` (body length count) — RFC 6376 §3.5, §3.4.5, §3.7: the count is
    /// taken over the **canonicalized** body, so truncation happens after
    /// canonicalization.
    #[test]
    fn canon_body_length_tag() {
        let body = b"Hello World\r\n";
        // l=0 -> "the body is completely unsigned" (§3.4.5): hash of "".
        assert_eq!(canon_body_bytes(CanonBody::Simple, body, Some(0)), b"");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, body, Some(0)), b"");
        // l= exactly the canonicalized length -> the whole body.
        assert_eq!(
            canon_body_bytes(CanonBody::Simple, body, Some(12)),
            b"Hello World\r\n"
        );
        assert_eq!(
            canon_body_bytes(CanonBody::Relaxed, body, Some(12)),
            b"Hello World\r\n"
        );
        // Mid-line truncation of the canonicalized body.
        assert_eq!(canon_body_bytes(CanonBody::Simple, body, Some(11)), b"Hello World");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, body, Some(11)), b"Hello World");
        // l= larger than the body -> no effect.
        assert_eq!(
            canon_body_bytes(CanonBody::Simple, body, Some(100)),
            b"Hello World\r\n"
        );
        assert_eq!(
            canon_body_bytes(CanonBody::Relaxed, body, Some(100)),
            b"Hello World\r\n"
        );
        // l= with a multi-line body.
        let multi = b"Line1\r\nLine2\r\nLine3\r\n";
        assert_eq!(canon_body_bytes(CanonBody::Simple, multi, Some(10)), b"Line1\r\nLi");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, multi, Some(10)), b"Line1\r\nLi");
    }

    /// Ordering proof: at the same `l=` the two body algorithms yield
    /// *different* bytes — only possible when the length count is measured
    /// after canonicalization (§3.4.5: "any whitespace ignored by a
    /// canonicalization algorithm is not included as part of the body
    /// length count").
    #[test]
    fn canon_body_length_applies_after_canonicalization() {
        let body = b"A  B\r\n";
        // simple keeps the double SP (canonicalized length 6) ...
        assert_eq!(canon_body_bytes(CanonBody::Simple, body, None), b"A  B\r\n");
        // ... relaxed collapses it (canonicalized length 5) ...
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, body, None), b"A B\r\n");
        // ... so l=3 truncates different octets.
        assert_eq!(canon_body_bytes(CanonBody::Simple, body, Some(3)), b"A  ");
        assert_eq!(canon_body_bytes(CanonBody::Relaxed, body, Some(3)), b"A B");
    }

    /// Combined header/body canonicalization modes (c= header/body)
    #[test]
    fn canon_header_body_combinations() {
        let body = b"  Hello \t World  \r\n\r\n";
        
        // relaxed/simple
        let h = canon_body_bytes(CanonBody::Simple, body, None);
        let h_relaxed = canon_body_bytes(CanonBody::Relaxed, body, None);
        assert_ne!(h, h_relaxed);
        
        // Verify simple preserves internal WSP
        assert!(h.windows(2).any(|w| w == b"  "));
        // Verify relaxed compresses WSP
        assert!(!h_relaxed.windows(2).any(|w| w == b"  "));
    }

    #[test]
    fn none_when_no_header() {
        let dns = MockResolver::new();
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: "X-Other: 1".to_string(),
                headers: vec![],
                body: b"hi\r\n".to_vec(),
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::None);
    }

    #[test]
    fn expired_fails() {
        let dns = MockResolver::new();
        let v = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; t=1000; x=2000; \
                 bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=AAECAw==";
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: format!("DKIM-Signature: {v}"),
                headers: vec![("From".to_string(), "a@b.c".to_string())],
                body: vec![],
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::Fail);
    }

    #[test]
    fn permerror_on_bad_tag_list() {
        let dns = MockResolver::new();
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: "DKIM-Signature: not-a-tag-list".to_string(),
                headers: vec![],
                body: vec![],
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::PermError);
    }

    #[test]
    fn temperror_on_dns_failure() {
        use base64::Engine;
        let empty_hash = base64::engine::general_purpose::STANDARD.encode(sha256(b"\r\n"));
        let v =
            format!("v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh={empty_hash}; b=AAECAw==");
        let dns = MockResolver::new().with_temp_fail("sel._domainkey.example.com");
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: format!("DKIM-Signature: {v}"),
                headers: vec![("From".to_string(), "a@b.c".to_string())],
                body: vec![],
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::TempError);
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use crate::dkim::{CanonHeader, DkimInput, DkimResult, header_hash_input, sha256, verify};
    use crate::dns::MockResolver;

    const NOW: i64 = 1_786_000_000;

    /// RSA round-trip with a test-only xorshift RNG (no `rand` dep).
    #[test]
    fn rsa_round_trip_pass_then_tamper_fail() {
        use base64::Engine;
        use rsa::pkcs1::EncodeRsaPublicKey;
        let mut rng = SimpleRng(0x1234_5678_9abc_def0);
        let privkey = rsa::RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let pubkey = rsa::RsaPublicKey::from(&privkey);
        let pub_der = pubkey.to_pkcs1_der().expect("der").as_bytes().to_vec();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_der);

        let body = b"Hello world\r\n";
        let bh = base64::engine::general_purpose::STANDARD.encode(sha256(body));
        let v_nosig = format!(
            "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test; \
             h=from:subject; bh={bh}; b="
        );
        let hdrs = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("Subject".to_string(), "hello".to_string()),
        ];
        let signed = header_hash_input(
            CanonHeader::Simple,
            &hdrs,
            &["from".to_string(), "subject".to_string()],
            "DKIM-Signature",
            &v_nosig,
        );
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::RandomizedSigner;
        use rsa::signature::SignatureEncoding;
        let scheme = SigningKey::<sha2::Sha256>::new(privkey.clone());
        let sig_bytes = scheme.sign_with_rng(&mut rng, &signed).to_vec();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
        let v = format!("{v_nosig}{sig_b64}");

        let dns = MockResolver::new().with_txt(
            "test._domainkey.example.com",
            &[&format!("v=DKIM1; k=rsa; p={pub_b64}")],
        );
        let mut full = hdrs.clone();
        full.push(("DKIM-Signature".to_string(), v.clone()));
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: format!("DKIM-Signature: {v}"),
                headers: full,
                body: body.to_vec(),
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::Pass, "{}", out.explanation);
        let out2 = verify(
            &dns,
            &DkimInput {
                signature_header: format!("DKIM-Signature: {v}"),
                headers: vec![("From".to_string(), "x@y.z".to_string())],
                body: b"Hello evil\r\n".to_vec(),
                now_unix: NOW,
            },
        );
        assert_eq!(out2.result, DkimResult::Fail);
    }

    /// Ed25519 round-trip with a fixed test seed (deterministic, offline).
    #[test]
    fn ed25519_round_trip() {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        let body = b"ed test\r\n";
        let bh = base64::engine::general_purpose::STANDARD.encode(sha256(body));
        let v_nosig = format!(
            "v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed1; \
             h=from:subject; bh={bh}; b="
        );
        let hdrs = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("Subject".to_string(), "hello".to_string()),
        ];
        let signed = header_hash_input(
            CanonHeader::Relaxed,
            &hdrs,
            &["from".to_string(), "subject".to_string()],
            "DKIM-Signature",
            &v_nosig,
        );
        let sig = signing.sign(&signed);
        let v = format!(
            "{v_nosig}{}",
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        );
        let dns = MockResolver::new().with_txt(
            "ed1._domainkey.example.com",
            &[&format!("v=DKIM1; k=ed25519; p={pub_b64}")],
        );
        let mut full = hdrs.clone();
        full.push(("DKIM-Signature".to_string(), v.clone()));
        let out = verify(
            &dns,
            &DkimInput {
                signature_header: format!("DKIM-Signature: {v}"),
                headers: full,
                body: body.to_vec(),
                now_unix: NOW,
            },
        );
        assert_eq!(out.result, DkimResult::Pass, "{}", out.explanation);
    }

///
/// Header canonicalization + hash-step-2 composition (RFC 6376 §3.4.1,
/// §3.4.2, §3.4.5, §3.5, §3.7, §5.4.2).
#[cfg(test)]
mod header_canon_tests {
    use crate::dkim::{CanonHeader, empty_b_value, header_hash_input, push_canon_header};

    /// RFC 6376 §3.4.5 Example 1: relaxed canonicalization of
    /// `A: <SP> X`, `B <SP> : <SP> Y <HTAB><CRLF><HTAB> Z <SP><SP>`
    /// is `a:X` and `b:Y <SP> Z`.
    #[test]
    fn rfc_6376_example1_relaxed_headers() {
        let mut out = Vec::new();
        push_canon_header(&mut out, CanonHeader::Relaxed, "A", " X ", true);
        push_canon_header(&mut out, CanonHeader::Relaxed, "B ", " Y \t\r\n\t Z  ", true);
        assert_eq!(out, b"a:X\r\nb:Y Z\r\n");
    }

    /// RFC 6376 §3.4.5 Example 2: simple canonicalization leaves the field
    /// name case, the WSP before the colon and the folding untouched.
    #[test]
    fn rfc_6376_example2_simple_headers() {
        let mut out = Vec::new();
        push_canon_header(&mut out, CanonHeader::Simple, "A", " X ", true);
        push_canon_header(&mut out, CanonHeader::Simple, "B ", " Y \t\r\n\t Z  ", true);
        assert_eq!(out, b"A: X \r\nB : Y \t\r\n\t Z  \r\n");
    }

    /// A trailing CRLF in the stored value is not duplicated, and the field
    /// terminator can be suppressed (§3.7 step 2 hashes the DKIM-Signature
    /// field *without* a trailing CRLF).
    #[test]
    fn trailing_crlf_is_normalized_and_optional() {
        let mut out = Vec::new();
        push_canon_header(&mut out, CanonHeader::Simple, "X", "v\r\n\r\n", true);
        assert_eq!(out, b"X:v\r\n");
        let mut out = Vec::new();
        push_canon_header(&mut out, CanonHeader::Relaxed, "X", "  v  ", false);
        assert_eq!(out, b"x:v");
    }

    /// §3.7 step 2: the DKIM-Signature field under verification is hashed
    /// **after** the `h=` fields and **without** a trailing CRLF.
    #[test]
    fn sig_field_is_appended_last_without_crlf() {
        let headers = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("Subject".to_string(), "hello".to_string()),
        ];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &["from".to_string(), "subject".to_string()],
            "DKIM-Signature",
            "v=1; d=example.com; b=AAECAw==",
        );
        assert_eq!(
            out,
            b"from:alice@example.com\r\nsubject:hello\r\ndkim-signature:v=1; d=example.com; b="
        );
        assert!(!out.ends_with(b"\r\n"));
    }


    /// §3.7 step 1: fields are hashed in `h=` order, not message order.
    #[test]
    fn h_order_wins_over_message_order() {
        let headers = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("Subject".to_string(), "hello".to_string()),
        ];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &["subject".to_string(), "from".to_string()],
            "DKIM-Signature",
            "v=1; b=",
        );
        assert_eq!(
            out,
            b"subject:hello\r\nfrom:alice@example.com\r\ndkim-signature:v=1; b="
        );
    }

    /// §3.5: names in `h=` that do not exist in the message contribute
    /// nothing (the null input) — they are not an error.
    #[test]
    fn missing_h_entries_contribute_nothing() {
        let headers = vec![("From".to_string(), "alice@example.com".to_string())];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &[
                "x-absent".to_string(),
                "from".to_string(),
                "x-also-absent".to_string(),
            ],
            "DKIM-Signature",
            "v=1; b=",
        );
        assert_eq!(out, b"from:alice@example.com\r\ndkim-signature:v=1; b=");
    }

    /// §5.4.2: repeated `h=` names select the physically last unused
    /// instances, bottom-up — the RFC's three-`Received` example signs
    /// `<C>` then `<B>`.
    #[test]
    fn repeated_h_names_take_last_unused_bottom_up() {
        let headers = vec![
            ("Received".to_string(), "A".to_string()),
            ("Received".to_string(), "B".to_string()),
            ("Received".to_string(), "C".to_string()),
        ];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &["received".to_string(), "received".to_string()],
            "DKIM-Signature",
            "v=1; b=",
        );
        assert_eq!(out, b"received:C\r\nreceived:B\r\ndkim-signature:v=1; b=");
    }

    /// More `h=` occurrences than instances: the extra ones are the null
    /// input (this is what lets a signer detect added fields).
    #[test]
    fn more_h_occurrences_than_instances() {
        let headers = vec![("Received".to_string(), "A".to_string())];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &["received".to_string(), "received".to_string()],
            "DKIM-Signature",
            "v=1; b=",
        );
        assert_eq!(out, b"received:A\r\ndkim-signature:v=1; b=");
    }

    /// §3.5: `h=dkim-signature` refers to *other* DKIM-Signature fields —
    /// never the one under verification, which §3.7 appends separately.
    #[test]
    fn h_dkim_signature_selects_other_signatures() {
        let headers = vec![
            (
                "DKIM-Signature".to_string(),
                "v=1; d=example.com; b=ORIGINAL".to_string(),
            ),
            ("From".to_string(), "alice@example.com".to_string()),
            (
                "DKIM-Signature".to_string(),
                "v=1; d=example.com; b=SELFTEST".to_string(),
            ),
        ];
        let out = header_hash_input(
            CanonHeader::Relaxed,
            &headers,
            &["dkim-signature".to_string(), "from".to_string()],
            "DKIM-Signature",
            "v=1; d=example.com; b=SELFTEST",
        );
        assert_eq!(
            out,
            b"dkim-signature:v=1; d=example.com; b=ORIGINAL\r\nfrom:alice@example.com\r\n\
              dkim-signature:v=1; d=example.com; b="
        );
    }

    /// §3.7: the `b=` value (with its surrounding whitespace) is the only
    /// tag value removed, and the tag structure is preserved.
    #[test]
    fn b_value_emptying() {
        assert_eq!(
            empty_b_value("v=1; a=rsa-sha256; d=example.com; b=AAECAw=="),
            "v=1; a=rsa-sha256; d=example.com; b="
        );
        assert_eq!(empty_b_value("v=1; b=AAECAw==; x=2000"), "v=1; b=; x=2000");
        // `bh=` is not the signature tag.
        assert_eq!(
            empty_b_value("v=1; bh=AAECAw==; b=SIG"),
            "v=1; bh=AAECAw==; b="
        );
        // FWS around the `=` (sig-b-tag = %x62 [FWS] "=" [FWS] data).
        assert_eq!(empty_b_value("v=1; b = AAECAw=="), "v=1; b =");
        // The `b=` value folded across lines goes away with its WSP.
        assert_eq!(
            empty_b_value("v=1;\r\n b=AAAA\r\n BBBB;\r\n d=example.com"),
            "v=1;\r\n b=;\r\n d=example.com"
        );
        // No `b=` tag at all: unchanged (callers report it as a parse error).
        assert_eq!(empty_b_value("v=1; d=example.com"), "v=1; d=example.com");
        // A "b=" inside another tag's value is not a tag start.
        assert_eq!(empty_b_value("v=1; d=b.com; b=SIG"), "v=1; d=b.com; b=");
    }
}

    struct SimpleRng(u64);
    impl rand_core::RngCore for SimpleRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for SimpleRng {}
}

fn verify_rsa_sha256(key: &rsa::RsaPublicKey, signed: &[u8], sig: &[u8]) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let Ok(s) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    let vk = VerifyingKey::<sha2::Sha256>::new(key.clone());
    vk.verify(signed, &s).is_ok()
}

fn verify_ed25519(key: &ed25519_dalek::VerifyingKey, signed: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let arr: &[u8] = sig;
    let Ok(s) = ed25519_dalek::Signature::try_from(arr) else {
        return false;
    };
    key.verify(signed, &s).is_ok()
}
