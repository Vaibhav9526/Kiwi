//! DKIM (RFC 6376): tag-list parse, header/body canonicalization
//! (simple/relaxed), RSA-SHA256 + Ed25519 verify, `s._domainkey.d` key fetch.
//!
//! Verification is deterministic: the caller supplies `now_unix` for expiry
//! checks (never the system clock). Unknown tags are ignored, never fatal.

use serde::{Deserialize, Serialize};

use crate::dns::{DnsError, DnsResolver};
use crate::{DomainName, Error, MAX_CANON_BYTES, MAX_TXT_LEN};

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
