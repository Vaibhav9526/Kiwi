//! Shared error type for all integrations.
//!
//! Security rule: error strings must never carry secrets. Request URLs can
//! embed capability secrets (the deliverability test slug lives in the URL
//! path), so transport failures are classified into [`TransportKind`] and the
//! underlying error message — which embeds the full URL — is dropped.

use thiserror::Error;

/// Classification of transport-level failures. Deliberately coarse: fine
/// enough for retry/UI decisions, carries no URL and no provider message.
/// (TLS failures are reported as `Connect` — TLS is negotiated inside the
/// connect phase and reqwest exposes no narrower public classifier.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Connection could not be established (DNS, refused, unreachable, TLS).
    Connect,
    /// The request exceeded the configured timeout.
    Timeout,
    /// The response could not be read/decoded.
    Decode,
    /// Anything else (client-build errors, request aborts). A refused redirect
    /// is **not** here: redirects are never
    /// followed, so a 3xx comes back as [`IntegrationError::Http`].
    Other,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrationError {
    /// Transport failure. `kind` is all you get — the provider's own error
    /// text is dropped because it embeds the request URL (capability secret).
    #[error("transport failure ({kind:?})")]
    Transport { kind: TransportKind },

    /// The provider answered with a status the operation does not specialize,
    /// including any 3xx because redirects are never followed.
    #[error("unexpected HTTP status {status}")]
    Http { status: u16 },

    /// HTTP 429. `retry_after_ms` is the server's `Retry-After` hint when it
    /// sent a parseable seconds value; no other status maps here.
    #[error("rate limited")]
    RateLimited { retry_after_ms: Option<u64> },

    /// The reservation/address expired on the server (HTTP 410).
    #[error("expired on server")]
    Expired,

    /// The object does not exist server-side (HTTP 404).
    #[error("not found")]
    NotFound,

    /// Server-side analysis failed (deliverability `analysis_status=failed`).
    #[error("analysis failed on server")]
    AnalysisFailed,

    /// Response body or JSON did not match the documented schema.
    /// Detail names the missing/invalid field, never field contents.
    #[error("malformed response: {0}")]
    Malformed(&'static str),

    /// Body exceeded the configured byte cap before parse.
    #[error("response body too large")]
    BodyTooLarge,

    /// Caller's URL was not `https://` — refused before any socket opened.
    #[error("refused non-HTTPS URL")]
    InsecureUrl,

    /// Operation needs an established session/address and none exists.
    #[error("no active session")]
    NoSession,

    /// The provider reported a logical failure in-band (a top-level `error`
    /// envelope, or a body that is not the operation's documented success
    /// shape). The `&'static str` is a fixed code, never provider text.
    #[error("provider rejected request: {0}")]
    ProviderRejected(&'static str),
}

/// Reject a provider's top-level error envelope before any success parse.
///
/// Both integrated services answer logical failures with `200` and a body like
/// `{"error": "not_found"}`; parsing that as a success is the failure mode this
/// guards. A missing, `null`, or empty-string `error` is not an envelope, and
/// the returned code is a fixed `&'static str` — provider text never reaches an
/// error string.
pub(crate) fn reject_in_band_error(value: &serde_json::Value) -> Result<(), IntegrationError> {
    match value.get("error") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(()),
        Some(serde_json::Value::String(s)) if s.trim() == "not ownership" => {
            Err(IntegrationError::ProviderRejected("not_ownership"))
        }
        Some(_) => Err(IntegrationError::ProviderRejected("provider_error")),
    }
}
