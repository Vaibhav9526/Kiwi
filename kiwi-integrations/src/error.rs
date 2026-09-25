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
    /// Anything else (redirects refused, builder errors, aborts).
    Other,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrationError {
    /// Transport failure. `kind` is all you get — the provider's own error
    /// text is dropped because it embeds the request URL (capability secret).
    #[error("transport failure ({kind:?})")]
    Transport { kind: TransportKind },

    /// The provider answered with a non-2xx status we do not specialize.
    #[error("unexpected HTTP status {status}")]
    Http { status: u16 },

    /// 429 or an explicit Retry-After. `retry_after_ms` is the server's hint.
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

    /// Provider reported a logical failure in-band (e.g. GuerrillaMail
    /// returning an error payload).
    #[error("provider rejected request: {0}")]
    ProviderRejected(&'static str),
}
