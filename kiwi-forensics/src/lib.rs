//! KIWI forensics engine (agent 3, task T-003).
//!
//! Deterministic security analysis for mail transport, usable with **no AI and
//! no network access** (`prompt.md` §12). Everything reported here is
//! reproducible from bounded, typed evidence (`prompt.md` §2.5).
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`model`] | Normalized protocol/security model (`ConnectionSecurityEvent`) |
//! | [`analyzers`] | Deterministic SMTP/IMAP/POP3 trace analyzers (STARTTLS + AUTH observation) |
//! | [`findings`] | Finding/evidence/impact/remediation records, stable keys, re-scan diff |
//! | [`rules`] | Deterministic rule engine + catalog (TLS, cipher, key-exchange, cert, auth, STARTTLS) |
//! | [`score`] | Integer-only deterministic scoring and grading |
//! | [`pcap`] | Bounded `.pcap`/`.pcapng` ingest; every byte is untrusted input |
//! | [`report`] | Versioned forensic report aggregate + JSON renderer interface |
//!
//! # Design rules enforced here
//!
//! 1. **Determinism.** No clocks, RNG, floats or iteration-order dependence in
//!    findings or scoring. Timestamps and capture identity are *inputs*, not
//!    ambient state, so identical input yields identical output
//!    (`docs/contracts/forensics.md` §7).
//! 2. **No invented findings.** A rule emits a finding only from an observed,
//!    typed field. Facts the input cannot establish become
//!    [`report::Limitation`]s, never failures of the peer.
//! 3. **Chain of custody.** Findings carry [`findings::Evidence`] that
//!    references the session and, when available, capture frame indices.
//! 4. **Untrusted input.** PCAP bytes, capability strings, protocol lines and
//!    certificate metadata are bounded at every boundary
//!    ([`pcap::CaptureLimits`]).
//! 5. **AI is never authoritative.** AI text is attached only as
//!    [`report::AiEnrichment`], and must cite the deterministic findings it is
//!    grounded in (`prompt.md` §12).

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![warn(missing_docs)]

pub mod model;

// Remaining modules are authored in the order listed in
// `docs/agents/agent-3-status.md`. Each declaration is uncommented as the module
// lands, so the crate always compiles for the layer that is complete. The task is
// only reported done when every module below is present and `cargo test` +
// `cargo clippy` are green.
// pub mod analyzers;
// pub mod findings;
// pub mod pcap;
// pub mod report;
// pub mod rules;
// pub mod score;

/// Version of the finding/evidence/report contract implemented by this crate.
///
/// Consumers must tolerate unknown fields and unknown enum variants
/// (`docs/API_CONTRACTS.md`, cross-cutting invariants).
pub const CONTRACT_VERSION: &str = "kiwi.forensics/1";

/// Rule-catalog version.
///
/// Bumped whenever a rule's decision logic or default severity changes, so two
/// findings carrying the same rule id but different `rule_version` values are
/// never treated as identical by a re-scan diff.
pub const RULE_CATALOG_VERSION: u16 = 1;

/// Version of the deterministic scoring model ([`score`]).
pub const SCORING_MODEL_VERSION: &str = "kiwi-score-1";
