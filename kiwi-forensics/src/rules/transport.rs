//! Transport-protection, STARTTLS-negotiation and protocol-identity rules.
//!
//! Every rule here answers one question about the *channel*: is it encrypted, was
//! the upgrade prevented, and do we even know which protocol this is?
//! `TransportSecurity::Unknown` never produces a finding — it becomes an analysis
//! limitation instead (`report::Limitation`), because "we could not see" is not
//! the same as "it was insecure".

use super::{FnRule, Rule, RuleContext, ids};
use crate::findings::{
    Confidence, Evidence, EvidenceKind, EvidenceValue, Finding, FindingCategory, Remediation,
    Severity,
};
use crate::model::Protocol;

/// Register the transport rules.
pub fn register(rules: &mut Vec<Box<dyn Rule>>) {
    rules.push(Box::new(FnRule::new(
        ids::TRANSPORT_PLAINTEXT,
        FindingCategory::Transport,
        "Mail transport is not encrypted",
        "Detects a mail session whose application data was exchanged without TLS.",
        rule_plaintext_transport,
    )));
    rules.push(Box::new(FnRule::new(
        ids::TRANSPORT_IMPLICIT_PORT_PLAINTEXT,
        FindingCategory::Transport,
        "TLS-only port served in plaintext",
        "Detects plaintext mail on a port defined as implicit TLS (465/993/995).",
        rule_implicit_port_plaintext,
    )));
    rules.push(Box::new(FnRule::new(
        ids::PROTOCOL_UNKNOWN,
        FindingCategory::Protocol,
        "Mail protocol could not be identified",
        "Records that the session protocol could not be established from the observation.",
        rule_protocol_unknown,
    )));
    rules.push(Box::new(FnRule::new(
        ids::STARTTLS_STRIPPING,
        FindingCategory::StartTls,
        "STARTTLS downgrade or stripping indicator",
        "Detects a session where the upgrade was requested but application data continued in the clear.",
        rule_starttls_stripping,
    )));
    rules.push(Box::new(FnRule::new(
        ids::STARTTLS_NOT_ADVERTISED,
        FindingCategory::StartTls,
        "Server did not offer STARTTLS",
        "Detects a plaintext session on a STARTTLS-capable port where the server never advertised the upgrade.",
        rule_starttls_not_advertised,
    )));
    rules.push(Box::new(FnRule::new(
        ids::STARTTLS_NOT_ATTEMPTED,
        FindingCategory::StartTls,
        "Client did not attempt STARTTLS",
        "Detects a plaintext session where the server offered STARTTLS but the client never requested it.",
        rule_starttls_not_attempted,
    )));
    rules.push(Box::new(FnRule::new(
        ids::STARTTLS_REFUSED,
        FindingCategory::StartTls,
        "Server refused the STARTTLS upgrade",
        "Detects a server that rejected an explicit STARTTLS request.",
        rule_starttls_refused,
    )));
}

fn rule_plaintext_transport(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.require_tls || !ctx.session.transport.is_known_plaintext() {
        return Vec::new();
    }
    // A reusable secret observed in the clear escalates this from "unencrypted"
    // to "credentials already exposed" — that distinction drives triage.
    let exposed = ctx
        .session
        .auth
        .as_ref()
        .map(|auth| auth.exposes_reusable_secret(false))
        .unwrap_or(false);
    let severity = if exposed {
        Severity::Critical
    } else {
        Severity::High
    };

    let mut builder = Finding::builder(
        ids::TRANSPORT_PLAINTEXT,
        crate::RULE_CATALOG_VERSION,
        FindingCategory::Transport,
        severity,
        Confidence::Certain,
        ctx.session,
    )
    .title("Mail transport is not encrypted")
    .description("The session was classified as plaintext: no TLS record was observed.")
    .impact(if exposed {
        "Credentials or tokens crossed the network in a reusable form, so a passive observer can authenticate as this account."
    } else {
        "Mail content, addresses and commands are readable and modifiable by anyone on the path."
    })
    .remediation(
        Remediation::new(
            "Require TLS for this account (implicit TLS on 465/993/995, or STARTTLS on 25/143/110/587).",
            &[
                "Set the account to implicit TLS if the service supports it (preferred).",
                "Otherwise enable STARTTLS and verify the upgrade succeeds on every connection.",
                "Remove any fallback that allows plaintext when the upgrade fails.",
            ],
        )
        .with_references(&["RFC 8314 §3"]),
    )
    .reference("RFC 8314 §3")
    .evidence(Evidence::new(
        EvidenceKind::TransportState,
        "transport classification",
        EvidenceValue::text(ctx.session.transport.as_str()),
        ctx.session_anchor(),
    ));

    if let Some(auth) = &ctx.session.auth {
        builder = builder
            .evidence(Evidence::new(
                EvidenceKind::AuthMechanism,
                "authentication mechanism observed on the plaintext channel",
                EvidenceValue::text(auth.mechanism.map(|m| m.as_str()).unwrap_or("unobserved")),
                ctx.session_anchor(),
            ))
            .evidence(Evidence::new(
                EvidenceKind::AuthOutcome,
                "credential material exposed to a passive observer",
                EvidenceValue::boolean(exposed),
                ctx.session_anchor(),
            ));
    }

    vec![builder.build()]
}

fn rule_implicit_port_plaintext(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.strict_implicit_tls_ports || !ctx.session.transport.is_known_plaintext() {
        return Vec::new();
    }
    let port = ctx.session.server.port;
    if !Protocol::is_implicit_tls_port(port) {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::TRANSPORT_IMPLICIT_PORT_PLAINTEXT,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::Critical,
            Confidence::Certain,
            ctx.session,
        )
        .title("TLS-only port served in plaintext")
        .description(&format!(
            "Port {port} is defined as implicit TLS, but the session carried plaintext mail protocol data."
        ))
        .impact("Either the client is misconfigured or the service is impersonating a TLS-only endpoint; the protocol contract for this port is violated either way.")
        .remediation(
            Remediation::new(
                "Resolve the port/TLS mode mismatch before sending credentials.",
                &[
                    "If the service requires implicit TLS, enable it in the account settings.",
                    "If the service is plaintext-only, move the account to its correct port and require STARTTLS.",
                    "Do not authenticate until the classification is corrected.",
                ],
            )
            .with_references(&["RFC 8314 §3.3"]),
        )
        .reference("RFC 8314 §3.3")
        .evidence(Evidence::new(
            EvidenceKind::SessionStructure,
            "server port classified as implicit TLS",
            EvidenceValue::number(i64::from(port)),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::TransportState,
            "observed transport for that port",
            EvidenceValue::text(ctx.session.transport.as_str()),
            ctx.session_anchor(),
        ))
        .discriminator(&format!("port{port}"))
        .build(),
    ]
}

fn rule_protocol_unknown(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if ctx.session.protocol != Protocol::Unknown {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::PROTOCOL_UNKNOWN,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Protocol,
            Severity::Info,
            Confidence::Tentative,
            ctx.session,
        )
        .title("Mail protocol could not be identified")
        .description("Neither the port nor the protocol trace identified the mail protocol.")
        .impact("Protocol-specific expectations cannot be asserted, so findings for this session are limited to transport-level facts.")
        .remediation(Remediation::new(
            "Confirm the configured port and the capture coverage for this account.",
            &[
                "Verify the account's server port settings.",
                "Capture the start of the connection so the greeting can be analysed.",
            ],
        ))
        .evidence(Evidence::new(
            EvidenceKind::SessionStructure,
            "server port that could not be mapped to a mail protocol",
            EvidenceValue::number(i64::from(ctx.session.server.port)),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_starttls_stripping(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(starttls) = &ctx.session.starttls else {
        return Vec::new();
    };
    if !starttls.is_stripping_indicator() {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::STARTTLS_STRIPPING,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::StartTls,
            Severity::Critical,
            Confidence::Firm,
            ctx.session,
        )
        .title("STARTTLS downgrade or stripping indicator")
        .description("The server advertised STARTTLS and the client requested it, but the mail protocol continued in the clear instead of upgrading.")
        .impact("This is the classic active-MITM pattern: an on-path attacker, proxy or downgrade device suppressed the upgrade while both endpoints carried on normally.")
        .remediation(
            Remediation::new(
                "Treat this connection as hostile until the path is understood.",
                &[
                    "Abort the session; do not send or receive mail on it.",
                    "Prefer implicit TLS, which cannot be stripped in-band.",
                    "Investigate the network path for a TLS-intercepting proxy or downgrade policy.",
                    "Re-test from another network to see whether the indicator reproduces.",
                ],
            )
            .with_references(&["RFC 3207", "RFC 8314 §3.1"]),
        )
        .reference("RFC 3207")
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "server advertised the STARTTLS capability",
            EvidenceValue::boolean(starttls.advertised_by_server),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "client requested the upgrade",
            EvidenceValue::boolean(starttls.client_requested),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "handshake observed after the request",
            EvidenceValue::boolean(starttls.handshake_completed),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "mail data observed across the upgrade request",
            EvidenceValue::boolean(starttls.application_data_before_tls),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "credentials sent in the clear after the upgrade request",
            EvidenceValue::boolean(starttls.plaintext_auth_after_request),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_starttls_not_advertised(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.require_starttls {
        return Vec::new();
    }
    let Some(starttls) = &ctx.session.starttls else {
        return Vec::new();
    };
    if starttls.advertised_by_server || !ctx.session.transport.is_known_plaintext() {
        return Vec::new();
    }
    // Outside a STARTTLS-capable port the absence is expected, not a finding.
    if !Protocol::is_starttls_capable_port(ctx.session.server.port) {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::STARTTLS_NOT_ADVERTISED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::StartTls,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("Server did not offer STARTTLS")
        .description(&format!(
            "Port {} supports STARTTLS negotiation, but the server never advertised the upgrade and the session stayed in plaintext.",
            ctx.session.server.port,
        ))
        .impact("Without an upgrade offer the client cannot protect the session opportunistically; a stripping proxy and a legacy server look identical here, so the session must be treated as unprotected.")
        .remediation(
            Remediation::new(
                "Require an upgrade path for this service.",
                &[
                    "Prefer implicit TLS, which needs no in-band advertisement.",
                    "If the service should offer STARTTLS, fix the server configuration and re-test.",
                    "Until then, do not authenticate on this session.",
                ],
            )
            .with_references(&["RFC 8314 §3.1"]),
        )
        .reference("RFC 8314 §3.1")
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "server advertised the STARTTLS capability",
            EvidenceValue::boolean(false),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::SessionStructure,
            "plaintext session on a STARTTLS-capable port",
            EvidenceValue::number(i64::from(ctx.session.server.port)),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_starttls_not_attempted(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.require_starttls {
        return Vec::new();
    }
    let Some(starttls) = &ctx.session.starttls else {
        return Vec::new();
    };
    if !starttls.advertised_by_server
        || starttls.client_requested
        || !ctx.session.transport.is_known_plaintext()
    {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::STARTTLS_NOT_ATTEMPTED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::StartTls,
            Severity::High,
            Confidence::Certain,
            ctx.session,
        )
        .title("Client did not attempt STARTTLS")
        .description("The server offered STARTTLS but the client never requested the upgrade and the session stayed in plaintext.")
        .impact("An offered upgrade that is never taken is a client-side failure: credentials and mail cross the network in the clear despite the server doing its part.")
        .remediation(
            Remediation::new(
                "Make the client require the upgrade.",
                &[
                    "Enable STARTTLS (or implicit TLS) in the account settings and remove plaintext fallbacks.",
                    "Verify the very next connection upgrades before any AUTH command.",
                ],
            )
            .with_references(&["RFC 8314 §3.1"]),
        )
        .reference("RFC 8314 §3.1")
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "server advertised the STARTTLS capability",
            EvidenceValue::boolean(true),
            ctx.session_anchor(),
        ))
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "client requested the upgrade",
            EvidenceValue::boolean(false),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_starttls_refused(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.require_starttls {
        return Vec::new();
    }
    let Some(starttls) = &ctx.session.starttls else {
        return Vec::new();
    };
    if starttls.server_reply_ok != Some(false) {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::STARTTLS_REFUSED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::StartTls,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("Server refused the STARTTLS upgrade")
        .description("The client requested STARTTLS and the server explicitly refused, leaving the session in plaintext.")
        .impact("A refusal may be policy (the server genuinely offers no TLS) or interference; either way no protected channel exists and authentication must not proceed under a TLS-requiring policy.")
        .remediation(
            Remediation::new(
                "Resolve the refusal before sending mail.",
                &[
                    "Prefer implicit TLS, which has no upgrade step to refuse.",
                    "If the service should support STARTTLS, fix the server side and re-test.",
                    "Do not authenticate until a protected channel is established.",
                ],
            )
            .with_references(&["RFC 3207"]),
        )
        .reference("RFC 3207")
        .evidence(Evidence::new(
            EvidenceKind::StartTlsNegotiation,
            "server reply to the upgrade request",
            EvidenceValue::text("refused"),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}
