//! Capture-to-report pipeline: the composed public entry point.
//!
//! [`analyze_capture`] wires the contract §10 chain end to end over raw
//! capture bytes: `pcap::PcapReader` → `pcap::decode` → reassembly →
//! `analyzers::analyze` (protocol sniffed per flow) → `RuleEngine` →
//! `report::ReportBuilder`. Everything the chain cannot establish becomes a
//! report [`Limitation`](crate::report::Limitation), never a peer fault.
//!
//! Conversation order across the two stream directions is reconstructed
//! from capture order: each protocol line is attributed to the frames that
//! carried it, and lines sort by their earliest covering frame (ties: the
//! initiator's line first). Frame order is time order, so this is an
//! observation, not a guess.

use std::collections::BTreeMap;

use crate::analyzers::{AnalyzerLimits, Direction, ProtocolTrace, TraceLine, analyze};
use crate::model::Protocol;
use crate::pcap::{
    CaptureError, CaptureLimits, PcapReader, ReassembledFlow, Reassembler, ReassemblyLimits,
    StreamReassembler, decode_tcp,
};
use crate::report::{
    Limitation, Report, ReportBuilder, limitation_codes, session_limitation_codes,
};
use crate::rules::{RuleEngine, SecurityPolicy};

/// Options for one capture analysis. All bounds travel with the call so the
/// pipeline never invents its own resource policy.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// Capture identity used in deterministic session ids (`source_tag`).
    pub source_tag: String,
    /// Human scope recorded on the report (account label, case name, …).
    pub scope: String,
    /// Rule policy in force.
    pub policy: SecurityPolicy,
    /// Capture-reader bounds.
    pub capture: CaptureLimits,
    /// Trace-analyzer bounds (also bound line splitting here).
    pub analyzers: AnalyzerLimits,
    /// Reassembly bounds.
    pub reassembly: ReassemblyLimits,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        CaptureOptions {
            source_tag: "capture".to_string(),
            scope: "capture".to_string(),
            policy: SecurityPolicy::default(),
            capture: CaptureLimits::default(),
            analyzers: AnalyzerLimits::default(),
            reassembly: ReassemblyLimits::default(),
        }
    }
}

impl CaptureOptions {
    /// Set the capture identity (also the default scope).
    pub fn with_source_tag(mut self, source_tag: &str) -> Self {
        self.source_tag = source_tag.to_string();
        self.scope = source_tag.to_string();
        self
    }

    /// Set the report scope independently of the capture identity.
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = scope.to_string();
        self
    }

    /// Set the rule policy.
    pub fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Frames skipped per reason, in sorted-reason order (deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipCount {
    /// One of `pcap::skip_reasons::*`.
    pub reason: String,
    /// Frames skipped for this reason.
    pub frames: u64,
}

/// Pipeline run diagnostics: counts, not verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineDiagnostics {
    /// Frames read from the capture.
    pub frames_read: u64,
    /// Frames that yielded a TCP segment.
    pub tcp_segments: u64,
    /// Flows reassembled.
    pub flows: usize,
    /// Sessions (traces) evaluated.
    pub sessions: u32,
    /// Skip counts by reason.
    pub skips: Vec<SkipCount>,
    /// Segments dropped by reassembly bounds.
    pub dropped_segments: u64,
    /// Flows refused by the flow bound.
    pub dropped_flows: u64,
    /// Findings dropped by the engine for lack of evidence (must be 0).
    pub dropped_without_evidence: u32,
}

/// A finished capture analysis: the report plus how it was reached.
#[derive(Debug, Clone)]
pub struct CaptureReport {
    /// Versioned findings, score, and limitations.
    pub report: Report,
    /// Counts behind the report.
    pub diagnostics: PipelineDiagnostics,
}

/// Analyze raw capture bytes (classic pcap or pcapng) into a report.
///
/// Returns [`CaptureError`] only when the capture itself cannot be read;
/// undecodable frames and unresolvable streams become limitations and
/// diagnostics instead.
pub fn analyze_capture(
    bytes: &[u8],
    options: &CaptureOptions,
) -> Result<CaptureReport, CaptureError> {
    let mut reader = PcapReader::from_slice(bytes, options.capture)?;
    let link = reader.link_type();
    let mut reassembler = Reassembler::new(options.reassembly);
    let mut skips: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut frames_read: u64 = 0;
    let mut tcp_segments: u64 = 0;
    while let Some(packet) = reader.next_packet()? {
        frames_read += 1;
        match decode_tcp(
            link,
            &packet.data,
            packet.index,
            packet.timestamp.unix_millis(),
        ) {
            Ok(segment) => {
                tcp_segments += 1;
                reassembler.feed(&segment);
            }
            Err(skip) => {
                *skips.entry(skip.reason).or_insert(0) += 1;
            }
        }
    }
    let dropped_segments = reassembler.dropped_segments();
    let dropped_flows = reassembler.dropped_flows();
    let flows = reassembler.finish();

    let engine = RuleEngine::new(options.policy);
    let mut builder = ReportBuilder::new(&options.scope, &options.source_tag);
    let mut sessions: u32 = 0;
    let mut flows_with_gaps: u32 = 0;
    let mut unknown_protocol_sessions: u32 = 0;
    let mut dropped_without_evidence: u32 = 0;
    let mut transport_unknown_sessions: u32 = 0;
    let mut kex_unobserved_sessions: u32 = 0;
    let mut auth_unobserved_sessions: u32 = 0;
    for (ordinal, flow) in flows.iter().enumerate() {
        let trace = trace_from_flow(flow, ordinal as u64, options);
        if trace.lines.is_empty() {
            // Bytes were captured but nothing could be decoded into lines —
            // the transport question is unanswerable for this flow.
            if !flow.to_server.is_empty() || !flow.to_client.is_empty() {
                transport_unknown_sessions += 1;
            }
            continue;
        }
        let outcome = analyze(&trace, &options.analyzers);
        let session = &outcome.session;
        if outcome.analyzed_as == Protocol::Unknown {
            unknown_protocol_sessions += 1;
        }
        // Promised evidence markers (forensics.md §8, FOR-10): absence of
        // evidence must be counted, not read as clean.
        for code in session_limitation_codes(session) {
            match code {
                limitation_codes::TRANSPORT_UNKNOWN => transport_unknown_sessions += 1,
                limitation_codes::KEX_UNOBSERVED => kex_unobserved_sessions += 1,
                limitation_codes::AUTH_UNOBSERVED => auth_unobserved_sessions += 1,
                _ => {}
            }
        }
        if flow.has_gaps {
            flows_with_gaps += 1;
        }
        let (findings, diagnostics) = engine.evaluate_session_with_diagnostics(session);
        dropped_without_evidence += diagnostics.dropped_without_evidence;
        sessions += 1;
        builder = builder.add_session_findings(1, findings);
    }
    if flows_with_gaps > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::STREAM_GAP,
            &format!(
                "{flows_with_gaps} flow(s) had TCP sequence gaps; bytes across the gaps were not analyzed."
            ),
        ));
    }
    if dropped_segments > 0 || dropped_flows > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::CAPTURE_OVER_LIMIT,
            &format!(
                "Reassembly bounds dropped {dropped_segments} segment(s) in {dropped_flows} refused flow(s); those bytes were not analyzed."
            ),
        ));
    }
    if dropped_without_evidence > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::EVIDENCELESS_DROPPED,
            &format!(
                "The engine dropped {dropped_without_evidence} finding(s) for lack of evidence; a rule needs review."
            ),
        ));
    }
    if sessions > 0 {
        // Capture input never validates chains (contract §1): report-level
        // truth even where no per-session certificate finding fired.
        builder = builder.limitation(Limitation::new(
            limitation_codes::CHAIN_UNVERIFIED,
            "Capture input: no trust layer validated any presented chain.",
        ));
    }
    if unknown_protocol_sessions > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::PROTOCOL_UNKNOWN,
            &format!(
                "{unknown_protocol_sessions} session(s) could not be identified as SMTP, IMAP, or POP3."
            ),
        ));
    }
    if transport_unknown_sessions > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::TRANSPORT_UNKNOWN,
            &format!(
                "{transport_unknown_sessions} session(s) had transport security unclassifiable from the capture."
            ),
        ));
    }
    if kex_unobserved_sessions > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::KEX_UNOBSERVED,
            &format!(
                "{kex_unobserved_sessions} session(s) resumed or had missing handshake bytes; no fresh key exchange observed."
            ),
        ));
    }
    if auth_unobserved_sessions > 0 {
        builder = builder.limitation(Limitation::new(
            limitation_codes::AUTH_UNOBSERVED,
            &format!(
                "{auth_unobserved_sessions} protected session(s) showed no authentication exchange."
            ),
        ));
    }
    let report = builder.build();
    let diagnostics = PipelineDiagnostics {
        frames_read,
        tcp_segments,
        flows: flows.len(),
        sessions,
        skips: skips
            .into_iter()
            .map(|(reason, frames)| SkipCount {
                reason: reason.to_string(),
                frames,
            })
            .collect(),
        dropped_segments,
        dropped_flows,
        dropped_without_evidence,
    };
    Ok(CaptureReport {
        report,
        diagnostics,
    })
}

/// Build an analyzable trace from one reassembled flow.
///
/// The flow protocol starts as [`Protocol::Unknown`] so `analyze` sniffs it
/// from the greeting lines; mail client/server roles come from
/// [`resolve_roles`]. Lines from both directions merge in capture (frame)
/// order.
fn trace_from_flow(
    flow: &ReassembledFlow,
    session_index: u64,
    options: &CaptureOptions,
) -> ProtocolTrace {
    let started_at_unix_ms = flow.first_timestamp_ms.min(i64::MAX as u64) as i64;
    // (earliest frame, initiator-first rank, direction, byte range)
    let mut lines: Vec<(u64, u8, bool, u64, u64)> = Vec::new();
    collect_lines(
        &mut lines,
        &flow.to_server,
        &flow.extents_to_server,
        true,
        &options.analyzers,
    );
    collect_lines(
        &mut lines,
        &flow.to_client,
        &flow.extents_to_client,
        false,
        &options.analyzers,
    );
    lines.sort();
    let initiator_is_client = resolve_roles(flow, lines.first().map(line_text(flow)));
    let mut trace = ProtocolTrace::new(
        &options.source_tag,
        Protocol::Unknown,
        if initiator_is_client {
            flow.initiator.clone()
        } else {
            flow.responder.clone()
        },
        if initiator_is_client {
            flow.responder.clone()
        } else {
            flow.initiator.clone()
        },
        started_at_unix_ms,
    );
    trace.session_index = session_index;
    for (_, _, to_server, start, end) in lines {
        let bytes = if to_server {
            &flow.to_server
        } else {
            &flow.to_client
        };
        let Some(slice) = slice_range(bytes, start, end) else {
            continue;
        };
        let text = String::from_utf8_lossy(slice);
        // `to_server` means "sent by the initiator": it is a client line
        // exactly when the initiator is the client.
        let direction = if to_server == initiator_is_client {
            Direction::Client
        } else {
            Direction::Server
        };
        let frames = flow.frames_for_range(to_server, start, end, 64);
        trace.push(TraceLine::new(direction, text.as_ref()).with_frames(&frames));
    }
    trace
}

/// Extract the text of a collected line range for role resolution.
fn line_text(flow: &ReassembledFlow) -> impl Fn(&(u64, u8, bool, u64, u64)) -> (bool, String) + '_ {
    move |(_, _, to_server, start, end): &(u64, u8, bool, u64, u64)| {
        let bytes = if *to_server {
            &flow.to_server
        } else {
            &flow.to_client
        };
        let text = slice_range(bytes, *start, *end)
            .map(|slice| String::from_utf8_lossy(slice).into_owned())
            .unwrap_or_default();
        (*to_server, text)
    }
}

/// Resolve which flow endpoint is the mail client.
///
/// Priority — every step is an observation, never a guess:
///
/// 1. **Well-known mail port** (IANA fact via
///    `Protocol::from_well_known_port`): when exactly one endpoint sits on
///    25/465/587/143/993/110/995, that peer is the server.
/// 2. **Greeting content**: the sender of the earliest line is the server
///    when that line is a recognizable server greeting (`220`, `+OK`,
///    `-ERR`, `* OK`/`* PREAUTH`/`* BYE`, `IMAP4REV`). Mail servers greet
///    first on every standard port, including non-standard ones (dev
///    servers, tunnels) where rule 1 abstains.
/// 3. **Initiator default**: the first observed sender is the client.
///
/// Returns `true` when the initiator is the client.
fn resolve_roles(flow: &ReassembledFlow, earliest: Option<(bool, String)>) -> bool {
    let initiator_mail_port = Protocol::from_well_known_port(flow.initiator.port).is_some();
    let responder_mail_port = Protocol::from_well_known_port(flow.responder.port).is_some();
    match (initiator_mail_port, responder_mail_port) {
        (false, true) => return true,
        (true, false) => return false,
        _ => {}
    }
    if let Some((to_server, text)) = earliest
        && is_server_greeting(&text)
    {
        // The greeting's sender is the server: if the initiator sent
        // it, the initiator is the server.
        return !to_server;
    }
    true
}

/// `true` when a line looks like a mail server greeting (mirrors the
/// `sniff_protocol` markers in `analyzers`, which stay authoritative for
/// protocol identity — this only decides direction).
fn is_server_greeting(text: &str) -> bool {
    let upper = text.trim_start().to_ascii_uppercase();
    upper.starts_with("220")
        || upper.starts_with("+OK")
        || upper.starts_with("-ERR")
        || upper.starts_with("* OK")
        || upper.starts_with("* PREAUTH")
        || upper.starts_with("* BYE")
        || upper.contains("IMAP4REV")
}

/// Split one direction's bytes into CRLF/LF-terminated line ranges.
///
/// Empty lines carry no signal and are skipped. Bounded by
/// `max_lines` per direction; over-long lines are truncated on a
/// character boundary (credentials never survive: only the analyzer's
/// verb/code extraction ever reads these lines).
fn collect_lines(
    out: &mut Vec<(u64, u8, bool, u64, u64)>,
    bytes: &[u8],
    extents: &[crate::pcap::StreamExtent],
    to_server: bool,
    limits: &AnalyzerLimits,
) {
    let mut start: usize = 0;
    let mut count: usize = 0;
    let mut index = 0usize;
    while index < bytes.len() {
        if count >= limits.max_lines {
            break;
        }
        if matches!(bytes.get(index).copied(), Some(b'\n')) {
            let mut end = index;
            if end > start && matches!(bytes.get(end - 1).copied(), Some(b'\r')) {
                end -= 1;
            }
            push_line(out, bytes, extents, to_server, start, end, limits);
            count += 1;
            start = index + 1;
        }
        index += 1;
    }
    // Trailing bytes without a terminator still form a (possibly partial) line.
    if start < bytes.len() && count < limits.max_lines {
        push_line(out, bytes, extents, to_server, start, bytes.len(), limits);
    }
}

/// Record one line range with its earliest covering frame for ordering.
fn push_line(
    out: &mut Vec<(u64, u8, bool, u64, u64)>,
    bytes: &[u8],
    extents: &[crate::pcap::StreamExtent],
    to_server: bool,
    start: usize,
    end: usize,
    limits: &AnalyzerLimits,
) {
    let Some(slice) = slice_range(bytes, start as u64, end as u64) else {
        return;
    };
    if slice
        .iter()
        .all(|byte| *byte == b'\r' || *byte == b'\n' || *byte == b' ')
    {
        return;
    }
    let truncated_end = char_truncate_end(slice, limits.max_line_chars);
    let end = start as u64 + truncated_end as u64;
    let mut earliest = u64::MAX;
    for extent in extents {
        if extent.start < end && (start as u64) < extent.end && extent.frame < earliest {
            earliest = extent.frame;
        }
    }
    if earliest == u64::MAX {
        earliest = 0;
    }
    let rank = if to_server { 0 } else { 1 };
    out.push((earliest, rank, to_server, start as u64, end));
}

/// Byte-range slice without indexing (crate denies `indexing_slicing`).
fn slice_range(bytes: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    if start > end || end > bytes.len() as u64 {
        return None;
    }
    bytes.get(start as usize..end as usize)
}

/// Byte length of the first `max_chars` characters (char-boundary safe).
///
/// Operates on valid UTF-8 only; undecodable input falls back to a byte cap
/// (the pipeline lossy-decodes after truncation, and analyzers sanitize
/// everything through `SafeText` downstream).
fn char_truncate_end(slice: &[u8], max_chars: usize) -> usize {
    let Ok(text) = std::str::from_utf8(slice) else {
        return slice.len().min(max_chars);
    };
    let mut end = 0usize;
    for (kept, (index, ch)) in text.char_indices().enumerate() {
        if kept >= max_chars {
            break;
        }
        end = index + ch.len_utf8();
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Endpoint;

    fn flow_between(initiator_port: u16, responder_port: u16) -> ReassembledFlow {
        ReassembledFlow {
            key: "k".to_string(),
            initiator: Endpoint::new("10.0.0.5", initiator_port),
            responder: Endpoint::new("93.184.216.34", responder_port),
            to_server: Vec::new(),
            to_client: Vec::new(),
            extents_to_server: Vec::new(),
            extents_to_client: Vec::new(),
            has_gaps: false,
            frames: Vec::new(),
            first_timestamp_ms: 0,
        }
    }

    #[test]
    fn char_truncation_never_splits_a_character() {
        let slice = "héllo wörld".as_bytes();
        let end = char_truncate_end(slice, 2);
        assert_eq!(&slice[..end], "hé".as_bytes());
        assert_eq!(char_truncate_end(slice, 100), slice.len());
    }

    #[test]
    fn collect_lines_splits_crlf_and_skips_blanks() {
        let bytes = b"EHLO x\r\n\r\nQUIT\r\npartial";
        let extents = [crate::pcap::StreamExtent {
            start: 0,
            end: bytes.len() as u64,
            frame: 3,
        }];
        let mut out = Vec::new();
        collect_lines(&mut out, bytes, &extents, true, &AnalyzerLimits::default());
        // EHLO, QUIT, partial — the blank line is skipped.
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|line| line.0 == 3));
    }

    #[test]
    fn slice_range_rejects_out_of_bounds() {
        let bytes = b"abc";
        assert!(slice_range(bytes, 0, 3).is_some());
        assert!(slice_range(bytes, 2, 2).is_some());
        assert!(slice_range(bytes, 0, 4).is_none());
        assert!(slice_range(bytes, 3, 2).is_none());
    }

    #[test]
    fn well_known_port_decides_roles() {
        // Initiator on the submission port is the server.
        let flow = flow_between(587, 51000);
        assert!(!resolve_roles(&flow, None));
        // Initiator on the ephemeral port is the client.
        let flow = flow_between(51000, 587);
        assert!(resolve_roles(&flow, None));
    }

    #[test]
    fn greeting_sender_is_the_server_on_odd_ports() {
        let flow = flow_between(4000, 5000);
        // Initiator greeted: initiator is the server.
        assert!(!resolve_roles(&flow, Some((true, "220 hi".to_string()))));
        // Responder greeted: responder is the server, initiator the client.
        assert!(resolve_roles(&flow, Some((false, "+OK ready".to_string()))));
        // Non-greeting first line: initiator default (client).
        assert!(resolve_roles(&flow, Some((true, "EHLO x".to_string()))));
        assert!(resolve_roles(&flow, None));
    }
}
