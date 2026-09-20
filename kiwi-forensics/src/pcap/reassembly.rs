//! Deterministic TCP stream reassembly (Phase-5 implementation).
//!
//! [`Reassembler`] turns directed [`TcpSegment`]s into ordered
//! [`ReassembledFlow`]s, one per connection, with payload bytes split by
//! direction. Overlapping segments resolve **first-seen-wins**; sequence
//! gaps set [`ReassembledFlow::has_gaps`] and are reported, never silently
//! skipped.
//!
//! Two deliberate observations, not guesses (contract §7 — determinism,
//! §1 — no invented findings):
//!
//! * **Initiator = first observed sender.** The peer that sends the first
//!   segment of a flow is recorded as the initiator. That is a fact about
//!   the capture, not a mail role: for server-greeting protocols the
//!   initiator is the server, and `crate::pipeline` resolves mail roles
//!   separately (well-known port, then greeting content, then default).
//! * **Overlap order is capture order.** First-seen bytes win, so feeding
//!   the same segments in a different order may merge differently —
//!   determinism means identical input yields identical output, and capture
//!   order is part of the input.
//!
//! All buffering obeys [`ReassemblyLimits`]; over-limit segments and flows
//! are dropped and counted ([`Reassembler::dropped_segments`],
//! [`Reassembler::dropped_flows`]) so the pipeline can report them instead
//! of silently losing bytes.

use super::decode::TcpSegment;
use crate::model::Endpoint;

/// Bounds applied before any buffering. Defaults fit local dev captures;
/// callers analyzing larger captures raise them explicitly and own the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Maximum concurrent flows tracked (default 1024).
    pub max_flows: usize,
    /// Maximum segments buffered per flow (default 65,536).
    pub max_segments_per_flow: usize,
    /// Maximum payload bytes kept per direction per flow (default 8 MiB).
    pub max_bytes_per_direction: usize,
    /// Maximum frame indices retained per flow (default 4096).
    pub max_frames_per_flow: usize,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        ReassemblyLimits {
            max_flows: 1024,
            max_segments_per_flow: 65_536,
            max_bytes_per_direction: 8 * 1024 * 1024,
            max_frames_per_flow: 4096,
        }
    }
}

/// One merged byte range inside a reassembled direction: which merged
/// offsets came from which capture frame. Lets the pipeline attribute
/// protocol lines back to frames without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamExtent {
    /// First merged-stream offset covered (inclusive).
    pub start: u64,
    /// First merged-stream offset not covered (exclusive).
    pub end: u64,
    /// Capture frame that carried these bytes.
    pub frame: u64,
}

/// One reassembled TCP connection: ordered payload bytes per direction.
///
/// Endpoints are named for observation order, **not** mail roles: the
/// initiator is whoever sent the first observed segment, which for
/// server-greeting protocols (all of SMTP/IMAP/POP3) is the *server*.
/// Mail client/server resolution happens in `crate::pipeline`
/// (`resolve_roles`: well-known port, then greeting content, then default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledFlow {
    /// Canonical flow key (`"a:port|b:port"`, endpoints sorted).
    pub key: String,
    /// First observed sender (not necessarily the mail client — see above).
    pub initiator: Endpoint,
    /// The other peer.
    pub responder: Endpoint,
    /// Ordered bytes from client to server.
    pub to_server: Vec<u8>,
    /// Ordered bytes from server to client.
    pub to_client: Vec<u8>,
    /// Byte extents of [`Self::to_server`], in merge order.
    pub extents_to_server: Vec<StreamExtent>,
    /// Byte extents of [`Self::to_client`], in merge order.
    pub extents_to_client: Vec<StreamExtent>,
    /// `true` when sequence gaps remain (missing segments observed).
    pub has_gaps: bool,
    /// Contributing frame indices, sorted and de-duplicated, bounded.
    pub frames: Vec<u64>,
    /// Earliest segment timestamp seen, milliseconds since the Unix epoch.
    pub first_timestamp_ms: u64,
}

impl ReassembledFlow {
    /// Frame indices whose bytes intersect merged offsets `[start, end)`.
    ///
    /// Used to attribute a protocol line back to the frames that carried
    /// it. Bounded: at most `limit` frames, in merge order.
    pub fn frames_for_range(
        &self,
        to_server: bool,
        start: u64,
        end: u64,
        limit: usize,
    ) -> Vec<u64> {
        let extents = if to_server {
            &self.extents_to_server
        } else {
            &self.extents_to_client
        };
        let mut out = Vec::new();
        for extent in extents {
            if out.len() >= limit {
                break;
            }
            if extent.start < end && start < extent.end && !out.contains(&extent.frame) {
                out.push(extent.frame);
            }
        }
        out
    }
}

/// Reassembles segments into ordered flows. Phase-5 implementor contract:
///
/// - overlapping segments resolve deterministically (first-seen wins);
/// - reassembly buffers obey [`ReassemblyLimits`];
/// - gaps are reported, never silently skipped.
pub trait StreamReassembler {
    /// Feed one decoded segment; implementations buffer per connection.
    fn feed(&mut self, segment: &TcpSegment);
    /// Drain completed flows, in first-seen flow order.
    fn finish(self) -> Vec<ReassembledFlow>;
}

/// Buffered segment with arrival order for first-seen-wins merging.
#[derive(Debug, Clone)]
struct BufferedSegment {
    seq: u32,
    payload: Vec<u8>,
    frame: u64,
    order: u64,
}

/// Per-flow buffer: one segment list per direction plus provenance.
struct FlowBuffer {
    key: String,
    initiator_ip: String,
    initiator_port: u16,
    responder_ip: String,
    responder_port: u16,
    to_responder: Vec<BufferedSegment>,
    to_initiator: Vec<BufferedSegment>,
    bytes_to_responder: u64,
    bytes_to_initiator: u64,
    frames: Vec<u64>,
    first_timestamp_ms: u64,
}

/// Bounded deterministic reassembler: the default [`StreamReassembler`].
pub struct Reassembler {
    limits: ReassemblyLimits,
    flows: Vec<FlowBuffer>,
    order: u64,
    dropped_segments: u64,
    dropped_flows: u64,
}

impl Reassembler {
    /// Create a reassembler with explicit bounds.
    pub fn new(limits: ReassemblyLimits) -> Self {
        Reassembler {
            limits,
            flows: Vec::new(),
            order: 0,
            dropped_segments: 0,
            dropped_flows: 0,
        }
    }

    /// Segments dropped because a per-flow bound fired.
    pub fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    /// New flows refused because `max_flows` fired.
    pub fn dropped_flows(&self) -> u64 {
        self.dropped_flows
    }

    /// Canonical key for an endpoint pair (sorted, so both directions
    /// of one connection share a flow).
    fn canonical_key(a_ip: &str, a_port: u16, b_ip: &str, b_port: u16) -> String {
        let left = format!("{a_ip}:{a_port}");
        let right = format!("{b_ip}:{b_port}");
        if left <= right {
            format!("{left}|{right}")
        } else {
            format!("{right}|{left}")
        }
    }
}

impl StreamReassembler for Reassembler {
    fn feed(&mut self, segment: &TcpSegment) {
        if segment.payload.is_empty() {
            return;
        }
        let key = Self::canonical_key(
            &segment.source_ip,
            segment.source_port,
            &segment.dest_ip,
            segment.dest_port,
        );
        let position = self.flows.iter().position(|flow| flow.key == key);
        let index = match position {
            Some(index) => index,
            None => {
                if self.flows.len() >= self.limits.max_flows {
                    self.dropped_flows += 1;
                    return;
                }
                self.flows.push(FlowBuffer {
                    key,
                    initiator_ip: segment.source_ip.clone(),
                    initiator_port: segment.source_port,
                    responder_ip: segment.dest_ip.clone(),
                    responder_port: segment.dest_port,
                    to_responder: Vec::new(),
                    to_initiator: Vec::new(),
                    bytes_to_responder: 0,
                    bytes_to_initiator: 0,
                    frames: Vec::new(),
                    first_timestamp_ms: segment.timestamp_ms,
                });
                self.flows.len() - 1
            }
        };
        let Some(flow) = self.flows.get_mut(index) else {
            return;
        };
        let from_initiator =
            segment.source_ip == flow.initiator_ip && segment.source_port == flow.initiator_port;
        let (list, bytes) = if from_initiator {
            (&mut flow.to_responder, &mut flow.bytes_to_responder)
        } else {
            (&mut flow.to_initiator, &mut flow.bytes_to_initiator)
        };
        if list.len() >= self.limits.max_segments_per_flow {
            self.dropped_segments += 1;
            return;
        }
        let length = segment.payload.len() as u64;
        if bytes.saturating_add(length) > self.limits.max_bytes_per_direction as u64 {
            self.dropped_segments += 1;
            return;
        }
        *bytes += length;
        let order = self.order;
        self.order = self.order.saturating_add(1);
        list.push(BufferedSegment {
            seq: segment.seq,
            payload: segment.payload.clone(),
            frame: segment.frame_index,
            order,
        });
        if segment.timestamp_ms < flow.first_timestamp_ms {
            flow.first_timestamp_ms = segment.timestamp_ms;
        }
        if flow.frames.len() < self.limits.max_frames_per_flow
            && !flow.frames.contains(&segment.frame_index)
        {
            flow.frames.push(segment.frame_index);
        }
    }

    fn finish(mut self) -> Vec<ReassembledFlow> {
        let mut out = Vec::new();
        for flow in self.flows.drain(..) {
            out.push(merge_flow(flow));
        }
        out
    }
}

/// Merge one flow's segments per direction: sequence order, first-seen-wins
/// on overlap, gaps flagged. Sequence-number wrap is handled with the
/// standard half-space heuristic.
fn merge_flow(flow: FlowBuffer) -> ReassembledFlow {
    let (to_server, extents_to_server, gaps_server) = merge_direction(flow.to_responder);
    let (to_client, extents_to_client, gaps_client) = merge_direction(flow.to_initiator);
    let mut frames = flow.frames;
    frames.sort_unstable();
    frames.dedup();
    ReassembledFlow {
        key: flow.key,
        initiator: Endpoint::new(&flow.initiator_ip, flow.initiator_port),
        responder: Endpoint::new(&flow.responder_ip, flow.responder_port),
        to_server,
        to_client,
        extents_to_server,
        extents_to_client,
        has_gaps: gaps_server || gaps_client,
        frames,
        first_timestamp_ms: flow.first_timestamp_ms,
    }
}

/// Merge one direction's segments into ordered bytes plus extents.
fn merge_direction(mut segments: Vec<BufferedSegment>) -> (Vec<u8>, Vec<StreamExtent>, bool) {
    segments.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.order.cmp(&b.order)));
    let mut bytes = Vec::new();
    let mut extents = Vec::new();
    let mut gaps = false;
    let mut cursor: Option<u64> = None;
    for segment in &segments {
        let mut start = segment.seq as u64;
        let length = segment.payload.len() as u64;
        if length == 0 {
            continue;
        }
        match cursor {
            None => {
                let base = bytes.len() as u64;
                bytes.extend_from_slice(&segment.payload);
                extents.push(StreamExtent {
                    start: base,
                    end: base + length,
                    frame: segment.frame,
                });
                cursor = Some(start + length);
            }
            Some(position) => {
                // Unwrap heuristic: a sequence far below the cursor wrapped.
                if position > start && position - start > 0x8000_0000 {
                    start += 0x1_0000_0000;
                }
                if start > position {
                    gaps = true;
                    let base = bytes.len() as u64;
                    bytes.extend_from_slice(&segment.payload);
                    extents.push(StreamExtent {
                        start: base,
                        end: base + length,
                        frame: segment.frame,
                    });
                    cursor = Some(start.saturating_add(length));
                } else if start + length > position {
                    // Overlap: first-seen bytes already kept; append the new tail.
                    let skip = (position - start) as usize;
                    let Some(tail) = segment.payload.get(skip..) else {
                        continue;
                    };
                    let base = bytes.len() as u64;
                    bytes.extend_from_slice(tail);
                    extents.push(StreamExtent {
                        start: base,
                        end: base + tail.len() as u64,
                        frame: segment.frame,
                    });
                    cursor = Some(position + tail.len() as u64);
                }
                // Fully-duplicate segments contribute nothing.
            }
        }
    }
    (bytes, extents, gaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::decode::TcpSegment;

    fn segment(
        source: (&str, u16),
        dest: (&str, u16),
        seq: u32,
        payload: &[u8],
        frame: u64,
    ) -> TcpSegment {
        TcpSegment {
            source_ip: source.0.to_string(),
            source_port: source.1,
            dest_ip: dest.0.to_string(),
            dest_port: dest.1,
            seq,
            payload: payload.to_vec(),
            frame_index: frame,
            timestamp_ms: 1_700_000_000_000 + frame,
        }
    }

    const CLIENT: (&str, u16) = ("10.0.0.5", 51000);
    const SERVER: (&str, u16) = ("93.184.216.34", 587);

    fn feed_all(segments: &[TcpSegment]) -> Vec<ReassembledFlow> {
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        for segment in segments {
            reassembler.feed(segment);
        }
        reassembler.finish()
    }

    #[test]
    fn in_order_segments_merge_with_direction_split() {
        let flows = feed_all(&[
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1),
            segment(SERVER, CLIENT, 1, b"220 hi\r\n", 2),
            segment(CLIENT, SERVER, 9, b"QUIT\r\n", 3),
        ]);
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.to_server, b"EHLO x\r\nQUIT\r\n");
        assert_eq!(flow.to_client, b"220 hi\r\n");
        assert_eq!(flow.initiator.port, 51000);
        assert_eq!(flow.responder.port, 587);
        assert!(!flow.has_gaps);
        assert_eq!(flow.frames, vec![1, 2, 3]);
    }

    #[test]
    fn out_of_order_segments_reorder_by_sequence() {
        let flows = feed_all(&[
            segment(CLIENT, SERVER, 9, b"QUIT\r\n", 2),
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1),
        ]);
        assert_eq!(flows[0].to_server, b"EHLO x\r\nQUIT\r\n");
        assert!(!flows[0].has_gaps);
    }

    #[test]
    fn overlap_resolves_first_seen_wins() {
        let flows = feed_all(&[
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1),
            // Retransmission with different bytes for the same sequence:
            // the first capture wins.
            segment(CLIENT, SERVER, 1, b"EVIL__\r\n", 2),
        ]);
        assert_eq!(flows[0].to_server, b"EHLO x\r\n");
    }

    #[test]
    fn missing_segment_sets_has_gaps() {
        let flows = feed_all(&[
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1),
            segment(CLIENT, SERVER, 100, b"QUIT\r\n", 5),
        ]);
        let flow = &flows[0];
        assert!(flow.has_gaps);
        assert_eq!(flow.to_server, b"EHLO x\r\nQUIT\r\n");
    }

    #[test]
    fn initiator_is_first_observed_sender() {
        // Server speaks first (no SYN captured): the initiator is the
        // server endpoint; mail-role resolution happens in the pipeline.
        let flows = feed_all(&[segment(SERVER, CLIENT, 1, b"220 hi\r\n", 1)]);
        assert_eq!(flows[0].initiator.port, 587);
        assert_eq!(flows[0].responder.port, 51000);
        assert_eq!(flows[0].to_client, b"");
        assert_eq!(flows[0].to_server, b"220 hi\r\n");
    }

    #[test]
    fn bounds_drop_and_count() {
        let limits = ReassemblyLimits {
            max_flows: 1,
            max_segments_per_flow: 1,
            max_bytes_per_direction: 8,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.feed(&segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1));
        // Second segment exceeds the per-flow segment bound.
        reassembler.feed(&segment(CLIENT, SERVER, 9, b"QUIT\r\n", 2));
        // Second flow exceeds the flow bound.
        reassembler.feed(&segment(("10.0.0.6", 51001), SERVER, 1, b"X", 3));
        assert_eq!(reassembler.dropped_segments(), 1);
        assert_eq!(reassembler.dropped_flows(), 1);
        let flows = reassembler.finish();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].to_server, b"EHLO x\r\n");
    }

    #[test]
    fn same_input_gives_same_output() {
        let segments = vec![
            segment(CLIENT, SERVER, 9, b"QUIT\r\n", 2),
            segment(SERVER, CLIENT, 1, b"220 hi\r\n", 3),
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 1),
        ];
        assert_eq!(feed_all(&segments), feed_all(&segments));
    }

    #[test]
    fn line_frames_come_from_covering_extents() {
        let flows = feed_all(&[
            segment(CLIENT, SERVER, 1, b"EHLO x\r\n", 4),
            segment(CLIENT, SERVER, 9, b"QUIT\r\n", 9),
        ]);
        let flow = &flows[0];
        assert_eq!(flow.frames_for_range(true, 0, 8, 64), vec![4]);
        assert_eq!(flow.frames_for_range(true, 8, 14, 64), vec![9]);
        assert_eq!(flow.frames_for_range(true, 0, 14, 64), vec![4, 9]);
    }
}
