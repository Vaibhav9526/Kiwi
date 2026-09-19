//! Phase-5 interface: TCP stream reassembly.
//!
//! Frame-level readers (`super`) are complete; ordered byte streams per
//! connection are not built yet. This module reserves the exact interface
//! the reassembler will implement so analyzers can be written against it.
//!
//! Status: interface only, no implementation (lib.rs gating notes). Per
//! SECURITY.md rule 7 this is a marked, isolated stub: nothing in the crate
//! calls it yet, so there is no fail-open path to test.

use serde::{Deserialize, Serialize};

/// One reassembled ordered byte stream for a single TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpStream {
    /// Caller-supplied connection key (e.g. `client:port-server:port`).
    pub key: String,
    /// Ordered payload bytes (retransmissions deduplicated by the impl).
    pub data: Vec<u8>,
    /// `true` when gaps remain (missing segments observed).
    pub has_gaps: bool,
}

/// Reassembles frames into ordered streams. Phase-5 implementor contract:
///
/// - overlapping segments resolve deterministically (first-seen wins);
/// - reassembly buffers obey `CaptureLimits`-style bounds;
/// - gaps are reported, never silently skipped.
pub trait StreamReassembler {
    /// Feed one frame's bytes; implementations buffer per connection.
    fn feed(&mut self, key: &str, seq: u32, payload: &[u8]);
    /// Drain completed streams.
    fn finish(self) -> Vec<TcpStream>;
}
