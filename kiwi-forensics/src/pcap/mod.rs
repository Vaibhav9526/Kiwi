//! Bounded `.pcap`/`.pcapng` capture readers.
//!
//! Every byte here is untrusted input (SECURITY.md B7). [`PcapReader`] is a
//! streaming reader over a byte slice: bounds from [`CaptureLimits`] are
//! enforced before allocation at every step, and every failure is a
//! [`CaptureError`] value — never a panic, never an unbounded allocation.
//!
//! Scope: frame-level records ([`PcapReader`]), link/transport decoding
//! ([`decode`]), and deterministic TCP reassembly ([`reassembly`]). The
//! capture-to-report composition lives in `crate::pipeline`.

pub mod decode;
pub mod reader;
pub mod reassembly;

pub use decode::{DecodeSkip, TcpSegment, decode_tcp, skip_reasons};
pub use reader::PcapReader;
pub use reassembly::{
    ReassembledFlow, Reassembler, ReassemblyLimits, StreamExtent, StreamReassembler,
};

use serde::{Deserialize, Serialize};

/// Bounds applied before any allocation. Defaults fit local dev captures;
///
/// callers analyzing larger captures raise them explicitly and own the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLimits {
    /// Refuse to consume past this many file bytes (checked incrementally
    /// as packets are read, so huge files still open cheaply).
    pub max_file_bytes: usize,
    /// Maximum packets ever returned by one reader.
    pub max_packets: u32,
    /// Refuse a packet whose captured length exceeds this (checked before
    /// any buffer is created).
    pub max_captured_packet_bytes: u32,
    /// Refuse a pcapng block larger than this (bytes).
    pub max_block_bytes: u32,
    /// Maximum pcapng interfaces tracked (per-interface timestamp state).
    pub max_interfaces: u32,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        CaptureLimits {
            max_file_bytes: 64 * 1024 * 1024,
            max_packets: 1_000_000,
            max_captured_packet_bytes: 256 * 1024,
            max_block_bytes: 16 * 1024 * 1024,
            max_interfaces: 64,
        }
    }
}

/// Capture container format, detected from magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureFormat {
    /// Classic `.pcap` (libpcap savefile).
    ClassicPcap {
        /// `true` when timestamps are nanoseconds (magic `a1b23c4d`).
        nanosecond: bool,
    },
    /// `.pcapng` (sectioned file format).
    PcapNg,
}

/// Link-layer type of captured frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    /// IEEE 802.3 Ethernet (linktype 1).
    Ethernet,
    /// Any other linktype value, preserved raw.
    Other(u16),
}

impl LinkType {
    /// Map a pcap/IDB linktype value.
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => LinkType::Ethernet,
            other => LinkType::Other(other),
        }
    }
}

/// Capture timestamp, normalized so `nanos` is always below one second.
///
/// Hostile fractions (e.g. a microsecond field holding `u32::MAX`) carry
/// into seconds instead of corrupting later arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch.
    pub seconds: u64,
    /// Sub-second part in nanoseconds, always `< 1_000_000_000`.
    pub nanos: u32,
}

impl Timestamp {
    /// Build from seconds + a fractional part of `per_second` units.
    pub fn from_fraction(seconds: u64, frac: u64, per_second: u64) -> Self {
        let per_second = per_second.max(1);
        let carry = frac / per_second;
        let nanos = ((frac % per_second) as u128 * 1_000_000_000u128 / per_second as u128) as u32;
        Timestamp {
            seconds: seconds.saturating_add(carry),
            nanos,
        }
    }

    /// Milliseconds since the Unix epoch (saturating).
    pub fn unix_millis(&self) -> u64 {
        self.seconds
            .saturating_mul(1_000)
            .saturating_add(u64::from(self.nanos) / 1_000_000)
    }
}

/// One captured frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet {
    /// 1-based frame ordinal (matches Wireshark/tcpdump numbering).
    pub index: u64,
    /// Bytes captured for this frame.
    pub captured_len: u32,
    /// Bytes on the wire (may exceed `captured_len` when sliced).
    pub original_len: u32,
    /// Captured bytes (length == `captured_len`, enforced before allocation).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: Timestamp,
}

impl Packet {
    /// `true` when the capture sliced this frame (`captured < original`).
    pub fn is_truncated(&self) -> bool {
        self.captured_len < self.original_len
    }
}

/// Why a capture could not be opened or read. Always data, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// First bytes match neither pcap nor pcapng magic.
    UnsupportedFormat {
        /// First bytes seen (up to 4), for diagnostics.
        magic: Vec<u8>,
    },
    /// A fixed-size header ran past the available bytes.
    TruncatedHeader {
        /// Bytes the field required.
        needed: usize,
        /// Bytes actually remaining.
        available: usize,
    },
    /// A packet record ran past the available bytes.
    TruncatedPacket {
        /// 1-based frame ordinal.
        frame: u64,
        /// Bytes the record required.
        needed: usize,
        /// Bytes actually remaining.
        available: usize,
    },
    /// `captured_len` exceeds `original_len` — corrupt or hostile.
    InconsistentLengths {
        /// 1-based frame ordinal.
        frame: u64,
        /// Claimed captured length.
        captured_len: u32,
        /// Claimed wire length.
        original_len: u32,
    },
    /// Declared capture length exceeds the per-packet bound (checked before
    /// any buffer is created).
    PacketTooLarge {
        /// 1-based frame ordinal.
        frame: u64,
        /// Declared captured length.
        captured_len: u32,
        /// Bound that fired.
        limit: u32,
    },
    /// A configured bound was exceeded (which bound is named).
    LimitExceeded {
        /// Bound that fired, e.g. `"max_file_bytes"`.
        limit: &'static str,
    },
    /// A pcapng block's leading and trailing lengths disagree, or the
    /// length is not a multiple of 4.
    BlockLengthMismatch {
        /// Byte offset of the block.
        offset: usize,
    },
    /// pcapng section version other than 1.0.
    UnsupportedVersion {
        /// Byte offset of the section header.
        offset: usize,
        /// Major version seen.
        major: u16,
    },
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::UnsupportedFormat { magic } => {
                write!(f, "unsupported capture magic: {magic:02x?}")
            }
            CaptureError::TruncatedHeader { needed, available } => write!(
                f,
                "truncated capture header: need {needed} bytes, have {available}"
            ),
            CaptureError::TruncatedPacket {
                frame,
                needed,
                available,
            } => write!(
                f,
                "frame {frame}: truncated packet: need {needed} bytes, have {available}"
            ),
            CaptureError::InconsistentLengths {
                frame,
                captured_len,
                original_len,
            } => write!(
                f,
                "frame {frame}: captured length {captured_len} exceeds wire length {original_len}"
            ),
            CaptureError::PacketTooLarge {
                frame,
                captured_len,
                limit,
            } => write!(
                f,
                "frame {frame}: captured length {captured_len} exceeds bound {limit}"
            ),
            CaptureError::LimitExceeded { limit } => {
                write!(f, "capture bound exceeded: {limit}")
            }
            CaptureError::BlockLengthMismatch { offset } => {
                write!(f, "pcapng block length mismatch at offset {offset}")
            }
            CaptureError::UnsupportedVersion { offset, major } => write!(
                f,
                "unsupported pcapng section version {major} at offset {offset}"
            ),
        }
    }
}

impl std::error::Error for CaptureError {}
