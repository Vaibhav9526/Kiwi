//! Link/network/transport header decoding: Ethernet + IPv4 + TCP.
//!
//! Turns capture-frame bytes into directed [`TcpSegment`]s for reassembly.
//! Anything else (non-Ethernet link types, non-IPv4 ethertypes, non-TCP IP
//! protocols, truncated or malformed headers) is a [`DecodeSkip`] value:
//! counted by the pipeline, never fatal, never guessed.
//!
//! Scope is deliberate: mail forensics needs TCP payload bytes with
//! direction, not a general packet dissector. IPv6, VLAN tags, tunnels and
//! TCP options are skipped with a named reason (see [`skip_reasons`]) rather
//! than half-parsed.

use super::LinkType;

/// One TCP segment extracted from a frame: directed payload bytes plus the
/// provenance the pipeline needs to rebuild an ordered, attributed stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    /// Source IPv4 literal (`"a.b.c.d"`).
    pub source_ip: String,
    /// Source TCP port.
    pub source_port: u16,
    /// Destination IPv4 literal.
    pub dest_ip: String,
    /// Destination TCP port.
    pub dest_port: u16,
    /// TCP sequence number of the first payload byte.
    pub seq: u32,
    /// Payload bytes (empty for pure ACKs; still a valid segment).
    pub payload: Vec<u8>,
    /// 1-based capture frame this segment came from.
    pub frame_index: u64,
    /// Capture timestamp of the frame, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// Why a frame contributed no TCP segment. Counted, never fatal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeSkip {
    /// 1-based capture frame that was skipped.
    pub frame_index: u64,
    /// One of [`skip_reasons`].
    pub reason: &'static str,
}

/// Stable skip reasons (also used as limitation detail text).
pub mod skip_reasons {
    /// Frame arrived on a link type other than Ethernet.
    pub const NON_ETHERNET_LINK: &str = "non-ethernet-link";
    /// Ethernet ethertype is not IPv4 (covers ARP, IPv6, VLAN-tagged, …).
    pub const NON_IPV4: &str = "non-ipv4";
    /// IP protocol is not TCP (UDP, ICMP, …).
    pub const NON_TCP: &str = "non-tcp";
    /// A fixed-size header ran past the captured bytes.
    pub const TRUNCATED_HEADER: &str = "truncated-header";
    /// Header fields contradict each other (bad version, IHL < 5, …).
    pub const MALFORMED_HEADER: &str = "malformed-header";
}

/// Copy out one byte or `None`.
fn get1(bytes: &[u8], at: usize) -> Option<u8> {
    bytes.get(at).copied()
}

/// Copy out a big-endian u16 or `None`.
fn get_u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    let hi = get1(bytes, at)? as u16;
    let lo = get1(bytes, at + 1)? as u16;
    Some((hi << 8) | lo)
}

/// Copy out a big-endian u32 or `None`.
fn get_u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    let mut value: u32 = 0;
    for offset in 0..4 {
        value = (value << 8) | get1(bytes, at + offset)? as u32;
    }
    Some(value)
}

/// Format four bytes as an IPv4 literal. Total function over its inputs.
fn ipv4_literal(bytes: &[u8], at: usize) -> Option<String> {
    Some(format!(
        "{}.{}.{}.{}",
        get1(bytes, at)?,
        get1(bytes, at + 1)?,
        get1(bytes, at + 2)?,
        get1(bytes, at + 3)?
    ))
}

/// Extract the TCP segment from one frame, or explain the skip.
///
/// `link` is the capture's link type (unknown link types are skipped, never
/// guessed); `timestamp_ms` is carried through untouched for stream timing.
pub fn decode_tcp(
    link: Option<LinkType>,
    data: &[u8],
    frame_index: u64,
    timestamp_ms: u64,
) -> Result<TcpSegment, DecodeSkip> {
    let skip = |reason: &'static str| DecodeSkip {
        frame_index,
        reason,
    };
    if link != Some(LinkType::Ethernet) {
        return Err(skip(skip_reasons::NON_ETHERNET_LINK));
    }
    // Ethernet: 6 dst + 6 src + 2 ethertype.
    const ETH_HEADER: usize = 14;
    let ethertype = get_u16_be(data, 12).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    if ethertype != 0x0800 {
        return Err(skip(skip_reasons::NON_IPV4));
    }
    // IPv4.
    let ip_start = ETH_HEADER;
    let version_ihl = get1(data, ip_start).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    if version_ihl >> 4 != 4 {
        return Err(skip(skip_reasons::MALFORMED_HEADER));
    }
    let ip_header_len = (version_ihl & 0x0F) as usize * 4;
    if ip_header_len < 20 {
        return Err(skip(skip_reasons::MALFORMED_HEADER));
    }
    let total_len =
        get_u16_be(data, ip_start + 2).ok_or(skip(skip_reasons::TRUNCATED_HEADER))? as usize;
    let protocol = get1(data, ip_start + 9).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    if protocol != 6 {
        return Err(skip(skip_reasons::NON_TCP));
    }
    let source_ip =
        ipv4_literal(data, ip_start + 12).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    let dest_ip = ipv4_literal(data, ip_start + 16).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    // TCP.
    let tcp_start = ip_start + ip_header_len;
    let source_port = get_u16_be(data, tcp_start).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    let dest_port = get_u16_be(data, tcp_start + 2).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    let seq = get_u32_be(data, tcp_start + 4).ok_or(skip(skip_reasons::TRUNCATED_HEADER))?;
    let data_offset =
        get1(data, tcp_start + 12).ok_or(skip(skip_reasons::TRUNCATED_HEADER))? as usize / 16 * 4;
    if data_offset < 20 {
        return Err(skip(skip_reasons::MALFORMED_HEADER));
    }
    let payload_start = tcp_start + data_offset;
    if payload_start > data.len() {
        // Header claims past what was captured (sliced capture or lie).
        return Err(skip(skip_reasons::TRUNCATED_HEADER));
    }
    // A sliced capture may hold fewer bytes than the IP total length
    // advertises: the payload is whatever was actually captured.
    let payload_end = (ip_start + total_len).min(data.len()).max(payload_start);
    let mut payload = Vec::new();
    let mut at = payload_start;
    while at < payload_end {
        if let Some(byte) = data.get(at) {
            payload.push(*byte);
        }
        at += 1;
    }
    Ok(TcpSegment {
        source_ip,
        source_port,
        dest_ip,
        dest_port,
        seq,
        payload,
        frame_index,
        timestamp_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/TCP frame around `payload`.
    pub(crate) fn frame(source_port: u16, dest_port: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 14];
        out[12] = 0x08;
        out[13] = 0x00;
        let total = (20 + 20 + payload.len()) as u16;
        out.extend_from_slice(&[
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            0x00,
            0x00,
            0x40,
            0x00,
            0x40,
            0x06,
            0x00,
            0x00,
            10,
            0,
            0,
            5,
            93,
            184,
            216,
            34,
        ]);
        out.extend_from_slice(&[
            (source_port >> 8) as u8,
            source_port as u8,
            (dest_port >> 8) as u8,
            dest_port as u8,
            (seq >> 24) as u8,
            (seq >> 16) as u8,
            (seq >> 8) as u8,
            seq as u8,
            0x00,
            0x00,
            0x00,
            0x00,
            0x50,
            0x18,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn valid_frame_decodes_with_direction_and_seq() {
        let bytes = frame(51000, 587, 1000, b"EHLO x\r\n");
        let seg =
            decode_tcp(Some(LinkType::Ethernet), &bytes, 7, 1_700_000_000_123).expect("decodes");
        assert_eq!(seg.source_ip, "10.0.0.5");
        assert_eq!(seg.dest_ip, "93.184.216.34");
        assert_eq!((seg.source_port, seg.dest_port), (51000, 587));
        assert_eq!(seg.seq, 1000);
        assert_eq!(seg.payload, b"EHLO x\r\n");
        assert_eq!(seg.frame_index, 7);
        assert_eq!(seg.timestamp_ms, 1_700_000_000_123);
    }

    #[test]
    fn pure_ack_decodes_with_empty_payload() {
        let bytes = frame(587, 51000, 44, b"");
        let seg = decode_tcp(Some(LinkType::Ethernet), &bytes, 1, 0).expect("decodes");
        assert!(seg.payload.is_empty());
    }

    #[test]
    fn non_ethernet_link_is_skipped_not_guessed() {
        let bytes = frame(1, 2, 0, b"x");
        let skip = decode_tcp(Some(LinkType::Other(228)), &bytes, 3, 0).expect_err("skipped");
        assert_eq!(skip.reason, skip_reasons::NON_ETHERNET_LINK);
        assert_eq!(skip.frame_index, 3);
    }

    #[test]
    fn arp_ethertype_is_not_ipv4() {
        let mut bytes = frame(1, 2, 0, b"x");
        bytes[12] = 0x08;
        bytes[13] = 0x06;
        let skip = decode_tcp(Some(LinkType::Ethernet), &bytes, 1, 0).expect_err("skipped");
        assert_eq!(skip.reason, skip_reasons::NON_IPV4);
    }

    #[test]
    fn udp_protocol_is_not_tcp() {
        let mut bytes = frame(1, 2, 0, b"x");
        bytes[14 + 9] = 17;
        let skip = decode_tcp(Some(LinkType::Ethernet), &bytes, 1, 0).expect_err("skipped");
        assert_eq!(skip.reason, skip_reasons::NON_TCP);
    }

    #[test]
    fn short_buffer_is_truncated_never_panics() {
        for len in [0, 1, 13, 14, 20, 40] {
            let bytes = vec![0u8; len];
            let _ = decode_tcp(Some(LinkType::Ethernet), &bytes, 1, 0);
        }
        let empty: Vec<u8> = Vec::new();
        let skip = decode_tcp(Some(LinkType::Ethernet), &empty, 1, 0).expect_err("skipped");
        assert_eq!(skip.reason, skip_reasons::TRUNCATED_HEADER);
    }

    #[test]
    fn bad_ip_version_is_malformed() {
        let mut bytes = frame(1, 2, 0, b"x");
        bytes[14] = 0x60;
        let skip = decode_tcp(Some(LinkType::Ethernet), &bytes, 1, 0).expect_err("skipped");
        assert_eq!(skip.reason, skip_reasons::MALFORMED_HEADER);
    }
}
