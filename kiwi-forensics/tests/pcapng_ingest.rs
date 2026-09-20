//! Pcap-NG ingest tests: section/interface/packet blocks, options, and hostile
//! block structures. Synthetic bytes only.

use kiwi_forensics::pcap::{CaptureFormat, CaptureLimits, LinkType, PcapReader};

fn limits() -> CaptureLimits {
    CaptureLimits {
        max_file_bytes: 8_192,
        max_packets: 16,
        max_captured_packet_bytes: 128,
        max_block_bytes: 1_024,
        max_interfaces: 4,
    }
}

/// A pcapng block: type, length, body, trailing length (little-endian).
fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = 12 + body.len() as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&block_type.to_le_bytes());
    bytes.extend_from_slice(&total.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&total.to_le_bytes());
    bytes
}

/// Section header block (little-endian, version 1.0, unspecified length).
fn section_header() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes()); // byte-order magic
    body.extend_from_slice(&1u16.to_le_bytes()); // major
    body.extend_from_slice(&0u16.to_le_bytes()); // minor
    body.extend_from_slice(&(-1i64).to_le_bytes()); // section length
    block(0x0a0d_0d0a, &body)
}

/// Interface description block with optional if_tsresol (code 9).
fn interface_block(link_type: u16, tsresol: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&link_type.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    body.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
    if let Some(resolution) = tsresol {
        body.extend_from_slice(&9u16.to_le_bytes()); // if_tsresol
        body.extend_from_slice(&1u16.to_le_bytes()); // length 1
        body.push(resolution);
        body.extend_from_slice(&[0, 0, 0]); // pad to 4 bytes
    }
    block(0x0000_0001, &body)
}

/// Enhanced packet block; data is padded to a 4-byte boundary.
fn enhanced_packet_block(interface_id: u32, ticks: u64, data: &[u8], original_len: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&interface_id.to_le_bytes());
    body.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(ticks as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&original_len.to_le_bytes());
    body.extend_from_slice(data);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(0x0000_0006, &body)
}

#[test]
fn pcapng_section_interface_and_enhanced_packet_are_read() {
    let mut bytes = section_header();
    bytes.extend_from_slice(&interface_block(1, None));
    // 1_700_000_000 s in microseconds = 1.7e15 ticks.
    bytes.extend_from_slice(&enhanced_packet_block(
        0,
        1_700_000_000_000_000,
        &[1, 2, 3, 4],
        1514,
    ));

    let mut reader = PcapReader::from_slice(&bytes, limits()).expect("valid pcapng opens");
    assert_eq!(reader.format(), CaptureFormat::PcapNg);
    assert_eq!(reader.link_type(), Some(LinkType::Ethernet));

    let packet = reader.next_packet().expect("ok").expect("packet");
    assert_eq!(packet.index, 1);
    assert_eq!(packet.captured_len, 4);
    assert_eq!(packet.original_len, 1514);
    assert!(packet.is_truncated());
    assert_eq!(packet.data, vec![1, 2, 3, 4]);
    assert_eq!(packet.timestamp.seconds, 1_700_000_000);
    assert_eq!(packet.timestamp.nanos, 0);
    assert!(reader.next_packet().expect("clean eof").is_none());
}

#[test]
fn pcapng_nanosecond_timestamp_resolution_is_honoured() {
    let mut bytes = section_header();
    bytes.extend_from_slice(&interface_block(1, Some(9))); // 10^-9 seconds per tick
    bytes.extend_from_slice(&enhanced_packet_block(
        0,
        1_700_000_000_123_456_789,
        &[0xaa],
        1,
    ));

    let mut reader = PcapReader::from_slice(&bytes, limits()).expect("opens");
    let packet = reader.next_packet().expect("ok").expect("packet");
    assert_eq!(packet.timestamp.seconds, 1_700_000_000);
    assert_eq!(packet.timestamp.nanos, 123_456_789);
}

#[test]
fn pcapng_unknown_blocks_are_skipped_not_fatal() {
    let mut bytes = section_header();
    bytes.extend_from_slice(&block(0x0000_0005, &[0, 0, 0, 0])); // interface statistics
    bytes.extend_from_slice(&block(0x0000_0004, &[0, 0, 0, 0])); // name resolution
    bytes.extend_from_slice(&interface_block(1, None));
    bytes.extend_from_slice(&enhanced_packet_block(0, 0, &[0x0f], 1));

    let mut reader = PcapReader::from_slice(&bytes, limits()).expect("opens");
    let packet = reader.next_packet().expect("ok").expect("packet");
    assert_eq!(packet.data, vec![0x0f]);
}
