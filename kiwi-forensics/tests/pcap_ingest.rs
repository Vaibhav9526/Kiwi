//! PCAP ingest tests — every input here is treated as hostile.
//!
//! These cover the "malformed packet stream" fixtures from
//! `docs/contracts/forensics.md`: truncated records, impossible lengths, hostile
//! sizes. All byte vectors are synthetic; no real capture data is used
//! (`docs/SECURITY.md`: no private data in fixtures).

use kiwi_forensics::pcap::{CaptureError, CaptureFormat, CaptureLimits, LinkType, PcapReader};

/// Classic pcap global header (little-endian, microseconds).
fn classic_global_le(network: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic, stored LE
    bytes.extend_from_slice(&2u16.to_le_bytes()); // version major
    bytes.extend_from_slice(&4u16.to_le_bytes()); // version minor
    bytes.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    bytes.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
    bytes.extend_from_slice(&network.to_le_bytes());
    bytes
}

/// Classic pcap global header (big-endian, nanoseconds).
fn classic_global_be_nano() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_3c4du32.to_be_bytes()); // nano magic, stored BE
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&262_144u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes
}

/// Append a classic pcap record.
fn push_record_le(bytes: &mut Vec<u8>, ts_sec: u32, ts_frac: u32, data: &[u8], original_len: u32) {
    bytes.extend_from_slice(&ts_sec.to_le_bytes());
    bytes.extend_from_slice(&ts_frac.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&original_len.to_le_bytes());
    bytes.extend_from_slice(data);
}

fn small_limits() -> CaptureLimits {
    CaptureLimits {
        max_file_bytes: 4_096,
        max_packets: 8,
        max_captured_packet_bytes: 64,
        max_block_bytes: 1_024,
        max_interfaces: 4,
    }
}

#[test]
fn classic_pcap_reads_packets_and_timestamps() {
    let mut bytes = classic_global_le(1);
    push_record_le(
        &mut bytes,
        1_700_000_000,
        250_000,
        &[0xde, 0xad, 0xbe, 0xef],
        60,
    );
    push_record_le(&mut bytes, 1_700_000_001, 0, &[0x01, 0x02], 2);

    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("valid capture opens");
    assert_eq!(
        reader.format(),
        CaptureFormat::ClassicPcap { nanosecond: false }
    );
    assert_eq!(reader.link_type(), Some(LinkType::Ethernet));

    let first = reader.next_packet().expect("read ok").expect("one packet");
    assert_eq!(first.index, 1, "frame numbering is 1-based like Wireshark");
    assert_eq!(first.captured_len, 4);
    assert_eq!(first.original_len, 60);
    assert!(first.is_truncated(), "captured < original must be reported");
    assert_eq!(first.data, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(first.timestamp.seconds, 1_700_000_000);
    assert_eq!(first.timestamp.nanos, 250_000_000);
    assert_eq!(first.timestamp.unix_millis(), 1_700_000_000_250);

    let second = reader
        .next_packet()
        .expect("read ok")
        .expect("second packet");
    assert_eq!(second.index, 2);
    assert!(!second.is_truncated());
    assert!(reader.next_packet().expect("clean eof").is_none());
}

#[test]
fn classic_big_endian_nanosecond_capture_is_decoded() {
    let mut bytes = classic_global_be_nano();
    bytes.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    bytes.extend_from_slice(&123_456_789u32.to_be_bytes()); // nanoseconds
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb]);

    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    assert_eq!(
        reader.format(),
        CaptureFormat::ClassicPcap { nanosecond: true }
    );
    let packet = reader.next_packet().expect("ok").expect("packet");
    assert_eq!(packet.timestamp.nanos, 123_456_789);
    assert_eq!(packet.data, vec![0xaa, 0xbb]);
}

#[test]
fn unsupported_magic_is_rejected_without_guessing() {
    let bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let error = PcapReader::from_slice(&bytes, small_limits()).expect_err("must reject");
    assert!(matches!(error, CaptureError::UnsupportedFormat { .. }));
}

#[test]
fn truncated_global_header_is_an_error() {
    let bytes = [0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00];
    let error = PcapReader::from_slice(&bytes, small_limits()).expect_err("must reject");
    assert!(matches!(
        error,
        CaptureError::TruncatedHeader {
            needed: 4,
            available: 2
        }
    ));
}

#[test]
fn captured_greater_than_original_is_rejected() {
    let mut bytes = classic_global_le(1);
    push_record_le(&mut bytes, 1, 0, &[0x01, 0x02, 0x03, 0x04], 2);
    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let error = reader.next_packet().expect_err("must reject");
    match error {
        CaptureError::InconsistentLengths {
            captured_len,
            original_len,
            ..
        } => {
            assert_eq!(captured_len, 4);
            assert_eq!(original_len, 2);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn oversized_captured_length_is_rejected_before_allocation() {
    // Declares 4096 captured bytes (far over the 64-byte limit) and supplies none:
    // the limit must trip *before* any buffer is created.
    let mut bytes = classic_global_le(1);
    bytes.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
    bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_frac
    bytes.extend_from_slice(&4096u32.to_le_bytes()); // captured_len
    bytes.extend_from_slice(&4096u32.to_le_bytes()); // original_len
    // no packet bytes follow
    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let error = reader.next_packet().expect_err("must reject");
    assert!(matches!(
        error,
        CaptureError::PacketTooLarge {
            captured_len: 4_096,
            limit: 64,
            ..
        }
    ));
}

#[test]
fn packet_truncated_mid_data_is_reported_not_silently_shortened() {
    let mut bytes = classic_global_le(1);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&8u32.to_le_bytes()); // captured_len says 8
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x02]); // only 2 bytes are present
    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let error = reader.next_packet().expect_err("must reject");
    assert!(matches!(error, CaptureError::TruncatedPacket { .. }));
}

#[test]
fn packet_and_file_size_limits_are_enforced() {
    let mut bytes = classic_global_le(1);
    for _ in 0..200 {
        push_record_le(&mut bytes, 1, 0, &[0x00; 32], 32);
    }
    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let packets = reader.read_packets(4).expect("reads within budget");
    assert_eq!(packets.len(), 4, "max_packets caps a read_packets call");

    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let mut limit_error = None;
    loop {
        match reader.next_packet() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                limit_error = Some(error);
                break;
            }
        }
    }
    match limit_error {
        Some(CaptureError::LimitExceeded { limit, .. }) => assert_eq!(limit, "max_file_bytes"),
        other => panic!("expected file-size limit, got {other:?}"),
    }
}

#[test]
fn nanosecond_overflow_in_a_hostile_fraction_is_normalized() {
    // A writer that stuffs a huge fraction into a microsecond field must not
    // produce nanos >= 1e9 (which would corrupt every later timestamp).
    let mut bytes = classic_global_le(1);
    push_record_le(&mut bytes, 7, u32::MAX, &[0x00], 1);
    let mut reader = PcapReader::from_slice(&bytes, small_limits()).expect("opens");
    let packet = reader.next_packet().expect("ok").expect("packet");
    assert!(packet.timestamp.nanos < 1_000_000_000);
    assert!(packet.timestamp.seconds >= 7);
}
