//! Capture-to-report integration tests: synthetic bytes in, findings out.
//!
//! Builds minimal classic-pcap files around hand-crafted Ethernet/IPv4/TCP
//! segments and asserts the full pipeline (`analyze_capture`) reproduces the
//! analyzer-level verdicts with real frame provenance attached.

use kiwi_forensics::pipeline::{CaptureOptions, analyze_capture};
use kiwi_forensics::report::limitation_codes;

const CLIENT_IP: [u8; 4] = [10, 0, 0, 5];
const SERVER_IP: [u8; 4] = [192, 0, 2, 10];
const CLIENT_PORT: u16 = 51000;
const SERVER_PORT: u16 = 587;

/// One directed TCP segment as frame bytes.
struct Segment {
    from_client: bool,
    seq: u32,
    payload: &'static [u8],
}

fn frame_bytes(seg: &Segment) -> Vec<u8> {
    let (source_ip, source_port, dest_ip, dest_port) = if seg.from_client {
        (CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
    } else {
        (SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)
    };
    let total = (20 + 20 + seg.payload.len()) as u16;
    let mut out = vec![0u8; 14];
    out[12] = 0x08;
    out[13] = 0x00;
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
    ]);
    out.extend_from_slice(&source_ip);
    out.extend_from_slice(&dest_ip);
    out.extend_from_slice(&[
        (source_port >> 8) as u8,
        source_port as u8,
        (dest_port >> 8) as u8,
        dest_port as u8,
        (seg.seq >> 24) as u8,
        (seg.seq >> 16) as u8,
        (seg.seq >> 8) as u8,
        seg.seq as u8,
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
    out.extend_from_slice(seg.payload);
    out
}

/// Wrap frames in a little-endian classic pcap with linktype Ethernet.
fn pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0xD4, 0xC3, 0xB2, 0xA1];
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        let ts = 1_700_000_000u32 + index as u32;
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

/// Assign sequence numbers per direction in capture order.
fn capture(segments: &[Segment]) -> Vec<u8> {
    let mut client_seq: u32 = 5000;
    let mut server_seq: u32 = 1000;
    let mut frames = Vec::new();
    for seg in segments {
        let seq = if seg.from_client {
            let seq = client_seq;
            client_seq += seg.payload.len() as u32;
            seq
        } else {
            let seq = server_seq;
            server_seq += seg.payload.len() as u32;
            seq
        };
        frames.push(frame_bytes(&Segment {
            from_client: seg.from_client,
            seq,
            payload: seg.payload,
        }));
    }
    pcap_bytes(&frames)
}

/// Use the segments' explicit sequence numbers (for gap testing).
fn capture_exact(segments: &[Segment]) -> Vec<u8> {
    let frames = segments.iter().map(frame_bytes).collect::<Vec<_>>();
    pcap_bytes(&frames)
}

fn smtp_strip_segments() -> Vec<Segment> {
    vec![
        Segment {
            from_client: false,
            seq: 0,
            payload: b"220 fake ESMTP\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"EHLO client\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"250-fake\r\n250-STARTTLS\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"STARTTLS\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"220 2.0.0 ready\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"235 ok\r\n",
        },
    ]
}

fn rule_ids(report: &kiwi_forensics::report::Report) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect()
}

#[test]
fn smtp_stripped_capture_yields_starttls_and_auth_findings() {
    let bytes = capture(&smtp_strip_segments());
    let options = CaptureOptions::default().with_source_tag("test-cap");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert_eq!(result.diagnostics.frames_read, 7);
    assert_eq!(result.diagnostics.tcp_segments, 7);
    assert_eq!(result.diagnostics.sessions, 1);
    assert_eq!(result.report.sessions_evaluated, 1);
    let ids = rule_ids(&result.report);
    assert!(ids.contains(&"KIWI-STARTTLS-001"), "got {ids:?}");
    assert!(ids.contains(&"KIWI-AUTH-001"), "got {ids:?}");
    // Capture input never validates chains: report-level limitation.
    assert!(
        result
            .report
            .limitations
            .iter()
            .any(|limitation| limitation.code == limitation_codes::CHAIN_UNVERIFIED),
        "chain-unverified limitation present"
    );
    // Frame provenance reaches the session sources.
    let sources = &result.report.findings[0].sources;
    assert!(!sources.is_empty(), "findings carry sources");
    assert!(
        sources.iter().any(|source| !source.frames.is_empty()),
        "capture frames attached"
    );
    // Report JSON round-trips.
    let json = result.report.to_json();
    let back = kiwi_forensics::report::Report::from_json(&json).expect("parses");
    assert_eq!(back, result.report);
}

#[test]
fn imap_login_failure_capture_yields_auth_failure() {
    let segments = vec![
        Segment {
            from_client: false,
            seq: 0,
            payload: b"* OK fake IMAP4rev1\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"a001 CAPABILITY\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"a001 OK done\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"a002 LOGIN alice s3cr3t-hunter2\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"a002 NO invalid credentials\r\n",
        },
    ];
    let bytes = capture(&segments);
    let options = CaptureOptions::default().with_source_tag("test-imap");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert_eq!(result.diagnostics.sessions, 1);
    let ids = rule_ids(&result.report);
    assert!(ids.contains(&"KIWI-AUTH-003"), "got {ids:?}");
    // The credential itself never lands in an excerpt (rule prose may still
    // discuss secrets in the abstract — match the distinctive password).
    let json = result.report.to_json();
    assert!(!json.contains("s3cr3t-hunter2"), "no credential in report");
}

#[test]
fn sequence_gap_is_a_limitation_not_a_silent_loss() {
    // Same strip scenario, but the final server reply arrives 50 bytes past
    // the contiguous sequence: reassembly flags the gap instead of hiding it.
    let segments = vec![
        Segment {
            from_client: false,
            seq: 1000,
            payload: b"220 fake ESMTP\r\n",
        },
        Segment {
            from_client: true,
            seq: 5000,
            payload: b"EHLO client\r\n",
        },
        Segment {
            from_client: false,
            seq: 1016,
            payload: b"250-fake\r\n250-STARTTLS\r\n",
        },
        Segment {
            from_client: true,
            seq: 5013,
            payload: b"STARTTLS\r\n",
        },
        Segment {
            from_client: false,
            seq: 1040,
            payload: b"220 2.0.0 ready\r\n",
        },
        Segment {
            from_client: true,
            seq: 5023,
            payload: b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n",
        },
        Segment {
            from_client: false,
            seq: 1159,
            payload: b"235 ok\r\n",
        },
    ];
    let bytes = capture_exact(&segments);
    let options = CaptureOptions::default().with_source_tag("test-gap");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert_eq!(result.diagnostics.sessions, 1);
    assert!(
        result
            .report
            .limitations
            .iter()
            .any(|limitation| limitation.code == limitation_codes::STREAM_GAP),
        "gap limitation present: {:?}",
        result.report.limitations
    );
}

#[test]
fn non_tcp_frames_are_counted_skips() {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    // An ARP frame: Ethernet ethertype 0x0806, 28 bytes of payload.
    let mut arp = vec![0u8; 14];
    arp[12] = 0x08;
    arp[13] = 0x06;
    arp.extend_from_slice(&[0u8; 28]);
    frames.push(arp);
    let mut client_seq: u32 = 5000;
    let mut server_seq: u32 = 1000;
    for seg in smtp_strip_segments() {
        let seq = if seg.from_client {
            let seq = client_seq;
            client_seq += seg.payload.len() as u32;
            seq
        } else {
            let seq = server_seq;
            server_seq += seg.payload.len() as u32;
            seq
        };
        frames.push(frame_bytes(&Segment {
            from_client: seg.from_client,
            seq,
            payload: seg.payload,
        }));
    }
    let bytes = pcap_bytes(&frames);
    let options = CaptureOptions::default().with_source_tag("test-skips");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert_eq!(result.diagnostics.frames_read, 8);
    assert_eq!(result.diagnostics.tcp_segments, 7);
    assert!(
        result
            .diagnostics
            .skips
            .iter()
            .any(|skip| skip.reason == "non-ipv4" && skip.frames == 1),
        "ARP frame counted: {:?}",
        result.diagnostics.skips
    );
    assert_eq!(result.diagnostics.sessions, 1);
}

#[test]
fn garbage_bytes_are_rejected_not_guessed() {
    let options = CaptureOptions::default();
    let error = analyze_capture(b"definitely not a capture", &options).expect_err("rejected");
    assert!(
        matches!(
            error,
            kiwi_forensics::pcap::CaptureError::UnsupportedFormat { .. }
        ),
        "unsupported magic: {error}"
    );
}

#[test]
fn starttls_accepted_without_handshake_yields_kex_limitation() {
    // FOR-10: the server accepted STARTTLS, then the flow carried TLS record
    // bytes the capture layer cannot decode — the key exchange was never
    // observed. The promised marker must fire (not be read as clean).
    let segments = vec![
        Segment {
            from_client: false,
            seq: 0,
            payload: b"220 fake ESMTP\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"EHLO client\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"250-fake\r\n250-STARTTLS\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"STARTTLS\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"220 2.0.0 ready\r\n",
        },
        // TLS ClientHello record bytes — unreadable as protocol lines.
        Segment {
            from_client: true,
            seq: 0,
            payload: b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03",
        },
    ];
    let bytes = capture(&segments);
    let options = CaptureOptions::default().with_source_tag("test-kex");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert!(
        result
            .report
            .limitations
            .iter()
            .any(|limitation| limitation.code == limitation_codes::KEX_UNOBSERVED),
        "kex-unobserved limitation present: {:?}",
        result.report.limitations
    );
}

#[test]
fn whitespace_only_flow_yields_transport_unknown() {
    // FOR-10: bytes were captured but nothing decodable — the transport
    // question is unanswerable and must be reported as a limitation.
    let segments = vec![Segment {
        from_client: true,
        seq: 0,
        payload: b"\r\n  \r\n",
    }];
    let bytes = capture(&segments);
    let options = CaptureOptions::default().with_source_tag("test-tunk");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    assert!(
        result
            .report
            .limitations
            .iter()
            .any(|limitation| limitation.code == limitation_codes::TRANSPORT_UNKNOWN),
        "transport-unknown limitation present: {:?}",
        result.report.limitations
    );
}

#[test]
fn healthy_plaintext_session_emits_no_for10_limitations() {
    // A readable plaintext session must not carry unobserved-fact markers.
    let segments = vec![
        Segment {
            from_client: false,
            seq: 0,
            payload: b"220 fake ESMTP\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"EHLO client\r\n",
        },
        Segment {
            from_client: false,
            seq: 0,
            payload: b"250-fake\r\n250 OK\r\n",
        },
        Segment {
            from_client: true,
            seq: 0,
            payload: b"QUIT\r\n",
        },
    ];
    let bytes = capture(&segments);
    let options = CaptureOptions::default().with_source_tag("test-clean");
    let result = analyze_capture(&bytes, &options).expect("pipeline runs");
    for code in [
        limitation_codes::TRANSPORT_UNKNOWN,
        limitation_codes::KEX_UNOBSERVED,
        limitation_codes::AUTH_UNOBSERVED,
    ] {
        assert!(
            !result.report.limitations.iter().any(|l| l.code == code),
            "unexpected limitation {code}: {:?}",
            result.report.limitations
        );
    }
}
