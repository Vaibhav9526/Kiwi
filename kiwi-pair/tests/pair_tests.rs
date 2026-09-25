//! Deterministic kiwi-pair tests — fixed vectors only, no OS entropy.

use kiwi_pair::*;

// ---- fixed vectors --------------------------------------------------------

/// RFC 8032 §7.1 TEST 1 — Ed25519 over the empty message.
const RFC8032_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const RFC8032_SIG_EMPTY: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

const NONCE_A: [u8; 32] = [0xAA; 32];
const NONCE_B: [u8; 32] = [0xBB; 32];

fn signer() -> DeviceSigner {
    DeviceSigner::from_seed(&RFC8032_SEED)
}

fn engine() -> PairEngine {
    PairEngine::open_memory().unwrap()
}

fn register(engine: &mut PairEngine, id: &str) {
    engine
        .register_device(
            id,
            "Test Phone",
            KeyAlgorithm::Ed25519,
            &signer().public_key(),
            Some("keystore://dev1"),
            1_700_000_000,
        )
        .unwrap();
}

fn spec(
    id: &str,
    dev: &str,
    session: &str,
    event: ChallengeEvent,
    nonce: [u8; 32],
) -> ChallengeSpec {
    ChallengeSpec {
        challenge_id: id.into(),
        device_id: dev.into(),
        session_id: session.into(),
        event,
        nonce,
    }
}

fn issue(engine: &mut PairEngine, id: &str, dev: &str, nonce: [u8; 32], now: i64) -> Challenge {
    engine
        .issue_challenge(
            spec(id, dev, "x-tx:1", ChallengeEvent::Unlock, nonce),
            now,
            CHALLENGE_TTL_SECS,
        )
        .unwrap()
}

fn resp_for(c: &Challenge, s: &DeviceSigner) -> ChallengeResponse {
    ChallengeResponse {
        challenge_id: c.challenge_id.clone(),
        device_id: c.device_id.clone(),
        session_id: c.session_id.clone(),
        event: c.event,
        signature: s.sign(&c.canonical_bytes()).to_vec(),
    }
}

// ---- crypto ---------------------------------------------------------------

#[test]
fn rfc8032_test1_vector() {
    let s = signer();
    assert_eq!(s.public_key(), RFC8032_PUB);
    assert_eq!(s.sign(b""), RFC8032_SIG_EMPTY);
    assert!(Ed25519Verifier.verify(&RFC8032_PUB, b"", &RFC8032_SIG_EMPTY));
    assert!(!Ed25519Verifier.verify(&RFC8032_PUB, b"tampered", &RFC8032_SIG_EMPTY));
    // malformed inputs fail closed, never panic
    assert!(!Ed25519Verifier.verify(&[0u8; 16], b"", &RFC8032_SIG_EMPTY));
    assert!(!Ed25519Verifier.verify(&RFC8032_PUB, b"", &[0u8; 8]));
}

#[test]
fn fingerprint_fixed_vector() {
    // sha256([0u8;32]) = 66687aadf862bd776c8fc18b8e9f8e2008971485...
    assert_eq!(
        device_fingerprint(&[0u8; 32]),
        "6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20"
    );
    assert_eq!(device_fingerprint(&RFC8032_PUB).len(), 39);
}

#[test]
fn canonical_bytes_locked_layout() {
    // Challenge::consumed is private — build via issue() like kiwi-core.
    let mut book = ChallengeBook::new();
    let c = book
        .issue(
            ChallengeSpec {
                challenge_id: "chg-1".into(),
                device_id: "dev-1".into(),
                session_id: "x-tx:1".into(),
                event: ChallengeEvent::Unlock,
                nonce: NONCE_A,
            },
            1_700_000_000,
            120,
        )
        .unwrap();
    let b = c.canonical_bytes();
    // u32be(17)+"kiwi-challenge-v1" + u32be(5)+"chg-1" + u32be(5)+"dev-1"
    // + u32be(6)+"x-tx:1" + 0x01 + 32B nonce + 8B issued + 8B expires
    assert_eq!(b.len(), 4 + 17 + 4 + 5 + 4 + 5 + 4 + 6 + 1 + 32 + 8 + 8);
    assert_eq!(&b[..4], &17u32.to_be_bytes());
    assert_eq!(&b[4..21], b"kiwi-challenge-v1");
    assert_eq!(b[21 + 4 + 5 + 4 + 5 + 4 + 6], 0x01); // Unlock tag
    // every bound field present
    assert!(b.windows(32).any(|w| w == NONCE_A));
    assert!(b.windows(5).any(|w| w == b"chg-1"));
}

// ---- tickets + QR -----------------------------------------------------------

#[test]
fn ticket_lifecycle() {
    let mut e = engine();
    let t = e
        .issue_pairing_ticket("Vaibhav's Pixel", &[7u8; 32], 1_000)
        .unwrap();
    assert_eq!(t.expires_unix, 1_000 + QR_TTL_SECS);
    assert_eq!(t.ticket.len(), 43);
    assert!(
        t.ticket
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );

    // deterministic — same rand, same ticket
    let t2 = e
        .issue_pairing_ticket("Vaibhav's Pixel", &[7u8; 32], 1_000)
        .unwrap_err();
    // PK collision — a repeated ticket insert must fail, not double-issue
    assert!(matches!(t2, PairError::Store(_)));

    assert_eq!(
        e.consume_pairing_ticket(&t.ticket, 1_100).unwrap(),
        "Vaibhav's Pixel"
    );
    assert!(matches!(
        e.consume_pairing_ticket(&t.ticket, 1_100),
        Err(PairError::InvalidTicket)
    ));
    // bad charset / wrong length
    assert!(matches!(
        e.consume_pairing_ticket("bad ticket!", 1_100),
        Err(PairError::InvalidTicket)
    ));
    // expired
    let t3 = e.issue_pairing_ticket("p2", &[8u8; 32], 1_000).unwrap();
    assert!(matches!(
        e.consume_pairing_ticket(&t3.ticket, 1_000 + QR_TTL_SECS + 1),
        Err(PairError::TicketExpired)
    ));
}

#[test]
fn qr_payload_exact_shape() {
    let t = PairingTicket {
        ticket: "b1Qc-9xR".into(),
        expires_unix: 1_729_000_300,
    };
    let json = PairEngine::qr_payload_json(
        &t,
        "ws://192.168.1.20:49310/pair",
        "Vaibhav's Pixel",
        "ed25519:AAAA",
        1_729_000_000,
    )
    .unwrap();
    // serde_json Map is sorted — exact-matchable contract shape
    assert_eq!(
        json,
        r#"{"desktop_endpoint":"ws://192.168.1.20:49310/pair","desktop_public_key_b64":"ed25519:AAAA","device_label":"Vaibhav's Pixel","expires_unix":1729000300,"issued_unix":1729000000,"pairing_ticket":"b1Qc-9xR","type":"kiwi-pairing","v":1}"#
    );
    // non-ed25519 prefix fails closed
    assert!(matches!(
        PairEngine::qr_payload_json(&t, "ws://x", "l", "rsa3072:AAAA", 0),
        Err(PairError::UnsupportedAlgorithm(_))
    ));
}

// ---- devices ----------------------------------------------------------------

#[test]
fn registration_and_revocation() {
    let mut e = engine();
    register(&mut e, "dev-1");
    assert_eq!(e.list_devices(500).unwrap()[0].status, "pending");

    assert!(matches!(
        e.register_device(
            "dev-1",
            "x",
            KeyAlgorithm::Ed25519,
            &signer().public_key(),
            None,
            0
        ),
        Err(PairError::DeviceExists(_))
    ));
    assert!(matches!(
        e.register_device("d2", "x", KeyAlgorithm::EcdsaP256, &[0u8; 33], None, 0),
        Err(PairError::UnsupportedAlgorithm(_))
    ));
    assert!(matches!(
        e.register_device("d2", "x", KeyAlgorithm::Ed25519, &[0u8; 31], None, 0),
        Err(PairError::BadKeyLength(31))
    ));

    // revoke is terminal + idempotent
    e.revoke_device("dev-1", 2_000).unwrap();
    e.revoke_device("dev-1", 2_001).unwrap();
    let d = &e.list_devices(500).unwrap()[0];
    assert_eq!(d.status, "revoked");
    assert_eq!(d.revoked_unix, Some(2_000));
    assert!(matches!(
        e.revoke_device("ghost", 0),
        Err(PairError::DeviceNotFound(_))
    ));
    // revoked device gets no new challenges
    assert!(matches!(
        e.issue_challenge(
            spec("c", "dev-1", "s", ChallengeEvent::Unlock, NONCE_A),
            3_000,
            60
        ),
        Err(PairError::DeviceRevoked(_))
    ));
}

#[test]
fn fingerprint_lookup() {
    let mut e = engine();
    register(&mut e, "dev-1");
    // registered-device fingerprint == direct computation over the pubkey
    assert_eq!(
        e.device_fingerprint("dev-1").unwrap(),
        Some(device_fingerprint(&signer().public_key()))
    );
    assert_eq!(e.device_fingerprint("ghost").unwrap(), None);
}

// ---- challenges --------------------------------------------------------------

#[test]
fn issue_gates() {
    let mut e = engine();
    register(&mut e, "dev-1"); // pending

    // pending device may only get device-pairing challenges
    assert!(matches!(
        e.issue_challenge(
            spec("c1", "dev-1", "s", ChallengeEvent::Unlock, NONCE_A),
            100,
            60
        ),
        Err(PairError::DeviceNotActive(_))
    ));
    e.issue_challenge(
        spec("c1", "dev-1", "s", ChallengeEvent::DevicePairing, NONCE_A),
        100,
        60,
    )
    .unwrap();

    // nonce reuse → replay detected
    assert!(matches!(
        e.issue_challenge(
            spec("c2", "dev-1", "s", ChallengeEvent::DevicePairing, NONCE_A),
            100,
            60
        ),
        Err(PairError::ReplayDetected)
    ));
    // ttl bounds
    assert!(matches!(
        e.issue_challenge(
            spec("c2", "dev-1", "s", ChallengeEvent::DevicePairing, NONCE_B),
            100,
            0
        ),
        Err(PairError::InvalidField {
            field: "ttl_secs",
            ..
        })
    ));
    assert!(matches!(
        e.issue_challenge(
            spec("c2", "dev-1", "s", ChallengeEvent::DevicePairing, NONCE_B),
            100,
            MAX_TTL_SECS + 1
        ),
        Err(PairError::InvalidField {
            field: "ttl_secs",
            ..
        })
    ));
    // unknown device
    assert!(matches!(
        e.issue_challenge(
            spec("c2", "ghost", "s", ChallengeEvent::Unlock, NONCE_B),
            100,
            60
        ),
        Err(PairError::DeviceNotFound(_))
    ));
}

#[test]
fn full_pairing_flow_then_unlock() {
    let mut e = engine();
    let t = e.issue_pairing_ticket("Pixel", &[9u8; 32], 1_000).unwrap();
    let label = e.consume_pairing_ticket(&t.ticket, 1_010).unwrap();
    assert_eq!(label, "Pixel");

    let s = signer();
    e.register_device(
        "dev-1",
        &label,
        KeyAlgorithm::Ed25519,
        &s.public_key(),
        Some("ks://1"),
        1_020,
    )
    .unwrap();

    // device-pairing challenge → sign → verify → device activates
    let c = e
        .issue_challenge(
            spec(
                "pair-1",
                "dev-1",
                "pair-session",
                ChallengeEvent::DevicePairing,
                NONCE_A,
            ),
            1_030,
            120,
        )
        .unwrap();
    let r = ChallengeResponse {
        challenge_id: c.challenge_id.clone(),
        device_id: c.device_id.clone(),
        session_id: c.session_id.clone(),
        event: c.event,
        signature: s.sign(&c.canonical_bytes()).to_vec(),
    };
    e.verify_response(&r, 1_040).unwrap();
    assert_eq!(e.list_devices(500).unwrap()[0].status, "active");

    // now an unlock challenge on the active device
    let c2 = issue(&mut e, "u-1", "dev-1", NONCE_B, 1_050);
    let r2 = resp_for(&c2, &s);
    e.verify_response(&r2, 1_060).unwrap();
}

#[test]
fn verify_ordering_and_replay() {
    let mut e = engine();
    register(&mut e, "dev-1");
    // activate via pairing challenge first
    let c = e
        .issue_challenge(
            spec("p", "dev-1", "ps", ChallengeEvent::DevicePairing, NONCE_A),
            100,
            120,
        )
        .unwrap();
    e.verify_response(&resp_for(&c, &signer()), 110).unwrap();

    let c2 = issue(&mut e, "u-1", "dev-1", NONCE_B, 200);
    let s = signer();

    // unknown challenge
    let mut bad = resp_for(&c2, &s);
    bad.challenge_id = "nope".into();
    assert!(matches!(
        e.verify_response(&bad, 210),
        Err(PairError::Challenge(ChallengeError::UnknownChallenge))
    ));

    // expired
    let r = resp_for(&c2, &s);
    assert!(matches!(
        e.verify_response(&r, 200 + 121),
        Err(PairError::Challenge(ChallengeError::Expired))
    ));

    // binding mismatch does not consume
    let mut bad = resp_for(&c2, &s);
    bad.session_id = "x-tx:other".into();
    assert!(matches!(
        e.verify_response(&bad, 210),
        Err(PairError::Challenge(ChallengeError::BindingMismatch))
    ));
    assert!(!e.store().get_challenge("u-1").unwrap().unwrap().consumed);

    // bad signature does not consume
    let mut bad = resp_for(&c2, &s);
    bad.signature = vec![0u8; 64];
    assert!(matches!(
        e.verify_response(&bad, 210),
        Err(PairError::Challenge(ChallengeError::InvalidSignature))
    ));

    // good signature consumes; replay then fails AlreadyConsumed
    e.verify_response(&resp_for(&c2, &s), 210).unwrap();
    assert!(matches!(
        e.verify_response(&resp_for(&c2, &s), 211),
        Err(PairError::Challenge(ChallengeError::AlreadyConsumed))
    ));
}

#[test]
fn revoked_device_cannot_verify() {
    let mut e = engine();
    register(&mut e, "dev-1");
    let c = e
        .issue_challenge(
            spec("p", "dev-1", "ps", ChallengeEvent::DevicePairing, NONCE_A),
            100,
            120,
        )
        .unwrap();
    e.revoke_device("dev-1", 105).unwrap();
    assert!(matches!(
        e.verify_response(&resp_for(&c, &signer()), 110),
        Err(PairError::DeviceRevoked(_))
    ));
}

// ---- T-269: pair_status / atomic claim / persistence / bounds ----------

/// Unique on-disk engine dir (restart tests need real pair.db files).
fn temp_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "kiwi-pair-test-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[test]
fn ticket_status_state_machine() {
    let mut e = engine();
    let t = e.issue_pairing_ticket("Pixel", &[9u8; 32], 1_000).unwrap();

    // awaiting-phone: exists, unclaimed, unexpired
    let s = e.ticket_status(&t.ticket, 1_100).unwrap();
    assert_eq!(s.state, TicketState::AwaitingPhone);
    assert_eq!(s.device_id, None);
    assert_eq!(s.expires_unix, t.expires_unix);

    // expired once past expiry — unlinked and unclaimed
    let s = e.ticket_status(&t.ticket, t.expires_unix).unwrap();
    assert_eq!(s.state, TicketState::Expired);
    assert_eq!(s.device_id, None);

    // unknown / malformed collapse to InvalidTicket
    assert!(matches!(
        e.ticket_status("nope-nope-nope", 1_100),
        Err(PairError::InvalidTicket)
    ));
    assert!(matches!(
        e.ticket_status("bad ticket!", 1_100),
        Err(PairError::InvalidTicket)
    ));
    assert!(matches!(
        e.ticket_status("short", 1_100),
        Err(PairError::InvalidTicket)
    ));
    // consumed-but-unlinked → InvalidTicket while unexpired (non-oracle)…
    let mut e2 = engine();
    let t2 = e2.issue_pairing_ticket("Other", &[8u8; 32], 1_000).unwrap();
    e2.consume_pairing_ticket(&t2.ticket, 1_010).unwrap();
    assert!(matches!(
        e2.ticket_status(&t2.ticket, 1_020),
        Err(PairError::InvalidTicket)
    ));
    // …but expiry outranks the consumed flag once it passes.
    let s = e2.ticket_status(&t2.ticket, t2.expires_unix).unwrap();
    assert_eq!(s.state, TicketState::Expired);
}

#[test]
fn claim_ticket_and_register_is_atomic_and_linked() {
    let mut e = engine();
    let t = e
        .issue_pairing_ticket("Pixel 8", &[1u8; 32], 1_000)
        .unwrap();
    let s = signer();

    let row = e
        .claim_ticket_and_register(
            &t.ticket,
            "dev-9",
            KeyAlgorithm::Ed25519,
            &s.public_key(),
            Some("ks://9"),
            1_050,
        )
        .unwrap();
    assert_eq!(row.label, "Pixel 8"); // label bound at issue, not re-supplied
    assert_eq!(row.status, "pending");

    // status now reports claimed with the linked device
    let st = e.ticket_status(&t.ticket, 1_060).unwrap();
    assert_eq!(st.state, TicketState::Claimed);
    assert_eq!(st.device_id.as_deref(), Some("dev-9"));

    // claim is single-use even against its own link
    assert!(matches!(
        e.claim_ticket_and_register(
            &t.ticket,
            "dev-10",
            KeyAlgorithm::Ed25519,
            &s.public_key(),
            None,
            1_070,
        ),
        Err(PairError::TicketConsumed)
    ));
}

#[test]
fn claim_rejects_expired_and_duplicate_without_consuming() {
    let mut e = engine();
    let s = signer();

    // expired ticket: claim fails TicketExpired and the ticket is NOT
    // consumed (it still reports expired, not invalid)
    let t = e.issue_pairing_ticket("Old", &[2u8; 32], 1_000).unwrap();
    assert!(matches!(
        e.claim_ticket_and_register(
            &t.ticket,
            "dev-x",
            KeyAlgorithm::Ed25519,
            &s.public_key(),
            None,
            1_000 + QR_TTL_SECS + 1,
        ),
        Err(PairError::TicketExpired)
    ));
    let st = e.ticket_status(&t.ticket, 1_000 + QR_TTL_SECS + 2).unwrap();
    assert_eq!(st.state, TicketState::Expired);

    // duplicate device_id → DeviceExists, ticket stays unclaimed
    let t2 = e
        .issue_pairing_ticket("Phone A", &[3u8; 32], 2_000)
        .unwrap();
    e.claim_ticket_and_register(
        &t2.ticket,
        "dev-1",
        KeyAlgorithm::Ed25519,
        &s.public_key(),
        None,
        2_010,
    )
    .unwrap();
    let t3 = e
        .issue_pairing_ticket("Phone B", &[4u8; 32], 2_020)
        .unwrap();
    assert!(matches!(
        e.claim_ticket_and_register(
            &t3.ticket,
            "dev-1",
            KeyAlgorithm::Ed25519,
            &[7u8; 32],
            None,
            2_030,
        ),
        Err(PairError::DeviceExists(_))
    ));
    // t3 untouched — still awaiting (claim rolled back)
    let st = e.ticket_status(&t3.ticket, 2_040).unwrap();
    assert_eq!(st.state, TicketState::AwaitingPhone);
}

#[test]
fn duplicate_labels_conflict_on_issue_and_register() {
    let mut e = engine();
    let s = signer();
    e.register_device(
        "dev-1",
        "My Phone",
        KeyAlgorithm::Ed25519,
        &s.public_key(),
        None,
        1_000,
    )
    .unwrap();

    // normalized (trim + case) duplicates refuse at both entry points
    assert!(matches!(
        e.issue_pairing_ticket(" my phone ", &[6u8; 32], 1_010),
        Err(PairError::DeviceLabelConflict(_))
    ));
    assert!(matches!(
        e.register_device(
            "dev-7",
            "MY PHONE",
            KeyAlgorithm::Ed25519,
            &[3u8; 32],
            None,
            1_020
        ),
        Err(PairError::DeviceLabelConflict(_))
    ));
    // …but a revoked device releases its name
    e.revoke_device("dev-1", 1_030).unwrap();
    e.register_device(
        "dev-8",
        "My Phone",
        KeyAlgorithm::Ed25519,
        &[4u8; 32],
        None,
        1_040,
    )
    .unwrap();
}

#[test]
fn issue_pairing_challenge_requires_pending_device() {
    let mut e = engine();
    register(&mut e, "dev-1");
    let s = signer();
    // activate via the pairing challenge
    let c = e
        .issue_challenge(
            spec("p", "dev-1", "sess", ChallengeEvent::DevicePairing, NONCE_A),
            100,
            120,
        )
        .unwrap();
    e.verify_response(&resp_for(&c, &s), 110).unwrap();
    // PAIR-1: an active device can no longer be issued a pairing challenge
    assert!(matches!(
        e.issue_challenge(
            spec(
                "p2",
                "dev-1",
                "sess",
                ChallengeEvent::DevicePairing,
                NONCE_B
            ),
            120,
            120,
        ),
        Err(PairError::DeviceNotActive(DeviceStatus::Active))
    ));
    // unlock still works on active
    e.issue_challenge(
        spec("u", "dev-1", "sess", ChallengeEvent::Unlock, [0xCC; 32]),
        130,
        120,
    )
    .unwrap();
}

#[test]
fn revocation_and_replay_survive_reopen() {
    let root = temp_root("reopen");
    {
        let mut e = PairEngine::open(&root).unwrap();
        register(&mut e, "dev-1");
        let s = signer();
        let c = e
            .issue_challenge(
                spec("p", "dev-1", "sess", ChallengeEvent::DevicePairing, NONCE_A),
                100,
                120,
            )
            .unwrap();
        e.verify_response(&resp_for(&c, &s), 110).unwrap();
        e.revoke_device("dev-1", 120).unwrap();
    } // engine dropped — everything below is a FRESH open on the same db

    let mut e = PairEngine::open(&root).unwrap();
    let d = e.list_devices(500).unwrap();
    assert_eq!(d[0].status, "revoked");
    assert_eq!(d[0].revoked_unix, Some(120));
    // revoked device can never be challenged again — across the restart
    assert!(matches!(
        e.issue_challenge(
            spec("u2", "dev-1", "sess", ChallengeEvent::Unlock, [0xDD; 32]),
            130,
            120,
        ),
        Err(PairError::DeviceRevoked(_))
    ));
    // nonce replay ledger persisted across the reopen
    register(&mut e, "dev-2");
    assert!(matches!(
        e.issue_challenge(
            spec(
                "p3",
                "dev-2",
                "sess",
                ChallengeEvent::DevicePairing,
                NONCE_A
            ),
            140,
            120,
        ),
        Err(PairError::ReplayDetected)
    ));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn two_engines_cannot_both_consume_one_challenge() {
    let root = temp_root("race");
    let mut e1 = PairEngine::open(&root).unwrap();
    let mut e2 = PairEngine::open(&root).unwrap();
    let s = signer();
    register(&mut e1, "dev-1");
    let c = e1
        .issue_challenge(
            spec("p", "dev-1", "sess", ChallengeEvent::DevicePairing, NONCE_A),
            100,
            120,
        )
        .unwrap();
    let r = resp_for(&c, &s);
    e1.verify_response(&r, 110).unwrap();
    // The second engine instance sees the row consumed at read time — and
    // even if it had raced past that read, the atomic UPDATE inside
    // consume_challenge_and_activate refuses a second success.
    assert!(matches!(
        e2.verify_response(&r, 111),
        Err(PairError::Challenge(ChallengeError::AlreadyConsumed))
    ));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn device_list_total_order_and_bound() {
    let mut e = engine();
    let s = signer();
    // Same registered_unix on purpose — device_id breaks the tie.
    for (id, label) in [("dev-b", "B"), ("dev-a", "A"), ("dev-c", "C")] {
        e.register_device(
            id,
            label,
            KeyAlgorithm::Ed25519,
            &s.public_key(),
            None,
            1_700_000_000,
        )
        .unwrap();
    }
    let ids: Vec<String> = e
        .list_devices(500)
        .unwrap()
        .into_iter()
        .map(|d| d.device_id)
        .collect();
    assert_eq!(ids, vec!["dev-a", "dev-b", "dev-c"]);
    assert_eq!(e.list_devices(2).unwrap().len(), 2);
}

#[test]
fn verify_response_bounds_input_before_lookup() {
    let mut e = engine();
    register(&mut e, "dev-1");
    let r = ChallengeResponse {
        challenge_id: String::new(),
        device_id: "dev-1".into(),
        session_id: "s".into(),
        event: ChallengeEvent::Unlock,
        signature: vec![0u8; 64],
    };
    assert!(matches!(
        e.verify_response(&r, 100),
        Err(PairError::InvalidField {
            field: "challenge_id",
            ..
        })
    ));
    let r2 = ChallengeResponse {
        challenge_id: "c".into(),
        device_id: "dev-1".into(),
        session_id: "s".into(),
        event: ChallengeEvent::Unlock,
        signature: vec![0u8; 600],
    };
    assert!(matches!(
        e.verify_response(&r2, 100),
        Err(PairError::InvalidField {
            field: "signature",
            ..
        })
    ));
}
