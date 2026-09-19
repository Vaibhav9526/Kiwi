//! Static parameter table for IANA-registered TLS cipher suites.
//!
//! Why a hand-maintained table instead of a crate: we need *deterministic
//! classification* (key exchange / bulk cipher / MAC) for a bounded, documented
//! set, and a cipher-suite id that is absent from the table must be reported as
//! **unrecognized** rather than silently guessed (`prompt.md` §2.5).
//!
//! Strength is **derived** from these parameters by
//! [`super::tls::CipherStrength::classify`], never stored per row, so the
//! classification stays auditable in exactly one place.
//!
//! Values are the IANA TLS Cipher Suites registry ids and official names.
//! `NULL`, `EXPORT`, anonymous-DH, RC4, 3DES and CBC/SHA-1 suites are included
//! deliberately: they are precisely what a downgrade or misconfiguration looks
//! like on the wire, and naming them is required for evidence quality.

use super::tls::{BulkCipher, KeyExchange, MacAlgorithm};

/// One row of the cipher-suite parameter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuiteParams {
    /// IANA cipher suite registry id (the two `CipherSuite` bytes on the wire).
    pub iana_id: u16,
    /// Official IANA name.
    pub name: &'static str,
    /// Key-establishment mechanism.
    pub key_exchange: KeyExchange,
    /// Bulk encryption algorithm.
    pub bulk: BulkCipher,
    /// MAC / AEAD construction.
    pub mac: MacAlgorithm,
}

const fn row(
    iana_id: u16,
    name: &'static str,
    key_exchange: KeyExchange,
    bulk: BulkCipher,
    mac: MacAlgorithm,
) -> CipherSuiteParams {
    CipherSuiteParams {
        iana_id,
        name,
        key_exchange,
        bulk,
        mac,
    }
}

/// The table, sorted ascending by `iana_id` (enforced by a unit test).
const TABLE: &[CipherSuiteParams] = &[
    // ---- NULL / EXPORT / anonymous: broken by construction ------------------
    row(
        0x0000,
        "TLS_NULL_WITH_NULL_NULL",
        KeyExchange::Null,
        BulkCipher::Null,
        MacAlgorithm::Null,
    ),
    row(
        0x0001,
        "TLS_RSA_WITH_NULL_MD5",
        KeyExchange::Rsa,
        BulkCipher::Null,
        MacAlgorithm::HmacMd5,
    ),
    row(
        0x0002,
        "TLS_RSA_WITH_NULL_SHA",
        KeyExchange::Rsa,
        BulkCipher::Null,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0003,
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        KeyExchange::Rsa,
        BulkCipher::Rc4_40,
        MacAlgorithm::HmacMd5,
    ),
    row(
        0x0004,
        "TLS_RSA_WITH_RC4_128_MD5",
        KeyExchange::Rsa,
        BulkCipher::Rc4_128,
        MacAlgorithm::HmacMd5,
    ),
    row(
        0x0005,
        "TLS_RSA_WITH_RC4_128_SHA",
        KeyExchange::Rsa,
        BulkCipher::Rc4_128,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0006,
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        KeyExchange::Rsa,
        BulkCipher::Rc2_40,
        MacAlgorithm::HmacMd5,
    ),
    row(
        0x0007,
        "TLS_RSA_WITH_IDEA_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Idea,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0008,
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Des40,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0009,
        "TLS_RSA_WITH_DES_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Des,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x000A,
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::TripleDes,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0013,
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        KeyExchange::Dhe,
        BulkCipher::Des40,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0016,
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        KeyExchange::Dhe,
        BulkCipher::Des40,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0018,
        "TLS_DH_anon_WITH_RC4_128_MD5",
        KeyExchange::Anonymous,
        BulkCipher::Rc4_128,
        MacAlgorithm::HmacMd5,
    ),
    // ---- CBC-era suites: still deployed, deprecated by modern guidance ------
    row(
        0x002F,
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0032,
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        KeyExchange::Dhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0033,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        KeyExchange::Dhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0034,
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        KeyExchange::Anonymous,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0035,
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0039,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        KeyExchange::Dhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x003C,
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        KeyExchange::Rsa,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0x003D,
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        KeyExchange::Rsa,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0x0041,
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Camellia128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0067,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        KeyExchange::Dhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0x006B,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        KeyExchange::Dhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0x008C,
        "TLS_PSK_WITH_AES_128_CBC_SHA",
        KeyExchange::Psk,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0x0096,
        "TLS_RSA_WITH_SEED_CBC_SHA",
        KeyExchange::Rsa,
        BulkCipher::Seed,
        MacAlgorithm::HmacSha1,
    ),
    // ---- AEAD without forward secrecy ---------------------------------------
    row(
        0x009C,
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        KeyExchange::Rsa,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x009D,
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        KeyExchange::Rsa,
        BulkCipher::Aes256Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x009E,
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        KeyExchange::Dhe,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x009F,
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        KeyExchange::Dhe,
        BulkCipher::Aes256Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x00A8,
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        KeyExchange::Psk,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x00AA,
        "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        KeyExchange::PskDhe,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    // ---- TLS 1.3 suites (ephemeral key agreement is implicit) ---------------
    row(
        0x1301,
        "TLS_AES_128_GCM_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x1302,
        "TLS_AES_256_GCM_SHA384",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0x1303,
        "TLS_CHACHA20_POLY1305_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::ChaCha20Poly1305,
        MacAlgorithm::Aead,
    ),
    row(
        0x1304,
        "TLS_AES_128_CCM_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Ccm,
        MacAlgorithm::Aead,
    ),
    row(
        0x1305,
        "TLS_AES_128_CCM_8_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Ccm,
        MacAlgorithm::Aead,
    ),
    // ---- ECC suites ----------------------------------------------------------
    row(
        0xC007,
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Rc4_128,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC008,
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::TripleDes,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC009,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC00A,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC011,
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Rc4_128,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC012,
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::TripleDes,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC013,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC014,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC023,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0xC024,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha384,
    ),
    row(
        0xC027,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha256,
    ),
    row(
        0xC028,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Cbc,
        MacAlgorithm::HmacSha384,
    ),
    row(
        0xC02B,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0xC02C,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0xC02F,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0xC030,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        KeyExchange::Ecdhe,
        BulkCipher::Aes256Gcm,
        MacAlgorithm::Aead,
    ),
    row(
        0xC035,
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        KeyExchange::PskEcdhe,
        BulkCipher::Aes128Cbc,
        MacAlgorithm::HmacSha1,
    ),
    row(
        0xC09C,
        "TLS_RSA_WITH_AES_128_CCM",
        KeyExchange::Rsa,
        BulkCipher::Aes128Ccm,
        MacAlgorithm::Aead,
    ),
    row(
        0xC0AC,
        "TLS_ECDHE_RSA_WITH_AES_128_CCM",
        KeyExchange::Ecdhe,
        BulkCipher::Aes128Ccm,
        MacAlgorithm::Aead,
    ),
    row(
        0xCCA8,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::ChaCha20Poly1305,
        MacAlgorithm::Aead,
    ),
    row(
        0xCCA9,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        KeyExchange::Ecdhe,
        BulkCipher::ChaCha20Poly1305,
        MacAlgorithm::Aead,
    ),
];

/// Number of cipher-suite ids this classifier can name.
pub fn table_len() -> usize {
    TABLE.len()
}

/// Look up a cipher suite by IANA id.
///
/// `None` means "unrecognized": callers must surface that as an informational
/// finding instead of classifying the suite.
pub fn lookup(iana_id: u16) -> Option<&'static CipherSuiteParams> {
    TABLE
        .binary_search_by_key(&iana_id, |entry| entry.iana_id)
        .ok()
        .and_then(|idx| TABLE.get(idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        for pair in TABLE.windows(2) {
            let [a, b] = pair else { continue };
            assert!(
                a.iana_id < b.iana_id,
                "cipher table out of order: {:#06x} then {:#06x}",
                a.iana_id,
                b.iana_id
            );
        }
        assert!(table_len() > 40, "cipher table unexpectedly small");
    }

    #[test]
    fn lookup_finds_known_and_rejects_unknown() {
        assert_eq!(
            lookup(0x1301).map(|r| r.name),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert!(lookup(0x9999).is_none());
    }

    #[test]
    fn tls13_suites_are_classified_as_aead_with_forward_secrecy() {
        let entry = lookup(0x1303).expect("tls1.3 chacha suite present");
        assert_eq!(entry.bulk, BulkCipher::ChaCha20Poly1305);
        assert_eq!(entry.mac, MacAlgorithm::Aead);
        assert_eq!(entry.key_exchange, KeyExchange::Ecdhe);
    }
}
