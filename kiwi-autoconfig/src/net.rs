//! Network seam for discovery: MX lookup + HTTPS fetch.
//!
//! The trait is synchronous on purpose (mirrors `kiwi-mailauth`): the live
//! adapter blocks on a private runtime; tests use [`MockNet`] and never
//! touch the network. Failures are `None`/empty — stages skip, discovery
//! falls through to manual entry. Nothing here ever returns `Err`.

use crate::DomainName;

/// MX record: exchange host + preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// Exchange hostname (normalized).
    pub host: String,
    /// Preference value (lower = preferred).
    pub preference: u16,
}

/// What discovery needs from the network.
pub trait DiscoveryNet: Send + Sync {
    /// MX records for `domain`, preference order preserved. Empty = none.
    fn lookup_mx(&self, domain: &DomainName) -> Vec<MxRecord>;
    /// HTTPS GET body for `url`. `None` = unreachable / non-2xx / too big.
    fn fetch_https(&self, url: &str) -> Option<String>;
}

/// In-memory offline net for tests and offline operation.
#[derive(Debug, Clone, Default)]
pub struct MockNet {
    mx: std::collections::HashMap<String, Vec<MxRecord>>,
    https: std::collections::HashMap<String, String>,
}

impl MockNet {
    /// Empty net (everything unreachable).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// MX records served for `domain` (in preference order).
    #[must_use]
    pub fn with_mx(mut self, domain: &str, records: &[(&str, u16)]) -> Self {
        let v: Vec<MxRecord> = records
            .iter()
            .filter_map(|(h, p)| {
                DomainName::parse(h).ok().map(|d| MxRecord {
                    host: d.as_str().to_string(),
                    preference: *p,
                })
            })
            .take(crate::MAX_CANDIDATES)
            .collect();
        self.mx.insert(domain.trim().to_ascii_lowercase(), v);
        self
    }
    /// HTTPS body served for `url`.
    #[must_use]
    pub fn with_https(mut self, url: &str, body: &str) -> Self {
        self.https.insert(
            url.to_string(),
            body.chars().take(crate::MAX_XML_LEN).collect(),
        );
        self
    }
}

impl super::DiscoveryNet for MockNet {
    fn lookup_mx(&self, domain: &DomainName) -> Vec<MxRecord> {
        self.mx.get(domain.as_str()).cloned().unwrap_or_default()
    }
    fn fetch_https(&self, url: &str) -> Option<String> {
        self.https.get(url).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_net_empty_by_default() {
        let net = MockNet::new();
        let d = DomainName::parse("nothing.test").unwrap();
        assert!(net.lookup_mx(&d).is_empty());
        assert!(net.fetch_https("https://x.test/a.xml").is_none());
    }

    #[test]
    fn mock_net_serves_configured_records() {
        let net = MockNet::new()
            .with_mx(
                "mx.test",
                &[("alt2.aspmx.l.google.com", 20), ("aspmx.l.google.com", 10)],
            )
            .with_https(
                "https://autoconfig.mx.test/mail/config-v1.1.xml",
                "<clientConfig/>",
            );
        let d = DomainName::parse("MX.TEST").unwrap();
        let mx = net.lookup_mx(&d);
        assert_eq!(mx.len(), 2);
        // hosts are normalized via DomainName
        assert_eq!(mx[0].host, "alt2.aspmx.l.google.com");
        assert_eq!(mx[0].preference, 20);
        assert_eq!(
            net.fetch_https("https://autoconfig.mx.test/mail/config-v1.1.xml"),
            Some("<clientConfig/>".to_string())
        );
    }

    #[test]
    fn mock_net_rejects_invalid_mx_host() {
        let net = MockNet::new().with_mx("bad.test", &[("not a host!", 10)]);
        let d = DomainName::parse("bad.test").unwrap();
        assert!(net.lookup_mx(&d).is_empty());
    }

    #[test]
    fn mock_net_caps_mx_records() {
        let hosts: Vec<String> = (0..40).map(|i| format!("mx{i}.t")).collect();
        let refs: Vec<(&str, u16)> = hosts.iter().map(|h| (h.as_str(), 10)).collect();
        let net = MockNet::new().with_mx("cap.test", &refs);
        assert_eq!(
            net.lookup_mx(&DomainName::parse("cap.test").unwrap()).len(),
            crate::MAX_CANDIDATES
        );
    }
}
