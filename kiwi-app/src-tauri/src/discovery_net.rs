//! Live `DiscoveryNet` for `kiwi_autoconfig::discover` (T-230).
//!
//! Two real network operations, both behind the crate's
//! "failures are `None`/empty — stages skip" contract:
//!
//! - `fetch_https` rides the shared integrations transport (reqwest +
//!   rustls, HTTPS-only, no redirects, bounded body) and truncates to the
//!   autoconfig XML cap.
//! - `lookup_mx` uses hickory's system resolver (same pin kiwi-mailauth
//!   declared; the mailauth live adapter is a separate task).
//!
//! `DiscoveryNet` is a synchronous trait — each call drives a private
//! current-thread runtime (the mailauth convention). The command layer
//! already runs discovery on a blocking thread, so nothing stalls the
//! async executor.

use std::sync::Arc;

use kiwi_autoconfig::net::{DiscoveryNet, MxRecord};
use kiwi_integrations::http::{HttpClient, HttpRequest};

/// Production discovery net built on the shared integrations transport.
pub struct LiveDiscoveryNet {
    http: Arc<dyn HttpClient>,
}

impl LiveDiscoveryNet {
    pub fn new(http: Arc<dyn HttpClient>) -> Self {
        Self { http }
    }

    /// Fresh current-thread runtime per call — discovery is a rare,
    /// wizard-time operation, and a private runtime keeps the sync trait
    /// honest (the mailauth live-adapter convention).
    fn runtime() -> Option<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
    }
}

impl DiscoveryNet for LiveDiscoveryNet {
    fn lookup_mx(&self, domain: &kiwi_autoconfig::DomainName) -> Vec<MxRecord> {
        let Some(rt) = Self::runtime() else {
            return Vec::new();
        };
        let name = domain.as_str().to_string();
        rt.block_on(async move {
            let resolver = hickory_resolver::TokioResolver::builder_tokio()
                .ok()?
                .build()
                .ok()?;
            let lookup = resolver.mx_lookup(name).await.ok()?;
            let out: Vec<MxRecord> = lookup
                .answers()
                .iter()
                .take(kiwi_autoconfig::MAX_CANDIDATES)
                .filter_map(|r| match &r.data {
                    hickory_resolver::proto::rr::RData::MX(mx) => {
                        kiwi_autoconfig::DomainName::parse(&mx.exchange.to_utf8())
                            .ok()
                            .map(|host| MxRecord {
                                host: host.as_str().to_string(),
                                preference: mx.preference,
                            })
                    }
                    _ => None,
                })
                .collect();
            Some(out)
        })
        .unwrap_or_default()
    }

    fn fetch_https(&self, url: &str) -> Option<String> {
        let rt = Self::runtime()?;
        let http = self.http.clone();
        let url = url.to_string();
        rt.block_on(async move { http.request(HttpRequest::get(url)).await })
            .ok()
            .filter(|resp| (200..300).contains(&resp.status))
            .and_then(|resp| {
                // Autoconfig docs are small XML — cap at the crate's bound
                // on top of the transport's body cap (defense in depth).
                let body = &resp.body[..resp.body.len().min(kiwi_autoconfig::MAX_XML_LEN)];
                String::from_utf8(body.to_vec()).ok()
            })
    }
}
