//! DNS abstraction: mock-first, hickory-backed live adapter.
//!
//! Tests use [`MockResolver`] (fully offline). [`HickoryResolver`] is the
//! production adapter (real system DNS). [`DnsError`] maps to `temperror`
//! in callers — never a hard failure.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use crate::{DomainName, MAX_TXT_LEN};

/// DNS failure: always `temperror` in SPF/DMARC, never `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Timeout / refused / transport error.
    Temp(String),
    /// NXDOMAIN / NODATA (no records).
    NxDomain,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Temp(s) => write!(f, "temporary DNS error: {s}"),
            Self::NxDomain => write!(f, "name does not exist"),
        }
    }
}

/// Minimal DNS surface for SPF/DKIM/DMARC. Sync on purpose: the live
/// adapter blocks on a private runtime; tests never touch the network.
pub trait DnsResolver {
    /// All TXT strings at `name`.
    fn lookup_txt(&self, name: &DomainName) -> Result<Vec<String>, DnsError>;
    /// A/AAAA addresses for `name`.
    fn lookup_host(&self, name: &DomainName) -> Result<Vec<IpAddr>, DnsError>;
    /// MX exchange hosts for `name` (priority order preserved).
    fn lookup_mx(&self, name: &DomainName) -> Result<Vec<DomainName>, DnsError>;
    /// Reverse pointer targets for `ip`.
    fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<DomainName>, DnsError>;
}

/// In-memory offline resolver for tests and offline operation.
#[derive(Debug, Clone, Default)]
pub struct MockResolver {
    txt: HashMap<String, Vec<String>>,
    host: HashMap<String, Vec<IpAddr>>,
    mx: HashMap<String, Vec<DomainName>>,
    ptr: HashMap<IpAddr, Vec<DomainName>>,
    temp_fail: Vec<String>,
}

fn norm(name: &str) -> String {
    DomainName::parse(name)
        .map(|d| d.as_str().to_string())
        .unwrap_or_else(|_| name.trim().trim_end_matches('.').to_ascii_lowercase())
}
impl MockResolver {
    /// Empty resolver (everything NXDOMAIN).
    pub fn new() -> Self {
        Self::default()
    }
    /// TXT records at `name`.
    pub fn with_txt(mut self, name: &str, records: &[&str]) -> Self {
        let key = norm(name);
        let v: Vec<String> = records
            .iter()
            .map(|s| s.chars().take(MAX_TXT_LEN).collect())
            .collect();
        self.txt.insert(key, v);
        self
    }
    /// A/AAAA addresses at `name`.
    pub fn with_host(mut self, name: &str, addrs: &[&str]) -> Self {
        let parsed: Vec<IpAddr> = addrs
            .iter()
            .filter_map(|s| IpAddr::from_str(s).ok())
            .collect();
        self.host.insert(norm(name), parsed);
        self
    }

    /// MX exchange hosts at `name`.
    pub fn with_mx(mut self, name: &str, hosts: &[&str]) -> Self {
        let parsed: Vec<DomainName> = hosts
            .iter()
            .filter_map(|s| DomainName::parse(s).ok())
            .collect();
        self.mx.insert(norm(name), parsed);
        self
    }
    /// PTR targets for `ip`.
    pub fn with_ptr(mut self, ip: IpAddr, names: &[&str]) -> Self {
        let parsed: Vec<DomainName> = names
            .iter()
            .filter_map(|s| DomainName::parse(s).ok())
            .collect();
        self.ptr.insert(ip, parsed);
        self
    }
    /// Force Temp failure for `name`.
    pub fn with_temp_fail(mut self, name: &str) -> Self {
        self.temp_fail.push(norm(name));
        self
    }
    fn check_temp(&self, name: &DomainName) -> Result<(), DnsError> {
        if self.temp_fail.iter().any(|t| t == name.as_str()) {
            return Err(DnsError::Temp("mock injected failure".to_string()));
        }
        Ok(())
    }
}

impl DnsResolver for MockResolver {
    fn lookup_txt(&self, name: &DomainName) -> Result<Vec<String>, DnsError> {
        self.check_temp(name)?;
        self.txt
            .get(name.as_str())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
    fn lookup_host(&self, name: &DomainName) -> Result<Vec<IpAddr>, DnsError> {
        self.check_temp(name)?;
        self.host
            .get(name.as_str())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
    fn lookup_mx(&self, name: &DomainName) -> Result<Vec<DomainName>, DnsError> {
        self.check_temp(name)?;
        self.mx
            .get(name.as_str())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
    fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<DomainName>, DnsError> {
        self.ptr.get(&ip).cloned().ok_or(DnsError::NxDomain)
    }
}

/// Per-attempt query timeout. DNS is off the hot path; 2s is generous for
/// a healthy resolver and keeps a dead one from stalling ingest.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
/// Total attempts per query (bounded retries — never unbounded).
const DEFAULT_ATTEMPTS: usize = 2;

/// Live DNS resolver over the system configuration (hickory-resolver).
///
/// `DnsResolver` is synchronous: each call drives a lazily-built private
/// current-thread runtime, so callers never need an ambient executor and
/// tests stay on [`MockResolver`]. Bounds are fixed at construction —
/// per-attempt `timeout` × `attempts` caps total wait, and the resolver
/// config is read from the system once at first lookup.
///
/// Failure posture is fail-closed per contract: NXDOMAIN/NODATA (and a
/// name that cannot even be encoded) map to [`DnsError::NxDomain`]; every
/// transport, timeout, or configuration failure maps to
/// [`DnsError::Temp`] — which callers render as `temperror`, never
/// `fail`. A resolver that cannot be built (no system config, no runtime)
/// memoizes as broken and every lookup returns `Temp` — degrade, don't
/// panic.
pub struct HickoryResolver {
    timeout: Duration,
    attempts: usize,
    inner: Mutex<ResolverState>,
}

/// Lazily-initialized resolver state — `Broken` memoizes a failed build
/// so a DNS-less host degrades per-lookup instead of rebuilding forever.
enum ResolverState {
    Unbuilt,
    /// Boxed: `Runtime` + resolver are large; `Broken`'s `String` keeps
    /// the enum from forcing that size on every state.
    Ready(Box<Ready>),
    Broken(String),
}

struct Ready {
    rt: tokio::runtime::Runtime,
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryResolver {
    /// System-configured resolver (`/etc/resolv.conf` / registry) with the
    /// default bounds: 2s per attempt, 2 attempts per query.
    pub fn system() -> Self {
        Self::with_bounds(DEFAULT_TIMEOUT, DEFAULT_ATTEMPTS)
    }

    /// Resolver with explicit bounds. `attempts` is clamped to ≥1 — zero
    /// would ask for zero tries and misreport `Temp` as if DNS failed.
    pub fn with_bounds(timeout: Duration, attempts: usize) -> Self {
        HickoryResolver {
            timeout,
            attempts: attempts.max(1),
            inner: Mutex::new(ResolverState::Unbuilt),
        }
    }

    /// Build the runtime + resolver once, memoizing failure. `Send`/`Sync`
    /// come from the `Mutex`. The boxed future borrows the resolver for
    /// the duration of one `block_on`.
    fn with_resolver<T, F>(&self, f: F) -> Result<T, DnsError>
    where
        T: Send,
        F: Send
            + for<'a> FnOnce(
                &'a hickory_resolver::TokioResolver,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, DnsError>> + Send + 'a>,
            >,
    {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if matches!(*state, ResolverState::Unbuilt) {
            let built = (|| -> Result<_, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime: {e}"))?;
                // `builder_tokio` reads the system resolver config
                // (/etc/resolv.conf / registry) and merges its options;
                // only the bounds are overridden — system `ndots` /
                // search-list / transport choices stay intact.
                let mut builder = hickory_resolver::TokioResolver::builder_tokio()
                    .map_err(|e| format!("system resolver config: {e}"))?;
                let options = builder.options_mut();
                options.timeout = self.timeout;
                options.attempts = self.attempts;
                let resolver = builder
                    .build()
                    .map_err(|e| format!("resolver build: {e}"))?;
                Ok((rt, resolver))
            })();
            *state = match built {
                Ok((rt, resolver)) => ResolverState::Ready(Box::new(Ready { rt, resolver })),
                Err(e) => ResolverState::Broken(e),
            };
        }
        match &*state {
            ResolverState::Ready(ready) => {
                // `Runtime::block_on` panics when invoked from a thread
                // already driving an async runtime — and this sync facade
                // is called from Tauri async command handlers. Scoped-
                // thread the `block_on` so the facade is context-agnostic;
                // a panicking lookup degrades to `Temp`, never propagates.
                let Ready { rt, resolver } = &**ready;
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| rt.block_on(f(resolver)))
                        .join()
                        .unwrap_or_else(|_| {
                            Err(DnsError::Temp("dns lookup thread panicked".into()))
                        })
                })
            }
            ResolverState::Broken(e) => Err(DnsError::Temp(e.clone())),
            ResolverState::Unbuilt => unreachable!("state assigned above"),
        }
    }

    /// Map a hickory transport/parse outcome onto the contract's two-value
    /// error vocabulary. `is_no_records_found` covers NXDOMAIN *and*
    /// NODATA; everything else is a temporary failure.
    fn map_err(e: hickory_resolver::net::NetError) -> DnsError {
        if e.is_no_records_found() {
            DnsError::NxDomain
        } else {
            DnsError::Temp(e.to_string())
        }
    }
}

impl std::fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("timeout", &self.timeout)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl DnsResolver for HickoryResolver {
    fn lookup_txt(&self, name: &DomainName) -> Result<Vec<String>, DnsError> {
        use hickory_resolver::proto::rr::RData;
        let query = name.as_str().to_string();
        self.with_resolver(|resolver| {
            Box::pin(async move {
                let lookup = resolver
                    .txt_lookup(query)
                    .await
                    .map_err(HickoryResolver::map_err)?;
                // Each TXT record's character-strings concatenate into one
                // record value (RFC 7208 §3.3 / RFC 6376 §3.6.1) — SPF and
                // DKIM both rely on the joined form. Bounded at MAX_TXT_LEN
                // like the mock.
                let out: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::TXT(txt) => Some(
                            txt.txt_data
                                .iter()
                                .map(|s| String::from_utf8_lossy(s).into_owned())
                                .collect::<String>()
                                .chars()
                                .take(MAX_TXT_LEN)
                                .collect(),
                        ),
                        _ => None,
                    })
                    .collect();
                if out.is_empty() {
                    Err(DnsError::NxDomain)
                } else {
                    Ok(out)
                }
            })
        })
    }

    fn lookup_host(&self, name: &DomainName) -> Result<Vec<IpAddr>, DnsError> {
        let query = name.as_str().to_string();
        self.with_resolver(|resolver| {
            Box::pin(async move {
                let lookup = resolver
                    .lookup_ip(query)
                    .await
                    .map_err(HickoryResolver::map_err)?;
                let out: Vec<IpAddr> = lookup.iter().collect();
                if out.is_empty() {
                    Err(DnsError::NxDomain)
                } else {
                    Ok(out)
                }
            })
        })
    }

    fn lookup_mx(&self, name: &DomainName) -> Result<Vec<DomainName>, DnsError> {
        use hickory_resolver::proto::rr::RData;
        let query = name.as_str().to_string();
        self.with_resolver(|resolver| {
            Box::pin(async move {
                let lookup = resolver
                    .mx_lookup(query)
                    .await
                    .map_err(HickoryResolver::map_err)?;
                let mut records: Vec<(u16, DomainName)> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::MX(mx) => DomainName::parse(&mx.exchange.to_utf8())
                            .ok()
                            .map(|d| (mx.preference, d)),
                        _ => None,
                    })
                    .collect();
                // Priority order: lowest preference value first (RFC 5321 §5).
                records.sort_by_key(|(pref, _)| *pref);
                if records.is_empty() {
                    Err(DnsError::NxDomain)
                } else {
                    Ok(records.into_iter().map(|(_, d)| d).collect())
                }
            })
        })
    }

    fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<DomainName>, DnsError> {
        use hickory_resolver::proto::rr::RData;
        self.with_resolver(|resolver| {
            Box::pin(async move {
                let lookup = resolver
                    .reverse_lookup(ip)
                    .await
                    .map_err(HickoryResolver::map_err)?;
                let out: Vec<DomainName> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::PTR(ptr) => DomainName::parse(&ptr.0.to_utf8()).ok(),
                        _ => None,
                    })
                    .collect();
                if out.is_empty() {
                    Err(DnsError::NxDomain)
                } else {
                    Ok(out)
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The production resolver satisfies every seam the mock does:
    /// `DnsResolver` (the trait), `AuthSealer` via the blanket impl, and
    /// `Send + Sync` for the shared `OnceLock` the app stores it in.
    #[test]
    fn hickory_resolver_fits_the_resolver_seam() {
        fn assert<T: DnsResolver + Send + Sync>() {}
        assert::<HickoryResolver>();
        let r: &dyn DnsResolver = &HickoryResolver::system();
        let _ = r;
    }

    /// Bounds are honored: zero attempts clamps to one (zero tries would
    /// fabricate `Temp` without ever asking the network).
    #[test]
    fn with_bounds_clamps_zero_attempts() {
        let r = HickoryResolver::with_bounds(Duration::from_millis(5), 0);
        assert_eq!(r.attempts, 1);
        assert_eq!(r.timeout, Duration::from_millis(5));
    }

    /// Integration seam: exercises the full private-runtime →
    /// system-config → query path with no live-DNS requirement. A 1 ms
    /// timeout against the RFC 2606 reserved `.invalid` TLD can only
    /// produce a bounded failure — `Temp` (timeout/transport, the common
    /// case) or `NxDomain` (an absurdly fast local resolver answering
    /// negatively). `Ok` or a panic means the seam is broken; hanging
    /// means the bound is not honored.
    #[test]
    fn hickory_lookup_fails_closed_offline() {
        let r = HickoryResolver::with_bounds(Duration::from_millis(1), 1);
        let name = DomainName::parse("t-279.invalid").unwrap();
        let err = r
            .lookup_txt(&name)
            .expect_err("a 1ms lookup of a reserved TLD must not succeed");
        assert!(
            matches!(err, DnsError::NxDomain | DnsError::Temp(_)),
            "fail-closed vocabulary only: {err:?}"
        );
        let ip_err = r
            .lookup_host(&name)
            .expect_err("host lookup must fail closed too");
        assert!(matches!(ip_err, DnsError::NxDomain | DnsError::Temp(_)));
        // The shared runtime + memoized resolver keep working across
        // lookups and for the other record types (PTR exercises the
        // reverse-map path).
        let _ = r.lookup_ptr(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    /// Live-DNS smoke — manual verification only. Not part of CI: a host
    /// without working DNS is a supported configuration, so this cannot
    /// be a required test. Run it when changing bounds or plumbing:
    /// `cargo test -p kiwi-mailauth hickory_live -- --ignored`.
    #[test]
    #[ignore = "requires live system DNS — run manually per mailauth.md §6"]
    fn hickory_live_dns_smoke() {
        let r = HickoryResolver::system();
        let name = DomainName::parse("gmail.com").unwrap();
        let mx = r
            .lookup_mx(&name)
            .expect("live MX lookup failed — is system DNS working?");
        assert!(!mx.is_empty(), "gmail.com publishes MX records");
        // Sanity on the second query kind against the same shared
        // runtime — proves the resolver isn't a one-shot.
        assert!(r.lookup_host(&name).is_ok());
    }
}
