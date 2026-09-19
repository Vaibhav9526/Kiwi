//! DNS abstraction: mock-first, hickory-backed live adapter.
//!
//! Tests use [`MockResolver`] (fully offline). [`DnsError`] maps to
//! `temperror` in callers — never a hard failure.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

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
        self.txt.get(name.as_str()).cloned().ok_or(DnsError::NxDomain)
    }
    fn lookup_host(&self, name: &DomainName) -> Result<Vec<IpAddr>, DnsError> {
        self.check_temp(name)?;
        self.host.get(name.as_str()).cloned().ok_or(DnsError::NxDomain)
    }
    fn lookup_mx(&self, name: &DomainName) -> Result<Vec<DomainName>, DnsError> {
        self.check_temp(name)?;
        self.mx.get(name.as_str()).cloned().ok_or(DnsError::NxDomain)
    }
    fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<DomainName>, DnsError> {
        self.ptr.get(&ip).cloned().ok_or(DnsError::NxDomain)
    }
}
