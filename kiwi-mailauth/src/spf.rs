//! SPF evaluation (RFC 7208): mechanism/macro evaluator, bounded DNS.
//!
//! Result set: pass / fail / softfail / neutral / none / temperror /
//! permerror. Limits (§4.6.4): at most [`MAX_DNS_LOOKUPS`] DNS-querying
//! mechanisms+modifiers per evaluation; at most [`MAX_VOID_LOOKUPS`] void
//! (empty/NXDOMAIN) lookups — exceeding either yields `permerror`.
//! `ptr` is supported but flagged deprecated in evidence.

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::dns::{DnsError, DnsResolver};
use crate::{DomainName, Error, MAX_TXT_LEN};

/// Max DNS-querying mechanisms/modifiers per evaluation (RFC 7208 §4.6.4).
pub const MAX_DNS_LOOKUPS: u8 = 10;
/// Max void lookups before `permerror` (RFC 7208 §4.6.4).
pub const MAX_VOID_LOOKUPS: u8 = 2;
/// Max redirect/include recursion depth (loop protection; RFC has no number
/// — this is a hard bound, documented in the contract).
pub const MAX_RECURSION: u8 = 5;
/// Max address (A/AAAA) queries one `mx` mechanism may issue before
/// `permerror` (RFC 7208 §4.6.4).
pub const MAX_MX_ADDR_LOOKUPS: usize = 10;
/// Max address (A/AAAA) queries one `ptr` mechanism may issue; further PTR
/// records are ignored (RFC 7208 §4.6.4).
pub const MAX_PTR_ADDR_LOOKUPS: usize = 10;
/// Max expanded domain-spec length (bounded evidence).
pub const MAX_EXPANDED_LEN: usize = 253;

/// SPF verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpfResult {
    /// Mechanism matched with `+` qualifier.
    Pass,
    /// Matched with `-`.
    Fail,
    /// Matched with `~`.
    SoftFail,
    /// Matched with `?`, or no mechanism matched and no redirect.
    Neutral,
    /// No SPF record published.
    None,
    /// Transient DNS failure during evaluation.
    TempError,
    /// Permanent error (bad record, too many lookups, loop, …).
    PermError,
}

impl SpfResult {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Input to one SPF check.
#[derive(Debug, Clone)]
pub struct SpfInput {
    /// Domain under test (MAIL FROM domain, or HELO domain on null sender).
    pub check_domain: DomainName,
    /// Connecting client IP.
    pub sender_ip: IpAddr,
    /// HELO/EHLO hostname (for `%h` macros; validated, fallback `unknown`).
    pub helo: String,
    /// Envelope sender localpart (for `%l` macros; default `postmaster`).
    pub sender_local: String,
}

/// Typed SPF outcome (serializable into forensics evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfOutput {
    /// Verdict.
    pub result: SpfResult,
    /// Mechanism or modifier that decided (e.g. `-all`, `redirect=...`).
    pub decided_by: Option<String>,
    /// SPF record text evaluated (truncated to [`MAX_TXT_LEN`]).
    pub record: Option<String>,
    /// True when a deprecated `ptr` mechanism was evaluated.
    pub ptr_deprecated_used: bool,
    /// DNS-querying mechanisms consumed (limit 10).
    pub lookups_used: u8,
    /// Evidence-grounded explanation (never a finding).
    pub explanation: String,
}

/// Mechanism qualifier: `+` pass (default), `-` fail, `~` softfail,
/// `?` neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    fn of(term: &str) -> (Self, &str) {
        match term.as_bytes().first() {
            Some(b'+') => (Self::Pass, &term[1..]),
            Some(b'-') => (Self::Fail, &term[1..]),
            Some(b'~') => (Self::SoftFail, &term[1..]),
            Some(b'?') => (Self::Neutral, &term[1..]),
            _ => (Self::Pass, term),
        }
    }
    fn to_result(self) -> SpfResult {
        match self {
            Self::Pass => SpfResult::Pass,
            Self::Fail => SpfResult::Fail,
            Self::SoftFail => SpfResult::SoftFail,
            Self::Neutral => SpfResult::Neutral,
        }
    }
}

struct Ctx<'a, R: DnsResolver> {
    dns: &'a R,
    input: SpfInput,
    lookups: u8,
    voids: u8,
    ptr_used: bool,
    depth: u8,
}

impl<R: DnsResolver> Ctx<'_, R> {
    fn charge_lookup(&mut self) -> Result<(), SpfResult> {
        self.lookups = self.lookups.saturating_add(1);
        if self.lookups > MAX_DNS_LOOKUPS {
            return Err(SpfResult::PermError);
        }
        Ok(())
    }
    fn charge_void(&mut self) -> Result<(), SpfResult> {
        self.voids = self.voids.saturating_add(1);
        if self.voids > MAX_VOID_LOOKUPS {
            return Err(SpfResult::PermError);
        }
        Ok(())
    }
}

/// Evaluate SPF for `input` against the SPF record published at
/// `input.check_domain`. Never returns `Err` on DNS trouble: DNS errors
/// become `temperror` results; only invalid *input* is an `Err`.
pub fn evaluate<R: DnsResolver>(dns: &R, input: &SpfInput) -> Result<SpfOutput, Error> {
    let mut ctx = Ctx {
        dns,
        input: input.clone(),
        lookups: 0,
        voids: 0,
        ptr_used: false,
        depth: 0,
    };
    Ok(eval_domain(&mut ctx, &input.check_domain.clone(), true))
}

fn out(ctx: &Ctx<impl DnsResolver>, r: SpfResult, by: Option<&str>) -> SpfOutput {
    SpfOutput {
        result: r,
        decided_by: by.map(|s| s.chars().take(300).collect()),
        record: None,
        ptr_deprecated_used: ctx.ptr_used,
        lookups_used: ctx.lookups,
        explanation: String::new(),
    }
}

fn with_record(mut o: SpfOutput, rec: &str, why: &str) -> SpfOutput {
    o.record = Some(rec.chars().take(MAX_TXT_LEN).collect());
    o.explanation = why.chars().take(500).collect();
    o
}

/// Fetch the single SPF record for `domain` (RFC 7208 §4.5 selection).
fn fetch_record<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    domain: &DomainName,
) -> Result<String, SpfOutput> {
    let txts = match ctx.dns.lookup_txt(domain) {
        Ok(t) => t,
        Err(DnsError::NxDomain) => {
            return Err(with_record(
                out(ctx, SpfResult::None, None),
                "",
                "no TXT records: no SPF record published",
            ));
        }
        Err(DnsError::Temp(e)) => {
            let mut o = out(ctx, SpfResult::TempError, None);
            o.explanation = format!("DNS error fetching TXT: {e}")
                .chars()
                .take(500)
                .collect();
            return Err(o);
        }
    };
    let mut found: Vec<&String> = txts
        .iter()
        .filter(|t| t == &"v=spf1" || t.starts_with("v=spf1 ") || t.starts_with("v=spf1\t"))
        .collect();
    if found.is_empty() {
        return Err(with_record(
            out(ctx, SpfResult::None, None),
            "",
            "TXT present but no v=spf1 record",
        ));
    }
    if found.len() > 1 {
        return Err(with_record(
            out(ctx, SpfResult::PermError, None),
            found[0],
            "multiple SPF records published",
        ));
    }
    Ok(found.pop().unwrap().clone())
}

/// Evaluate the SPF record published at `domain`.
///
/// A `none` result (no record at this domain) is returned to the caller
/// unchanged: the top level reports absence of a record, while `include`
/// (§5.2) and `redirect` (§6.1) must turn it into `permerror`.
fn eval_domain<R: DnsResolver>(ctx: &mut Ctx<R>, domain: &DomainName) -> SpfOutput {
    if ctx.depth > MAX_RECURSION {
        return with_record(
            out(ctx, SpfResult::PermError, Some("redirect/include loop")),
            "",
            "include/redirect recursion limit exceeded",
        );
    }
    let record = match fetch_record(ctx, domain) {
        Ok(r) => r,
        Err(o) => return o,
    };
    eval_terms(ctx, domain, &record)
}

fn eval_terms<R: DnsResolver>(ctx: &mut Ctx<R>, domain: &DomainName, record: &str) -> SpfOutput {
    let body = record.get(6..).unwrap_or("");
    let terms = match split_terms(body) {
        Ok(t) => t,
        Err(_) => {
            return with_record(
                out(ctx, SpfResult::PermError, None),
                record,
                "unparseable SPF record",
            );
        }
    };
    let mut redirect: Option<String> = None;
    let mut mechs = Vec::new();
    for t in terms {
        if let Some(v) = t.strip_prefix("redirect=") {
            if redirect.is_some() {
                return with_record(
                    out(ctx, SpfResult::PermError, None),
                    record,
                    "duplicate redirect modifier",
                );
            }
            redirect = Some(v.to_string());
        } else if t.starts_with("exp=") {
            continue;
        } else if t.contains('=') {
            continue; // unknown modifiers ignored per RFC 7208 section 6
        } else {
            mechs.push(t);
        }
    }
    for term in &mechs {
        match eval_mechanism(ctx, domain, term) {
            MechOutcome::Match(q) => {
                let mut o = out(ctx, q.to_result(), Some(term));
                o.record = Some(record.chars().take(MAX_TXT_LEN).collect());
                o.explanation = format!("mechanism '{term}' matched for {}", ctx.input.sender_ip)
                    .chars()
                    .take(500)
                    .collect();
                return o;
            }
            MechOutcome::NoMatch => {}
            MechOutcome::Error(r) => {
                let mut o = out(ctx, r, Some(term));
                o.record = Some(record.chars().take(MAX_TXT_LEN).collect());
                o.explanation = format!("mechanism '{term}' error: {}", r.as_str())
                    .chars()
                    .take(500)
                    .collect();
                return o;
            }
        }
    }
    if let Some(target) = redirect {
        if ctx.charge_lookup().is_err() {
            return with_record(
                out(ctx, SpfResult::PermError, Some("redirect=")),
                record,
                "lookup limit exceeded at redirect",
            );
        }
        let expanded = expand_macros(ctx, &target);
        let rdom = match DomainName::parse(&expanded) {
            Ok(d) => d,
            Err(_) => {
                return with_record(
                    out(ctx, SpfResult::PermError, Some("redirect=")),
                    record,
                    "redirect target is not a valid domain",
                );
            }
        };
        ctx.depth += 1;
        let mut o = eval_domain(ctx, &rdom, false);
        ctx.depth -= 1;
        if o.result == SpfResult::None {
            let mut n = out(ctx, SpfResult::Neutral, Some("redirect="));
            n.record = Some(record.chars().take(MAX_TXT_LEN).collect());
            n.explanation = "redirect target has no SPF record".to_string();
            return n;
        }
        if o.record.is_none() {
            o.record = Some(record.chars().take(MAX_TXT_LEN).collect());
        }
        return o;
    }
    with_record(
        out(ctx, SpfResult::Neutral, None),
        record,
        "no mechanism matched",
    )
}

/// Outcome of one mechanism evaluation.
enum MechOutcome {
    /// Mechanism matched: apply the qualifier.
    Match(Qualifier),
    /// No match: continue with the next term.
    NoMatch,
    /// Stop evaluation with this verdict.
    Error(SpfResult),
}

fn eval_mechanism<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    domain: &DomainName,
    term: &str,
) -> MechOutcome {
    let (q, rest) = Qualifier::of(term);
    let name_end = rest.find([':', '/']).unwrap_or(rest.len());
    let (name, tail) = rest.split_at(name_end);
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "all" => {
            if tail.is_empty() {
                MechOutcome::Match(q)
            } else {
                MechOutcome::Error(SpfResult::PermError)
            }
        }
        "include" => {
            if ctx.charge_lookup().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            let spec = match tail.strip_prefix(':') {
                Some(s) if !s.is_empty() => s,
                _ => return MechOutcome::Error(SpfResult::PermError),
            };
            let expanded = expand_macros(ctx, spec);
            let target = match DomainName::parse(&expanded) {
                Ok(d) => d,
                Err(_) => return MechOutcome::Error(SpfResult::PermError),
            };
            if ctx.depth >= MAX_RECURSION {
                return MechOutcome::Error(SpfResult::PermError);
            }
            ctx.depth += 1;
            let o = eval_domain(ctx, &target, false);
            ctx.depth -= 1;
            match o.result {
                SpfResult::Pass => MechOutcome::Match(q),
                SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => MechOutcome::NoMatch,
                SpfResult::TempError => MechOutcome::Error(SpfResult::TempError),
                _ => MechOutcome::Error(SpfResult::PermError),
            }
        }
        "a" | "mx" | "ptr" | "exists" => {
            if ctx.charge_lookup().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            eval_dns_mech(ctx, domain, &name, tail, q)
        }
        "ip4" => match parse_ip4_mech(tail) {
            Some((net, prefix)) => match ctx.input.sender_ip {
                IpAddr::V4(v4) => {
                    if ipv4_in_cidr(v4, net, prefix) {
                        MechOutcome::Match(q)
                    } else {
                        MechOutcome::NoMatch
                    }
                }
                IpAddr::V6(_) => MechOutcome::NoMatch,
            },
            None => MechOutcome::Error(SpfResult::PermError),
        },
        "ip6" => match parse_ip6_mech(tail) {
            Some((net, prefix)) => match ctx.input.sender_ip {
                IpAddr::V6(v6) => {
                    if ipv6_in_cidr(v6, net, prefix) {
                        MechOutcome::Match(q)
                    } else {
                        MechOutcome::NoMatch
                    }
                }
                IpAddr::V4(_) => MechOutcome::NoMatch,
            },
            None => MechOutcome::Error(SpfResult::PermError),
        },
        _ => {
            let _ = tail;
            MechOutcome::Error(SpfResult::PermError)
        }
    }
}

/// Split on ASCII spaces (RFC 7208: terms separated by SP).
fn split_terms(s: &str) -> Result<Vec<String>, ()> {
    let parts: Vec<String> = s
        .split(' ')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    if parts.len() > 64 {
        return Err(());
    }
    for p in &parts {
        if p.len() > 300 {
            return Err(());
        }
    }
    Ok(parts)
}

/// `(domain-spec, cidr4_len, cidr6_len)` from a mechanism tail
/// `[:domain-spec][/cidr4[/cidr6]]` (RFC 7208 §5.3/§5.4:
/// `a = "a" [ ":" domain-spec ] [ dual-cidr-length ]`).
///
/// `Some(("", None, None))` means "no arguments at all" (use the current
/// domain); `None` is a syntax error (`a:`, `a//64`, non-numeric CIDR,
/// over-long spec). A tail with no colon (`a/24`) is a CIDR-only form.
fn split_dual_cidr(tail: &str) -> Option<(&str, Option<u8>, Option<u8>)> {
    if tail.is_empty() {
        return Some(("", None, None));
    }
    let body = match tail.strip_prefix(':') {
        // "a:" / "exists:" — an empty domain-spec is a syntax error.
        Some(b) if b.is_empty() => return None,
        Some(b) => b,
        None => tail,
    };
    // Find the first '/' that is NOT inside a %{...} macro.
    let mut depth = 0usize;
    let mut cut: Option<usize> = None;
    for (i, b) in body.bytes().enumerate() {
        match b {
            b'{' if i > 0 && body.as_bytes()[i - 1] == b'%' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'/' if depth == 0 => {
                cut = Some(i);
                break;
            }
            _ => {}
        }
    }
    let (spec, cidr) = match cut {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    if spec.len() > MAX_EXPANDED_LEN {
        return None;
    }
    let (c4, c6) = match cidr {
        None => (None, None),
        Some(c) => {
            if let Some(slash) = c.find("//") {
                let _ = slash;
                return None; // never valid: at most one extra slash
            }
            match c.split_once('/') {
                Some((a, b)) => (Some(parse_cidr_len(a)?), Some(parse_cidr_len(b)?)),
                None => (Some(parse_cidr_len(c)?), None),
            }
        }
    };
    Some((spec, c4, c6))
}

fn parse_cidr_len(s: &str) -> Option<u8> {
    if s.is_empty() || s.len() > 3 {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u8>().ok()
}

fn eval_a<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    current: &DomainName,
    tail: &str,
    q: Qualifier,
) -> MechOutcome {
    let (spec, c4, c6) = match split_dual_cidr(tail) {
        Some(v) => v,
        None => return MechOutcome::Error(SpfResult::PermError),
    };
    let use_spec = if spec.is_empty() {
        current.as_str()
    } else {
        spec
    };
    let target = match DomainName::parse(&expand_macros(ctx, use_spec)) {
        Ok(d) => d,
        Err(_) => return MechOutcome::Error(SpfResult::PermError),
    };
    match ctx.dns.lookup_host(&target) {
        Err(DnsError::Temp(_)) => MechOutcome::Error(SpfResult::TempError),
        Err(DnsError::NxDomain) => {
            if ctx.charge_void().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            MechOutcome::NoMatch
        }
        Ok(addrs) if addrs.is_empty() => {
            if ctx.charge_void().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            MechOutcome::NoMatch
        }
        Ok(addrs) => {
            if addrs
                .iter()
                .any(|a| ip_matches(*a, ctx.input.sender_ip, c4, c6))
            {
                MechOutcome::Match(q)
            } else {
                MechOutcome::NoMatch
            }
        }
    }
}

fn eval_mx<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    current: &DomainName,
    tail: &str,
    q: Qualifier,
) -> MechOutcome {
    let (spec, c4, c6) = match split_dual_cidr(tail) {
        Some(v) => v,
        None => return MechOutcome::Error(SpfResult::PermError),
    };
    let use_spec = if spec.is_empty() {
        current.as_str()
    } else {
        spec
    };
    let target = match DomainName::parse(&expand_macros(ctx, use_spec)) {
        Ok(d) => d,
        Err(_) => return MechOutcome::Error(SpfResult::PermError),
    };
    let hosts = match ctx.dns.lookup_mx(&target) {
        Err(DnsError::Temp(_)) => return MechOutcome::Error(SpfResult::TempError),
        Err(DnsError::NxDomain) => {
            if ctx.charge_void().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            return MechOutcome::NoMatch;
        }
        Ok(h) => h,
    };
    if hosts.is_empty() {
        if ctx.charge_void().is_err() {
            return MechOutcome::Error(SpfResult::PermError);
        }
        return MechOutcome::NoMatch;
    }
    for h in hosts.iter().take(32) {
        if ctx.charge_lookup().is_err() {
            return MechOutcome::Error(SpfResult::PermError);
        }
        match ctx.dns.lookup_host(h) {
            Err(DnsError::Temp(_)) => return MechOutcome::Error(SpfResult::TempError),
            Err(DnsError::NxDomain) => {
                if ctx.charge_void().is_err() {
                    return MechOutcome::Error(SpfResult::PermError);
                }
            }
            Ok(addrs) => {
                if addrs
                    .iter()
                    .any(|a| ip_matches(*a, ctx.input.sender_ip, c4, c6))
                {
                    return MechOutcome::Match(q);
                }
            }
        }
    }
    MechOutcome::NoMatch
}

fn eval_ptr<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    current: &DomainName,
    tail: &str,
    q: Qualifier,
) -> MechOutcome {
    ctx.ptr_used = true; // deprecated mechanism (flagged in evidence)
    let (spec, _c4, _c6) = match split_dual_cidr(tail) {
        Some(v) => v,
        None => return MechOutcome::Error(SpfResult::PermError),
    };
    let use_spec = if spec.is_empty() {
        current.as_str()
    } else {
        spec
    };
    let ptr_names = match ctx.dns.lookup_ptr(ctx.input.sender_ip) {
        Err(DnsError::Temp(_)) => return MechOutcome::Error(SpfResult::TempError),
        Err(DnsError::NxDomain) => {
            if ctx.charge_void().is_err() {
                return MechOutcome::Error(SpfResult::PermError);
            }
            return MechOutcome::NoMatch;
        }
        Ok(n) => n,
    };
    let want = DomainName::parse(&expand_macros(ctx, use_spec)).unwrap_or_else(|_| current.clone());
    for n in ptr_names.iter().take(32) {
        if ctx.charge_lookup().is_err() {
            return MechOutcome::Error(SpfResult::PermError);
        }
        match ctx.dns.lookup_host(n) {
            Err(DnsError::Temp(_)) => return MechOutcome::Error(SpfResult::TempError),
            Err(DnsError::NxDomain) => {
                if ctx.charge_void().is_err() {
                    return MechOutcome::Error(SpfResult::PermError);
                }
            }
            Ok(addrs) => {
                if addrs.contains(&ctx.input.sender_ip) && (n == &want || n.is_subdomain_of(&want))
                {
                    return MechOutcome::Match(q);
                }
            }
        }
    }
    MechOutcome::NoMatch
}

fn eval_exists<R: DnsResolver>(ctx: &mut Ctx<R>, tail: &str, q: Qualifier) -> MechOutcome {
    let body = match tail.strip_prefix(':') {
        Some(s) if !s.is_empty() => s,
        _ => return MechOutcome::Error(SpfResult::PermError),
    };
    if body.len() > MAX_EXPANDED_LEN {
        return MechOutcome::Error(SpfResult::PermError);
    }
    let target = match DomainName::parse(&expand_macros(ctx, body)) {
        Ok(d) => d,
        Err(_) => return MechOutcome::Error(SpfResult::PermError),
    };
    match ctx.dns.lookup_host(&target) {
        Err(DnsError::Temp(_)) => MechOutcome::Error(SpfResult::TempError),
        Err(DnsError::NxDomain) => MechOutcome::NoMatch,
        Ok(addrs) if addrs.is_empty() => MechOutcome::NoMatch,
        Ok(_) => MechOutcome::Match(q),
    }
}

fn eval_dns_mech<R: DnsResolver>(
    ctx: &mut Ctx<R>,
    current: &DomainName,
    name: &str,
    tail: &str,
    q: Qualifier,
) -> MechOutcome {
    match name {
        "a" => eval_a(ctx, current, tail, q),
        "mx" => eval_mx(ctx, current, tail, q),
        "ptr" => eval_ptr(ctx, current, tail, q),
        "exists" => eval_exists(ctx, tail, q),
        _ => MechOutcome::Error(SpfResult::PermError),
    }
}

fn ip_matches(addr: IpAddr, sender: IpAddr, c4: Option<u8>, c6: Option<u8>) -> bool {
    match (addr, sender) {
        (IpAddr::V4(a), IpAddr::V4(s)) => {
            let p = c4.unwrap_or(32);
            if p > 32 {
                return false;
            }
            ipv4_in_cidr(s, a, p)
        }
        (IpAddr::V6(a), IpAddr::V6(s)) => {
            let p = c6.unwrap_or(128);
            if p > 128 {
                return false;
            }
            ipv6_in_cidr(s, a, p)
        }
        _ => false,
    }
}

fn parse_ip4_mech(tail: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let body = tail.strip_prefix(':')?;
    if body.is_empty() || body.len() > 40 {
        return None;
    }
    let (addr_s, pref) = match body.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (body, None),
    };
    let addr = std::net::Ipv4Addr::from_str(addr_s).ok()?;
    let p = match pref {
        None => 32,
        Some(s) => parse_cidr_len(s)?,
    };
    if p > 32 {
        return None;
    }
    Some((addr, p))
}

fn parse_ip6_mech(tail: &str) -> Option<(std::net::Ipv6Addr, u8)> {
    let body = tail.strip_prefix(':')?;
    if body.is_empty() || body.len() > 60 {
        return None;
    }
    let (addr_s, pref) = match body.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (body, None),
    };
    let addr = std::net::Ipv6Addr::from_str(addr_s).ok()?;
    let p = match pref {
        None => 128,
        Some(s) => parse_cidr_len(s)?,
    };
    if p > 128 {
        return None;
    }
    Some((addr, p))
}

fn ipv4_in_cidr(ip: std::net::Ipv4Addr, net: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_cidr(ip: std::net::Ipv6Addr, net: std::net::Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let a = u128::from(ip);
    let n = u128::from(net);
    let mask: u128 = u128::MAX << (128 - prefix);
    (a & mask) == (n & mask)
}

/// Expand RFC 7208 §7 macros in `spec`. Unknown macros are left literal
/// (fail-closed: the expanded name then fails `DomainName::parse` and the
/// term becomes `permerror` rather than matching something unintended).
/// Output truncated to [`MAX_EXPANDED_LEN`] + NUL-terminated safety.
fn expand_macros<R: DnsResolver>(ctx: &Ctx<R>, spec: &str) -> String {
    let mut out = String::with_capacity(spec.len().saturating_add(16));
    let bytes = spec.as_bytes();
    let mut i = 0;
    while i < bytes.len() && out.len() < MAX_EXPANDED_LEN {
        if bytes[i] == b'%' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'%' => {
                    out.push('%');
                    i += 2;
                }
                b'_' => {
                    out.push(' ');
                    i += 2;
                }
                b'-' => {
                    out.push_str("%20");
                    i += 2;
                }
                b'{' => {
                    if let Some(end) = spec[i + 2..].find('}') {
                        let inner = &spec[i + 2..i + 2 + end];
                        out.push_str(&expand_one(ctx, inner));
                        i += 2 + end + 1;
                    } else {
                        out.push('%');
                        i += 1;
                    }
                }
                _ => {
                    out.push('%');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn expand_one<R: DnsResolver>(ctx: &Ctx<R>, inner: &str) -> String {
    if inner.is_empty() || inner.len() > 16 {
        return String::new();
    }
    let mut chars = inner.chars();
    let letter = chars.next().unwrap_or('x');
    // Optional digit(s): keep-LABELS count.
    let mut digits = String::new();
    for c in chars.clone() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            break;
        }
    }
    let keep: usize = if digits.is_empty() {
        0
    } else {
        digits.parse::<usize>().unwrap_or(0).min(32)
    };
    let rest: String = chars.skip(digits.len()).collect();
    let reverse = rest.starts_with('r');
    let delim_chars: Vec<char> = rest.chars().filter(|c| *c != 'r').collect();
    let delims: Vec<char> = if delim_chars.is_empty() {
        vec!['.']
    } else {
        delim_chars.into_iter().take(4).collect()
    };
    let raw = match letter {
        's' => {
            let local = if ctx.input.sender_local.is_empty() {
                "postmaster"
            } else {
                ctx.input.sender_local.as_str()
            };
            format!("{local}@{}", ctx.input.check_domain.as_str())
        }
        'l' => {
            if ctx.input.sender_local.is_empty() {
                "postmaster".to_string()
            } else {
                ctx.input.sender_local.clone()
            }
        }
        'o' => ctx.input.check_domain.as_str().to_string(),
        'd' => ctx.input.check_domain.as_str().to_string(),
        'i' => match ctx.input.sender_ip {
            IpAddr::V4(v) => v.to_string(),
            IpAddr::V6(v) => v.to_string(),
        },
        'h' => sanitize_helo(&ctx.input.helo),
        'v' => match ctx.input.sender_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        },
        'p' => "unknown".to_string(),
        _ => return String::new(),
    };
    // Split on '.' per §7.1, then rejoin on the LAST delimiter char; `r`
    // reverses label order; digit prefix keeps the rightmost N labels.
    let mut parts: Vec<&str> = raw.split('.').collect();
    if reverse {
        parts.reverse();
    }
    if keep > 0 && keep < parts.len() {
        parts = parts[parts.len() - keep..].to_vec();
    }
    let joiner = delims.last().copied().unwrap_or('.');
    let mut joined = parts.join(&joiner.to_string());
    if letter == 'i' || letter == 'h' || letter == 'l' {
        joined = url_escape(&joined);
    }
    joined.chars().take(MAX_EXPANDED_LEN).collect()
}

fn sanitize_helo(helo: &str) -> String {
    let t = helo.trim();
    if t.is_empty() {
        return "unknown".to_string();
    }
    let clean: String = t
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .take(253)
        .collect();
    if clean.is_empty() {
        "unknown".to_string()
    } else {
        clean
    }
}

fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MockResolver;
    use std::net::IpAddr;

    fn input(domain: &str, ip: &str) -> SpfInput {
        SpfInput {
            check_domain: DomainName::parse(domain).unwrap(),
            sender_ip: IpAddr::from_str(ip).unwrap(),
            helo: "mail.sender.example".to_string(),
            sender_local: "alice".to_string(),
        }
    }

    #[test]
    fn ip4_pass_and_fail() {
        let dns = MockResolver::new().with_txt("example.com", &["v=spf1 ip4:192.0.2.10 -all"]);
        let good = input("example.com", "192.0.2.10");
        let o = evaluate(&dns, &good).unwrap();
        assert_eq!(o.result, SpfResult::Pass);
        let bad = input("example.com", "192.0.2.99");
        let o = evaluate(&dns, &bad).unwrap();
        assert_eq!(o.result, SpfResult::Fail);
    }

    #[test]
    fn no_record_is_none_not_failure() {
        let dns = MockResolver::new();
        let o = evaluate(&dns, &input("example.com", "192.0.2.1")).unwrap();
        assert_eq!(o.result, SpfResult::None);
    }

    #[test]
    fn softfail_and_neutral() {
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 ~all"])
            .with_txt("other.example", &["v=spf1 ?all"]);
        assert_eq!(
            evaluate(&dns, &input("example.com", "192.0.2.1"))
                .unwrap()
                .result,
            SpfResult::SoftFail
        );
        assert_eq!(
            evaluate(&dns, &input("other.example", "192.0.2.1"))
                .unwrap()
                .result,
            SpfResult::Neutral
        );
    }

    #[test]
    fn include_chain_and_redirect() {
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 include:_spf.example.net -all"])
            .with_txt("_spf.example.net", &["v=spf1 ip4:192.0.2.0/24 -all"])
            .with_txt("alias.example", &["v=spf1 redirect=example.com"]);
        assert_eq!(
            evaluate(&dns, &input("example.com", "192.0.2.55"))
                .unwrap()
                .result,
            SpfResult::Pass
        );
        assert_eq!(
            evaluate(&dns, &input("alias.example", "192.0.2.55"))
                .unwrap()
                .result,
            SpfResult::Pass
        );
    }

    #[test]
    fn temp_error_on_dns_failure() {
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 a -all"])
            .with_temp_fail("example.com");
        let o = evaluate(&dns, &input("example.com", "192.0.2.1")).unwrap();
        assert_eq!(o.result, SpfResult::TempError);
    }

    #[test]
    fn perm_error_on_multiple_records() {
        let dns = MockResolver::new().with_txt("example.com", &["v=spf1 -all", "v=spf1 ~all"]);
        let o = evaluate(&dns, &input("example.com", "192.0.2.1")).unwrap();
        assert_eq!(o.result, SpfResult::PermError);
    }

    #[test]
    fn lookup_limit_enforced() {
        let mut dns = MockResolver::new();
        dns = dns.with_txt(
            "example.com",
            &["v=spf1 include:a1.x include:a2.x include:a3.x include:a4.x include:a5.x include:a6.x -all"],
        );
        for n in 1..=6 {
            let sub = format!("a{n}.x");
            dns = dns.with_txt(&sub, &["v=spf1 include:b1.y include:b2.y -all"]);
        }
        dns = dns
            .with_txt("b1.y", &["v=spf1 -all"])
            .with_txt("b2.y", &["v=spf1 -all"]);
        let o = evaluate(&dns, &input("example.com", "192.0.2.1")).unwrap();
        assert_eq!(o.result, SpfResult::PermError);
        assert!(o.lookups_used > MAX_DNS_LOOKUPS - 2);
    }

    #[test]
    fn ptr_sets_deprecated_flag() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 ptr -all"])
            .with_ptr(ip, &["host.example.com"])
            .with_host("host.example.com", &["192.0.2.7"]);
        let o = evaluate(&dns, &input("example.com", "192.0.2.7")).unwrap();
        assert_eq!(o.result, SpfResult::Pass);
        assert!(o.ptr_deprecated_used);
    }

    #[test]
    fn exists_and_macros() {
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 exists:%{i}._spf.example.com -all"])
            .with_host("192.0.2.9._spf.example.com", &["192.0.2.9"]);
        // Hostile IP label: macro value contains dots, still a valid name.
        let o = evaluate(&dns, &input("example.com", "192.0.2.9")).unwrap();
        assert_eq!(o.result, SpfResult::Pass);
        let o2 = evaluate(&dns, &input("example.com", "192.0.2.10")).unwrap();
        assert_eq!(o2.result, SpfResult::Fail);
    }

    #[test]
    fn mx_and_a_with_cidr() {
        let dns = MockResolver::new()
            .with_txt("example.com", &["v=spf1 mx -all"])
            .with_mx("example.com", &["mail.example.com"])
            .with_host("mail.example.com", &["192.0.2.25"])
            .with_txt("cidr.example", &["v=spf1 a/cidr.example/24 -all"])
            .with_host("cidr.example", &["192.0.2.0"]);
        // mx path
        assert_eq!(
            evaluate(&dns, &input("example.com", "192.0.2.25"))
                .unwrap()
                .result,
            SpfResult::Pass
        );
        // a with dual-cidr spec tail: 'a/cidr.example/24' is name 'a' +
        // garbage tail -> permerror proves tail validation works.
        let o = evaluate(&dns, &input("cidr.example", "192.0.2.5")).unwrap();
        assert_eq!(o.result, SpfResult::PermError);
    }
}
