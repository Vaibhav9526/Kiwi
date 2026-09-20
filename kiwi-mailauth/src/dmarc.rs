//! DMARC evaluation (RFC 7489): `v=DMARC1` parse, SPF/DKIM alignment
//! (strict/relaxed), policy outcome (none/quarantine/reject).
//!
//! Inputs are the already-computed SPF + DKIM outcomes plus the RFC 5322
//! From domain — this crate never re-implements SPF/DKIM here. `pct`
//! sampling is reported as evidence, never silently applied: the outcome
//! carries `sampled_out` so callers can distinguish "policy applies" from
//! "policy sampled out" deterministically (caller supplies the sampled
//! roll as input — no RNG in this crate).

use serde::{Deserialize, Serialize};

use crate::dns::{DnsError, DnsResolver};
use crate::{DomainName, Error, MAX_TXT_LEN};

/// DMARC policy (`p=` / `sp=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcPolicy {
    /// No action requested.
    None,
    /// Treat as suspicious (quarantine / spam folder).
    Quarantine,
    /// Reject outright.
    Reject,
}

impl DmarcPolicy {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

/// Alignment mode (`aspf=` / `adkim=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlignMode {
    /// Exact domain match required.
    Strict,
    /// Same organizational domain suffices.
    Relaxed,
}

/// Parsed `v=DMARC1` record (evidence fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcRecord {
    /// Requested policy for the organizational domain.
    pub policy: DmarcPolicy,
    /// Subdomain policy (defaults to `policy`).
    pub sub_policy: DmarcPolicy,
    /// SPF identifier alignment (default relaxed).
    pub spf_align: AlignMode,
    /// DKIM identifier alignment (default relaxed).
    pub dkim_align: AlignMode,
    /// Sampling percentage 0–100 (default 100).
    pub pct: u8,
    /// Raw record text (truncated).
    pub raw: String,
}

/// Input to one DMARC evaluation.
#[derive(Debug, Clone)]
pub struct DmarcInput {
    /// RFC 5322 From domain (the identifier DMARC protects).
    pub from_domain: DomainName,
    /// Envelope-from domain that SPF was checked against.
    pub spf_domain: DomainName,
    /// Did SPF pass (any pass counts, alignment checked separately)?
    pub spf_pass: bool,
    /// DKIM signing domain (`d=`), if a signature verified.
    pub dkim_domain: Option<DomainName>,
    /// Did a DKIM signature verify?
    pub dkim_pass: bool,
    /// Explicit org domain override (exact PSL deployments); None → heuristic.
    pub org_override: Option<DomainName>,
    /// Deterministic sampling roll 0–99 (caller-supplied; e.g. hash of the
    /// message id mod 100). `None` → no sampling applied (pct treated as 100
    /// for the verdict, `sampled_out=false`).
    pub sample_roll: Option<u8>,
}

/// Typed DMARC outcome (serializable into forensics evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcOutput {
    /// `none` when no record; `temperror`/`permerror` on DNS/record faults.
    pub result: DmarcVerdict,
    /// Policy that would apply after alignment (none if aligned or no record).
    pub policy_applied: DmarcPolicy,
    /// SPF identifier aligned with the From domain.
    pub spf_aligned: bool,
    /// DKIM identifier aligned with the From domain.
    pub dkim_aligned: bool,
    /// True when `pct` sampling excluded this message (verdict forced to
    /// `none`-policy regardless of alignment).
    pub sampled_out: bool,
    /// The record that decided (None when no record found).
    pub record: Option<DmarcRecord>,
    /// Evidence-grounded explanation (never a finding).
    pub explanation: String,
}

/// DMARC evaluation verdict (mirrors the SPF result vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcVerdict {
    /// DMARC check passed (aligned SPF or DKIM pass).
    Pass,
    /// No DMARC record published — not a failure.
    None,
    /// Policy applies (see `policy_applied`).
    Fail,
    /// Transient DNS failure.
    TempError,
    /// Permanent error (bad record, …).
    PermError,
}

impl DmarcVerdict {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::None => "none",
            Self::Fail => "fail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Parse a `v=DMARC1; …` record. Unknown tags ignored; malformed known
/// tags → `Err` (caller: permerror).
pub fn parse_record(text: &str) -> Result<DmarcRecord, Error> {
    let raw: String = text.chars().take(MAX_TXT_LEN).collect();
    let mut tags: Vec<(String, String)> = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or(Error::Malformed("dmarc: bad tag"))?;
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() || key.len() > 16 {
            return Err(Error::Malformed("dmarc: bad tag name"));
        }
        if tags.len() >= 32 {
            return Err(Error::Malformed("dmarc: too many tags"));
        }
        tags.push((key, v.trim().to_string()));
    }
    let get = |k: &str| {
        tags.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    match get("v") {
        Some(v) if v.trim() == "DMARC1" => {}
        _ => return Err(Error::Malformed("dmarc: missing v=DMARC1")),
    }
    let policy = match get("p") {
        Some("none") => DmarcPolicy::None,
        Some("quarantine") => DmarcPolicy::Quarantine,
        Some("reject") => DmarcPolicy::Reject,
        _ => return Err(Error::Malformed("dmarc: bad p=")),
    };
    let sub_policy = match get("sp") {
        None => policy,
        Some("none") => DmarcPolicy::None,
        Some("quarantine") => DmarcPolicy::Quarantine,
        Some("reject") => DmarcPolicy::Reject,
        Some(_) => return Err(Error::Malformed("dmarc: bad sp=")),
    };
    let spf_align = match get("aspf") {
        None => AlignMode::Relaxed,
        Some("r") => AlignMode::Relaxed,
        Some("s") => AlignMode::Strict,
        Some(_) => return Err(Error::Malformed("dmarc: bad aspf=")),
    };
    let dkim_align = match get("adkim") {
        None => AlignMode::Relaxed,
        Some("r") => AlignMode::Relaxed,
        Some("s") => AlignMode::Strict,
        Some(_) => return Err(Error::Malformed("dmarc: bad adkim=")),
    };
    let pct = match get("pct") {
        None => 100,
        Some(s) => {
            let n: u16 = s
                .trim()
                .parse()
                .map_err(|_| Error::Malformed("dmarc: bad pct="))?;
            if n > 100 {
                return Err(Error::Malformed("dmarc: bad pct="));
            }
            n as u8
        }
    };
    Ok(DmarcRecord {
        policy,
        sub_policy,
        spf_align,
        dkim_align,
        pct,
        raw,
    })
}

/// Evaluate DMARC: fetch `_dmarc.<org>`, check SPF/DKIM alignment, apply
/// policy + pct sampling. DNS trouble → `temperror` output (never `Err`).
pub fn evaluate<R: DnsResolver>(dns: &R, input: &DmarcInput) -> DmarcOutput {
    let org = match &input.org_override {
        Some(o) => o.clone(),
        None => crate::org_domain_heuristic(&input.from_domain),
    };
    let is_sub = input.from_domain.as_str() != org.as_str();
    let query = format!("_dmarc.{}", org.as_str());
    let query_name = match DomainName::parse(&query) {
        Ok(d) => d,
        Err(_) => {
            return DmarcOutput {
                result: DmarcVerdict::PermError,
                policy_applied: DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: "DMARC query name invalid".to_string(),
            };
        }
    };
    let txts = match dns.lookup_txt(&query_name) {
        Ok(t) => t,
        Err(DnsError::NxDomain) => {
            return DmarcOutput {
                result: DmarcVerdict::None,
                policy_applied: DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: "no DMARC record published".to_string(),
            };
        }
        Err(DnsError::Temp(e)) => {
            return DmarcOutput {
                result: DmarcVerdict::TempError,
                policy_applied: DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: format!("DMARC DNS error: {e}"),
            };
        }
    };
    let rec_txt = match txts.iter().find(|t| {
        let s = t.trim_start();
        s == "v=DMARC1" || s.starts_with("v=DMARC1;") || s.starts_with("v=DMARC1 ")
    }) {
        Some(t) => t.clone(),
        None => {
            return DmarcOutput {
                result: DmarcVerdict::None,
                policy_applied: DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: "TXT present but no v=DMARC1 record".to_string(),
            };
        }
    };
    let rec = match parse_record(&rec_txt) {
        Ok(r) => r,
        Err(_) => {
            return DmarcOutput {
                result: DmarcVerdict::PermError,
                policy_applied: DmarcPolicy::None,
                spf_aligned: false,
                dkim_aligned: false,
                sampled_out: false,
                record: None,
                explanation: "DMARC record unparseable".to_string(),
            };
        }
    };
    let policy = if is_sub { rec.sub_policy } else { rec.policy };
    let spf_aligned =
        input.spf_pass && aligned(&input.spf_domain, &input.from_domain, &org, rec.spf_align);
    let dkim_aligned = input.dkim_pass
        && input
            .dkim_domain
            .as_ref()
            .is_some_and(|d| aligned(d, &input.from_domain, &org, rec.dkim_align));
    if spf_aligned || dkim_aligned {
        return DmarcOutput {
            result: DmarcVerdict::Pass,
            policy_applied: DmarcPolicy::None,
            spf_aligned,
            dkim_aligned,
            sampled_out: false,
            record: Some(rec),
            explanation: "DMARC aligned (SPF or DKIM)".to_string(),
        };
    }
    let sampled_out = match input.sample_roll {
        None => false,
        Some(roll) => roll >= rec.pct,
    };
    if sampled_out {
        return DmarcOutput {
            result: DmarcVerdict::Fail,
            policy_applied: DmarcPolicy::None,
            spf_aligned,
            dkim_aligned,
            sampled_out: true,
            record: Some(rec),
            explanation: "DMARC unaligned but sampled out by pct".to_string(),
        };
    }
    DmarcOutput {
        result: DmarcVerdict::Fail,
        policy_applied: policy,
        spf_aligned,
        dkim_aligned,
        sampled_out: false,
        record: Some(rec),
        explanation: format!("DMARC unaligned; policy {}", policy.as_str()),
    }
}

fn aligned(id: &DomainName, from: &DomainName, org: &DomainName, mode: AlignMode) -> bool {
    match mode {
        AlignMode::Strict => id.as_str() == from.as_str(),
        AlignMode::Relaxed => {
            crate::org_domain_heuristic(id).as_str() == org.as_str()
                && crate::org_domain_heuristic(from).as_str() == org.as_str()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MockResolver;

    fn dmarc_dns() -> MockResolver {
        MockResolver::new()
            .with_txt(
                "_dmarc.example.com",
                &["v=DMARC1; p=reject; aspf=r; adkim=r; pct=100"],
            )
            .with_txt(
                "_dmarc.strict.example",
                &["v=DMARC1; p=quarantine; aspf=s; adkim=s"],
            )
            .with_txt("_dmarc.pct.example", &["v=DMARC1; p=reject; pct=50"])
            .with_txt("_dmarc.sub.example", &["v=DMARC1; p=reject; sp=quarantine"])
            .with_txt("_dmarc.bad.example", &["v=DMARC1; p=block"])
    }

    fn base(from: &str) -> DmarcInput {
        DmarcInput {
            from_domain: DomainName::parse(from).unwrap(),
            spf_domain: DomainName::parse(from).unwrap(),
            spf_pass: true,
            dkim_domain: None,
            dkim_pass: false,
            org_override: None,
            sample_roll: None,
        }
    }

    #[test]
    fn pass_on_aligned_spf() {
        let dns = dmarc_dns();
        let out = evaluate(&dns, &base("example.com"));
        assert_eq!(out.result, DmarcVerdict::Pass);
        assert!(out.spf_aligned);
    }

    #[test]
    fn relaxed_allows_subdomain_but_strict_does_not() {
        let dns = dmarc_dns();
        let mut i = base("mail.example.com");
        i.spf_domain = DomainName::parse("example.com").unwrap();
        let out = evaluate(&dns, &i);
        assert_eq!(out.result, DmarcVerdict::Pass); // relaxed org match
        let mut s = base("a.strict.example");
        s.from_domain = DomainName::parse("a.strict.example").unwrap();
        s.spf_domain = DomainName::parse("strict.example").unwrap();
        s.org_override = Some(DomainName::parse("strict.example").unwrap());
        let out2 = evaluate(&dns, &s);
        assert_eq!(out2.result, DmarcVerdict::Fail);
        assert_eq!(out2.policy_applied, DmarcPolicy::Quarantine);
    }

    #[test]
    fn dkim_alignment_counts() {
        let dns = dmarc_dns();
        let mut i = base("example.com");
        i.spf_pass = false;
        i.dkim_pass = true;
        i.dkim_domain = Some(DomainName::parse("example.com").unwrap());
        let out = evaluate(&dns, &i);
        assert_eq!(out.result, DmarcVerdict::Pass);
        assert!(out.dkim_aligned);
    }

    #[test]
    fn no_record_is_none() {
        let dns = MockResolver::new();
        let out = evaluate(&dns, &base("norecord.example"));
        assert_eq!(out.result, DmarcVerdict::None);
    }

    #[test]
    fn pct_sampling_reported() {
        let dns = dmarc_dns();
        let mut i = base("pct.example");
        i.from_domain = DomainName::parse("pct.example").unwrap();
        i.spf_domain = DomainName::parse("other.example").unwrap();
        i.org_override = Some(DomainName::parse("pct.example").unwrap());
        i.sample_roll = Some(75); // pct=50 → sampled out
        let out = evaluate(&dns, &i);
        assert!(out.sampled_out);
        assert_eq!(out.policy_applied, DmarcPolicy::None);
        i.sample_roll = Some(10);
        let out2 = evaluate(&dns, &i);
        assert!(!out2.sampled_out);
        assert_eq!(out2.policy_applied, DmarcPolicy::Reject);
    }

    #[test]
    fn sub_policy_and_bad_record() {
        let dns = dmarc_dns();
        let mut i = base("x.sub.example");
        i.from_domain = DomainName::parse("x.sub.example").unwrap();
        i.spf_domain = DomainName::parse("evil.example").unwrap();
        i.org_override = Some(DomainName::parse("sub.example").unwrap());
        let out = evaluate(&dns, &i);
        assert_eq!(out.policy_applied, DmarcPolicy::Quarantine);
        let mut b = base("bad.example");
        b.org_override = Some(DomainName::parse("bad.example").unwrap());
        let out2 = evaluate(&dns, &b);
        assert_eq!(out2.result, DmarcVerdict::PermError);
    }

    #[test]
    fn temperror_on_dns_failure() {
        let dns = MockResolver::new().with_temp_fail("_dmarc.example.com");
        let out = evaluate(&dns, &base("example.com"));
        assert_eq!(out.result, DmarcVerdict::TempError);
    }
}
