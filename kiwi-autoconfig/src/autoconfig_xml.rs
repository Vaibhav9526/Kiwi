//! Thunderbird-style `clientConfig` autoconfig XML: bounded parser + model.
//!
//! Dependency-free on purpose: no DTD/entity expansion, no namespace
//! machinery, no XXE surface. Bounds: ≤ [`MAX_XML_LEN`](crate::MAX_XML_LEN)
//! bytes, ≤ [`MAX_XML_DEPTH`](crate::MAX_XML_DEPTH) nesting, `<!DOCTYPE`
//! rejected outright, only the five predefined entities plus bounded
//! numeric references decoded.
//!
//! Fetched documents are untrusted input (SECURITY.md rule 9): every
//! field is length-checked and only the small vocabulary we understand is
//! mapped — unknown elements/attributes are ignored, never fatal.

use crate::suggest::{
    AccountSuggestion, AuthKind, IncomingKind, IncomingSuggestion, OutgoingSuggestion,
    SuggestionSource,
};
use crate::{DomainName, Error, MAX_CANDIDATES, MAX_XML_DEPTH, MAX_XML_LEN};
use kiwi_mail::transport::SocketSecurity;

/// One parsed XML element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
    text: String,
}

impl Element {
    fn child(&self, name: &str) -> Option<&Element> {
        self.children
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }
    fn children_named(&self, name: &str) -> impl Iterator<Item = &Element> {
        self.children
            .iter()
            .filter(move |c| c.name.eq_ignore_ascii_case(name))
    }
    /// Direct child text, trimmed and length-capped (256 chars).
    fn child_text(&self, name: &str) -> Option<String> {
        let t = self.child(name)?.text.trim();
        if t.is_empty() {
            return None;
        }
        Some(t.chars().take(256).collect())
    }
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse an autoconfig XML document into its root element.
pub(crate) fn parse_root(input: &str) -> Result<Element, Error> {
    if input.len() > MAX_XML_LEN {
        return Err(Error::TooLong);
    }
    // Reject DTD/entity declarations outright: kills external-entity and
    // billion-laughs classes of attack before parsing starts.
    let upper = input.to_ascii_uppercase();
    for forbidden in ["<!DOCTYPE", "<!ENTITY"] {
        if upper.contains(forbidden) {
            return Err(Error::MalformedXml("prohibited XML construct"));
        }
    }
    let mut p = Parser { s: input, pos: 0 };
    p.skip_misc()?;
    if p.peek() != Some('<') {
        return Err(Error::MalformedXml("no root element"));
    }
    let root = p.parse_element(0)?;
    p.skip_misc()?;
    if p.pos != input.len() {
        return Err(Error::MalformedXml("trailing content"));
    }
    Ok(root)
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.s[self.pos..]
    }
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }
    fn skip_ws(&mut self) {
        let n = self.rest().len()
            - self
                .rest()
                .trim_start_matches([' ', '\t', '\r', '\n'])
                .len();
        self.pos += n;
    }
    /// Skip comments, XML declarations and processing instructions.
    fn skip_misc(&mut self) -> Result<(), Error> {
        loop {
            self.skip_ws();
            let r = self.rest();
            if r.starts_with("<?") {
                let end = r.find("?>").ok_or(Error::MalformedXml("unterminated PI"))?;
                self.pos += end + 2;
            } else if r.starts_with("<!--") {
                let end = r
                    .find("-->")
                    .ok_or(Error::MalformedXml("unterminated comment"))?;
                self.pos += end + 3;
            } else {
                return Ok(());
            }
        }
    }
    fn expect(&mut self, lit: &str) -> Result<(), Error> {
        if self.rest().starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(Error::MalformedXml("unexpected token"))
        }
    }
    fn parse_name(&mut self) -> Result<String, Error> {
        let n = self
            .rest()
            .char_indices()
            .take_while(|(_, c)| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .ok_or(Error::MalformedXml("expected name"))?;
        if n > 64 {
            return Err(Error::MalformedXml("element name too long"));
        }
        let name = self.rest()[..n].to_string();
        self.pos += n;
        Ok(name)
    }
    /// Decode one `&…;` reference; only predefined + bounded numeric.
    fn parse_entity(&mut self) -> Result<char, Error> {
        let r = self.rest();
        debug_assert!(r.starts_with('&'));
        let end = r
            .find(';')
            .ok_or(Error::MalformedXml("unterminated entity"))?;
        let raw = &r[1..end];
        if raw.len() > 10 {
            return Err(Error::MalformedXml("unknown entity"));
        }
        let decoded = match raw {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let num = raw
                    .strip_prefix("#x")
                    .or_else(|| raw.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| raw.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                    .ok_or(Error::MalformedXml("unknown entity"))?;
                char::from_u32(num)
                    .filter(|c| !c.is_control() && *c != '\u{feff}')
                    .ok_or(Error::MalformedXml("bad character reference"))?
            }
        };
        self.pos += end + 1;
        Ok(decoded)
    }
    fn parse_text(&mut self) -> Result<String, Error> {
        let mut out = String::new();
        loop {
            let r = self.rest();
            if r.is_empty() || r.starts_with('<') {
                return Ok(out);
            }
            let stop = r.find(['<', '&']).unwrap_or(r.len());
            out.push_str(&r[..stop]);
            self.pos += stop;
            if self.rest().starts_with('&') {
                out.push(self.parse_entity()?);
            }
            if out.len() > 4096 {
                return Err(Error::MalformedXml("text too long"));
            }
        }
    }
}

impl Parser<'_> {
    /// Parse one element (assumes cursor is at `<`). Depth-bounded by caller.
    fn parse_element(&mut self, depth: usize) -> Result<Element, Error> {
        if depth > MAX_XML_DEPTH {
            return Err(Error::MalformedXml("nesting too deep"));
        }
        self.expect("<")?;
        let name = self.parse_name()?;
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    break;
                }
                Some('/') => {
                    self.expect("/>")?;
                    return Ok(Element {
                        name,
                        attrs,
                        children: Vec::new(),
                        text: String::new(),
                    });
                }
                Some(_) => {
                    let key = self.parse_name()?;
                    self.skip_ws();
                    self.expect("=")?;
                    self.skip_ws();
                    let quote = match self.peek() {
                        Some(q @ ('"' | '\'')) => q,
                        _ => return Err(Error::MalformedXml("unquoted attribute")),
                    };
                    self.pos += 1;
                    let end = self
                        .rest()
                        .find(quote)
                        .ok_or(Error::MalformedXml("unterminated attribute"))?;
                    let val = self.rest()[..end].to_string();
                    self.pos += end + 1;
                    if val.len() > 512 || attrs.len() >= MAX_CANDIDATES * 2 {
                        return Err(Error::MalformedXml("attribute limit"));
                    }
                    attrs.push((key, val));
                }
                None => return Err(Error::MalformedXml("unterminated element")),
            }
        }
        let mut el = Element {
            name,
            attrs,
            children: Vec::new(),
            text: String::new(),
        };
        loop {
            if self.rest().starts_with("</") {
                self.pos += 2;
                let close = self.parse_name()?;
                if close != el.name {
                    return Err(Error::MalformedXml("mismatched closing tag"));
                }
                self.skip_ws();
                self.expect(">")?;
                return Ok(el);
            }
            if self.rest().starts_with("<!--") {
                self.skip_misc()?;
                continue;
            }
            if self.rest().starts_with("<![CDATA[") {
                self.pos += 9;
                let end = self
                    .rest()
                    .find("]]>")
                    .ok_or(Error::MalformedXml("unterminated CDATA"))?;
                el.text.push_str(&self.rest()[..end]);
                self.pos += end + 3;
                continue;
            }
            if self.peek() == Some('<') {
                if el.children.len() >= MAX_CANDIDATES * 4 {
                    return Err(Error::MalformedXml("too many elements"));
                }
                let child = self.parse_element(depth + 1)?;
                el.children.push(child);
                continue;
            }
            if self.rest().is_empty() {
                return Err(Error::MalformedXml("unterminated element"));
            }
            let text = self.parse_text()?;
            el.text.push_str(&text);
            if el.text.len() > 4096 {
                return Err(Error::MalformedXml("text too long"));
            }
            if self.rest().is_empty() {
                return Err(Error::MalformedXml("unterminated element"));
            }
        }
    }
}

/// One `<incomingServer>` / `<outgoingServer>` entry, verbatim (bounded).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerSpec {
    /// `type` attribute (`imap`, `pop3`, `smtp`, …).
    pub kind: String,
    /// `<hostname>`.
    pub hostname: String,
    /// `<port>` when published (else inferred from socket type).
    pub port: Option<u16>,
    /// `<socketType>` (`SSL`, `STARTTLS`, `plain`).
    pub socket_type: String,
    /// `<username>` template (placeholders unexpanded here).
    pub username: String,
    /// `<authentication>` mechanism string.
    pub authentication: String,
}

/// `<oAuth2>` endpoints published by a provider (never secrets).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OAuth2Spec {
    /// Token issuer identifier (e.g. `accounts.google.com`).
    pub issuer: String,
    /// Requested scope.
    pub scope: String,
    /// Authorization endpoint.
    pub auth_url: String,
    /// Token endpoint.
    pub token_url: String,
}

/// Selected `emailProvider` from a parsed document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientConfig {
    /// `clientConfig` `version` attribute when present.
    pub version: Option<String>,
    /// Provider `id` attribute, else first listed `<domain>`.
    pub provider_id: Option<String>,
    /// Human-readable provider name.
    pub display_name: Option<String>,
    /// Domains this provider claims (≤16, validated).
    pub domains: Vec<String>,
    /// Incoming servers in document order (≤16).
    pub incoming: Vec<ServerSpec>,
    /// Outgoing servers in document order (≤16).
    pub outgoing: Vec<ServerSpec>,
    /// OAuth2 endpoints when published.
    pub oauth2: Option<OAuth2Spec>,
}

impl ClientConfig {
    /// Parse a document and select the provider best matching `domain`
    /// (exact `<domain>` match, else `id` match, else first provider).
    pub fn parse(xml: &str, domain: &DomainName) -> Result<Self, Error> {
        let root = parse_root(xml)?;
        let (version, providers): (Option<String>, Vec<&Element>) =
            if root.name.eq_ignore_ascii_case("clientConfig") {
                (
                    root.attr("version").map(|v| v.chars().take(16).collect()),
                    root.children_named("emailProvider").collect(),
                )
            } else if root.name.eq_ignore_ascii_case("emailProvider") {
                (None, vec![&root])
            } else {
                return Err(Error::MalformedXml("not a clientConfig document"));
            };
        let matches_domain = |p: &&Element, strict: bool| -> bool {
            if strict {
                p.children_named("domain")
                    .any(|d| DomainName::parse(d.text.trim()).is_ok_and(|x| x == *domain))
            } else {
                p.attr("id")
                    .is_some_and(|id| DomainName::parse(id).is_ok_and(|x| x == *domain))
            }
        };
        let chosen = providers
            .iter()
            .find(|p| matches_domain(p, true))
            .or_else(|| providers.iter().find(|p| matches_domain(p, false)))
            .or_else(|| providers.first())
            .ok_or(Error::MalformedXml("no emailProvider"))?;

        let servers = |tag: &str| -> Vec<ServerSpec> {
            chosen
                .children_named(tag)
                .take(MAX_CANDIDATES)
                .filter_map(|s| {
                    let hostname = s.child_text("hostname")?.to_ascii_lowercase();
                    let kind = s.attr("type").unwrap_or_default().to_ascii_lowercase();
                    Some(ServerSpec {
                        kind: kind.chars().take(16).collect(),
                        hostname,
                        port: s.child_text("port").and_then(|p| p.parse::<u16>().ok()),
                        socket_type: s.child_text("socketType").unwrap_or_else(|| "plain".into()),
                        username: s
                            .child_text("username")
                            .unwrap_or_else(|| "%EMAILADDRESS%".into()),
                        authentication: s.child_text("authentication").unwrap_or_default(),
                    })
                })
                .collect()
        };
        let domains: Vec<String> = chosen
            .children_named("domain")
            .take(MAX_CANDIDATES)
            .filter_map(|d| {
                DomainName::parse(d.text.trim())
                    .ok()
                    .map(|x| x.as_str().to_string())
            })
            .collect();
        Ok(Self {
            version,
            provider_id: chosen
                .attr("id")
                .map(|v| v.chars().take(128).collect())
                .or_else(|| domains.first().cloned()),
            display_name: chosen.child_text("displayName"),
            domains,
            incoming: servers("incomingServer"),
            outgoing: servers("outgoingServer"),
            oauth2: chosen.child("oAuth2").map(|o| OAuth2Spec {
                issuer: o.child_text("issuer").unwrap_or_default(),
                scope: o.child_text("scope").unwrap_or_default(),
                auth_url: o.child_text("authURL").unwrap_or_default(),
                token_url: o.child_text("tokenURL").unwrap_or_default(),
            }),
        })
    }
}

/// Published `socketType` → socket security. Unknown value → `None`
/// (server skipped; never guess a security mode).
fn socket_security(raw: &str) -> Option<SocketSecurity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ssl" | "tls" => Some(SocketSecurity::ImplicitTls),
        "starttls" => Some(SocketSecurity::StartTls),
        "plain" | "plaintext" | "none" => Some(SocketSecurity::Plaintext),
        _ => None,
    }
}

/// Published `<authentication>` → credential kind we can actually perform.
/// Unsupported mechanisms (GSSAPI/NTLM/client-IP) and `none` → `None`.
fn auth_kind(raw: &str) -> Option<AuthKind> {
    let a = raw.trim().to_ascii_lowercase();
    if a.contains("oauth") {
        Some(AuthKind::XOAuth2)
    } else if a.starts_with("password") || a.is_empty() || a.contains("cram") {
        Some(AuthKind::Password)
    } else {
        None
    }
}

/// Well-known port when the document omits `<port>`.
fn default_port(kind: &str, security: SocketSecurity) -> Option<u16> {
    Some(match (kind, security) {
        ("imap", SocketSecurity::ImplicitTls) => 993,
        ("imap", _) => 143,
        ("pop3", SocketSecurity::ImplicitTls) => 995,
        ("pop3", _) => 110,
        ("smtp", SocketSecurity::ImplicitTls) => 465,
        ("smtp", SocketSecurity::StartTls) => 587,
        ("smtp", SocketSecurity::Plaintext) => 25,
        _ => return None,
    })
}

fn security_rank(security: SocketSecurity) -> u8 {
    match security {
        SocketSecurity::ImplicitTls => 0,
        SocketSecurity::StartTls => 1,
        SocketSecurity::Plaintext => 2,
    }
}

/// Expand `%EMAILADDRESS%` / `%EMAILLOCALPART%` / `%EMAILDOMAIN%`
/// (case-insensitive); unknown placeholders are left untouched.
fn substitute(template: &str, email: &str, local: &str, domain: &str) -> String {
    let mut out = String::with_capacity(template.len() + email.len());
    let mut rest = template;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let token = after[..end].to_ascii_lowercase();
                match token.as_str() {
                    "emailaddress" => out.push_str(email),
                    "emaillocalpart" => out.push_str(local),
                    "emaildomain" => out.push_str(domain),
                    _ => {
                        out.push('%');
                        out.push_str(&after[..end]);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(rest);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.chars().take(256).collect()
}

impl ClientConfig {
    /// Convert the selected provider into an [`AccountSuggestion`] for
    /// `email`. `None` when the document publishes no usable
    /// incoming+outgoing pair (unsupported auth/socket type, bad host,
    /// missing servers) — the caller then falls through to the next stage.
    ///
    /// Ranking (deterministic, no floats): IMAP before POP3, then
    /// ImplicitTLS before STARTTLS before plaintext; ties resolve in
    /// document order.
    #[must_use]
    pub fn to_suggestion(
        &self,
        email: &str,
        source: SuggestionSource,
    ) -> Option<AccountSuggestion> {
        let (local, domain) = crate::split_email(email).ok()?;
        let domain_s = domain.as_str();
        let incoming = self
            .incoming
            .iter()
            .filter_map(|s| {
                let security = socket_security(&s.socket_type)?;
                let kind = match s.kind.as_str() {
                    "imap" => IncomingKind::Imap,
                    "pop3" => IncomingKind::Pop3,
                    _ => return None,
                };
                let port = s.port.or_else(|| default_port(&s.kind, security))?;
                Some((
                    (
                        u8::from(kind == IncomingKind::Pop3),
                        security_rank(security),
                    ),
                    IncomingSuggestion {
                        kind,
                        host: s.hostname.clone(),
                        port,
                        security,
                        auth: auth_kind(&s.authentication)?,
                        username: substitute(&s.username, email, &local, domain_s),
                    },
                ))
            })
            .min_by_key(|(k, _)| *k)
            .map(|(_, v)| v)?;
        let outgoing = self
            .outgoing
            .iter()
            .filter_map(|s| {
                if s.kind != "smtp" {
                    return None;
                }
                let security = socket_security(&s.socket_type)?;
                let port = s.port.or_else(|| default_port(&s.kind, security))?;
                Some((
                    security_rank(security),
                    OutgoingSuggestion {
                        host: s.hostname.clone(),
                        port,
                        security,
                        auth: auth_kind(&s.authentication)?,
                        username: substitute(&s.username, email, &local, domain_s),
                    },
                ))
            })
            .min_by_key(|(k, _)| *k)
            .map(|(_, v)| v)?;
        AccountSuggestion {
            source,
            email: email.trim().to_string(),
            display_name: self.display_name.clone().unwrap_or_else(|| local.clone()),
            incoming,
            outgoing,
        }
        .checked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::{AuthKind, IncomingKind};

    /// Minimal well-formed Thunderbird clientConfig document.
    const FIXTURE_OK: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="example.test">
    <domain>example.test</domain>
    <displayName>Example Provider</displayName>
    <incomingServer type="imap">
      <hostname>imap.example.test</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>pop.example.test</hostname>
      <port>110</port>
      <socketType>plain</socketType>
      <username>%EMAILLOCALPART%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.test</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#;

    const FIXTURE_OAUTH2: &str = r#"<clientConfig>
  <emailProvider id="oauth.test">
    <domain>oauth.test</domain>
    <displayName>OAuth Corp</displayName>
    <incomingServer type="imap">
      <hostname>imap.oauth.test</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>OAuth2</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.oauth.test</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
    </outgoingServer>
    <oAuth2>
      <issuer>accounts.oauth.test</issuer>
      <scope>mail.read</scope>
      <authURL>https://accounts.oauth.test/auth</authURL>
      <tokenURL>https://accounts.oauth.test/token</tokenURL>
    </oAuth2>
  </emailProvider>
</clientConfig>"#;

    #[test]
    fn parses_full_client_config() {
        let d = DomainName::parse("example.test").unwrap();
        let cfg = ClientConfig::parse(FIXTURE_OK, &d).unwrap();
        assert_eq!(cfg.provider_id.as_deref(), Some("example.test"));
        assert_eq!(cfg.display_name.as_deref(), Some("Example Provider"));
        assert_eq!(cfg.domains, vec!["example.test"]);
        assert_eq!(cfg.incoming.len(), 2);
        assert_eq!(cfg.outgoing.len(), 1);
        let imap = &cfg.incoming[0];
        assert_eq!(imap.hostname, "imap.example.test");
        assert_eq!(imap.port, Some(993));
        assert_eq!(imap.socket_type, "SSL");
    }

    #[test]
    fn domain_selection_exact_beats_order() {
        let xml = r#"<clientConfig>
  <emailProvider id="a.test">
    <domain>a.test</domain>
    <displayName>A</displayName>
  </emailProvider>
  <emailProvider id="b.test">
    <domain>b.test</domain>
    <displayName>B</displayName>
  </emailProvider>
</clientConfig>"#;
        let d = DomainName::parse("b.test").unwrap();
        let cfg = ClientConfig::parse(xml, &d).unwrap();
        assert_eq!(cfg.display_name.as_deref(), Some("B"));
        assert_eq!(cfg.provider_id.as_deref(), Some("b.test"));
    }

    #[test]
    fn oauth2_doc_maps_to_xoauth2_and_defaults_port() {
        let d = DomainName::parse("oauth.test").unwrap();
        let cfg = ClientConfig::parse(FIXTURE_OAUTH2, &d).unwrap();
        let s = cfg
            .to_suggestion("u@oauth.test", SuggestionSource::AutoconfigHost)
            .unwrap();
        assert_eq!(s.incoming.auth, AuthKind::XOAuth2);
        assert_eq!(s.incoming.port, 993);
        // outgoing port was explicit (465) with SSL.
        assert_eq!(s.outgoing.host, "smtp.oauth.test");
        assert_eq!(s.outgoing.port, 465);
        assert_eq!(s.outgoing.security, SocketSecurity::ImplicitTls);
        assert_eq!(cfg.oauth2.as_ref().unwrap().issuer, "accounts.oauth.test");
    }

    #[test]
    fn substitutes_placeholders() {
        assert_eq!(
            substitute("%EMAILADDRESS%", "u@x.test", "u", "x.test"),
            "u@x.test"
        );
        assert_eq!(
            substitute("%EMAILLOCALPART%@host", "u@x.test", "u", "x.test"),
            "u@host"
        );
        assert_eq!(
            substitute("u@%EMAILDOMAIN%", "u@x.test", "u", "x.test"),
            "u@x.test"
        );
        // Unknown placeholders preserved verbatim.
        assert_eq!(substitute("%NOPE%", "u@x.test", "u", "x.test"), "%NOPE%");
        // Case-insensitive.
        assert_eq!(
            substitute("%emailaddress%", "u@x.test", "u", "x.test"),
            "u@x.test"
        );
    }

    #[test]
    fn socket_and_auth_mapping() {
        assert_eq!(socket_security("SSL"), Some(SocketSecurity::ImplicitTls));
        assert_eq!(socket_security("starttls"), Some(SocketSecurity::StartTls));
        assert_eq!(socket_security("plain"), Some(SocketSecurity::Plaintext));
        assert_eq!(socket_security("tls-unknown"), None);
        assert_eq!(auth_kind("OAuth2"), Some(AuthKind::XOAuth2));
        assert_eq!(auth_kind("password-cleartext"), Some(AuthKind::Password));
        assert_eq!(auth_kind("password-encrypted"), Some(AuthKind::Password));
        assert_eq!(auth_kind("gssapi"), None);
        assert_eq!(auth_kind("SMTP"), None);
    }

    #[test]
    fn ranking_imap_tls_first() {
        let d = DomainName::parse("example.test").unwrap();
        let cfg = ClientConfig::parse(FIXTURE_OK, &d).unwrap();
        let s = cfg
            .to_suggestion("u@example.test", SuggestionSource::WellKnown)
            .unwrap();
        assert_eq!(s.incoming.kind, IncomingKind::Imap);
        assert_eq!(s.incoming.security, SocketSecurity::ImplicitTls);
        assert_eq!(s.incoming.username, "u@example.test");
        assert_eq!(s.outgoing.port, 587);
        assert_eq!(s.source, SuggestionSource::WellKnown);
    }

    #[test]
    fn doctype_rejected() {
        let evil = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><clientConfig/>"#;
        assert!(matches!(
            parse_root(evil),
            Err(Error::MalformedXml("prohibited XML construct"))
        ));
    }

    #[test]
    fn entities_and_cdata_decode() {
        let xml = "<a><t>a&lt;b&amp;c&#65;&#x42;</t><c><![CDATA[raw<ok>]]></c></a>";
        let root = parse_root(xml).unwrap();
        assert_eq!(root.child("t").unwrap().text, "a<b&cAB");
        assert_eq!(root.child("c").unwrap().text, "raw<ok>");
    }

    #[test]
    fn unknown_entity_rejected() {
        assert!(matches!(
            parse_root("<a>&evil;</a>"),
            Err(Error::MalformedXml("unknown entity"))
        ));
    }

    #[test]
    fn deep_nesting_rejected() {
        let mut xml = String::new();
        for _ in 0..40 {
            xml.push_str("<a>");
        }
        xml.push('x');
        for _ in 0..40 {
            xml.push_str("</a>");
        }
        assert!(parse_root(&xml).is_err());
    }

    #[test]
    fn mismatched_tag_rejected() {
        assert!(parse_root("<a><b></c></a>").is_err());
    }

    #[test]
    fn overlong_document_rejected() {
        let big = format!("<a>{}</a>", "x".repeat(MAX_XML_LEN + 1));
        assert_eq!(parse_root(&big), Err(Error::TooLong));
    }

    #[test]
    fn unsupported_socket_or_auth_skips_server() {
        // Only a gssapi imap server → no usable incoming → no suggestion.
        let xml = r#"<clientConfig><emailProvider id="x.test"><domain>x.test</domain>
            <incomingServer type="imap">
              <hostname>imap.x.test</hostname><port>993</port>
              <socketType>SSL</socketType><authentication>gssapi</authentication>
            </incomingServer>
            <outgoingServer type="smtp">
              <hostname>smtp.x.test</hostname><port>587</port>
              <socketType>STARTTLS</socketType><authentication>password-cleartext</authentication>
            </outgoingServer>
        </emailProvider></clientConfig>"#;
        let d = DomainName::parse("x.test").unwrap();
        let cfg = ClientConfig::parse(xml, &d).unwrap();
        assert!(
            cfg.to_suggestion("u@x.test", SuggestionSource::AutoconfigHost)
                .is_none()
        );
    }

    #[test]
    fn non_clientconfig_root_rejected() {
        // parse_root is generic; ClientConfig::parse enforces the root name.
        assert!(parse_root("<html><body/></html>").is_ok());
        let d = DomainName::parse("x.test").unwrap();
        assert!(ClientConfig::parse("<html/>", &d).is_err());
    }
}
