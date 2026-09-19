//! Mail protocol identification and transport-security classification.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Mail protocol a session belongs to.
///
/// `Unknown` is a first-class value: the engine must never guess a protocol
/// from weak heuristics alone, because protocol identity drives which security
/// expectations apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// SMTP / ESMTP (client-to-server submission and relay).
    Smtp,
    /// IMAP4rev1 / IMAP4rev2.
    Imap,
    /// POP3.
    Pop3,
    /// Not identified (e.g. unknown port and no recognizable protocol trace).
    Unknown,
}

impl Protocol {
    /// Every protocol variant, for iteration in reports and tests.
    pub const ALL: [Protocol; 4] = [
        Protocol::Smtp,
        Protocol::Imap,
        Protocol::Pop3,
        Protocol::Unknown,
    ];

    /// Stable lowercase identifier used in JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::Unknown => "unknown",
        }
    }

    /// Ports on which this protocol is conventionally served.
    pub fn well_known_ports(self) -> &'static [u16] {
        match self {
            Protocol::Smtp => &[25, 465, 587],
            Protocol::Imap => &[143, 993],
            Protocol::Pop3 => &[110, 995],
            Protocol::Unknown => &[],
        }
    }

    /// Identify a protocol from a TCP port number.
    ///
    /// Returns `None` when the port is not a well-known mail port; callers must
    /// then fall back to a protocol trace or record [`Protocol::Unknown`]
    /// rather than assuming a mapping.
    pub fn from_well_known_port(port: u16) -> Option<Protocol> {
        match port {
            25 | 465 | 587 => Some(Protocol::Smtp),
            143 | 993 => Some(Protocol::Imap),
            110 | 995 => Some(Protocol::Pop3),
            _ => None,
        }
    }

    /// Identify a protocol from a port, recording `Unknown` when unrecognized.
    pub fn from_port_or_unknown(port: u16) -> Protocol {
        Protocol::from_well_known_port(port).unwrap_or(Protocol::Unknown)
    }

    /// Ports that are defined as TLS-only, where plaintext is a hard violation
    /// of the protocol contract (`RFC 8314` §3.3: 465/993/995).
    pub fn is_implicit_tls_port(port: u16) -> bool {
        matches!(port, 465 | 993 | 995)
    }

    /// Ports that advertise STARTTLS upgrade (25/143/110 submission + access).
    pub fn is_starttls_capable_port(port: u16) -> bool {
        matches!(port, 25 | 587 | 143 | 110)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the observed connection was protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSecurity {
    /// No TLS in this session (mail exchanged in the clear).
    Plaintext,
    /// TLS negotiated in-band with STARTTLS/STLS.
    StartTls,
    /// TLS from the first byte (implicit TLS port, e.g. 465/993/995).
    ImplicitTls,
    /// The capture does not allow the question to be answered.
    Unknown,
}

impl TransportSecurity {
    /// Stable lowercase identifier used in JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportSecurity::Plaintext => "plaintext",
            TransportSecurity::StartTls => "starttls",
            TransportSecurity::ImplicitTls => "implicit_tls",
            TransportSecurity::Unknown => "unknown",
        }
    }

    /// `true` when the application data of this session is known to be
    /// unencrypted on the wire.
    pub fn is_known_plaintext(self) -> bool {
        matches!(self, TransportSecurity::Plaintext)
    }

    /// `true` when the session is expected to be cryptographically protected.
    ///
    /// `StartTls`/`ImplicitTls` mean TLS was *observed*; `Unknown` is **not**
    /// treated as protected, so credential-exposure rules stay conservative.
    pub fn is_protected(self) -> bool {
        matches!(self, TransportSecurity::StartTls | TransportSecurity::ImplicitTls)
    }
}

impl fmt::Display for TransportSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_port_mapping_is_exact() {
        assert_eq!(Protocol::from_well_known_port(587), Some(Protocol::Smtp));
        assert_eq!(Protocol::from_well_known_port(993), Some(Protocol::Imap));
        assert_eq!(Protocol::from_well_known_port(995), Some(Protocol::Pop3));
        assert_eq!(Protocol::from_well_known_port(8443), None);
        assert_eq!(Protocol::from_port_or_unknown(8443), Protocol::Unknown);
    }

    #[test]
    fn implicit_tls_ports_are_the_rfc8314_three() {
        assert!(Protocol::is_implicit_tls_port(465));
        assert!(Protocol::is_implicit_tls_port(993));
        assert!(Protocol::is_implicit_tls_port(995));
        assert!(!Protocol::is_implicit_tls_port(25));
        assert!(Protocol::is_starttls_capable_port(25));
        assert!(Protocol::is_starttls_capable_port(587));
        assert!(!Protocol::is_starttls_capable_port(465));
    }

    #[test]
    fn unknown_transport_is_not_treated_as_protected() {
        assert!(!TransportSecurity::Unknown.is_protected());
        assert!(TransportSecurity::ImplicitTls.is_protected());
        assert!(TransportSecurity::Plaintext.is_known_plaintext());
    }
}