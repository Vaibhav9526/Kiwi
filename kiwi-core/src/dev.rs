//! Development fixture seam — `KIWI_DEV_PLAINTEXT=1`.
//!
//! Local mail fixtures (Mailpit, GreenMail) speak plaintext on loopback.
//! The production posture refuses plaintext credentials and hard-locks on a
//! plaintext session, which makes those fixtures unusable. This module is the
//! single opt-in seam: when the env var is truthy AND the target host is
//! loopback, callers may set `allow_plaintext_auth` and the trust policy
//! records the session as a low-severity observation instead of locking.
//!
//! Boundaries (THREAT-MODEL: dev fixture mode):
//! - Loopback only — a non-loopback host never qualifies, env or not.
//! - The session is still recorded (evidence is preserved) — it is downgraded,
//!   not hidden.
//! - Default is absent → production binaries are unchanged without the flag.

/// Env var gating the dev plaintext fixture mode (`1`/`true`).
pub const DEV_PLAINTEXT_ENV: &str = "KIWI_DEV_PLAINTEXT";

/// `KIWI_DEV_PLAINTEXT` truthy check (`1`/`true`, case-insensitive).
pub fn dev_plaintext_enabled() -> bool {
    std::env::var(DEV_PLAINTEXT_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Loopback-only check: `localhost` (incl. subdomains) or a loopback IP
/// literal (`127.0.0.0/8`, `::1`). Anything else — including hosts that merely
/// resolve to loopback — is out of scope; the flag authorizes literals, not
/// DNS answers.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches(|c| c == '[' || c == ']');
    if h.eq_ignore_ascii_case("localhost") || h.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    h.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Whether plaintext auth/transport may be tolerated for this host under the
/// dev fixture flag. Both conditions required — either alone means production
/// posture.
pub fn plaintext_fixture_for(host: &str) -> bool {
    dev_plaintext_enabled() && is_loopback_host(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_host_detection() {
        for h in [
            "127.0.0.1",
            "127.10.20.30",
            "::1",
            "[::1]",
            "localhost",
            "LOCALHOST",
            "mail.localhost",
        ] {
            assert!(is_loopback_host(h), "{h} should be loopback");
        }
        for h in [
            "example.com",
            "192.168.1.1",
            "10.0.0.1",
            "localhost.evil.com",
            "::2",
            "",
        ] {
            assert!(!is_loopback_host(h), "{h} must NOT be loopback");
        }
    }
}
