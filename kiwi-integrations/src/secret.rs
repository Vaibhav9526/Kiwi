//! Secret-bearing in-memory strings.
//!
//! Capability material in this crate (provider session ids, the deliverability
//! reservation slug) is held in [`SecretString`], which:
//!
//! - never renders its contents — `Debug` and `Display` print `[redacted]`, so
//!   a stray `{:?}` in a log line cannot leak a credential;
//! - zeroizes its buffer when dropped, so a freed allocation does not keep the
//!   secret readable;
//! - deliberately implements **no** `serde` traits: a serializable capability is
//!   a loggable capability, so the only way out of this type is
//!   [`SecretString::expose`], which is `pub(crate)`.

use std::fmt;

use zeroize::Zeroizing;

/// An owned string that is redacted on print and zeroized on drop.
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Take ownership of `s`; the buffer is zeroized on drop.
    pub(crate) fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Borrow the secret for request building. Internal use only — the result
    /// must never be formatted into an error, log, or assertion message.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(Zeroizing::new((*self.0).clone()))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_never_carry_the_secret() {
        let s = SecretString::new("slug-abc123".into());
        assert_eq!(format!("{s:?}"), "SecretString([redacted])");
        assert!(!format!("{s:?}").contains("abc123"));
        assert_eq!(s.expose(), "slug-abc123");
    }

    #[test]
    fn clone_is_independent_and_redacted() {
        let s = SecretString::new("session-9".into());
        let c = s.clone();
        assert_eq!(c.expose(), "session-9");
        assert!(!format!("{c:?}").contains("session"));
        drop(s);
        assert_eq!(c.expose(), "session-9");
    }
}
