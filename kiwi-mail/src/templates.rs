//! Message templates (T-288): stored boilerplate for the composer — a
//! name, a subject line, a text body, and an optional HTML body, with
//! `{{name}}` placeholders resolved at apply time by
//! [`Template::render`].
//!
//! Templates are content, not policy: no per-account scoping, no
//! ordering — a flat named list the composer picks from. Validation is
//! store-side (`MailStore` re-runs [`Template::validate`] on every
//! write) because the renderer is untrusted: bounds live here, not in
//! the UI.
//!
//! Placeholder grammar — deliberately minimal for v1:
//!
//! - A token is `{{` + name + `}}`; the name may be surrounded by
//!   whitespace (`{{ name }}`) and matches `[A-Za-z0-9_.-]+`, at most
//!   [`MAX_VAR_NAME_LEN`] bytes. Anything else between the braces —
//!   including an empty name or invalid characters — is literal text,
//!   not a placeholder.
//! - Substitution is a single non-recursive pass: a substituted value
//!   containing `{{x}}` stays literal, so a template can never expand
//!   recursively or re-scan attacker-influenced values.
//! - Unknown names are left verbatim in the output and reported in
//!   `missing_vars` (sorted, deduped) — the composer can flag them
//!   rather than silently dropping or guessing.
//! - There are no escapes in v1: `{{` always opens a token scan. To
//!   emit a literal `{{name}}`, provide it via a variable value.

use std::collections::BTreeSet;

use crate::error::{MailError, Result};

/// Template id (`tpl-N`, store-assigned) — printable ASCII only.
pub const MAX_TEMPLATE_ID_LEN: usize = 64;
/// Display name.
pub const MAX_TEMPLATE_NAME_LEN: usize = 128;
/// Subject line — RFC 5322's 998-char line cap is the natural bound.
pub const MAX_TEMPLATE_SUBJECT_LEN: usize = 998;
/// Plain-text body cap.
pub const MAX_TEMPLATE_TEXT_LEN: usize = 64 * 1024;
/// HTML body cap (markup inflates; still bounded).
pub const MAX_TEMPLATE_HTML_LEN: usize = 128 * 1024;
/// Variables accepted by one render call.
pub const MAX_RENDER_VARS: usize = 64;
/// Placeholder name cap inside `{{ }}`.
pub const MAX_VAR_NAME_LEN: usize = 64;
/// One substituted value cap.
pub const MAX_VAR_VALUE_LEN: usize = 4 * 1024;
/// Reserved id prefix — store-assigned ids only; caller-supplied ids
/// using it are rejected so the sequence is never collided with.
pub const TEMPLATE_ID_PREFIX: &str = "tpl-";

fn invalid(reason: &str) -> MailError {
    MailError::InvalidInput(format!("template rejected: {reason}"))
}

/// A stored template row. `body_html` is optional — plain-text-only
/// templates are the common case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// `tpl-N`, assigned by the store on insert when empty.
    pub id: String,
    pub name: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub created_unix: i64,
    pub updated_unix: i64,
}

/// Render output: the substituted fields plus the names that were
/// placeholders but had no supplied value (left verbatim in the text).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedTemplate {
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    /// Well-formed `{{name}}` tokens with no supplied value.
    pub missing_vars: Vec<String>,
}

/// Rejects controls except the whitespace bodies legitimately carry.
fn clean_text(field: &str, s: &str, max: usize) -> Result<()> {
    if s.len() > max {
        return Err(invalid(&format!("{field} exceeds {max} bytes")));
    }
    if s.bytes()
        .any(|b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r') || b == 0x7F)
    {
        return Err(invalid(&format!("{field} contains control characters")));
    }
    Ok(())
}

impl Template {
    /// Store-boundary validation — every field bounded, ids printable.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() || self.id.len() > MAX_TEMPLATE_ID_LEN {
            return Err(invalid("id must be non-empty and bounded"));
        }
        if !self.id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid("id must be printable ASCII"));
        }
        if self.name.trim().is_empty() || self.name.len() > MAX_TEMPLATE_NAME_LEN {
            return Err(invalid("name missing or too long"));
        }
        clean_text("subject", &self.subject, MAX_TEMPLATE_SUBJECT_LEN)?;
        clean_text("bodyText", &self.body_text, MAX_TEMPLATE_TEXT_LEN)?;
        if let Some(h) = &self.body_html {
            clean_text("bodyHtml", h, MAX_TEMPLATE_HTML_LEN)?;
        }
        Ok(())
    }

    /// Resolve `{{name}}` placeholders against `vars`. See the module
    /// docs for the grammar: single pass, non-recursive, unknown names
    /// preserved and reported. `vars` itself is validated (count, name,
    /// value caps) so a hostile caller cannot make the renderer do
    /// unbounded work — oversized inputs are `invalid-input`, not a
    /// partial render.
    pub fn render(
        &self,
        vars: &std::collections::BTreeMap<String, String>,
    ) -> Result<RenderedTemplate> {
        if vars.len() > MAX_RENDER_VARS {
            return Err(invalid("too many template variables"));
        }
        for (k, v) in vars {
            if k.is_empty() || k.len() > MAX_VAR_NAME_LEN || !is_var_name(k) {
                return Err(invalid("variable name"));
            }
            if v.len() > MAX_VAR_VALUE_LEN {
                return Err(invalid("variable value too long"));
            }
        }
        let mut missing = BTreeSet::new();
        Ok(RenderedTemplate {
            subject: substitute(&self.subject, vars, &mut missing),
            body_text: substitute(&self.body_text, vars, &mut missing),
            body_html: self
                .body_html
                .as_deref()
                .map(|h| substitute(h, vars, &mut missing)),
            missing_vars: missing.into_iter().collect(),
        })
    }
}

fn is_var_name(name: &str) -> bool {
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Single-pass `{{name}}` substitution. Unterminated `{{`, empty or
/// invalid names stay literal; known names are replaced; unknown
/// well-formed names stay literal and are collected into `missing`.
fn substitute(
    input: &str,
    vars: &std::collections::BTreeMap<String, String>,
    missing: &mut BTreeSet<String>,
) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let inner_start = start + 2;
        // Bound the token scan: a legal name is ≤ MAX_VAR_NAME_LEN plus
        // surrounding whitespace slack — a `}}` beyond that window makes
        // the text literal by definition. `get` not index: the cap may
        // land mid-char.
        let scan_end = (inner_start + MAX_VAR_NAME_LEN + 4).min(rest.len());
        let window = rest.get(inner_start..scan_end).unwrap_or("");
        match window.find("}}") {
            None => {
                // No terminator inside the token budget → literal `{{`,
                // and scanning continues after it (a shorter, nested
                // `{{x}}` inside overlong text still parses).
                out.push_str("{{");
                rest = &rest[inner_start..];
            }
            Some(rel) => {
                let close = inner_start + rel;
                let name = rest[inner_start..close].trim();
                if !name.is_empty() && name.len() <= MAX_VAR_NAME_LEN && is_var_name(name) {
                    match vars.get(name) {
                        Some(v) => out.push_str(v),
                        None => {
                            missing.insert(name.to_string());
                            out.push_str(&rest[start..close + 2]);
                        }
                    }
                } else {
                    out.push_str(&rest[start..close + 2]);
                }
                rest = &rest[close + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tpl() -> Template {
        Template {
            id: "tpl-1".into(),
            name: "Follow up".into(),
            subject: "Re: {{topic}}".into(),
            body_text: "Hi {{name}},\n\nabout {{topic}} — {{extra}}\n".into(),
            body_html: Some("<p>Hi {{name}}</p>".into()),
            created_unix: 1,
            updated_unix: 1,
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn render_substitutes_and_reports_missing() {
        let r = tpl()
            .render(&vars(&[("name", "Ada"), ("topic", "the plan")]))
            .unwrap();
        assert_eq!(r.subject, "Re: the plan");
        assert_eq!(r.body_text, "Hi Ada,\n\nabout the plan — {{extra}}\n");
        assert_eq!(r.body_html.as_deref(), Some("<p>Hi Ada</p>"));
        assert_eq!(r.missing_vars, vec!["extra"]);
    }

    #[test]
    fn render_whitespace_inside_braces() {
        let mut t = tpl();
        t.subject = String::new();
        t.body_html = None;
        t.body_text = "{{  name  }}!".into();
        let r = t.render(&vars(&[("name", "Ada")])).unwrap();
        assert_eq!(r.body_text, "Ada!");
    }

    #[test]
    fn render_nonrecursive_and_literals() {
        // A substituted value containing a token stays literal.
        let mut t = tpl();
        t.subject = String::new();
        t.body_html = None;
        t.body_text = "{{a}} then {{b}}".into();
        let r = t.render(&vars(&[("a", "{{b}}"), ("b", "x")])).unwrap();
        assert_eq!(r.body_text, "{{b}} then x");
        assert!(r.missing_vars.is_empty());
    }

    #[test]
    fn render_invalid_tokens_stay_literal_and_unreported() {
        let mut t = tpl();
        t.subject = String::new();
        t.body_html = None;
        t.body_text = "{{}} {{ not a var! }} {{unterminated".into();
        let r = t.render(&vars(&[])).unwrap();
        assert_eq!(r.body_text, "{{}} {{ not a var! }} {{unterminated");
        assert!(r.missing_vars.is_empty());
    }

    #[test]
    fn render_bounds_vars() {
        let over: BTreeMap<String, String> = (0..=MAX_RENDER_VARS)
            .map(|i| (format!("v{i}"), "x".into()))
            .collect();
        assert!(tpl().render(&over).is_err());
        assert!(tpl().render(&vars(&[("bad name!", "x")])).is_err());
        assert!(
            tpl()
                .render(&vars(&[("k", &"y".repeat(MAX_VAR_VALUE_LEN + 1))]))
                .is_err()
        );
    }

    #[test]
    fn validate_bounds_and_controls() {
        let mut t = tpl();
        assert!(t.validate().is_ok());
        t.name = "  ".into();
        assert!(t.validate().is_err());
        t.name = "ok".into();
        t.body_text = "x\u{0007}".into(); // BEL is not legal body text
        assert!(t.validate().is_err());
        t.body_text = "line\nwith\ttabs\r\nfine".into();
        assert!(t.validate().is_ok());
        t.subject = "s".repeat(MAX_TEMPLATE_SUBJECT_LEN + 1);
        assert!(t.validate().is_err());
    }

    #[test]
    fn render_multibyte_is_char_safe() {
        let mut t = tpl();
        t.subject = String::new();
        t.body_html = None;
        t.body_text = "héllo {{name}} — €".into();
        let r = t.render(&vars(&[("name", "wörld")])).unwrap();
        assert_eq!(r.body_text, "héllo wörld — €");
    }
}
