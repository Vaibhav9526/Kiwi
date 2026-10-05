//! T-340 — the lock gate, verified by enumeration instead of by memory.
//!
//! The gap this closes: "is every registered command gated?" used to be
//! answered by reading the hand-written group comments in `lib.rs` and
//! trusting that whoever added the next command put it under the right header.
//! That is exactly how an ungated command becomes invisible — a new command
//! lands under `// accounts (gated)`, the comment says gated, and the body
//! silently isn't.
//!
//! So the matrix is now **code**. This module parses the real
//! `invoke_handler!` list out of `lib.rs`, resolves each command's body, and
//! asserts every registered command is either:
//!
//!   (a) **gated** — calls `gate()` (or delegates to an `_impl` that does), or
//!       the §9d.7 flow-scoped `pair_gate()`; or
//!   (b) **exempt** — present in [`LOCK_EXEMPT`] below, with a written reason.
//!
//! A command that is neither fails the build. That is the point: the exemption
//! list is the only place a command can skip the gate, so the default is
//! "gated" and an exemption is a deliberate, reviewable act.
//!
//! Exemptions follow the T-269 `pair_gate` pattern: narrow, written down, and
//! justified by what the command actually returns — not by convenience.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Commands reachable while the endpoint is `Locked`.
///
/// Each entry is `command -> why it is safe to run locked`. Adding a row is a
/// security decision and must be reviewed as one: a reviewer should be able to
/// read this table and agree the command returns nothing the lock withholds.
const LOCK_EXEMPT: &[(&str, &str)] = &[
    // -- the lock path itself: the renderer must be able to ask "am I locked?"
    //    and drive the unlock flow, or a locked app is permanently unusable.
    ("kiwi_ping", "returns a static string; no state read"),
    (
        "kiwi_app_info",
        "version/contract/deviceId/org/accountCount metadata only; no mailbox \
         data, no credential, no body.",
    ),
    (
        "kiwi_security_status",
        "IS the lock-state surface the overlay renders from. Returns trust state \
         + signal kind/severity/penalty + `evidenceRef` pointers, never payloads.",
    ),
    (
        "kiwi_lock",
        "locking must stay available while locked; there it is an idempotent \
         re-lock that can only ever reduce access.",
    ),
    (
        "kiwi_dev_unlock",
        "unlock path under KIWI_DEV_PLAINTEXT=1 only — gating it would deny \
         its entire purpose; without the env it fails closed unsupported-event. \
         Audited both ways (THREAT-MODEL RR-12).",
    ),
    ("kiwi_request_challenge", "step 1 of the unlock flow"),
    ("kiwi_submit_challenge", "step 2 of the unlock flow"),
    // -- §9d.7 canonical unlock path. Exempt by definition: this command *is*
    //    the lock-exit path, so gating it would be a denial of service.
    (
        "unlock_challenge",
        "§9d.7 — the canonical unlock path itself",
    ),
    // -- §9d.7 flow-scoped pairing exemption (T-269 `pair_gate`). NOT
    //    unconditionally exempt: `pair_gate` admits them while locked only when
    //    a backend-owned, unexpired flow is live (and `pair_status` only for the
    //    flow's own ticket). Listed so the classifier recognises `pair_gate` as
    //    enforcement rather than omission.
    (
        "pair_begin",
        "§9d.7/T-269 — `pair_gate`: only while a live flow exists",
    ),
    (
        "pair_status",
        "§9d.7/T-269 — `pair_gate`: live flow AND matching ticket",
    ),
    // -- trust input, not trust output. Signals must keep flowing while locked
    //    or the engine cannot tell the endpoint is still degraded at unlock.
    //    `Locked` is sticky in `TrustMachine::evaluate`, so this can never
    //    clear a lock — it only feeds evidence and re-evaluates.
    (
        "kiwi_collect_endpoint_signals",
        "feeds trust evidence; `Locked` is sticky in TrustMachine::evaluate so \
         this cannot unlock. Returns indicator observations, not mailbox data.",
    ),
    // -- T-331: audit-chain health. Verdict only — `ok|corrupt|unknown` plus a
    //    boolean. No rows, counts, paths, or hashes. The row reader
    //    (`kiwi_audit_events`) stays lock-gated.
    (
        "kiwi_audit_integrity",
        "returns only an integrity verdict; no row content, counts, or paths. \
         The audit row reader remains gated.",
    ),
    // -- T-345: the explicit quit path. Reads nothing, writes nothing — it only
    //    calls `AppHandle::exit`. Gating it on lock state would let a locked
    //    app refuse to terminate, which is strictly worse: the user could not
    //    close their own client.
    (
        "tray::kiwi_confirm_quit",
        "T-345 — terminates the process; reads no mailbox data and must stay \
         reachable while locked or the app could refuse to exit.",
    ),
];

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` under the crate's `src/`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The command names in `lib.rs`'s real
/// `invoke_handler(tauri::generate_handler![…])` list, group comments stripped.
fn registered_commands(lib_rs: &str) -> Vec<String> {
    let start = lib_rs
        .find("invoke_handler(tauri::generate_handler![")
        .expect("invoke_handler! block not found in lib.rs");
    // Start *after* the opening line, or `invoke_handler(tauri::generate_handler![`
    // itself parses as a command name.
    let body = &lib_rs[start..];
    let body = &body[body.find('\n').expect("no newline after invoke_handler![") + 1..];
    let end = body.find("])").expect("unterminated invoke_handler! block");
    body[..end]
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.trim_end_matches(',').trim().to_string())
        .collect()
}

/// Body of `fn <name>` in `src`, by brace matching from the signature.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let idx = src.find(&format!("fn {name}("))?;
    let open = src[idx..].find('{')? + idx;
    let mut depth = 0i32;
    for (off, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=open + off]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Map every function name in the crate to its body text, so a thin
/// `#[tauri::command]` wrapper that delegates to an `_impl` resolves to the
/// impl's body too.
fn all_fn_bodies(sources: &[PathBuf]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for p in sources {
        let Ok(text) = std::fs::read_to_string(p) else {
            continue;
        };
        for (idx, _) in text.match_indices("fn ") {
            let name: String = text[idx + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            if let Some(body) = fn_body(&text, &name) {
                map.entry(name).or_insert_with(|| body.to_string());
            }
        }
    }
    map
}

/// Does this body enforce the lock gate, directly or via an `_impl` it calls?
fn enforces_gate(body: &str, bodies: &BTreeMap<String, String>) -> bool {
    if body.contains("gate(state.inner())")
        || body.contains("gate(state)")
        || body.contains("gate(&state)")
        || body.contains("pair_gate(")
    {
        return true;
    }
    // Thin wrapper: follow one level of `something_impl(...)` delegation.
    bodies.iter().any(|(name, impl_body)| {
        name.ends_with("_impl")
            && body.contains(&format!("{name}("))
            && (impl_body.contains("gate(") || impl_body.contains("pair_gate("))
    })
}

#[test]
fn every_registered_command_is_gated_or_explicitly_exempt() {
    let root = src_root();
    let lib_rs = std::fs::read_to_string(root.join("lib.rs")).expect("lib.rs");
    let registered = registered_commands(&lib_rs);
    assert!(
        registered.len() > 100,
        "parsed only {} commands — the parser is broken, not the matrix",
        registered.len()
    );

    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    let bodies = all_fn_bodies(&sources);

    let exempt: BTreeMap<&str, &str> = LOCK_EXEMPT.iter().copied().collect();
    let mut ungated: Vec<&str> = Vec::new();

    for cmd in &registered {
        // A registered name with no resolvable body means the parser lost it;
        // treat as ungated so the failure is loud either way.
        let gated = bodies
            .get(cmd.as_str())
            .is_some_and(|b| enforces_gate(b, &bodies));
        if !gated && !exempt.contains_key(cmd.as_str()) {
            ungated.push(cmd);
        }
    }

    assert!(
        ungated.is_empty(),
        "UNGATED-BY-OMISSION: these commands are reachable while locked but call \
         neither gate() nor pair_gate() and are not on the LOCK_EXEMPT list. Add \
         `gate(state.inner()).await?;` — or, if the exemption is genuinely correct, \
         add a LOCK_EXEMPT row with a written reason: {ungated:?}"
    );
}

#[test]
fn the_exempt_list_has_no_dead_entries() {
    // An exemption for a command that is no longer registered (or was renamed)
    // is a stale claim about the security surface: it keeps the default
    // "gated" for the renamed command while reviewers read the list as covering
    // it.
    let lib_rs = std::fs::read_to_string(src_root().join("lib.rs")).expect("lib.rs");
    let registered = registered_commands(&lib_rs);
    let stale: Vec<&str> = LOCK_EXEMPT
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !registered.iter().any(|c| c == name))
        .collect();
    assert!(
        stale.is_empty(),
        "LOCK_EXEMPT lists commands that are not registered: {stale:?} — remove \
         the stale row, or re-register the command"
    );
}

#[test]
fn every_exemption_documents_a_reason() {
    for (name, reason) in LOCK_EXEMPT {
        assert!(
            reason.len() > 20,
            "exemption `{name}` has no meaningful written reason — an undocumented \
             exemption is indistinguishable from an omission"
        );
    }
}

/// A gate that runs *after* the work is a gate that does not gate. This is the
/// check a "does it call `gate()`?" grep cannot make: presence of the call
/// says nothing about ordering, and a command that reads the store and only
/// then refuses has already done the thing the lock is meant to prevent.
#[test]
fn the_gate_runs_before_the_command_does_any_work() {
    let root = src_root();
    let lib_rs = std::fs::read_to_string(root.join("lib.rs")).expect("lib.rs");
    let registered = registered_commands(&lib_rs);
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    let bodies = all_fn_bodies(&sources);

    let mut late: Vec<String> = Vec::new();
    for cmd in &registered {
        // Resolve to the function that actually holds the gate: either the
        // command itself, or the `_impl` it forwards to.
        let Some(body) = bodies.get(cmd.as_str()) else {
            continue;
        };
        let holder = if body.contains("gate(") || body.contains("pair_gate(") {
            body.as_str()
        } else {
            bodies
                .iter()
                .find(|(name, impl_body)| {
                    name.ends_with("_impl")
                        && body.contains(&format!("{name}("))
                        && (impl_body.contains("gate(") || impl_body.contains("pair_gate("))
                })
                .map_or("", |(_, b)| b.as_str())
        };
        let Some(pos) = holder.find("gate(").or_else(|| holder.find("pair_gate(")) else {
            continue; // exempt commands are not subject to ordering
        };
        let before = &holder[..pos];
        // Nothing may have *executed* before the gate: no statement
        // terminator, no `.await`, and no direct state/store touch.
        let executed_something = before.contains(';')
            || before.contains(".await")
            || before.contains("state.")
            || before.contains("run_mail_io");
        if executed_something {
            late.push(cmd.clone());
        }
    }

    assert!(
        late.is_empty(),
        "LATE GATE: these commands do work before refusing, so the lock does not \
         actually gate them: {late:?} — move `gate(...)` to the first statement"
    );
}
