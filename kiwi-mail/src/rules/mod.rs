//! Inbox rules (F1 groundwork, T-228) — deterministic, local, pure.
//!
//! A [`Rule`] is `when` (a [`Predicate`] tree over sender / recipient /
//! subject / headers / body / attachment names) → `then` (a list of
//! [`RuleAction`]s). [`evaluate`] is the whole engine: a pure function
//! from `(message, rules)` to [`RuleOutcome`] — no I/O, no clock, no
//! store. Callers fetch scope-appropriate rules via
//! [`MailStore::list_rules`](crate::store::MailStore::list_rules), call
//! `evaluate`, then perform the actions themselves (move/flag writes are
//! the caller's side effects, deliberately outside this module).
//!
//! Precedence: `is_block` rules — the sender block list's storage form —
//! are evaluated before all regular rules and the first match is
//! terminal. Regular rules then apply in `position` order; flag actions
//! dedupe and the first folder disposition wins.
//!
//! Layout: `model.rs` — wire/durable types + bounds; `eval.rs` — the
//! evaluator + matching helpers.

mod eval;
mod model;

pub use eval::evaluate;
pub(crate) use model::RuleSpec;
pub use model::{MatchOp, Predicate, Rule, RuleAction, RuleOutcome};
