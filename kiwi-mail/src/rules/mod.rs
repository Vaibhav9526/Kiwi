//! Inbox rules (F1 groundwork, T-228) — deterministic, local, pure.
//!
//! A [`Rule`] is `when` (a [`Predicate`] tree over sender / recipient /
//! subject / headers / body / attachment names) → `then` (a list of
//! [`RuleAction`]s). [`evaluate`] is the whole engine: a pure function
//! from `(message, rules)` to [`RuleOutcome`] — no I/O, no clock, no
//! store. Callers fetch scope-appropriate rules via
//! [`MailStore::list_rules`](crate::store::MailStore::list_rules), call
//! `evaluate`, then [`apply_on_ingest`]/[`apply_now`]/[`preview_rule`]
//! perform the store side (move/flag writes, hit rows, eval watermarks —
//! deliberately separated from the pure evaluator).
//!
//! Precedence: `is_block` rules — the sender block list's storage form —
//! are evaluated before all regular rules and the first match is
//! terminal. Regular rules then apply in `position` order; flag actions
//! dedupe and the first folder disposition wins.
//!
//! Deferred eval (T-244): the `rule_evals` watermark records the deepest
//! stage each stored message was evaluated at (`Envelope` = header facts
//! absent). A message whose body arrives by *any* path after its
//! envelope eval re-enters the pending queue and is fully evaluated at
//! the next sync pass — the on-view loader is never hooked (a rule must
//! not move a message while it is open in the reader).
//!
//! Layout: `model.rs` — wire/durable types + bounds; `eval.rs` — the
//! evaluator + matching helpers; `apply.rs` — executing outcomes against
//! the store (ingest hook + "run now" + dry-run preview), the only
//! side-effecting part.

mod apply;
mod eval;
mod model;

pub use apply::{
    ARCHIVE_FOLDER, AppliedRules, ApplyNowReport, EvalStage, PreviewHit, RulePreview, TRASH_FOLDER,
    apply_now, apply_on_ingest, preview_rule,
};
pub use eval::evaluate;
pub(crate) use model::RuleSpec;
pub use model::{MatchOp, Predicate, Rule, RuleAction, RuleOutcome};
