//! kiwi-core — KIWI security-session model, endpoint trust engine,
//! SecureMail identity, and lock/unlock policy.
//!
//! Implements contract `docs/contracts/security-session.md` v1.
//! Deterministic only: no AI is consulted anywhere in this crate.

pub mod challenge;
pub mod dev;
pub mod device;
pub mod identity;
pub mod policy;
pub mod session;
pub mod trust;
