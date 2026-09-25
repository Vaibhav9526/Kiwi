//! kiwi-sandbox — provider-pluggable disposable-VM boundary for hostile
//! attachment/document analysis (ADR-008, `docs/sandbox.md`).
//!
//! Contract: `docs/contracts/sandbox.md`. Callers code against
//! [`SandboxProvider`]/[`Sandbox`] only — never provider internals. A
//! provider may legitimately answer [`Availability::Unavailable`]; callers
//! MUST surface that to the user and MUST NOT fall back to host execution.
//!
//! Tiers (design doc §2):
//!   * QEMU/WHPX — dedicated-kernel target on Windows (not yet provisioned)
//!   * WSL2 dedicated distro — interim tier, works today; shared-kernel
//!     caveat is reported honestly via `dedicated_kernel: false`
//!   * Firecracker — Linux hosts (future)
//!   * [`NullProvider`] — always `Unavailable`; the no-sandbox answer.

pub mod error;
pub mod null;
pub mod wsl2;

pub use error::SandboxError;
pub use null::NullProvider;
pub use wsl2::{Wsl2Config, Wsl2Provider};

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, SandboxError>;

/// Invariant 5: hostile guest output must never exhaust host memory.
/// Providers truncate reports to these bounds.
pub const MAX_REPORT_ENTRIES: usize = 4096;
pub const MAX_STDOUT_TAIL: usize = 64 * 1024;
pub const MAX_FINDINGS: usize = 256 * 1024;
/// Default cap on artifact bytes copied into a guest.
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Egress enforcement a provider can actually guarantee — honesty over
/// capability claims (contract invariant 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressControl {
    /// Cannot enforce per-instance egress control.
    None,
    /// Egress is blocked by default (e.g. in-guest netns drop, no NIC).
    Blocked,
    /// Egress allowed through a capture path that yields a PCAP.
    FilteredPcap,
}

/// Which monitoring channels the provider can actually populate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Monitors {
    pub process: bool,
    pub fs: bool,
    pub network: bool,
}

/// What a provider can actually do on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// False on the shared-kernel WSL2 tier (documented caveat).
    pub dedicated_kernel: bool,
    pub snapshot_revert: bool,
    pub egress_control: EgressControl,
    pub monitors: Monitors,
    pub max_artifact_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Availability {
    Available(SandboxCapabilities),
    /// Usable with a stated limitation.
    Degraded(SandboxCapabilities, String),
    /// Not usable; human-readable reason. Never a silent downgrade.
    Unavailable(String),
}

impl Availability {
    pub fn capabilities(&self) -> Option<&SandboxCapabilities> {
        match self {
            Self::Available(c) | Self::Degraded(c, _) => Some(c),
            Self::Unavailable(_) => None,
        }
    }

    pub fn is_usable(&self) -> bool {
        !matches!(self, Self::Unavailable(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Host-side path; copied into the guest read-only for artifact targets.
    pub artifact_path: PathBuf,
    /// HTTP(S) target for providers that support isolated link analysis.
    /// Mutually exclusive with `artifact_path` in practice.
    pub link_url: Option<String>,
    /// Stable evidence reason codes explaining why the user opened the target.
    /// Never filenames, URLs, domains, or message content.
    pub evidence_reasons: Vec<String>,
    /// Hard kill past this.
    pub timeout_secs: u64,
    pub max_memory_mb: u32,
    /// Default false. Providers that cannot enforce per-instance egress
    /// control must refuse `true` (invariant 6).
    pub allow_egress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsChange {
    pub path: String,
    pub kind: FsChangeKind,
    /// SHA-256 of created files when the guest can hash them.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    pub dst: String,
    pub proto: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcEvent {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub args: Vec<String>,
}

/// Egress enforcement evidence (guest agent `network` section). On the
/// WSL2 tier egress is enforced structurally (netns drop) — the probe
/// fields are the *proof*, not a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressEvidence {
    /// How egress is enforced: "netns-drop" | "no-nic" | "none".
    pub enforced: String,
    /// Result of the agent's in-netns outbound probe (e.g. "unreachable").
    pub probe_inside_netns: String,
    /// Agent's own-namespace reachability — diagnostic context only.
    pub probe_outside_netns: String,
    /// In-netns DNS resolution probe ("blocked" expected).
    pub dns: String,
    /// Observed egress attempts — empty on the dropped-netns tier
    /// (nothing can attempt once the namespace has no net).
    pub attempts: Vec<NetEvent>,
}

/// Evidence, not a verdict — treat as untrusted data (contract: callers'
/// obligations). All fields bounded to `MAX_*` constants.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Stable reason codes supplied at open time — why KIWI asked the sandbox
    /// to inspect this target. Evidence, never a finding or verdict.
    #[serde(default)]
    pub evidence_reasons: Vec<String>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// Crash/kill/truncation → partial data; always honest.
    pub incomplete: bool,
    pub processes: Vec<ProcEvent>,
    pub fs_changes: Vec<FsChange>,
    pub net_events: Vec<NetEvent>,
    /// Captured traffic, if the provider supports it (WSL2 tier: never).
    pub pcap: Option<PathBuf>,
    /// Guest-agent egress evidence; None when no agent produced one
    /// (pre-agent runs, or report.json unreadable).
    #[serde(default)]
    pub egress: Option<EgressEvidence>,
    /// Last `MAX_STDOUT_TAIL` bytes of guest stdout.
    pub stdout_tail: String,
    /// Guest-side analysis output, truncated to `MAX_FINDINGS`.
    pub findings_raw: String,
}

#[async_trait::async_trait]
pub trait SandboxProvider: Send + Sync {
    /// Probe once at startup; cheap. Cache the result at the call site.
    fn availability(&self) -> Availability;

    /// Instantiate a sandbox from the provider's prepared base image.
    /// `Err(SandboxError::Unavailable)` when `availability()` is
    /// `Unavailable`.
    async fn create(&self, spec: SandboxSpec) -> Result<Box<dyn Sandbox>>;
}

#[async_trait::async_trait]
pub trait Sandbox: Send {
    /// Copy artifact in (read-only), execute under monitors, return a
    /// bounded report. The provider enforces `spec.timeout_secs` — a hung
    /// guest is killed and the report returns `timed_out: true`.
    async fn analyze(&mut self) -> Result<AnalysisReport>;

    /// Wipe the instance back to base state. Idempotent.
    async fn revert(&mut self) -> Result<()>;

    /// Destroy instance + all guest state. Best-effort — cannot fail open;
    /// also runs on Drop as a backstop.
    async fn teardown(self: Box<Self>) -> Result<()>;
}
