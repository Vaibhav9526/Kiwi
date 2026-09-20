# Contract — Sandbox Interface (create / analyze / revert / teardown)

**Version:** 1.1 (draft) · **Owner:** Agent 2 · **Consumers:** kiwi-app IPC
layer, kiwi-forensics, Lead orchestration · **Design:** `docs/sandbox.md`

**v1.1 (T-168, Agent 10):** guest-agent report schema added
(`report.json`, `kiwi.sandbox.report/1`), `AnalysisReport.egress` field
added (serde-default, backwards compatible), exchange-channel rule
documented under invariant 1.

The sandbox boundary is **provider-pluggable**. Callers code against this
contract only — never against QEMU/WSL2/Firecracker specifics. A provider
may legitimately be `Unavailable`; callers MUST handle that path (no
fallback to host execution, ever — ADR-008).

## Types

```rust
/// What a provider can actually do on this host.
struct SandboxCapabilities {
    dedicated_kernel: bool,   // false on the shared-kernel WSL2 tier
    snapshot_revert: bool,
    egress_control: EgressControl,  // None | Blocked | FilteredPcap
    monitors: Monitors,             // {process, fs, network} bools
    max_artifact_bytes: u64,
}

enum Availability {
    Available(SandboxCapabilities),
    Degraded(SandboxCapabilities, String /* why degraded */),
    Unavailable(String /* human-readable reason */),
}

struct SandboxSpec {
    artifact_path: PathBuf,      // host-side, copied in read-only
    timeout_secs: u64,           // hard kill past this
    max_memory_mb: u32,
    allow_egress: bool,          // default false
}

struct FsChange { path: String, kind: FsChangeKind, sha256: Option<String> }
struct NetEvent { /* dst, proto, bytes — only when egress enabled */ }
struct ProcEvent { pid: u32, ppid: u32, exe: String, args: Vec<String> }

/// Egress enforcement evidence (v1.1). On tiers that enforce egress
/// structurally (dropped netns, no NIC), the probe fields are the proof.
struct EgressEvidence {
    enforced: String,            // "netns-drop" | "no-nic" | "none"
    probe_inside_netns: String,  // agent's own deny-test: "unreachable" …
    probe_outside_netns: String, // agent-namespace reachability (context)
    dns: String,                 // in-netns DNS probe: "blocked" …
    attempts: Vec<NetEvent>,     // observed attempts; empty on drop tiers
}

struct AnalysisReport {
    exit_code: Option<i32>,
    timed_out: bool,
    incomplete: bool,            // crash/kill → partial data, say so
    processes: Vec<ProcEvent>,   // bounded
    fs_changes: Vec<FsChange>,   // bounded
    net_events: Vec<NetEvent>,   // bounded; empty when egress blocked
    pcap: Option<PathBuf>,       // captured traffic, if provider supports
    egress: Option<EgressEvidence>, // guest-agent egress evidence (v1.1)
    stdout_tail: String,         // truncated
    findings_raw: String,        // guest-agent analysis output, truncated
}
```

## Interface (Rust trait shape; IPC mirrors it via serde)

```rust
#[async_trait]
trait SandboxProvider: Send + Sync {
    /// Probe once at startup; cache the result. Cheap.
    fn availability(&self) -> Availability;

    /// Instantiate a sandbox from the provider's prepared base image.
    /// Err(SandboxError::Unavailable) if availability() is Unavailable.
    async fn create(&self, spec: SandboxSpec) -> Result<Box<dyn Sandbox>, SandboxError>;
}

#[async_trait]
trait Sandbox: Send {
    /// Copy artifact in (read-only), execute under monitors, return report.
    /// The provider enforces `spec.timeout_secs` — a hung guest is killed,
    /// and the report is returned with `timed_out: true`.
    async fn analyze(&mut self) -> Result<AnalysisReport, SandboxError>;

    /// Wipe the instance back to base state. QEMU: discard overlay;
    /// WSL2: unregister+reimport. Idempotent.
    async fn revert(&mut self) -> Result<(), SandboxError>;

    /// Destroy instance + all guest state. Always succeeds best-effort;
    /// also runs on Drop as a backstop.
    async fn teardown(self: Box<Self>) -> Result<(), SandboxError>;
}
```

## Errors

```rust
enum SandboxError {
    Unavailable(String),       // provider absent — normal degradation path
    ImageMissing(String),      // base image not provisioned yet
    Create(String),            // VM/distro failed to start
    GuestError(String),        // guest-side agent failure
    Io(std::io::Error),
}
```

## Guest agent + report schema (v1.1)

Providers run an in-guest agent (`kiwi-sandbox/agent/kiwi-agent.sh` on the
WSL2 tier — a busybox-`sh` script copied in at analyze-time). The agent
runs the payload under resource limits (probed `ulimit`: cpu_secs,
file_blocks, nofile, vmem_kb, nproc — unsupported limits are reported in
`agent_notes`, never silently skipped) inside a dropped network
namespace, then writes a structured report to a **guest-side exchange
dir** (`/kiwi-out/`). The provider reads `report.json` back over the exec
channel before teardown.

> Exchange channel note: `/kiwi-out` is guest-side storage the host pulls
> via `wsl -e` exec pipes — NOT a guest-writable host mount. A real host
> mount would violate invariant 1.

`kiwi.sandbox.report/1` — `report.json` fields (all bounds enforced
host-side regardless of what the guest claims):

| field | meaning |
|---|---|
| `schema` | `"kiwi.sandbox.report/1"` |
| `exit_code` | payload exit status (null if never ran) |
| `timed_out` | guest-side `timeout` fired (host watchdog is separate) |
| `payload_error` | why the payload didn't run (e.g. egress isolation missing) |
| `limits_applied` | map of ulimit key→value actually accepted by the guest |
| `writes_outside_workdir` | count of fs changes outside `/kiwi-work` |
| `processes[]` | `{pid, ppid, exe, args}` — polled `ps` snapshots, deduped. Honest limit: processes shorter than the poll interval can evade. |
| `fs_changes[]` | `{path, kind: created|modified|deleted, outside_workdir, sha256}` — created files hashed (≤256) |
| `network.enforced` | `"netns-drop"` (payload runs under `unshare -rn`) or `"none"` |
| `network.probe_inside_netns` | agent's deny-test result: `"unreachable"` is the expected pass |
| `network.probe_outside_netns` | reachability of the agent's own namespace — context for judging whether inside-netns block is doing the work |
| `network.dns` | in-netns DNS probe result |
| `network.attempts_observed` | always `[]` on drop tiers — no egress attempts are possible inside a netns without a link |
| `stdout_tail` / `stderr_tail` | last 64KiB of payload output, escaped |
| `agent_notes[]` | honest degradation log (missing applets, unsupported limits) |

Fail-closed rule: if `unshare` is absent the agent sets `payload_error`
and never executes the artifact (invariant 6). The provider maps this to
`incomplete: true`.

## Invariants (provider MUST guarantee)

1. Artifact enters read-only; nothing guest-writable maps to the host FS.
   The exchange dir is guest-side; the host pulls reports over the exec
   channel — a guest-writable host mount is NOT permitted.
2. No host credentials, keys, or mailbox data are ever visible inside.
3. `revert()` restores exact base state; instances are single-analysis.
4. `teardown()` cannot fail open — partial teardown still destroys the VHDX.
5. Report fields are bounded (provider truncates; counts capped at 4096
   entries each) — hostile output cannot exhaust host memory.
6. Egress is off unless `spec.allow_egress`; a provider that can't enforce
   per-instance net control must report `egress_control: None` and refuse
   `allow_egress: true` requests.
7. `analyze` on a provider whose `dedicated_kernel` is false must flag the
   report (`incomplete` is NOT the flag — capability is in
   `availability()`; callers decide whether the tier is acceptable for the
   artifact's risk level).

## Callers' obligations

- Check `availability()` first; `Unavailable` → surface "active analysis
  unavailable" to UI, do NOT execute the attachment any other way.
- Always `teardown()` (or rely on Drop) — no instance reuse.
- Treat `AnalysisReport` as untrusted data; it is evidence, not a verdict.
