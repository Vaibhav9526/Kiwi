# KIWI Attachment Sandbox — Design (T-132)

**Status:** design + host evaluation complete; WSL2 lifecycle PoC verified.
**Author:** Agent 2 · **Date:** 2026-09-20 · **Branch:** release/v0.1.0
**Contract:** `docs/contracts/sandbox.md` · **ADR:** ADR-008, ADR-009

## 1. Why this exists

KIWI analyzes untrusted attachments/documents/links — by definition hostile
input. ADR-008 requires a *disposable VM* boundary; Docker is explicitly not
one (shared host kernel). This document records what this host can actually
do and the design that ships.

## 2. Host evaluation — measured on this machine (2026-09-20)

Probe: `tests/infra/check-sandbox-host.ps1` (read-only). Results:

| Fact | Value |
|---|---|
| OS | Windows 11 **Home** Single Language |
| `HypervisorPresent` | **True** (a hypervisor is already running) |
| `WinHvPlatform.dll` + `hvix64.exe` | **present** → WHPX user-mode API + driver installed |
| `vmcompute` (HCS) | **Running** — the service that hosts WSL2 utility VMs |
| `vmms` (Hyper-V Manager service) | **absent** — Hyper-V role not available on Home |
| WSL2 | present (`docker-desktop` distro running, kernel 6.6.114-microsoft) |
| `/dev/kvm` inside WSL2 | **absent** — nested virtualization disabled |
| QEMU | **not installed** |
| Docker | present — infra only, **never** the hostile-code boundary |

### Option matrix (honest boundaries)

| Option | Feasible here | Boundary provided | Verdict |
|---|---|---|---|
| **Firecracker** | ✗ | — | Requires KVM → Linux-only. Inside WSL2 would need nested virtualization (currently off; VM-in-VM adds moving parts for a weaker management story). Remains the Linux-host provider per ADR-008. |
| **QEMU/KVM** | ✗ | — | KVM does not exist on Windows. Dead end. |
| **Hyper-V Manager (`vmms`)** | ✗ | — | Not on Windows Home SKUs — no `New-VM`, no checkpoints. |
| **QEMU + WHPX** | ◐ (needs QEMU install) | **Full**: dedicated VM, own kernel, qcow2 snapshot/revert, `-object filter-dump` PCAP → kiwi-forensics, no NIC by default | **Primary target.** WHPX works on Home; QEMU is a portable binary — no Hyper-V role needed. |
| **HCS utility VM** | ◐ (hcsshim work) | Full | Same API WSL2 rides on; usable on Home but sparsely documented for arbitrary VMs. Keep as research track. |
| **WSL2 dedicated distro** | ✓ **today** | Real VM boundary vs host; **shared-kernel caveat** — all WSL2 distros share one utility-VM kernel, so a kernel-level escape lands in the WSL2 VM (not the host) but can reach other distros' filesystems | **PoC + interim provider.** Zero install, snapshot = re-import rootfs. |
| Docker container | ✗ | none vs host kernel | Excluded by ADR-008. |

### Decision

- **Tier A (target provider):** QEMU + WHPX, dedicated VM per analysis.
- **Tier B (interim, works today):** dedicated WSL2 distro instance per
  analysis — disposable via `wsl --unregister`; real hypervisor boundary vs
  the host, documented shared-kernel caveat.
- **Tier C (Linux deployments):** Firecracker, per ADR-008.
- All tiers behind the `SandboxProvider` interface (`contracts/sandbox.md`);
  callers see `Availability`, never a hard dependency. Sandbox absent →
  active analysis reports `Unavailable`, UI marks it disabled, **no
  fallback to host execution ever**.

## 3. Architecture

```
kiwi-app ──▶ SandboxProvider (trait, contracts/sandbox.md)
                ├─ availability() → Available | Degraded | Unavailable
                ├─ create(Spec)   → Sandbox
                ├─ analyze(Artifact, Budget) → AnalysisReport
                ├─ revert()       → wipe to base snapshot
                └─ teardown()     → destroy instance

providers/
   qemu_whpx/   dedicated VM, qcow2 overlay, virtio-serial agent, PCAP dump
   wsl2/        per-run distro: import pristine rootfs → run → unregister
   firecracker/ (linux) microVM, rootfs + kernel pair, vsock agent
```

### 3.1 Prebuilt base image + snapshot/revert

- **Base image is built once** (offline, by CI or admin tooling), versioned,
  hash-pinned. Contains: minimal Linux userland, `kiwi-sandbox-agent`
  (static binary), analysis toolchain (file/pdftotext/strace/tcpdump where
  applicable), *no* creds, *no* network tools needed by analysts.
- **Per-analysis lifecycle:**
  - QEMU/WHPX: `qcow2` overlay (`qemu-img create -b base.qcow2 -F qcow2
    overlay.qcow2`) → boot → analyze → discard overlay. Base is never
    written.
  - WSL2: `wsl --import` pristine `rootfs.tar` into a uniquely-named
    instance → run → `wsl --unregister`. Re-import = revert.
  - Never boot the base image mutable. Never reuse an instance.

### 3.2 Isolation guarantees (contract-enforced)

| Guarantee | QEMU/WHPX | WSL2 tier |
|---|---|---|
| Dedicated kernel | yes | **no — shared WSL2 kernel** (caveat) |
| Isolated FS | qcow2 overlay, destroyed after run | per-instance VHDX, destroyed |
| No host FS | default (9p/virtio-fs off or read-only artifact in) | `/mnt/c` auto-mount **disabled** via per-instance `wsl.conf` `[automount] enabled=false` |
| No host creds/keys | nothing mapped in | nothing mapped in |
| Controlled egress | no NIC by default; optional slirp user-net | no per-distro net toggle — inside-guest `unshare -rn` (netns drop) or host firewall on the WSL switch; flagged as weaker |
| Resource limits | `-m`, `-smp`, `-device` caps | `.wslconfig` is global; per-run `prlimit`/cgroup inside |
| Time limit | host-side watchdog → kill QEMU | watchdog → `wsl -t` + `--unregister` |
| Monitoring | guest agent over virtio-serial (proc/fs events) + slirp `-object filter-dump` PCAP | agent stdout stream (strace wrapper) + FS diff on teardown; no net when netns dropped |

### 3.3 Monitoring outputs (feeds kiwi-forensics)

- **process**: agent wraps payload exec with `strace -f` / auditd-lite;
  syscall summary + exec tree in report.
- **filesystem**: agent diffs the overlay FS (files created/modified/
  deleted + hashes of created files).
- **network**: only when egress enabled — QEMU `-object
  filter-dump,netdev=n0,file=*.pcap` gives real PCAP straight into
  kiwi-forensics' existing PCAP path. WSL2 tier reports egress as
  unavailable rather than faking it.
- **report contract**: `AnalysisReport` is bounded (max artifact counts,
  truncated strings) — a hostile guest cannot blow up the host parser.

### 3.4 Failure & degradation model

- Provider `availability()` is probed at startup and cached; absent
  QEMU/WSL2/base image → `Unavailable(reason)` with a human-readable cause.
- Any VM timeout/crash → auto-revert + teardown, report partial findings
  flagged `incomplete: true`.
- Nothing executes on the host. `analysis_requested` without an available
  provider is surfaced to the user as a capability gap, never silently
  downgraded.

## 4. Build order (next steps)

1. ✅ Host probe + evaluation (this doc, `check-sandbox-host.ps1`)
2. ✅ Interface contract (`contracts/sandbox.md`)
3. ✅ WSL2 lifecycle PoC (`tests/infra/sandbox-wsl-poc.ps1` — create/run/
   revert/teardown verified)
4. `kiwi-sandbox` crate: `SandboxProvider` trait + `Wsl2Provider` impl +
   `NullProvider` (Unavailable)
5. QEMU/WHPX provider once QEMU binary is provisioned (winget/portable —
   needs one-off install decision; not bundled silently)
6. Base image build recipe (Dockerfile → rootfs export → versioned tar)
7. Agent 6 transcripts: recorded QEMU command lines + agent protocol traces

## 5. ADR-009 justification (QEMU/WHPX component)

- **Need:** dedicated-kernel VM boundary on Windows Home — WSL2 tier's
  shared kernel is a documented gap.
- **Why not simpler:** Docker (no boundary), Hyper-V (SKU-blocked),
  Firecracker (no KVM).
- **Security:** qcow2 overlays (base never mutated), no NIC default,
  PCAP capture for monitoring, agent channel is virtio-serial (no net
  dependency).
- **Cost:** ~100–300MB binaries, one VM ≤ configured RAM/CPU budget, cold
  boot ~1–3s for microVM-sized images.
- **Testing:** scripted transcripts vs `qemu-img`/`qemu-system` CLI; WHPX
  availability probe; golden PCAP from known-benign payload.
