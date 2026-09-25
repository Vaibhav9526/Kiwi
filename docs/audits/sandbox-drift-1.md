# Sandbox Contract Drift Audit 1 (T-256)

**Reviewer:** Agent 22 · **Date:** 2026-09-25 · **Mode:** read-only analysis.
**Scope:** `docs/contracts/sandbox.md` v1.1 against the complete current
`kiwi-sandbox` crate, `kiwi-sandbox/agent/kiwi-agent.sh`, the Tauri command
surface under `kiwi-app/src-tauri`, and the sandbox design/lifecycle tests.
No Rust, TypeScript, contract implementation, or shared-worktree source files
were changed.

**Provenance:** T-132 supplied the design, T-161 supplied the provider crate,
T-168 supplied the guest agent, T-196 supplied the original SBX-1..7 and SBX-I
observations, and T-252 supplied the canonical register. This audit re-read the
contract and current source, then traced the caller and guest-agent surfaces
that the original broad audit did not enumerate individually.

## Method and severity

The contract was read in full. Each type, trait method, error variant, report
field, invariant, and caller obligation was mapped to source evidence or an
explicitly proven absence. WSL2 management commands, guest exec, the embedded
agent, unit tests, the live lifecycle test, and the Tauri registry/manifests
were inspected. A finding is recorded when the current implementation or a
required consumer boundary disagrees with a normative promise, not merely
because a future provider or UI is not implemented.

- **H:** a host or credential boundary can be crossed, or hostile content can
  execute outside the required sandbox boundary.
- **M:** a normative isolation, lifecycle, evidence, or caller obligation is
  incomplete or can produce materially misleading behavior.
- **L:** report/schema/taxonomy/documentation drift with no direct host escape.
- **I:** implemented-but-undocumented surface or a non-normative follow-up
  gap.

The WSL2 tier is intentionally an interim provider with a shared WSL2 utility
kernel. `dedicated_kernel: false` is therefore an honest capability value, not
a defect by itself.

## Summary

| Area | Result |
|---|---|
| Public types, provider traits, and lifecycle method shapes | Present and substantially aligned; the canonical broad-audit conclusion remains valid. |
| Availability, shared-kernel caveat, NullProvider, and no-host-fallback rule | Aligned. `NullProvider` always returns `Unavailable`; WSL2 exposes `dedicated_kernel: false` and `egress_control: Blocked`. |
| Artifact/exchange/network/time/resource paths | Core WSL2 flow exists, with the documented report-plumbing drifts SBX-3..7 and the bound drift SBX-1. |
| Base-image host-FS/credential isolation | Depends on an externally prepared `wsl.conf`; the provider does not verify that precondition at runtime. This is a T-256 observation, not a claim that the tested PoC image is unsafe. |
| Tauri/app/forensics/Lead caller obligations | No sandbox command or provider consumer is present. The interface is a library boundary only in the current tree. |
| Links | No link/URL input or analysis method is defined by the sandbox contract; only `artifact_path` bytes are specified. This is a contract/product decision, not a link-analysis implementation claim. |

## Contract-surface enumeration

| ID | Contract promise | Current implementation/evidence | Result |
|---|---|---|---|
| C-01 | Provider is pluggable; callers use only `SandboxProvider`/`Sandbox`; no host fallback ever. | `kiwi-sandbox/src/lib.rs:11-14,174-198`; `src/null.rs:19-27`. The crate has no host execution fallback. | Aligned. |
| C-02 | `SandboxCapabilities` has kernel, snapshot, egress, monitor, and artifact-cap fields. | `src/lib.rs:38-67`; WSL2 fills all five fields at `src/wsl2.rs:96-112`. | Aligned. |
| C-03 | `Availability` exposes `Available`, `Degraded`, or `Unavailable`; availability is cheap and cached. | `src/lib.rs:69-89`; `Wsl2Provider` uses `OnceLock` at `src/wsl2.rs:77-82,119-129,230-237`. WSL2 reports `Available` with a false dedicated-kernel capability rather than hiding the caveat. | Aligned. `Degraded` is currently unused by WSL2, which the contract permits. |
| C-04 | `SandboxSpec` carries a host artifact path, hard timeout, memory budget, and default-off egress. | `src/lib.rs:91-101`; validation and artifact copy are at `src/wsl2.rs:137-165,201-223`. | Aligned, subject to the prepared-image observations below. |
| C-05 | Public report fields are bounded and include exit, timeout, incomplete state, process/FS/network evidence, PCAP, egress, output, and findings. | `AnalysisReport` is field-complete at `src/lib.rs:151-172`; WSL2 builds it at `src/wsl2.rs:383-488`. | Shape aligned; guest evidence fields have SBX-3..6 gaps. |
| C-06 | `create` must return `Unavailable` when the provider is unavailable. | `src/wsl2.rs:166-168,230-237`; `NullProvider` returns the same normal degradation error at `src/null.rs:25-27`. | Aligned except the missing-image error is classified as `Unavailable` (SBX-2). |
| C-07 | `create` imports a prepared pristine instance and copies the artifact into the guest. | `wsl --import`, unique naming, and stdin copy are at `src/wsl2.rs:170-225`; the live test exercises import/create at `src/wsl2.rs:1045-1066`. | Implemented. The guest-side mount policy is supplied by the rootfs recipe, not verified by the provider. |
| C-08 | `analyze` runs under monitors, enforces `spec.timeout_secs`, kills a hung guest, and returns partial evidence. | Host watchdog and guest timeout are at `src/wsl2.rs:407-469`; `exec_guest` kills the child at `src/wsl2.rs:742-766`; the agent polls/limits output at `agent/kiwi-agent.sh:74-99`. | Aligned for guest exec; WSL management-command timeout handling has T256-O1. |
| C-09 | `revert` restores exact base state and is idempotent. | Unregister plus pristine re-import is at `src/wsl2.rs:491-516`; the live test verifies marker removal at `src/wsl2.rs:1097-1111`. | Aligned. Re-import is a fresh instance and the design's single-analysis rule remains the caller's responsibility. |
| C-10 | `teardown` destroys guest state, cannot fail open, and Drop is a backstop. | Explicit teardown is at `src/wsl2.rs:519-541`; Drop at `src/wsl2.rs:544-553`. | Aligned in the normal path; a timed-out WSL management child is not killed (T256-O1). |
| C-11 | Error taxonomy is `Unavailable`, `ImageMissing`, `Create`, `GuestError`, and `Io`. | All variants exist at `src/error.rs:5-20`; current missing-rootfs handling is at `src/wsl2.rs:120-128,166-168`. | SBX-2: `ImageMissing` is declared but never constructed. |
| C-12 | WSL2 copies the guest agent at analyze time rather than baking it into the base image. | `AGENT_SH` is embedded at `src/wsl2.rs:49-51` and copied at `src/wsl2.rs:396-405`. | Aligned. |
| C-13 | Agent probes and applies CPU, file, descriptor, memory, and process limits; unsupported limits are reported. | Probe and application are at `agent/kiwi-agent.sh:30-55,76-82`; notes are emitted at `:162-164`. | Aligned at the shell-contract level. `max_memory_mb=0` is not rejected by the provider and is noted below as a hardening gap. |
| C-14 | `/kiwi-out` is guest-side and the host reads the report over `wsl -e`, never through a guest-writable host mount. | Agent writes the exchange directory at `agent/kiwi-agent.sh:23-27,172-200`; provider reads it at `src/wsl2.rs:437-459`. | Aligned. |
| C-15 | Agent fails closed if `unshare` is absent and does not execute the artifact. | Presence check, refusal, and payload branch are at `agent/kiwi-agent.sh:20-21,39-40,76-99`. | Aligned. Presence alone does not prove that the requested `unshare -rn` flags work; probe output preserves `untested`. |
| C-16 | Process evidence is bounded, polled, deduplicated, and honestly limited. | Polling and 4096-line cap are at `agent/kiwi-agent.sh:84-95`; JSON emission is at `:143-160`; host merge truncation is at `src/wsl2.rs:625-636`. | Mostly aligned; SBX-5 is a wire-shape mismatch. Short-process evasion is documented in the contract. |
| C-17 | FS evidence reports created/modified/deleted paths, outside-workdir state, and hashes for created files. | Agent diff and hash paths are at `agent/kiwi-agent.sh:70-117,127-140`; host fallback is at `src/wsl2.rs:317-377`. | Drift: SBX-1 and SBX-4; the public `FsChange` type does not retain `outside_workdir`. |
| C-18 | Egress is off by default; a provider that cannot enforce per-instance control reports `None` and refuses `allow_egress: true`. | WSL2 reports `Blocked`, refuses true at `src/wsl2.rs:97-111,138-143`, and runs the payload under `unshare -rn` at `agent/kiwi-agent.sh:74-82`. | Aligned. |
| C-19 | Egress evidence includes enforcement, inside/outside probes, DNS, and attempts. | Agent fields are emitted at `agent/kiwi-agent.sh:190-195`; public mapping is at `src/wsl2.rs:609-619,654-661`. | Drift: SBX-6 and SBX-7. Empty attempts are expected on a dropped-netns tier. |
| C-20 | `report.json` includes `limits_applied`, `payload_error`, outside-workdir count, process/FS/network data, tails, and notes. | Agent writes the fields at `agent/kiwi-agent.sh:172-200`; host parse/merge is at `src/wsl2.rs:556-685`. | Drift: SBX-3 and SBX-4; output escaping is T256-O4. |
| C-21 | All report fields are bounded and hostile guest output cannot exhaust host memory. | Raw guest capture is capped at `MAX_GUEST_OUT` (`src/wsl2.rs:725-766`); fields are truncated at `src/wsl2.rs:621-685`; constants are at `src/lib.rs:30-36`. | Mostly aligned; SBX-1 exceeds the documented 4096 fs-change cap. |
| C-22 | Artifact enters read-only; guest-writable host mappings are forbidden. | Artifact is piped and mode set to `0444` at `src/wsl2.rs:201-210`; no host path is mounted by the provider. | Initial copy is read-only, but the payload runs as root (`src/wsl2.rs:697-706`), so mode bits are not an immutability guarantee; see T256-O2. |
| C-23 | No host credentials, keys, or mailbox data are visible in the guest. | The only protection visible in the crate is the prepared-rootfs comment at `src/wsl2.rs:53-56`; the test bakes `automount=false` and `interop=false` at `src/wsl2.rs:1027-1032`. | Conditional: the provider does not inspect/verify a supplied rootfs. See T256-O2. |
| C-24 | Instances are single-analysis and `revert` is a fresh base state. | Unique per-run name/import and re-import are at `src/wsl2.rs:170-199,491-516`. | Aligned by design; the type does not enforce a one-analyze state transition. |
| C-25 | Timeout/teardown failures must not leave a live instance or fail open. | Guest exec kills its child; WSL management timeout at `src/wsl2.rs:809-815` returns without killing the child. | T256-O1: management command cleanup is incomplete on timeout. |
| C-26 | Callers check availability first, surface `Unavailable`, and never execute elsewhere. | No `kiwi-sandbox` dependency, sandbox module, command, or provider call exists in the current Tauri tree; `kiwi-app/src-tauri/Cargo.toml:16-20` and `src/lib.rs:66-155` show the current dependency/handler catalogs. | Caller obligation is not implemented; see T256-O3. |
| C-27 | Callers always teardown or rely on Drop. | The library has Drop, but there is no application/orchestration caller to exercise the obligation. | Library backstop exists; consumer wiring is absent. |
| C-28 | Reports are evidence, not a verdict. | The crate documents evidence-only semantics at `src/lib.rs:151-152`; no Tauri consumer maps a report to a verdict. | Contract/library wording aligned; consumer handling is not implemented. |
| C-29 | `kiwi-forensics` is a named consumer of the sandbox evidence. | `kiwi-forensics/Cargo.toml:14-23` has no sandbox dependency, and repository search found no `AnalysisReport`/`SandboxProvider` consumer outside `kiwi-sandbox`. | Consumer seam is not wired; this is a product/Lead scope decision, not a provider type mismatch. |
| C-30 | Hostile inputs may be attachments, documents, or links. | The contract models only a copied `artifact_path`; no URL/link type, fetch policy, or link-analysis method is defined. | Not specified by the contract; decide whether links are a separate contract/version. |
| C-31 | Normal attachment download is distinct from active analysis. | `kiwi_download_attachment` writes a user-selected decoded attachment to a host path at `kiwi-app/src-tauri/src/commands/message/attachment.rs:20-31,77-108`; it does not invoke the sandbox. | Aligned boundary: this is a save operation, not an active-analysis execution path. |
| C-32 | Availability/lifecycle/report behavior has regression coverage. | Unit tests cover NullProvider, bad specs, UTF-16 management output, and a gated real WSL lifecycle at `src/wsl2.rs:892-1133`; the live test verifies marker removal and egress evidence. | Good lifecycle coverage; no test covers SBX-3..7, management timeout, or unverified mount policy. |

## Canonical SBX findings revalidated

| ID | Contract promise | Current behavior and evidence | Severity | Disposition |
|---|---|---|---|---|
| **SBX-1** | Invariant 5 caps counts at 4096 entries each. | Guest merge accepts `MAX_REPORT_ENTRIES * 3` = 12,288 fs changes at `src/wsl2.rs:638-640`; fallback takes 4096 per kind and marks totals over 12,288 at `:352-377`; contract bound is `docs/contracts/sandbox.md:159-160`. | M | **Code-fix:** cap the merged `fs_changes` vector to 4096 overall, or amend the contract to explicitly authorize three 4096-entry subcaps. The current wording is one shared bound. |
| **SBX-2** | `ImageMissing` means the base image is not provisioned. | Variant exists at `src/error.rs:10-12`; missing rootfs is converted to `Availability::Unavailable` at `src/wsl2.rs:120-128`, and no source construction was found. | M | **Code-fix:** return `ImageMissing` when `rootfs` is absent, or remove the variant and amend the contract/error mapping. |
| **SBX-3** | Guest `report.json.limits_applied` is documented and emitted. | Agent emits it at `kiwi-sandbox/agent/kiwi-agent.sh:178`; `GuestReport` has no field at `src/wsl2.rs:561-582`, so serde drops it. | L | **Code-fix:** parse and expose the accepted-limit map, or explicitly define that it is guest-only diagnostics and remove it from the normative host report. |
| **SBX-4** | `writes_outside_workdir` counts all fs changes outside `/kiwi-work`. | Agent counts only created/modified lines at `agent/kiwi-agent.sh:169`; host merge ignores the guest count and recalculates over accepted changes, including deleted paths, at `src/wsl2.rs:638-647`. | L | **Code-fix:** define one canonical set and count it identically; include deleted files if the contract's “fs changes” wording includes them, or narrow the field. |
| **SBX-5** | `processes[].args` is `Vec<String>`. | Agent emits one whitespace-joined JSON string at `agent/kiwi-agent.sh:157`; host expects a string and splits it at `src/wsl2.rs:592-594,630-635`. A conforming array would fail guest report parsing. | L | **Code-fix:** emit a JSON array and deserialize `Vec<String>` with an explicit backward-compatible reader for legacy strings. |
| **SBX-6** | `network.attempts_observed` is part of the guest report and maps to egress evidence. | Agent writes `attempts_observed: []` at `agent/kiwi-agent.sh:195`; `GuestNet` has no attempts field at `src/wsl2.rs:609-619`; `merge_into` hardcodes `attempts: Vec::new()` at `:654-661`. | L | **Code-fix:** parse the documented field and preserve it where a provider supports attempts. Empty remains correct for the current dropped-netns tier. |
| **SBX-7** | Inside-netns probe uses the documented result vocabulary, with `unreachable` as the pass value. | Agent can emit `reachable` or `untested` at `agent/kiwi-agent.sh:59-65`; provider stores the string without validation at `src/wsl2.rs:654-660`; the live test accepts `unreachable` or `untested` at `src/wsl2.rs:1088-1094`. | L | **Code/contract decision:** document `reachable` as a failed probe and `untested` as missing evidence, or make the schema a closed enum and map unexpected values to incomplete. |
| **SBX-I** | The public/report surface is defined by the contract. | Agent adds `agent: "shell-busybox"` at `agent/kiwi-agent.sh:172-175`; the crate exposes public limits, `Availability` helpers, `Result`, providers/config, and report helpers not specified as contract wire fields (`src/lib.rs:20-36,78-89`; `src/wsl2.rs:53-85`). | I | **Contract-fix:** document the extra report field and public library surface, or mark them as internal/provider-extension APIs. |

## T-256 provisional observations

These are distinct from the canonical T-196 SBX rows and are not added to
`FINDINGS.md` by this read-only task. They should be assigned or rejected by
the sandbox/contract owners before being merged into the master register.

| ID | Observation | Evidence | Severity | Recommended resolution |
|---|---|---|---|---|
| **T256-O1** | `run_wsl` returns on a management-command timeout without killing the child. `exec_guest` does kill its child, but import/unregister/`wsl -t` can continue after the timeout and race cleanup. | `src/wsl2.rs:742-766` versus `src/wsl2.rs:809-815`; timeout map at `:813-815` has no `child.kill()`. | M | **Code-fix:** kill and await the management child on timeout, then make create/revert/teardown cleanup idempotent. Add a mocked/failing management-command test. |
| **T256-O2** | Read-only artifact and no-host-filesystem guarantees depend on an unverified prepared rootfs. `chmod 0444` is advisory for the root user running the payload, and the provider accepts any existing rootfs without checking `automount`/`interop` or mount contents. | Artifact mode is set at `src/wsl2.rs:201-210`; payload runs as root at `src/wsl2.rs:697-706`; rootfs policy is only a config comment at `:53-56`; the test bakes the policy at `:1027-1032`. | M | **Code-fix or explicit contract precondition:** validate/hash-pin the base image and enforce a non-root/read-only artifact mechanism, or make the prepared-image guarantee a checked provider precondition with a fail-closed probe. |
| **T256-O3** | The contract's app IPC, Lead orchestration, and forensics caller obligations are not implemented. There is no `kiwi-sandbox` dependency, sandbox command module, provider initialization, availability UI state, report handoff, or teardown call in the current Tauri tree. | `kiwi-app/src-tauri/Cargo.toml:16-20`; command module list `kiwi-app/src-tauri/src/commands/mod.rs:13-26`; handler catalog `kiwi-app/src-tauri/src/lib.rs:66-155`; `kiwi-forensics/Cargo.toml:14-23`; repository search found no provider/report consumer. | M | **Lead scope decision:** either queue the app/forensics wiring as a code task with IPC/error/UI contract coverage, or narrow the sandbox contract's consumer list until that seam exists. Do not add a host fallback. |
| **T256-O4** | The agent's JSON escaping is incomplete for control characters. Output, process, filesystem, and note emitters escape CR, backslash, and quotes, but not all JSON-forbidden controls such as tab; a hostile payload can make `report.json` unparseable and force `incomplete`. | `agent/kiwi-agent.sh:121-125,127-140,143-164`; host parse failure path is `src/wsl2.rs:447-455`. | M | **Code-fix:** use a JSON encoder or escape every U+0000–U+001F control character in all string emitters; add control-character regression fixtures. |
| **T256-O5** | The WSL2 module header still says no guest agent and that process/network monitors are false, while the current code embeds and runs the agent and advertises both monitors true. | `src/wsl2.rs:14-19` conflicts with `src/wsl2.rs:49-51,103-111,396-405`. | I | **Contract-fix/code-comment cleanup:** update stale module documentation so capability readers do not infer the pre-T-168 behavior. |
| **T256-O6** | The contract does not define how a link/URL becomes an artifact, fetches it, bounds remote content, or records source metadata; only `artifact_path` bytes are modeled. | Contract types at `docs/contracts/sandbox.md:34-39` and trait at `:82-87`; sandbox design mentions links at `docs/sandbox.md:9-10`; no link command/type exists. | I | **Product/contract decision:** define a separate link-analysis contract or explicitly state that links are out of scope for v1.1. |

## Recommended disposition

1. Resolve SBX-1 and SBX-2 first: they are small, objective mismatches in the
   canonical register and affect bounded evidence and caller error handling.
2. Resolve SBX-3 through SBX-7 as one report-schema compatibility change,
   preserving the current dropped-netns behavior rather than weakening it.
3. Assign T256-O1 and T256-O2 to the sandbox owner before declaring the WSL2
   provider production-safe. Both concern lifecycle/isolation cleanup, not just
   documentation.
4. Have the Lead decide whether T256-O3 is an intentionally future consumer
   seam or a queued implementation task. Until then, report the sandbox as a
   library provider only; do not claim active app analysis is available.
5. Keep the WSL2 shared-kernel caveat explicit and keep `allow_egress: true`
   refused. Do not describe the interim tier as a dedicated-kernel VM.
6. Add focused tests for the report-schema cases, control-character escaping,
   management-command timeout cleanup, and base-image policy validation before
   changing the corresponding findings to fixed.

## Scope boundary

This is a read-only contract/implementation audit. It does not modify
`docs/contracts/sandbox.md`, `kiwi-sandbox`, Tauri commands, the T-252 master
register, or any concurrent Agent 18/19/20/21 work. The existing
`docs/audits/contract-drift-1.md` SBX rows remain the canonical source rows;
T256-O1..O6 are provisional observations for owner review.
