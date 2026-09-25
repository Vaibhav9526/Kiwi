//! Wsl2Provider — the interim sandbox tier that works on this host today
//! (design doc §2 Tier B): a dedicated, disposable WSL2 distro per
//! analysis. Real hypervisor boundary vs the host, with the documented
//! shared-kernel caveat (`dedicated_kernel: false`).
//!
//! Lifecycle (mirrors `tests/infra/sandbox-wsl-poc.ps1`):
//!   create  — `wsl --import` a pristine rootfs tar into a uniquely-named
//!             instance; artifact piped in read-only via `wsl -e`
//!   analyze — FS baseline → bounded payload run inside `unshare -rn`
//!             (netns drop — egress stays blocked, fail-closed) → FS diff
//!   revert  — `wsl --unregister` + re-import the pristine rootfs
//!   teardown— `wsl --unregister` (VHDX destroyed) + workdir removal
//!
//! Honest capability report: no per-distro net toggle exists on WSL2, so
//! `allow_egress: true` is refused outright (invariant 6) and
//! `egress_control` reports `Blocked` (we never run a payload outside the
//! netns drop). Process/network monitors are false — no guest agent yet;
//! FS monitoring is real (before/after file-list diff + sha256 of created
//! files).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::{
    AnalysisReport, Availability, DEFAULT_MAX_ARTIFACT_BYTES, EgressControl, EgressEvidence,
    FsChange, FsChangeKind, MAX_FINDINGS, MAX_REPORT_ENTRIES, MAX_STDOUT_TAIL, Monitors, ProcEvent,
    Result, Sandbox, SandboxCapabilities, SandboxError, SandboxProvider, SandboxSpec,
};

const IMPORT_TIMEOUT: Duration = Duration::from_secs(180);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Slack over spec.timeout_secs for the host-side watchdog.
const EXEC_SLACK: Duration = Duration::from_secs(15);
const MAX_SPEC_TIMEOUT_SECS: u64 = 600;
/// Cap on sha256 hashing work per report.
const MAX_HASHED_FILES: usize = 256;
/// Bound on captured wsl.exe management output (UTF-16 console text).
const MAX_WSL_OUT: usize = 64 * 1024;
/// Bound on guest command output collected into the report.
const MAX_GUEST_OUT: usize = MAX_STDOUT_TAIL + MAX_FINDINGS;

static INSTANCE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Guest agent (kiwi.sandbox.report/1) — copied into the distro at
/// analyze-time, never baked into the base image.
const AGENT_SH: &str = include_str!("../agent/kiwi-agent.sh");

pub struct Wsl2Config {
    /// Pristine base rootfs tarball — built once by CI/admin tooling
    /// (docker export + baked `etc/wsl.conf`: automount off, interop off).
    /// Never mutated; every create/revert imports a fresh copy.
    pub rootfs: PathBuf,
    /// Scratch dir for per-instance VHDX storage; removed at teardown.
    pub work_dir: PathBuf,
    /// Distro name prefix (`[A-Za-z0-9_-]` only); a unique suffix is
    /// appended per instance.
    pub name_prefix: String,
    pub max_artifact_bytes: u64,
}

impl Default for Wsl2Config {
    fn default() -> Self {
        Self {
            rootfs: PathBuf::new(),
            work_dir: std::env::temp_dir().join("kiwi-sandbox"),
            name_prefix: "kiwi-sbx".into(),
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
        }
    }
}

pub struct Wsl2Provider {
    config: Wsl2Config,
    caps: SandboxCapabilities,
    /// Probed once, cached — contract requires cheap `availability()`.
    probe: std::sync::OnceLock<Availability>,
}

impl Wsl2Provider {
    pub fn new(config: Wsl2Config) -> Result<Self> {
        if config
            .name_prefix
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(SandboxError::Create(
                "name_prefix must be [A-Za-z0-9_-]".into(),
            ));
        }
        Ok(Self {
            caps: SandboxCapabilities {
                dedicated_kernel: false, // shared WSL2 utility-VM kernel
                snapshot_revert: true,
                // Egress is enforced by an in-guest netns drop
                // (`unshare -rn`) and analyze fails closed without it —
                // per-instance control is real, monitoring is not.
                egress_control: EgressControl::Blocked,
                monitors: Monitors {
                    // Guest agent: polled ps snapshots (short-lived procs
                    // can evade — honest limit, noted in contract).
                    process: true,
                    fs: true,
                    // Egress is enforced + probe-verified; there is no
                    // per-packet logging on this tier.
                    network: true,
                },
                max_artifact_bytes: config.max_artifact_bytes,
            },
            config,
            probe: std::sync::OnceLock::new(),
        })
    }

    fn probe_once(&self) -> Availability {
        if !self.config.rootfs.is_file() {
            return Availability::Unavailable(format!(
                "base rootfs missing at {}",
                self.config.rootfs.display()
            ));
        }
        match probe_wsl() {
            Ok(()) => Availability::Available(self.caps.clone()),
            Err(reason) => Availability::Unavailable(reason),
        }
    }
}

impl Wsl2Provider {
    /// Create a live instance — the concrete return lets callers/tests
    /// inspect the distro name; the trait impl boxes it.
    async fn create_instance(&self, spec: SandboxSpec) -> Result<Wsl2Sandbox> {
        // Spec validation first — deterministic regardless of host state.
        if spec.link_url.is_some() {
            return Err(SandboxError::Unavailable(
                "WSL2 tier blocks egress and cannot open links".into(),
            ));
        }
        if spec.allow_egress {
            return Err(SandboxError::Create(
                "allow_egress refused: WSL2 tier has no per-instance egress \
                 monitoring (egress_control=Blocked, invariant 6)"
                    .into(),
            ));
        }
        if spec.timeout_secs == 0 || spec.timeout_secs > MAX_SPEC_TIMEOUT_SECS {
            return Err(SandboxError::Create(format!(
                "timeout_secs must be 1..={MAX_SPEC_TIMEOUT_SECS}"
            )));
        }
        let meta = std::fs::metadata(&spec.artifact_path).map_err(|_| {
            SandboxError::Create(format!(
                "artifact not found: {}",
                spec.artifact_path.display()
            ))
        })?;
        if !meta.is_file() {
            return Err(SandboxError::Create("artifact is not a file".into()));
        }
        if meta.len() > self.config.max_artifact_bytes {
            return Err(SandboxError::Create(format!(
                "artifact {} bytes exceeds cap {}",
                meta.len(),
                self.config.max_artifact_bytes
            )));
        }
        if let Availability::Unavailable(reason) = self.availability() {
            return Err(SandboxError::Unavailable(reason));
        }

        let seq = INSTANCE_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("{}-{}-{}", self.config.name_prefix, std::process::id(), seq);
        let vhdx_dir = self.config.work_dir.join(&name);
        std::fs::create_dir_all(&vhdx_dir)?;

        // CREATE — import the pristine rootfs as a uniquely-named instance.
        if let Err(e) = run_wsl(
            &[
                "--import",
                &name,
                &vhdx_dir.to_string_lossy(),
                &self.config.rootfs.to_string_lossy(),
            ],
            None,
            IMPORT_TIMEOUT,
            MAX_WSL_OUT,
        )
        .await
        {
            let _ = std::fs::remove_dir_all(&vhdx_dir);
            return Err(SandboxError::Create(format!("wsl --import: {e}")));
        }

        let sbx = Wsl2Sandbox {
            name,
            vhdx_dir,
            rootfs: self.config.rootfs.clone(),
            spec,
            alive: true,
        };

        // Copy the artifact in read-only via `wsl -e` stdin — nothing
        // host-side is mounted into the guest (invariant 1), this is a
        // one-way byte pipe.
        let bytes = std::fs::read(&sbx.spec.artifact_path)?;
        if let Err(e) = sbx
            .exec(
                "cat > /kiwi-artifact && chmod 0444 /kiwi-artifact",
                Some(bytes),
                Duration::from_secs(60),
            )
            .await
        {
            // Never leave a registered instance behind on a failed create.
            let _ = run_wsl(
                &["--unregister", &sbx.name],
                None,
                PROBE_TIMEOUT,
                MAX_WSL_OUT,
            )
            .await;
            let _ = std::fs::remove_dir_all(&sbx.vhdx_dir);
            return Err(SandboxError::Create(format!("artifact copy-in: {e}")));
        }

        Ok(sbx)
    }
}

#[async_trait::async_trait]
impl SandboxProvider for Wsl2Provider {
    fn availability(&self) -> Availability {
        self.probe.get_or_init(|| self.probe_once()).clone()
    }

    async fn create(&self, spec: SandboxSpec) -> Result<Box<dyn Sandbox>> {
        Ok(Box::new(self.create_instance(spec).await?))
    }
}

/// One live WSL2 instance. Single-analysis; `revert` restores base state.
struct Wsl2Sandbox {
    name: String,
    vhdx_dir: PathBuf,
    rootfs: PathBuf,
    spec: SandboxSpec,
    alive: bool,
}

impl Wsl2Sandbox {
    /// Run a guest command via `wsl -d <name> -e sh -c`, bounded output.
    async fn exec(
        &self,
        script: &str,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<GuestRun> {
        exec_guest(&self.name, script, stdin, timeout).await
    }

    /// Sorted full file list — the FS-diff baseline (busybox `find`; no
    /// `-printf` dependency).
    async fn guest_file_list(&self) -> Result<BTreeSet<String>> {
        let run = self
            .exec(
                "find / -xdev -type f 2>/dev/null | sort",
                None,
                Duration::from_secs(60),
            )
            .await?;
        Ok(run
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Files touched after `/tmp/.kiwi-t0` (mtime diff marker).
    async fn guest_newer_list(&self) -> Result<BTreeSet<String>> {
        let run = self
            .exec(
                "find / -xdev -type f -newer /tmp/.kiwi-t0 2>/dev/null | sort",
                None,
                Duration::from_secs(60),
            )
            .await?;
        Ok(run
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// sha256 of each created path, batched through guest `sha256sum`.
    async fn guest_hashes(&self, paths: &[String]) -> Result<Vec<(String, String)>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let run = self
            .exec(
                "xargs sha256sum 2>/dev/null",
                Some(paths.join("\n").into_bytes()),
                Duration::from_secs(120),
            )
            .await?;
        Ok(run
            .stdout
            .lines()
            .filter_map(|l| l.split_once("  "))
            .map(|(hash, path)| (path.trim().to_string(), hash.trim().to_string()))
            .collect())
    }

    /// Host-side FS-diff fallback — used when the guest agent produced no
    /// report (push failure, crash). Same evidence, computed host-side.
    async fn fallback_fs_diff(&self, baseline: &BTreeSet<String>, report: &mut AnalysisReport) {
        let Ok(after) = self.guest_file_list().await else {
            report.incomplete = true;
            return;
        };
        let newer = self.guest_newer_list().await.unwrap_or_default();
        let harness = |p: &String| {
            p == "/kiwi-artifact" || p == "/tmp/.kiwi-t0" || p.starts_with("/kiwi-out/")
        };
        let created: Vec<String> = after
            .difference(baseline)
            .filter(|p| !harness(p))
            .cloned()
            .collect();
        let deleted: Vec<String> = baseline
            .difference(&after)
            .filter(|p| !harness(p))
            .cloned()
            .collect();
        let modified: Vec<String> = newer
            .intersection(baseline)
            .filter(|p| !harness(p) && after.contains(*p))
            .cloned()
            .collect();

        let hashable: Vec<String> = created.iter().take(MAX_HASHED_FILES).cloned().collect();
        let hashes: std::collections::HashMap<String, String> = self
            .guest_hashes(&hashable)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

        for p in created.iter().take(MAX_REPORT_ENTRIES) {
            report.fs_changes.push(FsChange {
                path: p.clone(),
                kind: FsChangeKind::Created,
                sha256: hashes.get(p).cloned(),
            });
        }
        for p in modified.iter().take(MAX_REPORT_ENTRIES) {
            report.fs_changes.push(FsChange {
                path: p.clone(),
                kind: FsChangeKind::Modified,
                sha256: None,
            });
        }
        for p in deleted.iter().take(MAX_REPORT_ENTRIES) {
            report.fs_changes.push(FsChange {
                path: p.clone(),
                kind: FsChangeKind::Deleted,
                sha256: None,
            });
        }
        if created.len() > MAX_HASHED_FILES
            || created.len() + modified.len() + deleted.len() > 3 * MAX_REPORT_ENTRIES
        {
            report.incomplete = true;
        }
    }
}

#[async_trait::async_trait]
impl Sandbox for Wsl2Sandbox {
    async fn analyze(&mut self) -> Result<AnalysisReport> {
        if !self.alive {
            return Err(SandboxError::Create("instance not alive".into()));
        }
        let mut report = AnalysisReport {
            evidence_reasons: self.spec.evidence_reasons.clone(),
            ..AnalysisReport::default()
        };

        // Host-side FS baseline — fallback evidence if the agent never
        // produces a report (agent push failure, guest crash mid-run).
        let baseline = self.guest_file_list().await.unwrap_or_default();
        let _ = self
            .exec("touch /tmp/.kiwi-t0", None, Duration::from_secs(30))
            .await;

        // Install the guest agent at analyze-time (single-use instance —
        // the script is copied in, never baked into the base image).
        let agent = AGENT_SH.replace("\r\n", "\n");
        self.exec(
            "cat > /kiwi-agent.sh && chmod 0500 /kiwi-agent.sh",
            Some(agent.into_bytes()),
            Duration::from_secs(60),
        )
        .await
        .map_err(|e| SandboxError::GuestError(format!("agent install: {e}")))?;

        // Run the agent: guest-side `timeout` inside the agent + host
        // watchdog here. The agent fails closed if `unshare` is missing —
        // the payload then never executes (invariant 6).
        let run = self
            .exec(
                &format!(
                    "sh /kiwi-agent.sh /kiwi-artifact /kiwi-out {} {}",
                    self.spec.timeout_secs, self.spec.max_memory_mb
                ),
                None,
                Duration::from_secs(self.spec.timeout_secs) + EXEC_SLACK,
            )
            .await;

        let mut host_timed_out = false;
        let mut run_ok: Option<GuestRun> = None;
        match run {
            Ok(r) => run_ok = Some(r),
            Err(SandboxError::GuestError(e)) if e.contains("timed out") => {
                // Host watchdog fired — terminate the whole instance so the
                // payload cannot outlive the report.
                let _ = run_wsl(&["-t", &self.name], None, PROBE_TIMEOUT, MAX_WSL_OUT).await;
                host_timed_out = true;
            }
            Err(e) => {
                report.incomplete = true;
                report.findings_raw = truncate_str(&format!("agent run failed: {e}"), MAX_FINDINGS);
            }
        }

        // Read the structured report back over the exec channel BEFORE
        // teardown — `/kiwi-out` is the exchange dir (guest-side only;
        // nothing guest-writable maps to the host FS, invariant 1).
        if let Some(raw) = self
            .exec("cat /kiwi-out/report.json", None, Duration::from_secs(30))
            .await
            .ok()
            .map(|r| r.stdout)
            .filter(|s| !s.is_empty())
        {
            match serde_json::from_str::<GuestReport>(&raw) {
                Ok(g) => g.merge_into(&mut report),
                Err(_) => {
                    report.incomplete = true;
                    report.findings_raw = truncate_str(
                        &format!("guest report unparseable: {}", tail_str(&raw, 4096)),
                        MAX_FINDINGS,
                    );
                }
            }
        } else {
            report.incomplete = true;
        }

        // Host-observed facts override the guest self-report.
        if host_timed_out {
            report.timed_out = true;
            report.incomplete = true;
        }
        if let Some(r) = &run_ok
            && r.truncated
        {
            report.incomplete = true;
        }
        if report.findings_raw.is_empty() {
            report.findings_raw = truncate_str(
                &format!(
                    "guest_report={} fs_changes={} processes={} egress={:?}",
                    report.egress.is_some(),
                    report.fs_changes.len(),
                    report.processes.len(),
                    report.egress.as_ref().map(|e| e.enforced.as_str())
                ),
                MAX_FINDINGS,
            );
        }

        // Fallback FS evidence when the agent produced none.
        if report.fs_changes.is_empty() && !baseline.is_empty() {
            self.fallback_fs_diff(&baseline, &mut report).await;
        }
        Ok(report)
    }

    /// Revert = destroy the instance and re-import the pristine rootfs.
    /// Idempotent — works whether or not the instance is alive.
    async fn revert(&mut self) -> Result<()> {
        let _ = run_wsl(
            &["--unregister", &self.name],
            None,
            PROBE_TIMEOUT,
            MAX_WSL_OUT,
        )
        .await;
        std::fs::create_dir_all(&self.vhdx_dir)?;
        run_wsl(
            &[
                "--import",
                &self.name,
                &self.vhdx_dir.to_string_lossy(),
                &self.rootfs.to_string_lossy(),
            ],
            None,
            IMPORT_TIMEOUT,
            MAX_WSL_OUT,
        )
        .await
        .map_err(|e| SandboxError::Create(format!("revert re-import: {e}")))?;
        self.alive = true;
        Ok(())
    }

    /// Destroy the instance + VHDX + workdir. Cannot fail open — every
    /// step is attempted regardless of earlier failures. `unregister`
    /// already removes the VHDX dir itself, so a missing dir is success.
    async fn teardown(mut self: Box<Self>) -> Result<()> {
        let r1 = run_wsl(
            &["--unregister", &self.name],
            None,
            PROBE_TIMEOUT,
            MAX_WSL_OUT,
        )
        .await;
        self.alive = false;
        let r2 = match std::fs::remove_dir_all(&self.vhdx_dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        match (r1, r2) {
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e.into()),
            _ => Ok(()),
        }
    }
}

impl Drop for Wsl2Sandbox {
    fn drop(&mut self) {
        if self.alive {
            // Backstop teardown — sync, best-effort (Drop cannot be async).
            let _ = std::process::Command::new("wsl")
                .args(["--unregister", &self.name])
                .output();
            let _ = std::fs::remove_dir_all(&self.vhdx_dir);
        }
    }
}

/// Guest agent report — `kiwi.sandbox.report/1` written to
/// `/kiwi-out/report.json`. Everything is `#[serde(default)]`: hostile or
/// truncated JSON must degrade, not panic. `merge_into` applies the
/// contract bounds (entry caps, string truncation) on the way in.
#[derive(Debug, serde::Deserialize)]
struct GuestReport {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    timed_out: bool,
    #[serde(default)]
    payload_error: Option<String>,
    #[serde(default)]
    processes: Vec<GuestProc>,
    #[serde(default)]
    fs_changes: Vec<GuestFs>,
    #[serde(default)]
    network: Option<GuestNet>,
    #[serde(default)]
    stdout_tail: Option<String>,
    #[serde(default)]
    stderr_tail: Option<String>,
    #[serde(default)]
    agent_notes: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GuestProc {
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    ppid: u32,
    #[serde(default)]
    exe: String,
    /// Guest emits a single whitespace-joined args string; split on read.
    #[serde(default)]
    args: String,
}

#[derive(Debug, serde::Deserialize)]
struct GuestFs {
    #[serde(default)]
    path: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    outside_workdir: Option<bool>,
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GuestNet {
    #[serde(default)]
    enforced: String,
    #[serde(default)]
    probe_inside_netns: String,
    #[serde(default)]
    probe_outside_netns: String,
    #[serde(default)]
    dns: String,
}

impl GuestReport {
    fn merge_into(self, report: &mut AnalysisReport) {
        report.exit_code = self.exit_code;
        report.timed_out = self.timed_out;
        for p in self.processes.iter().take(MAX_REPORT_ENTRIES) {
            report.processes.push(ProcEvent {
                pid: p.pid,
                ppid: p.ppid,
                exe: truncate_str(&p.exe, 1024),
                args: p
                    .args
                    .split_whitespace()
                    .take(64)
                    .map(|a| truncate_str(a, 1024))
                    .collect(),
            });
        }
        let mut outside = 0usize;
        for f in self.fs_changes.iter().take(MAX_REPORT_ENTRIES * 3) {
            let kind = match f.kind.as_str() {
                "created" => FsChangeKind::Created,
                "modified" => FsChangeKind::Modified,
                _ => FsChangeKind::Deleted,
            };
            if f.outside_workdir.unwrap_or(false) {
                outside += 1;
            }
            report.fs_changes.push(FsChange {
                path: truncate_str(&f.path, 4096),
                kind,
                sha256: f.sha256.as_deref().map(|s| truncate_str(s, 128)),
            });
        }
        if let Some(net) = self.network {
            report.egress = Some(EgressEvidence {
                enforced: truncate_str(&net.enforced, 64),
                probe_inside_netns: truncate_str(&net.probe_inside_netns, 64),
                probe_outside_netns: truncate_str(&net.probe_outside_netns, 64),
                dns: truncate_str(&net.dns, 64),
                attempts: Vec::new(),
            });
        }
        if let Some(t) = self.stdout_tail {
            report.stdout_tail = tail_str(&t, MAX_STDOUT_TAIL);
        }
        let notes: Vec<String> = self
            .agent_notes
            .iter()
            .take(64)
            .map(|n| truncate_str(n, 256))
            .collect();
        report.findings_raw = truncate_str(
            &format!(
                "schema={} payload_error={:?} outside_workdir_writes={} stderr_tail={} notes={:?}",
                self.schema.as_deref().unwrap_or("unknown"),
                self.payload_error.as_deref().map(|s| truncate_str(s, 512)),
                outside,
                tail_str(&self.stderr_tail.unwrap_or_default(), 4096),
                notes
            ),
            MAX_FINDINGS,
        );
        if self.payload_error.is_some() {
            report.incomplete = true;
        }
    }
}

/// One bounded guest-command run. stderr is still drained (a full pipe
/// would deadlock the guest) but only stdout is surfaced.
#[derive(Default)]
struct GuestRun {
    stdout: String,
    truncated: bool,
}

/// `wsl -d <name> -u root -e sh -c <script>` with bounded output + timeout.
/// Exit code propagates from the guest (wsl -e passes it through).
async fn exec_guest(
    name: &str,
    script: &str,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<GuestRun> {
    let mut cmd = Command::new("wsl");
    cmd.args(["-d", name, "-u", "root", "-e", "sh", "-c", script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Create(format!("wsl exec spawn: {e}")))?;

    if let Some(bytes) = stdin
        && let Some(mut s) = child.stdin.take()
    {
        use tokio::io::AsyncWriteExt;
        let _ = s.write_all(&bytes).await;
    }

    // Bounded capture: hostile output cannot exhaust host memory (inv. 5).
    // `take(cap)` stops reading past the cap — a payload that floods its
    // pipes blocks on write until the watchdog kills it, which is the
    // correct failure mode (bounded memory beats unbounded capture).
    let mut out = Vec::new();
    let mut err = Vec::new();
    let (mut so, mut se) = (child.stdout.take(), child.stderr.take());
    let read_out = async {
        if let Some(s) = &mut so {
            let _ = s.take(MAX_GUEST_OUT as u64).read_to_end(&mut out).await;
        }
    };
    let read_err = async {
        if let Some(s) = &mut se {
            let _ = s.take(MAX_GUEST_OUT as u64).read_to_end(&mut err).await;
        }
    };
    let wait = tokio::time::timeout(timeout, async {
        tokio::join!(read_out, read_err);
        child.wait().await
    });
    let mut truncated = false;
    let mut timed_out = false;
    match wait.await {
        Ok(Ok(_status)) => {}
        Ok(Err(e)) => return Err(SandboxError::Io(e)),
        Err(_) => {
            timed_out = true;
            let _ = child.kill().await;
        }
    }
    if out.len() >= MAX_GUEST_OUT || err.len() >= MAX_GUEST_OUT {
        truncated = true;
    }
    let stdout = String::from_utf8_lossy(&out).into_owned();
    if timed_out {
        return Err(SandboxError::GuestError(format!(
            "guest command timed out after {}s",
            timeout.as_secs()
        )));
    }
    Ok(GuestRun { stdout, truncated })
}

/// Run a `wsl.exe` management command (`--import`, `--unregister`, `-t`,
/// `--status`). Management output is UTF-16LE console text on Windows —
/// decode lossily for error messages; never logged to secrets.
async fn run_wsl(
    args: &[&str],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cap: usize,
) -> Result<()> {
    let mut cmd = Command::new("wsl");
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Unavailable(format!("wsl.exe spawn: {e}")))?;
    if let Some(bytes) = stdin
        && let Some(mut s) = child.stdin.take()
    {
        use tokio::io::AsyncWriteExt;
        let _ = s.write_all(&bytes).await;
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let (mut so, mut se) = (child.stdout.take(), child.stderr.take());
    let read_out = async {
        if let Some(s) = &mut so {
            let _ = s.take(cap as u64).read_to_end(&mut out).await;
        }
    };
    let read_err = async {
        if let Some(s) = &mut se {
            let _ = s.take(cap as u64).read_to_end(&mut err).await;
        }
    };
    let status = tokio::time::timeout(timeout, async {
        tokio::join!(read_out, read_err);
        child.wait().await
    })
    .await
    .map_err(|_| SandboxError::GuestError("wsl command timed out".into()))?
    .map_err(SandboxError::Io)?;
    if status.success() {
        return Ok(());
    }
    let detail = decode_wsl_text(&err)
        .or_else(|| decode_wsl_text(&out))
        .unwrap_or_default();
    Err(SandboxError::GuestError(format!(
        "wsl {} exited {}: {}",
        args.first().copied().unwrap_or(""),
        status.code().unwrap_or(-1),
        detail
    )))
}

/// `wsl --status` — a cheap liveness probe for the WSL2 subsystem.
fn probe_wsl() -> std::result::Result<(), String> {
    let out = std::process::Command::new("wsl")
        .arg("--status")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("wsl.exe not found: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let detail = decode_wsl_text(&out.stderr)
            .or_else(|| decode_wsl_text(&out.stdout))
            .unwrap_or_else(|| "unknown".into());
        Err(format!("wsl --status failed: {detail}"))
    }
}

/// wsl.exe management output is UTF-16LE; exec-channel output is UTF-8.
/// Try UTF-16 first when the buffer looks like it (NUL interleaved).
fn decode_wsl_text(bytes: &[u8]) -> Option<String> {
    let utf16ish = bytes.len() >= 4
        && bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count() > bytes.len() / 4;
    if utf16ish {
        let wide: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let s = String::from_utf16_lossy(&wide).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Keep the LAST `max` bytes (tail semantics for stdout).
fn tail_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Availability, SandboxProvider};

    fn tmp_rootfs() -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("kiwi-sbx-test-rootfs-{}.tar", std::process::id()));
        std::fs::write(&p, b"not-a-real-rootfs").unwrap();
        p
    }

    #[test]
    fn null_and_wsl_availability_are_honest() {
        // Missing rootfs → Unavailable with a reason, never a silent yes.
        let p = Wsl2Provider::new(Wsl2Config {
            rootfs: PathBuf::from("does-not-exist-anywhere.tar"),
            ..Default::default()
        })
        .unwrap();
        match p.availability() {
            Availability::Unavailable(r) => assert!(r.contains("rootfs")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_refuses_egress_and_bad_spec() {
        let artifact = tmp_rootfs();
        let p = Wsl2Provider::new(Wsl2Config {
            rootfs: artifact.clone(),
            ..Default::default()
        })
        .unwrap();
        // allow_egress must be refused even before availability probing —
        // the provider can never satisfy it (invariant 6).
        let err = p
            .create_instance(SandboxSpec {
                artifact_path: artifact.clone(),
                link_url: None,
                evidence_reasons: Vec::new(),
                timeout_secs: 30,
                max_memory_mb: 256,
                allow_egress: true,
            })
            .await
            .err()
            .expect("egress spec must be refused");
        assert!(matches!(err, SandboxError::Create(_)));

        // timeout bounds
        let err = p
            .create_instance(SandboxSpec {
                artifact_path: artifact.clone(),
                link_url: None,
                evidence_reasons: Vec::new(),
                timeout_secs: 0,
                max_memory_mb: 256,
                allow_egress: false,
            })
            .await
            .err()
            .expect("zero timeout must be refused");
        assert!(matches!(err, SandboxError::Create(_)));

        // missing artifact
        let err = p
            .create_instance(SandboxSpec {
                artifact_path: PathBuf::from("nope.bin"),
                link_url: None,
                evidence_reasons: Vec::new(),
                timeout_secs: 30,
                max_memory_mb: 256,
                allow_egress: false,
            })
            .await
            .err()
            .expect("missing artifact must be refused");
        assert!(matches!(err, SandboxError::Create(_)));
    }

    #[test]
    fn utf16_management_output_decodes() {
        let wide: Vec<u8> = "WSL ok"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_wsl_text(&wide).as_deref(), Some("WSL ok"));
        assert_eq!(
            decode_wsl_text(b"plain utf8").as_deref(),
            Some("plain utf8")
        );
        assert_eq!(decode_wsl_text(b""), None);
    }

    /// Full lifecycle against real WSL2 + Docker — gated: needs
    /// `KIWI_SANDBOX_WSL=1`, docker (busybox export for the base rootfs)
    /// and a working `wsl.exe`. Mirrors the proven PoC.
    #[tokio::test]
    async fn wsl2_full_lifecycle() {
        if std::env::var("KIWI_SANDBOX_WSL").ok().as_deref() != Some("1") {
            eprintln!("skipped: set KIWI_SANDBOX_WSL=1 to run the live lifecycle test");
            return;
        }
        let work = std::env::temp_dir().join(format!("kiwi-sbx-it-{}", std::process::id()));
        std::fs::create_dir_all(&work).unwrap();
        let rootfs = work.join("rootfs.tar");

        // Build the pristine base: docker export busybox + baked wsl.conf.
        for (args, what) in [
            (vec!["pull", "-q", "busybox:latest"], "docker pull"),
            (
                vec![
                    "create",
                    "--name",
                    "kiwi-sbx-it-src",
                    "busybox:latest",
                    "sh",
                    "-c",
                    "true",
                ],
                "docker create",
            ),
        ] {
            let st = std::process::Command::new("docker")
                .args(&args)
                .status()
                .unwrap();
            assert!(st.success(), "{what} failed");
        }
        let st = std::process::Command::new("docker")
            .args(["export", "kiwi-sbx-it-src", "-o"])
            .arg(&rootfs)
            .status()
            .unwrap();
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", "kiwi-sbx-it-src"])
            .status();
        assert!(st.success(), "docker export failed");
        assert!(rootfs.is_file());

        // Bake wsl.conf into the image (automount+interop off) via tar append.
        std::fs::create_dir_all(work.join("etc")).unwrap();
        std::fs::write(
            work.join("etc/wsl.conf"),
            "[automount]\nenabled=false\n\n[interop]\nenabled=false\n",
        )
        .unwrap();
        let st = std::process::Command::new("tar")
            .args(["-rf", "rootfs.tar", "etc/wsl.conf"])
            .current_dir(&work)
            .status()
            .unwrap();
        assert!(st.success(), "tar append failed");

        // Artifact: a script that writes a marker + prints evidence.
        let artifact = work.join("payload.sh");
        std::fs::write(&artifact, "echo PAYLOAD > /marker\necho 'sandbox-run-ok'\n").unwrap();

        let provider = Wsl2Provider::new(Wsl2Config {
            rootfs: rootfs.clone(),
            work_dir: work.join("vhdx"),
            name_prefix: "kiwisbxit".into(),
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
        })
        .unwrap();
        assert!(
            provider.availability().is_usable(),
            "expected Available, got {:?}",
            provider.availability()
        );

        let mut sbx = provider
            .create_instance(SandboxSpec {
                artifact_path: artifact,
                link_url: None,
                evidence_reasons: Vec::new(),
                timeout_secs: 60,
                max_memory_mb: 256,
                allow_egress: false,
            })
            .await
            .expect("create");

        let report = sbx.analyze().await.expect("analyze");
        assert!(
            report.stdout_tail.contains("sandbox-run-ok"),
            "stdout_tail: {:?}",
            report.stdout_tail
        );
        assert_eq!(report.exit_code, Some(0));
        assert!(
            report
                .fs_changes
                .iter()
                .any(|c| c.path == "/marker" && c.kind == FsChangeKind::Created),
            "marker creation must appear in fs_changes: {:?}",
            report.fs_changes
        );
        // Guest agent evidence (T-168): process tree + egress proof.
        assert!(
            !report.processes.is_empty(),
            "agent must capture ps snapshots"
        );
        let egress = report.egress.as_ref().expect("agent egress evidence");
        assert_eq!(egress.enforced, "netns-drop");
        assert!(
            egress.probe_inside_netns == "unreachable" || egress.probe_inside_netns == "untested",
            "probe_inside_netns: {}",
            egress.probe_inside_netns
        );
        assert!(!report.timed_out);

        // Revert → marker must be gone on the re-imported instance.
        sbx.revert().await.expect("revert");
        let check = exec_guest(
            &sbx.name,
            "test -f /marker && echo PRESENT || echo ABSENT",
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert!(
            check.stdout.contains("ABSENT"),
            "marker must not survive revert: {:?}",
            check.stdout
        );

        // Teardown → distro absent.
        let name = sbx.name.clone();
        Box::new(sbx).teardown().await.expect("teardown");
        let list = std::process::Command::new("wsl")
            .args(["--list", "--quiet"])
            .output()
            .unwrap();
        let names: Vec<String> = String::from_utf16_lossy(
            &list
                .stdout
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<u16>>(),
        )
        .split_whitespace()
        .map(str::to_string)
        .collect();
        assert!(!names.contains(&name), "{name} still registered");
    }
}
