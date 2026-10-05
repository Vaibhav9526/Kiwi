"""T-249w standing fast-gate watcher.

Runs four read-only gates every ten minutes, reports only newly appearing
file-level failure episodes, and never modifies the files named by a failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAD_TERMINAL = "term_db8527c7-eb71-4274-b416-61c91143a6cf"
DEFAULT_INTERVAL = 600
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

GATES = (
    ("fmt", ("cargo", "fmt", "--check"), ROOT),
    ("tsc", (shutil.which("npx.cmd") or shutil.which("npx") or "npx", "tsc", "--noEmit"), ROOT / "kiwi-app"),
    ("overlap", (sys.executable, "tests/tools/copy_overlap.py"), ROOT),
    ("secrets", (sys.executable, "tests/tools/secret_scan.py"), ROOT),
)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_output(value: str) -> str:
    return ANSI_RE.sub("", value or "").replace("\r\n", "\n")


def normalize_path(value: str) -> str:
    value = value.strip().strip('"')
    if value.startswith("\\\\?\\"):
        value = value[4:]
    value = value.replace("\\", "/")
    try:
        if os.path.isabs(value):
            value = os.path.relpath(value, ROOT).replace("\\", "/")
    except ValueError:
        pass
    return value.lstrip("./")


def finding_key(gate: str, path: str) -> str:
    """Identity of one failure episode: gate + file, never diff line."""
    return json.dumps([gate, normalize_path(path)], separators=(",", ":"))


def location_from_line(gate: str, raw: str):
    line = clean_output(raw).strip()
    patterns = (
        r"^Diff in (.+?):(\d+):$",
        r"^(.+?)\((\d+),\d+\):\s+error\s+TS\d+:",
        r"^(?:A/\S+|B/substantive)\s+(.+?):(\d+):",
        r"^HIT\s+\S+\s+(.+?):(\d+):",
    )
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            path = normalize_path(match.group(1))
            if gate == "tsc" and not path.startswith("kiwi-app/"):
                path = f"kiwi-app/{path}"
            return path, int(match.group(2)), line
    return None


def execute_gate(gate: str, command: tuple[str, ...], cwd: Path, timeout: int):
    started = time.monotonic()
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "CARGO_TERM_COLOR": "never", "TERM": "dumb"})
    try:
        proc = subprocess.run(
            list(command), cwd=cwd, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
        combined = clean_output(proc.stdout) + "\n" + clean_output(proc.stderr)
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        combined = clean_output((exc.stdout or "") + "\n" + clean_output(exc.stderr or ""))
        combined += f"\nGATE_TIMEOUT after {timeout}s"
        code = 124
    except OSError as exc:
        combined = f"GATE_EXEC_ERROR: {exc}"
        code = 127

    elapsed = time.monotonic() - started
    print(f"[{now_utc()}] {gate}: exit={code} elapsed={elapsed:.1f}s", flush=True)
    if code == 0:
        return {}

    grouped: dict[str, dict[int, list[str]]] = {}
    for raw in combined.splitlines():
        parsed = location_from_line(gate, raw)
        if parsed:
            path, number, message = parsed
            grouped.setdefault(path, {}).setdefault(number, []).append(message)

    findings = {}
    if not grouped:
        first = next((x.strip() for x in reversed(combined.splitlines()) if x.strip()), "unknown failure")
        grouped[f"<{gate} gate>"] = {0: [first[:400]]}

    for path, lines in grouped.items():
        line_numbers = sorted(lines)
        details = " | ".join(
            f"{line}: {lines[line][0]}" for line in line_numbers
        )[:800]
        findings[finding_key(gate, path)] = {
            "gate": gate,
            "path": path,
            "lines": line_numbers,
            "message": f"{len(line_numbers)} failing line(s): {details}",
        }
    return findings


def ownership_patterns(clause: str) -> list[tuple[str, str, str]]:
    """Expand CURRENT-OWNERSHIP shorthand into scoped matcher patterns."""
    ignored = {"cmd", "cmds", "command", "commands", "file", "files"}
    patterns: list[tuple[str, str, str]] = []

    def add_part(part: str, scope: str = "") -> None:
        part = normalize_path(part).strip("/")
        if not part or part.lower() in ignored:
            return
        for token in part.split("/"):
            if token and token.lower() not in ignored:
                patterns.append(("part", token.lower(), normalize_path(scope)))

    for group in clause.split("+"):
        words = group.strip().split()
        if not words:
            continue
        comma_items = [item.strip().lower() for item in group.split(",") if item.strip()]
        if len(comma_items) > 1:
            first = normalize_path(comma_items[0]).rstrip("/")
            # views,chrome,shell,App and icons,themes,plugins are siblings
            # beneath the parent of their first, more-specific directory.
            scope = str(Path(first).parent).replace("\\", "/") if first.count("/") >= 2 else ""
            patterns.append(("dir", first, scope))
            for item in comma_items[1:]:
                add_part(item, scope)
            continue

        first = normalize_path(words[0]).rstrip("/")
        if len(words) == 1:
            if first.endswith("/"):
                patterns.append(("segment_dir", first.rstrip("/"), ""))
            elif first.endswith((".ts", ".tsx", ".rs", ".md")):
                add_part(first)
            elif "/" in first:
                patterns.append(("dir", first, ""))
            else:
                add_part(first)
            continue

        scope = first
        for descriptor in words[1:]:
            if descriptor.lower() in ignored:
                continue
            add_part(descriptor, scope)
    return patterns


def parse_current_ownership() -> list[dict]:
    tasks = ROOT / "docs" / "TASKS.md"
    entries = []
    try:
        lines = tasks.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return entries
    try:
        start = next(i for i, line in enumerate(lines) if "CURRENT-OWNERSHIP" in line)
    except StopIteration:
        return entries
    for raw in lines[start + 1:]:
        if "-->" in raw:
            break
        match = re.match(r"^\s*(.*?)\s*->\s*(.+?)\s*$", raw)
        if not match:
            continue
        entries.append({
            "patterns": ownership_patterns(match.group(1)),
            "owner": match.group(2).strip(),
        })
    return entries


def ownership_score(path: str, entry: dict) -> int:
    path = normalize_path(path)
    stem = Path(path).stem.lower()
    parts = [part.lower() for part in Path(path).parts]
    best = 0
    for kind, value, scope in entry["patterns"]:
        scope = normalize_path(scope).rstrip("/")
        if scope == "src-tauri":
            in_scope = "/src-tauri/" in f"/{path}"
        else:
            in_scope = not scope or path.startswith(scope + "/")
        if not in_scope:
            continue
        if kind == "dir" and (path == value or path.startswith(value + "/")):
            best = max(best, 1000 + len(value))
        elif kind == "segment_dir" and value in parts:
            best = max(best, 700 + len(value))
        elif kind == "part" and (
            stem == value or (len(value) >= 4 and value in stem) or value in parts
        ):
            best = max(best, 800 + len(value))
    return best


def likely_owner(path: str, ownership: list[dict]) -> str:
    matches = [
        (ownership_score(path, entry), entry["owner"])
        for entry in ownership
    ]
    matches = [(score, owner) for score, owner in matches if score]
    if not matches:
        return "owner not identifiable from TASKS.md CURRENT-OWNERSHIP"
    best = max(score for score, _ in matches)
    owners = []
    for _, owner in matches:
        if owner not in owners:
            owners.append(owner)
    return f"docs/TASKS.md CURRENT-OWNERSHIP {' / '.join(owners)}"


def send_lead(text: str) -> bool:
    orca = shutil.which("orca")
    if not orca:
        print(f"GATE-WATCH SEND FAILED: orca not found: {text}", flush=True)
        return False
    try:
        proc = subprocess.run(
            [orca, "terminal", "send", "--terminal", LEAD_TERMINAL, "--text", text, "--enter"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"GATE-WATCH SEND FAILED: {exc}: {text}", flush=True)
        return False
    if proc.returncode != 0:
        print(f"GATE-WATCH SEND FAILED ({proc.returncode}): {clean_output(proc.stderr)}: {text}", flush=True)
        return False
    print(f"GATE-WATCH SENT: {text}", flush=True)
    return True


def load_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}

    # Migrate v1 gate+file+line records into v2 gate+file episodes. This keeps
    # an already-reported in-flight file suppressed across the upgrade.
    raw = value.get("findings", {})
    episodes: dict[str, dict] = {}
    if isinstance(raw, dict):
        for finding in raw.values():
            if not isinstance(finding, dict) or not finding.get("gate") or not finding.get("path"):
                continue
            gate = str(finding["gate"])
            path = normalize_path(str(finding["path"]))
            key = finding_key(gate, path)
            lines = set(episodes.get(key, {}).get("lines", []))
            if isinstance(finding.get("lines"), list):
                lines.update(int(line) for line in finding["lines"] if str(line).isdigit())
            if isinstance(finding.get("line"), int):
                lines.add(finding["line"])
            episodes[key] = {
                "gate": gate, "path": path, "lines": sorted(lines),
                "message": str(finding.get("message", "migrated failure episode")),
            }
    value["findings"] = episodes
    value["version"] = 2
    return value


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


def run_once(state_path: Path, timeout: int, notify_ready: bool = True) -> dict:
    previous = load_state(state_path)
    prior_findings = previous.get("findings", {}) if isinstance(previous.get("findings", {}), dict) else {}
    first_run = int(previous.get("run_count", 0)) == 0
    current: dict[str, dict] = {}
    summaries = []

    for gate, command, cwd in GATES:
        findings = execute_gate(gate, command, cwd, timeout)
        current.update(findings)
        summaries.append(f"{gate}={'PASS' if not findings else 'FAIL'}")

    retained = {}
    ownership = parse_current_ownership()
    for key, finding in sorted(current.items()):
        old = prior_findings.get(key)
        changed = old is None
        if first_run:
            retained[key] = finding
            lines = ",".join(str(line) for line in finding["lines"])
            print(
                f"BASELINE FAILURE (suppressed): {finding['path']} "
                f"lines={lines} [{finding['gate']}]",
                flush=True,
            )
            continue
        if not changed:
            retained[key] = finding
            continue
        owner = likely_owner(finding["path"], ownership)
        lines = ",".join(str(line) for line in finding["lines"])
        text = (
            f"GATE-WATCH NEW: {finding['gate']} failure {finding['path']} "
            f"lines={lines} — {finding['message']} ({owner})"
        )
        if send_lead(text):
            retained[key] = finding

    state = {
        "version": 2, "run_count": int(previous.get("run_count", 0)) + 1,
        "last_run_utc": now_utc(), "last_summary": summaries,
        "findings": retained,
    }
    save_state(state_path, state)
    print(f"CYCLE {state['run_count']}: {' '.join(summaries)} baseline={first_run}", flush=True)

    if first_run and notify_ready:
        if current:
            failed_gates = [name for name, status in zip(
                [gate[0] for gate in GATES], summaries
            ) if not status.endswith("PASS")]
            passed = len(GATES) - len(failed_gates)
            ready = (
                f"DONE: Watcher T-249w gate-watch armed — baseline {passed}/{len(GATES)} gates pass; "
                f"suppressed {len(current)} existing {','.join(failed_gates)} file failure episode(s), "
                "no new-failure report sent"
            )
        else:
            ready = "DONE: Watcher T-249w gate-watch armed — baseline all-pass"
        send_lead(ready)
    return state


def main() -> int:
    default_state = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "KiwiMail" / "gate-watch"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="seconds between runs")
    parser.add_argument("--state-dir", type=Path, default=default_state)
    parser.add_argument("--timeout", type=int, default=300, help="per-gate timeout in seconds")
    parser.add_argument("--no-ready", action="store_true", help="suppress first-run ready notification")
    args = parser.parse_args()
    if args.interval < 60:
        parser.error("--interval must be at least 60 seconds")

    state_path = args.state_dir / "state.json"
    while True:
        try:
            run_once(state_path, args.timeout, notify_ready=not args.no_ready)
        except Exception as exc:  # keep the standing loop alive
            print(f"GATE-WATCH CYCLE ERROR: {type(exc).__name__}: {exc}", flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())

