"""KIWI fallback secret scanner (Agent 6).

Used when gitleaks is not installed. Scans tracked text files for
high-signal secret patterns. Exit 0 = clean, 1 = hits found.
Usage:  python tests/tools/secret_scan.py [--root .]

Deliberately stdlib-only so it runs on a bare checkout.
"""
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "password_assignment": re.compile(r"(?i)(password|passwd|pwd|client_secret|api[_-]?key)\s*[:=]\s*['\"]?\S{4,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
}

# Files that are documentation/catalogs, not scannable secrets carriers,
# are still scanned — allowlist only covers synthetic markers.
ALLOW_MARKERS = re.compile(
    r"kiwi-test\.invalid|example\.invalid|STARTTLS-STRIPPED|FORWARD-SECRECY-FAIL|INPUT-MALFORMED"
)
SKIP_SUFFIXES = {".pcapng", ".pcap", ".exe", ".dll", ".png", ".ico", ".jpg", ".db", ".sqlite"}
SKIP_DIRS = {"source", "target", "node_modules", ".git", "obj-precise"}


def tracked_files(root: Path):
    try:
        # Tracked files PLUS untracked-but-not-ignored files: this repo is
        # early-stage and much work is not yet committed — a scanner that
        # only looks at `git ls-files` would silently scan nothing.
        seen: list[str] = []
        for args in (["git", "ls-files"], ["git", "ls-files", "--others", "--exclude-standard"]):
            out = subprocess.run(
                args, cwd=root, capture_output=True, text=True, check=True
            ).stdout.splitlines()
            seen.extend(p for p in out if p.strip())
        return [root / p for p in dict.fromkeys(seen) if p.strip()]
    except Exception:
        # Not a git checkout (or git missing): walk the tree instead.
        files = []
        for p in root.rglob("*"):
            if p.is_file() and not any(d in p.parts for d in SKIP_DIRS):
                files.append(p)
        return files


def main() -> int:
    root = Path(sys.argv[sys.argv.index("--root") + 1]) if "--root" in sys.argv else Path(".")
    hits = 0
    scanned = 0
    for f in tracked_files(root):
        if f.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="strict")
        except Exception:
            continue  # binary/unreadable — skipped, not failed
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            if ALLOW_MARKERS.search(line):
                continue
            for name, rx in PATTERNS.items():
                if rx.search(line):
                    print(f"HIT {name} {f}:{lineno}")
                    hits += 1
    print(f"secret_scan: scanned={scanned} hits={hits}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
