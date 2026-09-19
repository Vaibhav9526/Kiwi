"""KIWI fixture catalog integrity checker (Agent 6).

Validates tests/fixtures/MANIFEST.json against the directory:
  - manifest is valid JSON with schema {version, fixtures[{path,suite,status,generation,expected_findings}]}
  - path naming convention per tests/fixtures/README.md
  - status 'present' files exist; every file on disk is indexed
  - no fixture file trips secret patterns (imports secret_scan)
  - size caps: single file <= 5MB, total <= 100MB

Usage:  python tests/tools/check_fixtures.py [--root .]
Exit 0 = ok, 1 = violations.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from secret_scan import PATTERNS  # noqa: E402

SUITES = {"pcap", "cert", "message"}
STATUSES = {"planned", "present"}
NAME_RX = {
    "pcap": re.compile(r"^pcap/(smtp|imap|pop3)_(plaintext|starttls|implicit-tls|stripped)_(notls|tls12|tls13)(_[a-z0-9-]+)?\.pcapng$"),
    "cert": re.compile(r"^certs/[a-z0-9-]+\.pem$"),
    "message": re.compile(r"^messages/[a-z0-9-]+\.eml$"),
}
SINGLE_CAP = 5 * 1024 * 1024
TOTAL_CAP = 100 * 1024 * 1024


def main() -> int:
    root = Path(sys.argv[sys.argv.index("--root") + 1]) if "--root" in sys.argv else Path(".")
    fx = root / "tests" / "fixtures"
    errors: list[str] = []
    try:
        manifest = json.loads((fx / "MANIFEST.json").read_text(encoding="utf-8"))
    except Exception as e:
        print(f"FAIL: cannot read MANIFEST.json: {e}")
        return 1
    entries = manifest.get("fixtures", [])
    indexed = set()
    total = 0
    for i, e in enumerate(entries):
        tag = f"fixtures[{i}]"
        for k in ("path", "suite", "status", "generation", "expected_findings"):
            if k not in e:
                errors.append(f"{tag}: missing key '{k}'")
        if e.get("suite") not in SUITES:
            errors.append(f"{tag}: bad suite {e.get('suite')!r}")
            continue
        if e.get("status") not in STATUSES:
            errors.append(f"{tag}: bad status {e.get('status')!r}")
        if not NAME_RX[e["suite"]].match(e.get("path", "")):
            errors.append(f"{tag}: path {e.get('path')!r} violates naming scheme")
        if e.get("path") in indexed:
            errors.append(f"{tag}: duplicate path {e['path']!r}")
        indexed.add(e.get("path"))
        p = fx / e.get("path", "")
        if e.get("status") == "present":
            if not p.is_file():
                errors.append(f"{tag}: status=present but missing {e['path']}")
            else:
                size = p.stat().st_size
                total += size
                if size > SINGLE_CAP:
                    errors.append(f"{tag}: {size} bytes exceeds 5MB cap")
                try:
                    text = p.read_text(encoding="utf-8", errors="strict")
                    for lineno, line in enumerate(text.splitlines(), 1):
                        for name, rx in PATTERNS.items():
                            if rx.search(line):
                                errors.append(f"{tag}: secret pattern {name} at {e['path']}:{lineno}")
                except Exception:
                    pass  # binary fixture — size-checked only
        else:
            if p.exists():
                errors.append(f"{tag}: status=planned but file exists — flip to present")
    on_disk = set()
    for sub in ("pcap", "certs", "messages"):
        d = fx / sub
        if d.is_dir():
            for p in d.iterdir():
                if p.is_file() and p.name != ".gitkeep":
                    on_disk.add(f"{sub}/{p.name}")
    for orphan in sorted(on_disk - indexed):
        errors.append(f"unindexed file on disk: {orphan}")
    if total > TOTAL_CAP:
        errors.append(f"total fixture size {total} exceeds 100MB cap")
    if errors:
        print(f"check_fixtures: FAIL ({len(errors)} problem(s))")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"check_fixtures: OK (entries={len(entries)} present_bytes={total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
