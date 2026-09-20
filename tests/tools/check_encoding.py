"""Mojibake / encoding gate (T-177).

Fails on double-encoded UTF-8 (the T-154 TASKS.md incident: an editor
round-tripped the file through windows-1252, turning every arrow/dash
into mojibake that committed cleanly because it is still valid UTF-8)
and on files that are not UTF-8 at all.

Stdlib only. Run from repo root: `python tests/tools/check_encoding.py`.
Exit 0 when clean, 1 with the offending paths otherwise.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Exact byte signatures of UTF-8 → cp1252 → UTF-8 double-encoding for the
# characters this repo actually uses (->, -, --, section sign). Bare U+00E2
# (U+00e2) alone is also flagged: it cannot appear in correct UTF-8 text
# except as the lead byte of a 3-byte sequence, and every legitimate use
# here (->, em/en dashes) is covered by the triple patterns below — a lone
# one is corruption residue.
MOJIBAKE = (
    b"\xc3\xa2\xe2\x80\xa0\xe2\x80\x99",  # ->  (U+2192)
    b"\xc3\xa2\xe2\x82\xac\xe2\x80\x9d",  # --  (U+2014)
    b"\xc3\xa2\xe2\x82\xac\xe2\x80\x9c",  # --  (U+2013)
    b"\xc3\x82\xc2\xa7",  # section (U+00A7)
)

TEXT_EXTENSIONS = {
    ".md", ".py", ".rs", ".ts", ".tsx", ".js", ".json", ".yml", ".yaml",
    ".toml", ".txt", ".html", ".css", ".ps1", ".sql", ".xml", ".example",
}

SKIP_DIRS = {
    ".git", "source", "node_modules", "target", "dist", "build",
    ".venv", "__pycache__", ".next", "coverage",
}

# Generated logs, not source: console-captured output in the writer's
# system encoding. Never gate on these.
SKIP_FILES = {
    "tools/watcher/watcher-cycle-log.md",
}


def iter_files():
    import os

    for dirpath, dirnames, filenames in os.walk(ROOT, topdown=True):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in SKIP_DIRS and not name.startswith(".")
            or name in (".github",)
        )
        # os.walk pruning above keeps .github (CI lives there) while
        # dropping .git and other dot-dirs.
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(ROOT).as_posix()
            if rel in SKIP_FILES:
                continue
            if path.suffix not in TEXT_EXTENSIONS and name != ".env.example":
                continue
            yield path


def main():
    bad = []
    count = 0
    for path in iter_files():
        count += 1
        try:
            raw = path.read_bytes()
        except OSError as exc:
            bad.append((path, "unreadable: %s" % exc))
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            bad.append((path, "not utf-8: %s" % exc))
            continue
        for signature in MOJIBAKE:
            if signature in raw:
                bad.append((path, "double-encoded utf-8 signature"))
                break
    if bad:
        print("check_encoding: FAIL")
        for path, reason in bad:
            print("  %s: %s" % (path.relative_to(ROOT), reason))
        return 1
    print("check_encoding: OK (files=%d)" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
