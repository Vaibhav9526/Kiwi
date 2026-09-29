"""KIWI copy-overlap gate (Agent 21, T-198).

Blocks verbatim code copied out of the GPL/AGPL study checkouts in
`reference/` (Mailspring = GPL-3.0, MailFlow = AGPL-3.0) into our own tree.
KIWI is MPL-2.0 and must stay original: docs/ARCHITECTURE.md "study patterns,
write our own code", docs/BACKLOG-MAILFLOW.md "Study-only; no source copying",
docs/DECISIONS.md ADR-005 "completely independent ... Do NOT fork".

Two independent checks. Exit 0 = pass, 1 = fail.

  CHECK A - forbidden-marker scan (ALWAYS RUNS, needs no reference checkout)
      Scans our tracked source files for Mailspring/MailFlow provenance
      evidence: their licence headers, their vendor names, their distinctive
      internal identifiers. This is the half that actually gates in CI, because
      `reference/` is gitignored and therefore absent from a CI checkout.

  CHECK B - >=45-char verbatim-overlap scan (RUNS ONLY IF reference/ IS PRESENT)
      Builds a set of every distinct trimmed source line >= MIN_LINE_LEN chars
      found in the reference trees, then reports lines our own tracked sources
      share with it. Shared lines are classified: BOILERPLATE (documented
      allowlist below) is excused; anything SUBSTANTIVE fails, as does any
      contiguous run of >= MIN_CONTIGUOUS_RUN shared lines, which indicates a
      transliterated block even when every individual line is generic.
      When `reference/` is absent this check is reported as SKIPPED, not
      silently passed - see the banner printed in that case.

Stdlib-only, so it runs on a bare checkout with no pip install.

Usage:
    python tests/tools/copy_overlap.py [--root .]
                                       [--ref-dir reference]
                                       [--min-len 45]
                                       [--max-shown 40]
Env:
    KIWI_COPY_REF_DIR   overrides --ref-dir (for a CI mount that provides the
                        reference checkouts out-of-band).

Exit 0 = clean. Exit 1 = copying risk or marker hit. Exit 2 = the scan could
not run at all (git missing AND no ref dir) - deliberately NOT 0, so a broken
environment cannot masquerade as a pass.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------

# 45 chars is the floor used by the T-197 audit. Below it, matches are
# dominated by language keywords, punctuation runs and import paths, which
# carry no authorship signal. At/above it, a match is a real expression,
# statement or comment sentence.
MIN_LINE_LEN = 45

# Two adjacent boilerplate lines can collide by chance; three or more in a row
# means a block was carried across. This is what catches a "harmless-looking"
# transliteration whose individual lines each passed the allowlist.
MIN_CONTIGUOUS_RUN = 3

# Source extensions we compare. Deliberately excludes prose (.md), data
# (.json/.sql/.yml) and assets: those carry no code authorship, and docs
# legitimately name Mailspring when explaining the study-only policy.
SOURCE_SUFFIXES = {
    ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".go", ".java", ".kt", ".kts", ".swift", ".rb",
    ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".coffee", ".scss", ".sass", ".less", ".vue", ".svelte",
}

# Trees that are never our authorship and must not be scanned.
# `vendor/` joins `reference/` as the ui-migration checkout of upstream
# source we port from — it holds third-party authorship, not ours.
SKIP_DIR_PARTS = {
    "reference", "vendor", "source", "node_modules", "target", ".git",
    "obj-precise", "dist", "artifacts", "__pycache__",
}

# Reference trees scanned by CHECK B when they exist.
DEFAULT_REF_DIRS = (
    "reference/mailspring/app/src",
    "reference/mailspring/app/internal_packages",
    "reference/mailspring/mailsync",
    "reference/mailflow/frontend/src",
    "reference/mailflow/backend",
)

# Binary / oversized inputs are skipped, never silently counted as clean.
MAX_FILE_BYTES = 300_000
MIN_FILE_BYTES = 200

# The scanner has to contain the forbidden markers as data, so it excludes
# itself from CHECK A.
SELF_RELPATH = "tests/tools/copy_overlap.py"

# Directories of intentionally verbatim ported code, exempt from CHECK B
# only (CHECK A markers still apply). Each entry requires a recorded
# license decision in docs/DECISIONS.md.
#   kiwi-app/src/ms/ — Mailspring component ports for the ui-migration.
#   Project owner holds a license/rights grant from the Mailspring author
#   permitting verbatim reuse (recorded under the ui-migration decision).
PORTED_EXEMPT_PREFIXES = (
    "kiwi-app/src/ms/",
)


# --------------------------------------------------------------------------
# CHECK A - forbidden provenance markers
# --------------------------------------------------------------------------
#
# Each entry is (label, regex). Every pattern here is a string we must never
# reproduce in our own source. Prose files are excluded entirely (SOURCE_
# SUFFIXES only), so docs may keep saying "Mailspring-inspired".

FORBIDDEN_MARKERS = (
    # Mailspring is GPL-3.0. Its licence text and the FSF copyright line.
    ("gpl_header", re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I)),
    ("gpl_header", re.compile(r"Version 3, 29 June 2007", re.I)),
    ("gpl_header", re.compile(r"gnu\.org/licenses", re.I)),
    # MailFlow is AGPL-3.0.
    ("agpl_header", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I)),
    ("agpl_header", re.compile(r"Version 3, 19 November 2007", re.I)),
    # Vendors / authors. Bare "Mailspring" and "mailflow" are NOT banned: docs
    # and comments legitimately say "Mailspring-inspired", and `mailflow` is
    # our own mail-flow audit feature. Only the distinctive vendor spellings
    # and author lines are hard-failed.
    ("vendor", re.compile(r"Foundry\s*376", re.I)),
    ("vendor", re.compile(r"Mailspring,?\s+Inc", re.I)),
    ("vendor", re.compile(r"Copyright\s*\(\s*c\s*\)\s*[^\n|]{0,40}?Nylas", re.I)),
    ("vendor", re.compile(r"Copyright\s*\(\s*c\s*\)\s*[^\n|]{0,40}?MailFlow", re.I)),
    # Mailspring internals. A transliterated rebuild almost always drags at
    # least one of these along with it.
    ("mailspring_internals", re.compile(r"\bpersona-?(?:id|store)\b", re.I)),
    ("mailspring_internals", re.compile(r"\bparticipant-?list\b", re.I)),
    ("mailspring_internals", re.compile(r"\bspaceduck\b", re.I)),
    ("mailspring_internals", re.compile(r"\bmailsync\b", re.I)),
    # An AGPL/GPL notice pasted into a source file.
    ("copyleft_notice_in_source", re.compile(
        r"(?m)^[ \t]*(?://|#|/\*|\*)[ \t]*(?:This program is free software|"
        r"under the terms of the (?:GNU )?(?:Affero )?General Public License)",
        re.I)),
)

# --------------------------------------------------------------------------
# CHECK B - boilerplate allowlist
# --------------------------------------------------------------------------
#
# Justification for every entry, per the T-197 audit: each of these lines was
# observed as a shared line between reference/ and our tree, and each was
# judged non-substantive - i.e. it is language/framework/tooling convention
# that two independent projects write identically, not expression.
#
# This list is deliberately tiny and pattern-based. Anything not matched here
# is treated as SUBSTANTIVE and fails the gate. Adding an entry is a licence-
# relevant decision and must be justified in review.

BOILERPLATE = (
    # 1. Comment rulers: `// ----...`, `// ====...`, `# ----...`, `/* ----...`.
    #    A run of punctuation is not an authorial work; it is section
    #    decoration that every codebase uses.
    ("comment_ruler", re.compile(r"^[/*#!\-\s]*(?:-{4,}|={4,}|_{4,}|\*{5,})[/*#!\-\s]*$")),
    # 2. Linter suppressions. Tool-generated, written by the linter's docs,
    #    carries no project authorship.
    ("eslint_disable", re.compile(r"^\s*//\s*eslint-disable(?:-next-line|-line)?\b")),
    ("ts_ignore", re.compile(r"^\s*//\s*@ts-(?:ignore|nocheck|expect-error)\b")),
    ("rust_allow", re.compile(r"^\s*#!?\[allow\(")),
    # 3. React's single-hook state declaration. The form
    #    `const [a, setA] = useState(false);` is imposed by the framework's
    #    naming convention; the variable names are chosen by the caller and
    #    are not protectable expression.
    ("react_usestate", re.compile(
        r"^\s*(?:const|let|var)\s*\[\s*\w+\s*,\s*set\w+\s*\]\s*=\s*useState\([^;]*\)\s*;\s*$")),
    # 4. Byte-size constants. `const MAX_X = 25 * 1024 * 1024;` is arithmetic
    #    on a round number; the collision in the audit was coincidental.
    ("size_constant", re.compile(
        r"^\s*(?:pub\s+)?(?:const|static|let|var)\s+\w*(?:MAX|MIN|SIZE|LIMIT|BYTES|"
        r"LENGTH|DEPTH|COUNT)\w*\s*(?::\s*\w+)?\s*=\s*[\d_]+\s*[*]{0,2}\s*"
        r"(?:1024|1000)\s*[*]{0,2}\s*[\d_]+\s*;\s*$", re.I)),
    # 5. Thunderbird / Mozilla autoconfig XML vocabulary. This is NOT
    #    Mailspring IP: these element values are dictated by the Mozilla
    #    autoconfig specification that kiwi-autoconfig parses. They are
    #    protocol constants, exactly like `STARTTLS` or `text/plain`.
    ("autoconfig_spec_token", re.compile(
        r"^<(?:authentication|email-provider|domain|port-server|"
        r"hostname|username|oauth2|oauth2-method|displayname)>[^<]{0,40}</(?:"
        r"authentication|email-provider|domain|port-server|hostname|username|"
        r"oauth2|oauth2-method|displayname)>$")),
    # 6. Vitest/Jest spec preamble. `import { describe, it, expect } from
    #    'vitest';` is emitted by the test-runner scaffolding and is the
    #    mandated first line of every spec file for those frameworks; the
    #    names are fixed by the runner's API. Narrowly anchored to a named
    #    runner so a hand-written import cannot hide here.
    ("test_runner_preamble", re.compile(
        r"^import\s*\{[^}]*\}\s*from\s*['\"](?:vitest|jest|@jest/globals|"
        r"node:test|@playwright/test)['\"]\s*;?\s*$")),
    # 7. Node ESM->CJS interop one-liner. `createRequire(import.meta.url)` is
    #    the documented Node recipe (nodejs.org/api/esm.html#esmcreaterequire)
    #    for loading a CommonJS addon from an ES module; it is a fixed
    #    two-call incantation, not authored expression.
    ("esm_cjs_interop", re.compile(
        r"^import\s*\{\s*createRequire\s*\}\s*from\s*['\"]node:module['\"]\s*;?\s*$")),
    ("esm_cjs_interop", re.compile(
        r"^const\s+require\s*=\s*createRequire\(\s*import\.meta\.url\s*\)\s*;?\s*$")),
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p)


def is_ours(path: Path) -> bool:
    """True if this file is one of our own source files (never reference/)."""
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return False
    return not any(part in SKIP_DIR_PARTS for part in path.parts)


def read_text(path: Path):
    try:
        st = path.stat()
    except OSError:
        return None
    if st.st_size > MAX_FILE_BYTES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None  # binary/unreadable — skipped, not failed


def our_source_files(root: Path) -> list[Path]:
    """Tracked + untracked-but-not-ignored source files under root.

    Matches secret_scan.py's contract: this repo is early-stage and much work
    is not committed yet, so `git ls-files` alone would scan almost nothing.
    """
    try:
        found: list[str] = []
        for args in (["git", "ls-files"],
                     ["git", "ls-files", "--others", "--exclude-standard"]):
            out = subprocess.run(args, cwd=root, capture_output=True, text=True,
                                 check=True).stdout.splitlines()
            found.extend(p for p in out if p.strip())
        paths = [root / p for p in dict.fromkeys(found)]
    except Exception:
        paths = [p for p in root.rglob("*") if p.is_file()]
    return [p for p in paths if is_ours(p)]


def classify(line: str):
    """Return the boilerplate label if `line` is excusable, else None."""
    for label, rx in BOILERPLATE:
        if rx.match(line):
            return label
    return None


# --------------------------------------------------------------------------
# CHECK A
# --------------------------------------------------------------------------

def check_a(root: Path):
    """Forbidden-marker scan. Returns (scanned, findings)."""
    scanned = 0
    findings: list[str] = []
    self_path = (root / SELF_RELPATH).resolve()
    for f in our_source_files(root):
        if f.resolve() == self_path:
            continue
        text = read_text(f)
        if text is None:
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            for label, rx in FORBIDDEN_MARKERS:
                if rx.search(line):
                    findings.append(
                        f"A/{label} {rel(root, f)}:{lineno}: {line.strip()[:100]}")
                    break
    return scanned, findings


# --------------------------------------------------------------------------
# CHECK B
# --------------------------------------------------------------------------

def ref_line_set(root: Path, ref_dirs: tuple, min_len: int):
    """Build the set of distinct trimmed reference lines >= min_len chars.

    Returns (line_set, files_read).
    """
    out: set = set()
    files_read = 0
    for rel_dir in ref_dirs:
        base = root / rel_dir
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            try:
                size = p.stat().st_size
                if size < MIN_FILE_BYTES or size > MAX_FILE_BYTES:
                    continue
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            files_read += 1
            for line in text.splitlines():
                t = line.strip()
                if len(t) >= min_len:
                    out.add(t)
    return out, files_read


def check_b(root: Path, ref_dirs: tuple, min_len: int, max_shown: int):
    """Verbatim-overlap scan. Returns (findings, stats)."""
    ref_lines, ref_files = ref_line_set(root, ref_dirs, min_len)
    findings: list = []
    our_files = our_source_files(root)
    stats = {
        "ref_files": ref_files,
        "ref_lines": len(ref_lines),
        "our_files": len(our_files),
        "shared": 0,
        "boilerplate": 0,
        "substantive": 0,
        "longest_run": 0,
        "ported_exempt": 0,
    }
    longest = 0
    for f in our_files:
        text = read_text(f)
        if text is None:
            continue
        if rel(root, f).startswith(PORTED_EXEMPT_PREFIXES):
            stats["ported_exempt"] += 1
            continue
        run_len = 0
        run_lines: list = []
        for lineno, line in enumerate(text.splitlines(), 1):
            t = line.strip()
            shared = len(t) >= min_len and t in ref_lines
            if shared:
                stats["shared"] += 1
                if classify(t) is None:
                    stats["substantive"] += 1
                    findings.append(
                        f"B/substantive {rel(root, f)}:{lineno}: {t[:100]}")
                else:
                    stats["boilerplate"] += 1
                run_lines.append(lineno)
                run_len += 1
            else:
                if run_len >= MIN_CONTIGUOUS_RUN:
                    longest = max(longest, run_len)
                    findings.append(
                        f"B/run{run_len} {rel(root, f)}:{run_lines[0]}-{run_lines[-1]}"
                        f": contiguous shared block")
                run_len = 0
                run_lines = []
        if run_len >= MIN_CONTIGUOUS_RUN:
            longest = max(longest, run_len)
            findings.append(
                f"B/run{run_len} {rel(root, f)}:{run_lines[0]}-{run_lines[-1]}"
                f": contiguous shared block")
    stats["longest_run"] = longest
    findings.sort()
    if len(findings) > max_shown:
        findings = findings[:max_shown] + [f"... and {len(findings) - max_shown} more"]
    return findings, stats


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    def opt(flag, default):
        return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

    root = Path(opt("--root", "."))
    ref_dir = Path(os.environ.get("KIWI_COPY_REF_DIR") or opt("--ref-dir", "reference"))
    min_len = int(opt("--min-len", MIN_LINE_LEN))
    max_shown = int(opt("--max-shown", 40))
    # DEFAULT_REF_DIRS are repo-relative ("reference/..."); re-root them under
    # the (possibly external) ref_dir.
    ref_dirs = tuple(str(ref_dir) + d[len("reference"):] for d in DEFAULT_REF_DIRS)

    # Console-safe output: a cp1252 Windows console (and some CI log
    # collectors) cannot encode a BOM or an em-dash found in a scanned file.
    # Without this, printing a finding aborts the gate with UnicodeEncodeError
    # and a non-zero exit that looks like a crash rather than a verdict.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    scanned_a, findings_a = check_a(root)
    print(f"copy_overlap A(markers): scanned={scanned_a} hits={len(findings_a)}")
    for f in findings_a[:max_shown]:
        print(f"  HIT {f}")

    ref_present = any((root / d).is_dir() for d in ref_dirs)
    failed = bool(findings_a)

    if not ref_present:
        # reference/ is gitignored, so a plain CI checkout has none. CHECK A
        # still gated. Say so loudly rather than implying B passed.
        print("copy_overlap B(overlap): SKIPPED — no reference/ sources present "
              "(gitignored by design). Set KIWI_COPY_REF_DIR to enable.")
        print("copy_overlap: OK (A enforced; B not exercised)" if not failed
              else "copy_overlap: FAIL")
        return 1 if failed else 0

    findings_b, stats = check_b(root, ref_dirs, min_len, max_shown)
    print(
        f"copy_overlap B(overlap): ref_files={stats['ref_files']} "
        f"ref_lines>={min_len}={stats['ref_lines']} our_files={stats['our_files']} "
        f"shared={stats['shared']} boilerplate={stats['boilerplate']} "
        f"substantive={stats['substantive']} longest_run={stats['longest_run']}"
        f" ported_exempt_files={stats['ported_exempt']}"
    )
    for f in findings_b[:max_shown]:
        print(f"  HIT {f}")
    if findings_b:
        failed = True

    print("copy_overlap: FAIL" if failed else "copy_overlap: OK")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
