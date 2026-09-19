"""KIWI Tauri CSP assertion (Agent 6, T-113 follow-up).

Asserts kiwi-app/src-tauri/tauri.conf.json carries a restrictive Content
Security Policy so mail-driven XSS cannot reach Tauri IPC (THREAT-MODEL T-WEB,
SECURITY.md B2). Read-only: never modifies the config.

Errors (exit 1): missing file, unparseable JSON, csp null/missing/empty,
no default-src, 'unsafe-inline'/'unsafe-eval'/wildcard in script-src (or in
default-src as script fallback), remote http(s) script sources.
Warnings (exit 0): style 'unsafe-inline' present, object-src/frame-src
unrestricted, remote image sources beyond data:/blob: (tracking-pixel risk
must then be handled app-side per SECURITY.md rule 12).

Usage:  python tests/tools/check_csp.py [--root .]
"""
import json
import re
import sys
from pathlib import Path

REMOTE_HTTP = re.compile(r"https?://(?!ipc\.localhost|localhost|127\.0\.0\.1)")


def parse_csp(csp: str) -> dict:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def main() -> int:
    root = Path(sys.argv[sys.argv.index("--root") + 1]) if "--root" in sys.argv else Path(".")
    conf = root / "kiwi-app" / "src-tauri" / "tauri.conf.json"
    errors: list[str] = []
    warnings: list[str] = []
    try:
        cfg = json.loads(conf.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"check_csp: FAIL — cannot read {conf}: {e}")
        return 1
    csp = (cfg.get("app", {}) or {}).get("security", {}).get("csp")
    if csp is None:
        print("check_csp: FAIL — app.security.csp is null (T-WEB: mail XSS could reach IPC)")
        return 1
    if not isinstance(csp, str) or not csp.strip():
        print("check_csp: FAIL — csp present but empty/not a string")
        return 1
    d = parse_csp(csp)
    if "default-src" not in d:
        errors.append("missing default-src (script fallback undefined)")
    script_src = d.get("script-src", d.get("default-src", []))
    for bad in ("'unsafe-inline'", "'unsafe-eval'", "*"):
        if bad in script_src:
            errors.append(f"script-src allows {bad}")
    for src in script_src:
        if REMOTE_HTTP.search(src):
            errors.append(f"remote script source: {src}")
    style_src = d.get("style-src", [])
    if "'unsafe-inline'" in style_src:
        warnings.append("style-src 'unsafe-inline' (common for React; keep scripts locked down)")
    obj_src = d.get("object-src", d.get("default-src", []))
    if "'none'" not in obj_src:
        warnings.append("object-src not 'none' (consider hardening plugins/objects)")
    if "frame-src" not in d:
        warnings.append("frame-src unrestricted (consider 'self' or 'none')")
    img_src = d.get("img-src", [])
    if any(REMOTE_HTTP.search(s) or s in ("https:", "http:", "*") for s in img_src):
        warnings.append("remote image sources allowed — tracking-pixel block must be enforced app-side (rule 12)")
    for w in warnings:
        print(f"check_csp: WARN — {w}")
    if errors:
        print("check_csp: FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"check_csp: OK (directives={len(d)} warnings={len(warnings)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
