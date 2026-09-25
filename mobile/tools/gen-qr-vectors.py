"""Generate the QR scaffold's two derived artefacts (T-194, Agent 17).

Run from the repository root:

    python mobile/tools/gen-qr-vectors.py

Outputs (both checked in, so CI needs no Python):

  mobile/src/qr/tables.ts              EC block structure (ISO/IEC 18004 Table 9)
                                       for versions 1..25, levels L and M
  mobile/tests/fixtures/qr-vectors.ts  reference matrices produced by segno

Why generate: the encoder in `mobile/src/qr/qrcode.ts` is hand-written
(dependency-free, React-Native friendly). Its correctness evidence is
byte-exact equality with matrices from an *independent* implementation
(segno), so the vectors are kept as fixtures: `npm test` re-checks them on
every run without Python or the network.

The EC block table is read out of `segno.consts.ECC` (which mirrors ISO/IEC
18004) rather than retyped by hand -- 50 rows of block structure is exactly
the kind of table a typo hides in. Fixtures contain no secrets: every payload
string is synthetic (SECURITY.md rule 6).
"""

from __future__ import annotations

import json
import pathlib
import sys

try:
    import segno
    from segno import consts as segno_consts
except ImportError:  # pragma: no cover - developer tool, not a CI gate
    sys.exit("segno is required: python -m pip install segno")

MAX_VERSION = 25
LEVELS = [("L", segno_consts.ERROR_LEVEL_L), ("M", segno_consts.ERROR_LEVEL_M)]

# One fixture per interesting structural case: version selection, both EC
# levels, the single- and two-group block splits, and v>=7 (version-info
# blocks + alignment patterns).
FIXTURES = [
    ("byte-v1-m", "KIWI", "m"),
    (
        "json-v2-l",
        json.dumps(
            {"v": 1, "type": "kiwi-pairing", "pairing_ticket": "Ab12Cd34Ef56"},
            separators=(",", ":"),
        ),
        "l",
    ),
    (
        "json-v3-m",
        json.dumps(
            {
                "v": 1,
                "type": "kiwi-pairing",
                "pairing_ticket": "Ab12Cd34Ef56Gh78Ij90",
                "desktop_endpoint": "wss://192.168.1.20:49310/pair",
                "device_label": "Fixture Pixel",
                "desktop_public_key_b64": "ed25519:" + "A" * 44,
                "issued_unix": 1729000000,
                "expires_unix": 1729000300,
            },
            separators=(",", ":"),
        ),
        "m",
    ),
    ("json-v5-l", json.dumps({"padding": "x" * 150}, separators=(",", ":")), "l"),
    ("json-v7-m", json.dumps({"padding": "y" * 215}, separators=(",", ":")), "m"),
    ("json-v12-m", json.dumps({"padding": "z" * 430}, separators=(",", ":")), "m"),
]


def write_tables(path: pathlib.Path) -> None:
    header = (
        "/**\n"
        " * QR EC block structure -- GENERATED FILE, do not hand-edit.\n"
        " *\n"
        " * Source: `mobile/tools/gen-qr-vectors.py`, which reads `segno.consts.ECC`\n"
        " * (mirrors ISO/IEC 18004 Table 9). Regenerate with:\n"
        " *\n"
        " *   python mobile/tools/gen-qr-vectors.py\n"
        " *\n"
        f" * Generated with segno {segno.__version__}; versions 1..{MAX_VERSION}, error-correction\n"
        " * levels L and M (the ones `qrcode.ts` encodes). Each entry lists block\n"
        " * groups as (count, totalCodewords per block, dataCodewords per block).\n"
        " */\n"
        "\n"
        "export interface EcBlockGroup {\n"
        "  readonly count: number;\n"
        "  readonly totalCodewords: number;\n"
        "  readonly dataCodewords: number;\n"
        "}\n"
        "\n"
        "export type EcLevel = 'L' | 'M';\n"
        "\n"
        "export const EC_BLOCKS: Readonly<\n"
        "  Record<number, Readonly<Record<EcLevel, readonly EcBlockGroup[]>>>\n"
        "> = {\n"
    )

    rows: list[str] = []
    for version in range(1, MAX_VERSION + 1):
        per_level = segno_consts.ECC[version]
        parts: list[str] = []
        for label, level in LEVELS:
            groups = ", ".join(
                "{ count: %d, totalCodewords: %d, dataCodewords: %d }" % (n, total, data)
                for n, total, data in per_level[level]
            )
            parts.append(f"{label}: [{groups}]")
        rows.append(f"  {version}: {{ {', '.join(parts)} }},")

    footer = (
        "};\n\n"
        "/** Highest version this table covers (larger payloads are rejected). */\n"
        f"export const MAX_QR_VERSION = {MAX_VERSION};\n"
    )
    path.write_text(header + "\n".join(rows) + "\n" + footer, encoding="utf-8")
    print(f"wrote {path} ({len(rows)} versions x {len(LEVELS)} levels)")


def fixture_matrix(text: str, level: str) -> dict[str, object]:
    """Render one byte-mode symbol and return its module matrix as row strings."""
    code = segno.make(text, error=level, mode="byte", boost_error=False, micro=False)
    rows = ["".join("1" if bit else "0" for bit in row) for row in code.matrix]
    return {
        "name": None,
        "text": text,
        "ecLevel": level.upper(),
        "version": int(code.version),
        "mask": int(code.mask),
        "size": len(rows),
        "rows": rows,
    }



def write_vectors(path: pathlib.Path) -> None:
    fixtures = []
    for name, text, level in FIXTURES:
        fx = fixture_matrix(text, level)
        fx["name"] = name
        fixtures.append(fx)

    lines: list[str] = [
        "/**",
        " * Reference QR matrices -- GENERATED FILE, do not hand-edit.",
        " *",
        f" * Produced by `mobile/tools/gen-qr-vectors.py` using segno {segno.__version__} (an",
        " * independent ISO/IEC 18004 implementation). `tests/qr/qrcode.test.ts` asserts that",
        " * the hand-written encoder in `src/qr/qrcode.ts` reproduces these matrices",
        " * module-for-module -- that equality is the correctness evidence for the QR",
        " * surface of the pairing screen.",
        " *",
        " * Payload strings are synthetic fixtures; no real ticket, endpoint or key",
        " * material appears here (SECURITY.md rule 6).",
        " */",
        "",
        "export interface QrVector {",
        "  readonly name: string;",
        "  readonly text: string;",
        "  readonly ecLevel: 'L' | 'M';",
        "  readonly version: number;",
        "  readonly mask: number;",
        "  readonly size: number;",
        "  /** One string per module row: '1' = dark, '0' = light (quiet zone excluded). */",
        "  readonly rows: readonly string[];",
        "}",
        "",
        "export const QR_VECTORS: readonly QrVector[] = [",
    ]
    for fx in fixtures:
        lines.append("  {")
        lines.append(f"    name: {json.dumps(fx['name'])},")
        lines.append(f"    text: {json.dumps(fx['text'])},")
        lines.append(f"    ecLevel: {json.dumps(fx['ecLevel'])},")
        lines.append(f"    version: {fx['version']},")
        lines.append(f"    mask: {fx['mask']},")
        lines.append(f"    size: {fx['size']},")
        lines.append("    rows: [")
        for row in fx["rows"]:
            lines.append(f"      {json.dumps(row)},")
        lines.append("    ],")
        lines.append("  },")
    lines.append("];")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    summary = ", ".join(
        f"{f['name']}=v{f['version']}/{f['ecLevel']}/mask{f['mask']}" for f in fixtures
    )
    print(f"wrote {path} ({len(fixtures)} vectors: {summary})")


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    tables = root / "src" / "qr" / "tables.ts"
    vectors = root / "tests" / "fixtures" / "qr-vectors.ts"
    tables.parent.mkdir(parents=True, exist_ok=True)
    vectors.parent.mkdir(parents=True, exist_ok=True)
    write_tables(tables)
    write_vectors(vectors)


if __name__ == "__main__":
    main()

