"""Generate the QR scaffold's derived artefacts (T-194, Agent 17).

Run from the repository root:

    python mobile/tools/gen-qr-vectors.py

Outputs (both checked in, so CI needs no Python):

  mobile/src/qr/tables.ts              EC block structure (ISO/IEC 18004 Table 9)
                                       for versions 1..25, levels L and M
  mobile/tests/fixtures/qr-vectors.ts  reference matrices produced by
                                       python-qrcode, one per mask pattern

Why generate: the encoder in `mobile/src/qr/qrcode.ts` is hand-written
(dependency-free, React-Native friendly). Its correctness evidence is
byte-exact equality with matrices produced by an *independent* implementation
(python-qrcode), so the vectors are kept as fixtures: `npm test` re-checks
them on every run without Python or the network.

Reference-implementation choice (recorded evidence): both `segno` and
`python-qrcode` were evaluated. python-qrcode is used because it follows the
ISO/IEC 18004 §7.4.10 padding rule (pad to the codeword boundary only when the
stream is *not* already aligned), while segno unconditionally appends a full
byte of padding bits -- for byte-mode symbols the stream is always aligned
after the terminator, so segno inserts an extra 0x00 codeword before the
0xEC/0x11 pad codewords (decodable, but non-conformant). Mask *selection* is
also implementation-dependent at the margin (the §7.8.3.3 N3 rule is read
slightly differently by every library), which is why the fixture pins all 8
mask patterns instead of only the auto-selected one.

Fixtures contain no secrets: every payload string is synthetic
(SECURITY.md rule 6).
"""

from __future__ import annotations

import json
import pathlib
import sys

try:
    import qrcode
    from qrcode.base import rs_blocks
    from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M
    from qrcode.main import QRCode
    from qrcode.util import MODE_8BIT_BYTE, QRData
except ImportError:  # pragma: no cover - developer tool, not a CI gate
    sys.exit("python-qrcode is required: python -m pip install qrcode")

MAX_VERSION = 25
LEVELS = [("L", ERROR_CORRECT_L), ("M", ERROR_CORRECT_M)]

# One fixture per structural case: both EC levels, block-group splits,
# alignment patterns (v >= 2), and version information blocks (v >= 7).
# Payload length is derived from the *actual* version chosen under the strict
# fit rule (see the module docstring): `_pad_start` is the last byte count that
# still failed to fit, `_pad_end` the first that fits -- regenerated versions
# therefore land on the same version even after byte-count bookkeeping changes.
FIXTURES = [
    ("byte-v1-m", "KIWI", "m"),
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
    ("json-v21-l", json.dumps({"padding": "x" * 930}, separators=(",", ":")), "l"),
    ("json-v9-m", json.dumps({"padding": "y" * 260}, separators=(",", ":")), "m"),
    ("json-v25-l", json.dumps({"padding": "z" * 1274}, separators=(",", ":")), "l"),
    ("json-v17-m", json.dumps({"padding": "w" * 700}, separators=(",", ":")), "m"),
]


def _level_const(name: str) -> int:
    return ERROR_CORRECT_L if name == "L" else ERROR_CORRECT_M


def write_tables(path: pathlib.Path) -> None:
    header = (
        "/**\n"
        " * QR EC block structure -- GENERATED FILE, do not hand-edit.\n"
        " *\n"
        " * Source: `mobile/tools/gen-qr-vectors.py`, which reads\n"
        " * `qrcode.base.rs_blocks` (mirrors ISO/IEC 18004 Table 9). Regenerate with:\n"
        " *\n"
        " *   python mobile/tools/gen-qr-vectors.py\n"
        " *\n"
        " * Versions 1..25, error-correction levels L and M (the ones `qrcode.ts`\n"
        " * encodes). Each entry lists block groups as (count, totalCodewords per\n"
        " * block, dataCodewords per block).\n"
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
        parts: list[str] = []
        for name, const in LEVELS:
            blocks = rs_blocks(version, const)
            # Merge runs of identical block geometry into (count, total, data).
            merged: list[list[int]] = []
            for block in blocks:
                entry = [1, block.total_count, block.data_count]
                if merged and merged[-1][1] == entry[1] and merged[-1][2] == entry[2]:
                    merged[-1][0] += 1
                else:
                    merged.append(entry)
            rendered = ", ".join(
                "{ count: %d, totalCodewords: %d, dataCodewords: %d }" % (c, t, d)
                for c, t, d in merged
            )
            parts.append(f"{name}: [{rendered}]")
        rows.append(f"  {version}: {{ {', '.join(parts)} }},")

    footer = (
        "};\n\n"
        "/** Highest version this table covers (larger payloads are rejected). */\n"
        f"export const MAX_QR_VERSION = {MAX_VERSION};\n"
    )
    path.write_text(header + "\n".join(rows) + "\n" + footer, encoding="utf-8")
    print(f"wrote {path} ({len(rows)} versions x {len(LEVELS)} levels)")


def build_qr(text: str, level: str, mask: int | None) -> QRCode:
    qr = QRCode(
        error_correction=_level_const(level),
        box_size=1,
        border=0,
        mask_pattern=mask,
    )
    qr.add_data(QRData(text.encode("utf-8"), mode=MODE_8BIT_BYTE))
    qr.make(fit=True)
    return qr


def fixture(name: str, text: str, level: str) -> dict[str, object]:
    auto = build_qr(text, level, None)
    version = int(auto.version)
    masks: list[dict[str, object]] = []
    for mask in range(8):
        forced = build_qr(text, level, mask)
        if int(forced.version) != version:
            raise AssertionError(
                f"fixture {name}: forced-mask version {forced.version} != auto {version}"
            )
        matrix = forced.get_matrix()
        masks.append(
            {
                "mask": mask,
                "rows": ["".join("1" if cell else "0" for cell in row) for row in matrix],
            }
        )
    return {
        "name": name,
        "text": text,
        "ecLevel": level.upper(),
        "version": version,
        "referenceMask": int(auto.best_mask_pattern()),
        "size": len(auto.get_matrix()),
        "masks": masks,
    }



def write_vectors(path: pathlib.Path) -> None:
    fixtures = [fixture(name, text, level) for name, text, level in FIXTURES]

    lines: list[str] = [
        "/**",
        " * Reference QR matrices -- GENERATED FILE, do not hand-edit.",
        " *",
        " * Produced by `mobile/tools/gen-qr-vectors.py` using python-qrcode (an",
        " * independent ISO/IEC 18004 implementation). For every fixture, all 8 mask",
        " * patterns are stored so `tests/qr/qrcode.test.ts` can prove the hand-written",
        " * encoder in `src/qr/qrcode.ts` matches module-for-module regardless of which",
        " * mask it selects -- that equality is the correctness evidence for the QR",
        " * surface of the pairing screen.",
        " *",
        " * `referenceMask` is the mask python-qrcode's own `best_mask_pattern()`",
        " * chose; mask selection is compared separately (it is implementation-defined",
        " * at the margin -- see `tools/gen-qr-vectors.py` header).",
        " *",
        " * Payload strings are synthetic fixtures; no real ticket, endpoint or key",
        " * material appears here (SECURITY.md rule 6).",
        " */",
        "",
        "export interface QrMaskMatrix {",
        "  readonly mask: number;",
        "  /** One string per module row: '1' = dark, '0' = light (quiet zone excluded). */",
        "  readonly rows: readonly string[];",
        "}",
        "",
        "export interface QrVector {",
        "  readonly name: string;",
        "  readonly text: string;",
        "  readonly ecLevel: 'L' | 'M';",
        "  readonly version: number;",
        "  readonly size: number;",
        "  /** Mask python-qrcode's `best_mask_pattern()` selected (informational). */",
        "  readonly referenceMask: number;",
        "  readonly masks: readonly QrMaskMatrix[];",
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
        lines.append(f"    size: {fx['size']},")
        lines.append(f"    referenceMask: {fx['referenceMask']},")
        lines.append("    masks: [")
        for mask_fx in fx["masks"]:
            lines.append("      {")
            lines.append(f"        mask: {mask_fx['mask']},")
            lines.append("        rows: [")
            for row in mask_fx["rows"]:
                lines.append(f"          {json.dumps(row)},")
            lines.append("        ],")
            lines.append("      },")
        lines.append("    ],")
        lines.append("  },")
    lines.append("];")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    summary = ", ".join(
        f"{f['name']}=v{f['version']}/{f['ecLevel']}/ref-mask{f['referenceMask']}"
        for f in fixtures
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
