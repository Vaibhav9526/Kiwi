# KIWI pitch deck generator — python-pptx.
# Source content: presentation/kiwi-presentation-script.md
# Run: python presentation/make_pptx.py
import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(ROOT)
ARCH = os.path.join(ROOT, "kiwi-architecture.png")
SHOT = os.path.join(REPO, "docs", "screenshots", "mail-light.png")
OUT = os.path.join(ROOT, "KIWI-pitch.pptx")

# ---- palette (KIWI) ----
INK = RGBColor(0x10, 0x23, 0x1A)       # near-black green
ACCENT = RGBColor(0x1E, 0x8E, 0x3E)    # kiwi green
ACCENT_D = RGBColor(0x14, 0x6A, 0x2E)  # deep green
MUTED = RGBColor(0x5F, 0x6B, 0x66)
CARD = RGBColor(0xF1, 0xF7, 0xF3)
LINE = RGBColor(0xD5, 0xE4, 0xDA)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
FONT = "Segoe UI"

W, H = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width, prs.slide_height = W, H
BLANK = prs.slide_layouts[6]


def slide():
    return prs.slides.add_slide(BLANK)


def box(s, x, y, w, h, fill=None, line=None, shadow=False, round_=True):
    shape = s.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if round_ else MSO_SHAPE.RECTANGLE,
        x, y, w, h,
    )
    if round_:
        try:
            shape.adjustments[0] = 0.06
        except Exception:
            pass
    if fill is None:
        shape.fill.background()
    else:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill
    if line is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line
        shape.line.width = Pt(1)
    shape.shadow.inherit = False
    return shape


def text(s, x, y, w, h, runs, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, space_after=6, line_spacing=1.06):
    """runs: str | list of paragraphs; each paragraph str or (text, opts)."""
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    if isinstance(runs, str):
        runs = [runs]
    for i, para in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space_after)
        p.line_spacing = line_spacing
        segs = para if isinstance(para, list) else [(para, {})]
        for txt, o in segs:
            r = p.add_run()
            r.text = txt
            f = r.font
            f.name = FONT
            f.size = Pt(o.get("size", size))
            f.bold = o.get("bold", bold)
            f.italic = o.get("italic", False)
            f.color.rgb = o.get("color", color)
    return tb


def header(s, kicker, title, sub=None):
    """Standard content-slide header with accent tick."""
    box(s, Inches(0.62), Inches(0.55), Inches(0.16), Inches(0.72), fill=ACCENT, round_=False)
    text(s, Inches(0.95), Inches(0.5), Inches(11), Inches(0.3), kicker,
         size=13, color=ACCENT_D, bold=True)
    text(s, Inches(0.95), Inches(0.82), Inches(11.6), Inches(0.9), title,
         size=34, color=INK, bold=True)
    if sub:
        text(s, Inches(0.95), Inches(1.42), Inches(11.6), Inches(0.5), sub,
             size=15, color=MUTED)


def bullets(s, x, y, w, h, items, size=17, gap=10, mark="— "):
    paras = []
    for head, body in items:
        segs = [(mark, {"color": ACCENT_D, "bold": True})]
        if head:
            segs.append((head + " ", {"bold": True}))
        segs.append((body, {"color": INK}))
        paras.append(segs)
    return text(s, x, y, w, h, paras, size=size, space_after=gap)


def footer(s, n):
    text(s, Inches(11.7), Inches(7.08), Inches(1.4), Inches(0.3),
         f"KIWI · {n}", size=10, color=MUTED, align=PP_ALIGN.RIGHT)


def pic(s, path, x, y, w=None, h=None, width=None, height=None):
    return s.shapes.add_picture(path, x, y, width or w, height or h)


# ============================ 1 · TITLE ============================
s = slide()
box(s, 0, 0, W, H, fill=INK, round_=False)
box(s, 0, Inches(7.12), W, Inches(0.38), fill=ACCENT_D, round_=False)
text(s, Inches(0.95), Inches(1.7), Inches(11.4), Inches(1.4), "KIWI",
     size=96, color=WHITE, bold=True)
text(s, Inches(0.98), Inches(3.1), Inches(11.4), Inches(0.9),
     "Email that proves its security.",
     size=32, color=RGBColor(0x9F, 0xE6, 0xB8))
text(s, Inches(0.98), Inches(4.1), Inches(10.6), Inches(1.4), [
    "A full desktop mail client and a security platform in one product —",
    "built from scratch on Rust + Tauri 2. Every claim backed by",
    "deterministic, tamper-evident evidence.",
], size=19, color=RGBColor(0xC9, 0xD6, 0xCE))
text(s, Inches(0.98), Inches(6.4), Inches(11), Inches(0.4),
     "hackathon build · MPL-2.0 · alpha",
     size=13, color=RGBColor(0x8B, 0x99, 0x90))

# ============================ 2 · PROBLEM ============================
s = slide()
header(s, "THE PROBLEM", "“This connection was encrypted.” — says who?")
bullets(s, Inches(0.95), Inches(2.0), Inches(7.1), Inches(4.6), [
    ("Trust without evidence.",
     "Every day we click links, open attachments, and hand our inbox credentials, contracts, and conversations — and no mainstream client can prove it did the secure thing."),
    ("Indicators that lie.",
     "Green checkmarks get painted from assumptions; when the evidence isn't there, most clients show it anyway — or invent scareware."),
    ("Nothing to check later.",
     "No record of what actually happened on the wire — no TLS facts, no DNS verdicts, no audit trail to stand behind a claim."),
], size=18, gap=16)
card = box(s, Inches(8.35), Inches(2.0), Inches(4.25), Inches(4.5), fill=CARD, line=LINE)
text(s, Inches(8.7), Inches(2.35), Inches(3.6), Inches(0.5),
     "KIWI's design rule", size=20, bold=True, color=ACCENT_D)
tb = text(s, Inches(8.7), Inches(2.95), Inches(3.6), Inches(3.4), [
    "Every security claim must be backed by evidence —",
    "and when the evidence isn't there, the UI says so",
    "instead of painting a fake green.",
], size=19)
footer(s, 2)

# ============================ 3 · WHAT KIWI IS ============================
s = slide()
header(s, "THE PRODUCT", "One app: a real mail client + a security platform")
c1 = box(s, Inches(0.95), Inches(1.95), Inches(5.7), Inches(4.85), fill=CARD, line=LINE)
text(s, Inches(1.3), Inches(2.2), Inches(5.0), Inches(0.5),
     "On the surface — a mail client you know", size=19, bold=True, color=ACCENT_D)
bullets(s, Inches(1.3), Inches(2.85), Inches(5.05), Inches(3.8), [
    ("", "Four-pane mailbox, unified inbox across accounts"),
    ("", "Compose with undo-send, send-later, templates"),
    ("", "FTS5 search, contacts, attachments, rules, snooze"),
    ("", "Multiple accounts — Gmail OAuth2 included — themes"),
], size=16, gap=9)
c2 = box(s, Inches(6.95), Inches(1.95), Inches(5.7), Inches(4.85), fill=INK)
text(s, Inches(7.3), Inches(2.2), Inches(5.0), Inches(0.5),
     "Underneath — security work most clients skip", size=19, bold=True,
     color=RGBColor(0x9F, 0xE6, 0xB8))
text(s, Inches(7.3), Inches(2.85), Inches(5.05), Inches(3.8), [
    [("— ", {"color": RGBColor(0x9F, 0xE6, 0xB8), "bold": True}),
     ("Every SMTP / IMAP / POP3 connection captured at the protocol layer",
      {"color": RGBColor(0xE4, 0xEE, 0xE8)})],
    [("— ", {"color": RGBColor(0x9F, 0xE6, 0xB8), "bold": True}),
     ("Scored by deterministic rules — no invented findings",
      {"color": RGBColor(0xE4, 0xEE, 0xE8)})],
    [("— ", {"color": RGBColor(0x9F, 0xE6, 0xB8), "bold": True}),
     ("Recorded as tamper-evident evidence, hash-chained on disk",
      {"color": RGBColor(0xE4, 0xEE, 0xE8)})],
    [("— ", {"color": RGBColor(0x9F, 0xE6, 0xB8), "bold": True}),
     ("Not a Thunderbird or Mailspring fork — built from scratch",
      {"color": RGBColor(0xE4, 0xEE, 0xE8)})],
], size=16, space_after=9)
footer(s, 3)

# ============================ 4 · PRODUCT SHOT ============================
s = slide()
header(s, "THE CLIENT", "Four-pane mailbox, honest by design")
from PIL import Image
im = Image.open(SHOT)
ph = Inches(5.0)
pw = Emu(int(ph * (im.width / im.height)))
pic(s, SHOT, Inches(0.95), Inches(1.8), height=ph)
text(s, Inches(0.95) + pw + Inches(0.35), Inches(1.8),
     W - pw - Inches(1.5), Inches(5.0), [
    [("Unified inbox", {"bold": True, "size": 15, "color": ACCENT_D})],
    [("across accounts — Gmail OAuth2, IMAP, POP3", {"size": 13.5})],
    [(" ", {"size": 6})],
    [("Per-message trust stamps", {"bold": True, "size": 15, "color": ACCENT_D})],
    [("risk + auth evidence attached at ingest", {"size": 13.5})],
    [(" ", {"size": 6})],
    [("Agenda rail + quick actions", {"bold": True, "size": 15, "color": ACCENT_D})],
    [("keyboard-first, snooze, templates, drag-to-folder", {"size": 13.5})],
    [(" ", {"size": 6})],
    [("Themes", {"bold": True, "size": 15, "color": ACCENT_D})],
    [("light / dark / high-contrast", {"size": 13.5})],
], size=13.5)
footer(s, 4)

# ============================ 5 · AUDIENCES ============================
s = slide()
header(s, "WHO IT SERVES", "Three audiences, one binary")
cards = [
    ("The everyday user", [
        "A polished, complete mail client",
        "Honest indicators instead of scareware",
        "Absent data renders absent — never a fake green",
    ]),
    ("The security professional", [
        "Deterministic TlsObservation per session — TLS version, cipher, key exchange, forward secrecy, cert chain, STARTTLS",
        "Captured, not inferred",
        "SPF / DKIM / DMARC over fail-closed DNS",
    ]),
    ("The organization", [
        "Admin plane: orgs, domains, users, roles",
        "Recipient-domain policy + mail-flow metadata — never message bodies",
        "Its own audit trail",
    ]),
]
x = Inches(0.95)
for title, items in cards:
    box(s, x, Inches(1.95), Inches(3.85), Inches(4.9), fill=CARD, line=LINE)
    text(s, x + Inches(0.3), Inches(2.25), Inches(3.25), Inches(0.9),
         title, size=19, bold=True, color=ACCENT_D)
    bullets(s, x + Inches(0.3), Inches(3.0), Inches(3.3), Inches(3.6),
            [("", i) for i in items], size=14.5, gap=8)
    x += Inches(4.13)
footer(s, 5)

# ============================ 6 · DIFFERENTIATORS ============================
s = slide()
header(s, "WHY IT'S DIFFERENT", "Four claims other clients can't make")
rows = [
    ("1", "Deterministic evidence, not vibes",
     "Every connection yields a TlsObservation — real TLS facts at the protocol layer. kiwi-forensics turns sessions into findings; no score exists without a rule behind it."),
    ("2", "The lock is real",
     "Suspicious signals feed a trust engine. When trust drops, the endpoint locks — enforced in Rust IPC across the entire command surface, not just a UI overlay. A compromised renderer can't bypass it."),
    ("3", "Tamper-evident audit",
     "Every mutation lands in a hash-chained audit.jsonl, genesis-verified on open. Corruption surfaces as audit-corrupt in the UI instead of being hidden."),
    ("4", "Fail closed over fabricate",
     "Absent data renders absent. A missing backend disables the action and says so. No placeholder signatures, no fabricated green — ever."),
]
y = Inches(1.9)
for n, head, body in rows:
    box(s, Inches(0.95), y, Inches(0.62), Inches(1.02), fill=ACCENT_D, round_=True)
    text(s, Inches(0.95), y + Inches(0.14), Inches(0.62), Inches(0.7), n,
         size=26, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    text(s, Inches(1.8), y - Inches(0.04), Inches(10.6), Inches(0.45), head,
         size=19, bold=True)
    text(s, Inches(1.8), y + Inches(0.38), Inches(10.6), Inches(0.7), body,
         size=14.5, color=MUTED)
    y += Inches(1.18)
box(s, Inches(0.95), y + Inches(0.05), Inches(11.45), Inches(0.62), fill=CARD, line=LINE)
text(s, Inches(1.2), y + Inches(0.16), Inches(11), Inches(0.4), [[
    ("AI explains, never asserts.  ", {"bold": True, "color": ACCENT_D, "size": 15}),
    ("AI may translate a finding into plain language — it never decides a verdict. The deterministic rule engine is the only authority.",
     {"size": 14.5, "color": INK}),
]])
footer(s, 6)

# ============================ 7 · SECURITY CHAIN ============================
s = slide()
header(s, "IN ACTION", "What happens when you click a link in KIWI")
steps = [
    ("stamps", "risk + auth stamps attached at ingest"),
    ("hints", "per-message evidence read at render"),
    ("click-gate", "verdict: allow · confirm · sandbox · deny"),
    ("sandbox", "risky links open in a disposable WSL2 guest — torn down before the session is recorded"),
    ("evidence", "every step lands in the audit chain"),
]
x = Inches(0.95)
ww = Inches(2.17)
for i, (t, d) in enumerate(steps):
    box(s, x, Inches(2.15), ww, Inches(1.5), fill=CARD, line=LINE)
    text(s, x + Inches(0.16), Inches(2.3), ww - Inches(0.32), Inches(0.45), t,
         size=17, bold=True, color=ACCENT_D)
    text(s, x + Inches(0.16), Inches(2.72), ww - Inches(0.32), Inches(0.9), d,
         size=11.5, color=INK)
    if i < 4:
        text(s, x + ww - Inches(0.02), Inches(2.62), Inches(0.35), Inches(0.5),
             "→", size=20, bold=True, color=ACCENT)
    x += ww + Inches(0.2)
bullets(s, Inches(0.95), Inches(4.15), Inches(11.5), Inches(2.4), [
    ("Re-openable, not bypassable.", "Opening a link again re-checks the source risk — the gate can't be cached around."),
    ("Verifiable reports.", "Forensics reports export as canonical bytes in a self-verifying SHA-256 envelope — you can prove the report wasn't altered after the fact."),
], size=16, gap=10)
footer(s, 7)

# ============================ 8 · ARCHITECTURE ============================
s = slide()
header(s, "UNDER THE HOOD", "Untrusted webview, trustworthy core")
im = Image.open(ARCH)
ah = Inches(5.55)
aw = Emu(int(ah * (im.width / im.height)))
pic(s, ARCH, Emu(int((W - aw) / 2)), Inches(1.6), height=ah)
footer(s, 8)

# ============================ 9 · TECH STACK ============================
s = slide()
header(s, "THE TECH", "Tauri 2 · Rust workspace · typed lock-gated IPC")
text(s, Inches(0.95), Inches(1.8), Inches(5.8), Inches(0.5),
     "Desktop — Tauri 2", size=19, bold=True, color=ACCENT_D)
bullets(s, Inches(0.95), Inches(2.3), Inches(5.8), Inches(4.4), [
    ("", "Rust host + React 18 / TS / Vite renderer — the webview is untrusted by design"),
    ("", "Every typed kiwi_* IPC command validates input, runs the lock gate, writes audit evidence"),
    ("", "Secrets live only in the OS credential store; unsafe_code forbidden workspace-wide"),
], size=15, gap=8)
text(s, Inches(6.95), Inches(1.8), Inches(5.8), Inches(0.5),
     "Rust 2024 workspace — ten crates", size=19, bold=True, color=ACCENT_D)
bullets(s, Inches(6.95), Inches(2.3), Inches(5.55), Inches(4.4), [
    ("kiwi-mail", "real SMTP·IMAP·POP3, MIME, SQLite+FTS5, rules, mbox, TLS capture"),
    ("kiwi-core · kiwi-pair", "trust engine, device identity, QR pairing authority"),
    ("kiwi-forensics · kiwi-mailauth", "PCAP reassembly + scoring; SPF/DKIM/DMARC on fail-closed DNS"),
    ("kiwi-sandbox · kiwi-integrations · kiwi-autoconfig · kiwi-contacts", "WSL2 guest, consent-bounded services, OAuth2 discovery, vCard"),
    ("kiwi-app", "~25 IPC command modules, audit chain, syncer, notifications"),
], size=14, gap=7)
box(s, Inches(0.95), Inches(6.15), Inches(11.45), Inches(0.75), fill=CARD, line=LINE)
text(s, Inches(1.2), Inches(6.28), Inches(11), Inches(0.55), [[
    ("Sidecars:  ", {"bold": True, "size": 14, "color": ACCENT_D}),
    ("kiwi-admin (Node + Drizzle + PostgreSQL org plane, React admin UI) · React Native authenticator for QR-paired approvals   |   ",
     {"size": 13.5}),
    ("Dev/CI:  ", {"bold": True, "size": 14, "color": ACCENT_D}),
    ("Docker mailpit + GreenMail · cargo test/clippy/fmt · tsc · vitest · CDP smoke", {"size": 13.5}),
]])
footer(s, 9)

# ============================ 10 · CLOSE ============================
s = slide()
box(s, 0, 0, W, H, fill=INK, round_=False)
text(s, Inches(0.95), Inches(2.0), Inches(11.4), Inches(1.2),
     "KIWI doesn't ask you to trust it —", size=40, color=WHITE, bold=True)
text(s, Inches(0.95), Inches(2.85), Inches(11.4), Inches(1.0),
     "it shows you the evidence.", size=40,
     color=RGBColor(0x9F, 0xE6, 0xB8), bold=True)
text(s, Inches(0.98), Inches(4.15), Inches(11), Inches(0.6),
     "A real mail client for daily use. A security platform underneath. Every claim backed by deterministic, tamper-evident proof.",
     size=18, color=RGBColor(0xC9, 0xD6, 0xCE))
box(s, Inches(0.98), Inches(5.35), Inches(4.6), Inches(0.9), fill=ACCENT_D, round_=True)
text(s, Inches(0.98), Inches(5.55), Inches(4.6), Inches(0.5),
     "Email that proves its security.", size=20, bold=True, color=WHITE,
     align=PP_ALIGN.CENTER)
text(s, Inches(0.98), Inches(6.7), Inches(11.5), Inches(0.4),
     "Tauri 2 · Rust 2024 (unsafe forbidden) · React 18 · SQLite+FTS5 · SPF/DKIM/DMARC · WSL2 sandbox · hash-chained audit · MPL-2.0 · alpha, ~30 MB",
     size=12.5, color=RGBColor(0x8B, 0x99, 0x90))

prs.save(OUT)
print("wrote", OUT)
