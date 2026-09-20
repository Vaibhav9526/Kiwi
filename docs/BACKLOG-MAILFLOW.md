# MailFlow feature backlog (mined)

Source reference: `reference/mailflow/` — AGPL-3.0 + commercial tier. **Study-only**;
no source copying into our tree. All features reimplemented natively, deterministic-first.

Status: BACKLOG — do not start until current T-task queues drain and the
Mailspring-replica UI (T-190-192) lands; F-features pair with that UI.

## Selected features

| # | Feature | Primary home | Notes |
|---|---------|--------------|-------|
| F1 | Inbox rules engine: sender/subject/recipient/headers/body/attachment-name predicates → move/archive/delete/mark-read/star; runs on sync ingest; ordered rules + block-list-first precedence; deterministic eval only (reuse kiwi-admin evaluator shape) | `kiwi-mail` + IPC + thin UI | Rules side-effects need security review |
| F2 | Categorization tabs: Primary/Newsletters/Social/Notifications/Other via List-Unsubscribe/bulk-precedence/sender heuristics; deterministic classifier; optional AI-reclassify seam = explanation layer only | `kiwi-mail` (classifier) + UI tabs | No network calls |
| F3 | One-click unsubscribe: List-Unsubscribe/List-Unsubscribe-Post detection; default action OPENS the URL; mailto path requires explicit confirm (outbound action = consent) | `kiwi-mail` header parse + UI affordance | Security review: outbound action |
| F4 | Sender block list: trash-before-rules, per-account | `kiwi-mail` + settings UI | |
| F5 | Mark-as-read behavior pref: immediate / delay-N-sec / manual | `kiwi-app` prefs + IPC | |
| F6 | GTD labels: Todo/Watch/Delegated/Someday/Reference backed by REAL IMAP folders (sync cross-client); keys t/w/d; per-account opt-in; Todo auto-clears on reply sent | `kiwi-mail` folder ops + UI | Folder-backed, not tag-backed — deliberate for sync |
| F7 | Smart contact autocomplete ranked by sent-mail frequency | `kiwi-contacts` + compose UI | |
| F8 | Sender avatars LOCAL ONLY: kiwi-contacts photos + deterministic initials; NO remote favicon proxying (metadata leak — privacy-first divergence, deliberate) | `kiwi-app` | Documented divergence |
| F9 | Per-user remappable keyboard shortcuts + layout switcher (classic/compact/vertical-split) | `kiwi-app` prefs | |
| F10 | Rich-text WYSIWYG composer: font family/size/color/highlight, tables, emoji picker, links, inline-image resize, Excel-paste fidelity; Mailspring-idiom styling; kiwi-mail mime builder already does multipart/alternative — renderer+editor work only | `kiwi-app` composer | Sanitization gate: ammonia allowlist must cover new markup |
| F11 | Native OS notifications on new mail via Tauri notification API, driven by existing `mail-changed` events (T-157); per-account toggle; no WebSocket needed | `kiwi-app` | Lock/trust gate: no body content on lock screen when degraded/locked |
| F12 | Threads include Sent items — inline sent replies in conversation view (extends T-165) | `kiwi-mail` threading + UI | |
| F13 | Junk marking: IMAP `\Junk` flag + move-to-Junk from context menu/toolbar/bulk; deterministic only (auto-filter = Phase-7 classifier territory) | `kiwi-mail` flags + UI | |
| F14 | Email priority: X-Priority/Importance headers on compose + display | `kiwi-mail` + composer | low-effort |
| F15 | Theme schemes beyond light/dark (token system already supports); custom per-user CSS field DEFERRED — power-user, style-injection surface | `kiwi-app` themes | deferred sub-item noted |

## Exposed gap — OAuth2

`kiwi-mail` speaks XOAUTH2 but nothing acquires tokens. Spec needed:
Google auth-code + Microsoft device-code/auth-code flows; tokens live in OS
credential store (never DB); refresh handling. Independent of UI — can start now.
Tracked as T-195 (Agent 8, queued after T-183).

## Rejected — recorded with reasons

- Verbatim remote-favicon PROXYING — metadata leak; replaced by opt-in direct
  fetch (see adapted map).
- Literal multi-user webmail model — replaced by the kiwi-admin org plane.

## Adapted mappings (PLAN-APPEND-2 — full parity, phase-deferred)

Every remaining MailFlow feature gets a KIWI home. Phase 6+ items require owner
sign-off before starting; all are registered intent, not current work.

| MailFlow feature | KIWI mapping | Phase | T-task |
|---|---|---|---|
| user-management / invites / admin-panel | kiwi-admin org plane | 6 | T-215 |
| TOTP-2FA | OPTIONAL secondary unlock factor in authenticator spec (RFC-6238; asymmetric challenge-response stays primary; secrets in OS credential store) | 3 | T-216 |
| SSO / OIDC | OIDC login for admin plane | 6 | T-217 |
| recovery-email | recovery-address option in SecureMail recovery spec | 3 | T-218 |
| PWA / push | mobile authenticator app covers it (documented mapping — no new work) | 4 | — |
| WebSocket toasts | F11 native Tauri notifications | — | T-210 |
| Todoist export | generic task-export action | 8 | T-219 |
| CardDAV | CardDAV server exposing kiwi-contacts | 6/7 | T-220 |
| remote favicons | OPT-IN direct favicon fetch — no proxy, explicit consent, cached, default OFF | 8 | T-221 |
| custom per-user CSS | power-user theming (style-injection surface — needs sanitization review) | 8 | T-222 |
| multi-language i18n | locale framework + string extraction | 8 | T-223 |
| AI assistant (summarize/draft/ask) | AI-layer expansion — stays non-authoritative per SECURITY.md | 7 | T-224 |
| spam-learning | classifier (deterministic-first; AI only as explanation layer) | 7 | T-225 |

## Standing gates for the whole backlog

- AGPL: `reference/mailflow/` is read-only study — no source copying.
- Deterministic-first: rules/classifier/spam are deterministic; AI stays
  explanation-only.
- Privacy: any network call beyond configured mail servers requires explicit
  opt-in (favicon direct-fetch is the precedent).
- Phase 6+ items require owner sign-off before any work starts.

## Acceptance per feature

Deterministic tests green; IPC contract updates in `docs/contracts/`; security
review per quality-gate (esp. F1 rules side-effects, F3 outbound action); no
network calls beyond configured servers.
