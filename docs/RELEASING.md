# Releasing KIWI (alpha)

Status: **alpha, unsigned, no auto-update.** This file documents what the
release build actually does on the Windows dev host — verified by running
it, not by assuming (T-337, 2026-09-25).

## Build

```powershell
cd kiwi-app
npx tauri build        # or: npm run tauri build
```

The command runs `npm run build` (tsc typecheck + `vite build` →
`kiwi-app/dist`), then a full `cargo build --release`, then the bundlers.
On this host (Windows 11 x64, tauri-cli 2.11.x) the last verified run
succeeded end-to-end.

### Verified outputs

| Artifact | Path | Verified |
|---|---|---|
| App binary | `target\release\kiwi-app.exe` (~30 MB) | exists |
| NSIS installer | `target\release\bundle\nsis\KIWI_0.1.0_x64-setup.exe` (~7 MB) | exists |
| WiX MSI | `target\release\bundle\msi\KIWI_0.1.0_x64_en-US.msi` (~10 MB) | exists |

## Bundle config decisions (`src-tauri/tauri.conf.json`)

- `bundle.targets: ["nsis", "msi"]` — explicit Windows targets only.
  `"all"` was replaced: on a Windows host it resolved to the same set, but
  the explicit list is what we claim to support. No `dmg`/`appimage`
  declarations — those targets don't build on this host and aren't
  advertised.
- `identifier: "com.kiwi.mail"` — project identifier; no registered
  domain backs it yet (alpha).
- `publisher: "KIWI contributors"`, MPL-2.0 copyright — honest metadata,
  no invented company.
- Icons (`icons/`): **real**, verified — the shipped mark is the KIWI "K"
  gradient, not the Tauri template logo. All five listed icon files exist.
- **Version is single-sourced.** `tauri.conf.json.version` is the
  authoritative string; `src/version.ts` imports it at build time
  (`resolveJsonModule`) and falls back to `package.json` only for web-only
  dev. `kiwi-app` Cargo.toml happens to agree (`0.1.0`) but is not the
  source. Do not hardcode the version anywhere else.
- CSP is declared in `app.security.csp` and applies to the bundled webview
  (`default-src 'self'`; the permissive entry is `style-src
  'unsafe-inline'` for the inline-styled UI).

## The installers are UNSIGNED

`Get-AuthenticodeSignature` reports `NotSigned` on `kiwi-app.exe`, the
NSIS setup, and the MSI. There is no code-signing certificate on this
host and none is configured.

**Consequence:** Windows SmartScreen will warn on both installers ("Windows
protected your PC"), and some enterprise policies will refuse execution.
This is expected for alpha; users must be told to expect the prompt —
do not describe the installers as trusted or signed anywhere.

**What signing requires (owner item, not landed):** a code-signing
certificate (EV for immediate SmartScreen reputation, or OV to build
reputation over time), then either `bundle.windows.certificateThumbprint`
for a cert in the Windows store, or signtool/a signing service in CI.
MSI and NSIS each sign independently; sign `kiwi-app.exe` too.

## No auto-update in alpha

`tauri-plugin-updater` is **not** in `Cargo.toml` and no update endpoint
exists. That is deliberate: Tauri's updater requires signed update
artifacts, and signing does not exist yet (above). Shipping a half-wired
updater that can never verify would be worse than none. Upgrades are
manual: download and run the newer installer — both NSIS and MSI
install over an existing install.

When signing lands, adding the updater is: `tauri-plugin-updater` +
`createUpdaterArtifacts`, a pubkey in the config, and a hosted update
manifest — a separate task, not a config tweak.

## Alpha release checklist

1. `cargo fmt --all -- --check` · `cargo clippy --workspace --all-targets
   -- -D warnings` · `cargo test --workspace` · `npm run typecheck` ·
   `npm test` — all green.
2. Bump `version` in `kiwi-app/src-tauri/tauri.conf.json` only.
3. `cd kiwi-app && npx tauri build`.
4. Verify both artifacts exist at the paths above and record their
   `Get-AuthenticodeSignature` status (expected: `NotSigned` until the
   cert item lands).
5. State the unsigned/SmartScreen caveat in the release notes verbatim —
   the installers must never be described as signed.
