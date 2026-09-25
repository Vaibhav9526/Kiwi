/**
 * Account setup wizard (T-143, T-156): email → autoconfig discovery chain
 * (`kiwi_discover_account` via the ipc wrapper; backend IPC pending T-230 so
 * a labeled local stub fills in), server presets, credential entry, live
 * server verification (kiwi_verify_server, incoming + outgoing with step
 * detail) and creation (kiwi_add_account). Secrets are sent once over local
 * IPC, land in the OS credential store, and are cleared from component state
 * after Add — never in DB/localStorage/logs.
 */
import { useEffect, useState } from "react";
import { api, BackendUnavailableError, IpcError } from "../ipc";
import type { AutoconfigSuggestion, VerifyResult } from "../kiwi";
import { OAuth2SignIn, oauth2ProviderLabel } from "../components/oauth2";
import { navigate } from "../router";
import { Icon } from "../components/icons/index";

const STEPS = ["Address", "Servers", "Credentials", "Verify & add"] as const;

/** Transient reconfigure handoff (Settings → wizard), never secrets. */
export const EDIT_HANDOFF_KEY = "kiwi.editAccount";

type Security = "tls" | "starttls" | "plaintext";

function toPort(v: string, fallback: number): number {
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 && n < 65536 ? n : fallback;
}

/**
 * Local discovery stub (T-156): used until `kiwi_discover_account` lands in
 * the backend (T-230). Provider presets for the two big hosts plus a generic
 * `mail.<domain>` guess — always TLS, always password, always labeled
 * `local-guess` so the verify step (not the guess) is the source of truth.
 */
export function localAutoconfigGuess(email: string): AutoconfigSuggestion | null {
  const at = email.lastIndexOf("@");
  if (at <= 0) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  if (!domain || domain.includes(" ") || !domain.includes(".")) return null;
  const user = email.trim();
  if (domain === "gmail.com" || domain === "googlemail.com") {
    return {
      source: "local-guess", protocol: "imap",
      inHost: "imap.gmail.com", inPort: 993, inSec: "tls",
      outHost: "smtp.gmail.com", outPort: 465, outSec: "tls",
      username: user, authKind: "password",
    };
  }
  if (domain === "outlook.com" || domain === "hotmail.com" || domain === "live.com" || domain === "office365.com") {
    return {
      source: "local-guess", protocol: "imap",
      inHost: "outlook.office365.com", inPort: 993, inSec: "tls",
      outHost: "smtp.office365.com", outPort: 587, outSec: "starttls",
      username: user, authKind: "password",
    };
  }
  return {
    source: "local-guess", protocol: "imap",
    inHost: `mail.${domain}`, inPort: 993, inSec: "tls",
    outHost: `mail.${domain}`, outPort: 465, outSec: "tls",
    username: user, authKind: "password",
  };
}

export function SetupWizardView({ mode, onAdded }: { mode: "live" | "demo"; onAdded: () => void }) {
  const [step, setStep] = useState(0);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [protocol, setProtocol] = useState<"imap" | "pop3">("imap");
  const [inHost, setInHost] = useState("");
  const [inPort, setInPort] = useState("993");
  const [inSec, setInSec] = useState<Security>("tls");
  const [outHost, setOutHost] = useState("");
  const [outPort, setOutPort] = useState("465");
  const [outSec, setOutSec] = useState<Security>("tls");
  const [username, setUsername] = useState("");
  const [authKind, setAuthKind] = useState<"password" | "xoauth2" | "apop" | "none">("password");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [plaintextAck, setPlaintextAck] = useState(false);
  const [checking, setChecking] = useState(false);
  const [incoming, setIncoming] = useState<VerifyResult | null>(null);
  const [outgoing, setOutgoing] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState(false);
  const [lookingUp, setLookingUp] = useState(false);
  const [lookupNote, setLookupNote] = useState<string | null>(null);
  const [reconfiguring, setReconfiguring] = useState<string | null>(null);
  // OAuth2 wizard branch (T-243): the discovery suggestion carries an
  // `oauth2` spec (provider + grant kind); a completed grant leaves its
  // ticket here for `kiwi_add_account`'s `oauth2Ticket` field.
  const [oauth2Spec, setOauth2Spec] = useState<{ provider: string; grant: string } | null>(null);
  const [oauth2Ticket, setOauth2Ticket] = useState<string | null>(null);
  const [pasteToken, setPasteToken] = useState(false);

  // Reconfigure handoff: Settings stores server fields (never secrets) under
  // EDIT_HANDOFF_KEY; the wizard prefills and consumes it once.
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(EDIT_HANDOFF_KEY);
      if (!raw) return;
      window.localStorage.removeItem(EDIT_HANDOFF_KEY);
      const h = JSON.parse(raw) as Record<string, unknown>;
      const s = (v: unknown) => (typeof v === "string" ? v : "");
      if (!s(h["email"])) return;
      setEmail(s(h["email"]));
      if (s(h["displayName"])) setDisplayName(s(h["displayName"]));
      if (h["protocol"] === "pop3" || h["protocol"] === "imap") setProtocol(h["protocol"]);
      if (s(h["inHost"])) setInHost(s(h["inHost"]));
      if (s(h["outHost"])) setOutHost(s(h["outHost"]));
      if (typeof h["inPort"] === "number") setInPort(String(h["inPort"]));
      if (typeof h["outPort"] === "number") setOutPort(String(h["outPort"]));
      if (h["inSec"] === "tls" || h["inSec"] === "starttls" || h["inSec"] === "plaintext") setInSec(h["inSec"]);
      if (h["outSec"] === "tls" || h["outSec"] === "starttls" || h["outSec"] === "plaintext") setOutSec(h["outSec"]);
      if (s(h["username"])) setUsername(s(h["username"]));
      setReconfiguring(s(h["email"]));
      setStep(1);
    } catch {
      // Corrupt handoff — start blank.
    }
  }, []);

  const emailOk = email.includes("@") && email.indexOf("@") > 0;
  const serversOk = inHost.trim().length > 0 && outHost.trim().length > 0 && /^\d+$/.test(inPort) && /^\d+$/.test(outPort);
  const plaintext = inSec === "plaintext" || outSec === "plaintext";
  // xoauth2 is satisfied by a completed grant ticket or a pasted token —
  // never by nothing (a null auth would persist AuthRef::None).
  const credsOk =
    authKind === "none" ||
    (authKind === "xoauth2" ? oauth2Ticket !== null || password.length > 0 : password.length > 0);
  const canVerify =
    emailOk && serversOk && credsOk && (!plaintext || plaintextAck) && mode === "live" && !oauth2Ticket;

  const authInput = () => {
    if (authKind === "none") return null;
    if (authKind === "xoauth2") {
      return oauth2Ticket
        ? { kind: "xoauth2", oauth2Ticket }
        : { kind: "xoauth2", secret: password };
    }
    return { kind: authKind, secret: password };
  };

  const applySuggestion = (s: AutoconfigSuggestion, note: string) => {
    setProtocol(s.protocol);
    setInHost(s.inHost);
    setInPort(String(s.inPort));
    setInSec((s.inSec === "starttls" || s.inSec === "plaintext" ? s.inSec : "tls") as Security);
    setOutHost(s.outHost);
    setOutPort(String(s.outPort));
    setOutSec((s.outSec === "starttls" || s.outSec === "plaintext" ? s.outSec : "tls") as Security);
    if (s.username) setUsername(s.username);
    if (s.authKind === "apop" && s.protocol === "pop3") setAuthKind("apop");
    else if (s.authKind === "none" || s.authKind === "xoauth2") setAuthKind("xoauth2");
    else setAuthKind("password");
    // OAuth2 spec rides along with XOAUTH2 suggestions — the Credentials
    // step renders the provider sign-in instead of a token box.
    setOauth2Spec(s.oauth2 ?? null);
    setOauth2Ticket(null);
    setPasteToken(false);
    // A new lookup invalidates earlier probe results.
    setIncoming(null);
    setOutgoing(null);
    setAdded(false);
    setLookupNote(note);
  };

  /** Discovery chain: backend IPC first, labeled local stub on any failure. */
  const lookup = async () => {
    if (!emailOk) return;
    setLookingUp(true);
    setLookupNote(null);
    try {
      const found = await api.lookupAutoconfig(email.trim());
      if (found) {
        applySuggestion(found, `Settings filled from ${found.source} discovery. Review on the next step, then Verify.`);
        return;
      }
      const guess = localAutoconfigGuess(email.trim());
      if (guess) {
        applySuggestion(guess, "The server found nothing for this address — filled a local guess instead. Verify before adding.");
      } else {
        setLookupNote("No settings found — enter the servers manually on the next step.");
      }
    } catch (e) {
      // Backend IPC absent (or lookup failed): the local stub keeps the
      // wizard usable. The verify step remains the source of truth.
      const guess = localAutoconfigGuess(email.trim());
      if (guess) {
        const why =
          e instanceof BackendUnavailableError
            ? "Autoconfig IPC is not in the backend yet — filled a local guess instead."
            : `Discovery failed (${e instanceof Error ? e.message : String(e)}) — filled a local guess instead.`;
        applySuggestion(guess, `${why} Verify before adding.`);
      } else {
        setLookupNote(
          e instanceof BackendUnavailableError
            ? "Autoconfig IPC is not in the backend yet and no guess fits — enter the servers manually."
            : `Discovery failed (${e instanceof Error ? e.message : String(e)}) — enter the servers manually.`,
        );
      }
    } finally {
      setLookingUp(false);
    }
  };

  /** One-click secure presets — TLS everywhere unless STARTTLS is wanted. */
  const applyPreset = (kind: "tls" | "starttls") => {
    if (kind === "tls") {
      setInSec("tls");
      setOutSec("tls");
      if (protocol === "imap") setInPort("993");
      else setInPort("995");
      setOutPort("465");
    } else {
      // STARTTLS required-upgrade (fail-closed server-side); ports are the
      // plaintext-then-upgrade submission ports.
      setInSec("starttls");
      setOutSec("starttls");
      if (protocol === "imap") setInPort("143");
      else setInPort("110");
      setOutPort("587");
    }
    setIncoming(null);
    setOutgoing(null);
    setAdded(false);
  };

  const verify = async () => {
    setChecking(true);
    setError(null);
    setIncoming(null);
    setOutgoing(null);
    try {
      const user = username.trim() || email.trim();
      const [inc, out] = await Promise.all([
        api.verifyServer({
          protocol,
          server: { host: inHost.trim(), port: toPort(inPort, 993), security: inSec },
          username: user,
          auth: authInput(),
          acceptInvalidCerts: false,
        }),
        api.verifyServer({
          protocol: "smtp",
          server: { host: outHost.trim(), port: toPort(outPort, 465), security: outSec },
          username: user,
          auth: authInput(),
          acceptInvalidCerts: false,
        }),
      ]);
      setIncoming(inc);
      setOutgoing(out);
    } catch (e) {
      setError(e instanceof IpcError ? `${e.code}: ${e.message}` : e instanceof Error ? e.message : String(e));
    } finally {
      setChecking(false);
    }
  };

  const add = async () => {
    setChecking(true);
    setError(null);
    try {
      const user = username.trim() || email.trim();
      await api.addAccount({
        displayName: displayName.trim() || email.trim(),
        email: email.trim(),
        incomingProtocol: protocol,
        incoming: { host: inHost.trim(), port: toPort(inPort, 993), security: inSec },
        outgoing: { host: outHost.trim(), port: toPort(outPort, 465), security: outSec },
        username: user,
        incomingAuth: authInput(),
        outgoingAuth: authInput(),
        acceptInvalidCerts: false,
      });
      setPassword("");
      setOauth2Ticket(null); // consumed by the backend on a successful add
      setAdded(true);
      onAdded();
    } catch (e) {
      setError(e instanceof IpcError ? `${e.code}: ${e.message}` : e instanceof Error ? e.message : String(e));
    } finally {
      setChecking(false);
    }
  };

  const renderResult = (label: string, r: VerifyResult | null) => {
    if (!r) return null;
    return (
      <div className={`kiwi-banner ${r.ok ? "warn" : "block"}`} role="status">
        <strong>
          {label}: <Icon name={r.ok ? "check" : "close"} size={10} /> {r.ok ? "ok" : "failed"}
        </strong>
        <ul>
          {r.steps.map((s) => (
            <li key={s.stage}>
              <small>
                {s.stage}: {s.ok ? "ok" : `FAILED — ${s.detail}`}
              </small>
            </li>
          ))}
        </ul>
        {r.findings.length > 0 && (
          <p>
            <small>
              {r.findings.length} finding(s) recorded from this probe — see Security.
            </small>
          </p>
        )}
      </div>
    );
  };

  return (
    <section aria-label="Add mail account" style={{ maxWidth: "42rem" }}>
      <h1>Add account</h1>
      {mode === "demo" && (
        <div className="kiwi-banner warn" role="status">
          Demo mode — verification and creation need the backend. Discovery falls back to a labeled local guess; run
          the Tauri app for live setup.
        </div>
      )}
      {reconfiguring && (
        <div className="kiwi-banner warn" role="status">
          Reconfiguring {reconfiguring}: servers prefilled (no secret carried over). Verify, Add, then remove the old
          entry in Settings → Accounts.
        </div>
      )}
      <ol style={{ display: "flex", gap: "0.6rem", listStyle: "none", padding: 0, flexWrap: "wrap" }}>
        {STEPS.map((s, i) => (
          <li key={s} aria-current={i === step ? "step" : undefined} style={{ fontWeight: i === step ? 700 : 400 }}>
            {i + 1}. {s}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <>
          <p>
            <label>
              Email address: <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
            </label>
          </p>
          <p>
            <label>
              Display name: <input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </label>
          </p>
          <p>
            <label>
              Protocol:{" "}
              <select value={protocol} onChange={(e) => setProtocol(e.target.value as "imap" | "pop3")}>
                <option value="imap">IMAP</option>
                <option value="pop3">POP3</option>
              </select>
            </label>
          </p>
          {!emailOk && email && (
            <p role="alert">
              <small>Enter a valid email address.</small>
            </p>
          )}
          <p>
            <button type="button" onClick={() => void lookup()} disabled={!emailOk || lookingUp}>
              {lookingUp ? "Looking up…" : "Look up settings"}
            </button>{" "}
            <small style={{ color: "var(--kiwi-text-secondary)" }}>
              Autoconfig discovery (ISPDB → server config → MX guess) fills the next step.
            </small>
          </p>
          {lookupNote && (
            <div className="kiwi-banner warn" role="status">
              <small>{lookupNote}</small>
            </div>
          )}
        </>
      )}

      {step === 1 && (
        <>
          <p>
            <button type="button" onClick={() => applyPreset("tls")}>
              SSL/TLS defaults
            </button>{" "}
            <button type="button" onClick={() => applyPreset("starttls")}>
              STARTTLS defaults
            </button>{" "}
            <small style={{ color: "var(--kiwi-text-secondary)" }}>
              Presets set ports + security only — hosts are never overwritten.
            </small>
          </p>
          <h2>Incoming ({protocol.toUpperCase()})</h2>
          <p>
            <label>
              Host: <input type="text" value={inHost} onChange={(e) => setInHost(e.target.value)} placeholder="mail.example.test" />
            </label>{" "}
            <label>
              Port: <input type="text" inputMode="numeric" value={inPort} onChange={(e) => setInPort(e.target.value)} style={{ width: "6rem" }} />
            </label>{" "}
            <label>
              Security:{" "}
              <select value={inSec} onChange={(e) => setInSec(e.target.value as Security)}>
                <option value="tls">SSL/TLS (recommended)</option>
                <option value="starttls">STARTTLS</option>
                <option value="plaintext">Plaintext (not recommended)</option>
              </select>
            </label>
          </p>
          <h2>Outgoing (SMTP)</h2>
          <p>
            <label>
              Host: <input type="text" value={outHost} onChange={(e) => setOutHost(e.target.value)} placeholder="mail.example.test" />
            </label>{" "}
            <label>
              Port: <input type="text" inputMode="numeric" value={outPort} onChange={(e) => setOutPort(e.target.value)} style={{ width: "6rem" }} />
            </label>{" "}
            <label>
              Security:{" "}
              <select value={outSec} onChange={(e) => setOutSec(e.target.value as Security)}>
                <option value="tls">SSL/TLS (recommended)</option>
                <option value="starttls">STARTTLS</option>
                <option value="plaintext">Plaintext (not recommended)</option>
              </select>
            </label>
          </p>
          {plaintext && (
            <div className="kiwi-banner block" role="alert">
              <label>
                <input type="checkbox" checked={plaintextAck} onChange={(e) => setPlaintextAck(e.target.checked)} /> I
                understand plaintext sends credentials and mail unencrypted. This account will show a persistent
                danger banner until upgraded.
              </label>
            </div>
          )}
        </>
      )}

      {step === 2 && (
        <>
          <p>
            <label>
              Username (defaults to email):{" "}
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder={email || "user@example.test"} />
            </label>
          </p>
          <p>
            <label>
              Auth:{" "}
              <select
                value={authKind}
                onChange={(e) => {
                  const k = e.target.value as "password" | "xoauth2" | "apop" | "none";
                  setAuthKind(k);
                  if (k !== "xoauth2") setOauth2Ticket(null);
                }}
              >
                <option value="password">Password</option>
                <option value="xoauth2">OAuth2 (sign-in grant or pasted token)</option>
                {protocol === "pop3" && <option value="apop">APOP</option>}
                <option value="none">None</option>
              </select>
            </label>
          </p>
          {authKind === "xoauth2" && oauth2Spec && !pasteToken && (
            <>
              <OAuth2SignIn
                provider={oauth2Spec.provider}
                email={email.trim() || undefined}
                onDone={(ticket) => setOauth2Ticket(ticket)}
              />
              <p>
                <small>
                  <button type="button" onClick={() => setPasteToken(true)}>
                    Paste an OAuth2 token instead
                  </button>{" "}
                  — for advanced setups; the sign-in flow above is recommended.
                </small>
              </p>
            </>
          )}
          {(authKind === "password" ||
            authKind === "apop" ||
            (authKind === "xoauth2" && (pasteToken || !oauth2Spec))) && (
            <p>
              <label>
                {authKind === "password" ? "Password" : authKind === "apop" ? "APOP secret" : "OAuth2 token"}:{" "}
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />{" "}
                <button type="button" onClick={() => setShowPassword((s) => !s)} aria-pressed={showPassword}>
                  {showPassword ? "Hide" : "Show"}
                </button>
              </label>
            </p>
          )}
          {oauth2Ticket && (
            <div className="kiwi-banner warn" role="status">
              <small>
                Signed in via {oauth2Spec ? oauth2ProviderLabel(oauth2Spec.provider) : "the provider"} — the grant is
                bound to this wizard. Continue to Verify &amp; add.
              </small>
            </div>
          )}
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>
              Secrets travel over local IPC once and land in the <strong>OS credential store</strong> — never in the
              mail DB, never in localStorage, never in logs. The UI clears them from memory right after Add.
            </small>
          </p>
        </>
      )}

      {step === 3 && (
        <>
          <p>
            <small>
              {oauth2Ticket
                ? "The provider grant already authorizes these servers — Add persists the account and binds the stored credential."
                : "Verify probes both servers and records the TLS observation, then Add persists the account."}
            </small>
          </p>
          {renderResult("Incoming", incoming)}
          {renderResult("Outgoing", outgoing)}
          {error && (
            <div className="kiwi-banner block" role="alert">
              {error} <button type="button" onClick={() => void verify()}>Retry</button>
            </div>
          )}
          {added && (
            <div className="kiwi-banner warn" role="status">
              Account added.
            </div>
          )}
        </>
      )}

      <div style={{ display: "flex", gap: "0.4rem" }}>
        <button type="button" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
          <Icon name="arrow-left" size={11} /> Back
        </button>
        {step < 3 && (
          <button type="button" onClick={() => setStep((s) => s + 1)} disabled={(step === 0 && !emailOk) || (step === 1 && !serversOk) || (step === 2 && !credsOk)}>
            Next <Icon name="arrow-right" size={11} />
          </button>
        )}
        {step === 3 && !oauth2Ticket && (
          <button type="button" onClick={() => void verify()} disabled={!canVerify || checking}>
            {checking ? "Checking…" : "Verify connection"}
          </button>
        )}
        {step === 3 && (
          <>
            <button
              type="button"
              className="kiwi-btn-primary"
              onClick={() => void add()}
              disabled={
                checking ||
                (oauth2Ticket ? !credsOk : !canVerify || !incoming?.ok || !outgoing?.ok)
              }
            >
              Add account
            </button>
            <button type="button" onClick={() => navigate({ name: "mail" })} disabled={!added}>
              Done
            </button>
          </>
        )}
      </div>
    </section>
  );
}
