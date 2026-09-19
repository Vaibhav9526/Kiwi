/**
 * Account setup wizard (T-143): live server verification
 * (kiwi_verify_server, incoming + outgoing with step detail) and creation
 * (kiwi_add_account). Secrets are sent once over local IPC, never stored or
 * logged by the UI, and cleared from component state after Add.
 */
import { useState } from "react";
import { api, IpcError } from "../ipc";
import type { VerifyResult } from "../kiwi";
import { navigate } from "../router";

const STEPS = ["Address", "Servers", "Credentials", "Verify & add"] as const;

type Security = "tls" | "starttls" | "plaintext";

function toPort(v: string, fallback: number): number {
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 && n < 65536 ? n : fallback;
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

  const emailOk = email.includes("@") && email.indexOf("@") > 0;
  const serversOk = inHost.trim().length > 0 && outHost.trim().length > 0 && /^\d+$/.test(inPort) && /^\d+$/.test(outPort);
  const plaintext = inSec === "plaintext" || outSec === "plaintext";
  const credsOk = authKind === "none" || authKind === "xoauth2" || password.length > 0;
  const canVerify = emailOk && serversOk && credsOk && (!plaintext || plaintextAck) && mode === "live";

  const authInput = () =>
    authKind === "none" || authKind === "xoauth2" ? null : { kind: authKind, secret: password };

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
          {label}: {r.ok ? "✓ ok" : "✕ failed"}
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
          Demo mode — verification and creation need the backend. Run the Tauri app for live setup.
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
        </>
      )}

      {step === 1 && (
        <>
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
              <select value={authKind} onChange={(e) => setAuthKind(e.target.value as "password" | "xoauth2" | "apop" | "none")}>
                <option value="password">Password</option>
                <option value="xoauth2">OAuth2 (token pasted, stored once)</option>
                {protocol === "pop3" && <option value="apop">APOP</option>}
                <option value="none">None</option>
              </select>
            </label>
          </p>
          {(authKind === "password" || authKind === "apop") && (
            <p>
              <label>
                {authKind === "password" ? "Password" : "APOP secret"}:{" "}
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
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>
              Secrets travel over local IPC once and land in the OS credential store — the UI never stores or logs
              them, and clears them after Add.
            </small>
          </p>
        </>
      )}

      {step === 3 && (
        <>
          <p>
            <small>
              Verify probes both servers and records the TLS observation, then Add persists the account.
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
          ← Back
        </button>
        {step < 3 && (
          <button type="button" onClick={() => setStep((s) => s + 1)} disabled={(step === 0 && !emailOk) || (step === 1 && !serversOk) || (step === 2 && !credsOk)}>
            Next →
          </button>
        )}
        {step === 3 && (
          <>
            <button type="button" onClick={() => void verify()} disabled={!canVerify || checking}>
              {checking ? "Checking…" : "Verify connection"}
            </button>
            <button type="button" className="kiwi-btn-primary" onClick={() => void add()} disabled={!canVerify || checking || !incoming?.ok || !outgoing?.ok}>
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
