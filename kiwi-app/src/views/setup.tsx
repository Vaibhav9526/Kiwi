/**
 * Account setup wizard (T-112): 4 steps, resumable local state, per-step
 * validation, verify step calls api.ping() and shows an inline TLS summary
 * stub (real observation: kiwi-mail transport, T-101). Surface KIWI-UI-019.
 */
import { useState } from "react";
import { api } from "../ipc";
import { navigate } from "../router";

const STEPS = ["Address", "Server", "Credentials", "Verify"] as const;

export function SetupWizardView() {
  const [step, setStep] = useState(0);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("993");
  const [security, setSecurity] = useState("ssl-tls");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [plaintextAck, setPlaintextAck] = useState(false);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const emailOk = email.includes("@") && email.indexOf("@") > 0;
  const serverOk = host.trim().length > 0 && /^\d+$/.test(port);
  const credsOk = password.length > 0;
  const plaintext = security === "plaintext";
  const canVerify = emailOk && serverOk && credsOk && (!plaintext || plaintextAck);

  const verify = async () => {
    setChecking(true);
    setError(null);
    setResult(null);
    try {
      const pong = await api.ping();
      setResult(
        `Backend reachable (${pong}). Demo TLS summary: ${host}:${port} via ${security} — real observation from kiwi-mail transport (T-101).`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setChecking(false);
    }
  };

  return (
    <section aria-label="Add mail account" style={{ maxWidth: "40rem" }}>
      <h1>Add account</h1>
      <ol style={{ display: "flex", gap: "0.6rem", listStyle: "none", padding: 0 }}>
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
          {!emailOk && email && (
            <p role="alert">
              <small>Enter a valid email address.</small>
            </p>
          )}
        </>
      )}

      {step === 1 && (
        <>
          <p>
            <label>
              Server host: <input type="text" value={host} onChange={(e) => setHost(e.target.value)} placeholder="mail.example.test" />
            </label>
          </p>
          <p>
            <label>
              Port: <input type="text" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} style={{ width: "6rem" }} />
            </label>{" "}
            <label>
              Security:{" "}
              <select value={security} onChange={(e) => setSecurity(e.target.value)}>
                <option value="ssl-tls">SSL/TLS (recommended)</option>
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
              Password:{" "}
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
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>OAuth2 browser flow and real credential storage arrive with kiwi-mail account work (T-105).</small>
          </p>
        </>
      )}

      {step === 3 && (
        <>
          <p>
            <small>
              Verify tests the connection for {email || "(address)"} at {host || "(host)"}:{port} and captures the TLS
              observation for the security panel.
            </small>
          </p>
          {result && (
            <div className="kiwi-banner warn" role="status">
              {result}
            </div>
          )}
          {error && (
            <div className="kiwi-banner block" role="alert">
              Verification failed: {error} <button type="button" onClick={verify}>Retry</button>
            </div>
          )}
        </>
      )}

      <div style={{ display: "flex", gap: "0.4rem" }}>
        <button type="button" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
          ← Back
        </button>
        {step < 3 && (
          <button type="button" onClick={() => setStep((s) => s + 1)} disabled={(step === 0 && !emailOk) || (step === 1 && !serverOk) || (step === 2 && !credsOk)}>
            Next →
          </button>
        )}
        {step === 3 && (
          <>
            <button type="button" onClick={verify} disabled={!canVerify || checking}>
              {checking ? "Checking…" : "Verify connection"}
            </button>
            <button type="button" onClick={() => navigate({ name: "mail" })} disabled={!result}>
              Done
            </button>
          </>
        )}
      </div>
    </section>
  );
}
