import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function App() {
  const [status, setStatus] = useState<string>("checking…");

  useEffect(() => {
    invoke<string>("kiwi_ping")
      .then(setStatus)
      .catch((e) => setStatus(`backend error: ${e}`));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
      <h1>KIWI</h1>
      <p>Security-first email client — Phase 0 shell.</p>
      <p>
        Backend: <code>{status}</code>
      </p>
    </main>
  );
}
