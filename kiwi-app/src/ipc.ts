/**
 * Typed Tauri IPC layer (T-112). Command names are the contract with
 * src-tauri/src/lib.rs — see docs/contracts/ui-surfaces.md §5 wiring order.
 *
 * Outside the Tauri webview (plain `vite dev` in a browser) every call throws
 * BackendUnavailableError and views fall back to local demo data, clearly
 * badged "demo". No business logic lives here — transport only.
 */
import { invoke } from "@tauri-apps/api/core";
import type { AccountInfo, TrustState } from "./kiwi";

export class BackendUnavailableError extends Error {
  constructor(command: string, cause?: unknown) {
    super(`KIWI backend unavailable for '${command}'${cause ? `: ${cause}` : ""}`);
    this.name = "BackendUnavailableError";
  }
}

/** True inside the Tauri webview; false in a plain browser (vite dev). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) throw new BackendUnavailableError(command, "not in Tauri webview");
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    throw new BackendUnavailableError(command, err);
  }
}

function asTrustState(raw: unknown): TrustState {
  if (typeof raw === "object" && raw !== null) {
    const r = raw as Record<string, unknown>;
    const trust = r["trust"];
    const locked = r["locked"];
    return {
      trust: trust === "secure" || trust === "warning" || trust === "danger" ? trust : "unknown",
      locked: locked === true,
    };
  }
  return { trust: "unknown", locked: false };
}

function asAccounts(raw: unknown): AccountInfo[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((item, i) => {
    if (typeof item !== "object" || item === null) return [];
    const r = item as Record<string, unknown>;
    if (typeof r["id"] !== "string" || typeof r["email"] !== "string") return [];
    const trust = r["trust"];
    return [
      {
        id: r["id"],
        email: r["email"],
        displayName: typeof r["displayName"] === "string" ? r["displayName"] : r["email"],
        trust: trust === "secure" || trust === "warning" || trust === "danger" ? trust : "unknown",
        unread: typeof r["unread"] === "number" ? r["unread"] : 0,
        color: typeof r["color"] === "string" ? r["color"] : ["#2563eb", "#7a5b00", "#b23a22"][i % 3],
      },
    ];
  });
}

export const api = {
  /** Health check — verifies the Rust backend is live. */
  ping(): Promise<string> {
    return call<string>("kiwi_ping");
  },
  /** Configured mail accounts (stub: [] until kiwi-mail lands). */
  async listAccounts(): Promise<AccountInfo[]> {
    return asAccounts(await call<unknown>("kiwi_list_accounts"));
  },
  /** Endpoint trust / lock state from kiwi-core (stub until Agent 2 wires it). */
  async securityStatus(): Promise<TrustState> {
    return asTrustState(await call<unknown>("kiwi_security_status"));
  },
};
