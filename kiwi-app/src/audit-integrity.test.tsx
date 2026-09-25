/**
 * T-331: audit corruption must be VISIBLE. Before this, the backend emitted
 * `audit-corrupt` and no renderer handled it — a tampered `audit.jsonl` was
 * indistinguishable from an empty audit panel.
 *
 * These tests pin the honest-display rules (ui-spec §11, extended T-338):
 *  1. `auditOk: false` renders a persistent, non-dismissible security signal
 *     with the mandated wording — not a toast, not a blank panel.
 *  2. A never-checked value (`null`/absent/non-boolean) renders a neutral
 *     "unchecked" pill — it must never degrade into green, and never be
 *     silent in a way indistinguishable from verified.
 *  3. `auditOk: true` is the ONLY state that earns the "verified" pill — a
 *     real backend verdict, not a renderer assumption.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { AUDIT_CORRUPT_MESSAGE, toTrustState } from "./kiwi";
import { TrustChip } from "./components/chrome";
import { SecurityCenterView } from "./views/security-center";
import { api, IpcError } from "./ipc";

/**
 * The audit-log table is the one captioned "App audit trail" — the view also
 * renders a transport-events table, so a bare `queryByRole("table")` would
 * match the wrong (unrelated) evidence.
 */
function auditTable(): HTMLElement | null {
  return screen.queryByRole("table", { name: /app audit trail/i });
}

function status(extra: Record<string, unknown> = {}) {
  return toTrustState({
    trust: "secure",
    state: "trusted",
    score: 100,
    locked: false,
    requiredAction: "none",
    signals: [],
    sessionsObserved: 1,
    deviceId: "dev-1",
    ...extra,
  });
}

function renderCenter() {
  return render(
    <SecurityCenterView events={[]} findings={[]} demo={false} onOpenFinding={() => {}} />,
  );
}

describe("audit integrity on the security strip (T-331)", () => {
  it("shows a persistent unverified pill when the chain failed verification", async () => {
    const t = status({ auditOk: false });
    expect(t.auditOk).toBe(false);
    render(<TrustChip {...t} />);
    const pill = await screen.findByLabelText(
      `KIWI audit: ${AUDIT_CORRUPT_MESSAGE}. Activate to open the Security view.`,
    );
    expect(pill).toBeInTheDocument();
    expect(pill.getAttribute("data-audit-integrity")).toBe("corrupt");
    expect(pill.textContent).toContain("unverified");
  });

  it("renders a neutral unchecked pill when the log was never checked (never green)", () => {
    for (const t of [status(), status({ auditOk: null }), status({ auditOk: "yes" })]) {
      // Anything that is not a real boolean is "not checked" → null.
      expect(t.auditOk).toBeNull();
      const { container, unmount } = render(<TrustChip {...t} />);
      const pill = container.querySelector("[data-audit-integrity]");
      expect(pill?.getAttribute("data-audit-integrity")).toBe("unchecked");
      expect(pill?.className).toContain("unknown");
      expect(pill?.className).not.toContain("secure");
      expect(pill?.className).not.toContain("danger");
      expect(pill?.textContent).toContain("unchecked");
      unmount();
    }
  });

  it("renders a quiet verified pill only on a real backend verdict", () => {
    const t = status({ auditOk: true });
    const { container } = render(<TrustChip {...t} />);
    const pill = container.querySelector("[data-audit-integrity='ok']");
    expect(pill).not.toBeNull();
    expect(pill?.className).toContain("secure");
    expect(pill?.textContent).toContain("verified");
  });
});

describe("audit corruption in the audit view (T-331)", () => {
  it("renders the persistent integrity failure instead of the row table", async () => {
    const integrity = vi.spyOn(api, "auditIntegrity").mockResolvedValue({ state: "corrupt", auditOk: false });
    const events = vi
      .spyOn(api, "auditEvents")
      .mockRejectedValue(new IpcError("audit-corrupt", "audit log parse failed"));
    try {
      renderCenter();
      const banner = await screen.findByText(/audit integrity failure/i);
      expect(banner.closest("[data-audit-integrity='corrupt']")).not.toBeNull();
      // The mandated honest wording, verbatim.
      expect(banner.parentElement?.textContent).toContain(AUDIT_CORRUPT_MESSAGE);
      // Not a toast: an in-view role=alert region, still present after render.
      expect(banner.closest("[role='alert']")).not.toBeNull();
      // Unverified rows must NOT be presented as evidence.
      expect(auditTable()).toBeNull();
    } finally {
      integrity.mockRestore();
      events.mockRestore();
    }
  });

  it("surfaces corruption from the probe alone, before any rows are read", async () => {
    const integrity = vi.spyOn(api, "auditIntegrity").mockResolvedValue({ state: "corrupt", auditOk: false });
    const events = vi.spyOn(api, "auditEvents").mockResolvedValue([]);
    try {
      renderCenter();
      await waitFor(() => {
        expect(integrity).toHaveBeenCalled();
      });
      const banner = await screen.findByText(/audit integrity failure/i);
      expect(banner.closest("[data-audit-integrity='corrupt']")).not.toBeNull();
      // A corrupt chain suppresses the (technically readable) rows entirely.
      await waitFor(() => {
        expect(auditTable()).toBeNull();
      });
    } finally {
      integrity.mockRestore();
      events.mockRestore();
    }
  });

  it("says nothing alarming when the chain verifies", async () => {
    const integrity = vi.spyOn(api, "auditIntegrity").mockResolvedValue({ state: "ok", auditOk: true });
    const events = vi.spyOn(api, "auditEvents").mockResolvedValue([]);
    try {
      renderCenter();
      await waitFor(() => {
        expect(screen.getByText(/no audit events recorded yet/i)).toBeInTheDocument();
      });
      expect(screen.queryByText(/integrity failure/i)).toBeNull();
    } finally {
      integrity.mockRestore();
      events.mockRestore();
    }
  });
});
