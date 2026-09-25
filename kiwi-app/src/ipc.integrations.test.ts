import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { api, BackendUnavailableError, IpcError } from "./ipc";
import { PUBLIC_INBOX_NOTICE } from "./kiwi";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockedInvoke = vi.mocked(invoke);

const pollPayload = {
  messages: [],
  totalNew: 0,
  address: "throwaway@example.test",
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const statusPayload = {
  testId: "test-1",
  analysisStatus: "analyzing",
  checksDone: 1,
  checksTotal: 2,
  ready: false,
  sent: true,
  consentConsumed: true,
};

beforeEach(() => {
  (window as unknown as Record<string, unknown>)["__TAURI_INTERNALS__"] = {};
});

afterEach(() => {
  delete (window as unknown as Record<string, unknown>)["__TAURI_INTERNALS__"];
});

describe("integrations IPC transport", () => {
  it("rejects commands outside the Tauri webview", async () => {
    delete (window as unknown as Record<string, unknown>)["__TAURI_INTERNALS__"];
    await expect(api.integrationsTempmailPoll()).rejects.toBeInstanceOf(BackendUnavailableError);
    expect(mockedInvoke).not.toHaveBeenCalled();
  });

  it("turns a decode failure into a malformed-response error", async () => {
    mockedInvoke.mockResolvedValue({ ...pollPayload, messages: "not-an-array" });
    await expect(api.integrationsTempmailPoll()).rejects.toMatchObject({
      name: "IpcError",
      code: "malformed-response",
    });
    mockedInvoke.mockResolvedValue({ ...pollPayload, publicInboxNotice: "paraphrased" });
    await expect(api.integrationsTempmailPoll()).rejects.toBeInstanceOf(IpcError);
    mockedInvoke.mockResolvedValue({ ...statusPayload, checksDone: 9 });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({
      code: "malformed-response",
    });
  });

  it("passes a decoded response through untouched", async () => {
    mockedInvoke.mockResolvedValue(pollPayload);
    await expect(api.integrationsTempmailPoll()).resolves.toEqual(pollPayload);
    expect(mockedInvoke).toHaveBeenCalledWith("kiwi_integrations_tempmail_poll", undefined);
    mockedInvoke.mockResolvedValue(statusPayload);
    await expect(api.integrationsDeliverabilityStatus("test-1")).resolves.toEqual(statusPayload);
    expect(mockedInvoke).toHaveBeenCalledWith("kiwi_integrations_deliverability_status", { testId: "test-1" });
  });

  it("reads a rate-limit delay only from the structured hint field", async () => {
    mockedInvoke.mockRejectedValue({ code: "rate-limited", message: "provider rate-limited", retryAfterMs: 5_000 });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({
      code: "rate-limited",
      retryAfterMs: 5_000,
    });
    mockedInvoke.mockRejectedValue({ code: "rate-limited", message: "rate limited", retry_after_ms: 7_000 });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({ retryAfterMs: 7_000 });
  });

  it("does not scrape a delay out of the human-readable message", async () => {
    mockedInvoke.mockRejectedValue({ code: "rate-limited", message: "provider rate-limited; retry after 5000 ms" });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({
      code: "rate-limited",
      retryAfterMs: undefined,
    });
    mockedInvoke.mockRejectedValue({ code: "rate-limited", message: "retry after 5000 ms", retryAfterMs: -1 });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({ retryAfterMs: undefined });
    mockedInvoke.mockRejectedValue({ code: "rate-limited", message: "rate limited", retryAfterMs: 1e9 });
    await expect(api.integrationsDeliverabilityStatus("test-1")).rejects.toMatchObject({
      retryAfterMs: 60 * 60 * 1000,
    });
  });

  it("normalizes a non-object backend failure", async () => {
    mockedInvoke.mockRejectedValue(new Error("pipe closed"));
    await expect(api.integrationsTempmailPoll()).rejects.toBeInstanceOf(BackendUnavailableError);
  });
});
