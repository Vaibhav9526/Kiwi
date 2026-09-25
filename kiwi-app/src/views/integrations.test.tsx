import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountView, DeliverabilityReportView, DeliverabilityStatusView, TempMessageSummaryView, TempPollView } from "../kiwi";
import { PUBLIC_INBOX_NOTICE } from "../kiwi";
import { api, IpcError } from "../ipc";
import { DeliverabilityPanel, IntegrationsView, TempMailPanel } from "./integrations";

const account: AccountView = {
  id: "account-1",
  displayName: "Test Account",
  email: "sender@example.test",
  incomingProtocol: "imap",
  incoming: { host: "imap.example.test", port: 993, security: "tls" },
  outgoing: { host: "smtp.example.test", port: 465, security: "tls" },
  username: "sender@example.test",
  unreadCount: 0,
  trustToken: "secure",
  color: "#000000",
};

const beginView = {
  testId: "test-1",
  address: "sink@example.test",
  consentToken: "consent-1",
  consentNotice: "Consent notice",
};

const sendView = {
  testId: beginView.testId,
  queueId: "queue-1",
  notBeforeUnix: 1_700_000_001,
};

const pendingStatus: DeliverabilityStatusView = {
  testId: beginView.testId,
  analysisStatus: "analyzing",
  checksDone: 1,
  checksTotal: 2,
  ready: false,
  sent: true,
};

const readyStatus: DeliverabilityStatusView = {
  testId: beginView.testId,
  analysisStatus: "checks_ready",
  checksDone: 2,
  checksTotal: 2,
  ready: true,
  sent: true,
};

const reportView: DeliverabilityReportView = {
  testId: beginView.testId,
  scoreOursMilli: 87_000,
  scoreCompatMilli: 9_100,
  complete: true,
  reportUrl: "https://reports.example.test/result",
  subscores: { auth: 100_000 },
  tallies: { auth: { pass: 1, warn: 0, fail: 0, skip: 0, other: 0 } },
  checks: [
    {
      id: "spf",
      category: "auth",
      categoryRaw: "auth",
      status: "pass",
      title: "SPF",
      summary: "passes",
      citations: [{ kind: "standards", title: "RFC", url: "https://www.rfc-editor.org/rfc/rfc7208" }],
    },
  ],
  authFailureIds: [],
  authGate: "pass",
};

const emptyPoll: TempPollView = {
  messages: [],
  totalNew: 0,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

function summary(overrides: Partial<TempMessageSummaryView> = {}): TempMessageSummaryView {
  return {
    mailId: "mail-1",
    from: "sender@example.test",
    subject: "A message",
    excerpt: "Body",
    date: "2026-09-25",
    read: false,
    ...overrides,
  };
}

function pollWith(messages: TempMessageSummaryView[]): TempPollView {
  return { ...emptyPoll, messages, totalNew: messages.length };
}

function mockBeginAndSend(status: DeliverabilityStatusView = pendingStatus) {
  vi.spyOn(api, "integrationsDeliverabilityBegin").mockResolvedValue(beginView);
  vi.spyOn(api, "integrationsDeliverabilitySend").mockResolvedValue(sendView);
  const statusMock = vi.spyOn(api, "integrationsDeliverabilityStatus").mockResolvedValue(status);
  vi.spyOn(api, "integrationsDeliverabilityReport").mockResolvedValue(reportView);
  return { status: statusMock };
}

async function startDeliverability() {
  fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
  await waitFor(() => expect(screen.getByText(/Test id:/)).toBeInTheDocument());
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.change(screen.getByRole("combobox"), { target: { value: account.id } });
  fireEvent.click(screen.getByRole("button", { name: "Send test" }));
  await waitFor(() => expect(screen.getByText("queued")).toBeInTheDocument());
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("integrations UI", () => {
  it("shows the public inbox notice and keeps the consent checkbox gate", async () => {
    vi.spyOn(api, "integrationsTempmailPoll").mockResolvedValue(emptyPoll);
    render(<IntegrationsView accounts={[account]} mode="live" />);
    expect(screen.getByRole("note", { name: "Public inbox notice" })).toHaveTextContent(PUBLIC_INBOX_NOTICE);

    vi.spyOn(api, "integrationsDeliverabilityBegin").mockResolvedValue(beginView);
    fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
    await waitFor(() => expect(screen.getByText(/Test id:/)).toBeInTheDocument());
    const consent = screen.getByRole("checkbox");
    const send = screen.getByRole("button", { name: "Send test" });
    expect(consent).not.toBeChecked();
    expect(send).toBeDisabled();
    fireEvent.click(consent);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: account.id } });
    expect(consent).toBeChecked();
    expect(send).toBeEnabled();
  });

  it("makes fetched temp-mail links and forms click-inert", async () => {
    const poll = vi.spyOn(api, "integrationsTempmailPoll").mockResolvedValueOnce(emptyPoll).mockResolvedValueOnce(pollWith([summary()]));
    vi.spyOn(api, "integrationsTempmailCreate").mockResolvedValue({
      address: "throwaway@example.test",
      publicInboxNotice: PUBLIC_INBOX_NOTICE,
    });
    vi.spyOn(api, "integrationsTempmailFetch").mockResolvedValue({
      mailId: "mail-1",
      from: "sender@example.test",
      subject: "A message",
      date: "2026-09-25",
      html: '<a id="https-link" href="https://evil.test">HTTPS</a><a id="data-link" href="data:text/html,x">data</a><svg><a id="svg-link" href="javascript:alert(1)">SVG</a></svg><form id="temp-form"><input name="secret" /></form>',
      remoteImagesStripped: 0,
      publicInboxNotice: PUBLIC_INBOX_NOTICE,
    });
    render(<TempMailPanel live />);
    fireEvent.click(screen.getByRole("button", { name: "Create disposable address" }));
    await waitFor(() => expect(poll).toHaveBeenCalledTimes(2));
    const toggle = document.querySelector('button[aria-expanded="false"]') as HTMLButtonElement;
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByText("HTTPS")).toBeInTheDocument());
    for (const id of ["https-link", "data-link", "svg-link"]) {
      const link = document.getElementById(id) as HTMLAnchorElement;
      const event = new MouseEvent("click", { bubbles: true, cancelable: true });
      link.dispatchEvent(event);
      expect(event.defaultPrevented).toBe(true);
    }
    const form = document.getElementById("temp-form") as HTMLFormElement;
    const submit = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(submit);
    expect(submit.defaultPrevented).toBe(true);
  });

  it("keeps report and citation URLs copy-only", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    mockBeginAndSend(readyStatus);
    render(<DeliverabilityPanel accounts={[account]} live />);
    await startDeliverability();
    await waitFor(() => expect(screen.getByText(/Full report:/)).toBeInTheDocument());
    expect(screen.queryByRole("link")).toBeNull();
    const copyButtons = screen.getAllByRole("button", { name: "Copy URL" });
    expect(copyButtons).toHaveLength(2);
    fireEvent.click(copyButtons[0]);
    fireEvent.click(copyButtons[1]);
    await waitFor(() => expect(writeText).toHaveBeenNthCalledWith(1, "https://www.rfc-editor.org/rfc/rfc7208"));
    expect(writeText).toHaveBeenNthCalledWith(2, reportView.reportUrl);
  });

  it("uses one in-flight recursive timeout and honors retryAfterMs", async () => {
    vi.useFakeTimers();
    let resolveFirst: ((value: DeliverabilityStatusView) => void) | undefined;
    const first = new Promise<DeliverabilityStatusView>((resolve) => {
      resolveFirst = resolve;
    });
    const { status } = mockBeginAndSend();
    status.mockReturnValueOnce(first).mockResolvedValue(pendingStatus);
    render(<DeliverabilityPanel accounts={[account]} live />);
    fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
    await act(async () => {
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: account.id } });
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(30_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveFirst?.({ ...pendingStatus, retryAfterMs: 5_000 });
      await first;
    });
    vi.advanceTimersByTime(4_999);
    expect(status).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    await act(async () => {
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(2);
  });

  it("stops after a terminal polling error", async () => {
    vi.useFakeTimers();
    const { status } = mockBeginAndSend();
    status.mockRejectedValue(new IpcError("server-reject", "terminal"));
    render(<DeliverabilityPanel accounts={[account]} live />);
    fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
    await act(async () => {
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: account.id } });
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(120_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("alert")).toHaveTextContent("terminal");
  });

  it("invalidates pending polling when a test is reset", async () => {
    vi.useFakeTimers();
    let resolveStatus: ((value: DeliverabilityStatusView) => void) | undefined;
    const pending = new Promise<DeliverabilityStatusView>((resolve) => {
      resolveStatus = resolve;
    });
    const { status } = mockBeginAndSend();
    status.mockReturnValue(pending);
    render(<DeliverabilityPanel accounts={[account]} live />);
    fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
    await act(async () => {
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: account.id } });
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(status).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "New test" }));
    await act(async () => {
      resolveStatus?.(pendingStatus);
      await pending;
    });
    vi.advanceTimersByTime(120_000);
    expect(status).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Begin test" })).toBeInTheDocument();
  });

  it("shows malformed integration responses as terminal errors", async () => {
    vi.spyOn(api, "integrationsDeliverabilityBegin").mockRejectedValue(new IpcError("malformed-response", "bad begin"));
    render(<DeliverabilityPanel accounts={[account]} live />);
    fireEvent.click(screen.getByRole("button", { name: "Begin test" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("bad begin"));
    expect(screen.getByRole("button", { name: "Begin test" })).toBeInTheDocument();
  });
});
