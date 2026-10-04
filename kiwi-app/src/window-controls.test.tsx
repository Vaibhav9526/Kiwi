/**
 * Window caption controls on the undecorated main window
 * (`decorations: false`). The point of these tests is the wiring that is easy
 * to break silently:
 *  1. outside the Tauri webview the cluster renders NOTHING (vite dev / demo
 *     build have no window to control — no dead buttons);
 *  2. in the webview it renders min / max-restore / close, each calling the
 *     matching Tauri window command;
 *  3. the cluster opts out of the titlebar drag region, so a mousedown on a
 *     caption button is a click, never a window drag;
 *  4. close goes through `close()` — which emits CloseRequested, the same path
 *     the native X used — so `tray::handle_window_event` still decides
 *     hide-vs-quit. No `exit()` anywhere.
 *  5. the max/restore glyph tracks real maximize state (including maximizes
 *     that did not come from our own button).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { WindowControls } from "./components/window-controls";

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: vi.fn(),
}));

const minimize = vi.fn();
const toggleMaximize = vi.fn();
const close = vi.fn();
const isMaximized = vi.fn();
const onResized = vi.fn();

const unlisten = vi.fn();

function enterTauri(on: boolean) {
  if (on) (window as unknown as Record<string, unknown>)["__TAURI_INTERNALS__"] = {};
  else delete (window as unknown as Record<string, unknown>)["__TAURI_INTERNALS__"];
}

beforeEach(() => {
  minimize.mockResolvedValue(undefined);
  toggleMaximize.mockResolvedValue(undefined);
  close.mockResolvedValue(undefined);
  isMaximized.mockResolvedValue(false);
  onResized.mockResolvedValue(unlisten);
  vi.mocked(getCurrentWindow).mockReturnValue({
    minimize,
    toggleMaximize,
    close,
    isMaximized,
    onResized,
  } as unknown as ReturnType<typeof getCurrentWindow>);
  enterTauri(true);
});

afterEach(() => {
  enterTauri(false);
});

function cluster(): HTMLElement {
  return screen.getByRole("group", { name: "Window controls" });
}

describe("window caption controls", () => {
  it("renders nothing outside the Tauri webview", () => {
    enterTauri(false);
    const { container } = render(<WindowControls />);
    expect(container).toBeEmptyDOMElement();
    expect(getCurrentWindow).not.toHaveBeenCalled();
  });

  it("renders min, max-restore and close in the webview", () => {
    render(<WindowControls />);
    expect(screen.getByLabelText("Minimize")).toBeInTheDocument();
    expect(screen.getByLabelText("Maximize")).toBeInTheDocument();
    expect(screen.getByLabelText("Close")).toBeInTheDocument();
  });

  it("opts out of the titlebar drag region so buttons receive clicks", () => {
    render(<WindowControls />);
    // tao's drag.js treats the literal string "false" as "drag blocked here and
    // for ancestors"; the parent .em-titlebar keeps its own drag region.
    expect(cluster().getAttribute("data-tauri-drag-region")).toBe("false");
  });

  it("minimizes, toggles maximize, and closes through the Tauri window API", async () => {
    render(<WindowControls />);
    fireEvent.click(screen.getByLabelText("Minimize"));
    fireEvent.click(screen.getByLabelText("Maximize"));
    fireEvent.click(screen.getByLabelText("Close"));
    expect(minimize).toHaveBeenCalledTimes(1);
    expect(toggleMaximize).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("swaps the max glyph when the window is maximized", async () => {
    isMaximized.mockResolvedValue(true);
    render(<WindowControls />);
    expect(await screen.findByLabelText("Restore")).toBeInTheDocument();
    expect(screen.queryByLabelText("Maximize")).not.toBeInTheDocument();
  });

  it("follows a maximize that came from outside the cluster (snap / Win+Up)", async () => {
    // Install the capturing listener BEFORE render — the effect subscribes once
    // on mount, so swapping the mock afterwards would never re-subscribe.
    let emit: ((e: unknown) => void) | undefined;
    onResized.mockImplementation(async (handler: (e: unknown) => void) => {
      emit = handler;
      return unlisten;
    });
    render(<WindowControls />);
    await screen.findByLabelText("Maximize");
    await waitFor(() => expect(emit).toBeDefined());
    // The user snapped the window: the window resized, and we are maximized.
    isMaximized.mockResolvedValue(true);
    emit?.({ event: "tauri://resize", id: 0, payload: { width: 1920, height: 1080 } });
    expect(await screen.findByLabelText("Restore")).toBeInTheDocument();
  });

  it("unsubscribes the resize listener on unmount", async () => {
    const { unmount } = render(<WindowControls />);
    await waitFor(() => expect(onResized).toHaveBeenCalled());
    unmount();
    expect(unlisten).toHaveBeenCalled();
  });

  it("keeps the other buttons alive when one command rejects", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    minimize.mockRejectedValue(new Error("minimize refused"));
    render(<WindowControls />);
    fireEvent.click(screen.getByLabelText("Minimize"));
    fireEvent.click(screen.getByLabelText("Close"));
    await waitFor(() => expect(close).toHaveBeenCalledTimes(1));
    expect(warn).toHaveBeenCalled();
  });
});
