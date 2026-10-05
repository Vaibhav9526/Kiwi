/**
 * Smoke checks for the ported Mailspring recipient-field chain (T-356):
 * ParticipantsTextField → TokenizingTextField → Menu/KeyCommandsRegion.
 *
 * These pin the port's contract, not the backend:
 *  1. Existing participants render as `.token` chips (participant-primary text).
 *  2. A malformed address renders as `.token.invalid` (tokenIsValid →
 *     ContactStore.isValidContact).
 *  3. Enter commits a typed address through `onAdd` → `change` with the new
 *     Contact appended to `to` (ContactStore.parseContactsInString path).
 *  4. With no address-book backend (jsdom), completions honestly render an
 *     empty container — nothing fabricated.
 *  5. Backspace arms selection on the last token; a second Backspace removes
 *     it through `change`.
 *  6. A `core:select-all` command CustomEvent (the KeyCommandsRegion seam)
 *     selects every token.
 */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, waitFor } from "@testing-library/react";
import ParticipantsTextField from "./participants-text-field";
import { Contact } from "./ms-exports";

function participants(): {
  to: Contact[];
  cc: Contact[];
  bcc: Contact[];
  replyTo: Contact[];
} {
  return {
    to: [new Contact({ id: "c1", name: "Alice Apple", email: "alice@x.com" })],
    cc: [],
    bcc: [],
    replyTo: [],
  };
}

function inputEl(container: HTMLElement): HTMLInputElement {
  const el = container.querySelector(".tokenizing-field-input input");
  expect(el).not.toBeNull();
  return el as HTMLInputElement;
}

describe("ParticipantsTextField (Mailspring port)", () => {
  it("renders existing participants as token chips", () => {
    render(
      <ParticipantsTextField field="to" label="To" participants={participants()} change={vi.fn()} />
    );
    const chip = document.querySelector(".token .participant-primary");
    expect(chip?.textContent).toBe("Alice Apple");
  });

  it("marks malformed addresses as invalid tokens", () => {
    const p = participants();
    p.to = [new Contact({ email: "not-an-email" })];
    const { container } = render(
      <ParticipantsTextField field="to" participants={p} change={vi.fn()} />
    );
    expect(container.querySelector(".token.invalid")).not.toBeNull();
  });

  it("commits a typed address on Enter via change()", async () => {
    const change = vi.fn();
    const { container } = render(
      <ParticipantsTextField field="to" participants={participants()} change={change} />
    );
    const input = inputEl(container);
    fireEvent.change(input, { target: { value: "new@x.com" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(change).toHaveBeenCalled());
    const updates = change.mock.calls[0][0] as { to: Contact[]; cc: Contact[] };
    expect(updates.to.map((c) => c.email)).toEqual(["alice@x.com", "new@x.com"]);
    expect(updates.cc).toHaveLength(0);
  });

  it("renders honestly empty completions when the address book is unavailable", async () => {
    const { container } = render(
      <ParticipantsTextField field="to" participants={participants()} change={vi.fn()} />
    );
    const input = inputEl(container);
    fireEvent.change(input, { target: { value: "alice" } });
    await waitFor(() =>
      expect(container.querySelector(".content-container")).toHaveClass("empty")
    );
    expect(container.querySelectorAll(".content-container .item")).toHaveLength(0);
  });

  it("backspace selects the last token, then a second backspace removes it", async () => {
    const change = vi.fn();
    const { container } = render(
      <ParticipantsTextField field="to" participants={participants()} change={change} />
    );
    const input = inputEl(container);
    fireEvent.keyDown(input, { key: "Backspace" });
    expect(container.querySelector(".token.selected")).not.toBeNull();
    fireEvent.keyDown(input, { key: "Backspace" });
    await waitFor(() => expect(change).toHaveBeenCalled());
    const updates = change.mock.calls[0][0] as { to: Contact[] };
    expect(updates.to).toHaveLength(0);
  });

  it("a core:select-all command event selects every token", () => {
    const p = participants();
    p.to.push(new Contact({ email: "bob@x.com" }));
    const { container } = render(
      <ParticipantsTextField field="to" participants={p} change={vi.fn()} />
    );
    const input = inputEl(container);
    fireEvent(input, new CustomEvent("core:select-all", { bubbles: true }));
    expect(container.querySelectorAll(".token.selected")).toHaveLength(2);
  });
});
