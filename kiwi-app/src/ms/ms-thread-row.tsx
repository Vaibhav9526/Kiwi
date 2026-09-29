// KIWI row composition for the ported Mailspring list-item layer.
// `msRowEntry` adapts one mailbox row (MessageEnvelope flat row or Thread
// group row) into `{item, itemProps}` for `ListTabularRows`:
//   item       → MsThread view-model from ./ms-thread factories
//   itemProps  → .em-row class/id/role/aria + rowProps (drag/ctx/keys)
//   columns    → KIWI_ROW_COLUMNS below (ported narrow `Item` column plus
//                KIWI's Pick dot+checkbox, Avatar, Marks and Quick overlay)
// All visual contract hooks (.em-row, .em-dot, .em-row-check, .em-avatar,
// .em-row-acct, .em-thread-badge, .em-quick) are emitted here so the
// smoke/stress selectors keep resolving.
import React from "react";
import type { MouseEvent as ReactMouseEvent } from "react";
import type { MessageEnvelope } from "../kiwi";
import type { Thread } from "../threading";
import { severityLabel } from "../kiwi";
import { navigate } from "../router";
import { ListTabularColumn } from "./ms-list-tabular";
import type { ListTabularRowsProps } from "./ms-list-tabular";
import { Narrow } from "./ms-thread-list-columns";
import { ThreadArchiveQuickAction, ThreadTrashQuickAction } from "./ms-thread-list-quick-actions";
import { InjectedComponentSet } from "./ms-injected-component";
import { threadAriaLabel } from "./ms-thread-list-aria-utils";
import { msThreadFromEnvelope, msThreadFromThread } from "./ms-thread";
import type { MsKiwiRow, MsThread } from "./ms-thread";
import { IconCheck, IconChevronDown, IconClose } from "../components/shell-icons";

/** Row height — the ported rows are absolutely positioned inside each
 *  group's `.list-rows` block (vendor metrics: top = idx * itemHeight). */
export const MS_ROW_HEIGHT = 72;

export type MsRowEntry =
  | { kind: "msg"; m: MessageEnvelope }
  | { kind: "thread"; t: Thread };

/** itemProps for the ported ListTabularItem (see ms-list-tabular-item). */
export interface MsRowItemProps {
  className?: string;
  role?: string;
  id?: string;
  ariaSelected?: boolean;
  ariaLabel?: string;
  /** Spread onto the inner `.list-item em-row` element (drag/ctx/keys). */
  rowProps?: React.HTMLAttributes<HTMLElement>;
}

/** Everything the row needs from the mailbox view (state + callbacks). */
export interface MsRowViewCtx {
  folder: string;
  draftsView: boolean;
  currentId?: string;
  picked: string[];
  armedDelId: string | null;
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
  onArmTrash: (rowId: string) => void;
  onDisarmTrash: () => void;
  onRowContext: (e: ReactMouseEvent, ids: string[]) => void;
  /** Per-row account chip for aggregate views (mailbox owns the rule). */
  acctTagFor?: (entry: MsRowEntry) => { label: string; color: string } | undefined;
  /** Avatar helpers stay in mailbox.tsx (avatarTint/senderName). */
  avatarFor: (seed: string) => { initial: string; color: string };
}

/* ------------------------- KIWI extra columns ------------------------- */

const cPick = new ListTabularColumn({
  name: "Pick",
  resolver: (thread: MsThread) => {
    const k = thread.__kiwi;
    return (
      <span className="em-row-pick">
        <span className={`em-dot${thread.unread ? " is-unread" : ""}`} aria-hidden="true" />
        <input
          type="checkbox"
          className="em-row-check"
          data-checked={k.isPicked}
          checked={k.isPicked}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => {
            e.stopPropagation();
            k.onPick(e.nativeEvent instanceof MouseEvent && e.nativeEvent.shiftKey);
          }}
          aria-label={
            k.ids.length > 1
              ? `Select all ${k.ids.length} messages in conversation ${thread.subject}`
              : `Select message: ${thread.subject}`
          }
        />
      </span>
    );
  },
});

const cAvatar = new ListTabularColumn({
  name: "Avatar",
  resolver: (thread: MsThread) => {
    const a = thread.__kiwi.avatar;
    return (
      <span className="em-avatar" aria-hidden="true" style={{ background: a.color }}>
        {a.initial}
      </span>
    );
  },
});

const cMarks = new ListTabularColumn({
  name: "Marks",
  resolver: (thread: MsThread) => {
    const k = thread.__kiwi;
    const count = thread.__messages.length;
    return (
      <span className="em-row-marks">
        {k.acctTag && (
          <span
            className="em-row-acct"
            title={`Account: ${k.acctTag.label}`}
            aria-label={`Account ${k.acctTag.label}`}
            style={{
              borderColor: k.acctTag.color,
              // A25 UI-sweep: avatar tints are mid-tone fill colors — as
              // 10px text they fail AA hard (orange ≈1.9:1). Keep the hue
              // on the border; mix the label toward theme text for legibility.
              color: `color-mix(in srgb, ${k.acctTag.color} 55%, var(--kiwi-ms-text, #231f20))`,
            }}
          >
            {k.acctTag.label}
          </span>
        )}
        {count > 1 && (
          <span
            className="em-thread-badge"
            title={`${count} messages in this conversation`}
            aria-label={`${count} messages`}
          >
            {count}
            <IconChevronDown size={9} />
          </span>
        )}
      </span>
    );
  },
});

const cQuick = new ListTabularColumn({
  name: "Quick",
  resolver: (thread: MsThread) => {
    const k = thread.__kiwi;
    return (
      <span className="em-quick" role="toolbar" aria-label={`Quick actions for: ${thread.subject}`}>
        {k.confirmDel ? (
          <>
            <button
              type="button"
              className="em-iconbtn"
              onClick={(e) => {
                e.stopPropagation();
                k.onDelete();
              }}
              title="Confirm delete"
              aria-label={`Confirm delete: ${thread.subject}`}
            >
              <IconCheck size={13} />
            </button>
            <button
              type="button"
              className="em-iconbtn"
              onClick={(e) => {
                e.stopPropagation();
                k.onDisarmTrash();
              }}
              title="Keep message"
              aria-label="Keep message"
            >
              <IconClose size={11} />
            </button>
          </>
        ) : (
          <InjectedComponentSet
            inline={true}
            containersRequired={false}
            matching={{ role: "ThreadListQuickAction" }}
            className="thread-injected-quick-actions"
            exposedProps={{ thread }}
          >
            <ThreadTrashQuickAction key="thread-trash-quick-action" thread={thread} />
            <ThreadArchiveQuickAction key="thread-archive-quick-action" thread={thread} />
          </InjectedComponentSet>
        )}
      </span>
    );
  },
});

/** Flat + threaded rows share the same column order (KIWI narrow idiom). */
export const KIWI_ROW_COLUMNS: ListTabularColumn[] = [cPick, cAvatar, ...Narrow, cMarks, cQuick];

/* ------------------------- entry → {item, itemProps} ------------------------- */

function kiwiRowBase(
  entry: MsRowEntry,
  ctx: MsRowViewCtx,
  rowId: string,
  navId: string,
  ids: string[],
  label: string,
): MsKiwiRow {
  const allPicked = ids.length > 0 && ids.every((id) => ctx.picked.includes(id));
  return {
    rowId,
    navId,
    folder: ctx.folder,
    ids,
    isPicked: allPicked,
    confirmDel: ctx.armedDelId === rowId,
    acctTag: ctx.acctTagFor?.(entry),
    // Avatar seed parity: threads tint off the same joined-participants
    // string the old row used, so hue/initial don't drift on re-render.
    avatar: ctx.avatarFor(
      entry.kind === "msg"
        ? entry.m.from
        : entry.t.participants.slice(0, 3).join(", ") +
            (entry.t.participants.length > 3 ? ` +${entry.t.participants.length - 3}` : ""),
    ),
    label,
    dragIds: ids.some((id) => ctx.picked.includes(id)) ? ctx.picked : ids,
    dragSubject: entry.kind === "msg" ? entry.m.subject : entry.t.subject,
    onPick: (range: boolean) => {
      if (entry.kind === "msg") {
        ctx.onTogglePick(navId, range);
      } else {
        // Thread pick = every member id (bulk actions act on the thread).
        const target = !allPicked;
        for (const id of ids) {
          if (target === !ctx.picked.includes(id)) ctx.onTogglePick(id, false);
        }
      }
    },
    onToggleStar: () => ctx.onToggleStar(navId),
    onArchive: () => ctx.onArchive(navId),
    onRequestTrash: () => ctx.onArmTrash(rowId),
    onDelete: () => {
      ctx.onDisarmTrash();
      ctx.onDelete(navId);
    },
    onDisarmTrash: () => ctx.onDisarmTrash(),
    onContextMenu: (e: ReactMouseEvent) => ctx.onRowContext(e, ids),
  };
}

/** Adapt one mailbox row into ListTabularRows' `{item, itemProps}` pair. */
export function msRowEntry(
  entry: MsRowEntry,
  ctx: MsRowViewCtx,
): { item: MsThread; itemProps: MsRowItemProps } {
  const isMsg = entry.kind === "msg";
  const m = isMsg ? entry.m : null;
  const t = isMsg ? null : entry.t;
  const navId = isMsg ? m!.id : t!.messages[t!.messages.length - 1].id;
  const rowId = isMsg ? m!.id : `thread-${t!.key.replace(/\W/g, "-")}`;
  const ids = isMsg ? [m!.id] : t!.messages.map((x) => x.id);
  const selected = isMsg ? m!.id === ctx.currentId : t!.messages.some((x) => x.id === ctx.currentId);

  const row = kiwiRowBase(entry, ctx, rowId, navId, ids, "");
  const item = isMsg
    ? msThreadFromEnvelope(m!, { draftsView: ctx.draftsView, row })
    : msThreadFromThread(t!, { draftsView: ctx.draftsView, row });

  // Ported aria label first (unread, participants, subject, timestamp,
  // count, attachment/starred) + KIWI's trust & pick suffixes preserved.
  const trust = isMsg ? m!.trust : t!.messages[t!.messages.length - 1].trust;
  const pickedBit = ids.every((id) => ctx.picked.includes(id)) && ids.length > 0
    ? " Selected for bulk actions."
    : "";
  const label = `${threadAriaLabel(item)}. Account trust ${severityLabel(trust)}.${pickedBit}`;
  row.label = label;

  const itemProps: MsRowItemProps = {
    className: `em-row${item.unread ? " is-unread unread" : ""}${selected ? " is-selected selected" : ""}`,
    id: rowId,
    role: "option",
    ariaSelected: selected,
    ariaLabel: label,
    rowProps: {
      draggable: !!row.dragIds,
      onDragStart: row.dragIds
        ? (e: React.DragEvent<HTMLElement>) => {
            e.dataTransfer.setData(
              "application/x-kiwi-messages",
              JSON.stringify({ ids: row.dragIds }),
            );
            // Dragover can't read getData — the source folder rides in a
            // TYPE token so drop targets can deny same-folder drops.
            const srcKey = row.dragIds![0]?.split(":").slice(0, 2).join("_").toLowerCase();
            if (srcKey) e.dataTransfer.setData(`application/x-kiwi-src-${srcKey}`, "1");
            e.dataTransfer.setData(
              "text/plain",
              `${row.dragIds!.length} message(s): ${row.dragSubject ?? ""}`,
            );
            e.dataTransfer.effectAllowed = "move";
            e.currentTarget.classList.add("em-dragging");
          }
        : undefined,
      onDragEnd: row.dragIds
        ? (e: React.DragEvent<HTMLElement>) => e.currentTarget.classList.remove("em-dragging")
        : undefined,
      onContextMenu: (e: ReactMouseEvent) => {
        // Row-level menu (T-299): suppress the browser menu; buttons/inputs
        // keep native behavior.
        if ((e.target as HTMLElement).closest("button,input")) return;
        row.onContextMenu(e);
      },
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === "Enter") {
          navigate({ name: "mail", folder: ctx.folder, messageId: navId });
        }
      },
      tabIndex: 0,
    },
  };
  return { item, itemProps };
}

export type { ListTabularRowsProps };
