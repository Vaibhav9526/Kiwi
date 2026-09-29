// Ported from Mailspring app/internal_packages/preferences/lib/
//   preferences-tabs-bar.tsx    — PreferencesTabItem + PreferencesTabsBar
//   tabs/config-schema-item.tsx — ConfigSchemaItem
//   lib/types.ts                — ConfigLike / ConfigSchemaLike
//   tabs/preferences-general.tsx + tabs/workspace-section.tsx — the
//     <section><h6/>…<div className="item"/>… idiom, wrapped here as
//     ItemizedSection / SettingRow / PlatformNote.
//
// Adapted seams (see docs/MAILSPRING-MIGRATION.md rule 2):
//   Actions.switchPreferencesTab(tabId, {accountId}) → onSelect(tabId, extra) prop
//   localized / mailspring-exports                   → ./ms-exports
//   RetinaImg tab icons (component-kit)              → optional `icon` ReactNode slot
//   process.platform                                 → msPlatform() (UA-derived)
//   underscore.string humanize                       → local humanize()
//   div[role=tab]                                    → button[role=tab]
//     (kiwi scripts/ui-smoke.mjs asserts button[role=tab]; the item's own
//     Enter/Space keydown is kept even though buttons self-activate)
//   horizontal .preferences-tabs strip               → vertical rail: ArrowUp/
//     ArrowDown join ArrowLeft/ArrowRight in _onKeyDown; the container carries
//     KIWI's .ms-prefs-rail skin (ui-stress.mjs mounts #/settings on it) and
//     items keep .ms-tab for the existing rail look.
//   KIWI rail groups (settings.tsx SECTION_GROUPS)   → optional `groups` prop
//     rendering .ms-rail-group/.ms-rail-label wrappers around tab items.

import React from "react";
import classNames from "classnames";
import _ from "underscore";
import { localized } from "./ms-exports";

/* ---------- lib/types.ts ---------- */

export interface ConfigLike {
  get: (key: string) => any;
  toggle: (key: string) => void;
  set: (key: string, val: any) => void;
}

export interface ConfigSchemaLike {
  type?: string;
  properties?: { [subkey: string]: ConfigSchemaLike };
  advanced?: boolean | string;
  note?: string;
  title?: string;
  enum?: string[];
  enumLabels?: string[];
  platforms?: string[];
}

/* ---------- seams ---------- */

/** Seam for `process.platform` — no process in the browser; derive the
 * Mailspring platform token from the UA so `platforms`-gated schema items
 * keep working. */
function msPlatform(): string {
  const ua = typeof navigator !== "undefined" ? navigator.userAgent.toLowerCase() : "";
  if (ua.includes("windows")) return "win32";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "darwin";
  return "linux";
}

/** Seam for underscore.string `humanize`: camelCase/snake-case → "Camel case". */
function humanize(key: string): string {
  const spaced = key
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .trim()
    .toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/* ---------- preferences-tabs-bar.tsx ---------- */

export interface PreferencesTabLike {
  tabId: string;
  displayName: string;
  /** KIWI seam: Mailspring rendered a 40px RetinaImg tab-icon here; the KIWI
   * rail is name-only, but the slot stays so callers can pass an <Icon/>. */
  icon?: React.ReactNode;
}

export interface PreferencesTabSelection {
  accountId?: string;
  tabId: string;
}

interface PreferencesTabItemProps {
  selection: PreferencesTabSelection;
  tabItem?: PreferencesTabLike;
  onSelect: (tabId: string, extra?: { accountId?: string }) => void;
}

export class PreferencesTabItem extends React.Component<PreferencesTabItemProps> {
  static displayName = "PreferencesTabItem";

  _onClick = () => {
    // seam: Actions.switchPreferencesTab(this.props.tabItem.tabId)
    this.props.onSelect(this.props.tabItem!.tabId);
  };

  _onClickAccount = (event: React.MouseEvent, accountId: string) => {
    // seam: Actions.switchPreferencesTab(this.props.tabItem.tabId, { accountId })
    this.props.onSelect(this.props.tabItem!.tabId, { accountId });
    event.stopPropagation();
  };

  _onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      this._onClick();
    }
  };

  render() {
    const { selection, tabItem } = this.props;
    const { tabId, displayName } = tabItem!;
    const classes = classNames({
      item: true,
      "ms-tab": true, // KIWI seam: existing rail-item skin (shell.css)
      active: tabId === selection.tabId,
    });

    const isSelected = tabId === selection.tabId;
    return (
      <button
        type="button"
        className={classes}
        role="tab"
        aria-selected={isSelected}
        aria-label={displayName}
        tabIndex={isSelected ? 0 : -1}
        onClick={this._onClick}
        onKeyDown={this._onKeyDown}
      >
        {tabItem!.icon}
        <span className="name">{displayName}</span>
      </button>
    );
  }
}

/** KIWI seam — optional rail group headings between the tab items
 * (.ms-rail-group/.ms-rail-label from shell.css). When omitted the bar is
 * flat like Mailspring's. `tabs` stays the flat ordered list so arrow-key
 * traversal lands on the right item. */
export interface PreferencesTabGroup {
  label: string;
  tabIds: string[];
}

interface PreferencesTabsBarProps {
  tabs: PreferencesTabLike[];
  selection: PreferencesTabSelection;
  onSelect: (tabId: string, extra?: { accountId?: string }) => void;
  groups?: PreferencesTabGroup[];
}

export class PreferencesTabsBar extends React.Component<PreferencesTabsBarProps> {
  static displayName = "PreferencesTabsBar";

  private _listRef = React.createRef<HTMLDivElement>();

  _onKeyDown = (e: React.KeyboardEvent) => {
    const { tabs, selection } = this.props;
    const currentIdx = tabs.findIndex((t) => t.tabId === selection.tabId);
    if (currentIdx < 0) return;

    let nextIdx: number | null = null;
    // Mailspring's strip is horizontal (Left/Right); the KIWI rail is
    // vertical, so Down/Up map onto next/previous the same way.
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      nextIdx = (currentIdx + 1) % tabs.length;
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      nextIdx = (currentIdx - 1 + tabs.length) % tabs.length;
    } else if (e.key === "Home") {
      nextIdx = 0;
    } else if (e.key === "End") {
      nextIdx = tabs.length - 1;
    } else {
      return;
    }

    e.preventDefault();
    // seam: Actions.switchPreferencesTab(tabs[nextIdx].tabId)
    this.props.onSelect(tabs[nextIdx].tabId);

    // Focus the newly activated tab (works even before React re-renders tabIndex)
    const tabEls = this._listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]');
    tabEls?.[nextIdx]?.focus();
  };

  _renderTab(tabItem: PreferencesTabLike) {
    return (
      <PreferencesTabItem
        key={tabItem.tabId}
        tabItem={tabItem}
        selection={this.props.selection}
        onSelect={this.props.onSelect}
      />
    );
  }

  renderTabs() {
    const { tabs, groups } = this.props;
    if (!groups) {
      return tabs.map((tabItem) => this._renderTab(tabItem));
    }
    const byId = new Map(tabs.map((t) => [t.tabId, t] as const));
    return groups.map((group) => (
      <div key={group.label} className="ms-rail-group" role="presentation">
        <div className="ms-rail-label" aria-hidden="true">
          {group.label}
        </div>
        {group.tabIds.map((id) => {
          const tab = byId.get(id);
          return tab ? this._renderTab(tab) : null;
        })}
      </div>
    ));
  }

  render() {
    return (
      // .ms-prefs-rail supplies flex-basis/sticky on the flex child of
      // .ms-prefs-layout (ui-stress mounts #/settings on this selector);
      // .container-preference-tabs is the Mailspring wrapper class.
      <div className="container-preference-tabs ms-prefs-rail">
        <div
          ref={this._listRef}
          className="preferences-tabs ms-tabs"
          role="tablist"
          aria-label={localized("Preferences")}
          aria-orientation="vertical"
          onKeyDown={this._onKeyDown}
        >
          {this.renderTabs()}
        </div>
      </div>
    );
  }
}

/* ---------- tabs/config-schema-item.tsx ---------- */

/*
This component renders input controls for a subtree of the Mailspring config-schema
and reads/writes current values using the `config` prop, which is expected to
be an instance of the config provided by `ConfigPropContainer`.

The config schema follows the JSON Schema standard: http://json-schema.org/
*/
interface ConfigSchemaItemProps {
  keyName?: string;
  keyPath: string;
  config: ConfigLike;
  configSchema: ConfigSchemaLike;
}

export class ConfigSchemaItem extends React.Component<ConfigSchemaItemProps> {
  static displayName = "ConfigSchemaItem";

  _appliesToPlatform() {
    if (!this.props.configSchema.platforms) {
      return true;
    } else if (this.props.configSchema.platforms.indexOf(msPlatform()) !== -1) {
      return true;
    }
    return false;
  }

  _onChangeChecked = (event: React.ChangeEvent<HTMLInputElement>) => {
    this.props.config.toggle(this.props.keyPath);
    event.target.blur();
  };

  _onChangeValue = (event: React.ChangeEvent<HTMLSelectElement>) => {
    this.props.config.set(this.props.keyPath, event.target.value);
    event.target.blur();
  };

  render() {
    if (!this._appliesToPlatform()) return false;

    // In the future, we may add an option to reveal "advanced settings"
    if (this.props.configSchema.advanced) return false;

    const note = this.props.configSchema.note ? (
      <div className="platform-note">{this.props.configSchema.note}</div>
    ) : null;

    if (this.props.configSchema.type === "object") {
      return (
        <section>
          <h6>{humanize(this.props.keyName ?? "")}</h6>
          {Object.entries(this.props.configSchema.properties ?? {}).map(([key, value]) => (
            <ConfigSchemaItem
              key={key}
              keyName={key}
              keyPath={`${this.props.keyPath}.${key}`}
              configSchema={value}
              config={this.props.config}
            />
          ))}
          {note}
        </section>
      );
    } else if (this.props.configSchema.enum) {
      return (
        <div className="item">
          <label htmlFor={this.props.keyPath} style={{ paddingRight: 8 }}>
            {this.props.configSchema.title}:
          </label>
          <select
            id={this.props.keyPath}
            onChange={this._onChangeValue}
            value={this.props.config.get(this.props.keyPath)}
          >
            {_.zip(this.props.configSchema.enum ?? [], this.props.configSchema.enumLabels ?? []).map(
              ([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              )
            )}
          </select>
          {note}
        </div>
      );
    } else if (this.props.configSchema.type === "boolean") {
      return (
        <div className="item">
          <input
            id={this.props.keyPath}
            type="checkbox"
            onChange={this._onChangeChecked}
            checked={!!this.props.config.get(this.props.keyPath)}
          />
          <label htmlFor={this.props.keyPath}>{this.props.configSchema.title}</label>
          {note}
        </div>
      );
    }
    return <span />;
  }
}

/* ---------- section / row pieces (preferences-general.tsx idiom) ---------- */

/** The Mailspring section block: `<section><h6>{title}</h6>{items}</section>`.
 * `title` renders the h6 group header — omit it for a headerless block. */
export function ItemizedSection({
  title,
  className,
  children,
}: {
  title?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={classNames("ms-pref-section", className)}>
      {title != null && title !== false && <h6>{title}</h6>}
      {children}
    </section>
  );
}

/** The `.item` setting row. KIWI rows keep the control INSIDE its <label>
 * (Mailspring renders label+select as siblings) so the whole row is one hit
 * target and `select.closest("label")` keeps resolving — the ui-smoke
 * notify-pref check depends on it. Freeform children are fine too. */
export function SettingRow({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return <div className={classNames("item", className)}>{children}</div>;
}

/** Ported `.platform-note` callout — informational aside inside a section. */
export function PlatformNote({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return <div className={classNames("platform-note", className)}>{children}</div>;
}
