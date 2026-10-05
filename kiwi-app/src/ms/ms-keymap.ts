// Adapter for Mailspring `rx-core` Disposable + `keymap-manager` +
// `command-registry` (AppEnv.commands) — no .cson loading. commands.add
// registers command-name listeners (custom DOM events, Mailspring semantics)
// AND treats combo-string keys ("mod+c", "escape") as direct keydown bindings
// on the target. KeymapManager bindings dispatch first (capture phase);
// string values re-dispatch the Mailspring command-name CustomEvent.
export class Disposable {
  constructor(private fn?: () => void) {}

  dispose() {
    const fn = this.fn;
    this.fn = undefined;
    fn?.();
  }
}

type CommandCallback = (event: Event) => void;
// Mailspring keymaps map keystrokes to command-name strings; direct handler
// functions are a KIWI convenience.
type KeymapBinding = string | CommandCallback;

const MOD_ALIASES: Record<string, string> = {
  cmd: "mod",
  command: "mod",
  ctrl: "mod",
  control: "mod",
  opt: "alt",
  option: "alt",
};

const KEY_ALIASES: Record<string, string> = {
  esc: "escape",
  return: "enter",
  space: " ",
  spacebar: " ",
  del: "delete",
  ins: "insert",
  up: "arrowup",
  down: "arrowdown",
  left: "arrowleft",
  right: "arrowright",
};

// "CmdOrCtrl+Enter" / "mod+c" → canonical "mod+enter" / "mod+c"
// (modifier order mod, alt, shift). Returns null if no non-modifier key.
function normalizeCombo(combo: string): string | null {
  const mods: string[] = [];
  let key = "";
  for (const raw of combo.toLowerCase().split("+")) {
    const part = MOD_ALIASES[raw.trim()] ?? KEY_ALIASES[raw.trim()] ?? raw.trim();
    if (part === "mod" || part === "alt" || part === "shift") {
      if (!mods.includes(part)) mods.push(part);
    } else if (part) {
      key = part;
    }
  }
  if (!key) return null;
  return [...["mod", "alt", "shift"].filter((m) => mods.includes(m)), key].join("+");
}

// Canonical combo string for a keydown event, or null for modifier-only presses.
function eventCombo(e: KeyboardEvent): string | null {
  const raw = e.key.toLowerCase();
  if (raw === "control" || raw === "meta" || raw === "alt" || raw === "shift") return null;
  const parts: string[] = [];
  if (e.ctrlKey || e.metaKey) parts.push("mod");
  if (e.altKey) parts.push("alt");
  if (e.shiftKey) parts.push("shift");
  parts.push(KEY_ALIASES[raw] ?? raw);
  return parts.join("+");
}

const keymaps: Map<string, KeymapBinding>[] = [];
let keymapListenerInstalled = false;

function onKeymapKeydown(e: KeyboardEvent) {
  const combo = eventCombo(e);
  if (!combo) return;
  // most recently added keymap wins, matching Mailspring's load order
  for (let i = keymaps.length - 1; i >= 0; i--) {
    const binding = keymaps[i].get(combo);
    if (binding === undefined) continue;
    e.preventDefault();
    e.stopPropagation();
    if (typeof binding === "string") {
      // Mailspring parity: a keystroke→command binding re-dispatches a
      // bubbling CustomEvent named by the command from the event target,
      // which AppEnv.commands listeners receive.
      e.target?.dispatchEvent(new CustomEvent(binding, { bubbles: true, cancelable: true }));
    } else {
      binding(e);
    }
    return;
  }
}

export const KeymapManager = {
  addKeymap(map: Record<string, KeymapBinding>): Disposable {
    const bindings = new Map<string, KeymapBinding>();
    for (const [combo, binding] of Object.entries(map)) {
      const normalized = normalizeCombo(combo);
      if (normalized === null) {
        console.warn(`KeymapManager.addKeymap: cannot parse combo "${combo}"`);
        continue;
      }
      bindings.set(normalized, binding);
    }
    if (!keymapListenerInstalled) {
      // capture phase: keymap bindings are consulted before the keydown
      // (bubble) listeners registered by commands.add.
      document.addEventListener("keydown", onKeymapKeydown, true);
      keymapListenerInstalled = true;
    }
    keymaps.push(bindings);
    return new Disposable(() => {
      const i = keymaps.indexOf(bindings);
      if (i >= 0) keymaps.splice(i, 1);
    });
  },
};

// Mailspring command names look like "core:send"; they can never be key combos.
const COMMAND_NAME = /:/;

// Adapter for the `AppEnv.config` surface the ported components read
// (`config.get`/`config.onDidChange` over schema-keyed prefs). KIWI has no
// .cson registry — the vendored schema defaults are the honest values:
// `detailedNames` and `use24HourClock` ship `false` upstream. onDidChange
// returns an inert Disposable because nothing in KIWI writes these keys.
const CONFIG_DEFAULTS: Record<string, unknown> = {
  "core.reading.detailedNames": false,
  "core.workspace.use24HourClock": false,
  "core.workspace.showImportant": true,
};

export const AppEnv = {
  commands: {
    add(target: Element, map: Record<string, CommandCallback>): Disposable {
      const off: (() => void)[] = [];
      const combos = new Map<string, CommandCallback>();

      for (const [name, handler] of Object.entries(map)) {
        const listener = (e: Event) => handler(e);
        // Command CustomEvents dispatched by KeymapManager (or bubbled from
        // descendants) arrive under the command name.
        target.addEventListener(name, listener);
        off.push(() => target.removeEventListener(name, listener));
        if (!COMMAND_NAME.test(name)) {
          const combo = normalizeCombo(name);
          if (combo) {
            combos.set(combo, handler);
          } else {
            console.warn(`AppEnv.commands.add: cannot parse combo "${name}"`);
          }
        }
      }

      const onKeydown = (e: Event) => {
        const combo = eventCombo(e as KeyboardEvent);
        const handler = combo ? combos.get(combo) : undefined;
        if (handler) {
          e.preventDefault();
          handler(e);
        }
      };
      // bubble listener on target == keydowns originating in descendants,
      // same reach as Mailspring's localHandlers.
      target.addEventListener("keydown", onKeydown);
      off.push(() => target.removeEventListener("keydown", onKeydown));

      return new Disposable(() => off.forEach((f) => f()));
    },
  },
  config: {
    get(key: string): unknown {
      return CONFIG_DEFAULTS[key];
    },
    onDidChange(_key: string, _callback: () => void): Disposable {
      return new Disposable();
    },
  },
};
