// Adapter for Mailspring `electron` + `@electron/remote` imports — clipboard
// via navigator.clipboard with execCommand fallback; Menu/MenuItem render a
// fixed DOM popup reusing the .em-ctx context-menu styles (no native menus);
// remote.webContents is a focus-targeted input shim; ipcRenderer throws.
export const clipboard = {
  async writeText(text: string): Promise<void> {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return;
      } catch (err) {
        console.warn("clipboard.writeText: async clipboard failed, trying execCommand", err);
      }
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    try {
      if (!document.execCommand("copy")) console.warn("clipboard.writeText: execCommand('copy') returned false");
    } catch (err) {
      console.warn("clipboard.writeText: execCommand('copy') threw", err);
    } finally {
      ta.remove();
    }
  },

  async readText(): Promise<string> {
    if (!navigator.clipboard?.readText) {
      console.warn("clipboard.readText: no clipboard API in this context");
      return "";
    }
    try {
      return await navigator.clipboard.readText();
    } catch (err) {
      console.warn("clipboard.readText: unavailable", err);
      return "";
    }
  },
};

export interface MenuItemOptions {
  id?: string;
  label?: string;
  click?: (menuItem: MenuItem, browserWindow?: unknown, event?: unknown) => void;
  enabled?: boolean;
  visible?: boolean;
  type?: "normal" | "separator" | "submenu" | "checkbox" | "radio";
  submenu?: MenuItemOptions[] | MenuItem[] | Menu;
  accelerator?: string;
  checked?: boolean;
}

export class MenuItem {
  id?: string;
  label: string;
  click?: (menuItem: MenuItem, browserWindow?: unknown, event?: unknown) => void;
  enabled: boolean;
  visible: boolean;
  type: string;
  submenu?: MenuItem[];
  accelerator?: string;
  checked: boolean;

  constructor(options: MenuItemOptions = {}) {
    this.id = options.id;
    this.label = options.label ?? "";
    this.click = options.click;
    this.enabled = options.enabled !== false;
    this.visible = options.visible !== false;
    this.type = options.type ?? (options.submenu ? "submenu" : "normal");
    this.accelerator = options.accelerator;
    this.checked = options.checked === true;
    const sub = options.submenu;
    if (sub instanceof Menu) this.submenu = sub.items;
    else if (Array.isArray(sub)) this.submenu = sub.map((i) => (i instanceof MenuItem ? i : new MenuItem(i)));
  }
}

export class Menu {
  items: MenuItem[] = [];
  private _root: HTMLElement | null = null;
  private _teardown: (() => void) | null = null;

  static buildFromTemplate(template: Array<MenuItem | MenuItemOptions>): Menu {
    const menu = new Menu();
    menu.items = template.map((t) => (t instanceof MenuItem ? t : new MenuItem(t)));
    return menu;
  }

  popup({ x = 0, y = 0 }: { x?: number; y?: number; window?: unknown; async?: boolean } = {}) {
    this.closeMenu();
    const root = document.createElement("div");
    root.className = "em-ctx ms-menu";
    root.setAttribute("role", "menu");
    root.style.left = `${x}px`;
    root.style.top = `${y}px`;
    for (const item of this.items) {
      if (item.visible !== false) root.appendChild(this._renderItem(item));
    }
    document.body.appendChild(root);
    const r = root.getBoundingClientRect(); // clamp inside the viewport
    if (x + r.width > window.innerWidth) root.style.left = `${Math.max(0, window.innerWidth - r.width - 6)}px`;
    if (y + r.height > window.innerHeight) root.style.top = `${Math.max(0, window.innerHeight - r.height - 6)}px`;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        this.closeMenu();
      }
    };
    const onMouseDown = (e: Event) => {
      if (this._root && !this._root.contains(e.target as Node)) this.closeMenu();
    };
    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("mousedown", onMouseDown, true);
    window.addEventListener("blur", this.closeMenu);
    this._root = root;
    this._teardown = () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("mousedown", onMouseDown, true);
      window.removeEventListener("blur", this.closeMenu);
    };
  }

  closeMenu = () => {
    this._teardown?.();
    this._teardown = null;
    this._root?.remove();
    this._root = null;
  };

  private _renderItem(item: MenuItem): HTMLElement {
    if (item.type === "separator") {
      const sep = document.createElement("div");
      sep.className = "em-ctx-sep";
      sep.setAttribute("role", "separator");
      return sep;
    }
    const wrap = document.createElement("div");
    wrap.className = "em-ctx-item-wrap";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "em-ctx-item";
    btn.disabled = item.enabled === false;
    const checkable = item.type === "checkbox" || item.type === "radio";
    btn.setAttribute("role", checkable ? `menuitem${item.type}` : "menuitem");
    if (checkable) btn.setAttribute("aria-checked", String(item.checked));

    const label = document.createElement("span");
    label.className = "em-ctx-label";
    label.textContent = item.label;
    btn.appendChild(label);
    if (item.accelerator) {
      const hint = document.createElement("span");
      hint.className = "em-ctx-hint";
      hint.textContent = item.accelerator;
      btn.appendChild(hint);
    }

    const sub = item.submenu;
    if (sub && sub.length > 0) {
      btn.setAttribute("aria-haspopup", "menu");
      const caret = document.createElement("span");
      caret.className = "em-ctx-caret";
      caret.textContent = "›";
      btn.appendChild(caret);
      // the submenu lives inside .em-ctx-item-wrap (position:relative), so
      // moving onto it keeps `wrap` hovered — same DOM shape as contextmenu.tsx.
      let subEl: HTMLElement | null = null;
      wrap.addEventListener("mouseenter", () => {
        if (btn.disabled || subEl) return;
        subEl = document.createElement("div");
        subEl.className = "em-ctx em-ctx-sub";
        subEl.setAttribute("role", "menu");
        for (const child of sub) {
          if (child.visible !== false) subEl.appendChild(this._renderItem(child));
        }
        wrap.appendChild(subEl);
      });
      wrap.addEventListener("mouseleave", () => {
        subEl?.remove();
        subEl = null;
      });
    } else {
      btn.addEventListener("click", () => {
        this.closeMenu();
        item.click?.(item);
      });
    }
    wrap.appendChild(btn);
    return wrap;
  }
}

export const remote = {
  Menu,
  MenuItem,
  getCurrentWindow() {
    const insertText = (text: string) => {
      let ok = false;
      try {
        ok = document.execCommand("insertText", false, text);
      } catch (err) {
        console.warn("remote.webContents.insertText: execCommand threw, dispatching textInput", err);
      }
      if (ok) return;
      try {
        (document.activeElement ?? document.body).dispatchEvent(
          new InputEvent("textInput", { data: text, bubbles: true, cancelable: true }),
        );
      } catch (err) {
        console.warn("remote.webContents.insertText: cannot insert", err);
      }
    };
    const copy = () => {
      try {
        if (!document.execCommand("copy")) console.warn("remote.webContents.copy: execCommand('copy') returned false");
      } catch (err) {
        console.warn("remote.webContents.copy: unavailable", err);
      }
    };
    return { webContents: { insertText, copy } };
  },
};

const unavailable = (..._args: any[]): never => {
  throw new Error("ipcRenderer unavailable in KIWI — adapt at call site");
};

export const ipcRenderer = {
  send: unavailable,
  invoke: unavailable,
  on: unavailable,
  once: unavailable,
  sendSync: unavailable,
  removeListener: unavailable,
  removeAllListeners: unavailable,
};
