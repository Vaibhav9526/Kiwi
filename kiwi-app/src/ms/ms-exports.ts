// Adapter for Mailspring `mailspring-exports` / `mailspring-component-kit` —
// barrel re-exporting the ms/* kit so ported files only change the module
// name. `Utils` additionally keeps its namespace-object shape (it is a bag
// of functions in Mailspring, not a named const like DOMUtils/RegExpUtils).
import * as Utils from "./ms-utils";
import { DOMUtils } from "./ms-dom-utils";
import { RegExpUtils } from "./ms-regexp-utils";

export * from "./ms-utils";
export * from "./ms-dom-utils";
export * from "./ms-regexp-utils";
export * from "./ms-i18n";
export * from "./ms-electron";
export * from "./ms-keymap";
export * from "./ms-contact";

export { Utils, DOMUtils, RegExpUtils };
