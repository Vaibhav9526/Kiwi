// Adapter for Mailspring `app/src/intl.ts` — English pass-through (KIWI has
// no lang tables; TODO real l10n). %@ sequential plus %@1..%@9 and %1$@..%9$@
// positional substitution preserved; indexed forms are 1-based consistently
// (vendor's fragment off-by-one on %N$@ is normalized to match localized()).
import { createElement, Fragment } from "react";
import type { ReactNode } from "react";

export function localized(str: string, ...args: any[]): string {
  let i = 0;
  let translated = str;
  if (args.length) {
    // "%1$@..%9$@" lets translations reorder args; "%@1..%@9" positional;
    // bare "%@" consumed in order.
    if (translated.includes("%1$@")) {
      args.forEach((sub, idx) => {
        translated = translated.replace(`%${idx + 1}$@`, sub);
      });
    } else {
      translated = translated.replace(/%@([1-9])?/g, (_m, n) => (n ? args[+n - 1] : args[i++]));
    }
  }
  return translated;
}

export function localizedReactFragment(str: string, ...args: any[]): ReactNode {
  let translated = str;
  if (!args.length) {
    return translated;
  }
  const parts: ReactNode[] = [];
  let match: RegExpExecArray | null = null;
  let used = 0;
  const pattern = /%(?:(\d+)\$)?@([1-9])?/g;
  while ((match = pattern.exec(translated))) {
    if (match.index > 0) {
      parts.push(translated.slice(0, match.index));
    }
    const idx = match[1] !== undefined ? +match[1] - 1 : match[2] !== undefined ? +match[2] - 1 : used++;
    parts.push(args[idx]);
    translated = translated.slice(match.index + match[0].length);
  }
  if (translated.length > 0) {
    parts.push(translated);
  }
  return createElement(Fragment, null, ...parts);
}
