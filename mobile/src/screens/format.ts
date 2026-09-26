/** Bounded, Intl-free time/id formatting shared by the screens. */
export function fmtTime(unix: number): string {
  const d = new Date(unix * 1000);
  const pad = (n: number): string => (n < 10 ? `0${n}` : String(n));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** Shorten wire ids for display — never echo full nonces or payloads. */
export function shortId(id: string, keep: number = 10): string {
  return id.length <= keep ? id : `${id.slice(0, keep)}…`;
}
