/**
 * `<Icon name="…" />` (T-268) — the single entry point for every UI glyph.
 * Renders an inline `<svg>` (16×16 grid) stroked with `currentColor`, so it
 * inherits text/pill/button color and both themes for free. Decorative by
 * default (`aria-hidden`); pass `label` to expose it as an `img`.
 */
import type { SVGAttributes } from "react";
import { ICONS } from "./icons";
import type { IconDef, IconName } from "./icons";

export interface IconProps extends Omit<SVGAttributes<SVGSVGElement>, "name"> {
  name: IconName;
  /** Rendered size in px (number) or any CSS size. Default 16 (icon-size token). */
  size?: number | string;
  /** Accessible name. Omit for decorative icons inside labeled controls. */
  label?: string;
  /** Stroke width override (default 1.25 — tuned for the 16px grid). */
  strokeWidth?: number;
}

export function Icon({ name, size = 16, label, strokeWidth = 1.25, className, style, ...rest }: IconProps) {
  const def: IconDef = ICONS[name];
  const cls = `kiwi-icon${def.fill ? " kiwi-icon-fill" : ""}${className ? ` ${className}` : ""}`;
  return (
    <svg
      viewBox="0 0 16 16"
      width={size}
      height={size}
      className={cls}
      style={style}
      fill={def.fill ? "currentColor" : "none"}
      stroke={def.fill ? "none" : "currentColor"}
      strokeWidth={def.fill ? undefined : strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
      aria-hidden={label === undefined ? true : undefined}
      role={label !== undefined ? "img" : undefined}
      aria-label={label}
      {...rest}
    >
      {def.body}
    </svg>
  );
}
