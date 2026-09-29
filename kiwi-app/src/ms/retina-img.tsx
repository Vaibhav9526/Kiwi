/* Ported from Mailspring `app/src/components/retina-img.tsx` — seam-adapted.
 * Mailspring resolved PNG assets through a resource-path cache and themed them
 * via `mode` (ContentIsMask tinted the bitmap with background-color). KIWI
 * glyphs are the `Icon` registry — inline SVG stroked with currentColor, the
 * ContentIsMask equivalent — so `name`/`url`/`fallback` resolve to Icon names
 * (Mailspring asset basenames map through NAME_ALIASES; unknown → fallback →
 * "folder"). `className`, `style`, and `alt` pass through; the `content-*`
 * mode class is preserved so ported CSS keeps working. */
import React from 'react';
import { Icon, isIconName } from '../components/icons/index';
import type { IconName } from '../components/icons/index';

const Mode = {
  ContentPreserve: 'original',
  ContentLight: 'light',
  ContentDark: 'dark',
  ContentIsMask: 'mask',
};

/* Mailspring sidebar PNG basenames → Icon registry names. */
const NAME_ALIASES: Record<string, IconName> = {
  'icon-sidebar-addcategory': 'plus',
  // tokenizing-text-field token action caret (composer-caret.png)
  'composer-caret': 'chevron-down',
  folder: 'folder',
  inbox: 'inbox',
  sent: 'send',
  archive: 'archive',
  trash: 'trash',
  junk: 'blocked',
  spam: 'blocked',
  drafts: 'compose',
  outbox: 'outbox',
  starred: 'star',
  unread: 'mail-open',
  snoozed: 'snooze',
  tag: 'flag',
  'icon-draft-pencil': 'compose',
};

function iconNameFor(ref?: string): IconName | null {
  if (!ref || typeof ref !== 'string') return null;
  const base = ref.split('/').pop() ?? ref;
  const stem = base
    .replace(/@[12]x/g, '')
    .replace(/\.(png|svg|gif|jpe?g|webp)$/i, '')
    .toLowerCase();
  if (isIconName(stem)) return stem;
  return NAME_ALIASES[stem] ?? null;
}

type RetinaImgProps = {
  mode: string;
  name?: string;
  url?: string;
  className?: string;
  style?: React.CSSProperties;
  fallback?: string;
  selected?: boolean;
  active?: boolean;
  alt?: string;
};

function RetinaImgInner(props: RetinaImgProps) {
  const name =
    iconNameFor(props.name) ?? iconNameFor(props.url) ?? iconNameFor(props.fallback) ?? 'folder';
  const style = props.style;
  const size =
    typeof style?.width === 'number'
      ? style.width
      : typeof style?.height === 'number'
        ? style.height
        : 14;
  const modeClass =
    props.mode === Mode.ContentIsMask
      ? ' content-mask'
      : props.mode === Mode.ContentDark
        ? ' content-dark'
        : props.mode === Mode.ContentLight
          ? ' content-light'
          : '';
  return (
    <Icon
      name={name}
      size={size}
      className={`${modeClass.trim()}${props.className ? ` ${props.className}` : ''}`}
      style={style}
      label={props.alt ? props.alt : undefined}
    />
  );
}

export const RetinaImg = Object.assign(RetinaImgInner, { Mode, displayName: 'RetinaImg' });
