/**
 * Challenge event tags (T-136).
 *
 * MUST stay numerically identical to `kiwi_core::challenge::ChallengeEvent::tag()`
 * (kiwi-core/src/challenge.rs). The tag byte is signed inside the canonical
 * challenge bytes, so a mismatched table breaks verification — flag to
 * Contract version 2 if kiwi-core ever adds or renumbers an event.
 */
export const CHALLENGE_EVENTS = ['unlock', 'device-pairing', 'recovery', 'elevated-action'] as const;

export type ChallengeEvent = (typeof CHALLENGE_EVENTS)[number];

const EVENT_TAGS: Record<ChallengeEvent, number> = {
  unlock: 0x01,
  'device-pairing': 0x02,
  recovery: 0x03,
  'elevated-action': 0x04,
};

/** Canonical wire tag for a challenge event (kiwi-core u8). */
export function eventTag(event: ChallengeEvent): number {
  return EVENT_TAGS[event];
}

/** Inverse of {@link eventTag}; returns null for unknown tags. */
export function eventFromTag(tag: number): ChallengeEvent | null {
  for (const e of CHALLENGE_EVENTS) {
    if (EVENT_TAGS[e] === tag) {return e;}
  }
  return null;
}

/** Lowercase wire label used in QR payloads and pairing messages. */
export function eventWireName(event: ChallengeEvent): ChallengeEvent {
  return event;
}
