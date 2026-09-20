/**
 * Challenge delivery transport interface (T-136 contract §3.2, §7).
 *
 * The wire is Phase 4 (pinned-TLS LAN channel / push relay). This scaffold
 * ships only the interface + a fail-closed offline stub so the queue logic
 * is fully testable and the app can never silently "deliver" anything.
 */
import type { ChallengeResponseData } from "../protocol/types";

export type TransportResult =
  | { kind: "delivered"; requestId: string }
  | { kind: "offline"; reason: string };

export interface ChallengeTransport {
  /** Best-effort POST of a response; never throws — resolves a result. */
  postResponse(resp: ChallengeResponseData): Promise<TransportResult>;
}

/** Scaffold default: permanently offline — nothing is ever sent. */
export class OfflineTransport implements ChallengeTransport {
  async postResponse(_resp: ChallengeResponseData): Promise<TransportResult> {
    return { kind: "offline", reason: "transport lands in Phase 4 (contract §3.2)" };
  }
}
