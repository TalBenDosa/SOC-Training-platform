import "server-only";
import { timingSafeEqual } from "node:crypto";

/**
 * Constant-time string comparison for secrets (e.g. the cron Bearer token).
 *
 * A plain `a === b` short-circuits on the first differing byte, which is a
 * timing side-channel: an attacker can, in principle, recover a secret byte by
 * byte from response-time differences. `timingSafeEqual` compares in time that
 * does not depend on where the strings differ.
 *
 * The length check before the compare deliberately leaks only the LENGTH of the
 * secret (timingSafeEqual itself requires equal-length buffers). That is the
 * standard, accepted trade-off — the secret's length is not the sensitive part.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
