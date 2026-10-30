import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Attempt tokens tie a graded submission to an investigation that was actually
 * started. Before this, `POST /grade` with an empty body returned the answer
 * key and the full debrief to anyone, and `timeTaken` was whatever the client
 * said it was (so `0` always earned the time bonus).
 *
 * The token is an HMAC over `<slug>.<startedAt>`; the grader recomputes the
 * elapsed time from `startedAt` itself. It is stateless on purpose: the
 * platform works for guests with no database, so there is no attempts table to
 * look up. It does not stop a determined user from starting an attempt and
 * submitting garbage to read the key — that needs per-user attempt tracking —
 * but it closes the zero-effort oracle and the client-dictated clock.
 *
 * Secret: `AUTH_SECRET` when configured. Otherwise a per-process random secret,
 * which is fine for a single dev instance and means tokens do not survive a
 * restart (the student just restarts the attempt).
 */

const MAX_ATTEMPT_AGE_MS = 6 * 60 * 60 * 1000; // 6 hours

let fallbackSecret: Buffer | null = null;
function secret(): Buffer {
  const configured = process.env.AUTH_SECRET;
  if (configured && configured.length >= 16) return Buffer.from(configured, "utf8");
  if (!fallbackSecret) fallbackSecret = randomBytes(32);
  return fallbackSecret;
}

function sign(slug: string, startedAt: number): string {
  return createHmac("sha256", secret()).update(`${slug}.${startedAt}`).digest("base64url");
}

export interface AttemptToken {
  token: string;
  startedAt: number;
}

export function issueAttemptToken(slug: string, now = Date.now()): AttemptToken {
  return { startedAt: now, token: `${now}.${sign(slug, now)}` };
}

export type AttemptVerification =
  | { ok: true; startedAt: number; elapsedSeconds: number }
  | { ok: false; reason: "malformed" | "bad-signature" | "expired" | "future" };

export function verifyAttemptToken(slug: string, token: string, now = Date.now()): AttemptVerification {
  const dot = token.indexOf(".");
  if (dot <= 0) return { ok: false, reason: "malformed" };
  const startedAt = Number(token.slice(0, dot));
  const sig = token.slice(dot + 1);
  if (!Number.isInteger(startedAt) || !sig) return { ok: false, reason: "malformed" };

  const expected = Buffer.from(sign(slug, startedAt));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
    return { ok: false, reason: "bad-signature" };
  }
  if (startedAt > now + 60_000) return { ok: false, reason: "future" };
  if (now - startedAt > MAX_ATTEMPT_AGE_MS) return { ok: false, reason: "expired" };

  return { ok: true, startedAt, elapsedSeconds: Math.max(0, Math.floor((now - startedAt) / 1000)) };
}
