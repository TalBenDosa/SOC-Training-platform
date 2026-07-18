/**
 * Rate-limit store abstraction — the seam for Phase 0.7.
 *
 * Today: `InMemoryRateLimitStore` — a per-instance fixed-window counter. Good
 * enough to stop casual abuse and runaway client loops, but it resets on cold
 * start and is not shared across serverless instances.
 *
 * Phase 0.7 (production): implement `UpstashRateLimitStore` (or Vercel KV) that
 * does an atomic INCR + EXPIRE against Redis, and switch `getRateLimitStore()`
 * to return it when UPSTASH_REDIS_* env is present. The middleware calls only
 * `checkRateLimit()`, so nothing else changes.
 */

export interface RateLimitResult {
  ok: boolean;
  /** Seconds until the window resets (only meaningful when !ok). */
  retryAfter: number;
}

export interface RateLimitStore {
  /** Record one hit for `key` and report whether it's within `limit` per `windowMs`. */
  hit(key: string, limit: number, windowMs: number): RateLimitResult;
}

type Bucket = { count: number; resetAt: number };

export class InMemoryRateLimitStore implements RateLimitStore {
  private store = new Map<string, Bucket>();

  hit(key: string, limit: number, windowMs: number): RateLimitResult {
    const now = Date.now();
    const b = this.store.get(key);
    if (!b || now >= b.resetAt) {
      this.store.set(key, { count: 1, resetAt: now + windowMs });
      this.sweep(now);
      return { ok: true, retryAfter: 0 };
    }
    b.count += 1;
    if (b.count > limit) {
      return { ok: false, retryAfter: Math.ceil((b.resetAt - now) / 1000) };
    }
    return { ok: true, retryAfter: 0 };
  }

  // Bound memory on long-lived instances.
  private sweep(now: number) {
    if (this.store.size < 5000) return;
    for (const [k, b] of this.store) if (now >= b.resetAt) this.store.delete(k);
  }
}

let singleton: RateLimitStore | null = null;

/** The active store. Swap the implementation here in Phase 0.7. */
export function getRateLimitStore(): RateLimitStore {
  if (!singleton) singleton = new InMemoryRateLimitStore();
  return singleton;
}

export function checkRateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  return getRateLimitStore().hit(key, limit, windowMs);
}
