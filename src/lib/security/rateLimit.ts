/**
 * Rate-limit store abstraction.
 *
 * Two backends behind one async `hit()` seam:
 *
 *  - `InMemoryRateLimitStore` — a per-instance fixed-window counter. Stops casual
 *    abuse and runaway client loops, but resets on cold start and is NOT shared
 *    across serverless/edge instances. This is the fallback.
 *
 *  - `UpstashRateLimitStore` — a durable, cross-instance fixed-window counter
 *    backed by Upstash Redis over its REST API (edge-safe, fetch-based, no SDK
 *    dependency). Active automatically when `UPSTASH_REDIS_REST_URL` and
 *    `UPSTASH_REDIS_REST_TOKEN` are set. This is the production posture: a limit
 *    of "10/min" actually means 10/min for a client, regardless of which edge
 *    instance serves each request.
 *
 * The interface is async because a durable store does network I/O. The in-memory
 * store simply resolves immediately, so nothing regresses when Upstash is absent.
 *
 * FAIL-OPEN on store errors: if the durable store is unreachable, a request is
 * allowed rather than blocked. Rate limiting is an abuse/cost control, not an
 * authentication boundary (that is enforced separately in middleware via
 * getUser()), so a transient Redis outage must not take the whole API down.
 */

export interface RateLimitResult {
  ok: boolean;
  /** Seconds until the window resets (only meaningful when !ok). */
  retryAfter: number;
}

export interface RateLimitStore {
  /** Record one hit for `key` and report whether it's within `limit` per `windowMs`. */
  hit(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
}

type Bucket = { count: number; resetAt: number };

export class InMemoryRateLimitStore implements RateLimitStore {
  private store = new Map<string, Bucket>();

  async hit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
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

/**
 * Durable fixed-window counter over Upstash Redis (REST).
 *
 * One pipelined round trip per hit does the whole atomic operation:
 *   INCR key                → the running count in this window
 *   EXPIRE key <sec> NX     → arm the window TTL only on the first hit (NX)
 *   PTTL key                → remaining window, to compute Retry-After
 *
 * `EXPIRE ... NX` is what makes it a fixed window: the TTL is set once, when the
 * key is created, and not extended by later hits — so the window is anchored to
 * the first request, not sliding forward on every call.
 */
export class UpstashRateLimitStore implements RateLimitStore {
  constructor(private url: string, private token: string) {}

  async hit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const sec = Math.max(1, Math.ceil(windowMs / 1000));
    const redisKey = `rl:${key}`;
    try {
      const res = await fetch(`${this.url}/pipeline`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([
          ["INCR", redisKey],
          ["EXPIRE", redisKey, String(sec), "NX"],
          ["PTTL", redisKey],
        ]),
        // Never let a slow Redis hang the request path.
        signal: AbortSignal.timeout(1500),
      });

      if (!res.ok) return failOpen();

      // Pipeline returns [{result:count},{result:0|1},{result:ttlMs}].
      const parsed = (await res.json()) as Array<{ result?: unknown; error?: string }>;
      const count = Number(parsed?.[0]?.result ?? 0);
      const ttlMs = Number(parsed?.[2]?.result ?? windowMs);
      if (!Number.isFinite(count) || count <= 0) return failOpen();

      if (count > limit) {
        const retryAfter = ttlMs > 0 ? Math.ceil(ttlMs / 1000) : sec;
        return { ok: false, retryAfter };
      }
      return { ok: true, retryAfter: 0 };
    } catch {
      return failOpen();
    }
  }
}

/** Rate limiting is a cost/abuse control, not an auth gate → allow on store failure. */
function failOpen(): RateLimitResult {
  return { ok: true, retryAfter: 0 };
}

let singleton: RateLimitStore | null = null;

/**
 * The active store. Prefers the durable Upstash backend when its env is present,
 * otherwise falls back to the per-instance in-memory counter. Reads process.env
 * directly (rather than the zod-parsed serverEnv) to stay light on the edge
 * runtime where the middleware runs.
 */
export function getRateLimitStore(): RateLimitStore {
  if (singleton) return singleton;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  singleton = url && token
    ? new UpstashRateLimitStore(url, token)
    : new InMemoryRateLimitStore();
  return singleton;
}

export async function checkRateLimit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
  return getRateLimitStore().hit(key, limit, windowMs);
}
