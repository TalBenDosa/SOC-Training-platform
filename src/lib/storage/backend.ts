/**
 * Storage backend abstraction — the ONE place Phase 1 swaps localStorage for a
 * server-backed store.
 *
 * Today: `localStorageBackend` (synchronous, browser localStorage, SSR-safe).
 *
 * Phase 1 (server DB): introduce a `ProgressProvider` React context that, on
 * mount, hydrates the authenticated user's data from the API into an in-memory
 * cache, and exposes a backend whose `get` reads that cache (still sync for the
 * UI) while `set` writes through to the API (fire-and-forget or queued). Then
 * call `setStorageBackend(remoteBackend)` once at app start. Because every
 * learner read/write already goes through the facades in this folder, NO call
 * site changes — the migration is contained to this file + the provider.
 *
 * The interface is deliberately sync to match the current UI (which reads in
 * render/effects). The remote backend keeps that contract via the hydrate-then-
 * read-cache pattern above; genuinely async operations (initial load) live in
 * the provider, not in these getters.
 */

export interface StorageBackend {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

// SSR / no-window fallback so importing a facade on the server never throws.
const memoryFallback = new Map<string, string>();

export const localStorageBackend: StorageBackend = {
  get(key) {
    try {
      if (typeof window === "undefined") return memoryFallback.get(key) ?? null;
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      if (typeof window === "undefined") { memoryFallback.set(key, value); return; }
      window.localStorage.setItem(key, value);
    } catch {
      /* quota / disabled storage — non-fatal */
    }
  },
  remove(key) {
    try {
      if (typeof window === "undefined") { memoryFallback.delete(key); return; }
      window.localStorage.removeItem(key);
    } catch {
      /* non-fatal */
    }
  },
};

let activeBackend: StorageBackend = localStorageBackend;

/** The backend all facades read/write through. */
export const backend: StorageBackend = {
  get: (k) => activeBackend.get(k),
  set: (k, v) => activeBackend.set(k, v),
  remove: (k) => activeBackend.remove(k),
};

/** Phase 1 entry point: install a server-backed backend at app start. */
export function setStorageBackend(next: StorageBackend): void {
  activeBackend = next;
}

// ─── JSON helpers used by every facade ──────────────────────────────────────────
export function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = backend.get(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

export function writeJson(key: string, value: unknown): void {
  try {
    backend.set(key, JSON.stringify(value));
  } catch {
    /* non-fatal */
  }
}
