"use client";
/**
 * Bridges auth state to the storage backend. Mounted once near the root:
 *  - Signed out (or Supabase not configured): does nothing — the app already
 *    defaults to `localStorageBackend`, guest mode, unchanged from today.
 *  - Signs in: hydrates a `RemoteBackend` from the user's Supabase rows, does a
 *    ONE-TIME import of this device's local guest progress if the account is
 *    brand new (see `signup/page.tsx`'s "progress carries over" promise), then
 *    swaps `backend.ts` over to it and reloads once so every already-mounted
 *    component re-reads from the now-authoritative remote data.
 *  - Signs out: swaps back to localStorageBackend and reloads once.
 */
import { useEffect, useRef } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { setStorageBackend, localStorageBackend } from "./backend";
import { createRemoteBackend } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";

export function ProgressProvider({ children }: { children: React.ReactNode }) {
  const { user, authEnabled, loading } = useAuth();
  const prevUserId = useRef<string | null | undefined>(undefined); // undefined = "not yet initialized"

  useEffect(() => {
    if (!authEnabled || loading) return;

    const currentId = user?.id ?? null;
    const isFirstRun = prevUserId.current === undefined;
    const transitioned = !isFirstRun && prevUserId.current !== currentId;
    prevUserId.current = currentId;

    if (!currentId) {
      // Signed out (or never signed in) — guest mode.
      setStorageBackend(localStorageBackend);
      if (transitioned) window.location.reload();
      return;
    }

    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    (async () => {
      // Snapshot local (guest) progress BEFORE swapping backends, in case this
      // is a brand-new account that should inherit it.
      const localSnapshot: Record<string, string | null> = {};
      for (const key of Object.values(LEARNER_KEYS)) localSnapshot[key] = localStorageBackend.get(key);

      const { backend: remote, hydrate } = createRemoteBackend(supabase, currentId);
      const { wasEmpty } = await hydrate();

      const hasLocalProgress = Object.values(localSnapshot).some(v => v && v !== "0" && v !== "[]" && v !== "{}");
      if (wasEmpty && hasLocalProgress) {
        for (const [key, value] of Object.entries(localSnapshot)) {
          if (value !== null) remote.set(key, value); // caches + persists to Supabase
        }
      }

      setStorageBackend(remote);
      if (transitioned || wasEmpty) window.location.reload();
    })();
  }, [user?.id, authEnabled, loading]);

  return <>{children}</>;
}
