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

/**
 * Reload at most ONCE per (tab, identity) — the sessionStorage marker survives
 * the reload itself, so even if the same "should reload" condition re-computes
 * on the next load, the second reload is suppressed. This is the guard that
 * makes an infinite refresh loop structurally impossible.
 */
function reloadOncePerIdentity(identity: string) {
  const marker = `soc_backend_reloaded_${identity}`;
  if (sessionStorage.getItem(marker) === "1") return;
  sessionStorage.setItem(marker, "1");
  window.location.reload();
}

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
      if (transitioned) reloadOncePerIdentity("guest");
      return;
    }

    // New identity — clear the guest marker so a future sign-out can reload again.
    sessionStorage.removeItem("soc_backend_reloaded_guest");

    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    (async () => {
      // Snapshot local (guest) progress BEFORE swapping backends, in case this
      // is a brand-new account that should inherit it.
      const localSnapshot: Record<string, string | null> = {};
      for (const key of Object.values(LEARNER_KEYS)) localSnapshot[key] = localStorageBackend.get(key);

      const { backend: remote, hydrate } = createRemoteBackend(supabase, currentId);
      const { wasEmpty, rowsMissing } = await hydrate();

      if (rowsMissing) {
        // Valid session, but the account's rows are gone — the user was deleted
        // server-side. Sign out cleanly instead of looping on a ghost account.
        console.warn("[ProgressProvider] account rows missing (deleted user?) — signing out");
        setStorageBackend(localStorageBackend);
        await supabase.auth.signOut();
        return; // auth state change re-runs this effect in the signed-out branch
      }

      const hasLocalProgress = Object.values(localSnapshot).some(v => v && v !== "0" && v !== "[]" && v !== "{}");
      const imported = wasEmpty && hasLocalProgress;
      if (imported) {
        for (const [key, value] of Object.entries(localSnapshot)) {
          if (value !== null) remote.set(key, value); // caches + persists to Supabase
        }
      }

      setStorageBackend(remote);
      // Reload only when the backend actually changed under mounted components:
      // a sign-in/out transition, or a one-time guest-progress import. NEVER on
      // plain `wasEmpty` (that's true on every load for any new account and
      // previously caused an infinite refresh loop). Guarded to once per tab.
      if (transitioned || imported) reloadOncePerIdentity(currentId);
    })();
  }, [user?.id, authEnabled, loading]);

  return <>{children}</>;
}
