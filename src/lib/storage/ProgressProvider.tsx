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
import { ssGet, ssSet, ssRemove } from "@/lib/storage/safeStorage";
import { useAuth } from "@/lib/auth/AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { setStorageBackend, localStorageBackend } from "./backend";
import { createRemoteBackend } from "./remoteBackend";
import { broadcastXpChanged, broadcastProgressHydrated } from "./progress";
import { LEARNER_KEYS } from "./keys";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";

/**
 * Reload at most ONCE per (tab, identity) — the sessionStorage marker survives
 * the reload itself, so even if the same "should reload" condition re-computes
 * on the next load, the second reload is suppressed. This is the guard that
 * makes an infinite refresh loop structurally impossible.
 */
function reloadOncePerIdentity(identity: string) {
  const marker = `soc_backend_reloaded_${identity}`;
  if (ssGet(marker) === "1") return;
  // E-22: with sessionStorage blocked the marker can't be kept, and reloading
  // anyway would loop forever — stay on the page instead.
  if (!ssSet(marker, "1")) return;
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
    ssRemove("soc_backend_reloaded_guest");

    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    (async () => {
      // Snapshot local (guest) progress BEFORE swapping backends, in case this
      // is a brand-new account that should inherit it.
      const localSnapshot: Record<string, string | null> = {};
      for (const key of Object.values(LEARNER_KEYS)) localSnapshot[key] = localStorageBackend.get(key);

      // Read the tenant context from the session's JWT (stamped by the
      // access-token hook). Null until multi-tenancy is live — writes then omit
      // org_id and behave exactly as before.
      const { data: { session } } = await supabase.auth.getSession();
      const { orgId } = decodeOrgClaim(session?.access_token);

      const { backend: remote, hydrate } = createRemoteBackend(supabase, currentId, orgId);
      let { wasEmpty, rowsMissing, failed } = await hydrate();
      if (failed.length > 0) {
        // A transient read failure used to fill the cache with empty lists and
        // /progress showed "0 attempted" for a learner whose rows were safely in
        // the DB. Retry once before settling for a partial load.
        console.warn("[ProgressProvider] hydrate read failed, retrying:", failed.join(", "));
        await new Promise(r => setTimeout(r, 800));
        ({ wasEmpty, rowsMissing, failed } = await hydrate());
      }

      if (rowsMissing) {
        // Valid session, but the account's rows are gone — the user was deleted
        // server-side. Sign out cleanly instead of looping on a ghost account.
        console.warn("[ProgressProvider] account rows missing (deleted user?) — signing out");
        setStorageBackend(localStorageBackend);
        await supabase.auth.signOut();
        return; // auth state change re-runs this effect in the signed-out branch
      }

      const hasLocalProgress = Object.values(localSnapshot).some(v => v && v !== "0" && v !== "[]" && v !== "{}");
      // `wasEmpty` is already false when any read failed — a partial load must
      // never look like a brand-new account and pull guest data over it.
      const imported = wasEmpty && hasLocalProgress;
      if (imported) {
        for (const [key, value] of Object.entries(localSnapshot)) {
          if (value !== null) remote.set(key, value); // caches + persists to Supabase
        }
      }

      setStorageBackend(remote);
      // hydrate() populated the XP cache from the server's authoritative
      // profiles.xp, but did so directly (no event). Announce it now so the
      // /progress header and rank badge converge on the same total the class
      // leaderboard shows, instead of the stale mount-time value (0 on a fresh
      // device). Harmless on the reload path below — the reload re-reads anyway.
      broadcastXpChanged();
      // Components that read progress once on mount (RoomClient) mounted against
      // the empty pre-hydrate backend on a hard reload; tell them to re-read so
      // they don't resume from nothing and save over the server row.
      // Pages gate their first read on this (useProgressSnapshot) so a signed-in
      // learner never sees the empty pre-hydrate backend rendered as zeros.
      broadcastProgressHydrated(failed);
      // Reload only when the backend actually changed under mounted components:
      // a sign-in/out transition, or a one-time guest-progress import. NEVER on
      // plain `wasEmpty` (that's true on every load for any new account and
      // previously caused an infinite refresh loop). Guarded to once per tab.
      if (transitioned || imported) reloadOncePerIdentity(currentId);
    })();
  }, [user?.id, authEnabled, loading]);

  return <>{children}</>;
}
