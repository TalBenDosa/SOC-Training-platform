"use client";
/**
 * The name to show the learner.
 *
 * The signup form lets someone choose a nickname, which lands in
 * profiles.handle. Without this hook that choice would be invisible: the
 * Topbar and the welcome screen both derived a name from the email local part,
 * so a user who picked "nightowl" would still see "tal14997" everywhere and
 * reasonably conclude the field did nothing.
 *
 * Falls back to the email local part while the profile is loading and if the
 * lookup fails, which is exactly what those screens showed before — so a
 * failure here degrades to the old behaviour rather than to a blank.
 */
import { useEffect, useState } from "react";
import { useAuth } from "./AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export function useDisplayName(): string {
  const { user } = useAuth();
  const fallback = user?.email?.split("@")[0] ?? "analyst";
  const [name, setName] = useState(fallback);

  useEffect(() => {
    setName(fallback);
    if (!user) return;

    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    let cancelled = false;
    // profiles SELECT is owner-only (migration 0004), so this reads the
    // signed-in user's own row and nothing else.
    supabase
      .from("profiles")
      .select("handle")
      .eq("id", user.id)
      .maybeSingle()
      .then(({ data }) => {
        if (cancelled) return;
        const handle = (data as { handle?: string } | null)?.handle;
        // The generated fallback handle looks like "tal14997_d0b992" — a
        // derived value nobody chose. Showing it would be worse than the email
        // local part it was built from, so only a CHOSEN handle wins.
        if (handle && !/_[0-9a-f]{6}$/.test(handle)) setName(handle);
      });

    return () => { cancelled = true; };
  }, [user, fallback]);

  return name;
}
