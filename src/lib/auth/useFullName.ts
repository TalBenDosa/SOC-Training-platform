"use client";
/**
 * The name to print on a certificate.
 *
 * A certificate is a public, shareable artefact, so it should carry the
 * learner's REAL name when they gave one. The signup form now offers an
 * optional "full name" that lands in profiles.display_name; this hook prefers
 * it, then falls back to the chosen handle, then to the email local part —
 * exactly the same graceful degradation as useDisplayName, one rung richer.
 *
 * Kept separate from useDisplayName on purpose: the Topbar identity is the
 * handle (a nickname you operate under), while the certificate is your name.
 * Merging them would force one choice on both surfaces.
 */
import { useEffect, useState } from "react";
import { useAuth } from "./AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

/** Generated fallback handles look like "tal14997_d0b992" — nobody chose them. */
const GENERATED_HANDLE = /_[0-9a-f]{6}$/;

export function useFullName(): string {
  const { user } = useAuth();
  const fallback = user?.email?.split("@")[0] ?? "Analyst";
  const [name, setName] = useState(fallback);

  useEffect(() => {
    setName(fallback);
    if (!user) return;

    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    let cancelled = false;
    // profiles SELECT is owner-only (migration 0004) — this reads only the
    // signed-in user's own row.
    supabase
      .from("profiles")
      .select("handle, display_name")
      .eq("id", user.id)
      .maybeSingle()
      .then(({ data }) => {
        if (cancelled) return;
        const row = data as { handle?: string; display_name?: string } | null;
        const display = row?.display_name?.trim();
        const handle = row?.handle?.trim();
        // A real full name is any display_name that isn't just a copy of the
        // generated handle. Trigger 0009 fills it from the signup "full name";
        // for older accounts it equals the handle/email-part, which is still a
        // fine thing to certify.
        if (display && !GENERATED_HANDLE.test(display)) {
          setName(display);
        } else if (handle && !GENERATED_HANDLE.test(handle)) {
          setName(handle);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [user, fallback]);

  return name;
}
