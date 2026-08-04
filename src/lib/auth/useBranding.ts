"use client";
/**
 * The caller's college branding — name, accent colour, logo — for light
 * per-tenant theming (a badge in the top bar, an accent CSS variable). Fetched
 * once per session from /api/org/branding; empty for guests / pre-migration, so
 * the app keeps its default HACK THE SOC identity.
 */
import { useEffect, useState } from "react";
import { useAuth } from "./AuthContext";

export interface Branding {
  name: string | null;
  color: string | null;
  logoUrl: string | null;
}

const EMPTY: Branding = { name: null, color: null, logoUrl: null };

export function useBranding(): Branding {
  const { user } = useAuth();
  const [branding, setBranding] = useState<Branding>(EMPTY);

  useEffect(() => {
    if (!user) { setBranding(EMPTY); return; }
    let cancelled = false;
    fetch("/api/org/branding")
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (cancelled || !d) return;
        const color = typeof d.branding?.color === "string" ? d.branding.color : null;
        setBranding({ name: d.name ?? null, color, logoUrl: d.branding?.logo_url ?? null });
        if (color) document.documentElement.style.setProperty("--org-accent", color);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [user]);

  return branding;
}
