"use client";
/**
 * The brand every client component reads (white label, ./brand.ts), plus the signed-in
 * learner's college branding (name / colour / logo / all-rooms-unlocked), fetched ONCE per
 * session here instead of once per component that asked.
 *
 * `brand` is resolved on the server from the request host and never changes on the client:
 * a white-label organization's brand shows ONLY on its own domain. On the platform's hosts
 * everyone (the super-admin moving between environments included) sees the platform.
 */
import { createContext, useContext, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import { PLATFORM_BRAND, type Brand } from "./brand";

export interface OrgBranding {
  name: string | null;
  color: string | null;
  logoUrl: string | null;
  /** Per-org gate bypass (migration 0036): every Learning Room unlocked for this org's members. */
  allRoomsUnlocked: boolean;
}

const EMPTY_ORG: OrgBranding = { name: null, color: null, logoUrl: null, allRoomsUnlocked: false };

const Ctx = createContext<{ brand: Brand; org: OrgBranding }>({ brand: PLATFORM_BRAND, org: EMPTY_ORG });

export function BrandProvider({ initial, children }: { initial: Brand; children: React.ReactNode }) {
  const { user } = useAuth();
  const [org, setOrg] = useState<OrgBranding>(EMPTY_ORG);

  useEffect(() => {
    if (!user) { setOrg(EMPTY_ORG); return; }
    let cancelled = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    // E-23 (QA phase 7): one failed read left the college's "all rooms unlocked" setting off
    // for the whole visit; retry once after a short pause before falling back to the defaults.
    const load = (again: boolean) => fetch("/api/org/branding")
      .then(r => {
        if (r.status >= 500) throw new Error(`status ${r.status}`);
        return r.ok ? r.json() : null;
      })
      .then(d => {
        if (cancelled || !d) return;
        const color = typeof d.branding?.color === "string" ? d.branding.color : null;
        setOrg({ name: d.name ?? null, color, logoUrl: d.branding?.logo_url ?? null, allRoomsUnlocked: d.all_rooms_unlocked === true });
      })
      .catch(() => { if (again && !cancelled) retry = setTimeout(() => { void load(false); }, 3000); });
    void load(true);
    return () => { cancelled = true; if (retry) clearTimeout(retry); };
  }, [user]);

  const brand = initial;
  const accent = brand.color ?? org.color;
  useEffect(() => {
    if (accent) document.documentElement.style.setProperty("--org-accent", accent);
  }, [accent]);

  return <Ctx.Provider value={{ brand, org }}>{children}</Ctx.Provider>;
}

/** Who the platform presents itself as right now. */
export function useBrand(): Brand {
  return useContext(Ctx).brand;
}

/** The signed-in learner's college branding (empty for guests). */
export function useOrgBranding(): OrgBranding {
  return useContext(Ctx).org;
}
