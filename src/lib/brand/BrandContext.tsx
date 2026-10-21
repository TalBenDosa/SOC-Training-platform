"use client";
/**
 * The brand every client component reads (white label, ./brand.ts), plus the signed-in
 * learner's college branding (name / colour / logo / all-rooms-unlocked), fetched ONCE per
 * session here instead of once per component that asked.
 *
 * A white-label domain always shows its own organization (resolved on the server from the
 * host, so from the first paint). On the platform's hosts every page shows the platform
 * (the public landing page, sign-in, privacy... are HACK THE SOC, always); only INSIDE the app
 * (AppBrandScope, mounted by the (app) layout) does the brand follow the environment the user
 * is standing in. Iron rule: one environment's identity never appears in another, so the
 * environment brand is cleared on every load and only applied when the server confirms it
 * belongs to the session's current environment.
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

interface BrandCtx { brand: Brand; org: OrgBranding; envBrand: Brand | null; hostBrand: Brand }
const Ctx = createContext<BrandCtx>({ brand: PLATFORM_BRAND, org: EMPTY_ORG, envBrand: null, hostBrand: PLATFORM_BRAND });

export function BrandProvider({ initial, children }: { initial: Brand; children: React.ReactNode }) {
  const { user } = useAuth();
  const [org, setOrg] = useState<OrgBranding>(EMPTY_ORG);
  const [envBrand, setEnvBrand] = useState<Brand | null>(null);

  useEffect(() => {
    setEnvBrand(null);
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
        setEnvBrand(d.brand && d.brand.whiteLabel === true ? (d.brand as Brand) : null);
      })
      .catch(() => { if (again && !cancelled) retry = setTimeout(() => { void load(false); }, 3000); });
    void load(true);
    return () => { cancelled = true; if (retry) clearTimeout(retry); };
  }, [user]);

  // Outside the app the brand is the host's, full stop (see AppBrandScope for inside).
  const brand = initial;
  const accent = brand.color ?? org.color;
  useEffect(() => {
    if (accent) document.documentElement.style.setProperty("--org-accent", accent);
  }, [accent]);

  return <Ctx.Provider value={{ brand, org, envBrand, hostBrand: initial }}>{children}</Ctx.Provider>;
}

/**
 * Inside the signed-in app only: the brand follows the environment the user is standing in
 * (a white-label org's logo and name in its own environment, the platform in every other).
 * A white-label domain keeps its host brand. Mounted by src/app/(app)/layout.tsx.
 */
export function AppBrandScope({ children }: { children: React.ReactNode }) {
  const c = useContext(Ctx);
  const brand = c.hostBrand.whiteLabel ? c.hostBrand : (c.envBrand ?? c.hostBrand);

  // Server-rendered tab titles on a platform host carry the platform name; inside a
  // white-label environment swap the suffix for the environment's own name.
  useEffect(() => {
    if (!brand.whiteLabel || c.hostBrand.whiteLabel) return;
    const fix = () => {
      if (document.title.includes(" // HACK THE SOC")) document.title = document.title.replace(" // HACK THE SOC", ` // ${brand.productName}`);
    };
    fix();
    const titleEl = document.querySelector("title");
    if (!titleEl) return;
    const obs = new MutationObserver(fix);
    obs.observe(titleEl, { childList: true, characterData: true, subtree: true });
    return () => obs.disconnect();
  }, [brand, c.hostBrand.whiteLabel]);

  return <Ctx.Provider value={{ ...c, brand }}>{children}</Ctx.Provider>;
}

/** Who the platform presents itself as right now. */
export function useBrand(): Brand {
  return useContext(Ctx).brand;
}

/** The signed-in learner's college branding (empty for guests). */
export function useOrgBranding(): OrgBranding {
  return useContext(Ctx).org;
}
