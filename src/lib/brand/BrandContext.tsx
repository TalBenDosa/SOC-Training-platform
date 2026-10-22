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
import { PLATFORM_BRAND, PLATFORM_NAME, type Brand } from "./brand";
import { themeVars } from "./theme";
import { ALL_FEATURES, parseFeatures, type FeatureKey, type Features } from "./features";

export interface OrgBranding {
  name: string | null;
  color: string | null;
  logoUrl: string | null;
  /** Per-org gate bypass (migration 0036): every Learning Room unlocked for this org's members. */
  allRoomsUnlocked: boolean;
}

const EMPTY_ORG: OrgBranding = { name: null, color: null, logoUrl: null, allRoomsUnlocked: false };

interface BrandCtx {
  brand: Brand; org: OrgBranding; envBrand: Brand | null; hostBrand: Brand; features: Features;
  /** The client fetch for THIS session's environment has answered (until then, the server's
   *  answer from the (app) layout stands, so nothing flashes on load or after a switch). */
  envReady: boolean;
}
const Ctx = createContext<BrandCtx>({ brand: PLATFORM_BRAND, org: EMPTY_ORG, envBrand: null, hostBrand: PLATFORM_BRAND, features: ALL_FEATURES, envReady: false });

export function BrandProvider({ initial, children }: { initial: Brand; children: React.ReactNode }) {
  const { user } = useAuth();
  const [org, setOrg] = useState<OrgBranding>(EMPTY_ORG);
  const [envBrand, setEnvBrand] = useState<Brand | null>(null);
  const [features, setFeatures] = useState<Features>(ALL_FEATURES);
  const [envReady, setEnvReady] = useState(false);

  useEffect(() => {
    setEnvBrand(null);
    setFeatures(ALL_FEATURES);
    setEnvReady(false);
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
        setFeatures(parseFeatures(d.features));
        setEnvReady(true);
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

  return <Ctx.Provider value={{ brand, org, envBrand, hostBrand: initial, features, envReady }}>{children}</Ctx.Provider>;
}

/**
 * Inside the signed-in app only: the brand follows the environment the user is standing in
 * (a white-label org's logo and name in its own environment, the platform in every other).
 * A white-label domain keeps its host brand. Mounted by src/app/(app)/layout.tsx.
 */
export function AppBrandScope({ children, initialEnvBrand = null, initialFeatures = null }: {
  children: React.ReactNode;
  /** The environment's brand as the server resolved it for this request (src/lib/brand/appBrand.ts). */
  initialEnvBrand?: Brand | null;
  /** The environment's plan as the server resolved it, so the nav never shows then hides items. */
  initialFeatures?: Features | null;
}) {
  const c = useContext(Ctx);
  // The server's answer until the client fetch for this session has answered: the first paint
  // (and the one right after an environment switch, which reloads) is already the right brand.
  const env = c.envReady ? c.envBrand : initialEnvBrand;
  const brand = c.hostBrand.whiteLabel ? c.hostBrand : (env ?? c.hostBrand);
  const features = c.envReady ? c.features : (initialFeatures ?? c.features);

  // Server-rendered tab titles on a platform host carry the platform name; inside a
  // white-label environment swap the suffix for the environment's own name.
  useEffect(() => {
    if (!brand.whiteLabel || c.hostBrand.whiteLabel) return;
    const fix = () => {
      const suffix = ` // ${PLATFORM_NAME}`;
      if (document.title.includes(suffix)) document.title = document.title.replace(suffix, ` // ${brand.productName}`);
    };
    fix();
    const titleEl = document.querySelector("title");
    if (!titleEl) return;
    const obs = new MutationObserver(fix);
    obs.observe(titleEl, { childList: true, characterData: true, subtree: true });
    return () => obs.disconnect();
  }, [brand, c.hostBrand.whiteLabel]);

  // Inside a white-label environment on a platform host, its colours apply while the user is in
  // the app, and are removed again on the way out (the platform's palette is never overwritten
  // for good). On a white-label domain the server already rendered them.
  useEffect(() => {
    if (c.hostBrand.whiteLabel || !brand.whiteLabel || !brand.theme) return;
    const vars = themeVars(brand.theme);
    const root = document.documentElement;
    for (const [k, v] of Object.entries(vars)) root.style.setProperty(k, v);
    return () => { for (const k of Object.keys(vars)) root.style.removeProperty(k); };
  }, [brand, c.hostBrand.whiteLabel]);

  return <Ctx.Provider value={{ ...c, brand, features }}>{children}</Ctx.Provider>;
}

/** Who the platform presents itself as right now. */
export function useBrand(): Brand {
  return useContext(Ctx).brand;
}

/** The tenant theme's accent for generated cover art (undefined = the platform's colours). */
export function useCoverAccent(): string | undefined {
  return useContext(Ctx).brand.theme?.accent;
}

/** Which parts of the platform the current environment's plan includes (all for guests). */
export function useFeatures(): Features {
  return useContext(Ctx).features;
}

/** True when the current environment's plan includes this feature. */
export function useFeature(key: FeatureKey): boolean {
  return useContext(Ctx).features[key];
}

/** The signed-in learner's college branding (empty for guests). */
export function useOrgBranding(): OrgBranding {
  return useContext(Ctx).org;
}
