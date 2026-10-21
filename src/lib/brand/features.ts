/**
 * Which parts of the platform an organization gets (its plan): part of the one tenant config
 * (organizations.branding.features), set by the super-admin per organization, white label or
 * not. A feature that is off disappears from the navigation AND its pages redirect away
 * (server-side, src/lib/brand/requireFeature.ts); APIs that start paid work check it too.
 * Missing = on, so every existing organization keeps everything it has today.
 * Isomorphic: no server or React imports.
 */

export const FEATURES = {
  learning_rooms: { label: "Learning Rooms", routes: ["/rooms"] },
  live_soc: { label: "Live SOC Dashboard + EDR", routes: ["/dashboard", "/edr"] },
  learning_path: { label: "Learning Path", routes: ["/learn"] },
  scenarios: { label: "Scenarios", routes: ["/scenarios"] },
  quizzes: { label: "Quizzes", routes: ["/quizzes"] },
  achievements: { label: "Achievements & certificates", routes: ["/achievements"] },
  college_materials: { label: "College Materials", routes: ["/resources"] },
  team_training: { label: "Team Training", routes: ["/team"] },
} as const;

export type FeatureKey = keyof typeof FEATURES;
export type Features = Record<FeatureKey, boolean>;

export const FEATURE_KEYS = Object.keys(FEATURES) as FeatureKey[];

export const ALL_FEATURES: Features = Object.fromEntries(FEATURE_KEYS.map(k => [k, true])) as Features;

/** Stored JSON → the full feature set (only an explicit `false` turns a feature off). */
export function parseFeatures(raw: unknown): Features {
  const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return Object.fromEntries(FEATURE_KEYS.map(k => [k, r[k] !== false])) as Features;
}

/** What to store: only the switched-off features (an all-on plan stores nothing). */
export function sanitizeFeatures(raw: unknown): Partial<Features> | null {
  const f = parseFeatures(raw);
  const off = FEATURE_KEYS.filter(k => !f[k]);
  return off.length ? (Object.fromEntries(off.map(k => [k, false])) as Partial<Features>) : null;
}

/** The feature a path belongs to (null = always available, e.g. /progress, /account). */
export function featureForPath(pathname: string): FeatureKey | null {
  for (const k of FEATURE_KEYS) {
    if (FEATURES[k].routes.some(r => pathname === r || pathname.startsWith(`${r}/`))) return k;
  }
  return null;
}
