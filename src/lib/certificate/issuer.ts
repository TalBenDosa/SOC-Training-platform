/**
 * Who issued a certificate, and where it points (#32 of the team-exercise report).
 *
 * The certificates printed "Issued by Individual" — the raw name of the
 * platform's own system org that solo learners and the super-admin belong to —
 * and the footer URL was `hack-the-soc.vercel.app` (the deployment alias) or,
 * in the rank modal, `window.location.origin` (so a localhost preview baked
 * "http://localhost:3000" into a shareable image). A certificate is an external
 * artefact: it names a real issuing organisation or the platform itself, and
 * always the canonical production domain.
 */
import { isRootOrg } from "@/lib/org/rootEnvironment";

/** Canonical production origin — never the Vercel alias, never the current host. */
export const PRODUCTION_ORIGIN = "https://www.hackthesoc.app";
/** The same, as printed on a certificate. */
export const PRODUCTION_HOST = "www.hackthesoc.app";
export const PLATFORM_ISSUER = "HACK THE SOC";

// Names that describe "no organisation" rather than an organisation — the
// system org has been called "Internal / Default" and "Individual".
const PLACEHOLDER_ORG = /^(individual|individuals|personal|internal|default|internal\s*\/\s*default|none|n\/a|solo)$/i;

/**
 * The issuer to print: the learner's organisation when they belong to a real
 * one (a college / customer), otherwise the platform.
 */
export function certificateIssuer(orgId: string | null | undefined, orgName: string | null | undefined): string {
  const name = (orgName ?? "").trim();
  if (!name || isRootOrg(orgId) || PLACEHOLDER_ORG.test(name)) return PLATFORM_ISSUER;
  return name;
}

/** True when the issuer is a real organisation (not the platform fallback). */
export function hasOrgIssuer(orgId: string | null | undefined, orgName: string | null | undefined): boolean {
  return certificateIssuer(orgId, orgName) !== PLATFORM_ISSUER;
}
