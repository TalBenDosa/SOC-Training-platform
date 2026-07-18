/**
 * Attack Story registry — the single source of truth for per-session attack narratives.
 *
 * Each story is a coherent, ordered kill-chain (10 events) built from the
 * scenario bundles in src/lib/sim/scenarios.ts. The dashboard picks ONE story
 * per session (per company), injects its events IN ORDER in small phases, and
 * uses the story metadata (title + MITRE techniques) as ground truth for the
 * incident-report grader.
 *
 * Diversity guarantees:
 *  - Company fit: a story is only offered to companies whose SIEM architecture
 *    actually contains the story's log sources (K8s pod escape never appears
 *    at a hospital with no Kubernetes).
 *  - Anti-repeat memory: the last N picked story ids are remembered in
 *    localStorage so consecutive sessions always see different attacks.
 *  - Victim variation: ~50% of sessions swap the victim user for another
 *    employee from the company pool.
 */

import {
  buildPhishingToExfil, buildBecScenario, buildRansomwareScenario, buildOAuthScenario,
  buildInsiderThreatScenario, buildImpossibleTravelScenario, buildCloudCryptoMiningScenario,
  buildDCSyncScenario, buildSupplyChainScenario, buildMfaFatigueScenario,
  buildAsRepRoastingScenario, buildNtlmRelayScenario, buildK8sPodEscapeScenario,
  buildOAuthConsentPhishingScenario, buildKerberoastingScenario, buildDNSTunnelingScenario,
  buildLOLBinsScenario, buildPhishingMalwareScenario, buildUsbMalwareScenario,
  buildBrowserExtensionMalwareScenario, buildTechSupportScamScenario,
  buildCrackedSoftwareScenario, buildMaliciousMacroScenario,
} from "@/lib/sim/scenarios";
import { COMPANY_PROFILES, COMPANY_ATTACKS, ROCKETSTACK_CRED_STUFFING_CHAIN } from "@/lib/sim/companyProfiles";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * Real difficulty for STORY SELECTION — how simple the attack itself is for a
 * student who is brand-new to SOC work, not how "advanced" the technique
 * sounds. This is independent of scenarios.ts's own `difficulty` field, which
 * grades attacker sophistication and was found (2026-07-03 alignment audit)
 * to mislabel several multi-stage identity attacks as "beginner."
 *  - foundation: one host, one user, no lateral movement, no credential
 *    theft, no cloud pivot. Safe as literally the first attack ever seen.
 *  - core: contained to one system/domain but multi-stage, or requires
 *    reading more than one log source together.
 *  - advanced: full kill chain — lateral movement, credential theft, cloud
 *    pivot, or multi-host/multi-domain reasoning.
 */
export type StoryComplexity = "foundation" | "core" | "advanced";

export interface AttackStory {
  id: string;
  title: string;
  events: TelemetryEvent[];
  /** Unique MITRE technique ids across the story's events — report ground truth */
  mitre: string[];
  /** Explicit company allowlist. Omitted = decided by the source-fit rule. */
  companies?: string[];
  complexity: StoryComplexity;
}

// ── Scenario bundles (instantiated once at module load) ───────────────────────

const _phishing         = buildPhishingToExfil();
const _bec              = buildBecScenario();
const _ransomware       = buildRansomwareScenario();
const _oauth            = buildOAuthScenario();
const _insider          = buildInsiderThreatScenario();
const _impossibleTravel = buildImpossibleTravelScenario();
const _cryptomining     = buildCloudCryptoMiningScenario();
const _dcsync           = buildDCSyncScenario();
const _supplyChain      = buildSupplyChainScenario();
const _mfaFatigue       = buildMfaFatigueScenario();
const _asrepRoasting    = buildAsRepRoastingScenario();
const _ntlmRelay        = buildNtlmRelayScenario();
const _k8sPodEscape     = buildK8sPodEscapeScenario();
const _oauthConsent     = buildOAuthConsentPhishingScenario();
const _kerberoasting    = buildKerberoastingScenario();
const _dnsTunneling     = buildDNSTunnelingScenario();
const _lolbins          = buildLOLBinsScenario();
const _phishingMalware  = buildPhishingMalwareScenario();
const _usbMalware       = buildUsbMalwareScenario();
const _browserExtension = buildBrowserExtensionMalwareScenario();
const _techSupportScam  = buildTechSupportScamScenario();
const _crackedSoftware  = buildCrackedSoftwareScenario();
const _maliciousMacro   = buildMaliciousMacroScenario();

/** Scenario info still needed by the Start-Training modal on the dashboard page */
export const SCENARIO_INFO = {
  phishing: { title: _phishing.title, narrative: _phishing.narrative, threat_actor: _phishing.threat_actor, events: _phishing.events },
  bec:      { title: _bec.title,      narrative: _bec.narrative,      threat_actor: _bec.threat_actor,      events: _bec.events      },
};

const deriveMitre = (events: TelemetryEvent[]): string[] =>
  Array.from(new Set(events.map(e => e.mitre_technique).filter(Boolean))) as string[];

const story = (
  id: string,
  bundle: { title: string; events: TelemetryEvent[] },
  complexity: StoryComplexity,
  companies?: string[],
): AttackStory => ({
  id,
  title: bundle.title,
  // Stamp each event with the story's tier so enrichEvent can scale log fidelity
  // (clean for foundation, production-grade noise for advanced).
  events: bundle.events.map(e => ({ ...e, tier: e.tier ?? complexity })),
  mitre: deriveMitre(bundle.events),
  complexity,
  ...(companies ? { companies } : {}),
});

const GENERIC_STORIES: AttackStory[] = [
  // ── foundation: one host, one user, no lateral movement — safe as a first attack ──
  story("phishing-malware",     _phishingMalware,     "foundation"),
  story("usb-malware",          _usbMalware,          "foundation"),
  story("browser-extension",    _browserExtension,    "foundation"),
  story("tech-support-scam",    _techSupportScam,     "foundation"),
  story("cracked-software",     _crackedSoftware,     "foundation"),
  story("malicious-macro",      _maliciousMacro,      "foundation"),

  // ── core: contained but multi-stage, or needs more than one log source read together ──
  story("insider",          _insider,          "core"),
  story("impossible-travel", _impossibleTravel, "core"),

  // ── advanced: full kill chain — lateral movement, credential theft, cloud pivot, or
  // multi-account/multi-domain reasoning. Mislabeled "beginner" by scenarios.ts's own
  // difficulty field for bec/mfa-fatigue (attacker-sophistication axis, not
  // student-readiness) — reclassified here per the 2026-07-03 alignment audit.
  story("phishing",          _phishing,        "advanced"),
  story("bec",               _bec,             "advanced"),
  story("ransomware",        _ransomware,      "advanced"),
  story("oauth",             _oauth,           "advanced"),
  story("cryptomining",      _cryptomining,    "advanced"),
  story("dcsync",            _dcsync,          "advanced"),
  story("supply-chain",      _supplyChain,     "advanced"),
  story("mfa-fatigue",       _mfaFatigue,      "advanced"),
  story("asrep-roasting",    _asrepRoasting,   "advanced"),
  story("ntlm-relay",        _ntlmRelay,       "advanced"),
  // Kubernetes attack only makes sense at the cloud-native SaaS company
  story("k8s-pod-escape",    _k8sPodEscape,    "advanced", ["rocketstack"]),
  story("oauth-consent",     _oauthConsent,    "advanced"),
  story("kerberoasting",     _kerberoasting,   "advanced"),
  story("dns-tunneling",     _dnsTunneling,    "advanced"),
  story("lolbins",           _lolbins,         "advanced"),
];

// ── Company-specific chains ────────────────────────────────────────────────────
// COMPANY_ATTACKS holds 4 hand-authored, vendor-accurate kill-chains per company
// (16 events each = 4 chains x 4 events), written specifically against that
// company's real security stack. These were orphaned by the old attack-pool
// mechanism and are now promoted into proper AttackStory entries so every
// company gets meaningfully more story variety instead of leaning on the
// generic cross-company pool above.
const CHAIN_TITLES: Record<string, string[]> = {
  nexacorp: [
    "Phishing → Inbox Rule → Key Vault Secrets Exfil",
    "CEO Account Takeover — Business Email Compromise",
    "Insider Data Theft — Deal Models to Personal Email",
    "AD Password Spray from TOR Exit Node",
  ],
  medcore: [
    "Ransomware — Phishing DOCM to EMR Encryption",
    "Insider Data Theft — Patient Records via USB",
    "VPN Compromise → PACS Medical Imaging Exfil",
    "Cisco VPN Brute Force → Clinical Account Compromise",
  ],
  globallogis: [
    "Finance Phishing → WMS Server Compromise → FTP Exfil",
    "Warehouse Terminal Malware → ERP Lateral Movement",
    "Disgruntled Employee — Bulk Customer Database Theft",
    "SSH Brute Force → Linux Server Root Compromise",
  ],
  rocketstack: [
    "Compromised Okta (TOR) → S3 Customer Database Exfil",
    "Malicious npm Package → Reverse Shell on Dev Workstation",
    "Container Escape → Crypto Mining + Prod Secrets",
    "Okta Credential Stuffing → AWS Console Compromise",
  ],
  quantumbank: [
    "MFA Fatigue → Cobalt Strike → Core Banking Session Takeover",
    "CyberArk Vault Abuse — Unauthorized Privilege Escalation",
    "Rogue Trading — Market Manipulation via Authorized Account",
    "SWIFT Password Spray → Core Banking Session Hijack",
  ],
};

function chunk4(events: TelemetryEvent[]): TelemetryEvent[][] {
  const out: TelemetryEvent[][] = [];
  for (let i = 0; i < events.length; i += 4) out.push(events.slice(i, i + 4));
  return out;
}

// These are 4-event slices carved out of larger 16-event company kill chains
// (see chunk4 above) — not individually verified for beginner-friendliness,
// so they default to "core" rather than being assumed simple. They still
// give Medium/Hard sessions company-flavored variety beyond the generic pool.
const COMPANY_CHAIN_STORIES: AttackStory[] = Object.entries(COMPANY_ATTACKS).flatMap(
  ([companyId, events]) => {
    const titles = CHAIN_TITLES[companyId] ?? [];
    return chunk4(events).map((chainEvents, i) =>
      story(`${companyId}-chain-${String.fromCharCode(97 + i)}`,
        { title: titles[i] ?? `${companyId} — Chain ${String.fromCharCode(65 + i)}`, events: chainEvents },
        "core",
        [companyId])
    );
  }
);

const ROCKETSTACK_CRED_STUFFING_STORY = story(
  "rocketstack-cred-stuffing",
  { title: "Credential Stuffing → Device Persistence → AWS/GitHub Theft", events: ROCKETSTACK_CRED_STUFFING_CHAIN },
  "advanced",
  ["rocketstack"]
);

export const ATTACK_STORIES: AttackStory[] = [
  ...GENERIC_STORIES,
  ...COMPANY_CHAIN_STORIES,
  ROCKETSTACK_CRED_STUFFING_STORY,
];

// ── Company fit ───────────────────────────────────────────────────────────────

/**
 * A story source is "available" at a company if the company's SIEM architecture
 * includes it or an equivalent telemetry channel that would carry those logs.
 */
const SOURCE_ALIASES: Record<string, string[]> = {
  sysmon:    ["sysmon", "edr"],
  proxy:     ["proxy", "firewall"],
  dns:       ["dns", "firewall"],
  iam:       ["okta", "ad", "o365"],
  okta:      ["okta"],
  ueba:      ["edr", "okta", "ad", "o365", "gws"],
  k8s_audit: ["cloudtrail"],
  dlp:       ["o365", "gws", "edr"],
  email:     ["o365", "gws"],
};

function companySources(companyId: string): string[] {
  const profile = COMPANY_PROFILES.find(c => c.id === companyId);
  return profile?.architecture.sources ?? [];
}

function sourceAvailable(src: string, sources: string[]): boolean {
  const accepted = SOURCE_ALIASES[src] ?? [src];
  return accepted.some(a => sources.includes(a));
}

/** Fraction of the story's events whose source exists in the company architecture */
function sourceFitRatio(s: AttackStory, sources: string[]): number {
  if (s.events.length === 0) return 0;
  const ok = s.events.filter(e => sourceAvailable(e.source, sources)).length;
  return ok / s.events.length;
}

/**
 * Which complexity tiers a chosen dashboard difficulty draws from. Easy is
 * restricted to "foundation" ONLY — a brand-new student's very first attacks
 * must never include lateral movement, credential theft, or a cloud pivot.
 * Medium opens up to "core" as well; Hard is the full kill-chain pool.
 */
const COMPLEXITY_FOR_DIFFICULTY: Record<"easy" | "medium" | "hard", StoryComplexity[]> = {
  easy:   ["foundation"],
  medium: ["foundation", "core"],
  hard:   ["advanced"],
};

export function storiesForCompany(companyId: string, difficulty?: "easy" | "medium" | "hard"): AttackStory[] {
  const sources = companySources(companyId);
  const allowedComplexity = difficulty ? COMPLEXITY_FOR_DIFFICULTY[difficulty] : null;

  const explicit = (s: AttackStory) => s.companies ? s.companies.includes(companyId) : null;
  const complexityOk = (s: AttackStory) => !allowedComplexity || allowedComplexity.includes(s.complexity);

  // Strict pass: every event's source is available
  const strict = ATTACK_STORIES.filter(s => {
    if (!complexityOk(s)) return false;
    const e = explicit(s);
    if (e !== null) return e;
    return sourceFitRatio(s, sources) === 1;
  });
  if (strict.length >= 4) return strict;

  // Relaxed pass: ≥80% of events fit (keeps enough variety for Okta-only shops)
  const relaxed = ATTACK_STORIES.filter(s => {
    if (!complexityOk(s)) return false;
    const e = explicit(s);
    if (e !== null) return e;
    return sourceFitRatio(s, sources) >= 0.8;
  });
  if (relaxed.length >= 3) return relaxed;

  // Fallback within the requested complexity tier: never leave a company without attacks
  const withinComplexity = ATTACK_STORIES.filter(s => complexityOk(s) && explicit(s) !== false);
  if (withinComplexity.length > 0) return withinComplexity;

  // Last resort: complexity tier had nothing at all for this company — ignore
  // the tier rather than showing no attack (should not happen once every
  // company has ≥1 foundation-tier story, but never leave the feed empty).
  return ATTACK_STORIES.filter(s => explicit(s) !== false);
}

// ── Anti-repeat memory ────────────────────────────────────────────────────────

const RECENT_KEY = "soc_recent_story_ids";
const RECENT_N   = 8;

function readRecent(): string[] {
  if (typeof window === "undefined") return [];
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]") as string[]; }
  catch { return []; }
}

function pushRecent(id: string) {
  if (typeof window === "undefined") return;
  const next = [id, ...readRecent().filter(x => x !== id)].slice(0, RECENT_N);
  localStorage.setItem(RECENT_KEY, JSON.stringify(next));
}

/**
 * Pick the session's attack story for a company: fits the company architecture,
 * matches the requested difficulty's complexity tier, avoids the last N
 * stories seen, remembers the choice.
 */
export function pickStoryForCompany(companyId: string, difficulty?: "easy" | "medium" | "hard"): AttackStory {
  const candidates = storiesForCompany(companyId, difficulty);
  const recent = readRecent();
  let pool = candidates.filter(s => !recent.includes(s.id));
  if (pool.length === 0) pool = candidates; // every candidate seen recently — allow repeats
  const picked = pool[Math.floor(Math.random() * pool.length)];
  pushRecent(picked.id);
  if (process.env.NODE_ENV !== "production") {
    const sources = companySources(companyId);
    const missing = Array.from(new Set(picked.events.map(e => e.source)))
      .filter(src => !sourceAvailable(src, sources));
    if (missing.length > 0) {
      console.warn(`[attackStories] story "${picked.id}" uses sources missing at ${companyId}:`, missing);
    }
  }
  return picked;
}

// ── Victim variation ──────────────────────────────────────────────────────────

const SERVICE_ACCOUNT = /^(svc-|ci-|admin@|noreply|system@)/i;

/**
 * ~50% of sessions swap the story's primary victim with another employee from
 * the company's benign pool, so the same story never reads identically twice.
 * Raw fields are left untouched (same tolerance as the feed's user rotation).
 */
export function instantiateStory(s: AttackStory, companyPool: TelemetryEvent[]): AttackStory {
  if (Math.random() < 0.5) return s;

  // Most frequent non-service victim in the story
  const counts = new Map<string, number>();
  for (const e of s.events) {
    if (e.user_email && !SERVICE_ACCOUNT.test(e.user_email)) {
      counts.set(e.user_email, (counts.get(e.user_email) ?? 0) + 1);
    }
  }
  const victim = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  if (!victim) return s;

  // Replacement candidates from the company pool
  const seen = new Set<string>();
  const users: string[] = [];
  for (const e of companyPool) {
    const u = e.user_email;
    if (!u || SERVICE_ACCOUNT.test(u) || u === victim || seen.has(u)) continue;
    seen.add(u); users.push(u);
  }
  if (users.length === 0) return s;

  const replacement = users[Math.floor(Math.random() * users.length)];
  const origName = victim.split("@")[0];
  const newName  = replacement.split("@")[0];
  const nameRe   = new RegExp(origName.replace(/\./g, "\\."), "g");

  return {
    ...s,
    events: s.events.map(e =>
      e.user_email === victim
        ? { ...e, user_email: replacement, description: e.description?.replace(nameRe, newName) ?? e.description }
        : e
    ),
  };
}
