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
// Expert scenario-packs — hand-authored, vendor-accurate kill-chains that until
// now only lived in the static /scenarios exercise and never surfaced in the
// LIVE dashboard feed. Wiring them here roughly doubles the attack variety a
// student can meet live. Each is company-restricted (below) to the estates whose
// telemetry actually carries it — ESXi/vCenter at on-prem datacenters, Linux
// auditd where there are Linux servers, AiTM/AD attacks at the M365/AD shops.
import { buildEsxiRansomwareScenario }        from "@/lib/sim/scenario-packs/esxiRansomware";
import { buildRogueAdminAccountScenario }     from "@/lib/sim/scenario-packs/rogueAdminAccount";
import { buildImpossibleTravelBasicScenario } from "@/lib/sim/scenario-packs/impossibleTravelBasic";
import { buildWebShellRceScenario }           from "@/lib/sim/scenario-packs/webShellRce";
import { buildLinuxSshCryptominerScenario }   from "@/lib/sim/scenario-packs/linuxSshCryptominer";
import { buildAitmTokenTheftScenario }        from "@/lib/sim/scenario-packs/aitmTokenTheft";
import { buildBruteForceSingleAccountScenario } from "@/lib/sim/scenario-packs/bruteForceSingleAccount";
// Foundation-tier additions. Before these, the easy tier held 7 stories, and
// after company-fit filtering the two Okta-only estates (rocketstack,
// quantumbank) saw just 4 — smaller than RECENT_N below, so the anti-repeat
// filter emptied and easy-mode students met a repeat by their fifth session.
// Three of the five are deliberately source-light (edr + firewall only) so they
// fit every estate; the Okta and Google Workspace packs exist specifically to
// give the two non-Microsoft companies an identity and an email scenario.
import { buildOktaPasswordBurstScenario }        from "@/lib/sim/scenario-packs/oktaPasswordBurst";
import { buildFakeBrowserUpdateScenario }        from "@/lib/sim/scenario-packs/fakeBrowserUpdate";
import { buildTrojanizedInstallerKeyloggerScenario } from "@/lib/sim/scenario-packs/trojanizedInstallerKeylogger";
import { buildGwsPhishingAttachmentScenario }    from "@/lib/sim/scenario-packs/gwsPhishingAttachment";
import { buildBundledCryptominerScenario }       from "@/lib/sim/scenario-packs/bundledCryptominer";
// Second foundation batch (six more source-light edr+firewall packs). Even after
// the first batch, the easy pool per company sat right at RECENT_N=8, so a
// student who played daily could still meet a repeat within a working week.
// These six lift every company's foundation pool clear of the anti-repeat window
// and add genuinely different initial-access tradecraft (SEO-poisoned installer,
// ISO/MotW smuggling, drive-by miner, ClickFix fake-CAPTCHA, clipboard clipper,
// scheduled-task persistence) so consecutive easy sessions feel distinct.
import { buildSeoPoisonedInstallerScenario }     from "@/lib/sim/scenario-packs/seoPoisonedInstaller";
import { buildIsoContainerSmugglingScenario }    from "@/lib/sim/scenario-packs/isoContainerSmuggling";
import { buildDriveByBrowserMinerScenario }      from "@/lib/sim/scenario-packs/driveByBrowserMiner";
import { buildClickFixFakeCaptchaScenario }      from "@/lib/sim/scenario-packs/clickFixFakeCaptcha";
import { buildClipboardClipperScenario }         from "@/lib/sim/scenario-packs/clipboardClipper";
import { buildScheduledTaskPersistenceScenario } from "@/lib/sim/scenario-packs/scheduledTaskPersistence";
// P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md). These
// close the biggest gaps DBIR/CISA flag versus what the feed taught: infostealer
// cookie theft + session replay (the #1 real credential source), edge-appliance
// pre-auth exploitation (dominant ransomware entry), exfil-only "no-encryptor"
// extortion (modern double-extortion reality), and help-desk MFA-reset account
// takeover (Scattered Spider). They also lift the thin core/advanced pools clear
// of the RECENT_N=8 anti-repeat window for the M365/Okta estates.
import { buildInfostealerSessionTheftScenario }  from "@/lib/sim/scenario-packs/infostealerSessionTheft";
import { buildEdgeVpnCveExploitScenario }        from "@/lib/sim/scenario-packs/edgeVpnCveExploit";
import { buildExfilFirstExtortionScenario }      from "@/lib/sim/scenario-packs/exfilFirstExtortion";
import { buildHelpdeskMfaResetScenario }         from "@/lib/sim/scenario-packs/helpdeskMfaReset";
import { COMPANY_ATTACKS, ROCKETSTACK_CRED_STUFFING_CHAIN } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES, COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
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

// Expert scenario-packs (see import note above)
const _esxiRansomware   = buildEsxiRansomwareScenario();
const _rogueAdmin       = buildRogueAdminAccountScenario();
const _impossibleTravelBasic = buildImpossibleTravelBasicScenario();
const _webShellRce      = buildWebShellRceScenario();
const _linuxCryptominer = buildLinuxSshCryptominerScenario();
const _aitmTokenTheft   = buildAitmTokenTheftScenario();
const _bruteForceSingle = buildBruteForceSingleAccountScenario();
const _oktaPasswordBurst    = buildOktaPasswordBurstScenario();
const _fakeBrowserUpdate    = buildFakeBrowserUpdateScenario();
const _trojanizedKeylogger  = buildTrojanizedInstallerKeyloggerScenario();
const _gwsPhishAttachment   = buildGwsPhishingAttachmentScenario();
const _bundledCryptominer   = buildBundledCryptominerScenario();
const _seoPoisonedInstaller    = buildSeoPoisonedInstallerScenario();
const _isoContainerSmuggling   = buildIsoContainerSmugglingScenario();
const _driveByBrowserMiner     = buildDriveByBrowserMinerScenario();
const _clickFixFakeCaptcha     = buildClickFixFakeCaptchaScenario();
const _clipboardClipper        = buildClipboardClipperScenario();
const _scheduledTaskPersistence = buildScheduledTaskPersistenceScenario();
// P0 additions (see import note above)
const _infostealerSessionTheft = buildInfostealerSessionTheftScenario();
const _edgeVpnCveExploit        = buildEdgeVpnCveExploitScenario();
const _exfilFirstExtortion      = buildExfilFirstExtortionScenario();
const _helpdeskMfaReset         = buildHelpdeskMfaResetScenario();

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
  // AWS-native (GitHub secret leak → S3 exfil) — rocketstack is the cloud-native
  // estate whose identities these carry; keeps the feed tenant-pure.
  story("cryptomining",      _cryptomining,    "advanced", ["rocketstack"]),
  story("dcsync",            _dcsync,          "advanced"),
  story("supply-chain",      _supplyChain,     "advanced", ["rocketstack"]),
  story("mfa-fatigue",       _mfaFatigue,      "advanced"),
  story("asrep-roasting",    _asrepRoasting,   "advanced"),
  story("ntlm-relay",        _ntlmRelay,       "advanced"),
  // Kubernetes attack only makes sense at the cloud-native SaaS company
  story("k8s-pod-escape",    _k8sPodEscape,    "advanced", ["rocketstack"]),
  story("oauth-consent",     _oauthConsent,    "advanced"),
  story("kerberoasting",     _kerberoasting,   "advanced"),
  story("dns-tunneling",     _dnsTunneling,    "advanced"),
  story("lolbins",           _lolbins,         "advanced"),

  // ── Expert scenario-packs, now live in the dashboard feed ──────────────────
  // Company-restricted to the estates whose telemetry actually carries the
  // attack (these packs use windows_security / linux_audit / waf / db_monitor /
  // email_gateway sources that the source-fit heuristic can't map, so an
  // explicit allowlist is required — same mechanism as k8s-pod-escape).

  // Single-account brute force, visible entirely in Windows auth logs — one
  // user, one source, no lateral movement: a genuine foundation-tier attack
  // that finally gives the Easy tier an identity scenario (was malware-only).
  story("bruteforce-single", _bruteForceSingle,      "foundation", ["nexacorp", "medcore", "globallogis"]),

  // The same lesson for estates with no Active Directory — the whole attack
  // lives in the Okta System Log. Deliberately ends in FAILURE at the second
  // factor: the password is compromised even though nobody got in.
  story("okta-password-burst", _oktaPasswordBurst,   "foundation", ["rocketstack", "quantumbank"]),

  // Google Workspace email-borne foundation story. rocketstack is the only
  // estate that ships gws telemetry, and until now it had no email scenario at
  // the easy tier at all.
  story("gws-phish-attachment", _gwsPhishAttachment, "foundation", ["rocketstack"]),

  // Source-light on purpose (edr + firewall), so every company can draw them.
  story("fake-browser-update", _fakeBrowserUpdate,   "foundation"),
  story("trojanized-keylogger", _trojanizedKeylogger, "foundation"),
  story("bundled-cryptominer", _bundledCryptominer,  "foundation"),
  // Second foundation batch — source-light (edr+firewall), fits every company.
  story("seo-poisoned-installer",  _seoPoisonedInstaller,    "foundation"),
  story("iso-container-smuggling", _isoContainerSmuggling,   "foundation"),
  story("drive-by-browser-miner",  _driveByBrowserMiner,     "foundation"),
  story("clickfix-fake-captcha",   _clickFixFakeCaptcha,     "foundation"),
  story("clipboard-clipper",       _clipboardClipper,        "foundation"),
  story("scheduled-task-persistence", _scheduledTaskPersistence, "foundation"),

  // core — contained identity/AD attacks that need correlating a few events
  story("impossible-travel-basic", _impossibleTravelBasic, "core", ["nexacorp", "medcore", "globallogis", "rocketstack", "quantumbank"]),
  story("rogue-admin",       _rogueAdmin,            "core", ["nexacorp", "medcore", "globallogis"]),

  // advanced — full kill chains on infrastructure the on-prem/cloud estates run
  story("esxi-ransomware",   _esxiRansomware,        "advanced", ["medcore", "globallogis", "nexacorp"]),
  story("webshell-rce",      _webShellRce,           "advanced", ["rocketstack", "quantumbank", "nexacorp"]),
  story("linux-cryptominer", _linuxCryptominer,      "advanced", ["globallogis", "rocketstack"]),
  story("aitm-token-theft",  _aitmTokenTheft,        "advanced", ["nexacorp", "medcore", "globallogis"]),

  // ── P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md) ──
  // Grouped by tier. All four are Entra/M365-native except edge-vpn, which is a
  // source-light appliance→internal-host chain that fits every estate.

  // core — infostealer cookie theft then session replay bypassing MFA (the #1
  // real-world credential source). Needs Entra sign-in logs to show the replay,
  // so it is offered to the three M365 estates only.
  story("infostealer-session-theft", _infostealerSessionTheft, "core", ["nexacorp", "medcore", "globallogis"]),

  // core — help-desk social engineering → MFA reset → new-device logon
  // (Scattered Spider). ServiceNow ticket + Entra auth/audit, M365 estates only.
  story("helpdesk-mfa-reset", _helpdeskMfaReset,     "core", ["nexacorp", "medcore", "globallogis"]),

  // advanced — pre-auth exploitation of an internet-facing SSL-VPN appliance as
  // initial access, then a pivot to an internal Windows host. Source-light
  // (firewall/vpn + edr + siem), so every company can draw it.
  story("edge-vpn-cve-exploit", _edgeVpnCveExploit,  "advanced"),

  // advanced — exfil-only "no-encryptor" double extortion: mass staging →
  // archive → cloud egress with T1486 deliberately absent. Needs a DLP surface
  // (Purview), so it is offered to the three M365 estates.
  story("exfil-first-extortion", _exfilFirstExtortion, "advanced", ["nexacorp", "medcore", "globallogis"]),
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
//
// Exception: a few chain-D slices end in host-to-host lateral movement or a
// root/privilege compromise (medcore-chain-d = VPN brute -> RDP lateral;
// globallogis-chain-d = SSH brute -> root -> dropper). Those meet the "advanced"
// bar, so a Medium session (foundation+core only) must NOT be served them —
// they are promoted to "advanced" and surface at Hard, where they also add
// company-specific variety to the otherwise generic advanced pool.
const ADVANCED_CHAIN_SLICES = new Set(["medcore-chain-d", "globallogis-chain-d"]);
const COMPANY_CHAIN_STORIES: AttackStory[] = Object.entries(COMPANY_ATTACKS).flatMap(
  ([companyId, events]) => {
    const titles = CHAIN_TITLES[companyId] ?? [];
    return chunk4(events).map((chainEvents, i) => {
      const id = `${companyId}-chain-${String.fromCharCode(97 + i)}`;
      return story(id,
        { title: titles[i] ?? `${companyId} — Chain ${String.fromCharCode(65 + i)}`, events: chainEvents },
        ADVANCED_CHAIN_SLICES.has(id) ? "advanced" : "core",
        [companyId]);
    });
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
  // Scenario-pack source types → the company channel that ingests them. These
  // stories are company-allowlisted, so this only quiets the dev sanity-warning;
  // it does not affect selection.
  windows_security: ["ad", "sysmon", "edr"],   // DC/Windows Security events via the AD channel
  linux_audit:      ["edr", "sysmon"],          // auditd shipped by the endpoint agent
  email_gateway:    ["o365", "gws"],
  waf:              ["firewall", "cloudtrail"],  // WAF is an edge/firewall-class device
  db_monitor:       ["edr", "cloudtrail"],       // database activity monitoring
  cloud_azure:      ["o365", "cloudtrail"],
  // SIEM/SOAR correlation + automation meta-events are produced by the platform
  // itself, so they are "available" wherever the SIEM is (i.e. everywhere).
  siem: ["edr", "ad", "o365", "okta", "cloudtrail", "firewall", "vpn", "dns", "proxy", "gws", "sysmon"],
  soar: ["edr", "ad", "o365", "okta", "cloudtrail", "firewall", "vpn", "dns", "proxy", "gws", "sysmon"],
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

/** Deep string-replace across every value of a raw object (recurses arrays/objects). */
function deepReplace(value: unknown, pairs: [string, string][]): unknown {
  if (typeof value === "string") {
    let out = value;
    for (const [from, to] of pairs) if (from && out.includes(from)) out = out.split(from).join(to);
    return out;
  }
  if (Array.isArray(value)) return value.map(v => deepReplace(v, pairs));
  if (value && typeof value === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) o[k] = deepReplace(v, pairs);
    return o;
  }
  return value;
}

// ── EDR vendor namespace normalisation (L-03) ────────────────────────────────
// The attack corpus is authored almost entirely on CrowdStrike's rich schema. When
// it lands on a company that runs a DIFFERENT EDR, the vendor-namespaced raw keys
// (crowdstrike.*) are a dead giveaway — on a SentinelOne shop every crowdstrike.*
// event IS the attack, and the field itself is invalid for that vendor. All the real
// evidence lives in the structured process/file fields (rendered by the feed, kept
// untouched here), so we reshape the raw block to the TARGET vendor's small,
// baseline-matching convention: drop foreign-vendor keys, keep the vendor-neutral
// (ECS) keys, and add the handful of target-vendor keys the company's own baseline +
// authored attacks actually use. Nothing is invented — every emitted key already
// appears in that company's feed.
type EdrNs = "crowdstrike" | "s1" | "sophos" | "mde";
const ANY_EDR_NS = /^(crowdstrike|s1|sophos|mde|cortex)\./;
// When reshaping to another vendor we keep only the small set of vendor-NEUTRAL keys
// the target companies' own EDR events actually use (evidence lives in the structured
// process/file fields). This also drops vendor-flavoured "neutral" keys like
// event.provider:"Microsoft Defender ATP" / event.dataset:"DeviceProcessEvents" that
// would otherwise out a Defender-authored event on a SentinelOne/Sophos shop.
const KEEP_NEUTRAL_PREFIX = /^(process|file|threat|source|destination|network|dns|usb|user|host|registry|url|http)\./;
const KEEP_NEUTRAL_EXACT = new Set(["action_result", "quarantine.status", "policy.name", "event.action", "event.outcome", "event.category"]);
// EDR product names that appear in prose/raw values — mapped to the company's own EDR
// so a description like "CrowdStrike Falcon killed…" can't out the attack elsewhere.
const EDR_PRODUCT_NAMES = [
  "Microsoft Defender for Endpoint", "Microsoft Defender ATP", "Microsoft Defender",
  "CrowdStrike Falcon Elite", "CrowdStrike Falcon", "SentinelOne Singularity",
  "Sophos Intercept X", "Cortex XDR", "Carbon Black",
  "CrowdStrike", "SentinelOne", "Sophos", "Falcon", "Defender",
];

function edrNsOfVendor(vendor?: string): EdrNs | null {
  const v = (vendor ?? "").toLowerCase();
  if (v.includes("crowdstrike") || v.includes("falcon")) return "crowdstrike";
  if (v.includes("sentinelone") || v.includes("singularity")) return "s1";
  if (v.includes("sophos")) return "sophos";
  if (v.includes("defender") || v === "mde") return "mde";
  return null;
}
function edrNsOfKeys(raw?: Record<string, unknown>): EdrNs | null {
  for (const k of Object.keys(raw ?? {})) {
    if (k.startsWith("crowdstrike.")) return "crowdstrike";
    if (k.startsWith("s1.")) return "s1";
    if (k.startsWith("sophos.")) return "sophos";
    if (k.startsWith("mde.")) return "mde";
  }
  return null;
}

const S1_EVENT_TYPE: Record<string, string> = {
  process_create: "PROCESS_CREATION", file_create: "FILE_CREATION",
  net_connection: "IP_CONNECT", av_detection: "THREAT", detection: "THREAT",
};
const SOPHOS_EVENT_TYPE: Record<string, string> = {
  process_create: "Process", file_create: "File",
  net_connection: "Network", av_detection: "Malware", detection: "Malware",
};
const S1_LEVEL: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low", informational: "none",
};
function edrAction(e: TelemetryEvent): string {
  const r = String(e.raw?.["action_result"] ?? "").toLowerCase();
  if (r.includes("kill")) return "kill";
  if (r.includes("block") || r.includes("quarantin")) return "quarantine";
  return "detect_only";
}

/** Rebuild an EDR event's raw block in `target`'s convention (see comment above). */
function reshapeEdrRaw(e: TelemetryEvent, target: EdrNs): Record<string, unknown> {
  const src = e.raw ?? {};
  const neutral: Record<string, unknown> = {};        // only whitelisted neutral keys
  for (const [k, v] of Object.entries(src)) if (KEEP_NEUTRAL_PREFIX.test(k) || KEEP_NEUTRAL_EXACT.has(k)) neutral[k] = v;

  const et = e.event_type ?? "";
  const isDetection = e.is_detection === true || /detection|threat|malware|ransom/i.test(et);
  const block: Record<string, unknown> = {};
  if (target === "crowdstrike") {
    block["crowdstrike.event_simpleName"] =
      et === "process_create" ? "ProcessRollup2" : et === "net_connection" ? "NetworkConnectIP4" : "DetectionSummaryEvent";
    if (isDetection && e.mitre_technique) block["crowdstrike.detection.technique_id"] = e.mitre_technique;
    if (e.severity) block["crowdstrike.SeverityName"] = e.severity.toUpperCase();
  } else if (target === "s1") {
    block["s1.event_type"] = S1_EVENT_TYPE[et] ?? (isDetection ? "THREAT" : "BEHAVIORAL_INDICATORS");
    block["s1.threat_level"] = S1_LEVEL[e.severity ?? "informational"] ?? "none";
    if (isDetection) block["s1.action"] = edrAction(e);
  } else if (target === "sophos") {
    block["sophos.event_type"] = SOPHOS_EVENT_TYPE[et] ?? (isDetection ? "Malware" : "Event");
    block["sophos.detection_name"] = isDetection ? (String(src["threat.name"] ?? "") || "Mal/Generic-A") : "none";
    if (isDetection) block["sophos.action"] = edrAction(e);
  } else {
    block["mde.ActionType"] = et === "process_create" ? "ProcessCreated" : isDetection ? "AlertRaised" : "GeneralEvent";
  }
  return { ...block, ...neutral };
}

/**
 * Adapt a shared attack story to the ACTIVE company so it reads as native telemetry,
 * not the same CrowdStrike chain under a new company name. ALWAYS applied. It rewrites
 * every company-identifying detail the story baked in for its author-company:
 *   • EDR vendor + raw schema  → the company's EDR (see reshapeEdrRaw above)
 *   • victim identity          → a user from the company roster (email + name forms)
 *   • email domain + NetBIOS   → the company's (catches DOMAIN\\user forms too)
 *   • hostnames                → the company's asset pool
 * across the banner, the description, the structured process/file fields, AND the raw
 * log — the last matters because the student is told to quote the raw exactly, so a
 * stale value there would be scored as fabricated evidence.
 */
export function instantiateStory(s: AttackStory, companyPool: TelemetryEvent[], companyEdr?: string, companyId?: string): AttackStory {
  const targetNs = edrNsOfVendor(companyEdr);
  if (companyEdr) {
    s = {
      ...s,
      events: s.events.map(e =>
        e.source === "edr" && e.vendor && e.vendor !== companyEdr ? { ...e, vendor: companyEdr } : e
      ),
    };
  }

  // L-03 (upgraded to CRITICAL): route the attack chain through the SAME company
  // adaptation the baseline already gets, and do it ALWAYS (not 50% of the time).
  // Otherwise the attack betrays itself in three more ways beyond the vendor: on a
  // SentinelOne shop every CrowdStrike event IS the attack; the one hostname that
  // doesn't match the asset pool is the attack; the one email domain that isn't the
  // company's is the attack. Swap victim→company roster, hostnames→company assets,
  // and the internal domain→the company's, so the incident reads as native.
  const roster: string[] = [];  const rSeen = new Set<string>();
  const hostPool: string[] = []; const hSeen = new Set<string>();
  const domainCount = new Map<string, number>();
  for (const e of companyPool) {
    const u = e.user_email;
    if (u && !SERVICE_ACCOUNT.test(u) && !rSeen.has(u)) { rSeen.add(u); roster.push(u); }
    if (u && u.includes("@")) { const d = u.split("@")[1]; domainCount.set(d, (domainCount.get(d) ?? 0) + 1); }
    const h = e.hostname;
    if (h && !hSeen.has(h)) { hSeen.add(h); hostPool.push(h); }
  }
  let companyDomain = [...domainCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

  // R-01 (CRITICAL): host + IP were never made company-specific — the shared benign
  // pool overlaps across companies, so the same WS-OPS-2214 / 10.10.55.19 opened in
  // the EDR console for all five, and a QuantumBank attack read as a NexaCorp London
  // workstation the analyst could not correlate to the feed. Draw hosts, the internal
  // subnet and the domain from the per-company asset registry, which mirrors the
  // conventions the SIEM feed uses — so the console shows the same host + IP as the
  // feed. Registry wins over the benign-pool inference when the company is known.
  const assets = companyId ? COMPANY_ASSETS[companyId] : undefined;
  const registryHostPool = assets ? assets.hosts : hostPool;
  if (assets) companyDomain = assets.domain;

  const pairs: [string, string][] = [];

  // Victim identity → a company roster user, in every form it appears (full email,
  // dotted name, squashed name). Longest-first so the email is replaced before the
  // bare username substring.
  const counts = new Map<string, number>();
  for (const e of s.events) if (e.user_email && !SERVICE_ACCOUNT.test(e.user_email)) counts.set(e.user_email, (counts.get(e.user_email) ?? 0) + 1);
  const victim = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  const replacement = roster.length ? roster[Math.floor(Math.random() * roster.length)] : undefined;
  if (victim && replacement && victim !== replacement) {
    const on = victim.split("@")[0], nn = replacement.split("@")[0];
    pairs.push([victim, replacement], [on, nn], [on.replace(/\./g, ""), nn.replace(/\./g, "")]);
  }

  // Internal email domain → the company's (catches any other internal identity that
  // still carried the story's baked-in domain, e.g. cryotech.com on a MedCore feed).
  const victimDomain = victim?.includes("@") ? victim.split("@")[1] : undefined;
  if (victimDomain && companyDomain && victimDomain !== companyDomain) pairs.push([victimDomain, companyDomain]);

  // Story hostnames → the company's asset pool (deterministic per distinct host).
  const storyHosts = [...new Set(s.events.map(e => e.hostname).filter((h): h is string => !!h))];
  const hostMap = new Map<string, string>();
  // Pick each host deterministically from the pool by hashing its name (so distinct
  // story hosts spread across the company's assets instead of all landing on the
  // first one), but offset by its position so two story hosts never collide onto one.
  const hostHash = (h: string) => { let x = 2166136261; for (let i = 0; i < h.length; i++) { x ^= h.charCodeAt(i); x = Math.imul(x, 16777619); } return Math.abs(x); };
  storyHosts.forEach((h, i) => {
    const t = registryHostPool.length ? registryHostPool[(hostHash(h) + i) % registryHostPool.length] : h;
    if (t !== h) { hostMap.set(h, t); pairs.push([h, t]); }
  });

  // Story INTERNAL IPs → the company's own subnet (R-01). Only RFC1918 addresses are
  // remapped — a public C2/attacker IP is company-agnostic and must stay identical so
  // threat-intel pivots still work. Each distinct private IP keeps its last octet and
  // takes the company's /24, so the host's IP correlates with the feed and two events
  // on the same source IP still share one address in the console.
  const ipMap = new Map<string, string>();
  if (assets) {
    const isPrivate = (ip: string) => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
    const remapIp = (ip?: string) => {
      if (!ip || !isPrivate(ip) || ipMap.has(ip)) return;
      const octet = Math.min(254, Math.max(1, Number(ip.split(".")[3]) || 10));
      const t = `${assets.subnet}.${octet}`;
      if (t !== ip) { ipMap.set(ip, t); pairs.push([ip, t]); }
    };
    for (const e of s.events) { remapIp(e.src_ip); remapIp(e.dst_ip); }
  }

  // NetBIOS/realm domain forms (NEXACORP\\user) survive the email-domain swap and
  // still name the origin company, so map every origin DOMAIN\\user token to the
  // company's short name.
  //
  // E-01 fix: the old scan ran a "(word)\\" regex over JSON.stringify(process/raw),
  // where a Windows path's single backslash serialises to "\\" — so it matched EVERY
  // path segment (Users\, Downloads\, Google\, Chrome\, the Adobe folder ARM\, even
  // the username) and rewrote each to the company name, corrupting 62% of
  // investigations. Constraining to "uppercase word" was not enough — legitimate path
  // folders are upper-cased too (ProgramData\Adobe\ARM\, C:\WINDOWS\). The reliable
  // signal is WHERE the token lives: a NetBIOS domain only ever appears in an
  // IDENTITY field (process.user, a *DomainName / *UserName / AccountName raw key),
  // never inside a filesystem path. So we scan ONLY those fields — a path is never
  // read — and take the DOMAIN part of a DOMAIN\<lowercase-user> token (real
  // usernames are lowercase: l.ferreira, svc-backup — which also skips
  // NT AUTHORITY\SYSTEM and BUILTIN\Administrators), plus any bare realm value in a
  // *DomainName field. Known system principals are never treated as a company.
  const SYSTEM_REALMS = new Set(["NT AUTHORITY", "AUTHORITY", "BUILTIN", "NT SERVICE", "SERVICE", "WORKGROUP", "LOCAL", "NT VIRTUAL MACHINE"]);
  const IDENTITY_KEY = /(user\.?name|SubjectUserName|TargetUserName|AccountName|SamAccountName|DomainName|LogonDomain)/i;
  const companyNetbios = (companyId ?? companyDomain?.split(".")[0] ?? "").toUpperCase();
  if (companyNetbios) {
    const storyNetbios = new Set<string>();
    const harvest = (v: unknown, wholeIsDomain: boolean) => {
      if (typeof v !== "string" || !v.trim()) return;
      // DOMAIN\<lowercase user> anywhere in the value → take the DOMAIN.
      for (const m of v.matchAll(/([A-Za-z][A-Za-z0-9-]{1,})\\{1,2}(?=[a-z])/g)) {
        if (!SYSTEM_REALMS.has(m[1].toUpperCase())) storyNetbios.add(m[1]);
      }
      // A *DomainName field's whole value is the realm (e.g. "NEXACORP"); accept it
      // when it looks like a NetBIOS name (no dot → not a DNS/email domain).
      if (wholeIsDomain) {
        const t = v.trim();
        if (/^[A-Za-z][A-Za-z0-9-]{1,}$/.test(t) && !SYSTEM_REALMS.has(t.toUpperCase())) storyNetbios.add(t);
      }
    };
    for (const e of s.events) {
      harvest(e.process?.user, false);
      for (const [k, val] of Object.entries(e.raw ?? {})) if (IDENTITY_KEY.test(k)) harvest(val, /DomainName$/i.test(k));
    }
    for (const nb of storyNetbios) if (nb.toUpperCase() !== companyNetbios) pairs.push([nb, companyNetbios]);
  }

  // EDR product names in prose / raw values → the company's own EDR (skip the ones
  // that ARE the company's product). Longest-first ordering (below) means
  // "Microsoft Defender for Endpoint" is replaced before the bare "Defender".
  if (companyEdr) {
    const cl = companyEdr.toLowerCase();
    for (const nm of EDR_PRODUCT_NAMES) {
      const nl = nm.toLowerCase();
      if (cl.includes(nl) || nl.includes(cl)) continue;   // never rewrite the company's own product
      pairs.push([nm, companyEdr]);
    }
  }

  const clean = pairs.filter(([f, t]) => f && t && f !== t).sort((a, b) => b[0].length - a[0].length);
  const subStr = (str: string) => { let o = str; for (const [f, t] of clean) if (o.includes(f)) o = o.split(f).join(t); return o; };
  // Nothing to change AND no EDR schema to normalise → return the story untouched.
  if (clean.length === 0 && !targetNs) return s;

  return {
    ...s,
    events: s.events.map(e => {
      const adapted = {
        ...e,
        user_email: victim && e.user_email === victim && replacement ? replacement : e.user_email,
        hostname:   e.hostname && hostMap.has(e.hostname) ? hostMap.get(e.hostname)! : e.hostname,
        src_ip:     e.src_ip && ipMap.has(e.src_ip) ? ipMap.get(e.src_ip)! : e.src_ip,
        dst_ip:     e.dst_ip && ipMap.has(e.dst_ip) ? ipMap.get(e.dst_ip)! : e.dst_ip,
        description: e.description ? subStr(e.description) : e.description,
        process: e.process ? (deepReplace(e.process, clean) as typeof e.process) : e.process,
        network: e.network ? (deepReplace(e.network, clean) as typeof e.network) : e.network,
        raw: e.raw ? (deepReplace(e.raw, clean) as typeof e.raw) : e.raw,
      };
      // Reshape a foreign-EDR raw block into the company's own vendor convention.
      if (adapted.source === "edr" && targetNs && edrNsOfKeys(adapted.raw) && edrNsOfKeys(adapted.raw) !== targetNs) {
        adapted.raw = reshapeEdrRaw(adapted, targetNs) as typeof adapted.raw;
      }
      return adapted;
    }),
  };
}
