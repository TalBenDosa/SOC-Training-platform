"use client";
import { useState, useEffect, useMemo, memo } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, Info, AlertTriangle, Clock, ExternalLink, Shield, X, PhoneCall, CheckCircle2, Copy, BookOpen } from "lucide-react";

export type TimeFilter = "15m" | "1h" | "4h" | "all";
import { cn } from "@/lib/utils";
import type { LiveEvent } from "./useLiveEvents";
import { LOG_SOURCE_GUIDE } from "./logSourceGuide";
import { toRawLog } from "./rawLogFormat";
import { techniqueById, tacticById } from "@/lib/mitre/attack";
import { DashboardTour, LogReadingTour } from "./OnboardingTour";
import { EmailHeaderViewer } from "./EmailHeaderViewer";

// ─── Source styles ─────────────────────────────────────────────────────────────

const SOURCE_COLORS: Record<string, string> = {
  edr:        "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  sysmon:     "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  ad:         "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  o365:       "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  gws:        "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  okta:       "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  firewall:   "bg-severity-high/20 text-severity-high border-severity-high/30",
  dns:        "bg-neon-green/20 text-neon-green border-neon-green/30",
  vpn:        "bg-slate-400/20 text-slate-300 border-slate-400/30",
  cloudtrail: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  proxy:      "bg-slate-400/20 text-slate-300 border-slate-400/30",
};

const SOURCE_LABEL: Record<string, string> = {
  edr:        "EDR",
  sysmon:     "Sysmon",
  ad:         "Active Directory",
  o365:       "Office 365",
  gws:        "Google Workspace",
  okta:       "Okta",
  firewall:   "Firewall",
  dns:        "DNS",
  vpn:        "VPN",
  cloudtrail: "Cloud",   // overridden per-event below: AWS vs Azure
  proxy:      "Proxy",
};

/** Derive the cloudtrail badge label from vendor field (AWS vs Azure vs generic). */
function cloudLabel(vendor?: string): string {
  if (!vendor) return "Cloud";
  const v = vendor.toLowerCase();
  if (v.includes("aws") || v.includes("guardduty") || v.includes("cloudtrail")) return "AWS";
  if (v.includes("azure") || v.includes("microsoft") || v.includes("entra")) return "Azure";
  return "Cloud";
}

// ─── Log Source Education Card ────────────────────────────────────────────────

function LogSourceCard({ source, vendor }: { source: string; vendor?: string }) {
  const [visible, setVisible] = useState(false);
  const key = source === "cloudtrail" ? "cloud" : source;
  const guide = LOG_SOURCE_GUIDE[key];
  const sourceLabel = source === "cloudtrail" ? cloudLabel(vendor) : (SOURCE_LABEL[source] ?? source.toUpperCase());
  const sourceColor = SOURCE_COLORS[source] ?? SOURCE_COLORS.proxy;

  if (!guide) {
    return (
      <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider", sourceColor)}>
        {sourceLabel}
      </span>
    );
  }

  return (
    <div className="relative inline-block">
      {/* Hover works with a mouse; onClick is the touch/keyboard fallback (mirrors
          Term.tsx) — without it this info card was unreachable on touch devices. */}
      <span
        className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider cursor-help", sourceColor)}
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
        onClick={(e) => { e.stopPropagation(); setVisible(v => !v); }}
      >
        {sourceLabel}
      </span>
      {visible && (
        <div
          className="absolute left-0 top-full mt-1.5 z-50 w-72 rounded-lg border border-border/80 bg-[#080d14] p-3 shadow-2xl"
          onMouseEnter={() => setVisible(true)}
          onMouseLeave={() => setVisible(false)}
        >
          <p className="text-[10px] font-bold text-white mb-2">{guide.label}</p>
          <p className="text-[9px] text-slate-500 mb-2">{guide.vendors}</p>
          <div className="mb-2">
            <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500 mb-1">What it monitors</p>
            <ul className="space-y-0.5">
              {guide.whatMonitors.map((item, i) => (
                <li key={i} className="text-[10px] text-slate-300 flex gap-1.5"><span className="text-slate-600 shrink-0">•</span>{item}</li>
              ))}
            </ul>
          </div>
          <div className="mb-2">
            <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500 mb-1">Key fields</p>
            <div className="flex flex-wrap gap-1">
              {guide.keyFields.map(f => (
                <code key={f} className="rounded bg-slate-800/80 px-1 py-0.5 font-mono text-[9px] text-cyber-300">{f}</code>
              ))}
            </div>
          </div>
          <div className="rounded border border-severity-high/30 bg-severity-high/5 px-2 py-1.5">
            <p className="text-[9px] font-semibold text-severity-high mb-0.5">🔍 Red flag</p>
            <p className="text-[9px] text-slate-300">{guide.redFlag}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Column header tooltip ─────────────────────────────────────────────────────

function HeaderTip({ label, tip }: { label: string; tip: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative inline-block"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
      onClick={(e) => { e.stopPropagation(); setVisible(v => !v); }}
    >
      <span className="cursor-help border-b border-dashed border-slate-600/60 hover:border-slate-400/60 transition-colors">
        {label}
      </span>
      {visible && (
        <div className="absolute left-0 top-full mt-1.5 z-50 w-64 rounded-lg border border-border/80 bg-[#080d14] px-3 py-2 shadow-2xl">
          <p className="text-[10px] leading-relaxed text-slate-300">{tip}</p>
        </div>
      )}
    </div>
  );
}

// ─── Action result badge (ALLOWED / BLOCKED / QUARANTINED …) ─────────────────

type ActionStatus = "allowed" | "blocked" | "quarantined" | "killed" | "detected" | "denied";

interface ActionInfo { label: string; status: ActionStatus }

function extractAction(event: LiveEvent): ActionInfo | null {
  const raw = event.raw ?? {};
  // Try all key conventions used across event files (priority order)
  const v: string = (
    (raw["action_result"]       as string | undefined) ??
    (raw["event.action_result"] as string | undefined) ??
    (raw["firewall.action"]     as string | undefined) ??
    (raw["pan.action"]          as string | undefined) ??
    (raw["fortinet.action"]     as string | undefined) ??
    (raw["cp.action"]           as string | undefined) ??
    (raw["event.action"]        as string | undefined) ??
    ""
  );
  if (!v) return null;
  const lv = v.toLowerCase();
  if (lv === "allow" || lv === "allowed" || lv === "accept" || lv === "pass")
    return { label: "ALLOWED",     status: "allowed"     };
  if (lv === "block" || lv === "blocked" || lv === "deny" || lv === "denied" ||
      lv === "drop"  || lv === "reset-both" || lv === "reset-client")
    return { label: "BLOCKED",     status: "blocked"     };
  if (lv === "quarantined")
    return { label: "QUARANTINED", status: "quarantined" };
  if (lv === "process_killed")
    return { label: "KILLED",       status: "killed"      };
  if (lv === "detected_not_blocked" || lv === "detect_only" || lv === "audit")
    return { label: "DETECTED",     status: "detected"    };
  if (lv.includes("allow") || lv.includes("accept"))  return { label: "ALLOWED",  status: "allowed"   };
  if (lv.includes("block") || lv.includes("drop") || lv.includes("deny"))
    return { label: "BLOCKED",  status: "blocked"   };
  return null;
}

const ACTION_STYLE: Record<ActionStatus, string> = {
  allowed:     "bg-neon-green/10   text-neon-green   border-neon-green/25",
  blocked:     "bg-severity-high/15 text-severity-high border-severity-high/30",
  quarantined: "bg-neon-amber/10   text-neon-amber   border-neon-amber/25",
  killed:      "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
  detected:    "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
  denied:      "bg-severity-high/15 text-severity-high border-severity-high/30",
};

function ActionBadge({ event }: { event: LiveEvent }) {
  const info = extractAction(event);
  if (!info) return null;
  return (
    <span className={cn(
      "shrink-0 inline-flex items-center rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest",
      ACTION_STYLE[info.status]
    )}>
      {info.label}
    </span>
  );
}

// ─── Rule level badge ──────────────────────────────────────────────────────────

function RuleLevelBadge({ level }: { level: number }) {
  // Neutral, generic styling on purpose — the number conveys severity, but the
  // colour must NOT flag "this is the attack" for the student. A subtle tonal
  // step keeps it readable without turning high levels into a red giveaway.
  const tone =
    level >= 7 ? "bg-slate-500/25 text-slate-100 border-slate-400/40" :
    level >= 4 ? "bg-slate-600/25 text-slate-200 border-slate-500/40" :
                 "bg-slate-700/30 text-slate-400 border-slate-600/40";
  return (
    <span className={cn("inline-flex h-6 w-6 items-center justify-center rounded border font-mono text-xs font-bold", tone)}>
      {level}
    </span>
  );
}

// ─── Action outcome extraction ─────────────────────────────────────────────────

type ActionOutcome =
  | { status: "blocked";        label: string; detail?: string }
  | { status: "quarantined";    label: string; detail?: string }
  | { status: "process_killed"; label: string; detail?: string }
  | { status: "detected";       label: string; detail?: string }
  | { status: "allowed";        label: string; detail?: string }
  | null;

function extractActionOutcome(event: LiveEvent): ActionOutcome {
  const raw = event.raw ?? {};
  const actionResult   = String(raw["action_result"]    ?? "").toLowerCase();
  const quarantineSt   = String(raw["quarantine.status"] ?? "").toLowerCase();
  const policyAction   = String(raw["policy.action"]    ?? "").toLowerCase();
  const eventAction    = String(raw["event.action"]     ?? "").toLowerCase();
  const wafAction      = String(raw["waf.action"]       ?? "").toLowerCase();
  const sessionBlocked = String(raw["session.blocked"]  ?? "").toLowerCase();
  const idsAction      = String(raw["ids.action"]       ?? "").toLowerCase();
  const fwAction       = String(raw["firewall.action"]  ?? "").toLowerCase();

  if (actionResult === "process_killed" || raw["process.killed"] === "true") {
    const policyName = raw["policy.name"] ? ` (Policy: ${raw["policy.name"]})` : "";
    return { status: "process_killed", label: "Process Terminated", detail: `Malicious process killed by endpoint agent${policyName}` };
  }
  if (actionResult === "quarantined" || quarantineSt === "quarantined") {
    const threat = raw["threat.name"] ?? raw["malware.name"] ?? "";
    return { status: "quarantined", label: "File Quarantined", detail: threat ? `Threat "${threat}" quarantined` : "File moved to quarantine" };
  }
  if (
    actionResult === "blocked" || actionResult === "denied" ||
    eventAction  === "block"   || eventAction  === "deny"   ||
    wafAction    === "block"   || fwAction === "block" || fwAction === "deny" || fwAction === "drop" ||
    idsAction    === "block"   || sessionBlocked === "true"  ||
    policyAction === "blockaccess" || policyAction === "block"
  ) {
    let src = "Security control";
    if (wafAction === "block")            src = "WAF";
    else if (event.source === "firewall") src = "Firewall";
    else if (idsAction === "block")       src = "IDS/IPS";
    else if (policyAction === "blockaccess") src = "DLP";
    else if (sessionBlocked === "true")   src = "Proxy";
    const ruleId = raw["waf.rule.id"] ?? raw["ids.rule.id"] ?? "";
    return { status: "blocked", label: "Blocked", detail: ruleId ? `${src} rule ${ruleId}` : `${src} blocked the connection/action` };
  }
  if (
    actionResult === "detected_not_blocked" || quarantineSt === "not_quarantined" ||
    policyAction === "notifyuser" || policyAction === "audit" ||
    raw["policy.action"] === "DetectionOnly"
  ) {
    const policyName = raw["policy.name"] ? `Policy: ${raw["policy.name"]}` : "";
    return { status: "detected", label: "⚠ Detected — NOT Blocked", detail: policyName || "Endpoint policy is detection-only. Manual response required." };
  }
  if (
    actionResult === "allowed" || actionResult === "allow" ||
    eventAction  === "allow"   || wafAction === "allow"    ||
    fwAction === "allow" || fwAction === "permit" || fwAction === "accept" ||
    policyAction === "allowed"
  ) {
    return { status: "allowed", label: "Allowed", detail: "Traffic / action permitted by policy" };
  }
  return null;
}

// ─── Threat Intel types ────────────────────────────────────────────────────────

type ThreatQuery =
  | { type: "hash";   value: string; event: LiveEvent }
  | { type: "ip";     value: string; event: LiveEvent }
  | { type: "domain"; value: string; event: LiveEvent };

interface EngineResult { name: string; detected: boolean; result?: string }

interface HashIntelData {
  hash: string;
  malicious: boolean;
  detectionCount: number;
  malwareName?: string;
  malwareFamily?: string;
  fileType: string;
  fileName?: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  engines: EngineResult[];
}

interface IpIntelData {
  ip: string;
  abusive: boolean;
  confidence: number;
  country?: string;
  countryFlag: string;
  isp?: string;
  usageType?: string;
  totalReports: number;
  lastReported?: string;
  categories: string[];
}

interface DomainIntelData {
  domain: string;
  malicious: boolean;
  detectionCount: number;
  registrar?: string;
  creationDate?: string;
  ageDays: number;
  categories: string[];
  tags: string[];
}

// ─── AV detection tables ───────────────────────────────────────────────────────

const AV_ENGINES = [
  "CrowdStrike Falcon",
  "Microsoft Defender",
  "Kaspersky",
  "Sophos",
  "ESET-NOD32",
  "Symantec",
  "Trend Micro",
  "Bitdefender",
  "Malwarebytes",
  "McAfee",
  "Avast",
  "SentinelOne",
];

const FAMILY_DETECTIONS: Record<string, Record<string, string>> = {
  CobaltStrike: {
    "CrowdStrike Falcon":  "CobaltStrike.Beacon.C",
    "Microsoft Defender":  "Backdoor:Win64/CobaltStrike.A!dha",
    "Kaspersky":           "Backdoor.Win64.CobaltStrike.gen",
    "Sophos":              "Mal/Cobalt-B",
    "ESET-NOD32":          "Win64/CobaltStrike.A",
    "Symantec":            "Backdoor.Cobeacon",
    "Trend Micro":         "TROJ_COBEACON.SM",
    "Bitdefender":         "Gen:Variant.Backdoor.CobaltStrike.1",
    "Malwarebytes":        "Backdoor.CobaltStrike",
    "McAfee":              "RDN/Generic BackDoor.t",
  },
  WannaCry: {
    "CrowdStrike Falcon":  "Ransom.WannaCry.WIN",
    "Microsoft Defender":  "Ransom:Win32/WannaCrypt.B",
    "Kaspersky":           "Ransom.Win32.WannaCryptor.gen",
    "Sophos":              "Troj/WannaCry-A",
    "ESET-NOD32":          "Win32/Filecoder.WannaCryptor.D",
    "Symantec":            "Ransom.Wannacry",
    "Trend Micro":         "RANSOM_WCRY.SM",
    "Bitdefender":         "Gen:Variant.Ransom.WannaCry.2",
    "Malwarebytes":        "Ransom.WannaCryptDecryptor",
    "McAfee":              "Ransom-WannaCry!0",
    "Avast":               "Win32:WannaCry-A [Ransom]",
    "SentinelOne":         "Ransom.WannaCry",
  },
  NotPetya: {
    "CrowdStrike Falcon":  "Wiper.NotPetya.WIN",
    "Microsoft Defender":  "Trojan:Win32/Petya.A!dha",
    "Kaspersky":           "Trojan-Ransom.Win32.ExPetr.a",
    "Sophos":              "Mal/NotPetya-A",
    "ESET-NOD32":          "Win32/Diskcoder.C",
    "Symantec":            "Ransom.Petya",
    "Trend Micro":         "TROJ_PETYA.SMA",
    "Bitdefender":         "Gen:Variant.Ransom.Petya.3",
    "Malwarebytes":        "Ransom.Petya",
    "McAfee":              "RDN/Petya.worm",
  },
  Mimikatz: {
    "CrowdStrike Falcon":  "HackTool.Mimikatz.WIN",
    "Microsoft Defender":  "HackTool:Win32/Mimikatz.A",
    "Kaspersky":           "HackTool.Win64.Mimikatz.gen",
    "Sophos":              "HPmal/Mimikatz-A",
    "ESET-NOD32":          "Win64/HackTool.Mimikatz.E",
    "Symantec":            "Hacktool.Mimikatz",
    "Trend Micro":         "HKTL_MIMIKATZ.SM",
    "Bitdefender":         "Gen:Variant.HackTool.Mimikatz.4",
    "Malwarebytes":        "HackTool.Mimikatz",
    "McAfee":              "Credential-Mimikatz!",
    "Avast":               "Win32:Hacktool-A",
  },
  Emotet: {
    "CrowdStrike Falcon":  "Trojan.Emotet.WIN",
    "Microsoft Defender":  "Trojan:Win32/Emotet.A!ml",
    "Kaspersky":           "Trojan-Banker.Win32.Emotet.gen",
    "Sophos":              "Mal/Emotet-G",
    "ESET-NOD32":          "Win32/Emotet.BD",
    "Symantec":            "Trojan.Emotet",
    "Trend Micro":         "TSPY_EMOTET.SM",
    "Bitdefender":         "Gen:Variant.Trojan.Emotet.14",
    "Malwarebytes":        "Trojan.Emotet",
    "McAfee":              "Emotet-FBF!",
    "Avast":               "Win32:Emotet-A [Trj]",
    "SentinelOne":         "Trojan.Emotet",
  },
  GenericKD: {
    "CrowdStrike Falcon":  "Trojan.GenericKD.WIN",
    "Microsoft Defender":  "Trojan:Win32/GenericKD.A!ml",
    "Kaspersky":           "Trojan.Win32.GenericKD.gen",
    "Sophos":              "Mal/Generic-A",
    "ESET-NOD32":          "Win32/Trojan.GenericKD",
    "Symantec":            "Trojan.Gen.2",
    "Trend Micro":         "TROJ_GENERIC.SM",
    "Bitdefender":         "Gen:Variant.Trojan.GenericKD.1",
    "Malwarebytes":        "Trojan.GenericKD",
    "McAfee":              "RDN/Generic Trojan.t",
  },
};

const PUP_DETECTIONS: Record<string, string> = {
  "CrowdStrike Falcon":  "PUP.Keygen.WIN",
  "Microsoft Defender":  "PUA:Win32/Keygen",
  "Kaspersky":           "not-a-virus:RiskTool.Win32.Keygen.gen",
  "Sophos":              "PUA/Keygen-A",
  "ESET-NOD32":          "Win32/Keygen.AU",
  "Malwarebytes":        "PUP.Optional.Keygen",
};

const COUNTRY_FLAGS: Record<string, string> = {
  "Germany": "🇩🇪", "Russia": "🇷🇺", "United States": "🇺🇸",
  "China": "🇨🇳", "Netherlands": "🇳🇱", "France": "🇫🇷",
  "Ukraine": "🇺🇦", "Romania": "🇷🇴", "Brazil": "🇧🇷",
  "United Kingdom": "🇬🇧", "Singapore": "🇸🇬", "India": "🇮🇳",
  "North Korea": "🇰🇵", "Iran": "🇮🇷",
};

// Deterministic pseudo-random (same hash always yields same result)
function seededRng(seed: number, i: number): number {
  return Math.abs(Math.sin(seed * 9301 + i * 49297 + 233995)) % 1;
}

// ─── Hash intel builder ────────────────────────────────────────────────────────

function buildHashIntel(hash: string, event: LiveEvent): HashIntelData {
  const raw = event.raw ?? {};
  const malwareFamily = String(raw["malware.family"] ?? "");
  const malwareName   = String(raw["malware.name"]   ?? "");
  const malwareType   = String(raw["malware.type"]   ?? "");
  const avVerdict     = String(raw["av.verdict"]     ?? "");
  const quarantine    = String(raw["quarantine.status"] ?? "");
  const actionResult  = String(raw["action_result"]  ?? "");
  const severity      = event.severity ?? "informational";

  const isPUP = malwareType === "PUP" || malwareName.toLowerCase().includes("pup");
  const isMalicious = !isPUP && (
    malwareFamily !== "" || malwareName !== "" ||
    quarantine === "quarantined" || quarantine === "deleted" ||
    actionResult === "quarantined" || actionResult === "process_killed" ||
    (avVerdict !== "" && avVerdict !== "clean")
  );

  const seed = (parseInt(hash.slice(0, 8), 16) || 0xdeadbeef);

  let detectionCount = 0;
  if (isMalicious) {
    if (severity === "critical") detectionCount = 40 + Math.floor(seededRng(seed, 0) * 20);
    else if (severity === "high") detectionCount = 28 + Math.floor(seededRng(seed, 1) * 14);
    else detectionCount = 15 + Math.floor(seededRng(seed, 2) * 12);
  } else if (isPUP) {
    detectionCount = 4 + Math.floor(seededRng(seed, 3) * 8);
  }

  const effectiveFamily = malwareFamily || (isPUP ? "_pup" : "GenericKD");
  const detectionMap = effectiveFamily === "_pup"
    ? PUP_DETECTIONS
    : (FAMILY_DETECTIONS[effectiveFamily] ?? FAMILY_DETECTIONS["GenericKD"] ?? {});

  const detectThreshold = isMalicious
    ? (severity === "critical" ? 0.85 : severity === "high" ? 0.75 : 0.62)
    : (isPUP ? 0.42 : 0);

  const engines: EngineResult[] = AV_ENGINES.map((name, i) => {
    // If file is clean, no engine should ever detect it
    if (!isMalicious && !isPUP) return { name, detected: false };
    const specific = detectionMap[name];
    if (specific) return { name, detected: true, result: specific };
    if (seededRng(seed + i * 137, i) < detectThreshold) {
      const n = Math.floor(seededRng(seed + i, 7) * 9999);
      return { name, detected: true, result: `Generic.${effectiveFamily.replace("_pup", "PUP")}.${n}` };
    }
    return { name, detected: false };
  });

  const tagMap: Record<string, string[]> = {
    CobaltStrike: ["cobalt-strike", "c2", "beacon", "post-exploitation"],
    WannaCry:     ["ransomware", "worm", "crypto-locker", "smb-exploit"],
    NotPetya:     ["wiper", "destructive", "petya", "notpetya"],
    Mimikatz:     ["credential-theft", "hacktool", "lsass-dump"],
    Emotet:       ["trojan", "banking", "loader", "botnet"],
    GenericKD:    ["trojan", "generic", "malware"],
  };
  const tags = (!isMalicious && !isPUP)
    ? []
    : (tagMap[effectiveFamily] ?? (isPUP ? ["pup", "keygen", "unwanted"] : ["trojan", "malware"]));

  const fileName = String(raw["file.name"] ?? event.file?.path?.split("\\").pop() ?? "");
  const y = 2017 + Math.floor(seededRng(seed, 99) * 8);
  const m = String(1 + Math.floor(seededRng(seed, 98) * 12)).padStart(2, "0");
  const d = String(1 + Math.floor(seededRng(seed, 97) * 27)).padStart(2, "0");

  return {
    hash, malicious: isMalicious || isPUP, detectionCount,
    malwareName: malwareName || undefined,
    malwareFamily: malwareFamily || (isPUP ? "PUP.Keygen" : undefined),
    fileType: "Win32 EXE",
    fileName: fileName || undefined,
    firstSeen: `${y}-${m}-${d}`, lastSeen: "2026-05-10",
    tags, engines,
  };
}

// ─── IP intel builder ──────────────────────────────────────────────────────────

function buildIpIntel(ip: string, event: LiveEvent): IpIntelData {
  const raw = event.raw ?? {};

  // Collect all vendor-specific threat/category fields into a single string for pattern matching
  const allThreatText = [
    raw["threat.category"],
    raw["threat.indicator"],
    raw["cisco.threat_category"],
    raw["cp.threat_category"],
    raw["fortinet.threat_category"],
    raw["pan.threat_category"],
    raw["ids.category"],
    raw["okta.risk.reasons"],
    // Also scan the description for explicit labels (e.g. "TOR exit node")
    event.description,
  ].filter(Boolean).join(" ").toLowerCase();

  const threatCategory  = String(raw["threat.category"]         ?? "").toLowerCase();
  const threatIndicator = String(raw["threat.indicator"]        ?? "").toLowerCase();
  const idsCategory     = String(raw["ids.category"]            ?? "").toLowerCase();
  const wafAttack       = String(raw["waf.attack_type"]         ?? "").toLowerCase();
  const country         = String(raw["source.geo.country_name"] ?? raw["destination.geo.country_name"] ?? "");
  const sessionBlocked  = String(raw["session.blocked"]         ?? "").toLowerCase();
  const eventAction     = String(raw["event.action"]            ?? "").toLowerCase();
  const isBlocked = sessionBlocked === "true" || eventAction === "block" || eventAction === "deny" ||
    event.event_type === "net_blocked" || event.event_type === "ids_signature";

  const parts = ip.split(".").map(Number);
  const seed = parts.reduce((a, b, i) => a + b * Math.pow(256, 3 - i), 0);
  const flag = COUNTRY_FLAGS[country] ?? "🌐";

  // TOR exit node — catch all vendor-specific fields + description text
  if (allThreatText.includes("tor") || threatCategory === "tor" || threatIndicator.includes("tor")) {
    return {
      ip, abusive: true, confidence: 100,
      country: country || "Germany", countryFlag: flag || "🇩🇪",
      isp: "Tor Project Inc.",
      usageType: "Anonymous Proxy / TOR Exit Node",
      totalReports: 1847 + Math.floor(seed % 500),
      lastReported: "2026-05-10",
      categories: ["Anonymous Proxy", "Hacking", "TOR Exit Node"],
    };
  }

  // SQL injection (WAF or IDS)
  if (wafAttack === "sqli" || wafAttack.includes("sql") ||
      allThreatText.includes("sql") || allThreatText.includes("injection")) {
    return {
      ip, abusive: true, confidence: 87,
      country: country || "Russia", countryFlag: flag || "🇷🇺",
      isp: country === "Russia" ? "JSC «ER-Telecom Holding»" : "AS-KIEVNET",
      usageType: "Data Center / Web Hosting",
      totalReports: 312 + Math.floor(seed % 200),
      lastReported: "2026-05-11",
      categories: ["SQL Injection", "Web Application Attack", "Hacking"],
    };
  }

  // Network / port scan
  if (idsCategory.includes("scan") || idsCategory.includes("nmap") ||
      allThreatText.includes("scan") || allThreatText.includes("scanner")) {
    return {
      ip, abusive: true, confidence: 78,
      country: country || "Germany", countryFlag: flag || "🇩🇪",
      isp: country === "Germany" ? "Hetzner Online GmbH" : "DigitalOcean LLC",
      usageType: "Data Center / Web Hosting",
      totalReports: 856 + Math.floor(seed % 300),
      lastReported: "2026-05-11",
      categories: ["Port Scan", "Network Scan", "Hacking"],
    };
  }

  // Botnet / malware C2
  if (allThreatText.includes("botnet") || allThreatText.includes("c2") ||
      allThreatText.includes("malware") || allThreatText.includes("cobalt")) {
    return {
      ip, abusive: true, confidence: 94,
      country: country || "Netherlands", countryFlag: flag || "🇳🇱",
      isp: "Serverius B.V.",
      usageType: "Data Center / Bulletproof Hosting",
      totalReports: 1203 + Math.floor(seed % 400),
      lastReported: "2026-05-11",
      categories: ["Malware C2", "Botnet", "Hacking"],
    };
  }

  // Generic block
  if (isBlocked) {
    return {
      ip, abusive: true, confidence: 82,
      country: country || "Unknown", countryFlag: flag,
      isp: "Unknown Hosting Provider",
      usageType: "Data Center / VPS",
      totalReports: 423 + Math.floor(seed % 250),
      lastReported: "2026-05-10",
      categories: ["Brute Force", "Hacking"],
    };
  }

  // Clean
  return {
    ip, abusive: false, confidence: 0,
    country: country || "United States", countryFlag: flag || "🇺🇸",
    isp: "Comcast Cable Communications",
    usageType: "Residential / Business",
    totalReports: 0,
    categories: [],
  };
}

// ─── Domain intel builder ──────────────────────────────────────────────────────

const REGISTRARS = ["NameCheap Inc.", "Namecheap, Inc.", "PDR Ltd. d/b/a PublicDomainRegistry.com", "NICENIC INTERNATIONAL GROUP CO., LIMITED"];

function buildDomainIntel(domain: string, event: LiveEvent): DomainIntelData {
  const raw = event.raw ?? {};
  const mitre = event.mitre_technique ?? "";
  const desc = (event.description ?? "").toLowerCase();

  // C2 / beaconing / DNS tunneling / DGA techniques
  const c2Techniques = new Set(["T1071.001", "T1071.004", "T1568.002", "T1041", "T1048.003"]);
  const threatCategory = String(raw["threat.category"] ?? raw["threat.name"] ?? "").toLowerCase();
  const explicitAge = Number(raw["domain.registration_age_days"] ?? NaN);

  const isMalicious =
    c2Techniques.has(mitre) ||
    threatCategory.includes("c2") || threatCategory.includes("phish") || threatCategory.includes("malware") ||
    desc.includes("command server") || desc.includes("command-and-control") || desc.includes("c2") ||
    (!Number.isNaN(explicitAge) && explicitAge <= 30) ||
    /registered\s+\d+\s+days?\s+ago/.test(desc);

  const seed = Array.from(domain).reduce((a, c) => a + c.charCodeAt(0), 0) + domain.length * 97;

  const ageDays = !Number.isNaN(explicitAge)
    ? explicitAge
    : isMalicious
      ? 1 + Math.floor(seededRng(seed, 1) * 13)
      : 800 + Math.floor(seededRng(seed, 1) * 4000);

  const detectionCount = isMalicious
    ? (event.severity === "critical" ? 22 + Math.floor(seededRng(seed, 2) * 15)
      : event.severity === "high" ? 12 + Math.floor(seededRng(seed, 2) * 10)
      : 4 + Math.floor(seededRng(seed, 2) * 6))
    : 0;

  const categories: string[] = [];
  if (isMalicious) {
    if (mitre === "T1071.001") categories.push("Command & Control", "Malware C2");
    else if (mitre === "T1071.004" || mitre === "T1048.003") categories.push("DNS Tunneling", "Data Exfiltration");
    else if (mitre === "T1568.002") categories.push("Domain Generation Algorithm", "Malware C2");
    else categories.push("Malicious", "Suspicious Activity");
    if (ageDays <= 30) categories.push("Newly Registered Domain");
  }

  const now = new Date("2026-05-10T00:00:00Z").getTime();
  const created = new Date(now - ageDays * 86_400_000);
  const creationDate = created.toISOString().slice(0, 10);

  return {
    domain,
    malicious: isMalicious,
    detectionCount,
    registrar: REGISTRARS[Math.floor(seededRng(seed, 3) * REGISTRARS.length)],
    creationDate,
    ageDays,
    categories,
    tags: isMalicious ? ["c2", "recently-registered", "suspicious-tld"].filter((_, i) => seededRng(seed, i + 4) > 0.3) : [],
  };
}

// ─── Hash Intel Panel ──────────────────────────────────────────────────────────

function HashPanel({ data, onClose }: { data: HashIntelData; onClose: () => void }) {
  const detected = data.engines.filter(e => e.detected).length;
  const total    = data.engines.length;
  const pct      = Math.round((detected / total) * 100);
  const isMal    = data.malicious;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyber-300" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-500">File Hash</span>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* Hash */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-1">SHA-256</p>
          <p className="font-mono text-[10px] text-neon-amber break-all leading-relaxed">{data.hash}</p>
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3",
          isMal ? "border-severity-critical/40 bg-severity-critical/10" : "border-neon-green/40 bg-neon-green/10"
        )}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", isMal ? "text-severity-critical" : "text-neon-green")}>
              {isMal ? "⚠ MALICIOUS" : "✓ CLEAN"}
            </span>
            <span className={cn("font-mono text-sm font-bold", isMal ? "text-severity-critical" : "text-neon-green")}>
              {detected} / {total}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-700/60 overflow-hidden">
            <div className={cn("h-full rounded-full", isMal ? "bg-severity-critical" : "bg-neon-green")} style={{ width: `${pct}%` }} />
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {detected > 0
              ? `${detected} of ${total} security vendors flagged this file`
              : "No security vendor flagged this file"}
          </p>
        </div>

        {/* Malware details */}
        {isMal && (
          <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Malware Classification</p>
            {data.malwareName && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-500">Detection Name</span>
                <span className="font-mono text-[10px] text-severity-critical">{data.malwareName}</span>
              </div>
            )}
            {data.malwareFamily && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-500">Family</span>
                <span className="font-mono text-[10px] text-slate-200">{data.malwareFamily}</span>
              </div>
            )}
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">File Type</span>
              <span className="font-mono text-[10px] text-slate-200">{data.fileType}</span>
            </div>
            {data.fileName && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-500">File Name</span>
                <span className="font-mono text-[10px] text-slate-200">{data.fileName}</span>
              </div>
            )}
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">First Seen</span>
              <span className="font-mono text-[10px] text-slate-200">{data.firstSeen}</span>
            </div>
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">Last Seen</span>
              <span className="font-mono text-[10px] text-slate-200">{data.lastSeen}</span>
            </div>
          </div>
        )}

        {/* Tags */}
        {data.tags.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {data.tags.map(tag => (
                <span key={tag} className="rounded border border-border/60 bg-black/20 px-2 py-0.5 font-mono text-[9px] text-slate-400">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Engine table */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">
            Security Vendor Analysis &nbsp;<span className="text-slate-600">({detected}/{total} detected)</span>
          </p>
          <div className="rounded border border-border/60 overflow-hidden text-[10px]">
            {data.engines.map((eng, i) => (
              <div key={eng.name} className={cn(
                "flex items-center justify-between px-3 py-2",
                i > 0 && "border-t border-border/30",
                eng.detected ? "bg-severity-critical/5" : ""
              )}>
                <span className={cn("font-medium w-[140px] shrink-0", eng.detected ? "text-slate-200" : "text-slate-500")}>{eng.name}</span>
                {eng.detected
                  ? <span className="font-mono text-severity-critical truncate">{eng.result}</span>
                  : <span className="text-slate-700">— (no detection)</span>
                }
              </div>
            ))}
          </div>
        </div>

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-600 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── IP Intel Panel ────────────────────────────────────────────────────────────

function IpPanel({ data, onClose }: { data: IpIntelData; onClose: () => void }) {
  const pct = data.confidence;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-neon-blue" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-500">IP Address</span>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* IP */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-1">IP Address</p>
          <p className="font-mono text-base font-bold text-neon-blue">{data.ip}</p>
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3",
          data.abusive ? "border-severity-critical/40 bg-severity-critical/10" : "border-neon-green/40 bg-neon-green/10"
        )}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", data.abusive ? "text-severity-critical" : "text-neon-green")}>
              {data.abusive ? "⚠ ABUSIVE" : "✓ CLEAN"}
            </span>
            <span className={cn("font-mono text-sm font-bold", data.abusive ? "text-severity-critical" : "text-neon-green")}>
              {pct}% confidence
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-700/60 overflow-hidden">
            <div className={cn("h-full rounded-full", data.abusive ? "bg-severity-critical" : "bg-neon-green")} style={{ width: `${pct}%` }} />
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {data.abusive
              ? `${data.totalReports.toLocaleString()} abuse reports on record`
              : "No abuse reports on record"}
          </p>
        </div>

        {/* IP info */}
        <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">IP Information</p>
          {data.country && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">Country</span>
              <span className="text-[10px] text-slate-200">{data.countryFlag} {data.country}</span>
            </div>
          )}
          {data.isp && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">ISP / Org</span>
              <span className="font-mono text-[10px] text-slate-200">{data.isp}</span>
            </div>
          )}
          {data.usageType && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">Usage Type</span>
              <span className="text-[10px] text-slate-200">{data.usageType}</span>
            </div>
          )}
          {data.abusive && data.totalReports > 0 && (
            <>
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-500">Total Reports</span>
                <span className="font-mono text-[10px] text-severity-critical">{data.totalReports.toLocaleString()}</span>
              </div>
              {data.lastReported && (
                <div className="flex gap-3 items-baseline">
                  <span className="w-28 shrink-0 text-[10px] text-slate-500">Last Reported</span>
                  <span className="font-mono text-[10px] text-slate-200">{data.lastReported}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Categories */}
        {data.categories.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Abuse Categories</p>
            <div className="flex flex-wrap gap-1.5">
              {data.categories.map(cat => (
                <span key={cat} className="rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[9px] font-semibold text-severity-critical">
                  {cat}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-600 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Domain Intel Panel ────────────────────────────────────────────────────────

function DomainPanel({ data, onClose }: { data: DomainIntelData; onClose: () => void }) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-neon-green" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-500">Domain</span>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* Domain */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-1">Domain</p>
          <p className="font-mono text-sm font-bold text-neon-green break-all">{data.domain}</p>
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3",
          data.malicious ? "border-severity-critical/40 bg-severity-critical/10" : "border-neon-green/40 bg-neon-green/10"
        )}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", data.malicious ? "text-severity-critical" : "text-neon-green")}>
              {data.malicious ? "⚠ MALICIOUS" : "✓ CLEAN"}
            </span>
            <span className={cn("font-mono text-sm font-bold", data.malicious ? "text-severity-critical" : "text-neon-green")}>
              {data.detectionCount} / 90 vendors
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {data.malicious
              ? `${data.detectionCount} security vendors flagged this domain`
              : "No security vendor flagged this domain"}
          </p>
        </div>

        {/* WHOIS-style info */}
        <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Registration Info</p>
          {data.registrar && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">Registrar</span>
              <span className="font-mono text-[10px] text-slate-200">{data.registrar}</span>
            </div>
          )}
          {data.creationDate && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-500">Created</span>
              <span className={cn("font-mono text-[10px]", data.ageDays <= 30 ? "text-severity-critical" : "text-slate-200")}>
                {data.creationDate} ({data.ageDays} day{data.ageDays === 1 ? "" : "s"} old)
              </span>
            </div>
          )}
        </div>

        {/* Categories */}
        {data.categories.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Categories</p>
            <div className="flex flex-wrap gap-1.5">
              {data.categories.map(cat => (
                <span key={cat} className="rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[9px] font-semibold text-severity-critical">
                  {cat}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        {data.tags.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {data.tags.map(tag => (
                <span key={tag} className="rounded border border-border/60 bg-black/20 px-2 py-0.5 font-mono text-[9px] text-slate-400">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-600 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Threat Intel Drawer (right-side panel) ────────────────────────────────────

function ThreatIntelDrawer({ query, onClose }: { query: ThreatQuery; onClose: () => void }) {
  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const hashData   = query.type === "hash"   ? buildHashIntel(query.value, query.event)   : null;
  const ipData     = query.type === "ip"     ? buildIpIntel(query.value, query.event)     : null;
  const domainData = query.type === "domain" ? buildDomainIntel(query.value, query.event) : null;

  return (
    <>
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />
      <motion.div
        initial={{ x: 460 }} animate={{ x: 0 }} exit={{ x: 460 }}
        transition={{ type: "spring", damping: 28, stiffness: 260 }}
        className="fixed right-0 top-0 h-screen w-[440px] bg-[#080d14] border-l border-border/80 z-50 shadow-2xl"
      >
        {hashData   && <HashPanel   data={hashData}   onClose={onClose} />}
        {ipData     && <IpPanel     data={ipData}     onClose={onClose} />}
        {domainData && <DomainPanel data={domainData} onClose={onClose} />}
      </motion.div>
    </>
  );
}

// ─── Threat-intel field helpers ────────────────────────────────────────────────

function isPublicIp(val: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return false;
  return !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|255\.)/.test(val);
}

const IP_FIELD_KEYS = new Set([
  "source.ip", "destination.ip", "source.nat.ip", "destination.nat.ip", "client.ip", "server.ip",
]);
const DOMAIN_FIELD_KEYS = new Set([
  "dns.question.name", "url.domain", "url.full", "source.domain", "destination.domain",
]);

function isSha256Field(key: string, val: string) {
  return (key === "file.hash.sha256" || key.endsWith(".sha256")) && /^[a-f0-9]{64}$/i.test(val);
}
function isIpCheckField(key: string, val: string) {
  return IP_FIELD_KEYS.has(key) && isPublicIp(val);
}
function isDomainCheckField(key: string, val: string) {
  if (!DOMAIN_FIELD_KEYS.has(key)) return false;
  return val.includes(".") && !val.includes(" ") && !isPublicIp(val) && val.length > 3;
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical:      "text-severity-critical",
  high:          "text-severity-high",
  medium:        "text-severity-medium",
  low:           "text-slate-300",
  informational: "text-slate-400",
};

const ADMIN_EVENT_TYPES = new Set([
  "group_modify", "account_modify", "account_create", "account_delete",
  "privilege_escalation", "role_assignment", "account_lockout",
]);

function DetailPanel({
  event,
  onThreatQuery,
  onXp,
}: {
  event: LiveEvent;
  onThreatQuery: (q: ThreatQuery) => void;
  onXp?: (xp: number) => void;
}) {
  const [showRawJson, setShowRawJson] = useState(false);
  const [itVerifyState, setItVerifyState] = useState<"idle" | "verifying" | "done">("idle");

  const hasItVerify = event.it_verify_result !== undefined || ADMIN_EVENT_TYPES.has(event.event_type);

  function handleItVerify(e: React.MouseEvent) {
    e.stopPropagation();
    if (!event.it_verify_result) return; // no predetermined result — shouldn't happen
    setItVerifyState("verifying");
    setTimeout(() => setItVerifyState("done"), 1400 + Math.random() * 600);
  }

  const sourceLabel = event.source === "cloudtrail"
    ? cloudLabel(event.vendor)
    : (SOURCE_LABEL[event.source] ?? event.source.toUpperCase());
  const severityColor = SEVERITY_COLORS[event.severity ?? ""] ?? "text-slate-300";
  const actionOutcome = extractActionOutcome(event);

  const actionLabel = actionOutcome
    ? actionOutcome.status === "detected" ? "DETECTED — NOT CONTAINED"
    : actionOutcome.status === "allowed"  ? "ALLOWED — NO ACTION TAKEN"
    : `${actionOutcome.label.toUpperCase()}${actionOutcome.detail ? ` · ${actionOutcome.detail}` : ""}`
    : null;

  const actionColor = actionOutcome
    ? actionOutcome.status === "detected" ? "text-severity-critical"
    : actionOutcome.status === "allowed"  ? "text-slate-400"
    : "text-neon-green"
    : undefined;

  const fullDescription = event.description ?? event.displayDescription;
  const sha256 = event.file?.sha256 ?? (event.raw?.["file.hash.sha256"] as string | undefined);

  const basicInfo: [string, string, string?][] = [
    ["Timestamp",  event.ts ? new Date(event.ts).toLocaleString("en-GB") : "—"],
    ["Severity",   (event.severity ?? "—").toUpperCase(), severityColor],
    ...(actionLabel ? [["Response", actionLabel, actionColor] as [string, string, string]] : []),
    ["Username",   event.user_email ?? "—"],
    ["Hostname",   event.hostname   ?? "—"],
    ["IP Address", event.src_ip     ?? "—"],
  ];

  const ecsCore: [string, string][] = [
    ["event.id",       event.id],
    ["event.provider", event.vendor ?? event.source.toUpperCase()],
    ["event.type",     event.event_type.replace(/_/g, " ")],
    ...(event.mitre_technique ? [["threat.technique.id", event.mitre_technique] as [string, string]] : []),
    ...(event.user_email ? [["user.email",  event.user_email]           as [string, string]] : []),
    ...(event.hostname   ? [["host.name",   event.hostname]             as [string, string]] : []),
    ...(event.src_ip   ? [["source.ip",         event.src_ip]           as [string, string]] : []),
    ...(event.src_port ? [["source.port",        String(event.src_port)] as [string, string]] : []),
    ...(event.dst_ip   ? [["destination.ip",     event.dst_ip]           as [string, string]] : []),
    ...(event.dst_port ? [["destination.port",   String(event.dst_port)] as [string, string]] : []),
    ...(event.protocol ? [["network.protocol",   event.protocol]         as [string, string]] : []),
    ...(event.network?.url    ? [["url.full",          event.network.url]         as [string, string]] : []),
    ...(event.network?.domain ? [["dns.question.name", event.network.domain]      as [string, string]] : []),
    ...(event.network?.method ? [["http.request.method", event.network.method]    as [string, string]] : []),
    ...(event.network?.bytes_out ? [["network.bytes_out", `${event.network.bytes_out} B`] as [string, string]] : []),
    ...(event.network?.bytes_in  ? [["network.bytes_in",  `${event.network.bytes_in} B`]  as [string, string]] : []),
    ...(event.process?.name        ? [["process.name",        event.process.name]              as [string, string]] : []),
    ...(event.process?.pid         ? [["process.pid",         String(event.process.pid)]        as [string, string]] : []),
    ...(event.process?.cmdline     ? [["process.command_line", event.process.cmdline]           as [string, string]] : []),
    ...(event.process?.parent_name ? [["process.parent.name", event.process.parent_name]        as [string, string]] : []),
    ...(event.process?.parent_pid  ? [["process.parent.pid",  String(event.process.parent_pid)] as [string, string]] : []),
    ...(event.process?.user        ? [["user.name",           event.process.user]               as [string, string]] : []),
    ...(event.process?.integrity   ? [["process.integrity",   event.process.integrity]          as [string, string]] : []),
    ...(event.file?.path   ? [["file.path",        event.file.path]        as [string, string]] : []),
    ...(event.file?.sha256 ? [["file.hash.sha256", event.file.sha256]      as [string, string]] : []),
    ...(event.file?.size   ? [["file.size",        `${event.file.size} B`] as [string, string]] : []),
  ];

  const ecsCoreKeys = new Set(ecsCore.map(([k]) => k));

  const rawFields: [string, string][] = Object.entries(event.raw ?? {})
    .filter(([k, v]) => !ecsCoreKeys.has(k) && v !== null && v !== undefined && v !== "" && typeof v !== "object" && typeof v !== "boolean")
    .map(([k, v]) => [k, String(v)]);

  const rawBool: [string, string][] = Object.entries(event.raw ?? {})
    .filter(([k, v]) => !ecsCoreKeys.has(k) && typeof v === "boolean")
    .map(([k, v]) => [k, v ? "true" : "false"]);

  const detailedFields: [string, string][] = [...ecsCore, ...rawFields, ...rawBool];

  return (
    <td colSpan={7} className="bg-[#080d14] p-0">
      {/* Log reading tour — fires once on first-ever event expansion */}
      <LogReadingTour />
      <div className="border-t border-border/50 px-5 py-4 space-y-3">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-semibold text-white">Log Analysis</span>
          </div>
          {/* Analysis ↔ Raw log segmented control — Raw shows the authentic vendor wire format */}
          <div className="inline-flex items-center rounded-md border border-border/70 bg-[#0a0f18] p-0.5 text-[11px] font-semibold">
            <button
              onClick={() => setShowRawJson(false)}
              className={cn("rounded px-2.5 py-1 transition-colors", !showRawJson ? "bg-cyber-500/20 text-cyber-200" : "text-slate-400 hover:text-slate-200")}
            >
              Analysis
            </button>
            <button
              onClick={() => setShowRawJson(true)}
              className={cn("rounded px-2.5 py-1 transition-colors", showRawJson ? "bg-cyber-500/20 text-cyber-200" : "text-slate-400 hover:text-slate-200")}
            >
              Raw log
            </button>
          </div>
        </div>

        {/* IT Verification Widget — shown for admin/privileged action events */}
        {!showRawJson && hasItVerify && event.it_verify_result && (
          <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2.5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">IT Verification</p>
            {itVerifyState === "idle" && (
              <>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  This event involves a privileged administrative action. Verify with the IT Help Desk whether a change ticket was raised for this activity.
                </p>
                <button
                  onClick={handleItVerify}
                  className="inline-flex items-center gap-2 rounded border border-cyber-500/50 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 hover:bg-cyber-500/20 transition-colors"
                >
                  <PhoneCall className="h-3.5 w-3.5" />
                  Verify with IT
                </button>
              </>
            )}
            {itVerifyState === "verifying" && (
              <div className="flex items-center gap-2.5 py-1 text-[11px] text-slate-400">
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-cyber-500/30 border-t-cyber-400" />
                Contacting IT Help Desk&hellip;
              </div>
            )}
            {itVerifyState === "done" && event.it_verify_result === "confirmed" && (
              <div className="rounded border border-neon-green/40 bg-neon-green/5 px-3 py-2.5">
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="h-4 w-4 text-neon-green mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-semibold text-neon-green mb-1">Authorised Change Confirmed</p>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      {event.it_verify_message ?? "IT confirmed a valid change ticket exists for this action. This is expected activity — classify as benign."}
                    </p>
                  </div>
                </div>
              </div>
            )}
            {itVerifyState === "done" && event.it_verify_result === "unverified" && (
              <div className="rounded border border-severity-critical/40 bg-severity-critical/5 px-3 py-2.5">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="h-4 w-4 text-severity-critical mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-semibold text-severity-critical mb-1">Unverified — No Ticket Found</p>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      {event.it_verify_message ?? "IT has no record of a change request for this action. Treat as suspicious and escalate for further investigation."}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {showRawJson ? (
          (() => {
            const rawLog = toRawLog(event);
            return (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="inline-flex items-center gap-1.5 rounded border border-border/60 bg-[#0d1520] px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                    <BookOpen className="h-3 w-3 text-slate-500" />
                    {rawLog.format}
                  </span>
                  <button
                    onClick={() => navigator.clipboard?.writeText(rawLog.text)}
                    className="inline-flex items-center gap-1.5 rounded border border-border/60 px-2 py-1 text-[10px] font-semibold text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors"
                  >
                    <Copy className="h-3 w-3" />
                    Copy
                  </button>
                </div>
                <pre className="max-h-72 overflow-auto rounded border border-border bg-[#0a0f18] p-3 font-mono text-[10px] leading-relaxed text-slate-300 whitespace-pre">
                  {rawLog.text}
                </pre>
                <p className="text-[10px] leading-relaxed text-slate-500">
                  This is how <span className="text-slate-400">{rawLog.format.split(",")[0]}</span> arrives in the SIEM before parsing — the same bytes a real analyst pivots on. The Analysis tab parses these fields into a readable view.
                </p>
              </div>
            );
          })()
        ) : (
          <>
            {/* Basic Info */}
            <div id="ef-detail-basic-info" className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Basic Information</p>
              <div className="space-y-2">
                {fullDescription && (
                  <div className="flex gap-3 pb-2 mb-1 border-b border-border/40">
                    <span className="w-36 shrink-0 text-[11px] text-slate-500">Description</span>
                    <span className="text-[11px] leading-relaxed text-slate-200 break-words">{fullDescription}</span>
                  </div>
                )}
                {/* SHA256 — opens internal panel */}
                {sha256 && /^[a-f0-9]{64}$/i.test(sha256) && (
                  <div className="flex gap-3 pb-2 mb-1 border-b border-border/40 items-start">
                    <span className="w-36 shrink-0 text-[11px] text-slate-500">File Hash</span>
                    <div className="flex flex-col gap-1.5 min-w-0">
                      <span className="font-mono text-[10px] text-neon-amber break-all">{sha256}</span>
                      <button
                        onClick={e => { e.stopPropagation(); onThreatQuery({ type: "hash", value: sha256, event }); }}
                        className="inline-flex w-fit items-center gap-1.5 rounded border border-severity-critical/50 bg-severity-critical/10 px-3 py-1 text-[10px] font-bold text-severity-critical hover:bg-severity-critical/20 transition"
                      >
                        <Shield className="h-3 w-3" />
                        Check Hash · Threat Intel
                      </button>
                    </div>
                  </div>
                )}
                {basicInfo.map(([label, value, colorClass]) => (
                  <div key={label} className="flex gap-3">
                    <span className="w-36 shrink-0 text-[11px] text-slate-500">{label}</span>
                    <span className={cn("font-mono text-[11px] text-slate-200 break-all", colorClass)}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Email Header Investigator ─────────────────────────── */}
            <EmailHeaderViewer event={event} onXp={onXp} />

            {/* Detailed Log Data */}
            <div id="ef-detail-log-data" className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Detailed Log Data</p>
              <div className="space-y-1.5">
                {(() => {
                  return detailedFields.map(([k, v]) => {
                  const showHash   = isSha256Field(k, v);
                  const showIp     = isIpCheckField(k, v);
                  const showDomain = isDomainCheckField(k, v);
                  const hasBtn     = showHash || showIp || showDomain;

                  return (
                    <div key={k} className={cn("flex gap-3", hasBtn ? "items-start py-0.5" : "items-baseline")}>
                      <span className="w-64 shrink-0 font-mono text-[10px] text-slate-500">{k}</span>
                      <div className="flex flex-col gap-1.5 min-w-0">
                        <span className={cn(
                          "font-mono text-[10px] break-all",
                          showHash ? "text-neon-amber" : showIp ? "text-neon-blue" : "text-slate-300"
                        )}>{v}</span>

                        {/* SHA256 → internal threat panel */}
                        {showHash && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "hash", value: v, event }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-amber/50 bg-neon-amber/10 px-2 py-0.5 text-[9px] font-bold text-neon-amber hover:bg-neon-amber/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check Hash · Threat Intel
                          </button>
                        )}

                        {/* Public IP → internal threat panel */}
                        {showIp && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "ip", value: v, event }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-blue/50 bg-neon-blue/10 px-2 py-0.5 text-[9px] font-bold text-neon-blue hover:bg-neon-blue/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check IP · Threat Intel
                          </button>
                        )}

                        {/* Domain → internal threat panel (was an external VirusTotal link —
                            removed because platform domains are fictional and VT either shows
                            nothing or unrelated real-world data for them) */}
                        {showDomain && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "domain", value: v, event }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-green/50 bg-neon-green/10 px-2 py-0.5 text-[9px] font-bold text-neon-green hover:bg-neon-green/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check Domain · Threat Intel
                          </button>
                        )}
                      </div>
                    </div>
                  );
                  });
                })()}
              </div>
            </div>
          </>
        )}


      </div>
    </td>
  );
}


// ─── MITRE Technique Badge + Slideout ─────────────────────────────────────────

function MitreSlideout({ techniqueId, onClose }: { techniqueId: string; onClose: () => void }) {
  const technique = techniqueById(techniqueId);
  const tactic = technique ? tacticById(technique.tactic) : undefined;

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!technique) return null;

  return (
    <>
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />
      <motion.div
        initial={{ x: 440 }} animate={{ x: 0 }} exit={{ x: 440 }}
        transition={{ type: "spring", damping: 28, stiffness: 260 }}
        className="fixed right-0 top-0 h-screen w-[420px] bg-[#080d14] border-l border-border/80 z-50 shadow-2xl overflow-y-auto"
      >
        <div className="px-5 py-4 border-b border-border/60 flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="rounded border border-neon-purple/50 bg-neon-purple/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-neon-purple">{technique.id}</span>
              {tactic && <span className="text-[10px] text-slate-500">{tactic.name}</span>}
            </div>
            <h3 className="text-sm font-semibold text-white">{technique.name}</h3>
          </div>
          <button onClick={onClose} className="mt-0.5 shrink-0 rounded p-1 text-slate-400 hover:bg-slate-700/50 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          {/* What attacker does */}
          {technique.whatAttackerDoes && (
            <div>
              <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-2">What the attacker does</p>
              <p className="text-[11px] leading-relaxed text-slate-200">{technique.whatAttackerDoes}</p>
            </div>
          )}

          {/* Log indicators */}
          {technique.logIndicators && technique.logIndicators.length > 0 && (
            <div>
              <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-2">What to look for in logs</p>
              <ul className="space-y-1.5">
                {technique.logIndicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-slate-300">
                    <span className="mt-0.5 shrink-0 text-neon-green">•</span>
                    <span>{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Detection hint */}
          {technique.detection_hint && (
            <div className="rounded border border-neon-amber/30 bg-neon-amber/5 px-3 py-2.5">
              <p className="text-[9px] font-semibold text-neon-amber mb-1">Detection tip</p>
              <p className="text-[10px] leading-relaxed text-slate-300">{technique.detection_hint}</p>
            </div>
          )}

          {/* Data sources */}
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-1.5">Data sources</p>
            <div className="flex flex-wrap gap-1">
              {technique.data_sources.map(ds => (
                <span key={ds} className="rounded border border-slate-600/50 bg-slate-800/50 px-2 py-0.5 text-[9px] text-slate-400">{ds}</span>
              ))}
            </div>
          </div>

          {/* External link */}
          <a
            href={`https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`}
            target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-[10px] text-cyber-400 hover:text-cyber-300 transition"
          >
            View on MITRE ATT&CK <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </motion.div>
    </>
  );
}

function MitreBadge({ technique }: { technique: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        onClick={e => { e.stopPropagation(); setOpen(true); }}
        className="inline-flex items-center gap-0.5 rounded border border-neon-purple/40 bg-neon-purple/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-neon-purple hover:bg-neon-purple/20 transition"
        title={`MITRE: ${technique}`}
      >
        {technique}
      </button>
      <AnimatePresence>
        {open && <MitreSlideout techniqueId={technique} onClose={() => setOpen(false)} />}
      </AnimatePresence>
    </>
  );
}

// ─── SOC Methodology Banner ───────────────────────────────────────────────────

function SocMethodologyBanner() {
  const [expanded, setExpanded] = useState(false);

  const steps = [
    { num: "1", label: "Source", detail: "Which tool logged this? What does that tool monitor? (Hover the SOURCE badge)" },
    { num: "2", label: "Actors", detail: "Who is the user? What machine? What process? What started it?" },
    { num: "3", label: "Behavior", detail: "Is this normal for this context? Would a legitimate user do exactly this?" },
    { num: "4", label: "Pattern", detail: "Does this match a known attack? Check the MITRE badge if present." },
    { num: "5", label: "Classify", detail: "Benign = expected normal activity. Suspicious = unusual but inconclusive. Malicious = clear attack indicator." },
  ];

  return (
    <div className="border-b border-border/40 bg-[#06101a]">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-2 hover:bg-white/[0.02] transition text-left"
      >
        <BookOpen className="h-3 w-3 text-cyber-500 shrink-0" />
        <span className="text-[9px] font-bold uppercase tracking-[0.18em] text-cyber-500">SOC Analysis Guide</span>
        <div className="flex items-center gap-2 ml-2 flex-1">
          {!expanded && steps.map(s => (
            <span key={s.num} className="hidden sm:flex items-center gap-1 text-[9px] text-slate-600">
              <span className="font-bold text-slate-500">{s.num}.</span> {s.label}
              {s.num !== "5" && <span className="text-slate-700 ml-1">→</span>}
            </span>
          ))}
        </div>
        <span className="text-[9px] text-slate-600 ml-auto shrink-0">{expanded ? "▲ hide" : "▼ show steps"}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-3 grid grid-cols-5 gap-2">
          {steps.map(s => (
            <div key={s.num} className="rounded border border-border/40 bg-[#0d1520] p-2.5">
              <div className="flex items-center gap-1.5 mb-1.5">
                <span className="flex h-4 w-4 items-center justify-center rounded-full bg-cyber-500/15 text-[9px] font-bold text-cyber-400">{s.num}</span>
                <span className="text-[10px] font-bold text-white">{s.label}</span>
              </div>
              <p className="text-[9px] leading-relaxed text-slate-500">{s.detail}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Event row ────────────────────────────────────────────────────────────────

const EventRow = memo(function EventRow({
  event, isNew, onThreatQuery, onXp, onRowOpened,
}: {
  event: LiveEvent;
  isNew: boolean;
  onThreatQuery: (q: ThreatQuery) => void;
  onXp?: (xp: number) => void;
  onRowOpened?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const timeStr = event.ts
    ? new Date(event.ts).toLocaleTimeString("en-GB", { hour12: false })
    : "—";
  const sourceLabel = event.source === "cloudtrail"
    ? cloudLabel(event.vendor)
    : (SOURCE_LABEL[event.source] ?? event.source.toUpperCase());
  const sourceColor = SOURCE_COLORS[event.source] ?? SOURCE_COLORS.proxy;

  return (
    <>
      <motion.tr
        layout
        initial={isNew ? { opacity: 0, y: -8 } : false}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        onClick={() => {
          // Side effect lives in the handler, not inside setExpanded's updater —
          // React (Strict Mode) may invoke an updater function twice to check
          // for impurities, which would double-count this if it lived there.
          if (!expanded) onRowOpened?.(); // only count transitions into "opened", not collapses
          setExpanded(v => !v);
        }}
        className={cn(
          "group cursor-pointer border-t border-border/60 transition-colors",
          expanded ? "bg-bg-hover" : "hover:bg-bg-hover/60",
        )}
      >
        <td className="w-6 pl-3">
          <ChevronRight className={cn("h-3 w-3 text-slate-500 transition-transform", expanded && "rotate-90")} />
        </td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400">{timeStr}</td>
        <td className="py-2.5 pr-3 font-mono text-xs text-slate-200">{event.hostname ?? "—"}</td>
        <td className="py-2.5 pr-3">
          <LogSourceCard source={event.source} vendor={event.vendor} />
        </td>
        <td className="py-2 pr-3 text-xs text-slate-300 max-w-[400px]">
          <div className="flex items-start gap-1.5">
            {/* Fired-times counter badge */}
            {(() => {
              const ft = Number(event.raw?.["firedtimes"] ?? 0);
              if (ft <= 1) return null;
              const color = ft >= 50
                ? "border-severity-critical/60 bg-severity-critical/15 text-severity-critical"
                : ft >= 15
                  ? "border-severity-high/60 bg-severity-high/15 text-severity-high"
                  : "border-neon-amber/50 bg-neon-amber/10 text-neon-amber";
              return (
                <span className={cn("shrink-0 inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold tabular-nums", color)}
                  title={`Rule fired ${ft} times`}>
                  {ft}×
                </span>
              );
            })()}

            {/* Description block: user chip + role chip + dry action */}
            <div className="min-w-0 flex-1">
              {event.user_email && (() => {
                const username  = event.user_email.split("@")[0];
                const userTitle = event.user_title ?? (event.user as { title?: string } | undefined)?.title;
                // Strip the username from the start of the description so it isn't
                // duplicated — also handles a possessive form ("Username's …").
                const rawDesc = event.displayDescription ?? "";
                const escaped  = username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                const stripped = rawDesc
                  .replace(new RegExp(`^${escaped}(?:['’]s)?[\\s\\-:·,]+`, "i"), "");
                const cleanDesc = (stripped.charAt(0).toUpperCase() + stripped.slice(1)).trim() || rawDesc;

                return (
                  <>
                    {/* Row 1: username + role */}
                    <div className="flex items-center gap-1 mb-0.5 flex-wrap">
                      <span className="font-mono text-[11px] font-bold text-cyber-300 leading-none">{username}</span>
                      {userTitle && (
                        <span className="rounded border border-slate-600/50 bg-slate-800/70 px-1.5 py-px text-[9px] font-medium text-slate-400 leading-none">
                          {userTitle}
                        </span>
                      )}
                    </div>
                    {/* Row 2: dry action text */}
                    <span className="line-clamp-1 text-[11px] leading-snug text-slate-400">{cleanDesc}</span>
                  </>
                );
              })()}

              {/* No user_email: fall back to single-line description */}
              {!event.user_email && (
                <span className="line-clamp-2 leading-relaxed">{event.displayDescription}</span>
              )}
            </div>
          </div>
        </td>
        <td className="py-2.5 pr-3">
          <RuleLevelBadge level={event.ruleLevel} />
        </td>
        <td className="py-2.5 pr-3">
          {/* No verdict/grading UI here by design — classifying a row would
              instantly reveal ground truth (a hint). The analyst reads the log,
              forms their own conclusion, and the Incident Report is the single
              place they state and are graded on their findings. */}
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-[10px] text-slate-500">{event.ruleId}</span>
            {event.mitre_technique && <MitreBadge technique={event.mitre_technique} />}
          </div>
        </td>
      </motion.tr>

      <AnimatePresence>
        {expanded && (
          <motion.tr
            key={`${event.id}-detail`}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            <DetailPanel event={event} onThreatQuery={onThreatQuery} onXp={onXp} />
          </motion.tr>
        )}
      </AnimatePresence>
    </>
  );
});

// ─── Feed ──────────────────────────────────────────────────────────────────────

const TIME_OPTIONS: { label: string; value: TimeFilter; ms: number | null }[] = [
  { label: "15 min", value: "15m", ms: 15 * 60_000 },
  { label: "1 hour", value: "1h",  ms: 60 * 60_000 },
  { label: "4 hours",value: "4h",  ms: 4 * 60 * 60_000 },
  { label: "All",    value: "all", ms: null },
];

export interface EventFeedProps {
  events: LiveEvent[];
  newIds?: Set<string>;
  severityFilter: "all" | "low" | "medium" | "high";
  sourceFilter: string;
  search: string;
  userFilter?: string;
  hostFilter?: string;
  ipFilter?: string;
  mitreFilter?: string;
  onXp?: (xp: number) => void;
  /** Phase-1 telemetry (ANALYST_TELEMETRY_PLAN.md) — fired once per row the
   * first time it's expanded, so the caller can count investigation thoroughness. */
  onRowOpened?: () => void;
}

export function EventFeed({
  events, newIds = new Set(),
  severityFilter, sourceFilter, search,
  userFilter = "all", hostFilter = "all", ipFilter = "all", mitreFilter = "all",
  onXp, onRowOpened,
}: EventFeedProps) {
  const [timeFilter, setTimeFilter] = useState<TimeFilter>("all");
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null);

  // Memoize the filter pass: it scans up to 100 events with 6 predicates and,
  // combined with each EventRow's framer-motion `layout` animation, previously
  // re-ran and re-laid-out the whole table on any parent state change.
  const filtered = useMemo(() => {
    const opt = TIME_OPTIONS.find(o => o.value === timeFilter);
    const cutoff = opt?.ms ? Date.now() - opt.ms : null;
    return events.filter(ev => {
      if (cutoff !== null && ev.ts && new Date(ev.ts).getTime() < cutoff) return false;
      if (severityFilter !== "all") {
        const lvl = ev.ruleLevel;
        if (severityFilter === "low"    && lvl > 3)            return false;
        if (severityFilter === "medium" && (lvl < 4 || lvl > 6)) return false;
        if (severityFilter === "high"   && lvl < 7)            return false;
      }
      if (sourceFilter !== "all" && ev.source         !== sourceFilter)   return false;
      if (userFilter  !== "all"  && ev.user_email     !== userFilter)     return false;
      if (hostFilter  !== "all"  && ev.hostname       !== hostFilter)     return false;
      if (ipFilter    !== "all"  && ev.src_ip         !== ipFilter)       return false;
      if (mitreFilter !== "all"  && ev.mitre_technique !== mitreFilter)   return false;
      if (search) {
        const q = search.toLowerCase();
        if (
          !ev.displayDescription.toLowerCase().includes(q) &&
          !ev.hostname?.toLowerCase().includes(q) &&
          !ev.user_email?.toLowerCase().includes(q) &&
          !ev.ruleId.toLowerCase().includes(q) &&
          !ev.src_ip?.toLowerCase().includes(q) &&
          !(ev.mitre_technique ?? "").toLowerCase().includes(q)
        ) return false;
      }
      return true;
    });
  }, [events, timeFilter, severityFilter, sourceFilter, userFilter, hostFilter, ipFilter, mitreFilter, search]);

  return (
    <div className="flex flex-col">
      {/* Time-range filter */}
      <div id="ef-filter-row" className="flex items-center gap-2 border-b border-border/40 bg-bg-elevated/60 px-4 py-2">
        <Clock className="h-3 w-3 shrink-0 text-slate-500" />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mr-1">Time range</span>
        <div className="flex items-center gap-1">
          {TIME_OPTIONS.map(opt => (
            <button key={opt.value} onClick={() => setTimeFilter(opt.value)}
              className={cn(
                "rounded px-2.5 py-0.5 text-[10px] font-semibold transition",
                timeFilter === opt.value
                  ? "bg-cyber-500/20 text-cyber-300 border border-cyber-500/40"
                  : "text-slate-500 hover:text-slate-300 border border-transparent hover:border-border/60"
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <span className="ml-auto font-mono text-[10px] text-slate-600">{filtered.length} events</span>
      </div>

      <SocMethodologyBanner />

      <div id="ef-event-table" className="max-h-[530px] overflow-y-auto overflow-x-auto">
        <table className="w-full min-w-[720px] text-xs">
          <thead className="sticky top-0 bg-bg-elevated/95 backdrop-blur">
            <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              <th className="w-6 pl-3 py-2" />
              <th id="ef-th-time"    className="py-2 pr-3"><HeaderTip label="Time"       tip="When the event occurred. Unusual hours (3 AM logins, weekend data transfers) are red flags worth investigating." /></th>
              <th id="ef-th-agent"   className="py-2 pr-3"><HeaderTip label="Agent Name" tip="The hostname of the computer or device where this event was recorded." /></th>
              <th id="ef-th-source"  className="py-2 pr-3"><HeaderTip label="Source"     tip="Which security tool detected this event. Each tool sees different activity — EDR sees processes, Firewall sees network traffic, AD sees logins. Hover over the badge for details." /></th>
              <th id="ef-th-desc"    className="py-2 pr-3"><HeaderTip label="Description" tip="A plain-language summary of what happened, generated from the raw log fields. Click the row to see all raw fields and a guided analysis." /></th>
              <th id="ef-th-level"   className="py-2 pr-3"><HeaderTip label="Level"      tip="Severity score 1-10. Levels 1-3: routine activity. Levels 4-6: investigate further. Levels 7-10: likely threat — take action." /></th>
              <th id="ef-th-ruleid"  className="py-2 pr-4"><HeaderTip label="Rule ID"    tip="The detection rule that fired on this event. When a known attack technique is detected, the rule maps to MITRE ATT&CK. Click the purple badge to learn about the technique." /></th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {filtered.map(ev => (
                <EventRow
                  key={ev.id}
                  event={ev}
                  isNew={newIds.has(ev.id)}
                  onThreatQuery={setThreatQuery}
                  onXp={onXp}
                  onRowOpened={onRowOpened}
                />
              ))}
            </AnimatePresence>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-xs text-slate-500">
                  No events match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Threat Intel Drawer */}
      <AnimatePresence>
        {threatQuery && (
          <ThreatIntelDrawer key="threat-drawer" query={threatQuery} onClose={() => setThreatQuery(null)} />
        )}
      </AnimatePresence>

      {/* Dashboard orientation tour — fires once for new users */}
      <DashboardTour />
    </div>
  );
}
