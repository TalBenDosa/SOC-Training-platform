"use client";

/**
 * Threat-intel drawer — the "Check Hash / Check IP / Check Domain" surface.
 *
 * Lifted out of the dashboard's EventFeed so the scenario log viewer can offer
 * the identical affordance instead of a second, divergent implementation. The
 * verdict is derived from the event's own raw fields (malware.family,
 * av.verdict, quarantine.status, action_result) plus its severity, so a lookup
 * always agrees with the log the analyst is reading.
 */

import { useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { TelemetryEvent } from "@/lib/sim/types";
// ─── Threat Intel types ────────────────────────────────────────────────────────

export type ThreatQuery =
  | { type: "hash";   value: string; event: TelemetryEvent }
  | { type: "ip";     value: string; event: TelemetryEvent }
  | { type: "domain"; value: string; event: TelemetryEvent };

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

/** First non-empty string value among `keys`, or "" — vendors disagree on field names. */
function pick(raw: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = raw[k];
    if (typeof v === "string" && v.trim() !== "") return v.trim();
  }
  return "";
}

function buildHashIntel(hash: string, event: TelemetryEvent): HashIntelData {
  const raw = event.raw ?? {};
  const malwareFamily = pick(raw, "malware.family", "threat.family");
  const malwareName   = pick(raw, "malware.name", "threat.name", "ThreatName");
  const malwareType   = pick(raw, "malware.type");
  const avVerdict     = pick(raw, "av.verdict");
  const quarantine    = pick(raw, "quarantine.status");
  const actionResult  = pick(raw, "action_result");
  const severity      = event.severity ?? "informational";

  // Vendor-native detection blocks. Real EDR logs do not carry a `malware.family`
  // key — CrowdStrike writes crowdstrike.detection.*, and reading only the
  // normalised names made a quarantined trojan-dropper come back CLEAN while the
  // log next to it said "Known trojan-dropper signature match, file quarantined".
  // A verdict that contradicts the log the analyst is reading teaches the wrong
  // lesson, so these count as detections too.
  const vendorDetection = pick(raw,
    "crowdstrike.detection.description",
    "crowdstrike.detection.scenario",
    "crowdstrike.detection.technique",
  );
  const disposition = pick(raw, "crowdstrike.detection.pattern_disposition_description");

  const isPUP = malwareType === "PUP" || malwareName.toLowerCase().includes("pup");
  const isMalicious = !isPUP && (
    malwareFamily !== "" || malwareName !== "" || vendorDetection !== "" ||
    quarantine === "quarantined" || quarantine === "deleted" ||
    actionResult === "quarantined" || actionResult === "process_killed" ||
    /quarantine|kill process|prevention|block/i.test(disposition) ||
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

function buildIpIntel(ip: string, event: TelemetryEvent): IpIntelData {
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

function buildDomainIntel(domain: string, event: TelemetryEvent): DomainIntelData {
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

export function ThreatIntelDrawer({ query, onClose }: { query: ThreatQuery; onClose: () => void }) {
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

/**
 * Does this field hold a SHA256 the analyst can run a threat-intel check on?
 *
 * The key test used to accept only "file.hash.sha256" / "*.sha256", which
 * silently hid the Check Hash button on most real vendor logs — CrowdStrike
 * writes cs.SHA256HashData, Sysmon writes Hashes, Defender writes SHA256, none
 * of which end in ".sha256". Matching on the vendor's actual field names is
 * what makes the button appear where a student would expect it.
 */
export function isSha256Field(key: string, val: string) {
  if (!/^[a-f0-9]{64}$/i.test(val)) return false;
  const k = key.toLowerCase();
  return (
    k === "file.hash.sha256" ||
    k.endsWith(".sha256") ||
    k.endsWith("sha256hashdata") ||   // CrowdStrike  cs.SHA256HashData
    k.endsWith("sha256") ||           // Defender / MDE  SHA256, process.hash.sha256
    k.endsWith(".hashes") || k === "hashes"   // Sysmon  Hashes
  );
}
export function isIpCheckField(key: string, val: string) {
  return IP_FIELD_KEYS.has(key) && isPublicIp(val);
}
export function isDomainCheckField(key: string, val: string) {
  if (!DOMAIN_FIELD_KEYS.has(key)) return false;
  return val.includes(".") && !val.includes(" ") && !isPublicIp(val) && val.length > 3;
}
