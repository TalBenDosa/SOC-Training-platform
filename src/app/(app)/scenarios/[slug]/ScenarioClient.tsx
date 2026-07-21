"use client";
import { useState, useEffect, useCallback, useMemo } from "react";
import { AnimatePresence } from "framer-motion";
import { Play, Send, ChevronRight, Search, Info, Target, Plus, X, ShieldAlert, ShieldCheck, FileText, Trophy, CheckCircle2, Shield } from "lucide-react";
import Link from "next/link";
import { cn, formatTs } from "@/lib/utils";
import { addTotalXp } from "@/lib/storage/progress";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { CompletionModal, type GradeResult } from "@/components/scenarios/CompletionModal";
import type { ScenarioBundle, TelemetryEvent, IOC } from "@/lib/sim/types";
import {
  ThreatIntelDrawer, isSha256Field, isIpCheckField, isDomainCheckField,
  type ThreatQuery,
} from "@/components/threat-intel/ThreatIntelDrawer";
import { shuffleSeeded } from "@/lib/lessons/shuffle";

// ─── Helpers ──────────────────────────────────────────────────────────────────

type Phase = "idle" | "investigating" | "submitted" | "complete";

function formatTime(s: number) {
  const m = Math.floor(s / 60).toString().padStart(2, "0");
  const sec = (s % 60).toString().padStart(2, "0");
  return `${m}:${sec}`;
}

// ─── Source / severity maps ───────────────────────────────────────────────────

const SOURCE_LABEL: Record<string, string> = {
  edr: "EDR", sysmon: "Sysmon", ad: "Active Directory",
  o365: "Office 365", okta: "Okta", firewall: "Firewall",
  dns: "DNS", vpn: "VPN", cloudtrail: "Azure/AWS", proxy: "Proxy",
  dlp: "DLP", k8s_audit: "K8s",
};

const SOURCE_COLORS: Record<string, string> = {
  edr:        "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  sysmon:     "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  ad:         "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  o365:       "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  okta:       "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  firewall:   "bg-severity-high/20 text-severity-high border-severity-high/30",
  dns:        "bg-neon-green/20 text-neon-green border-neon-green/30",
  vpn:        "bg-slate-400/20 text-slate-300 border-slate-400/30",
  cloudtrail: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  proxy:      "bg-slate-400/20 text-slate-300 border-slate-400/30",
  dlp:        "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
};

const SEV_LEVEL: Record<string, number> = {
  critical: 10, high: 8, medium: 5, low: 3, informational: 1,
};

const SEV_BADGE: Record<string, string> = {
  critical:      "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  high:          "bg-severity-high/15 text-severity-high border-severity-high/40",
  medium:        "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  low:           "bg-slate-500/15 text-slate-400 border-slate-500/30",
  informational: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

// ─── Log row detail panel ─────────────────────────────────────────────────────

function LogDetail({ ev, onThreatQuery }: { ev: TelemetryEvent; onThreatQuery: (q: ThreatQuery) => void }) {
  const [showJson, setShowJson] = useState(false);

  // "Rule Description" used to render `Detection: ${ev.mitre_technique}` — so
  // an event detail panel displayed "Detection: T1078" to a student who was, in
  // several scenarios, about to be asked which technique this was. It was the
  // same ATT&CK leak already stripped from 172 raw log blocks, surviving in the
  // view layer.
  //
  // It was also not what a SIEM shows. A detail pane names the ANALYTIC that
  // fired, not a framework id. We do not carry a rule name on the event, so
  // rather than invent one this shows what the vendor itself recorded — the
  // event action from the raw block — and falls back to the event type.
  const vendorAction = String(
    ev.raw?.["event.action"] ?? ev.raw?.["ActionType"] ?? ev.raw?.["event.dataset"] ?? "",
  );
  const basicInfo: [string, string][] = [
    ["Event Action",     vendorAction || ev.event_type.replace(/_/g, " ")],
    ["Source Type",      SOURCE_LABEL[ev.source] ?? ev.source.toUpperCase()],
    ["Timestamp",        new Date(ev.ts).toLocaleString("en-GB")],
    ["Severity",         (ev.severity ?? "informational").toUpperCase()],
    ["Username",         ev.user_email ?? "—"],
    ["Hostname",         ev.hostname ?? "—"],
    ["IP Address",       ev.src_ip ?? ev.dst_ip ?? "—"],
  ];

  // ECS fields from structured event properties
  const ecsCore: [string, string][] = [
    ["event.id",       ev.id],
    ["event.provider", ev.vendor ?? ev.source.toUpperCase()],
    ["event.type",     ev.event_type.replace(/_/g, " ")],
    ["event.severity", (ev.severity ?? "informational").toUpperCase()],
    ...(ev.mitre_technique ? [["threat.technique.id", ev.mitre_technique]  as [string, string]] : []),
    ...(ev.user_email ? [["user.email",    ev.user_email]           as [string, string]] : []),
    ...(ev.hostname   ? [["host.name",     ev.hostname]             as [string, string]] : []),
    ...(ev.src_ip   ? [["source.ip",       ev.src_ip]               as [string, string]] : []),
    ...(ev.src_port ? [["source.port",     String(ev.src_port)]     as [string, string]] : []),
    ...(ev.dst_ip   ? [["destination.ip",  ev.dst_ip]               as [string, string]] : []),
    ...(ev.dst_port ? [["destination.port",String(ev.dst_port)]     as [string, string]] : []),
    ...(ev.protocol ? [["network.protocol",ev.protocol]             as [string, string]] : []),
    ...(ev.network?.url    ? [["url.full",            ev.network.url]    as [string, string]] : []),
    ...(ev.network?.domain ? [["dns.question.name",   ev.network.domain] as [string, string]] : []),
    ...(ev.network?.method ? [["http.request.method", ev.network.method] as [string, string]] : []),
    ...(ev.network?.bytes_out ? [["network.bytes_out",`${ev.network.bytes_out} B`] as [string, string]] : []),
    ...(ev.network?.bytes_in  ? [["network.bytes_in", `${ev.network.bytes_in} B`]  as [string, string]] : []),
    ...(ev.process?.name        ? [["process.name",         ev.process.name]              as [string, string]] : []),
    ...(ev.process?.pid         ? [["process.pid",          String(ev.process.pid)]       as [string, string]] : []),
    ...(ev.process?.cmdline     ? [["process.command_line", ev.process.cmdline]           as [string, string]] : []),
    ...(ev.process?.parent_name ? [["process.parent.name",  ev.process.parent_name]       as [string, string]] : []),
    ...(ev.process?.parent_pid  ? [["process.parent.pid",   String(ev.process.parent_pid)]as [string, string]] : []),
    ...(ev.process?.user        ? [["user.name",            ev.process.user]              as [string, string]] : []),
    ...(ev.process?.integrity   ? [["process.integrity",    ev.process.integrity]         as [string, string]] : []),
    ...(ev.file?.path   ? [["file.path",        ev.file.path]          as [string, string]] : []),
    ...(ev.file?.sha256 ? [["file.hash.sha256", ev.file.sha256]        as [string, string]] : []),
    ...(ev.file?.size   ? [["file.size",        `${ev.file.size} B`]   as [string, string]] : []),
  ];
  const rawFields: [string, string][] = Object.entries(ev.raw ?? {})
    .filter(([, v]) => v !== null && v !== undefined && v !== "" && typeof v !== "object" && typeof v !== "boolean")
    .map(([k, v]) => [k, String(v)] as [string, string]);
  const rawBool: [string, string][] = Object.entries(ev.raw ?? {})
    .filter(([, v]) => typeof v === "boolean")
    .map(([k, v]) => [k, v ? "true" : "false"] as [string, string]);
  const detailedFields: [string, string][] = [...ecsCore, ...rawFields, ...rawBool];

  return (
    <td colSpan={6} className="bg-[#080d14] p-0">
      <div className="border-t border-border/40 px-5 py-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-semibold text-white">Log Analysis</span>
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-400 select-none">
            Raw JSON
            <button
              role="switch"
              aria-checked={showJson}
              onClick={() => setShowJson(v => !v)}
              className={cn(
                "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                showJson ? "bg-cyber-500" : "bg-slate-600/60"
              )}
            >
              <span className={cn(
                "inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform",
                showJson ? "translate-x-4" : "translate-x-1"
              )} />
            </button>
          </label>
        </div>

        {showJson ? (
          <pre className="max-h-72 overflow-auto rounded border border-border bg-[#0a0f18] p-3 font-mono text-[10px] leading-relaxed text-slate-300">
            {JSON.stringify(ev, null, 2)}
          </pre>
        ) : (
          <>
            {ev.description && (
              <div className="rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-cyber-300/70">Event Description</p>
                <p className="text-xs leading-relaxed text-slate-200">{ev.description}</p>
              </div>
            )}
            <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Basic Information</p>
              <div className="space-y-2">
                {basicInfo.map(([label, value]) => (
                  <div key={label} className="flex gap-3">
                    <span className="w-36 shrink-0 text-[11px] text-slate-500">{label}</span>
                    <span className="font-mono text-[11px] text-slate-200 break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Detailed Log Data</p>
              <div className="space-y-1.5">
                {detailedFields.map(([k, v]) => {
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

                        {showHash && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "hash", value: v, event: ev }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-amber/50 bg-neon-amber/10 px-2 py-0.5 text-[9px] font-bold text-neon-amber hover:bg-neon-amber/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check Hash · Threat Intel
                          </button>
                        )}
                        {showIp && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "ip", value: v, event: ev }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-blue/50 bg-neon-blue/10 px-2 py-0.5 text-[9px] font-bold text-neon-blue hover:bg-neon-blue/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check IP · Threat Intel
                          </button>
                        )}
                        {showDomain && (
                          <button
                            onClick={e => { e.stopPropagation(); onThreatQuery({ type: "domain", value: v, event: ev }); }}
                            className="inline-flex w-fit items-center gap-1 rounded border border-neon-purple/50 bg-neon-purple/10 px-2 py-0.5 text-[9px] font-bold text-neon-purple hover:bg-neon-purple/20 transition"
                          >
                            <Shield className="h-2.5 w-2.5" /> Check Domain · Threat Intel
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    </td>
  );
}

// ─── Single log row ───────────────────────────────────────────────────────────

function LogRow({ ev, onThreatQuery }: { ev: TelemetryEvent; onThreatQuery: (q: ThreatQuery) => void }) {
  const [expanded, setExpanded] = useState(false);
  const level = SEV_LEVEL[ev.severity ?? "informational"] ?? 1;
  const sevBadge = SEV_BADGE[ev.severity ?? "informational"];
  const srcLabel = SOURCE_LABEL[ev.source] ?? ev.source.toUpperCase();
  const srcColor = SOURCE_COLORS[ev.source] ?? SOURCE_COLORS.proxy;
  const timeStr = new Date(ev.ts).toLocaleTimeString("en-GB", { hour12: false });

  const description = ev.description ??
    (ev.process ? `${ev.process.name}${ev.process.parent_name ? ` ← ${ev.process.parent_name}` : ""}` :
    ev.network?.domain ? ev.network.domain :
    ev.network?.url ? ev.network.url :
    ev.file?.path ? ev.file.path :
    ev.event_type);

  return (
    <>
      <tr
        onClick={() => setExpanded(v => !v)}
        className={cn(
          "cursor-pointer border-t border-border/60 transition-colors",
          expanded ? "bg-bg-hover" : "hover:bg-bg-hover/60",
          ev.severity === "critical" && "border-l-2 border-l-severity-critical",
          ev.severity === "high"     && "border-l-2 border-l-severity-high",
        )}
      >
        <td className="w-5 pl-3">
          <ChevronRight className={cn("h-3 w-3 text-slate-500 transition-transform", expanded && "rotate-90")} />
        </td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400">{timeStr}</td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-200 max-w-[120px]">
          <span className="truncate block">{ev.hostname ?? "—"}</span>
        </td>
        <td className="py-2.5 pr-3">
          <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider", srcColor)}>
            {srcLabel}
          </span>
        </td>
        <td className="py-2.5 pr-3">
          <span className="block text-[11px] text-slate-300 leading-relaxed line-clamp-2">{description}</span>
          {ev.mitre_technique && (
            <span className="mt-0.5 font-mono text-[9px] text-neon-purple/70">{ev.mitre_technique}</span>
          )}
        </td>
        <td className="py-2.5 pr-4">
          <span className={cn("inline-flex h-5 w-5 items-center justify-center rounded border font-mono text-[10px] font-bold", sevBadge)}>
            {level}
          </span>
        </td>
      </tr>
      {expanded && (
        <tr>
          <LogDetail ev={ev} onThreatQuery={onThreatQuery} />
        </tr>
      )}
    </>
  );
}

// ─── Log viewer ───────────────────────────────────────────────────────────────

function ScenarioLogViewer({ events }: { events: TelemetryEvent[] }) {
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null);
  const [search, setSearch]       = useState("");
  const [sevFilter, setSevFilter] = useState<"all" | "medium" | "high">("all");
  const [showAll, setShowAll]     = useState(false);

  const filtered = useMemo(() => {
    // Sort by timestamp before filtering. Scenario builders declare events in
    // narrative order, which is not always chronological — a lateral-movement
    // event can be listed before the credential dump that enabled it while
    // carrying a later `ts`. A log viewer that renders array order therefore
    // showed the student an out-of-order kill chain and broke timeline
    // reasoning. Sorting a COPY here fixes every scenario at once and leaves
    // the source arrays (used by the attack-chain reconstruction) untouched.
    return [...events]
      .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())
      .filter(ev => {
      if (sevFilter === "high"   && ev.severity !== "high" && ev.severity !== "critical") return false;
      if (sevFilter === "medium" && (!ev.severity || SEV_LEVEL[ev.severity] < 4)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          (ev.hostname ?? "").toLowerCase().includes(q) ||
          (ev.user_email ?? "").toLowerCase().includes(q) ||
          (ev.mitre_technique ?? "").toLowerCase().includes(q) ||
          (ev.event_type ?? "").toLowerCase().includes(q) ||
          (ev.description ?? "").toLowerCase().includes(q) ||
          (ev.process?.name ?? "").toLowerCase().includes(q) ||
          (ev.network?.domain ?? "").toLowerCase().includes(q) ||
          (ev.file?.path ?? "").toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, sevFilter, search]);

  const visible = showAll ? filtered : filtered.slice(0, 30);

  return (
    <>
    <Card className="p-0 overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Security Events</h3>
        <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-slate-400">
          {filtered.length} events
        </span>
        <div className="ml-auto flex items-center gap-2">
          <div className="flex gap-1">
            {(["all", "medium", "high"] as const).map(f => (
              <button
                key={f}
                onClick={() => setSevFilter(f)}
                className={cn(
                  "rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition",
                  sevFilter === f
                    ? "bg-cyber-500/20 text-cyber-300 border border-cyber-500/30"
                    : "text-slate-500 hover:text-slate-300"
                )}
              >
                {f === "all" ? "All" : f === "medium" ? "≥ Medium" : "High/Critical"}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search events…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="rounded border border-border bg-bg-elevated pl-6 pr-3 py-1 text-[11px] text-slate-200 placeholder-slate-500 focus:border-cyber-500/40 focus:outline-none w-44"
            />
          </div>
        </div>
      </div>

      <div className="max-h-[520px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-bg-elevated/95 backdrop-blur">
            <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              <th className="w-5 pl-3 py-2" />
              <th className="py-2 pr-3">Time</th>
              <th className="py-2 pr-3">Agent</th>
              <th className="py-2 pr-3">Source</th>
              <th className="py-2 pr-3">Description</th>
              <th className="py-2 pr-4">Lvl</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(ev => (
              <LogRow key={ev.id} ev={ev} onThreatQuery={setThreatQuery} />
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-xs text-slate-500">No events match the filter.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {!showAll && filtered.length > 30 && (
        <div className="border-t border-border px-4 py-2.5 text-center">
          <button onClick={() => setShowAll(true)} className="text-xs text-cyber-300 hover:text-cyber-200 transition">
            Show all {filtered.length} events ↓
          </button>
        </div>
      )}
    </Card>

    <AnimatePresence>
      {threatQuery && (
        <ThreatIntelDrawer key="threat-drawer" query={threatQuery} onClose={() => setThreatQuery(null)} />
      )}
    </AnimatePresence>
    </>
  );
}

// ─── Investigation Panel ──────────────────────────────────────────────────────

const IOC_TYPES = ["ip", "domain", "url", "sha256", "email", "user", "host", "other"] as const;
type IocType = typeof IOC_TYPES[number];

interface ManualIoc {
  id: string;
  type: IocType;
  value: string;
}

const IOC_COLORS: Record<IocType, string> = {
  ip:     "text-neon-blue border-neon-blue/30 bg-neon-blue/10",
  domain: "text-neon-purple border-neon-purple/30 bg-neon-purple/10",
  url:    "text-neon-amber border-neon-amber/30 bg-neon-amber/10",
  sha256: "text-severity-high border-severity-high/30 bg-severity-high/10",
  email:  "text-cyber-300 border-cyber-500/30 bg-cyber-500/10",
  user:   "text-slate-300 border-slate-500/30 bg-slate-500/10",
  host:   "text-neon-green border-neon-green/30 bg-neon-green/10",
  other:  "text-slate-400 border-slate-500/30 bg-slate-500/10",
};

type ReportTab = "narrative" | "findings" | "iocs" | "verdict";

const REPORT_TABS: { id: ReportTab; label: string }[] = [
  { id: "narrative", label: "Narrative" },
  { id: "findings",  label: "Findings"  },
  { id: "iocs",      label: "IOCs"      },
  { id: "verdict",   label: "Verdict"   },
];

function InvestigationPanel({
  phase,
  notes,
  onNotesChange,
  findings,
  onFindingsChange,
  iocs,
  onAddIoc,
  onRemoveIoc,
  verdict,
  onVerdictChange,
  verdictReason,
  onVerdictReasonChange,
  onSubmit,
  quizComplete,
}: {
  phase: Phase;
  notes: string;
  onNotesChange: (v: string) => void;
  findings: string;
  onFindingsChange: (v: string) => void;
  iocs: ManualIoc[];
  onAddIoc: (ioc: ManualIoc) => void;
  onRemoveIoc: (id: string) => void;
  verdict: "tp" | "fp" | null;
  onVerdictChange: (v: "tp" | "fp") => void;
  verdictReason: string;
  onVerdictReasonChange: (v: string) => void;
  onSubmit: () => void;
  quizComplete: boolean;
}) {
  const [activeTab, setActiveTab] = useState<ReportTab>("narrative");
  const [newType, setNewType] = useState<IocType>("ip");
  const [newValue, setNewValue] = useState("");

  const addIoc = () => {
    const v = newValue.trim();
    if (!v) return;
    onAddIoc({ id: crypto.randomUUID(), type: newType, value: v });
    setNewValue("");
  };

  const disabled = phase === "idle";
  const inputCls = cn(
    "w-full rounded border border-border/60 bg-[#060b12] px-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:border-[#2dd4bf]/40 focus:outline-none",
    disabled && "opacity-40 cursor-not-allowed"
  );

  // Section completion: has meaningful content
  const sectionDone: Record<ReportTab, boolean> = {
    narrative: notes.trim().length > 10,
    findings:  findings.trim().length > 10,
    iocs:      iocs.length > 0,
    verdict:   verdict !== null,
  };
  const completedCount = Object.values(sectionDone).filter(Boolean).length;
  const canFinalize    = completedCount >= 3 && quizComplete;

  return (
    <div className="rounded-lg border border-border/60 bg-[#0d1520] overflow-hidden">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="border-b border-border/60 px-5 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-[#2dd4bf]/30 bg-[#2dd4bf]/10">
            <FileText className="h-3.5 w-3.5 text-[#2dd4bf]" />
          </div>
          <h3 className="text-sm font-bold text-white">Investigation Report</h3>
        </div>
        <span className="text-[10px] font-mono text-slate-500">
          {completedCount}<span className="text-slate-700">/4</span>
        </span>
      </div>

      {/* ── Tab bar ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 border-b border-border/60">
        {REPORT_TABS.map(tab => {
          const active = activeTab === tab.id;
          const done   = sectionDone[tab.id];
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "relative py-2.5 text-[11px] font-medium transition-colors",
                active
                  ? "bg-[#2dd4bf] text-[#0d1520] font-semibold"
                  : "text-slate-500 hover:text-slate-200 hover:bg-white/5"
              )}
            >
              {tab.label}
              {done && !active && (
                <span className="absolute right-2 top-1.5 h-1.5 w-1.5 rounded-full bg-[#2dd4bf]" />
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab content ───────────────────────────────────────────────── */}
      <div className="px-5 py-5">

        {/* NARRATIVE */}
        {activeTab === "narrative" && (
          <div>
            <p className="mb-0.5 text-sm font-semibold text-white">Narrative</p>
            <p className="mb-3 text-[11px] text-slate-500">Document your investigation process step by step</p>
            <textarea
              rows={10}
              disabled={disabled}
              value={notes}
              onChange={e => onNotesChange(e.target.value)}
              className={inputCls + " resize-none"}
              placeholder={
                disabled
                  ? "Start the investigation to begin writing..."
                  : "Describe the attack timeline, methods, and what you observed in the logs..."
              }
            />
          </div>
        )}

        {/* FINDINGS */}
        {activeTab === "findings" && (
          <div>
            <p className="mb-0.5 text-sm font-semibold text-white">Key Findings</p>
            <p className="mb-3 text-[11px] text-slate-500">MITRE techniques observed and specific evidence</p>
            <textarea
              rows={10}
              disabled={disabled}
              value={findings}
              onChange={e => onFindingsChange(e.target.value)}
              className={inputCls + " resize-none"}
              placeholder={
                disabled
                  ? "Start the investigation to begin writing..."
                  : "e.g. T1059.001 — PowerShell spawned from WINWORD.EXE (macro execution)\nT1071.001 — C2 beacon to 185.220.101.x:443 every 60s\nT1003.001 — LSASS memory read via rundll32.exe..."
              }
            />
          </div>
        )}

        {/* IOCs */}
        {activeTab === "iocs" && (
          <div>
            <p className="mb-0.5 text-sm font-semibold text-white">Indicators of Compromise</p>
            <p className="mb-4 text-[11px] text-slate-400">
              Tag indicators you discovered while analysing the logs
              {iocs.length > 0 && (
                <span className="ml-2 rounded bg-[#2dd4bf]/10 px-1.5 py-0.5 font-mono text-[9px] text-[#2dd4bf]">
                  {iocs.length} added
                </span>
              )}
            </p>

            {/* Add row */}
            <div className="flex gap-2 mb-4">
              <select
                disabled={disabled}
                value={newType}
                onChange={e => setNewType(e.target.value as IocType)}
                className="rounded border border-border/60 bg-[#060b12] px-2 py-1.5 text-[11px] text-slate-300 focus:border-[#2dd4bf]/40 focus:outline-none disabled:opacity-40"
              >
                {IOC_TYPES.map(t => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
              <input
                disabled={disabled}
                type="text"
                value={newValue}
                onChange={e => setNewValue(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addIoc(); } }}
                placeholder="Indicator value (IP, domain, hash…)"
                className="flex-1 rounded border border-border/60 bg-[#060b12] px-3 py-1.5 text-[11px] text-slate-200 placeholder-slate-600 focus:border-[#2dd4bf]/40 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed"
              />
              <button
                disabled={disabled || !newValue.trim()}
                onClick={addIoc}
                className="flex items-center gap-1 rounded border border-[#2dd4bf]/30 bg-[#2dd4bf]/10 px-3 py-1.5 text-[11px] font-semibold text-[#2dd4bf] hover:bg-[#2dd4bf]/20 transition disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>

            {iocs.length > 0 ? (
              <ul className="space-y-1.5">
                {iocs.map(ioc => (
                  <li key={ioc.id} className="flex items-center gap-2 rounded border border-border/60 bg-[#060b12] px-3 py-2">
                    <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase shrink-0", IOC_COLORS[ioc.type])}>
                      {ioc.type}
                    </span>
                    <span className="flex-1 truncate font-mono text-[11px] text-slate-200">{ioc.value}</span>
                    <button
                      onClick={() => onRemoveIoc(ioc.id)}
                      className="shrink-0 rounded p-0.5 text-slate-500 hover:text-severity-high hover:bg-severity-high/10 transition"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="rounded border border-dashed border-border/60 py-6 text-center text-[11px] text-slate-600">
                No indicators added yet — analyse the logs above and add what you find.
              </div>
            )}
          </div>
        )}

        {/* VERDICT */}
        {activeTab === "verdict" && (
          <div>
            <p className="mb-0.5 text-sm font-semibold text-white">Final Verdict</p>
            <p className="mb-4 text-[11px] text-slate-400">Based on your investigation, classify this alert</p>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <button
                disabled={disabled}
                onClick={() => onVerdictChange("tp")}
                className={cn(
                  "flex flex-col items-center gap-2 rounded border px-4 py-4 transition",
                  verdict === "tp"
                    ? "border-severity-critical/50 bg-severity-critical/10"
                    : "border-border/60 bg-[#060b12] hover:border-severity-critical/30 hover:bg-severity-critical/5",
                  disabled && "opacity-40 cursor-not-allowed"
                )}
              >
                <ShieldAlert className={cn("h-6 w-6", verdict === "tp" ? "text-severity-critical" : "text-slate-400")} />
                <div className="text-center">
                  <p className={cn("text-sm font-bold", verdict === "tp" ? "text-severity-critical" : "text-slate-300")}>
                    True Positive
                  </p>
                  <p className="text-[10px] text-slate-500 mt-0.5">Confirmed malicious activity</p>
                </div>
                {verdict === "tp" && (
                  <span className="rounded bg-severity-critical/20 px-2 py-0.5 text-[10px] font-bold text-severity-critical">SELECTED</span>
                )}
              </button>

              <button
                disabled={disabled}
                onClick={() => onVerdictChange("fp")}
                className={cn(
                  "flex flex-col items-center gap-2 rounded border px-4 py-4 transition",
                  verdict === "fp"
                    ? "border-neon-green/50 bg-neon-green/10"
                    : "border-border/60 bg-[#060b12] hover:border-neon-green/30 hover:bg-neon-green/5",
                  disabled && "opacity-40 cursor-not-allowed"
                )}
              >
                <ShieldCheck className={cn("h-6 w-6", verdict === "fp" ? "text-neon-green" : "text-slate-400")} />
                <div className="text-center">
                  <p className={cn("text-sm font-bold", verdict === "fp" ? "text-neon-green" : "text-slate-300")}>
                    False Positive
                  </p>
                  <p className="text-[10px] text-slate-500 mt-0.5">Legitimate / benign activity</p>
                </div>
                {verdict === "fp" && (
                  <span className="rounded bg-neon-green/20 px-2 py-0.5 text-[10px] font-bold text-neon-green">SELECTED</span>
                )}
              </button>
            </div>

            {verdict && (
              <div>
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Reasoning
                </p>
                <textarea
                  rows={3}
                  disabled={disabled}
                  value={verdictReason}
                  onChange={e => onVerdictReasonChange(e.target.value)}
                  className={inputCls + " resize-none"}
                  placeholder="Explain why this is a TP or FP based on the evidence you found..."
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Footer ────────────────────────────────────────────────────── */}
      <div className="border-t border-border/60 bg-[#080e18] px-5 py-4">
        <button
          disabled={!canFinalize || phase !== "investigating"}
          onClick={onSubmit}
          className={cn(
            "w-full flex items-center justify-center gap-2 rounded py-2.5 text-sm font-semibold transition-colors",
            canFinalize && phase === "investigating"
              ? "bg-[#2dd4bf]/10 border border-[#2dd4bf]/40 text-[#2dd4bf] hover:bg-[#2dd4bf]/20"
              : "bg-white/5 border border-border/40 text-slate-500 cursor-not-allowed"
          )}
        >
          <Trophy className={cn("h-4 w-4", canFinalize ? "text-neon-amber" : "text-slate-600")} />
          Finalize &amp; Evaluate Investigation
        </button>

        {(!canFinalize || !quizComplete) && phase === "investigating" && (
          <p className="mt-2 text-center text-[10px] text-slate-600">
            {!quizComplete && "Answer all quiz questions · "}
            {completedCount < 3 && `Complete ${3 - completedCount} more section${3 - completedCount !== 1 ? "s" : ""}`}
          </p>
        )}
      </div>

    </div>
  );
}

// ─── Interactive IOC Tracker ──────────────────────────────────────────────────

const IOC_TYPE_COLORS: Record<string, string> = {
  ip:     "border-neon-blue/40 bg-neon-blue/10 text-neon-blue",
  domain: "border-neon-purple/40 bg-neon-purple/10 text-neon-purple",
  url:    "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  sha256: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  md5:    "border-severity-high/40 bg-severity-high/10 text-severity-high",
  email:  "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
  user:   "border-slate-400/40 bg-slate-400/10 text-slate-300",
  host:   "border-neon-green/40 bg-neon-green/10 text-neon-green",
};


// ─── Main client component ────────────────────────────────────────────────────

export function ScenarioClient({ bundle, slug }: { bundle: ScenarioBundle; slug: string }) {
  const [phase, setPhase]               = useState<Phase>("idle");
  const [elapsed, setElapsed]           = useState(0);
  const [answers, setAnswers]           = useState<Record<string, string | string[]>>({});
  const [gradeResult, setGradeResult]   = useState<GradeResult | null>(null);
  const [isGrading, setIsGrading]       = useState(false);
  const [gradingError, setGradingError] = useState<string | null>(null);

  // IOC tracker — which bundle IOCs have been tagged as evidence

  // Investigation log state
  const [notes, setNotes]                   = useState("");
  const [findings, setFindings]             = useState("");
  const [manualIocs, setManualIocs]         = useState<ManualIoc[]>([]);
  const [verdict, setVerdict]               = useState<"tp" | "fp" | null>(null);
  const [verdictReason, setVerdictReason]   = useState("");

  // Timer
  useEffect(() => {
    if (phase !== "investigating") return;
    const id = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(id);
  }, [phase]);

  const handleStart = () => {
    setElapsed(0);
    setAnswers({});
    setManualIocs([]);
    setNotes("");
    setFindings("");
    setVerdict(null);
    setVerdictReason("");
    setGradeResult(null);
    setGradingError(null);
    setPhase("investigating");
  };

  const handleRetry = () => {
    setPhase("idle");
    setGradeResult(null);
    setElapsed(0);
    setAnswers({});
    setManualIocs([]);
    setNotes("");
    setFindings("");
    setVerdict(null);
    setVerdictReason("");
  };

  const handleAnswer = useCallback((questionId: string, value: string, multi: boolean) => {
    if (phase !== "investigating") return;
    setAnswers(prev => {
      if (multi) {
        const existing = (prev[questionId] as string[] | undefined) ?? [];
        const next = existing.includes(value)
          ? existing.filter(v => v !== value)
          : [...existing, value];
        return { ...prev, [questionId]: next };
      }
      return { ...prev, [questionId]: value };
    });
  }, [phase]);

  const handleAddIoc = useCallback((ioc: ManualIoc) => {
    setManualIocs(prev => [...prev, ioc]);
  }, []);

  const handleRemoveIoc = useCallback((id: string) => {
    setManualIocs(prev => prev.filter(i => i.id !== id));
  }, []);

  const allAnswered = bundle.questions.every(q => {
    const a = answers[q.id];
    if (!a) return false;
    if (Array.isArray(a)) return a.length > 0;
    return true;
  });

  const canSubmit = allAnswered && verdict !== null && !isGrading;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setPhase("submitted");
    setIsGrading(true);
    setGradingError(null);
    try {
      const res = await fetch(`/api/scenarios/${encodeURIComponent(slug)}/grade`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          answers,
          timeTaken: elapsed,
          iocTagged: manualIocs.length,
          verdict,
          verdictReason,
          analystNotes: notes,
          indicators: manualIocs,
        }),
      });
      if (!res.ok) throw new Error("Grading failed");
      const result: GradeResult = await res.json();
      setGradeResult(result);
      setPhase("complete");

      // Persist to localStorage so the progress page can display history
      try {
        const history = JSON.parse(localStorage.getItem("soc_scenario_history") ?? "[]");
        history.push({
          slug,
          title: bundle.title,
          score:    result.score,
          xpEarned: result.xpEarned + (result.timeBonusXp ?? 0),
          timeTaken: elapsed,
          date: new Date().toISOString(),
        });
        localStorage.setItem("soc_scenario_history", JSON.stringify(history.slice(-50)));
        // Also update cumulative XP — via the storage facade (Phase-1 seam).
        addTotalXp(result.xpEarned + (result.timeBonusXp ?? 0));
      } catch { /* ignore storage errors */ }
    } catch {
      setGradingError("Could not submit. Check your connection and retry.");
      setPhase("investigating");
    } finally {
      setIsGrading(false);
    }
  };

  return (
    <div>
      {/* The subtitle was `Threat actor: ${bundle.threat_actor}`, displayed for
          the whole investigation. Attribution is a conclusion the analyst is
          supposed to reach; printing it up front removed the exercise, and on
          the two false-positive scenarios the field literally read "None —
          authorised backup activity", i.e. the verdict. The field is now blanked
          server-side as well (see page.tsx); the ternary keeps the subtitle
          meaningful if it ever arrives populated. */}
      <Topbar
        title={bundle.title}
        subtitle={bundle.threat_actor ? `Threat actor: ${bundle.threat_actor}` : "Active investigation — attribution to be determined"}
        actions={undefined}
      />

      {/* Timer / Status bar */}
      <div className="border-b border-border bg-[#080d14] px-6 py-3">
        <div className="container mx-auto max-w-[1600px] flex items-center gap-4">
          {phase === "idle" && (
            <button
              onClick={handleStart}
              className="flex items-center gap-2 rounded border border-cyber-500/30 bg-cyber-500/10 px-4 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 transition"
            >
              <Play className="h-4 w-4" /> Start Investigation
            </button>
          )}
          {phase === "investigating" && (
            <>
              <div className="flex items-center gap-3 rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-1.5">
                <span className="h-2 w-2 rounded-full bg-cyber-400 animate-pulse" />
                <span className="font-mono text-lg font-bold text-cyber-300">{formatTime(elapsed)}</span>
                <span className="text-xs text-slate-400">Investigation Time</span>
              </div>
              {/* Progress indicators */}
              <div className="flex items-center gap-3 text-xs text-slate-500">
                <span className={cn("flex items-center gap-1", allAnswered && "text-neon-green")}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", allAnswered ? "bg-neon-green" : "bg-slate-600")} />
                  Quiz {Object.keys(answers).length}/{bundle.questions.length}
                </span>
                <span className={cn("flex items-center gap-1", verdict !== null && "text-neon-amber")}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", verdict !== null ? "bg-neon-amber" : "bg-slate-600")} />
                  Verdict {verdict ? verdict.toUpperCase() : "pending"}
                </span>
              </div>
              <div className="ml-auto flex items-center gap-2">
                {!canSubmit && (
                  <span className="text-[11px] text-slate-500">
                    {!allAnswered ? "Answer all quiz questions" : "Set a TP/FP verdict"} to submit
                  </span>
                )}
                {gradingError && (
                  <span className="text-[11px] text-severity-high">{gradingError}</span>
                )}
                <button
                  onClick={handleSubmit}
                  disabled={!canSubmit}
                  className="flex items-center gap-1.5 rounded border border-neon-green/30 bg-neon-green/10 px-4 py-1.5 text-sm font-semibold text-neon-green hover:bg-neon-green/20 transition disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Send className="h-3.5 w-3.5" />
                  {isGrading ? "Grading…" : "Submit Investigation"}
                </button>
              </div>
            </>
          )}
          {phase === "submitted" && (
            <div className="flex items-center gap-3 text-sm text-slate-400">
              <span className="animate-pulse">Analysing your investigation…</span>
            </div>
          )}
        </div>
      </div>

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* ── Ticket ─────────────────────────────────────────────────────────
            Before submission the analyst sees only what the SOC actually
            received: the triggering alert and the asset. The full narrative
            used to sit here in every phase and it described the intrusion in
            order — in the LockBit scenario four of five questions could be
            answered from that paragraph alone, without opening a log. It is
            now the debrief, shown once the report is in. */}
        <div className="rounded border border-border/60 bg-[#0d1520] px-5 py-4">
          <div className="flex items-center gap-2 mb-3">
            <Badge>{phase === "complete" ? "Debrief" : "Open Ticket"}</Badge>
            <Badge variant="outline">{bundle.alerts.length} alerts</Badge>
            <Badge variant="outline">{bundle.events.length} events</Badge>
          </div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-2">
            {phase === "complete" ? "What actually happened" : "Reported by"}
          </p>
          <p className="text-sm leading-relaxed text-slate-300">
            {phase === "complete"
              ? (gradeResult?.debrief?.narrative || bundle.narrative)
              : (bundle.briefing ?? "An alert fired on a monitored asset and was queued for triage. Work the log evidence below and write up what you find.")}
          </p>
          {phase !== "complete" && (
            <p className="mt-3 border-t border-border/40 pt-3 text-xs text-slate-500">
              Everything else — what happened, in what order, and how far it got — is yours
              to reconstruct from the evidence.
            </p>
          )}
        </div>

        {/* Learning objectives name the techniques the questions ask about
            ("PsExec lateral movement via SMB pass-the-hash" answers the lateral
            movement question outright), so they belong in the debrief too. */}
        {phase === "complete" && (
        <div className="rounded border border-neon-purple/20 bg-neon-purple/5 px-5 py-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="rounded border border-neon-purple/30 bg-neon-purple/10 p-1.5">
              <Target className="h-4 w-4 text-neon-purple" />
            </div>
            <span className="text-sm font-bold text-white">What this scenario taught</span>
          </div>
          <ul className="space-y-2">
            {(gradeResult?.debrief?.learningObjectives ?? bundle.learning_objectives).map((obj: string, i: number) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-neon-purple/70" />
                {obj}
              </li>
            ))}
          </ul>
        </div>
        )}

        {/* Security Events Log */}
        <ScenarioLogViewer events={bundle.events} />

        {/* Investigation Panel */}
        <InvestigationPanel
          phase={phase}
          notes={notes}
          onNotesChange={setNotes}
          findings={findings}
          onFindingsChange={setFindings}
          iocs={manualIocs}
          onAddIoc={handleAddIoc}
          onRemoveIoc={handleRemoveIoc}
          verdict={verdict}
          onVerdictChange={setVerdict}
          verdictReason={verdictReason}
          onVerdictReasonChange={setVerdictReason}
          onSubmit={handleSubmit}
          quizComplete={allAnswered}
        />

        {/* Analyst Quiz */}
        <Card>
          <h3 className="text-sm font-semibold text-white">Analyst Quiz</h3>
          <p className="mt-1 text-xs text-slate-500">
            {phase === "idle"
              ? "Click \"Start Investigation\" above to begin the timed exercise."
              : "Answer all questions then submit your investigation."}
          </p>
          <ol className="mt-4 space-y-5">
            {bundle.questions.map((q, idx) => {
              const isMulti = q.kind === "multi";
              const currentAnswer = answers[q.id];
              const answered = Array.isArray(currentAnswer) ? currentAnswer.length > 0 : !!currentAnswer;

              return (
                <li key={q.id} className={cn(
                  "rounded-md border p-4 transition-colors",
                  answered ? "border-cyber-500/30 bg-cyber-500/5" : "border-border bg-bg"
                )}>
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm text-slate-100">
                      <span className="mr-2 font-mono text-cyber-300">Q{idx + 1}.</span>
                      {q.prompt}
                      {isMulti && <span className="ml-1 text-[10px] text-slate-500">(select all that apply)</span>}
                    </p>
                    <span className="shrink-0 rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 font-mono text-[10px] text-cyber-300">
                      +{q.xp} XP
                    </span>
                  </div>
                  {q.options && (
                    <ul className="mt-3 space-y-1.5">
                      {/* Shuffled for display — see shuffleSeeded's header. Measured
                          across the 89 scenario questions, the correct answer was the
                          FIRST option 56 times (63%), so a student who never read a
                          question and always clicked the top choice scored 63%.
                          Grading compares o.value to q.answer, never position, so
                          reordering is presentation-only. */}
                      {shuffleSeeded(q.options, q.id ?? q.prompt).map(o => {
                        const selected = isMulti
                          ? (currentAnswer as string[] | undefined)?.includes(o.value)
                          : currentAnswer === o.value;
                        return (
                          <li key={o.value}>
                            <label className={cn(
                              "flex cursor-pointer items-center gap-2 rounded border px-2.5 py-1.5 text-xs transition-colors",
                              selected
                                ? "border-cyber-500/40 bg-cyber-500/10 text-white"
                                : "border-border bg-bg-elevated text-slate-200 hover:border-cyber-500/20",
                              phase !== "investigating" && "pointer-events-none opacity-50"
                            )}>
                              <input
                                type={isMulti ? "checkbox" : "radio"}
                                name={q.id}
                                value={o.value}
                                checked={!!selected}
                                onChange={() => handleAnswer(q.id, o.value, isMulti)}
                                className="accent-cyber-400"
                              />
                              <span>{o.label}</span>
                            </label>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {q.hint && (
                    <p className="mt-2 text-[11px] text-slate-500 italic">Hint: {q.hint}</p>
                  )}
                </li>
              );
            })}
          </ol>
        </Card>
      </div>

      {/* Completion Modal */}
      {phase === "complete" && gradeResult && (
        <CompletionModal
          result={gradeResult}
          scenarioTitle={bundle.title}
          timeTaken={elapsed}
          onRetry={handleRetry}
          onClose={() => setPhase("idle")}
        />
      )}
    </div>
  );
}
