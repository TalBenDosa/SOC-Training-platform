"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  ChevronRight, Info, Clock, Shield, FileText, Target,
  X, CheckCircle, AlertTriangle, Loader2, ArrowLeft,
  Zap, Tag, ExternalLink, Search, AlertCircle, ThumbsDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Topbar } from "@/components/nav/Topbar";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import type { TelemetryEvent } from "@/lib/sim/types";
import { lookupHash, vtLabel, vtColor, MALWARE_HASHES, CLEAN_HASHES } from "@/lib/sim/hashDatabase";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface GeneratedScenario {
  title: string;
  threat_actor: string;
  attack_kind: string;
  difficulty: string;
  narrative: string;
  events: TelemetryEvent[];
}

interface Ioc {
  value: string;
  type: "ip" | "domain" | "hash" | "email" | "file" | "process";
  tagged: boolean;
  isFp: boolean;           // analyst marked as FP
  source: string;
}

type Phase = "investigating" | "complete";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(s: number) {
  const m = Math.floor(s / 60).toString().padStart(2, "0");
  const sec = (s % 60).toString().padStart(2, "0");
  return `${m}:${sec}`;
}

function extractIocs(events: TelemetryEvent[]): Ioc[] {
  const seen = new Set<string>();
  const iocs: Ioc[] = [];
  function add(value: string | null | undefined, type: Ioc["type"], source: string) {
    if (!value || value === "—" || seen.has(value)) return;
    seen.add(value);
    iocs.push({ value, type, tagged: false, isFp: false, source });
  }
  for (const ev of events) {
    add(ev.src_ip,  "ip",      ev.id);
    add(ev.dst_ip,  "ip",      ev.id);
    add(ev.network?.domain, "domain", ev.id);
    add(ev.file?.sha256, "hash", ev.id);
    add(ev.file?.path,   "file", ev.id);
    add(ev.process?.name, "process", ev.id);
    add(ev.user_email,   "email",   ev.id);
    const r = ev.raw ?? {};
    if (typeof r["source.ip"]          === "string") add(r["source.ip"]          as string, "ip",     ev.id);
    if (typeof r["destination.ip"]     === "string") add(r["destination.ip"]     as string, "ip",     ev.id);
    if (typeof r["dns.question.name"]  === "string") add(r["dns.question.name"]  as string, "domain", ev.id);
    if (typeof r["file.hash.sha256"]   === "string") add(r["file.hash.sha256"]   as string, "hash",   ev.id);
  }
  return iocs.filter(i => i.value.length > 3);
}

// Which events are FP (marked in raw)
function isEventFp(ev: TelemetryEvent): boolean {
  return ev.raw?.["fp"] === true || ev.raw?.["fp"] === "true";
}

// Scoring logic
function calcScore(
  events: TelemetryEvent[],
  taggedIocs: Ioc[],
  fpEvents: string[],   // ids of events analyst marked as FP
  timeSec: number,
  notes: string,
  verdict: string,
): { total: number; breakdown: { label: string; pts: number; earned: number }[] } {
  const totalIocs = extractIocs(events).length;
  const realFpEventIds = events.filter(isEventFp).map(e => e.id);
  const correctFpFound = fpEvents.filter(id => realFpEventIds.includes(id)).length;
  const falseFpMarked  = fpEvents.filter(id => !realFpEventIds.includes(id)).length;

  const iocPts      = Math.round((taggedIocs.length / Math.max(totalIocs, 1)) * 40);
  const fpPts       = Math.max(0, correctFpFound * 15 - falseFpMarked * 10);
  const notesPts    = notes.trim().length > 80 ? 15 : notes.trim().length > 20 ? 8 : 0;
  const verdictPts  = verdict.trim().length > 60 ? 20 : verdict.trim().length > 20 ? 10 : 0;
  const timePts     = timeSec < 600 ? 10 : timeSec < 1200 ? 7 : timeSec < 1800 ? 4 : 0;

  return {
    total: Math.min(100, iocPts + fpPts + notesPts + verdictPts + timePts),
    breakdown: [
      { label: "IOC Evidence Tagged",     pts: 40, earned: iocPts },
      { label: "False Positive Detection", pts: 30, earned: Math.min(30, fpPts) },
      { label: "Investigation Notes",     pts: 15, earned: notesPts },
      { label: "Analyst Verdict",         pts: 20, earned: verdictPts },
      { label: "Speed Bonus",             pts: 10, earned: timePts },
    ],
  };
}

// ─── Source / severity maps ───────────────────────────────────────────────────

const SOURCE_LABEL: Record<string, string> = {
  edr: "EDR", sysmon: "Sysmon", ad: "Active Directory",
  o365: "Office 365", okta: "Okta", firewall: "Firewall",
  dns: "DNS", vpn: "VPN", cloudtrail: "AWS/Azure", proxy: "Proxy", dlp: "DLP",
};
const SOURCE_COLORS: Record<string, string> = {
  edr: "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  sysmon: "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  ad: "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  o365: "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  okta: "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  firewall: "bg-severity-high/20 text-severity-high border-severity-high/30",
  dns: "bg-neon-green/20 text-neon-green border-neon-green/30",
  vpn: "bg-slate-400/20 text-slate-300 border-slate-400/30",
  cloudtrail: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  proxy: "bg-slate-400/20 text-slate-300 border-slate-400/30",
  dlp: "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
};
const SEV_BADGE: Record<string, string> = {
  critical:      "border-severity-critical/40 bg-severity-critical/15 text-severity-critical",
  high:          "border-severity-high/40 bg-severity-high/15 text-severity-high",
  medium:        "border-severity-medium/40 bg-severity-medium/15 text-severity-medium",
  low:           "border-slate-500/30 bg-slate-500/15 text-slate-400",
  informational: "border-slate-500/20 bg-slate-500/10 text-slate-500",
};
const IOC_TYPE_BADGE: Record<Ioc["type"], string> = {
  ip:      "bg-neon-blue/10 text-neon-blue border-neon-blue/30",
  domain:  "bg-neon-green/10 text-neon-green border-neon-green/30",
  hash:    "bg-cyber-500/10 text-cyber-300 border-cyber-500/30",
  email:   "bg-neon-purple/10 text-neon-purple border-neon-purple/30",
  file:    "bg-neon-amber/10 text-neon-amber border-neon-amber/30",
  process: "bg-severity-high/10 text-severity-high border-severity-high/30",
};

// ─── Log event row ─────────────────────────────────────────────────────────────

function EventRow({
  ev,
  markedFp,
  onToggleFp,
}: {
  ev: TelemetryEvent;
  markedFp: boolean;
  onToggleFp: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const isFp = isEventFp(ev);
  const timeStr = new Date(ev.ts).toLocaleTimeString("en-GB", { hour12: false });
  const srcColor = SOURCE_COLORS[ev.source] ?? SOURCE_COLORS.proxy;
  const srcLabel = SOURCE_LABEL[ev.source] ?? ev.source.toUpperCase();

  const ecsFields: [string, string][] = [
    ["event.id",       ev.id],
    ["event.provider", ev.vendor ?? ev.source.toUpperCase()],
    ["event.type",     ev.event_type.replace(/_/g, " ")],
    ...(ev.mitre_technique ? [["threat.technique.id", ev.mitre_technique] as [string, string]] : []),
    ...(ev.user_email  ? [["user.email",             ev.user_email]   as [string, string]] : []),
    ...(ev.hostname    ? [["host.name",               ev.hostname]     as [string, string]] : []),
    ...(ev.src_ip      ? [["source.ip",               ev.src_ip]       as [string, string]] : []),
    ...(ev.dst_ip      ? [["destination.ip",          ev.dst_ip]       as [string, string]] : []),
    ...(ev.dst_port    ? [["destination.port",        String(ev.dst_port)] as [string, string]] : []),
    ...(ev.protocol    ? [["network.protocol",        ev.protocol]     as [string, string]] : []),
    ...(ev.network?.url    ? [["url.full",            ev.network.url]  as [string, string]] : []),
    ...(ev.network?.domain ? [["dns.question.name",   ev.network.domain] as [string, string]] : []),
    ...(ev.process?.name        ? [["process.name",         ev.process.name]       as [string, string]] : []),
    ...(ev.process?.pid         ? [["process.pid",          String(ev.process.pid)] as [string, string]] : []),
    ...(ev.process?.cmdline     ? [["process.command_line", ev.process.cmdline]     as [string, string]] : []),
    ...(ev.process?.parent_name ? [["process.parent.name",  ev.process.parent_name] as [string, string]] : []),
    ...(ev.process?.user        ? [["user.name",            ev.process.user]        as [string, string]] : []),
    ...(ev.file?.path   ? [["file.path",        ev.file.path]    as [string, string]] : []),
    ...(ev.file?.sha256 ? [["file.hash.sha256", ev.file.sha256]  as [string, string]] : []),
    ...(ev.file?.size   ? [["file.size",        `${ev.file.size} B`] as [string, string]] : []),
    ...Object.entries(ev.raw ?? {})
      .filter(([k, v]) => k !== "fp" && v !== null && v !== undefined && v !== "" && typeof v !== "object" && typeof v !== "boolean")
      .map(([k, v]) => [k, String(v)] as [string, string]),
    ...Object.entries(ev.raw ?? {})
      .filter(([k, v]) => k !== "fp" && typeof v === "boolean")
      .map(([k, v]) => [k, v ? "true" : "false"] as [string, string]),
  ];

  return (
    <>
      <tr
        onClick={() => setExpanded(v => !v)}
        className={cn(
          "cursor-pointer border-t border-border/40 transition-colors group",
          expanded ? "bg-bg-hover" : "hover:bg-bg-hover/50",
          markedFp && "opacity-60",
        )}
      >
        <td className="w-6 pl-3 py-2.5">
          <ChevronRight className={cn("h-3 w-3 text-slate-500 transition-transform", expanded && "rotate-90")} />
        </td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">{timeStr}</td>
        <td className="py-2.5 pr-3 font-mono text-[10px] text-slate-500 whitespace-nowrap">{ev.hostname ?? "—"}</td>
        <td className="py-2.5 pr-3">
          <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px]", srcColor)}>
            {srcLabel}
          </span>
        </td>
        <td className="py-2.5 pr-3">
          <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase", SEV_BADGE[ev.severity ?? "informational"])}>
            {(ev.severity ?? "info").slice(0, 4).toUpperCase()}
          </span>
        </td>
        <td className="py-2.5 pr-4 text-[11px] text-slate-300 max-w-sm">
          <span className="line-clamp-2">{ev.description ?? ev.event_type}</span>
        </td>
        <td className="py-2.5 pr-3 font-mono text-[10px] text-slate-500 whitespace-nowrap">
          {ev.mitre_technique ?? "—"}
        </td>
        {/* Mark FP button */}
        <td className="py-2.5 pr-3 w-10" onClick={e => { e.stopPropagation(); onToggleFp(ev.id); }}>
          <button
            title={markedFp ? "Unmark FP" : "Mark as False Positive"}
            className={cn(
              "rounded p-1 transition-colors",
              markedFp
                ? "bg-neon-amber/20 text-neon-amber"
                : "text-slate-600 hover:text-neon-amber hover:bg-neon-amber/10 opacity-0 group-hover:opacity-100"
            )}
          >
            <ThumbsDown className="h-3 w-3" />
          </button>
        </td>
      </tr>

      {expanded && (
        <tr>
          <td colSpan={8} className="bg-[#060b12] p-0">
            <div className="border-t border-border/40 px-5 py-4 space-y-3">
              {/* FP badge */}
              {(isFp || markedFp) && (
                <div className={cn(
                  "rounded border px-3 py-2 flex items-center gap-2 text-[11px]",
                  isFp ? "border-neon-amber/30 bg-neon-amber/5 text-neon-amber" : "border-slate-500/30 bg-slate-500/5 text-slate-400"
                )}>
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  {isFp
                    ? "⚠ This event is a FALSE POSITIVE — it looks suspicious but has a legitimate explanation. Good catch!"
                    : "You marked this as a False Positive. Verify against other evidence before excluding."}
                </div>
              )}

              {ev.description && (
                <div className="rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-cyber-300/70">Event Description</p>
                  <p className="text-xs leading-relaxed text-slate-200">{ev.description}</p>
                </div>
              )}

              {/* Hash check button if there's a SHA256 */}
              {ev.file?.sha256 && (
                <HashReputationPanel sha256={ev.file.sha256} />
              )}

              <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
                <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Log Fields (ECS)</p>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                  {ecsFields.map(([k, v]) => (
                    <div key={k} className="flex gap-2 min-w-0">
                      <span className="w-44 shrink-0 font-mono text-[10px] text-slate-500 truncate">{k}</span>
                      <span className={cn(
                        "font-mono text-[10px] break-all",
                        k === "file.hash.sha256" ? "text-cyber-300" : "text-slate-300"
                      )}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Hash Reputation Panel ─────────────────────────────────────────────────────

function HashReputationPanel({ sha256 }: { sha256: string }) {
  const [checked, setChecked] = useState(false);
  const known = lookupHash(sha256);

  function openVt() {
    window.open(`https://www.virustotal.com/gui/file/${sha256}`, "_blank", "noopener");
    setChecked(true);
  }

  return (
    <div className="rounded border border-cyber-500/20 bg-[#0a0f1a] px-4 py-3 space-y-2">
      <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-cyber-300/70 flex items-center gap-1.5">
        <Search className="h-3 w-3" /> Hash Reputation Check
      </p>

      {/* SHA256 display */}
      <div className="font-mono text-[10px] text-slate-400 break-all bg-[#060b12] rounded px-3 py-2">
        {sha256}
      </div>

      {/* Known result from our database */}
      {known && (
        <div className={cn(
          "rounded border px-3 py-2 text-[11px] space-y-0.5",
          known.malicious
            ? "border-severity-critical/30 bg-severity-critical/5"
            : "border-neon-green/30 bg-neon-green/5"
        )}>
          <div className="flex items-center justify-between">
            <span className="font-semibold text-white">{known.name}</span>
            <span className={cn("font-mono font-bold text-[10px]", vtColor(known))}>
              {vtLabel(known)}
            </span>
          </div>
          {"family" in known && (
            <p className="text-[10px] text-slate-400">
              Family: <span className="text-slate-300">{known.family}</span> ·
              Source: <span className="text-slate-400">{known.source}</span>
            </p>
          )}
        </div>
      )}

      {!known && checked && (
        <p className="text-[11px] text-slate-400">Hash not in local database — check VirusTotal for full results.</p>
      )}

      {/* VirusTotal button */}
      <button
        onClick={openVt}
        className={cn(
          "flex w-full items-center justify-center gap-2 rounded border px-3 py-2 text-[11px] font-semibold transition-colors",
          checked
            ? "border-neon-green/30 bg-neon-green/10 text-neon-green"
            : "border-cyber-500/30 bg-cyber-500/10 text-cyber-300 hover:bg-cyber-500/20"
        )}
      >
        <ExternalLink className="h-3.5 w-3.5" />
        {checked ? "Opened in VirusTotal ✓" : "Check on VirusTotal"}
      </button>
    </div>
  );
}

// ─── Completion overlay ────────────────────────────────────────────────────────

function CompletionOverlay({
  scenario,
  timeTaken,
  notes,
  verdict,
  taggedIocs,
  fpMarked,
  onClose,
}: {
  scenario: GeneratedScenario;
  timeTaken: number;
  notes: string;
  verdict: string;
  taggedIocs: Ioc[];
  fpMarked: string[];
  onClose: () => void;
}) {
  const allIocs = extractIocs(scenario.events);
  const realFpCount = scenario.events.filter(isEventFp).length;
  const correctFp = fpMarked.filter(id => scenario.events.find(e => e.id === id && isEventFp(e))).length;
  const score = calcScore(scenario.events, taggedIocs, fpMarked, timeTaken, notes, verdict);
  const grade = score.total >= 85 ? "A" : score.total >= 70 ? "B" : score.total >= 55 ? "C" : "D";
  const gradeColor = grade === "A" ? "text-neon-green" : grade === "B" ? "text-cyber-300" : grade === "C" ? "text-neon-amber" : "text-severity-high";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-6">
      <div className="w-full max-w-xl rounded-xl border border-border bg-[#080d14] shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="border-b border-border bg-[#0d1520] px-6 py-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full border border-neon-green/30 bg-neon-green/10">
              <CheckCircle className="h-5 w-5 text-neon-green" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Investigation Complete</p>
              <p className="text-[11px] text-slate-400">{scenario.title}</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-4">
          {/* Score + grade */}
          <div className="flex items-center justify-between rounded border border-border bg-[#0d1520] px-5 py-4">
            <div className="text-center">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">Score</p>
              <p className="font-mono text-3xl font-bold text-white mt-1">{score.total}<span className="text-slate-500 text-lg">/100</span></p>
            </div>
            <div className="text-center">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">Grade</p>
              <p className={cn("font-mono text-4xl font-bold mt-1", gradeColor)}>{grade}</p>
            </div>
            <div className="text-center">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">Time</p>
              <p className="font-mono text-2xl font-bold text-cyber-300 mt-1">{formatTime(timeTaken)}</p>
            </div>
            <div className="text-center">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">IOC Tagged</p>
              <p className="font-mono text-2xl font-bold text-neon-green mt-1">{taggedIocs.length}<span className="text-slate-500 text-sm">/{allIocs.length}</span></p>
            </div>
          </div>

          {/* Score breakdown */}
          <div className="rounded border border-border bg-[#0d1520] px-4 py-3">
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Score Breakdown</p>
            <div className="space-y-2">
              {score.breakdown.map(item => (
                <div key={item.label} className="space-y-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">{item.label}</span>
                    <span className={cn("font-mono font-bold", item.earned === item.pts ? "text-neon-green" : item.earned > 0 ? "text-neon-amber" : "text-severity-high")}>
                      {item.earned}/{item.pts}
                    </span>
                  </div>
                  <div className="h-1 rounded-full bg-border overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all", item.earned === item.pts ? "bg-neon-green" : item.earned > 0 ? "bg-neon-amber" : "bg-severity-high/30")}
                      style={{ width: `${(item.earned / item.pts) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* FP detection result */}
          <div className="rounded border border-border bg-[#0d1520] px-4 py-3">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">False Positive Detection</p>
            <div className="flex gap-4 text-[11px]">
              <div>
                <span className="text-slate-500">FP events in scenario:</span>
                <span className="ml-2 font-mono font-bold text-neon-amber">{realFpCount}</span>
              </div>
              <div>
                <span className="text-slate-500">Correctly identified:</span>
                <span className="ml-2 font-mono font-bold text-neon-green">{correctFp}</span>
              </div>
              <div>
                <span className="text-slate-500">Incorrectly flagged:</span>
                <span className="ml-2 font-mono font-bold text-severity-high">{fpMarked.length - correctFp}</span>
              </div>
            </div>
          </div>

          {/* Verdict */}
          {verdict && (
            <div className="rounded border border-neon-amber/20 bg-neon-amber/5 px-4 py-3">
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-neon-amber/70">Your Verdict</p>
              <p className="text-sm text-slate-200 leading-relaxed">{verdict}</p>
            </div>
          )}
        </div>

        <div className="border-t border-border px-6 py-3 flex justify-end gap-2 shrink-0">
          <Button variant="secondary" size="sm" onClick={onClose}>Review Logs</Button>
          <Button variant="primary" size="sm" onClick={() => window.history.back()}>
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Admin
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function ScenarioPreviewPage() {
  const router = useRouter();
  const [scenario, setScenario]       = useState<GeneratedScenario | null>(null);
  const [notFound, setNotFound]       = useState(false);
  const [elapsed, setElapsed]         = useState(0);
  const [running, setRunning]         = useState(false);
  const [notes, setNotes]             = useState("");
  const [verdict, setVerdict]         = useState("");
  const [iocs, setIocs]               = useState<Ioc[]>([]);
  const [fpEvents, setFpEvents]       = useState<string[]>([]);  // event ids marked FP
  const [showCompletion, setShowCompletion] = useState(false);
  const [filterSev, setFilterSev]     = useState<string>("all");
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem("generated_scenario");
    if (!raw) { setNotFound(true); return; }
    try {
      const s: GeneratedScenario = JSON.parse(raw);
      setScenario(s);
      setIocs(extractIocs(s.events));
    } catch { setNotFound(true); }
  }, []);

  useEffect(() => {
    if (running) {
      intervalRef.current = setInterval(() => setElapsed(t => t + 1), 1000);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [running]);

  const startTimer = useCallback(() => { if (!running) setRunning(true); }, [running]);

  function toggleTag(value: string) {
    setIocs(prev => prev.map(i => i.value === value ? { ...i, tagged: !i.tagged } : i));
    if (!running) startTimer();
  }

  function toggleFpEvent(id: string) {
    setFpEvents(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
    if (!running) startTimer();
  }

  function submitInvestigation() {
    setRunning(false);
    setShowCompletion(true);
  }

  const taggedIocs  = iocs.filter(i => i.tagged);
  const highCount   = scenario?.events.filter(e => e.severity === "critical" || e.severity === "high").length ?? 0;
  const fpCount     = scenario?.events.filter(isEventFp).length ?? 0;

  const filteredEvents = scenario?.events.filter(ev => {
    if (filterSev === "all") return true;
    if (filterSev === "fp") return isEventFp(ev);
    return ev.severity === filterSev;
  }) ?? [];

  if (notFound) {
    return (
      <div>
        <Topbar title="Investigation" subtitle="Generated scenario" />
        <div className="container mx-auto max-w-[1400px] px-6 py-20 text-center">
          <AlertTriangle className="mx-auto h-12 w-12 text-neon-amber mb-4" />
          <p className="text-lg font-semibold text-white mb-2">No scenario loaded</p>
          <p className="text-sm text-slate-400 mb-6">Generate a scenario from the Admin panel first.</p>
          <Button variant="primary" onClick={() => router.push("/admin")}>
            <ArrowLeft className="h-4 w-4" /> Go to Admin
          </Button>
        </div>
      </div>
    );
  }

  if (!scenario) {
    return (
      <div>
        <Topbar title="Investigation" subtitle="Loading…" />
        <div className="flex items-center justify-center py-32">
          <Loader2 className="h-8 w-8 animate-spin text-cyber-300" />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      <Topbar title={scenario.title} subtitle={`${scenario.threat_actor} · ${scenario.attack_kind.replace(/_/g, " ")}`} />

      <div className="flex flex-col flex-1 min-h-0 container mx-auto max-w-[1400px] px-6 py-4 gap-4">

        {/* Status bar */}
        <div className="flex items-center gap-4 rounded border border-cyber-500/20 bg-cyber-500/5 px-5 py-2.5 shrink-0 flex-wrap">
          {/* Timer */}
          <div className="flex items-center gap-2">
            <Clock className={cn("h-4 w-4", running ? "text-neon-green" : "text-slate-500")} />
            <span className="font-mono text-xl font-bold text-cyber-300 tabular-nums">{formatTime(elapsed)}</span>
            {!running && (
              <button onClick={startTimer} className="ml-1 rounded border border-cyber-500/30 bg-cyber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyber-300 hover:bg-cyber-500/20 transition-colors">
                Start
              </button>
            )}
            {running && (
              <span className="ml-1 inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-neon-green">
                <span className="h-1.5 w-1.5 rounded-full bg-neon-green animate-pulse" /> Live
              </span>
            )}
          </div>

          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-1.5 text-[11px]">
            <Tag className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-300">Evidence:</span>
            <span className={cn("font-mono font-bold", taggedIocs.length > 0 ? "text-neon-green" : "text-slate-500")}>
              {taggedIocs.length}/{iocs.length}
            </span>
          </div>

          <div className="h-4 w-px bg-border" />
          <div className="text-[11px] text-slate-400 flex items-center gap-2">
            <span><span className="text-severity-high font-semibold">{highCount}</span> high/crit</span>
            <span>·</span>
            <span><span className="text-neon-amber font-semibold">{fpCount}</span> FP events</span>
            <span>·</span>
            <span><span className="text-slate-300 font-semibold">{fpEvents.length}</span> you flagged</span>
          </div>

          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-2">
            <Badge variant="outline">{scenario.difficulty}</Badge>
            <span className="rounded bg-neon-green/10 px-2 py-0.5 text-[10px] uppercase tracking-widest text-neon-green font-semibold">AI Generated</span>
          </div>

          <div className="ml-auto">
            <Button variant="primary" size="sm" onClick={submitInvestigation}>
              <Shield className="h-3.5 w-3.5" /> Submit Investigation
            </Button>
          </div>
        </div>

        {/* Main 2-column layout */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_300px] flex-1 min-h-0 overflow-hidden">

          {/* Left — narrative + log table */}
          <div className="flex flex-col gap-4 min-h-0 overflow-hidden">

            {/* Narrative */}
            <div className="rounded border border-border bg-[#0d1520] px-5 py-4 shrink-0">
              <p className="mb-3 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                <Info className="h-3 w-3" /> Incident Briefing
              </p>
              <div className="space-y-2">
                {scenario.narrative.split(/\n+/).filter(Boolean).map((para, i) => (
                  <p key={i} className="text-[12px] leading-relaxed text-slate-300">{para}</p>
                ))}
              </div>
            </div>

            {/* Log events table */}
            <div className="flex flex-col flex-1 min-h-0 rounded border border-border bg-[#080d14] overflow-hidden">
              <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5 shrink-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Log Timeline — {filteredEvents.length} events
                </p>
                {/* Severity filter */}
                <div className="flex items-center gap-1">
                  {["all", "critical", "high", "medium", "low", "fp"].map(sev => (
                    <button key={sev} onClick={() => setFilterSev(sev)}
                      className={cn("rounded px-2 py-0.5 text-[10px] font-semibold uppercase transition-colors",
                        filterSev === sev ? "bg-cyber-500/20 text-cyber-300" : "text-slate-500 hover:text-slate-300"
                      )}>
                      {sev === "all" ? "All" : sev === "fp" ? "FP" : sev.slice(0, 4)}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex-1 overflow-y-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-[#080d14]/95 backdrop-blur z-10">
                    <tr className="border-b border-border/40">
                      <th className="w-6 pl-3" />
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Time</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Host</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Source</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Sev</th>
                      <th className="py-2 pr-4 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Description</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">MITRE</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest" title="Mark as False Positive">FP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map(ev => (
                      <EventRow key={ev.id} ev={ev} markedFp={fpEvents.includes(ev.id)} onToggleFp={toggleFpEvent} />
                    ))}
                    {filteredEvents.length === 0 && (
                      <tr><td colSpan={8} className="py-8 text-center text-xs text-slate-500">No events match the current filter.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Right — IOC tracker + notes + verdict */}
          <div className="flex flex-col gap-3 min-h-0 overflow-y-auto">

            {/* IOC Tracker */}
            <div className="rounded border border-border bg-[#080d14] shrink-0">
              <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
                  <Target className="h-3 w-3" /> IOC Tracker
                </p>
                <span className="font-mono text-[10px] text-slate-500">{taggedIocs.length}/{iocs.length}</span>
              </div>
              <div className="max-h-56 overflow-y-auto divide-y divide-border/40">
                {iocs.length === 0
                  ? <p className="px-4 py-6 text-center text-[11px] text-slate-500">No IOCs extracted</p>
                  : iocs.map(ioc => {
                      const hashEntry = ioc.type === "hash" ? lookupHash(ioc.value) : null;
                      return (
                        <div key={ioc.value}
                          className={cn("group flex items-start gap-2 px-3 py-2.5 transition-colors", ioc.tagged ? "bg-neon-green/5" : "hover:bg-bg-hover/40")}
                        >
                          {/* Tag checkbox */}
                          <div onClick={() => toggleTag(ioc.value)}
                            className={cn("mt-0.5 flex h-3.5 w-3.5 shrink-0 cursor-pointer items-center justify-center rounded-full border transition-colors",
                              ioc.tagged ? "border-neon-green bg-neon-green/20" : "border-slate-600"
                            )}>
                            {ioc.tagged && <div className="h-1.5 w-1.5 rounded-full bg-neon-green" />}
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className={cn("inline-flex items-center rounded border px-1 py-0 text-[9px] font-semibold uppercase tracking-wider", IOC_TYPE_BADGE[ioc.type])}>
                              {ioc.type}
                            </span>
                            <p className="mt-0.5 font-mono text-[10px] text-slate-300 break-all leading-relaxed">{ioc.value}</p>
                            {/* Hash: show VT link inline */}
                            {ioc.type === "hash" && (
                              <div className="mt-1 flex items-center gap-2">
                                {hashEntry && (
                                  <span className={cn("text-[9px] font-semibold", vtColor(hashEntry))}>
                                    {hashEntry.malicious ? `⚠ Malicious · ${hashEntry.vt_detections}/${hashEntry.vt_total}` : "✓ Clean"}
                                  </span>
                                )}
                                <a
                                  href={`https://www.virustotal.com/gui/file/${ioc.value}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  onClick={e => e.stopPropagation()}
                                  className="inline-flex items-center gap-0.5 text-[9px] text-cyber-300/70 hover:text-cyber-300 transition-colors"
                                >
                                  <ExternalLink className="h-2.5 w-2.5" /> VT
                                </a>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })
                }
              </div>
            </div>

            {/* Notes */}
            <div className="rounded border border-border bg-[#080d14]">
              <div className="border-b border-border/60 px-4 py-2.5">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
                  <FileText className="h-3 w-3" /> Investigation Notes
                </p>
              </div>
              <div className="px-3 py-3">
                <textarea value={notes} onChange={e => { setNotes(e.target.value); startTimer(); }}
                  placeholder="Document your findings, timeline reconstruction, attacker TTPs, and evidence…"
                  rows={7}
                  className="w-full resize-none rounded border border-border/40 bg-[#060b12] px-3 py-2.5 font-mono text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none leading-relaxed"
                />
              </div>
            </div>

            {/* Verdict */}
            <div className="rounded border border-border bg-[#080d14]">
              <div className="border-b border-border/60 px-4 py-2.5">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
                  <Zap className="h-3 w-3" /> Analyst Verdict
                </p>
              </div>
              <div className="px-3 py-3 space-y-2">
                <textarea value={verdict} onChange={e => { setVerdict(e.target.value); startTimer(); }}
                  placeholder="Initial access vector, lateral movement, data impacted, recommended containment steps…"
                  rows={5}
                  className="w-full resize-none rounded border border-border/40 bg-[#060b12] px-3 py-2.5 font-mono text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/40 focus:outline-none leading-relaxed"
                />
                <Button variant="primary" className="w-full justify-center" onClick={submitInvestigation}>
                  <Shield className="h-4 w-4" /> Submit Investigation
                </Button>
              </div>
            </div>

          </div>
        </div>
      </div>

      {showCompletion && (
        <CompletionOverlay
          scenario={scenario}
          timeTaken={elapsed}
          notes={notes}
          verdict={verdict}
          taggedIocs={taggedIocs}
          fpMarked={fpEvents}
          onClose={() => setShowCompletion(false)}
        />
      )}
    </div>
  );
}
