"use client";
import { ApiError, messageFromResponse, userMessageFor } from "@/lib/http/apiError";
import { NativeLogProvider, useNativeLog, nativeRows, type NativeRenderer } from "@/lib/logs/native/NativeLogContext";
import { useState, useEffect, useCallback, useMemo, useRef, memo, type MutableRefObject, type TextareaHTMLAttributes } from "react";
import Link from "next/link";
import { AnimatePresence } from "framer-motion";
import { Play, Send, ChevronRight, Search, Info, Target, Plus, X, ShieldAlert, ShieldCheck, ShieldX, FileText, Trophy, Shield, RotateCcw, Lock, Clock, LayoutGrid } from "lucide-react";
import { cn } from "@/lib/utils";
import { recordScenarioCompletion } from "@/lib/storage/progress";
import { describeScenarioXp } from "@/lib/storage/scenarioXp";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CompletionModal, type GradeResult } from "@/components/scenarios/CompletionModal";
import type { ScenarioBundle, ScenarioQuestion, Severity, TelemetryEvent } from "@/lib/sim/types";
import {
  ThreatIntelDrawer, isSha256Field, isIpCheckField, isDomainCheckField,
  type ThreatQuery, type IocTruth,
} from "@/components/threat-intel/ThreatIntelDrawer";
import { describeEventForRow } from "@/lib/sim/describeEvent";
import { EdrConsole } from "@/components/edr/EdrConsole";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";
import type { EdrInvestigation } from "@/lib/edr/investigations";
import { buildAlertIndex, effectiveSeverity, severityLabel, severityAtLeast } from "@/lib/scenarios/eventClass";
import { parseSearchQuery, matchesQuery } from "@/lib/scenarios/logSearch";
import {
  buildEntityIndex, pivotsForEvent, crossHostTimeline, type EntityStats, type EntityIndex,
} from "@/lib/scenarios/correlate";
import {
  displayedOptions, optionLetter, remapExplanation, buildOptionTokens, decodeAnswers, cryptoRandom,
  type OptionTokenMap,
} from "@/lib/scenarios/quizDisplay";
import {
  loadInvestigationStart, saveInvestigationStart, clearInvestigationStart, elapsedSeconds,
} from "@/lib/scenarios/investigationClock";

// ─── Helpers ──────────────────────────────────────────────────────────────────

type Phase = "idle" | "investigating" | "submitted" | "complete";

function formatTime(s: number) {
  const m = Math.floor(s / 60).toString().padStart(2, "0");
  const sec = (s % 60).toString().padStart(2, "0");
  return `${m}:${sec}`;
}

/**
 * The scenario's OWN EDR cases (one per edr/hybrid incident). Every EDR entry
 * point on this page goes here — never to /edr, which opens whatever live
 * SOC-Dashboard shift is stashed in the browser (the exercise landed on a
 * different company, RocketStack, from a scenario — finding #31). The builder's
 * summary is written for the live feed ("the attack running in your SOC
 * Dashboard feed"), so it is replaced with scenario wording. `iocTruth` makes
 * "Look up hash" agree with the threat-intel drawer on this case.
 */
function scenarioInvestigations(events: TelemetryEvent[], title: string, iocTruth: IocTruth | null): EdrInvestigation[] {
  return buildInvestigationsFromScenario({ title, events, iocTruth }).map(inv => ({
    ...inv,
    summary: `Endpoint view of this scenario's incident on ${inv.host.name}, built from the scenario's own telemetry. Walk the process tree, confirm the payload, and decide containment.`,
  }));
}

const utcTime = (ts: string) => new Date(ts).toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" });

// ─── Source / severity maps ───────────────────────────────────────────────────

const SOURCE_LABEL: Record<string, string> = {
  edr: "EDR", sysmon: "Sysmon", ad: "Active Directory", windows_security: "Windows Security",
  o365: "Office 365", okta: "Okta", firewall: "Firewall",
  dns: "DNS", vpn: "VPN", cloudtrail: "Azure/AWS", proxy: "Proxy",
  dlp: "DLP", k8s_audit: "K8s",
  hr: "HR System", vcs: "Source Control", virtualization: "Virtualization",
  infra_monitor: "Infra Monitoring",
};

const SOURCE_COLORS: Record<string, string> = {
  edr:        "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  sysmon:     "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  ad:         "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  windows_security: "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  o365:       "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  okta:       "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  firewall:   "bg-severity-high/20 text-severity-high border-severity-high/30",
  dns:        "bg-neon-green/20 text-neon-green border-neon-green/30",
  vpn:        "bg-slate-400/20 text-slate-300 border-slate-400/30",
  cloudtrail: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  proxy:      "bg-slate-400/20 text-slate-300 border-slate-400/30",
  dlp:        "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  hr:             "bg-slate-400/20 text-slate-300 border-slate-400/30",
  vcs:            "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  virtualization: "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  infra_monitor:  "bg-slate-400/20 text-slate-300 border-slate-400/30",
};

// The severity column used to print SEV_LEVEL (critical 10 / high 8 / medium 5 /
// low 3 / info 1) — a number that read like a Wazuh 0–15 rule level and was
// not one, stamped on raw telemetry ("ProcessRollup2 · LVL 10"). It now shows
// an honest word label from effectiveSeverity(): the vendor's severity on an
// alert, INFO on telemetry (findings #5 / #20).
const SEV_BADGE: Record<string, string> = {
  critical:      "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  high:          "bg-severity-high/15 text-severity-high border-severity-high/40",
  medium:        "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  low:           "bg-slate-500/15 text-slate-400 border-slate-500/30",
  informational: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

// ─── Log row detail panel ─────────────────────────────────────────────────────

function LogDetail({ ev, isAlert, effSev, onThreatQuery }: {
  ev: TelemetryEvent;
  isAlert: boolean;
  effSev: Severity;
  onThreatQuery: (q: ThreatQuery) => void;
}) {
  const [showJson, setShowJson] = useState(false);
  // Native-format view (docs/log-schemas): the record as the authored vendor emits it.
  const nativeView = useNativeLog(ev);

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
    ["Event Class",      isAlert ? "Alert — raised by a detection analytic" : "Telemetry — raw event (no vendor severity)"],
    ["Source Type",      SOURCE_LABEL[ev.source] ?? ev.source.toUpperCase()],
    ["Timestamp",        `${new Date(ev.ts).toLocaleString("en-GB", { timeZone: "UTC" })} UTC`],
    ["Severity",         effSev.toUpperCase()],
    ["Username",         ev.user_email ?? "—"],
    ["Hostname",         ev.hostname ?? "—"],
    ["IP Address",       ev.src_ip ?? ev.dst_ip ?? "—"],
  ];

  // ECS fields from structured event properties
  const ecsCore: [string, string][] = [
    ["event.id",       ev.id],
    ["event.provider", ev.vendor ?? ev.source.toUpperCase()],
    ["event.type",     ev.event_type.replace(/_/g, " ")],
    ["event.severity", effSev.toUpperCase()],
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
  // A raw block often repeats an ECS field the typed event already carries
  // (source.ip, destination.port…): show it once, not twice with a clashing key.
  const seen = new Set(ecsCore.map(([k, v]) => `${k}=${v}`));
  // No schema mixing: with a native view, only the product's own fields.
  const detailedFields: [string, string][] = nativeView ? nativeRows(nativeView.log.record) : [
    ...ecsCore,
    ...[...rawFields, ...rawBool].filter(([k, v]) => !seen.has(`${k}=${v}`)),
  ];

  return (
    <td colSpan={6} className="bg-[#080d14] p-0">
      <div className="border-t border-border/40 px-5 py-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-slate-400" />
            <span className="text-sm font-semibold text-white">Log Analysis</span>
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-400 select-none">
            Raw log
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
            {/* Native record (wire line for text-native sources). Without a native module
                this is the viewer's display projection, as before. */}
            {nativeView ? (nativeView.log.rawLine ?? JSON.stringify(nativeView.log.record, null, 2)) : JSON.stringify(ev, null, 2)}
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
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">Basic Information</p>
              <div className="space-y-2">
                {basicInfo.map(([label, value]) => (
                  <div key={label} className="flex gap-3">
                    <span className="w-36 shrink-0 text-[11px] text-slate-400">{label}</span>
                    <span className="font-mono text-[11px] text-slate-200 break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">Detailed Log Data</p>
              <div className="space-y-1.5">
                {detailedFields.map(([k, v], i) => {
                  const showHash   = isSha256Field(k, v);
                  const showIp     = isIpCheckField(k, v);
                  const showDomain = isDomainCheckField(k, v);
                  const hasBtn     = showHash || showIp || showDomain;

                  return (
                    <div key={`${i}:${k}`} className={cn("flex gap-3", hasBtn ? "items-start py-0.5" : "items-baseline")}>
                      <span className="w-64 shrink-0 font-mono text-[10px] text-slate-400">{k}</span>
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

const ENTITY_LABEL: Record<EntityStats["entity"]["type"], string> = {
  user: "User", host: "Host", ip: "IP", hash: "Hash",
};

/** What the row's Correlate menu can pivot on. */
type Pivot =
  | { kind: "entity"; id: string; label: string }
  | { kind: "incident"; id: string };

const LogRow = memo(function LogRow({
  ev, isAlert, effSev, onThreatQuery, focused, dimmed, pivots, incidentSize, onPivot,
  canInvestigate, onInvestigate, focusReq,
}: {
  ev: TelemetryEvent;
  /** Product detection (see eventClass.ts) — carries the ALERT badge. */
  isAlert: boolean;
  /** Severity the row shows: vendor severity on an alert, informational on telemetry. */
  effSev: Severity;
  onThreatQuery: (q: ThreatQuery) => void;
  /** true when this row belongs to the active pivot. */
  focused?: boolean;
  /** true when a pivot is active and this row is NOT part of it. */
  dimmed?: boolean;
  /** Entities of this row that also appear in other events (cross-host first). */
  pivots: EntityStats[];
  /** Events sharing this row's incident_id (0 when it has none). */
  incidentSize: number;
  onPivot: (p: Pivot | null) => void;
  /** true when this detection's incident is endpoint-investigable (edr/hybrid). */
  canInvestigate?: boolean;
  /** open this incident in the embedded EDR console. */
  onInvestigate: (incidentId: string) => void;
  /** Bumped by the timeline when it asks this row to expand + scroll into view. */
  focusReq?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const rowRef = useRef<HTMLTableRowElement>(null);
  const sevBadge = SEV_BADGE[effSev];
  const srcLabel = SOURCE_LABEL[ev.source] ?? ev.source.toUpperCase();
  const srcColor = SOURCE_COLORS[ev.source] ?? SOURCE_COLORS.proxy;
  // Render in UTC explicitly. This is deterministic on the server AND the client
  // (a fixed timeZone, not the runtime's), which closes the React #418 hydration
  // mismatch (SSR-UTC vs client-local) AND makes the table agree with the briefing,
  // which is written in UTC. (See the "Timestamps, Timezones & Building a Timeline"
  // room: a mature SIEM stores UTC — here we also display it.)
  const timeStr = utcTime(ev.ts);

  // The cross-host timeline asked for this row: open it and bring it into view.
  useEffect(() => {
    if (!focusReq) return;
    setExpanded(true);
    rowRef.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [focusReq]);

  // Same plain-language line as the Live SOC feed (observable fields only — the
  // authored description is withheld on this page because it states the answer).
  const row = describeEventForRow(ev);

  const canCorrelate = pivots.length > 0 || incidentSize > 1;

  return (
    <>
      <tr
        ref={rowRef}
        onClick={() => setExpanded(v => !v)}
        className={cn(
          "cursor-pointer border-t border-border/60 transition-colors",
          expanded ? "bg-bg-hover" : "hover:bg-bg-hover/60",
          effSev === "critical" && "border-l-2 border-l-severity-critical",
          effSev === "high"     && "border-l-2 border-l-severity-high",
          isAlert && "bg-cyber-500/[0.06]",
          focused && "bg-cyber-500/15 ring-1 ring-inset ring-cyber-500/40",
          dimmed && "opacity-40",
        )}
      >
        <td className="w-5 pl-3">
          <ChevronRight className={cn("h-3 w-3 text-slate-400 transition-transform", expanded && "rotate-90")} />
        </td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400">{timeStr}</td>
        <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-200 max-w-[120px]">
          <span className="truncate block">{ev.hostname ?? "—"}</span>
        </td>
        <td className="py-2.5 pr-3">
          <div className="flex items-center gap-1.5">
            <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider", srcColor)}>
              {srcLabel}
            </span>
            {isAlert && (
              <span
                title="Alert — raised by a detection analytic (the event that opens the ticket). Unbadged rows are raw telemetry."
                className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/15 px-1 py-0.5 text-[8px] font-bold uppercase tracking-wider text-cyber-300"
              >
                <span className="h-1 w-1 rounded-full bg-cyber-300" /> Alert
              </span>
            )}
          </div>
        </td>
        <td className="py-2.5 pr-3">
          {row.user && (
            <div className="mb-0.5 flex flex-wrap items-center gap-1">
              <span className="font-mono text-[11px] font-bold leading-none text-cyber-300">{row.user}</span>
              {row.title && (
                <span className="rounded border border-slate-600/50 bg-slate-800/70 px-1.5 py-px text-[9px] font-medium leading-none text-slate-400">{row.title}</span>
              )}
            </div>
          )}
          <span className="block text-[11px] text-slate-300 leading-relaxed line-clamp-2">{row.action}</span>
          <div className="relative mt-0.5 flex items-center gap-2">
            {ev.mitre_technique && (
              <span className="font-mono text-[9px] text-neon-purple/70">{ev.mitre_technique}</span>
            )}
            {canCorrelate && (
              <button
                onClick={e => {
                  e.stopPropagation();
                  if (focused) { onPivot(null); setMenuOpen(false); } else setMenuOpen(v => !v);
                }}
                title={focused ? "Clear correlation" : "Correlate — pivot on a user, host, IP or hash across every host"}
                className={cn(
                  "inline-flex items-center gap-0.5 rounded px-1 py-0.5 font-mono text-[8px] font-semibold uppercase tracking-wider transition",
                  focused || menuOpen ? "bg-cyber-500/25 text-cyber-200" : "text-slate-500 hover:text-cyber-300",
                )}
              >
                🔗 {focused ? "correlated" : "correlate"}
              </button>
            )}
            {canInvestigate && ev.incident_id && (
              <button
                onClick={e => { e.stopPropagation(); onInvestigate(ev.incident_id!); }}
                title="Open this incident on the endpoint — walk the process tree in the EDR console"
                className="inline-flex items-center gap-0.5 rounded border border-cyber-500/40 bg-cyber-500/15 px-1.5 py-0.5 font-mono text-[8px] font-bold uppercase tracking-wider text-cyber-200 transition hover:bg-cyber-500/25"
              >
                🔎 Investigate in EDR
              </button>
            )}
            {menuOpen && !focused && (
              <div
                onClick={e => e.stopPropagation()}
                className="absolute left-0 top-full z-20 mt-1 w-80 rounded border border-border bg-bg-elevated p-2 shadow-xl"
              >
                <p className="mb-1.5 px-1 text-[9px] font-semibold uppercase tracking-[0.15em] text-slate-400">
                  Pivot across all hosts on…
                </p>
                <ul className="space-y-0.5">
                  {pivots.slice(0, 8).map(p => (
                    <li key={`${p.entity.type}:${p.entity.key}`}>
                      <button
                        onClick={() => {
                          onPivot({ kind: "entity", id: `${p.entity.type}:${p.entity.key}`, label: `${ENTITY_LABEL[p.entity.type]} ${p.entity.display}` });
                          setMenuOpen(false);
                        }}
                        className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-[10px] text-slate-200 hover:bg-cyber-500/10"
                      >
                        <span className="w-9 shrink-0 font-mono text-[9px] uppercase text-slate-400">{ENTITY_LABEL[p.entity.type]}</span>
                        <span className="min-w-0 flex-1 truncate font-mono">{p.entity.display}</span>
                        <span className="shrink-0 font-mono text-[9px] text-slate-400">
                          {p.eventIds.length} ev · {p.hosts.length} host{p.hosts.length !== 1 ? "s" : ""}
                        </span>
                      </button>
                    </li>
                  ))}
                  {incidentSize > 1 && ev.incident_id && (
                    <li>
                      <button
                        onClick={() => { onPivot({ kind: "incident", id: ev.incident_id! }); setMenuOpen(false); }}
                        className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-[10px] text-slate-300 hover:bg-cyber-500/10"
                      >
                        <span className="w-9 shrink-0 font-mono text-[9px] uppercase text-slate-400">Case</span>
                        <span className="flex-1">Same EDR incident (this host)</span>
                        <span className="shrink-0 font-mono text-[9px] text-slate-400">{incidentSize} ev</span>
                      </button>
                    </li>
                  )}
                </ul>
              </div>
            )}
          </div>
        </td>
        <td className="py-2.5 pr-4">
          <span
            title={isAlert ? "Vendor severity of the alert" : "Raw telemetry carries no vendor severity"}
            className={cn("inline-flex h-5 min-w-[2.5rem] items-center justify-center rounded border px-1 font-mono text-[9px] font-bold tracking-wider", sevBadge)}
          >
            {severityLabel(effSev)}
          </span>
        </td>
      </tr>
      {expanded && (
        <tr>
          <LogDetail ev={ev} isAlert={isAlert} effSev={effSev} onThreatQuery={onThreatQuery} />
        </tr>
      )}
    </>
  );
});

const NO_PIVOTS: EntityStats[] = [];

// ─── Log viewer ───────────────────────────────────────────────────────────────

type ViewerTab = "events" | "timeline";

/**
 * Memoised: its only prop is the (stable) event array, so typing in the report,
 * answering the quiz or the timer ticking no longer re-renders every row and
 * every expanded detail pane. With all events expanded, a ~1,900-character
 * narrative used to freeze the tab (finding #29).
 */
const ScenarioLogViewer = memo(function ScenarioLogViewer({ events, title, iocTruth }: {
  events: TelemetryEvent[];
  title: string;
  /** Server-computed IOC truth (page.tsx → buildIocTruth) — TI verdicts follow the case. */
  iocTruth: IocTruth | null;
}) {
  const [threatQuery, setThreatQueryRaw] = useState<ThreatQuery | null>(null);
  // Every lookup opened from this page carries the scenario's truth table, so an
  // attacker IOC enriches as malicious here exactly as in the EDR console.
  const setThreatQuery = useCallback(
    (q: ThreatQuery | null) => setThreatQueryRaw(q ? { ...q, truth: iocTruth } : null),
    [iocTruth],
  );
  const [search, setSearch]       = useState("");
  const [sevFilter, setSevFilter] = useState<"all" | "medium" | "high">("all");
  const [showAll, setShowAll]     = useState(false);
  const [tab, setTab]             = useState<ViewerTab>("events");
  // De-flood: hide EDR telemetry rows, leaving alerts + SIEM logs. The hidden
  // process/file telemetry is then walked inside the EDR console tree (the pivot).
  // Default off so it never removes an event a scenario question references.
  const [detectionsOnly, setDetectionsOnly] = useState(false);
  // Correlation: the entity (or incident) currently pivoted on across the feed.
  const [pivot, setPivot] = useState<Pivot | null>(null);
  // Timeline → table focus: which row to expand/scroll, and a nonce so re-clicking works.
  const [focusReq, setFocusReq] = useState<{ id: string; n: number } | null>(null);
  // EDR pivot: one ISOLATED investigation per incident_id (edr/hybrid only) — each
  // a separate case in the console switcher. `edrCaseId` = the open case (null = closed).
  const edrInvestigations = useMemo(() => scenarioInvestigations(events, title, iocTruth), [events, title, iocTruth]);
  const edrIncidentIds = useMemo(() => new Set(edrInvestigations.map(i => i.id)), [edrInvestigations]);
  const [edrCaseId, setEdrCaseId] = useState<string | null>(null);

  // One classification feeds the badge, the severity column, the filters and
  // the header count — so the count always equals the badges shown.
  const alertIds = useMemo(() => buildAlertIndex(events), [events]);
  // Display projection: the object the row renders, the Raw JSON shows and the
  // search indexes. Its `severity` is the effective one, so a ProcessRollup2
  // does not read "critical" in the JSON while its row says INFO.
  const view = useMemo(() => {
    const m = new Map<string, { ev: TelemetryEvent; isAlert: boolean; effSev: Severity }>();
    for (const e of events) {
      const isAlert = alertIds.has(e.id);
      const effSev = effectiveSeverity(e, isAlert);
      m.set(e.id, { ev: { ...e, severity: effSev }, isAlert, effSev });
    }
    return m;
  }, [events, alertIds]);
  const entityIndex: EntityIndex = useMemo(() => buildEntityIndex(events), [events]);
  // Precomputed so each memoised row receives a STABLE pivots array.
  const pivotsByEvent = useMemo(
    () => new Map(events.map(e => [e.id, pivotsForEvent(entityIndex, e.id)] as const)),
    [events, entityIndex],
  );
  const incidentSizes = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events) if (e.incident_id) m.set(e.incident_id, (m.get(e.incident_id) ?? 0) + 1);
    return m;
  }, [events]);

  // Sort by timestamp once. Scenario builders declare events in narrative
  // order, which is not always chronological — a lateral-movement event can be
  // listed before the credential dump that enabled it while carrying a later
  // `ts`. Sorting a COPY fixes every scenario at once and leaves the source
  // arrays (used by the attack-chain reconstruction) untouched.
  const sorted = useMemo(
    () => [...events].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime()),
    [events],
  );
  const terms = useMemo(() => parseSearchQuery(search), [search]);

  const passes = useCallback((ev: TelemetryEvent) => {
    const v = view.get(ev.id)!;
    if (detectionsOnly
      && (ev.source === "edr" || ev.source === "sysmon" || ev.source === "av" || ev.source === "windows_security" || ev.source === "linux_audit")
      && !v.isAlert && !ev.is_detection) return false;
    if (sevFilter === "high"   && !severityAtLeast(v.effSev, "high")) return false;
    if (sevFilter === "medium" && !severityAtLeast(v.effSev, "medium")) return false;
    // Full-text over every field name and value of the record, plus field:value
    // syntax (logSearch.ts) — `user:svc_backup`, `dst_ip:10.20.6.28`, a hash.
    return matchesQuery(v.ev, terms);
  }, [view, detectionsOnly, sevFilter, terms]);

  const filtered = useMemo(() => sorted.filter(passes), [sorted, passes]);
  const visible = showAll ? filtered : filtered.slice(0, 30);

  // Events of the active pivot, chronological, from the FULL set — a pivot stays
  // whole even under a severity filter or the 30-row cap.
  const pivotIds = useMemo(() => {
    if (!pivot) return null;
    if (pivot.kind === "incident") return new Set(events.filter(e => e.incident_id === pivot.id).map(e => e.id));
    return new Set(entityIndex.byEntity.get(pivot.id)?.eventIds ?? []);
  }, [pivot, events, entityIndex]);
  const pivotEvents = useMemo(
    () => (pivotIds ? sorted.filter(e => pivotIds.has(e.id)) : []),
    [pivotIds, sorted],
  );
  const pivotHosts = useMemo(() => [...new Set(pivotEvents.map(e => e.hostname ?? "—"))], [pivotEvents]);

  // Unified cross-host timeline: the pivot's events when one is active, else all.
  const timeline = useMemo(
    () => crossHostTimeline(pivotIds ? pivotEvents : sorted),
    [pivotIds, pivotEvents, sorted],
  );

  const onInvestigate = useCallback((incidentId: string) => setEdrCaseId(incidentId), []);

  /** Timeline click → show that event in the table, expanded and in view. */
  const focusEvent = useCallback((id: string) => {
    const ev = events.find(e => e.id === id);
    if (!ev) return;
    // Clear whatever would hide it, then make sure the 30-row cap doesn't.
    if (!passes(ev)) { setSearch(""); setSevFilter("all"); setDetectionsOnly(false); }
    setShowAll(true);
    setTab("events");
    setFocusReq(prev => ({ id, n: (prev?.n ?? 0) + 1 }));
  }, [events, passes]);

  const alertCount = alertIds.size;

  return (
    <>
    <Card className="p-0 overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Security Events</h3>
        <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-slate-400">
          {filtered.length} events · {alertCount} alert{alertCount !== 1 ? "s" : ""}
        </span>
        <div className="flex gap-1">
          {(["events", "timeline"] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition",
                tab === t ? "bg-cyber-500/20 text-cyber-300 border border-cyber-500/30" : "text-slate-400 hover:text-slate-300",
              )}
            >
              {t === "events" ? "Events" : "Timeline · all hosts"}
            </button>
          ))}
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <div className="flex gap-1">
            {(["all", "medium", "high"] as const).map(f => (
              <button
                key={f}
                onClick={() => setSevFilter(f)}
                className={cn(
                  "rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition",
                  sevFilter === f
                    ? "bg-cyber-500/20 text-cyber-300 border border-cyber-500/30"
                    : "text-slate-400 hover:text-slate-300"
                )}
              >
                {f === "all" ? "All" : f === "medium" ? "≥ Medium" : "High/Critical"}
              </button>
            ))}
            <button
              onClick={() => setDetectionsOnly(v => !v)}
              title="Hide EDR telemetry — show only detections and SIEM logs. Walk the hidden process/file telemetry inside the EDR console (Investigate in EDR)."
              className={cn(
                "rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition",
                detectionsOnly
                  ? "bg-cyber-500/20 text-cyber-300 border border-cyber-500/30"
                  : "text-slate-400 hover:text-slate-300",
              )}
            >
              Detections only
            </button>
          </div>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-400" />
            <input
              type="text"
              placeholder="Search all fields — e.g. user:svc_backup"
              title={'Searches every field name and value of the raw log. Terms are ANDed. field:value (user:, host:, ip:, src_ip:, dst_ip:, hash:, process:, cmd:, domain:, port: or any raw field name), "quoted phrase", -exclude.'}
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="rounded border border-border bg-bg-elevated pl-6 pr-3 py-1 text-[11px] text-slate-200 placeholder-slate-500 focus:border-cyber-500/40 focus:outline-none w-64"
            />
          </div>
        </div>
      </div>

      {pivot && pivotEvents.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-cyber-500/25 bg-cyber-500/[0.05] px-4 py-2.5">
          <span className="text-[11px] font-semibold text-cyber-200">
            🔗 {pivot.kind === "entity" ? `Pivot: ${pivot.label}` : "Correlated incident"}
          </span>
          <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-slate-300">
            {pivotEvents.length} events · {pivotHosts.length} host{pivotHosts.length !== 1 ? "s" : ""} · {new Set(pivotEvents.map(e => e.source)).size} sources
          </span>
          <span className="font-mono text-[10px] text-slate-400">{pivotHosts.join(" → ")}</span>
          {/* Mini-timeline: one dot per event in time order; alerts stand out. Click to focus. */}
          <div className="flex items-center gap-1">
            {pivotEvents.map(e => (
              <button
                key={e.id}
                onClick={() => focusEvent(e.id)}
                title={`${utcTime(e.ts)} UTC · ${e.hostname ?? "—"} · ${SOURCE_LABEL[e.source] ?? e.source}${alertIds.has(e.id) ? " · ALERT" : ""}`}
                className={cn(
                  "h-2.5 w-2.5 rounded-full border",
                  alertIds.has(e.id) ? "bg-cyber-400 border-cyber-300" : "bg-slate-500/50 border-slate-500",
                )}
              />
            ))}
          </div>
          <button
            onClick={() => setTab("timeline")}
            className="text-[10px] font-semibold text-cyber-300 transition hover:text-cyber-200"
          >
            open as timeline →
          </button>
          <button
            onClick={() => setPivot(null)}
            className="ml-auto text-[10px] font-semibold text-slate-400 transition hover:text-white"
          >
            clear ✕
          </button>
        </div>
      )}

      {tab === "timeline" ? (
        <div className="max-h-[520px] overflow-y-auto">
          <p className="border-b border-border/60 px-4 py-2 text-[10px] text-slate-400">
            {pivot ? "Every event of the pivot" : "Every event of the scenario"} on one clock, across all hosts.
            Click an entry to open it in the event table.
          </p>
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-bg-elevated/95 backdrop-blur">
              <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                <th className="py-2 pl-4 pr-3">Time (UTC)</th>
                <th className="py-2 pr-3">Δ</th>
                <th className="py-2 pr-3">Host</th>
                <th className="py-2 pr-3">Source</th>
                <th className="py-2 pr-4">Event</th>
              </tr>
            </thead>
            <tbody>
              {timeline.map(({ event: e, host, offsetSec }, i) => {
                const hostChanged = i > 0 && timeline[i - 1].host !== host;
                return (
                  <tr
                    key={e.id}
                    onClick={() => focusEvent(e.id)}
                    className={cn(
                      "cursor-pointer border-t border-border/60 transition-colors hover:bg-bg-hover/60",
                      hostChanged && "border-t-cyber-500/40",
                      alertIds.has(e.id) && "bg-cyber-500/[0.06]",
                    )}
                  >
                    <td className="whitespace-nowrap py-2 pl-4 pr-3 font-mono text-[11px] text-slate-400">{utcTime(e.ts)}</td>
                    <td className="whitespace-nowrap py-2 pr-3 font-mono text-[10px] text-slate-500">+{formatTime(offsetSec)}</td>
                    <td className={cn("whitespace-nowrap py-2 pr-3 font-mono text-[11px]", hostChanged ? "text-cyber-200" : "text-slate-200")}>{host}</td>
                    <td className="whitespace-nowrap py-2 pr-3">
                      <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider", SOURCE_COLORS[e.source] ?? SOURCE_COLORS.proxy)}>
                        {SOURCE_LABEL[e.source] ?? e.source.toUpperCase()}
                      </span>
                      {alertIds.has(e.id) && (
                        <span className="ml-1.5 text-[8px] font-bold uppercase tracking-wider text-cyber-300">Alert</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 text-[11px] text-slate-300">
                      <span className="line-clamp-1">
                        {e.process?.name
                          ? `${e.process.name}${e.process.cmdline ? ` — ${e.process.cmdline}` : ""}`
                          : e.network?.domain ?? e.network?.url ?? e.file?.path ?? e.event_type.replace(/_/g, " ")}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
      <div className="max-h-[520px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-bg-elevated/95 backdrop-blur">
            <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-400">
              <th className="w-5 pl-3 py-2" />
              <th className="py-2 pr-3">Time (UTC)</th>
              <th className="py-2 pr-3">Agent</th>
              <th className="py-2 pr-3">Source</th>
              <th className="py-2 pr-3">Description</th>
              <th className="py-2 pr-4" title="Vendor severity on alerts; INFO on raw telemetry">Severity</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(ev => {
              const v = view.get(ev.id)!;
              return (
                <LogRow
                  key={ev.id}
                  ev={v.ev}
                  isAlert={v.isAlert}
                  effSev={v.effSev}
                  onThreatQuery={setThreatQuery}
                  pivots={pivotsByEvent.get(ev.id) ?? NO_PIVOTS}
                  incidentSize={ev.incident_id ? incidentSizes.get(ev.incident_id) ?? 0 : 0}
                  onPivot={setPivot}
                  focused={!!pivotIds && pivotIds.has(ev.id)}
                  dimmed={!!pivotIds && !pivotIds.has(ev.id)}
                  canInvestigate={(v.isAlert || !!ev.is_detection) && !!ev.incident_id && edrIncidentIds.has(ev.incident_id)}
                  onInvestigate={onInvestigate}
                  focusReq={focusReq?.id === ev.id ? focusReq.n : undefined}
                />
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-xs text-slate-400">No events match the filter.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}

      {tab === "events" && !showAll && filtered.length > 30 && (
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

    {edrCaseId && (
      <ScenarioEdrPanel
        investigations={edrInvestigations}
        caseId={edrCaseId}
        onClose={() => setEdrCaseId(null)}
      />
    )}
    </>
  );
});

// ─── Embedded EDR console panel (the scenario pivot) ───────────────────────────

function ScenarioEdrPanel({ investigations, caseId, onClose }: {
  investigations: EdrInvestigation[];
  caseId: string;
  onClose: () => void;
}) {
  if (investigations.length === 0) return null;
  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-bg/95 backdrop-blur-sm">
      <div className="flex shrink-0 items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyber-300" />
          <span className="text-sm font-bold text-white">EDR Console</span>
          {investigations.length > 1 && (
            <span
              title="Each incident is a separate, isolated case — switch between them without mixing their process trees"
              className="rounded border border-border bg-bg-elevated px-2 py-0.5 text-[10px] text-slate-400"
            >
              {investigations.length} separate incidents
            </span>
          )}
        </div>
        <button onClick={onClose} className="rounded p-1 text-slate-400 transition hover:text-white" aria-label="Close EDR console">
          <X className="h-5 w-5" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto px-5 py-4">
        <EdrConsole embedded investigations={investigations} initialCaseId={caseId} />
      </div>
    </div>
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

type ReportTab = "narrative" | "iocs" | "verdict";

const REPORT_TABS: { id: ReportTab; label: string }[] = [
  { id: "narrative", label: "Narrative" },
  { id: "iocs",      label: "IOCs"      },
  { id: "verdict",   label: "Verdict"   },
];

/**
 * A textarea that owns its own value. The parent keeps the text in a ref (read
 * at submit) and is only told when something it RENDERS changes — so a
 * keystroke re-renders this box, not the page (finding #29).
 */
const DraftTextarea = memo(function DraftTextarea({ initial, onChange, ...rest }: {
  initial: string;
  onChange: (v: string) => void;
} & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "value" | "defaultValue" | "onChange">) {
  const [value, setValue] = useState(initial);
  return (
    <textarea
      {...rest}
      value={value}
      onChange={e => { setValue(e.target.value); onChange(e.target.value); }}
    />
  );
});

function InvestigationPanel({
  phase,
  draftKey,
  notesRef,
  notesFilled,
  onNotesChange,
  iocs,
  onAddIoc,
  onRemoveIoc,
  verdict,
  onVerdictChange,
  reasonRef,
  onVerdictReasonChange,
  onSubmit,
  quizComplete,
}: {
  phase: Phase;
  /** Bumped on retry so the draft boxes remount empty. */
  draftKey: number;
  notesRef: MutableRefObject<string>;
  /** Derived in the parent; flips only when the narrative crosses 10 chars. */
  notesFilled: boolean;
  onNotesChange: (v: string) => void;
  iocs: ManualIoc[];
  onAddIoc: (ioc: ManualIoc) => void;
  onRemoveIoc: (id: string) => void;
  verdict: "tp" | "fp" | null;
  onVerdictChange: (v: "tp" | "fp") => void;
  reasonRef: MutableRefObject<string>;
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

  const disabled = phase !== "investigating";
  const inputCls = cn(
    "w-full rounded border border-border/60 bg-[#060b12] px-3 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:border-[#2dd4bf]/40 focus:outline-none",
    disabled && "opacity-40 cursor-not-allowed"
  );

  // Section completion: has meaningful content
  const sectionDone: Record<ReportTab, boolean> = {
    narrative: notesFilled,
    iocs:      iocs.length > 0,
    verdict:   verdict !== null,
  };
  const completedCount = Object.values(sectionDone).filter(Boolean).length;
  // Three sections now (Findings was folded into IOCs). Require any two — keeping
  // the same "you don't need every tab" leniency as the old 3-of-4 bar.
  const canFinalize    = completedCount >= 2 && quizComplete;

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
        <span className="text-[10px] font-mono text-slate-400">
          {completedCount}<span className="text-slate-700">/3</span>
        </span>
      </div>

      {/* ── Tab bar ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 border-b border-border/60">
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
                  : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
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
            <p className="mb-3 text-[11px] text-slate-400">Document your investigation process step by step</p>
            <DraftTextarea
              key={draftKey}
              rows={10}
              disabled={disabled}
              initial={notesRef.current}
              onChange={onNotesChange}
              className={inputCls + " resize-none"}
              placeholder={
                disabled
                  ? "Start the investigation to begin writing..."
                  : "Describe the attack timeline, methods, and what you observed in the logs..."
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
                className="flex-1 rounded border border-border/60 bg-[#060b12] px-3 py-1.5 text-[11px] text-slate-200 placeholder-slate-500 focus:border-[#2dd4bf]/40 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed"
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
                      className="shrink-0 rounded p-0.5 text-slate-400 hover:text-severity-high hover:bg-severity-high/10 transition"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="rounded border border-dashed border-border/60 py-6 text-center text-[11px] text-slate-400">
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
                  <p className="text-[10px] text-slate-400 mt-0.5">Confirmed malicious activity</p>
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
                  <p className="text-[10px] text-slate-400 mt-0.5">Legitimate / benign activity</p>
                </div>
                {verdict === "fp" && (
                  <span className="rounded bg-neon-green/20 px-2 py-0.5 text-[10px] font-bold text-neon-green">SELECTED</span>
                )}
              </button>
            </div>

            {verdict && (
              <div>
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">
                  Reasoning
                </p>
                <DraftTextarea
                  key={draftKey}
                  rows={3}
                  disabled={disabled}
                  initial={reasonRef.current}
                  onChange={onVerdictReasonChange}
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
              : "bg-white/5 border border-border/40 text-slate-400 cursor-not-allowed"
          )}
        >
          <Trophy className={cn("h-4 w-4", canFinalize ? "text-neon-amber" : "text-slate-400")} />
          Finalize &amp; Evaluate Investigation
        </button>

        {(!canFinalize || !quizComplete) && phase === "investigating" && (
          <p className="mt-2 text-center text-[10px] text-slate-400">
            {!quizComplete && "Answer all quiz questions · "}
            {completedCount < 2 && `Complete ${2 - completedCount} more section${2 - completedCount !== 1 ? "s" : ""}`}
          </p>
        )}
      </div>

    </div>
  );
}

// ─── Investigation timer ──────────────────────────────────────────────────────

/**
 * Its own component with its own interval, so the page does not re-render every
 * second. Elapsed is WALL time since the persisted start (finding #27) — a
 * reload resumes it and a throttled background tab cannot under-report.
 */
function InvestigationTimer({ startMs }: { startMs: number | null }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="font-mono text-lg font-bold text-cyber-300">{formatTime(elapsedSeconds(startMs, now))}</span>;
}

// ─── Completed state (debrief) ────────────────────────────────────────────────

/**
 * The page's completed state (finding #31). "Continue" on the score modal used
 * to drop the learner back to "Start Investigation" with nothing on screen. The
 * page now stays complete and shows what the grade response actually returned:
 * the summary, every question's result with its (letter-remapped) explanation,
 * the report rubric, and the attack timeline IF the server released the debrief.
 * Nothing the server withheld is inferred or shown (IOC values stay server-side;
 * only the cited/total counts come back).
 */
function ScenarioDebrief({ result, questions, events, title, iocTruth, timeTaken, verdict, onRetry, onShowScoreCard }: {
  result: GradeResult;
  questions: ScenarioQuestion[];
  events: TelemetryEvent[];
  title: string;
  iocTruth: IocTruth | null;
  timeTaken: number;
  verdict: "tp" | "fp" | null;
  onRetry: () => void;
  onShowScoreCard: () => void;
}) {
  // The scenario's OWN EDR cases — never a link to /edr, which shows whatever
  // live-dashboard shift is stashed in the browser (a different company).
  const investigations = useMemo(() => scenarioInvestigations(events, title, iocTruth), [events, title, iocTruth]);
  const [edrOpen, setEdrOpen] = useState(false);
  const qById = useMemo(() => new Map(questions.map(q => [q.id, q])), [questions]);
  const r = result.report;
  const bd = r?.breakdown;
  const correctCount = result.perQuestion.filter(q => q.correct).length;
  // Best-attempt XP accounting comes from the server (#30) — not recomputed here.
  const xp = describeScenarioXp(result);

  return (
    <div className={cn(
      "rounded border px-5 py-4 space-y-5",
      result.passed ? "border-neon-green/25 bg-neon-green/[0.04]" : "border-severity-high/25 bg-severity-high/[0.04]",
    )}>
      <div className="flex flex-wrap items-center gap-3">
        {result.passed
          ? <Trophy className="h-5 w-5 text-neon-green" />
          : <ShieldX className="h-5 w-5 text-severity-high" />}
        <h3 className="text-sm font-bold text-white">
          {result.passed ? "Case closed — passed" : "Case closed — not passed"}
        </h3>
        <Badge variant="outline">{result.score}% overall</Badge>
        <div className="ml-auto flex flex-wrap gap-2">
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 rounded border border-cyber-500/30 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition hover:bg-cyber-500/20"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Retry scenario
          </button>
          {investigations.length > 0 && (
            <button
              onClick={() => setEdrOpen(true)}
              className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/5"
            >
              <Shield className="h-3.5 w-3.5" /> Review in EDR console
            </button>
          )}
          <button
            onClick={onShowScoreCard}
            className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/5"
          >
            <Trophy className="h-3.5 w-3.5" /> Score card
          </button>
          <Link
            href="/scenarios"
            className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/5"
          >
            <LayoutGrid className="h-3.5 w-3.5" /> All scenarios
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {[
          { label: "Score",  value: `${result.score}%`, hint: result.passed ? "passed (≥ 70%)" : "70% to pass" },
          { label: "Quiz",   value: `${correctCount}/${result.perQuestion.length}`, hint: result.quizScore !== undefined ? `${result.quizScore}%` : "" },
          { label: "Report", value: r ? `${r.score}/100` : "—", hint: r ? `${r.words} words` : "" },
          { label: xp.label, value: `+${xp.added}`, hint: xp.added !== result.xpEarned ? `this run ${result.xpEarned} XP` : "best attempt counts" },
          { label: "Time",   value: formatTime(timeTaken), hint: "not graded" },
        ].map(s => (
          <div key={s.label} className="rounded border border-border bg-[#080d14] px-3 py-2.5 text-center">
            <p className="font-mono text-lg font-bold text-white">{s.value}</p>
            <p className="mt-0.5 text-[10px] uppercase tracking-widest text-slate-400">{s.label}</p>
            {s.hint && <p className="mt-0.5 text-[9px] text-slate-500">{s.hint}</p>}
          </div>
        ))}
      </div>

      {r && (
        <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">Report</p>
          <p className="text-xs text-slate-300">
            Your verdict: <span className="font-mono font-bold">{verdict ? verdict.toUpperCase() : "none"}</span>
            {" — "}
            {r.verdictCorrect
              ? <span className="text-neon-green">matches the evidence</span>
              : <span className="text-severity-high">does not match the evidence</span>}
            {" · "}cited {r.iocsCited} of {r.iocsTotal} key indicators
            {r.fabricated ? <span className="text-severity-high"> · {r.fabricated} cited indicator{r.fabricated !== 1 ? "s" : ""} not in the telemetry</span> : null}
          </p>
          {bd ? (
            <div className="mt-3 space-y-3">
              {bd.summary && <p className="text-xs leading-relaxed text-slate-300">{bd.summary}</p>}
              <ul className="space-y-1.5">
                {bd.items.map(it => (
                  <li key={it.key} className="flex gap-3 text-[11px]">
                    <span className="w-28 shrink-0 text-slate-300">{it.label}</span>
                    <span className={cn("w-14 shrink-0 font-mono", it.points >= it.max ? "text-neon-green" : "text-slate-200")}>{it.points}/{it.max}</span>
                    <span className="text-slate-400">{it.detail}</span>
                  </li>
                ))}
              </ul>
              {bd.cappedByVerdict && (
                <p className="text-[11px] text-severity-high">The report score was capped because the verdict does not match the evidence.</p>
              )}
              {/* Indicators are shown only when the server released them. */}
              {(bd.citedIndicators.length > 0 || (bd.missedIndicators && bd.missedIndicators.length > 0)) && (
                <div className="grid gap-3 sm:grid-cols-2">
                  {bd.citedIndicators.length > 0 && (
                    <div>
                      <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-neon-green/80">Key indicators you cited</p>
                      <ul className="space-y-0.5">{bd.citedIndicators.map(v => <li key={v} className="break-all font-mono text-[10px] text-slate-300">{v}</li>)}</ul>
                    </div>
                  )}
                  {bd.missedIndicators && bd.missedIndicators.length > 0 && (
                    <div>
                      <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-severity-high/80">Key indicators you missed</p>
                      <ul className="space-y-0.5">{bd.missedIndicators.map(v => <li key={v} className="break-all font-mono text-[10px] text-slate-300">{v}</li>)}</ul>
                    </div>
                  )}
                </div>
              )}
              {(bd.fabricatedValues.length > 0 || bd.misattributedValues.length > 0) && (
                <p className="text-[11px] text-severity-high">
                  {bd.fabricatedValues.length > 0 && <>Not in the telemetry: <span className="font-mono">{bd.fabricatedValues.join(", ")}</span>. </>}
                  {bd.misattributedValues.length > 0 && <>Benign/internal tagged as hostile: <span className="font-mono">{bd.misattributedValues.join(", ")}</span>.</>}
                </p>
              )}
              {bd.improvements.length > 0 && (
                <div>
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">What a senior analyst would add</p>
                  <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-slate-300">
                    {bd.improvements.map((t, i) => <li key={i}>{t}</li>)}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="mt-2 flex flex-wrap gap-2">
              {Object.entries(r.rubric).map(([k, v]) => (
                <span key={k} className="rounded border border-border bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-slate-300">
                  {k} {v}
                </span>
              ))}
            </div>
          )}
          {xp.note && <p className="mt-2 text-[11px] text-slate-400">{xp.note}</p>}
        </div>
      )}

      {result.aiFeedback && (
        <div className="rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-cyber-300/70">Analyst feedback</p>
          <p className="text-xs leading-relaxed text-slate-300">{result.aiFeedback}</p>
        </div>
      )}

      <div>
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">Question results</p>
        <ol className="space-y-2">
          {result.perQuestion.map((pq, i) => {
            const q = qById.get(pq.id);
            const shown = q ? displayedOptions(q) : [];
            // Letter of an option LABEL as the learner saw it ("B. …").
            const letterOf = (label: string) => {
              const idx = shown.findIndex(o => o.label === label);
              return idx >= 0 ? `${optionLetter(idx)}. ` : "";
            };
            const fmt = (a: string | string[] | null) =>
              a == null ? null : (Array.isArray(a) ? a : [a]).map(l => `${letterOf(l)}${l}`).join(" · ");
            const explanation = remapExplanation(pq.explanation, q);
            return (
              <li key={pq.id} className={cn(
                "rounded border px-3 py-2.5",
                pq.correct ? "border-neon-green/20 bg-neon-green/5" : "border-severity-high/20 bg-severity-high/5",
              )}>
                <div className="flex items-start gap-2">
                  {pq.correct
                    ? <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neon-green" />
                    : <ShieldX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-severity-high" />}
                  <div className="min-w-0 space-y-1">
                    <p className="text-xs text-slate-200">
                      <span className="mr-1.5 font-mono text-[10px] text-slate-400">Q{i + 1}.</span>{pq.prompt}
                    </p>
                    <p className="text-[11px] text-slate-400">
                      Your answer: <span className={pq.correct ? "text-neon-green" : "text-severity-high"}>{fmt(pq.yourAnswer) || "—"}</span>
                    </p>
                    {!pq.correct && pq.correctAnswer != null && (
                      <p className="text-[11px] text-slate-400">
                        Correct: <span className="text-neon-green">{fmt(pq.correctAnswer)}</span>
                      </p>
                    )}
                    {explanation && <p className="text-[11px] leading-relaxed text-slate-300">{explanation}</p>}
                  </div>
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-400">{pq.correct ? `+${pq.xp} XP` : "0 XP"}</span>
                </div>
              </li>
            );
          })}
        </ol>
      </div>

      {result.debrief?.killchain && result.debrief.killchain.length > 0 ? (
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400">Attack timeline</p>
          <ol className="space-y-1">
            {[...result.debrief.killchain]
              .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())
              .map((k, i) => (
                <li key={i} className="flex gap-3 text-[11px]">
                  <span className="w-16 shrink-0 font-mono text-slate-400">{utcTime(k.ts)}</span>
                  <span className="w-32 shrink-0 font-semibold text-slate-200">{k.phase}</span>
                  <span className="text-slate-300">{k.action}</span>
                </li>
              ))}
          </ol>
        </div>
      ) : result.debriefWithheld ? (
        <p className="rounded border border-dashed border-border/60 px-4 py-3 text-[11px] text-slate-400">
          The full debrief (story and attack timeline) unlocks on a complete attempt — answer every question and write a report.
        </p>
      ) : null}

      {edrOpen && investigations.length > 0 && (
        <ScenarioEdrPanel investigations={investigations} caseId={investigations[0].id} onClose={() => setEdrOpen(false)} />
      )}
    </div>
  );
}

// ─── Main client component ────────────────────────────────────────────────────

export function ScenarioClient({ bundle, slug, iocTruth = null }: {
  bundle: ScenarioBundle;
  slug: string;
  /** Digest-keyed IOC verdicts computed server-side from the FULL bundle. */
  iocTruth?: IocTruth | null;
}) {
  const [phase, setPhase]               = useState<Phase>("idle");
  // Native-format logs (docs/log-schemas), each in its authored vendor's format.
  // The 32 source modules load lazily.
  const [nativeMod, setNativeMod] = useState<typeof import("@/lib/logs/native") | null>(null);
  useEffect(() => {
    let alive = true;
    import("@/lib/logs/native").then(m => { if (alive) setNativeMod(m); }).catch(() => { /* legacy view stays */ });
    return () => { alive = false; };
  }, []);
  const nativeRender = useMemo<NativeRenderer | null>(() => (nativeMod ? ev => nativeMod.nativeViewAuthored(ev) : null), [nativeMod]);
  // Hydration gate (finding #28): the Start button is inert until the client has
  // mounted, so the first click is never swallowed by a not-yet-hydrated button.
  const [mounted, setMounted]           = useState(false);
  // Persisted investigation start (epoch ms) — see investigationClock.ts.
  const [startMs, setStartMs]           = useState<number | null>(null);
  // Final wall-clock time, frozen at submit for the score card / debrief.
  const [timeTaken, setTimeTaken]       = useState(0);
  // Answers are keyed by OPAQUE per-load option tokens (finding #4) and decoded
  // to real option ids only in the grade request.
  const [answers, setAnswers]           = useState<Record<string, string | string[]>>({});
  const [tokens, setTokens]             = useState<OptionTokenMap | null>(null);
  const [gradeResult, setGradeResult]   = useState<GradeResult | null>(null);
  const [showScoreCard, setShowScoreCard] = useState(false);
  const [isGrading, setIsGrading]       = useState(false);
  const [gradingError, setGradingError] = useState<string | null>(null);

  // Investigation log state. The two free-text fields live in refs and their
  // own DraftTextarea state (finding #29); the page only re-renders when the
  // narrative crosses the "section done" threshold.
  const notesRef                            = useRef("");
  const reasonRef                           = useRef("");
  const [notesFilled, setNotesFilled]       = useState(false);
  const [draftKey, setDraftKey]             = useState(0);
  const [manualIocs, setManualIocs]         = useState<ManualIoc[]>([]);
  const [verdict, setVerdict]               = useState<"tp" | "fp" | null>(null);
  const [submittedVerdict, setSubmittedVerdict] = useState<"tp" | "fp" | null>(null);

  const alertCount = useMemo(() => buildAlertIndex(bundle.events).size, [bundle.events]);

  // Mount: fresh option tokens (client-only — the questions are not rendered
  // before Start, so there is no SSR markup to mismatch) and resume a running
  // investigation after a reload.
  useEffect(() => {
    setTokens(buildOptionTokens(bundle.questions, cryptoRandom));
    const resumed = loadInvestigationStart(slug);
    if (resumed !== null) {
      setStartMs(resumed);
      setPhase("investigating");
    }
    setMounted(true);
  }, [bundle.questions, slug]);

  const handleNotesChange = useCallback((v: string) => {
    notesRef.current = v;
    setNotesFilled(v.trim().length > 10); // bail-out render when unchanged
  }, []);
  const handleReasonChange = useCallback((v: string) => { reasonRef.current = v; }, []);

  const resetDraft = () => {
    setAnswers({});
    setManualIocs([]);
    notesRef.current = "";
    reasonRef.current = "";
    setNotesFilled(false);
    setDraftKey(k => k + 1);
    setVerdict(null);
    setGradeResult(null);
    setGradingError(null);
    setShowScoreCard(false);
  };

  const handleStart = () => {
    if (!mounted) return;
    const now = Date.now();
    resetDraft();
    setStartMs(now);
    saveInvestigationStart(slug, now);
    setPhase("investigating");
  };

  const handleRetry = () => {
    resetDraft();
    clearInvestigationStart(slug);
    setStartMs(null);
    setTimeTaken(0);
    // New tokens per attempt, too.
    setTokens(buildOptionTokens(bundle.questions, cryptoRandom));
    setPhase("idle");
  };

  const handleAnswer = useCallback((questionId: string, token: string, multi: boolean) => {
    if (phase !== "investigating") return;
    setAnswers(prev => {
      if (multi) {
        const existing = (prev[questionId] as string[] | undefined) ?? [];
        const next = existing.includes(token)
          ? existing.filter(v => v !== token)
          : [...existing, token];
        return { ...prev, [questionId]: next };
      }
      return { ...prev, [questionId]: token };
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

  const canSubmit = allAnswered && verdict !== null && !isGrading && !!tokens;

  // Explanations cite authored option letters; options are shuffled for
  // display. The score card gets the same letter-remapped copy the debrief
  // renders (finding #15). CompletionModal itself is unchanged.
  const displayResult = useMemo<GradeResult | null>(() => {
    if (!gradeResult) return null;
    const qById = new Map(bundle.questions.map(q => [q.id, q]));
    return {
      ...gradeResult,
      perQuestion: gradeResult.perQuestion.map(pq => ({
        ...pq,
        explanation: remapExplanation(pq.explanation, qById.get(pq.id)),
      })),
    };
  }, [gradeResult, bundle.questions]);

  const handleSubmit = async () => {
    if (!canSubmit || !tokens) return;
    const taken = elapsedSeconds(startMs);
    const notes = notesRef.current;
    const verdictReason = reasonRef.current;
    setPhase("submitted");
    setIsGrading(true);
    setGradingError(null);
    try {
      const res = await fetch(`/api/scenarios/${encodeURIComponent(slug)}/grade`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          // Tokens → real option ids. The server grades exactly as before.
          answers: decodeAnswers(answers, tokens),
          // Wall time since the persisted start. NOT graded (FB-007) — the grade
          // route only stores it on the scenario_history row it writes.
          timeTaken: taken,
          iocTagged: manualIocs.length,
          verdict,
          verdictReason,
          analystNotes: notes,
          indicators: manualIocs,
        }),
      });
      if (!res.ok) throw new ApiError(await messageFromResponse(res), res.status);
      const result: GradeResult = await res.json();
      setGradeResult(result);
      setTimeTaken(taken);
      setSubmittedVerdict(verdict);
      setShowScoreCard(true);
      setPhase("complete");
      // The run is over — a reload must not resume its clock.
      clearInvestigationStart(slug);

      // The grade route is the only server-side writer of scenario_history.
      // recordScenarioCompletion mirrors the attempt into the facade (the local
      // copy /progress reads for guests) and moves the displayed XP total
      // truthfully: the server's authoritative totalXp when present, else only
      // the improvement over the best attempt (#30) — never the full run XP.
      try {
        recordScenarioCompletion({
          slug,
          title: bundle.title,
          score:    result.score,
          // FB-007: XP is accuracy + report quality only — no speed bonus.
          xpEarned: result.xpEarned,
          timeTaken: taken,
          date: new Date().toISOString(),
          // Keep the actual written deliverable, not just the score, so it can be
          // reviewed later (and surfaced to instructors in the org console).
          report: {
            verdict,
            verdictReason,
            notes,
            reportScore: result.report?.score,
            rubric: result.report?.rubric,
            passed: result.passed,
          },
        }, result);
      } catch { /* ignore storage errors */ }
    } catch (e) {
      setGradingError(`Could not submit — ${userMessageFor(e)} Your answers are still here.`);   // E-09
      setPhase("investigating");
    } finally {
      setIsGrading(false);
    }
  };

  return (
    <NativeLogProvider value={nativeRender}>
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
              disabled={!mounted}
              aria-busy={!mounted}
              className="flex items-center gap-2 rounded border border-cyber-500/30 bg-cyber-500/10 px-4 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 transition disabled:cursor-wait disabled:opacity-50"
            >
              <Play className="h-4 w-4" /> {mounted ? "Start Investigation" : "Loading…"}
            </button>
          )}
          {phase === "investigating" && (
            <>
              <div className="flex items-center gap-3 rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-1.5">
                <span className="h-2 w-2 rounded-full bg-cyber-400 animate-pulse" />
                <InvestigationTimer startMs={startMs} />
                <span className="text-xs text-slate-400">Investigation Time</span>
              </div>
              {/* Progress indicators */}
              <div className="flex items-center gap-3 text-xs text-slate-400">
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
                  <span className="text-[11px] text-slate-400">
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
          {phase === "complete" && gradeResult && (
            <div className="flex w-full flex-wrap items-center gap-3 text-sm">
              <span className={cn("font-semibold", gradeResult.passed ? "text-neon-green" : "text-severity-high")}>
                {gradeResult.passed ? "Completed — passed" : "Completed — not passed"} · {gradeResult.score}%
              </span>
              <span className="flex items-center gap-1 text-xs text-slate-400">
                <Clock className="h-3.5 w-3.5" /> {formatTime(timeTaken)}
              </span>
              <button
                onClick={handleRetry}
                className="ml-auto flex items-center gap-1.5 rounded border border-cyber-500/30 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition hover:bg-cyber-500/20"
              >
                <RotateCcw className="h-3.5 w-3.5" /> Retry
              </button>
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
            {/* Same classification as the table's ALERT badges (eventClass.ts),
                so this count always equals the badges shown (finding #5). */}
            <Badge variant="outline">{alertCount} alert{alertCount !== 1 ? "s" : ""}</Badge>
            <Badge variant="outline">{bundle.events.length} events</Badge>
          </div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2">
            {phase === "complete" ? "What actually happened" : "Reported by"}
          </p>
          <p className="text-sm leading-relaxed text-slate-300">
            {phase === "complete"
              ? (gradeResult?.debrief?.narrative || bundle.narrative || "The full story unlocks on a complete attempt.")
              : (bundle.briefing ?? "An alert fired on a monitored asset and was queued for triage. Work the log evidence below and write up what you find.")}
          </p>
          {phase !== "complete" && (
            <p className="mt-3 border-t border-border/40 pt-3 text-xs text-slate-400">
              Everything else — what happened, in what order, and how far it got — is yours
              to reconstruct from the evidence.
            </p>
          )}
        </div>

        {/* Learning objectives name the techniques the questions ask about
            ("PsExec lateral movement via SMB pass-the-hash" answers the lateral
            movement question outright), so they belong in the debrief too. */}
        {phase === "complete" && (gradeResult?.debrief?.learningObjectives ?? bundle.learning_objectives).length > 0 && (
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

        {/* Completed state — summary, per-question results, retry (finding #31). */}
        {phase === "complete" && gradeResult && (
          <ScenarioDebrief
            result={gradeResult}
            questions={bundle.questions}
            events={bundle.events}
            title={bundle.title}
            iocTruth={iocTruth}
            timeTaken={timeTaken}
            verdict={submittedVerdict}
            onRetry={handleRetry}
            onShowScoreCard={() => setShowScoreCard(true)}
          />
        )}

        {/* Security Events Log */}
        <ScenarioLogViewer events={bundle.events} title={bundle.title} iocTruth={iocTruth} />

        {/* Investigation Panel */}
        <InvestigationPanel
          phase={phase}
          draftKey={draftKey}
          notesRef={notesRef}
          notesFilled={notesFilled}
          onNotesChange={handleNotesChange}
          iocs={manualIocs}
          onAddIoc={handleAddIoc}
          onRemoveIoc={handleRemoveIoc}
          verdict={verdict}
          onVerdictChange={setVerdict}
          reasonRef={reasonRef}
          onVerdictReasonChange={handleReasonChange}
          onSubmit={handleSubmit}
          quizComplete={allAnswered}
        />

        {/* Analyst Quiz — the per-question results replace it once complete. */}
        {phase !== "complete" && (
        <Card>
          <h3 className="text-sm font-semibold text-white">Analyst Quiz</h3>
          <p className="mt-1 text-xs text-slate-400">
            {phase === "idle"
              ? "Click \"Start Investigation\" above to begin. The timer is just for your reference — take the time you need; it doesn't affect your score or XP."
              : "Answer all questions then submit your investigation."}
          </p>
          {/* Finding #4: the questions are not shown before the investigation
              starts — reading them first turns the logs into a lookup exercise.
              (Grading and the answer key are server-side regardless.) */}
          {phase === "idle" || !tokens ? (
            <div className="mt-4 flex items-center gap-3 rounded-md border border-dashed border-border/60 px-4 py-6 text-xs text-slate-400">
              <Lock className="h-4 w-4 shrink-0 text-slate-500" />
              {bundle.questions.length} question{bundle.questions.length !== 1 ? "s" : ""} unlock when you start the investigation.
            </div>
          ) : (
          <ol className="mt-4 space-y-5">
            {bundle.questions.map((q, idx) => {
              const isMulti = q.kind === "multi";
              const currentAnswer = answers[q.id];
              const answered = Array.isArray(currentAnswer) ? currentAnswer.length > 0 : !!currentAnswer;
              const qTokens = tokens.toToken.get(q.id);

              return (
                <li key={q.id} className={cn(
                  "rounded-md border p-4 transition-colors",
                  answered ? "border-cyber-500/30 bg-cyber-500/5" : "border-border bg-bg"
                )}>
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm text-slate-100">
                      <span className="mr-2 font-mono text-cyber-300">Q{idx + 1}.</span>
                      {q.prompt}
                      {isMulti && <span className="ml-1 text-[10px] text-slate-400">(select all that apply)</span>}
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
                          Grading compares option ids to q.answer, never position, so
                          reordering is presentation-only. The letter shown here is
                          the one the remapped explanations cite. */}
                      {displayedOptions(q).map((o, di) => {
                        const token = qTokens?.get(o.value) ?? "";
                        const selected = isMulti
                          ? (currentAnswer as string[] | undefined)?.includes(token)
                          : currentAnswer === token;
                        return (
                          <li key={token || di}>
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
                                value={token}
                                checked={!!selected}
                                onChange={() => handleAnswer(q.id, token, isMulti)}
                                className="accent-cyber-400"
                              />
                              <span className="font-mono text-[10px] text-slate-400">{optionLetter(di)}.</span>
                              <span>{o.label}</span>
                            </label>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {q.hint && (
                    <p className="mt-2 text-[11px] text-slate-400 italic">Hint: {q.hint}</p>
                  )}
                </li>
              );
            })}
          </ol>
          )}
        </Card>
        )}
      </div>

      {/* Score card. "Continue" now just closes it — the page stays in its
          completed state instead of resetting to Start (finding #31). */}
      {phase === "complete" && displayResult && showScoreCard && (
        <CompletionModal
          result={displayResult}
          scenarioTitle={bundle.title}
          timeTaken={timeTaken}
          onRetry={handleRetry}
          onClose={() => setShowScoreCard(false)}
        />
      )}
    </div>
    </NativeLogProvider>
  );
}
