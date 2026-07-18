"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Loader2, ChevronRight, ChevronLeft, Zap, Shield, Skull,
  Cloud, Users, Globe, Key, Shuffle, Info, BookMarked, Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import type { TelemetryEvent } from "@/lib/sim/types";

// ─── Types ────────────────────────────────────────────────────────────────────

interface GeneratedScenario {
  title: string;
  threat_actor: string;
  attack_kind: string;
  difficulty: string;
  narrative: string;
  events: TelemetryEvent[];
}

// ─── Attack type options ──────────────────────────────────────────────────────

const ATTACK_TYPES = [
  { id: "random",        label: "Random",               icon: Shuffle, color: "text-slate-300" },
  { id: "phishing",      label: "Phishing + Lateral",   icon: Zap,     color: "text-severity-high" },
  { id: "identity",      label: "Identity / BEC",        icon: Key,     color: "text-neon-amber" },
  { id: "ransomware",    label: "Ransomware",            icon: Skull,   color: "text-severity-critical" },
  { id: "cloud_apt",     label: "Cloud APT",             icon: Cloud,   color: "text-neon-blue" },
  { id: "insider",       label: "Insider Threat",        icon: Users,   color: "text-neon-purple" },
  { id: "webapp",        label: "Web App Attack",        icon: Globe,   color: "text-neon-green" },
  { id: "privilege_esc", label: "Privilege Escalation",  icon: Shield,  color: "text-cyber-300" },
] as const;

// ─── Source / severity helpers ────────────────────────────────────────────────

const SOURCE_COLORS: Record<string, string> = {
  edr:        "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  sysmon:     "bg-cyber-500/20 text-cyber-300 border-cyber-500/30",
  ad:         "bg-neon-blue/20 text-neon-blue border-neon-blue/30",
  o365:       "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  okta:       "bg-neon-amber/20 text-neon-amber border-neon-amber/30",
  firewall:   "bg-severity-high/20 text-severity-high border-severity-high/30",
  dns:        "bg-neon-green/20 text-neon-green border-neon-green/30",
  cloudtrail: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
  dlp:        "bg-neon-purple/20 text-neon-purple border-neon-purple/30",
  proxy:      "bg-slate-400/20 text-slate-300 border-slate-400/30",
  vpn:        "bg-slate-400/20 text-slate-300 border-slate-400/30",
};
const SOURCE_LABEL: Record<string, string> = {
  edr: "EDR", sysmon: "Sysmon", ad: "Active Directory", o365: "Office 365",
  okta: "Okta", firewall: "Firewall", dns: "DNS", vpn: "VPN",
  cloudtrail: "AWS/Azure", proxy: "Proxy", dlp: "DLP",
};
const SEV_COLORS: Record<string, string> = {
  critical:      "text-severity-critical",
  high:          "text-severity-high",
  medium:        "text-severity-medium",
  low:           "text-slate-300",
  informational: "text-slate-500",
};

// ─── Event row ────────────────────────────────────────────────────────────────

function EventRow({ ev }: { ev: TelemetryEvent }) {
  const [expanded, setExpanded] = useState(false);
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
    ...(ev.process?.name   ? [["process.name",        ev.process.name] as [string, string]] : []),
    ...(ev.process?.cmdline ? [["process.command_line", ev.process.cmdline] as [string, string]] : []),
    ...(ev.process?.parent_name ? [["process.parent.name", ev.process.parent_name] as [string, string]] : []),
    ...(ev.file?.path   ? [["file.path",        ev.file.path]   as [string, string]] : []),
    ...(ev.file?.sha256 ? [["file.hash.sha256", ev.file.sha256] as [string, string]] : []),
    ...Object.entries(ev.raw ?? {})
      .filter(([, v]) => v !== null && v !== undefined && v !== "" && typeof v !== "object" && typeof v !== "boolean")
      .map(([k, v]) => [k, String(v)] as [string, string]),
    ...Object.entries(ev.raw ?? {})
      .filter(([, v]) => typeof v === "boolean")
      .map(([k, v]) => [k, v ? "true" : "false"] as [string, string]),
  ];

  return (
    <>
      <tr
        onClick={() => setExpanded(v => !v)}
        className={cn(
          "cursor-pointer border-t border-border/40 transition-colors",
          expanded ? "bg-bg-hover" : "hover:bg-bg-hover/50",
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
          <span className={cn("font-mono text-[11px] font-semibold uppercase", SEV_COLORS[ev.severity ?? "informational"])}>
            {(ev.severity ?? "info").slice(0, 4).toUpperCase()}
          </span>
        </td>
        <td className="py-2.5 pr-4 text-[11px] text-slate-300 max-w-sm">
          <span className="line-clamp-2">{ev.description ?? ev.event_type}</span>
        </td>
        <td className="py-2.5 pr-4 font-mono text-[10px] text-slate-500 whitespace-nowrap">
          {ev.mitre_technique ?? "—"}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="bg-[#060b12] p-0">
            <div className="border-t border-border/40 px-5 py-4 space-y-3">
              {ev.description && (
                <div className="rounded border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-cyber-300/70">Event Description</p>
                  <p className="text-xs leading-relaxed text-slate-200">{ev.description}</p>
                </div>
              )}
              <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3">
                <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Log Fields (ECS)</p>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                  {ecsFields.map(([k, v]) => (
                    <div key={k} className="flex gap-2 min-w-0">
                      <span className="w-44 shrink-0 font-mono text-[10px] text-slate-500 truncate">{k}</span>
                      <span className="font-mono text-[10px] text-slate-300 break-all">{v}</span>
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

// ─── Inline content (used as a tab, no modal wrapper) ─────────────────────────

export function AdminScenarioGeneratorContent() {
  const router = useRouter();
  const [attackType, setAttackType]   = useState<string>("random");
  const [loading, setLoading]         = useState(false);
  const [scenario, setScenario]       = useState<GeneratedScenario | null>(null);
  const [error, setError]             = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [published, setPublished]     = useState(false);

  async function generate() {
    setLoading(true);
    setScenario(null);
    setError(null);
    try {
      const res = await fetch("/api/scenarios/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attackType }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error ?? "Generation failed");
      setScenario(data);
      setPublished(false);
      setSidebarOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  function startInvestigation() {
    if (!scenario) return;
    sessionStorage.setItem("generated_scenario", JSON.stringify(scenario));
    router.push("/scenarios/preview");
  }

  function publishScenario() {
    if (!scenario) return;
    try {
      const existing = JSON.parse(localStorage.getItem("published_scenarios") ?? "[]");
      const entry = { ...scenario, published_at: new Date().toISOString(), id: `gen-${Date.now()}` };
      localStorage.setItem("published_scenarios", JSON.stringify([entry, ...existing]));
      setPublished(true);
    } catch {
      // localStorage not available
    }
  }

  return (
    <div className="flex h-full min-h-0 overflow-hidden rounded border border-border bg-[#050a10]">

      {/* ── Attack type sidebar ─────────────────────────────────────── */}
      <div className={cn(
        "shrink-0 border-r border-border flex flex-col transition-all duration-200",
        sidebarOpen ? "w-52" : "w-11"
      )}>
        {sidebarOpen ? (
          <div className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
            <div className="flex items-center justify-between mb-3 px-1">
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Attack Type</p>
              <button onClick={() => setSidebarOpen(false)} className="rounded p-0.5 text-slate-500 hover:text-slate-300 transition-colors">
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
            </div>
            {ATTACK_TYPES.map(t => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setAttackType(t.id)}
                  className={cn(
                    "w-full flex items-center gap-2.5 rounded px-3 py-2 text-left text-[12px] transition-colors",
                    attackType === t.id
                      ? "bg-cyber-500/15 text-white border border-cyber-500/30"
                      : "text-slate-400 hover:bg-border/60 hover:text-slate-200"
                  )}
                >
                  <Icon className={cn("h-3.5 w-3.5 shrink-0", attackType === t.id ? t.color : "text-slate-500")} />
                  {t.label}
                </button>
              );
            })}
            <div className="pt-4">
              <Button variant="primary" size="sm" className="w-full justify-center" onClick={generate} disabled={loading}>
                {loading
                  ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Generating…</>
                  : <><Zap className="h-3.5 w-3.5" /> Generate</>
                }
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center py-3 gap-1.5">
            <button onClick={() => setSidebarOpen(true)} title="Expand" className="rounded p-1.5 text-slate-500 hover:bg-border hover:text-slate-200 transition-colors">
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
            <div className="my-1 h-px w-6 bg-border/60" />
            {ATTACK_TYPES.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.id} onClick={() => { setAttackType(t.id); setSidebarOpen(true); }} title={t.label}
                  className={cn("rounded p-1.5 transition-colors", attackType === t.id ? "bg-cyber-500/20 text-cyber-300" : "text-slate-600 hover:text-slate-300 hover:bg-border/60")}>
                  <Icon className="h-3.5 w-3.5" />
                </button>
              );
            })}
            <div className="my-1 h-px w-6 bg-border/60" />
            <button onClick={generate} disabled={loading} title="Re-generate" className="rounded p-1.5 text-cyber-300 hover:bg-cyber-500/20 transition-colors disabled:opacity-40">
              {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            </button>
          </div>
        )}
      </div>

      {/* ── Main area ──────────────────────────────────────────────── */}
      <div className="flex-1 overflow-hidden flex flex-col">

        {/* Empty state */}
        {!loading && !scenario && !error && (
          <div className="flex h-full items-center justify-center">
            <div className="text-center space-y-3">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-border bg-[#0d1520]">
                <Zap className="h-7 w-7 text-cyber-300/40" />
              </div>
              <p className="text-sm text-slate-400">Select an attack type and click Generate</p>
              <p className="text-[11px] text-slate-600">Creates a realistic incident with 11 matching log events</p>
            </div>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="flex h-full items-center justify-center">
            <div className="text-center space-y-4">
              <Loader2 className="mx-auto h-8 w-8 animate-spin text-cyber-300" />
              <p className="text-sm text-slate-300">Generating incident scenario…</p>
              <p className="text-[11px] text-slate-500">Writing narrative and crafting log events</p>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="m-5 rounded border border-severity-critical/30 bg-severity-critical/10 px-4 py-3">
            <p className="text-sm text-severity-critical">Generation failed: {error}</p>
          </div>
        )}

        {/* Generated scenario — 2-panel split */}
        {scenario && !loading && (
          <div className="flex flex-1 min-h-0 overflow-hidden">

            {/* Left: info + narrative */}
            <div className="w-72 shrink-0 border-r border-border overflow-y-auto flex flex-col gap-4 px-5 py-5">
              <div>
                <h2 className="text-base font-bold leading-snug text-white">{scenario.title}</h2>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Badge variant="outline">{scenario.difficulty}</Badge>
                  <Badge variant="outline">{scenario.attack_kind.replace(/_/g, " ")}</Badge>
                  <span className="rounded bg-neon-green/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-neon-green font-semibold">AI Generated</span>
                </div>
                <p className="mt-2 font-mono text-[11px] text-slate-400">{scenario.threat_actor}</p>
              </div>

              <div className="rounded border border-border bg-[#0d1520] px-4 py-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 flex items-center gap-1.5">
                  <Info className="h-3 w-3" /> Incident Briefing
                </p>
                <div className="space-y-2">
                  {scenario.narrative.split(/\n+/).filter(Boolean).map((para, i) => (
                    <p key={i} className="text-[11px] leading-relaxed text-slate-300">{para}</p>
                  ))}
                </div>
              </div>

              <div className="rounded border border-border bg-[#0d1520] px-4 py-3 space-y-1.5">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Event Summary</p>
                <div className="space-y-1 text-[11px]">
                  {[
                    ["Total events",  String(scenario.events.length),                                                                     "text-white"],
                    ["MITRE mapped",  String(scenario.events.filter(e => e.mitre_technique).length),                                       "text-cyber-300"],
                    ["High / Critical", String(scenario.events.filter(e => e.severity === "critical" || e.severity === "high").length),    "text-severity-high"],
                    ["Log sources",   String(new Set(scenario.events.map(e => e.source)).size),                                            "text-slate-300"],
                  ].map(([label, val, cls]) => (
                    <div key={label} className="flex justify-between">
                      <span className="text-slate-500">{label}</span>
                      <span className={cn("font-mono", cls)}>{val}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-auto space-y-2">
                <Button variant="primary" className="w-full justify-center" onClick={startInvestigation}>
                  <Shield className="h-4 w-4" /> Start Investigation
                </Button>
                <Button
                  variant="secondary"
                  className="w-full justify-center"
                  onClick={publishScenario}
                  disabled={published}
                >
                  {published
                    ? <><Check className="h-4 w-4 text-neon-green" /> Published</>
                    : <><BookMarked className="h-4 w-4" /> Publish Scenario</>
                  }
                </Button>
              </div>
            </div>

            {/* Right: full-height log table */}
            <div className="flex-1 flex flex-col overflow-hidden bg-[#050a10]">
              <div className="flex items-center justify-between border-b border-border/60 px-5 py-3 shrink-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Log Timeline — {scenario.events.length} events
                </p>
                <span className="text-[10px] text-slate-600">Click any row to expand fields</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-[#050a10]/95 backdrop-blur z-10">
                    <tr className="border-b border-border/40">
                      <th className="w-6 pl-3" />
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Time</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Host</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Source</th>
                      <th className="py-2 pr-3 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Sev</th>
                      <th className="py-2 pr-4 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">Description</th>
                      <th className="py-2 pr-4 text-left font-mono text-[10px] text-slate-500 uppercase tracking-widest">MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scenario.events.map(ev => (
                      <EventRow key={ev.id} ev={ev} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  );
}
