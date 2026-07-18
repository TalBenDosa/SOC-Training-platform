"use client";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { Term } from "@/components/ui/Term";
import type { LiveEvent } from "./useLiveEvents";

const SOURCE_LABEL: Record<string, string> = {
  edr: "EDR", sysmon: "Sysmon", ad: "AD", o365: "O365", gws: "GWS",
  okta: "Okta", firewall: "FW", dns: "DNS", vpn: "VPN",
  cloudtrail: "Cloud", proxy: "Proxy",
};

function mode<T>(arr: T[]): T | undefined {
  if (arr.length === 0) return undefined;
  const counts = new Map<T, number>();
  for (const item of arr) counts.set(item, (counts.get(item) ?? 0) + 1);
  let best: T | undefined; let bestCount = 0;
  for (const [item, count] of Array.from(counts.entries())) {
    if (count > bestCount) { bestCount = count; best = item; }
  }
  return best;
}

function fmtTimer(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

function fmtSpeed(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

interface SiemStatsProps {
  events: LiveEvent[];
  attackTimerSeconds?: number | null;
  avgCatchMs?: number | null;
}

export function SiemStats({ events, attackTimerSeconds = null, avgCatchMs = null }: SiemStatsProps) {
  // Compact by default — beginners see the 4 chips that matter; "+ more" reveals the rest
  const [showAll, setShowAll] = useState(false);
  const fiveMinAgo = Date.now() - 5 * 60 * 1000;
  const recentCount = events.filter(e => new Date(e.ts).getTime() > fiveMinAgo).length;
  const eventsPerMin = (recentCount / 5).toFixed(1);

  const last50   = events.slice(0, 50);
  const topSrc   = mode(last50.map(e => e.source)) ?? "—";
  const topHost  = mode(last50.map(e => e.hostname).filter((h): h is string => !!h)) ?? "—";
  const uniqueIps = new Set(events.map(e => e.src_ip).filter((ip): ip is string => !!ip));
  const alertPct  = events.length === 0
    ? 0
    : (events.filter(e => e.ruleLevel >= 7).length / events.length) * 100;
  const alertRate = alertPct.toFixed(0);

  // Timer color (null/undefined = no active attack)
  const timerColor = attackTimerSeconds == null ? null
    : attackTimerSeconds < 60  ? "critical"
    : attackTimerSeconds < 120 ? "medium"
    : "green";

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-border/60 bg-[#0a0f18] px-5 py-2.5">

      {/* SLA Attack Timer — only visible during active attack */}
      {attackTimerSeconds != null && timerColor && (
        <div className={cn(
          "inline-flex items-center gap-2 rounded-md border px-3 py-1.5",
          timerColor === "critical" ? "border-severity-critical/60 bg-severity-critical/10 animate-pulse" :
          timerColor === "medium"   ? "border-severity-medium/50 bg-severity-medium/8" :
                                      "border-neon-green/40 bg-neon-green/8"
        )}>
          <span className="text-[10px] text-slate-500 font-medium"><Term k="sla">SLA</Term></span>
          <span className={cn(
            "font-mono text-[11px] font-bold",
            timerColor === "critical" ? "text-severity-critical" :
            timerColor === "medium"   ? "text-severity-medium"   : "text-neon-green"
          )}>⏱ {fmtTimer(attackTimerSeconds ?? 0)}</span>
        </div>
      )}

      {/* Events/min */}
      <div className="inline-flex items-center gap-2 rounded-md border border-cyber-500/30 bg-cyber-500/10 px-3 py-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-cyber-400 animate-pulse" />
        <span className="text-[10px] text-slate-500 font-medium">Events/min</span>
        <span className="font-mono text-[11px] font-bold text-cyber-300">{eventsPerMin}</span>
      </div>

      {/* Secondary chips — hidden in compact mode */}
      {showAll && (
        <>
          {/* Top Source */}
          <div className="inline-flex items-center gap-2 rounded-md border border-neon-amber/30 bg-neon-amber/8 px-3 py-1.5">
            <span className="text-[10px] text-slate-500 font-medium">Top Source</span>
            <span className="font-mono text-[11px] font-bold text-neon-amber">
              {SOURCE_LABEL[topSrc] ?? topSrc.toUpperCase()}
            </span>
          </div>

          {/* Top Host */}
          <div className="inline-flex items-center gap-2 rounded-md border border-neon-green/30 bg-neon-green/8 px-3 py-1.5">
            <span className="text-[10px] text-slate-500 font-medium">Top Host</span>
            <span className="font-mono text-[11px] font-bold text-neon-green">{topHost}</span>
          </div>

          {/* Unique IPs */}
          <div className="inline-flex items-center gap-2 rounded-md border border-neon-purple/30 bg-neon-purple/8 px-3 py-1.5">
            <span className="text-[10px] text-slate-500 font-medium">Unique IPs</span>
            <span className="font-mono text-[11px] font-bold text-neon-purple">{uniqueIps.size}</span>
          </div>
        </>
      )}

      {/* Alert Rate */}
      <div className={cn(
        "inline-flex items-center gap-2 rounded-md border px-3 py-1.5",
        alertPct >= 20
          ? "border-severity-critical/50 bg-severity-critical/10"
          : alertPct >= 5
          ? "border-severity-medium/40 bg-severity-medium/8"
          : "border-border/60 bg-bg/40"
      )}>
        <span className="text-[10px] text-slate-500 font-medium"><Term k="alert">Alert</Term> Rate</span>
        <span className={cn(
          "font-mono text-[11px] font-bold",
          alertPct >= 20 ? "text-severity-critical" :
          alertPct >= 5  ? "text-severity-medium"   : "text-slate-400"
        )}>
          {alertRate}%
        </span>
      </div>

      {/* Avg Catch Speed — only visible after catching at least one attack */}
      {showAll && avgCatchMs != null && (
        <div className="inline-flex items-center gap-2 rounded-md border border-cyber-500/30 bg-cyber-500/8 px-3 py-1.5">
          <span className="text-[10px] text-slate-500 font-medium">Avg Speed</span>
          <span className="font-mono text-[11px] font-bold text-cyber-300">{fmtSpeed(avgCatchMs)}</span>
        </div>
      )}

      {/* Compact-mode expander */}
      <button
        onClick={() => setShowAll(v => !v)}
        className="ml-auto text-[10px] font-semibold text-slate-500 hover:text-slate-300 transition"
      >
        {showAll ? "− less" : "+ more stats"}
      </button>

    </div>
  );
}
