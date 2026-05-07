import { Topbar } from "@/components/nav/Topbar";
import { Card, StatCard } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { TACTICS, techniqueById } from "@/lib/mitre/attack";
import { formatTs, timeAgo, fmtBytes, truncate } from "@/lib/utils";
import { Activity, AlertTriangle, Eye, Flame, Shield, Siren, Users, Zap } from "lucide-react";
import Link from "next/link";

export const metadata = { title: "SOC Dashboard" };
export const dynamic = "force-static";

export default function DashboardPage() {
  // Build live-feeling data deterministically from the bundled scenarios.
  const a = buildPhishingToExfil();
  const b = buildBecScenario();
  const allAlerts = [...a.alerts, ...b.alerts].sort((x, y) => y.detected_at.localeCompare(x.detected_at));
  const allEvents = [...a.events, ...b.events];

  const open       = allAlerts.filter(a => !["resolved","false_positive","contained"].includes(a.status)).length;
  const critical   = allAlerts.filter(a => a.severity === "critical").length;
  const high       = allAlerts.filter(a => a.severity === "high").length;
  const medium     = allAlerts.filter(a => a.severity === "medium").length;
  const last24h    = allAlerts.length;

  // MITRE coverage rollup
  const techCount = new Map<string, number>();
  for (const al of allAlerts) {
    if (!al.mitre_technique) continue;
    techCount.set(al.mitre_technique, (techCount.get(al.mitre_technique) ?? 0) + 1);
  }
  const topTechniques = [...techCount.entries()]
    .map(([id, n]) => ({ id, n, name: techniqueById(id)?.name ?? id }))
    .sort((x, y) => y.n - x.n).slice(0, 6);

  // Top hostnames / users
  const hostCount = new Map<string, number>();
  const userCount = new Map<string, number>();
  for (const al of allAlerts) {
    if (al.hostname)  hostCount.set(al.hostname,  (hostCount.get(al.hostname)  ?? 0) + 1);
    if (al.user_email) userCount.set(al.user_email, (userCount.get(al.user_email) ?? 0) + 1);
  }
  const topHosts = [...hostCount.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5);
  const topUsers = [...userCount.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5);

  // Source breakdown
  const sourceCount = new Map<string, number>();
  for (const ev of allEvents) sourceCount.set(ev.source, (sourceCount.get(ev.source) ?? 0) + 1);
  const totalEvents = allEvents.length;

  return (
    <div>
      <Topbar
        title="SOC Dashboard"
        subtitle="Real-time view of alerts, telemetry, and analyst workload"
        actions={
          <>
            <Link href="/scenarios"><Button variant="outline" size="sm"><Zap className="h-4 w-4" /> Run Scenario</Button></Link>
            <Link href="/alerts"><Button variant="primary" size="sm"><Siren className="h-4 w-4" /> Alert Queue</Button></Link>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        {/* KPI strip */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
          <StatCard label="Open Alerts" value={open} icon={<Siren className="h-4 w-4" />} accent="cyber" delta={{ value: "+12 vs 24h", positive: false }} />
          <StatCard label="Critical" value={critical} icon={<Flame className="h-4 w-4" />} accent="red" />
          <StatCard label="High" value={high} icon={<AlertTriangle className="h-4 w-4" />} accent="amber" />
          <StatCard label="MTTT" value="4m 12s" icon={<Activity className="h-4 w-4" />} accent="green" delta={{ value: "-38s", positive: true }} />
          <StatCard label="Hosts at Risk" value={hostCount.size} icon={<Shield className="h-4 w-4" />} accent="purple" />
          <StatCard label="Users Affected" value={userCount.size} icon={<Users className="h-4 w-4" />} accent="cyber" />
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          {/* Live Alerts feed */}
          <Card padded={false} className="xl:col-span-2 overflow-hidden">
            <div className="flex items-center justify-between border-b border-border px-5 py-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Live Alert Feed</h3>
                <p className="text-xs text-slate-500">Stream from EDR, SIEM, Firewall, Identity, Cloud</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" /><span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" /></span>
                <span className="text-[10px] font-semibold uppercase tracking-widest text-neon-green">Streaming</span>
              </div>
            </div>
            <div className="max-h-[560px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-bg-elevated/95 backdrop-blur">
                  <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    <th className="px-5 py-2">Detected</th>
                    <th className="py-2">Sev</th>
                    <th className="py-2">UID</th>
                    <th className="py-2">Title</th>
                    <th className="py-2">Host / User</th>
                    <th className="py-2">MITRE</th>
                    <th className="py-2 pr-5">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {allAlerts.slice(0, 14).map(al => (
                    <tr key={al.id} className="border-t border-border/60 hover:bg-bg-hover">
                      <td className="px-5 py-2.5 font-mono text-[11px] text-slate-400">{formatTs(al.detected_at, "HH:mm:ss")}</td>
                      <td className="py-2.5"><SeverityBadge severity={al.severity} /></td>
                      <td className="py-2.5 font-mono text-cyber-300">{al.alert_uid}</td>
                      <td className="py-2.5 text-slate-200">{truncate(al.title, 56)}</td>
                      <td className="py-2.5">
                        <div className="flex flex-col">
                          {al.hostname && <span className="font-mono text-[11px] text-slate-300">{al.hostname}</span>}
                          {al.user_email && <span className="font-mono text-[10px] text-slate-500">{al.user_email}</span>}
                        </div>
                      </td>
                      <td className="py-2.5 font-mono text-[11px] text-neon-purple">{al.mitre_technique ?? "—"}</td>
                      <td className="py-2.5 pr-5"><StatusBadge status={al.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-border bg-bg-elevated px-5 py-2 text-right">
              <Link href="/alerts" className="text-xs font-semibold text-cyber-300 hover:text-cyber-200">View full alert queue →</Link>
            </div>
          </Card>

          {/* MITRE coverage */}
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">MITRE ATT&amp;CK Hits</h3>
              <Link href="/mitre" className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Heatmap →</Link>
            </div>
            <ul className="mt-4 space-y-3">
              {topTechniques.map(t => (
                <li key={t.id}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-cyber-300">{t.id}</span>
                    <span className="text-slate-400">{t.name}</span>
                    <span className="font-mono text-slate-300">×{t.n}</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded bg-bg">
                    <div className="h-full bg-gradient-to-r from-cyber-500 to-neon-purple"
                         style={{ width: `${Math.min(100, (t.n / topTechniques[0].n) * 100)}%` }} />
                  </div>
                </li>
              ))}
            </ul>

            <div className="mt-6 grid grid-cols-2 gap-2">
              {TACTICS.slice(2, 14).map(tac => (
                <div key={tac.id} className="rounded border border-border bg-bg p-2">
                  <p className="font-mono text-[10px] text-slate-500">{tac.id}</p>
                  <p className="text-xs text-slate-200">{tac.short}</p>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Lower row */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card>
            <h3 className="text-sm font-semibold text-white">Top Hosts at Risk</h3>
            <ul className="mt-3 divide-y divide-border">
              {topHosts.map(([h, n]) => (
                <li key={h} className="flex items-center justify-between py-2">
                  <span className="font-mono text-xs text-slate-200">{h}</span>
                  <span className="rounded bg-severity-critical/10 px-2 py-0.5 font-mono text-[10px] font-bold text-severity-critical">{n} alerts</span>
                </li>
              ))}
              {topHosts.length === 0 && <li className="py-3 text-xs text-slate-500">No host activity in window.</li>}
            </ul>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Top Users at Risk</h3>
            <ul className="mt-3 divide-y divide-border">
              {topUsers.map(([u, n]) => (
                <li key={u} className="flex items-center justify-between py-2">
                  <span className="font-mono text-xs text-slate-200">{u}</span>
                  <span className="rounded bg-severity-high/10 px-2 py-0.5 font-mono text-[10px] font-bold text-severity-high">{n} alerts</span>
                </li>
              ))}
              {topUsers.length === 0 && <li className="py-3 text-xs text-slate-500">No user activity in window.</li>}
            </ul>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Telemetry Sources</h3>
            <p className="mt-1 text-xs text-slate-500">{totalEvents.toLocaleString()} events ingested · last 24h</p>
            <ul className="mt-3 space-y-2">
              {[...sourceCount.entries()].sort((x, y) => y[1] - x[1]).map(([src, n]) => (
                <li key={src}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono uppercase text-slate-300">{src}</span>
                    <span className="font-mono text-slate-500">{n}</span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded bg-bg">
                    <div className="h-full bg-cyber-500" style={{ width: `${(n / totalEvents) * 100}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        {/* Active scenario banner */}
        <Card className="border-cyber-500/30 bg-gradient-to-br from-cyber-500/5 to-neon-purple/5">
          <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
            <div className="flex items-start gap-4">
              <div className="rounded-md border border-cyber-500/40 bg-cyber-500/10 p-3 text-cyber-300"><Eye className="h-5 w-5" /></div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Active simulation</p>
                <h3 className="mt-1 text-lg font-bold text-white">{a.title}</h3>
                <p className="mt-1 max-w-2xl text-sm text-slate-300">
                  Threat actor <span className="font-mono text-neon-purple">{a.threat_actor}</span> ·{" "}
                  {a.alerts.length} alerts · {a.iocs.length} IOCs · {a.events.length} telemetry events.
                  Started {timeAgo(a.events[0]?.ts ?? Date.now())}.
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              <Link href={`/scenarios/${"phishing-to-cloud-exfil"}`}><Button variant="primary" size="sm">Open Scenario</Button></Link>
              <Link href="/investigations"><Button variant="secondary" size="sm">My Investigations</Button></Link>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
