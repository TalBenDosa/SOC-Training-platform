import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { formatTs } from "@/lib/utils";
import Link from "next/link";
import { Filter, FileDown, RefreshCw } from "lucide-react";

export const metadata = { title: "Alerts" };

export default function AlertsPage() {
  const all = [
    ...buildPhishingToExfil().alerts,
    ...buildBecScenario().alerts,
  ].sort((x, y) => y.detected_at.localeCompare(x.detected_at));

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 } as Record<string, number>;
  for (const a of all) sevCounts[a.severity] = (sevCounts[a.severity] ?? 0) + 1;

  return (
    <div>
      <Topbar
        title="Alert Queue"
        subtitle={`${all.length} alerts · ${sevCounts.critical} critical · ${sevCounts.high} high`}
        actions={
          <>
            <Button variant="secondary" size="sm"><RefreshCw className="h-4 w-4" /> Refresh</Button>
            <Button variant="secondary" size="sm"><FileDown className="h-4 w-4" /> Export</Button>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-4">
        {/* Filter bar */}
        <Card padded={false}>
          <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-3">
            <Filter className="h-4 w-4 text-slate-400" />
            <div className="flex gap-1.5">
              {["all","critical","high","medium","low"].map(s => (
                <button key={s}
                  className="rounded-md border border-border bg-bg-elevated px-2.5 py-1 text-[11px] font-semibold uppercase tracking-widest text-slate-300 hover:border-cyber-500/40 hover:text-cyber-200">
                  {s} {s !== "all" && <span className="ml-1 font-mono text-slate-500">{sevCounts[s] ?? 0}</span>}
                </button>
              ))}
            </div>
            <div className="ml-auto flex flex-wrap gap-1.5">
              {["EDR","SIEM","Firewall","O365","Okta","DNS","CloudTrail"].map(src => (
                <span key={src} className="rounded border border-border bg-bg px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">{src}</span>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-bg-elevated/80">
                <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-2.5">Detected</th>
                  <th className="py-2.5">Severity</th>
                  <th className="py-2.5">Vendor</th>
                  <th className="py-2.5">UID</th>
                  <th className="py-2.5">Title</th>
                  <th className="py-2.5">Host</th>
                  <th className="py-2.5">User</th>
                  <th className="py-2.5">Tactic</th>
                  <th className="py-2.5">Technique</th>
                  <th className="py-2.5">Risk</th>
                  <th className="py-2.5 pr-5">Status</th>
                </tr>
              </thead>
              <tbody>
                {all.map(a => (
                  <tr key={a.id} className="border-t border-border/60 transition hover:bg-bg-hover">
                    <td className="px-5 py-2.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {formatTs(a.detected_at, "MMM dd HH:mm:ss")}
                    </td>
                    <td className="py-2.5"><SeverityBadge severity={a.severity} /></td>
                    <td className="py-2.5 text-slate-300">{a.vendor}</td>
                    <td className="py-2.5">
                      <Link href={`/alerts/${a.id}`} className="font-mono text-cyber-300 hover:text-cyber-200">{a.alert_uid}</Link>
                    </td>
                    <td className="py-2.5 text-slate-200 max-w-[360px]"><span className="line-clamp-1">{a.title}</span></td>
                    <td className="py-2.5 font-mono text-[11px] text-slate-300">{a.hostname ?? "—"}</td>
                    <td className="py-2.5 font-mono text-[11px] text-slate-400">{a.user_email ?? "—"}</td>
                    <td className="py-2.5 font-mono text-[11px] text-neon-purple">{a.mitre_tactic ?? "—"}</td>
                    <td className="py-2.5 font-mono text-[11px] text-cyber-300">{a.mitre_technique ?? "—"}</td>
                    <td className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 overflow-hidden rounded bg-bg">
                          <div className="h-full bg-gradient-to-r from-severity-medium to-severity-critical"
                               style={{ width: `${a.risk_score}%` }} />
                        </div>
                        <span className="font-mono text-[10px] text-slate-400">{a.risk_score}</span>
                      </div>
                    </td>
                    <td className="py-2.5 pr-5"><StatusBadge status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="text-xs text-slate-500">
          Tip: click an alert UID to drill in. SOC analysts on this platform ingest a mix of CrowdStrike (CRWD-*),
          Microsoft Defender (MDE-*), Palo Alto (PAN-*), Okta (OKTA-*), AWS CloudTrail (AWS-*), and Sysmon-derived alerts.
        </div>
      </div>
    </div>
  );
}
