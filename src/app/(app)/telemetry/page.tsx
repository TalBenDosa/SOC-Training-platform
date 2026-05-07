import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { formatTs, truncate } from "@/lib/utils";

export const metadata = { title: "Live Telemetry" };

export default function TelemetryPage() {
  const events = [...buildPhishingToExfil().events, ...buildBecScenario().events]
    .sort((a, b) => b.ts.localeCompare(a.ts))
    .slice(0, 200);

  return (
    <div>
      <Topbar title="Live Telemetry" subtitle={`${events.length} normalized events from EDR / Sysmon / FW / DNS / O365 / Okta / CloudTrail`} />
      <div className="container mx-auto max-w-[1600px] px-6 py-6">
        <Card padded={false}>
          <div className="border-b border-border px-5 py-3 flex items-center gap-2">
            <Badge>EDR</Badge><Badge>SYSMON</Badge><Badge>FIREWALL</Badge><Badge>DNS</Badge><Badge>O365</Badge><Badge>OKTA</Badge><Badge>CLOUDTRAIL</Badge>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-bg-elevated/80">
                <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-2">TS</th>
                  <th className="py-2">Source</th>
                  <th className="py-2">Vendor</th>
                  <th className="py-2">Event</th>
                  <th className="py-2">Host</th>
                  <th className="py-2">User</th>
                  <th className="py-2">Process</th>
                  <th className="py-2">Cmd / URL / Detail</th>
                  <th className="py-2 pr-5">Tech</th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <tr key={e.id} className="border-t border-border/60 hover:bg-bg-hover">
                    <td className="px-5 py-2 font-mono text-[10px] text-slate-400 whitespace-nowrap">{formatTs(e.ts, "MMM dd HH:mm:ss")}</td>
                    <td className="py-2 font-mono text-[10px] uppercase text-slate-300">{e.source}</td>
                    <td className="py-2 text-[11px] text-slate-300">{e.vendor ?? "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-cyber-300">{e.event_type}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-300">{e.hostname ?? "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-400">{e.user_email ?? "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-300">{e.process?.name ?? "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-200">
                      <span className="block max-w-[420px] truncate">
                        {e.process?.cmdline ?? e.network?.url ?? truncate(JSON.stringify(e.raw), 80)}
                      </span>
                    </td>
                    <td className="py-2 pr-5 font-mono text-[10px] text-neon-purple">{e.mitre_technique ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
