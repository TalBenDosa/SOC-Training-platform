import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { formatTs } from "@/lib/utils";

export const metadata = { title: "IOC Database" };

export default function IocsPage() {
  const iocs = [...buildPhishingToExfil().iocs, ...buildBecScenario().iocs];
  const counts = { ip: 0, domain: 0, url: 0, sha256: 0, md5: 0, email: 0, user: 0, host: 0 } as Record<string, number>;
  for (const i of iocs) counts[i.type] = (counts[i.type] ?? 0) + 1;

  return (
    <div>
      <Topbar title="IOC Database" subtitle={`${iocs.length} indicators across active scenarios`} />
      <div className="container mx-auto max-w-[1500px] px-6 py-6 space-y-4">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
          {Object.entries(counts).map(([k, n]) => (
            <Card key={k} padded={false} className="px-4 py-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">{k}</p>
              <p className="mt-1 font-mono text-2xl font-bold text-cyber-300">{n}</p>
            </Card>
          ))}
        </div>

        <Card padded={false}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-bg-elevated/80">
                <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-2">Type</th>
                  <th className="py-2">Value</th>
                  <th className="py-2">Reputation</th>
                  <th className="py-2">First seen</th>
                  <th className="py-2">Last seen</th>
                  <th className="py-2 pr-5">Hits</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map(i => (
                  <tr key={`${i.type}:${i.value}`} className="border-t border-border/60 hover:bg-bg-hover">
                    <td className="px-5 py-2">
                      <span className="rounded bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyber-300">{i.type}</span>
                    </td>
                    <td className="py-2 font-mono text-[11px] text-slate-200">{i.value}</td>
                    <td className="py-2">
                      <span className={
                        i.reputation === "malicious" ? "rounded bg-severity-critical/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-severity-critical" :
                        i.reputation === "suspicious" ? "rounded bg-severity-medium/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-severity-medium" :
                        "rounded bg-slate-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-slate-400"}>
                        {i.reputation ?? "unknown"}
                      </span>
                    </td>
                    <td className="py-2 font-mono text-[10px] text-slate-400">{i.first_seen ? formatTs(i.first_seen, "MMM dd HH:mm") : "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-400">{i.last_seen ? formatTs(i.last_seen, "MMM dd HH:mm") : "—"}</td>
                    <td className="py-2 pr-5 font-mono text-[11px] text-slate-300">{i.count ?? 1}</td>
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
