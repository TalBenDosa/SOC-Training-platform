import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { formatTs } from "@/lib/utils";
import { techniqueById, tacticById } from "@/lib/mitre/attack";
import { Bot, Shield, ShieldOff, Workflow, FileSearch, Network } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

export const metadata = { title: "Alert detail" };

export default function AlertDetail({ params }: { params: { id: string } }) {
  const bundles = [buildPhishingToExfil(), buildBecScenario()];
  let alert: ReturnType<typeof buildPhishingToExfil>["alerts"][number] | undefined;
  let bundle: ReturnType<typeof buildPhishingToExfil> | undefined;
  for (const b of bundles) {
    const a = b.alerts.find(a => a.id === params.id);
    if (a) { alert = a; bundle = b; break; }
  }
  if (!alert || !bundle) notFound();

  const related = bundle.events.filter(e => alert!.related_events.includes(e.id));
  const tech = alert.mitre_technique ? techniqueById(alert.mitre_technique) : undefined;
  const tactic = alert.mitre_tactic ? tacticById(alert.mitre_tactic) : undefined;

  return (
    <div>
      <Topbar
        title={alert.alert_uid}
        subtitle={alert.title}
        actions={
          <>
            <Button variant="outline" size="sm"><Bot className="h-4 w-4" /> Ask AI</Button>
            <Button variant="secondary" size="sm"><Shield className="h-4 w-4" /> Isolate Host</Button>
            <Button variant="danger" size="sm"><ShieldOff className="h-4 w-4" /> Escalate</Button>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card className="lg:col-span-2 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span className="rounded border border-border bg-bg px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                {alert.vendor}
              </span>
              <span className="rounded border border-border bg-bg px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                {alert.source}
              </span>
              <span className="ml-auto font-mono text-[11px] text-slate-500">
                {formatTs(alert.detected_at)}
              </span>
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{alert.title}</h2>
              <p className="mt-2 text-sm text-slate-300">{alert.description}</p>
            </div>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                ["Confidence", `${alert.confidence}%`],
                ["Risk", `${alert.risk_score}`],
                ["Hostname", alert.hostname ?? "—"],
                ["User", alert.user_email ?? "—"],
                ["Source IP", alert.src_ip ?? "—"],
                ["Dest IP", alert.dst_ip ?? "—"],
                ["Tactic", tactic ? `${tactic.id} ${tactic.name}` : "—"],
                ["Technique", tech ? `${tech.id} ${tech.name}` : "—"],
              ].map(([k, v]) => (
                <div key={k} className="rounded-md border border-border bg-bg p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{k}</p>
                  <p className="mt-1 font-mono text-xs text-slate-200">{v}</p>
                </div>
              ))}
            </div>

            {alert.process && (
              <div>
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Process</p>
                <pre className="overflow-x-auto rounded-md border border-border bg-bg p-3 font-mono text-[11px] text-slate-200">
{alert.process.parent ? `↳ ${alert.process.parent}\n  ` : ""}{alert.process.name}
{alert.process.cmdline ? `\n${alert.process.cmdline}` : ""}
{alert.process.sha256 ? `\nSHA256: ${alert.process.sha256}` : ""}
                </pre>
              </div>
            )}
          </Card>

          {/* Right column: actions */}
          <div className="space-y-4">
            <Card>
              <h3 className="text-sm font-semibold text-white">Triage Actions</h3>
              <ul className="mt-3 space-y-2 text-xs text-slate-300">
                <li>1. Confirm parent-child anomaly: Office → PowerShell.</li>
                <li>2. Pull full process tree from EDR for the host.</li>
                <li>3. Search for the SHA256 across the fleet.</li>
                <li>4. Isolate host via EDR if reputation = malicious.</li>
                <li>5. Reset user creds; revoke active SSO sessions.</li>
                <li>6. Open investigation; capture timeline.</li>
              </ul>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <Link href="/investigations/new" className="col-span-2"><Button className="w-full" variant="primary" size="sm"><FileSearch className="h-4 w-4" /> Open Investigation</Button></Link>
                <Button variant="secondary" size="sm"><Workflow className="h-4 w-4" /> Run Playbook</Button>
                <Button variant="secondary" size="sm"><Network className="h-4 w-4" /> Pivot Telemetry</Button>
              </div>
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-white">Indicators of Compromise</h3>
              <ul className="mt-3 space-y-1 text-xs">
                {bundle.iocs.slice(0, 8).map(i => (
                  <li key={`${i.type}:${i.value}`} className="flex items-center justify-between gap-3 rounded border border-border bg-bg px-2 py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="rounded bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyber-300">{i.type}</span>
                      <span className="truncate font-mono text-[11px] text-slate-200">{i.value}</span>
                    </div>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase tracking-widest ${
                      i.reputation === "malicious" ? "bg-severity-critical/10 text-severity-critical" :
                      i.reputation === "suspicious" ? "bg-severity-medium/10 text-severity-medium" :
                      "bg-slate-500/10 text-slate-400"
                    }`}>{i.reputation}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>

        {/* Related telemetry */}
        <Card padded={false}>
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <h3 className="text-sm font-semibold text-white">Related Telemetry ({related.length})</h3>
            <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Raw events from EDR / Sysmon</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-bg-elevated/80">
                <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-2">TS</th>
                  <th className="py-2">Source</th>
                  <th className="py-2">Type</th>
                  <th className="py-2">Process</th>
                  <th className="py-2">Cmdline / Detail</th>
                  <th className="py-2 pr-5">Tech</th>
                </tr>
              </thead>
              <tbody>
                {related.map(e => (
                  <tr key={e.id} className="border-t border-border/60 hover:bg-bg-hover">
                    <td className="px-5 py-2 font-mono text-[10px] text-slate-400">{formatTs(e.ts, "HH:mm:ss")}</td>
                    <td className="py-2 font-mono text-[10px] uppercase text-slate-300">{e.source}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-300">{e.event_type}</td>
                    <td className="py-2 font-mono text-[10px] text-cyber-300">{e.process?.name ?? "—"}</td>
                    <td className="py-2 font-mono text-[10px] text-slate-200">
                      <span className="line-clamp-1">{e.process?.cmdline ?? e.network?.url ?? JSON.stringify(e.raw).slice(0, 100)}</span>
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
