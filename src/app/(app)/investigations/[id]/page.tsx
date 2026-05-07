import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, StatusBadge, Badge } from "@/components/ui/Badge";
import { Textarea } from "@/components/ui/Input";
import { buildPhishingToExfil } from "@/lib/sim/scenarios";
import { formatTs } from "@/lib/utils";
import { Bot, Save, ShieldAlert, Tag, Workflow } from "lucide-react";

export const metadata = { title: "Investigation" };

export default function InvestigationDetail({ params }: { params: { id: string } }) {
  const bundle = buildPhishingToExfil();
  const alerts = bundle.alerts;
  const events = bundle.events;
  const killchain = bundle.killchain;

  return (
    <div>
      <Topbar
        title={`Investigation ${params.id}`}
        subtitle={bundle.title}
        actions={
          <>
            <Button variant="outline" size="sm"><Bot className="h-4 w-4" /> AI Co-Analyst</Button>
            <Button variant="secondary" size="sm"><Workflow className="h-4 w-4" /> Run Playbook</Button>
            <Button variant="primary" size="sm"><Save className="h-4 w-4" /> Save</Button>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left: timeline + notes */}
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Kill Chain Timeline</h3>
              <Badge variant="outline">MITRE-aligned</Badge>
            </div>
            <ol className="mt-4 space-y-4">
              {killchain.map((k, i) => (
                <li key={i} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <span className="flex h-8 w-8 items-center justify-center rounded-full border border-cyber-500/40 bg-cyber-500/10 font-mono text-[10px] font-bold text-cyber-300">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    {i < killchain.length - 1 && <span className="my-1 h-full w-px bg-border" />}
                  </div>
                  <div className="flex-1 rounded-md border border-border bg-bg p-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">{k.phase}</span>
                      <span className="font-mono text-[11px] text-slate-500">{formatTs(k.ts)}</span>
                    </div>
                    <p className="mt-1 text-sm text-slate-200">{k.action}</p>
                  </div>
                </li>
              ))}
            </ol>
          </Card>

          <Card padded={false}>
            <div className="border-b border-border px-5 py-3">
              <h3 className="text-sm font-semibold text-white">Linked Alerts ({alerts.length})</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-bg-elevated/80">
                  <tr className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    <th className="px-5 py-2">Time</th>
                    <th className="py-2">Sev</th>
                    <th className="py-2">UID</th>
                    <th className="py-2">Title</th>
                    <th className="py-2 pr-5">Tech</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map(a => (
                    <tr key={a.id} className="border-t border-border/60">
                      <td className="px-5 py-2 font-mono text-[10px] text-slate-400">{formatTs(a.detected_at, "HH:mm:ss")}</td>
                      <td className="py-2"><SeverityBadge severity={a.severity} /></td>
                      <td className="py-2 font-mono text-cyber-300">{a.alert_uid}</td>
                      <td className="py-2 text-slate-200">{a.title}</td>
                      <td className="py-2 pr-5 font-mono text-neon-purple">{a.mitre_technique ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card>
            <h3 className="text-sm font-semibold text-white">Analyst Notes</h3>
            <p className="mt-1 text-xs text-slate-500">Capture findings, hypotheses, and decisions. Markdown supported.</p>
            <Textarea placeholder="## Hypothesis
The user clicked a phishing attachment. Confirmed by Office → PowerShell parent-child chain at 09:47:18.

## Containment
- Network-isolate WS-FIN-3041 via EDR
- Reset a.park credentials and revoke SSO
- Block C2 domain at the egress proxy" defaultValue=""/>
            <div className="mt-2 flex items-center justify-between">
              <div className="flex flex-wrap gap-2">
                {["confirmed","high-confidence","ttp-T1059.001","ttp-T1003.001","action-isolate"].map(t => (
                  <span key={t} className="inline-flex items-center gap-1 rounded border border-border bg-bg px-2 py-0.5 text-[10px] font-mono text-slate-300">
                    <Tag className="h-3 w-3" /> {t}
                  </span>
                ))}
              </div>
              <Button size="sm" variant="primary"><Save className="h-4 w-4" /> Add Note</Button>
            </div>
          </Card>
        </div>

        {/* Right rail */}
        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Status</h3>
            <div className="mt-3 flex flex-col gap-2">
              <StatusBadge status="investigating" />
              <SeverityBadge severity="critical" />
              <Badge variant="outline">Verdict: True Positive</Badge>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-2">
              <Button variant="danger" size="sm"><ShieldAlert className="h-4 w-4" /> Escalate</Button>
              <Button variant="secondary" size="sm">Mark Contained</Button>
            </div>
          </Card>

          <Card>
            <h3 className="text-sm font-semibold text-white">IOCs ({bundle.iocs.length})</h3>
            <ul className="mt-3 max-h-[260px] space-y-1 overflow-y-auto pr-1">
              {bundle.iocs.slice(0, 30).map(i => (
                <li key={`${i.type}:${i.value}`} className="flex items-center justify-between gap-2 rounded border border-border bg-bg px-2 py-1.5 text-[11px]">
                  <span className="rounded bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyber-300">{i.type}</span>
                  <span className="flex-1 truncate font-mono text-slate-200">{i.value}</span>
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <h3 className="text-sm font-semibold text-white">Affected Assets</h3>
            <ul className="mt-3 space-y-1 text-xs">
              {["WS-FIN-3041","DC01.cryotech.local","a.park@cryotech.io","s3://cryotech-fin-bucket"].map(a => (
                <li key={a} className="rounded border border-border bg-bg px-2 py-1.5 font-mono text-slate-200">{a}</li>
              ))}
            </ul>
          </Card>

          <Card className="border-cyber-500/30 bg-cyber-500/5">
            <h3 className="text-sm font-semibold text-cyber-200">AI Suggestion</h3>
            <p className="mt-2 text-xs text-slate-300">
              The Office→PowerShell→rundll32→LSASS chain plus Run-key persistence is consistent with a foothold for
              hands-on-keyboard credential theft. Recommend pivoting on the dropped DLL SHA256 across the fleet,
              and reviewing all sign-ins for <span className="font-mono">a.park@cryotech.io</span> in the last 24h.
            </p>
            <Button className="mt-3 w-full" size="sm" variant="outline">Open AI Co-Analyst</Button>
          </Card>
        </div>
      </div>
    </div>
  );
}
