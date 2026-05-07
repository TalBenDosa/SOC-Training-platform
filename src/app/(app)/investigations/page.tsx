import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";
import { Plus, FileSearch } from "lucide-react";
import Link from "next/link";

export const metadata = { title: "Investigations" };

const SAMPLE_INVS = [
  {
    id: "inv-2026-0421",
    title: "WS-FIN-3041 — Macro-launched PowerShell + LSASS dump",
    severity: "critical", status: "in_progress",
    verdict: "true_positive",
    summary: "Finance analyst opened invoice .docm; full kill chain observed including credential theft and S3 exfil.",
    affected_assets: ["WS-FIN-3041","DC01.cryotech.local","s3://cryotech-fin-*"],
    iocs: 12, notes: 7, opened: "2026-05-07T09:48:00Z",
  },
  {
    id: "inv-2026-0419",
    title: "BEC mailbox rule '..' on a.park@cryotech.io",
    severity: "high", status: "open",
    verdict: undefined,
    summary: "Foreign-IP sign-in followed by hidden inbox rule for wire/invoice keywords.",
    affected_assets: ["a.park@cryotech.io"],
    iocs: 5, notes: 3, opened: "2026-05-07T02:18:00Z",
  },
  {
    id: "inv-2026-0418",
    title: "Suspicious WMI persistence on JMP-ADMIN01",
    severity: "medium", status: "contained",
    verdict: "true_positive",
    summary: "WMI event subscription created via wmic; container isolated, persistence removed.",
    affected_assets: ["JMP-ADMIN01"],
    iocs: 3, notes: 5, opened: "2026-05-06T23:12:00Z",
  },
];

export default function InvestigationsPage() {
  // Pull live alerts to populate the right rail.
  const recentAlerts = [
    ...buildPhishingToExfil().alerts,
    ...buildBecScenario().alerts,
  ].sort((a, b) => b.detected_at.localeCompare(a.detected_at)).slice(0, 6);

  return (
    <div>
      <Topbar
        title="Investigations"
        subtitle="Active and historical incident investigations"
        actions={
          <Link href="/investigations/new"><Button variant="primary" size="sm"><Plus className="h-4 w-4" /> New Investigation</Button></Link>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {SAMPLE_INVS.map(inv => (
            <Card key={inv.id} className="hover:border-cyber-500/30 transition">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyber-300">{inv.id}</span>
                    <SeverityBadge severity={inv.severity} />
                    <StatusBadge status={inv.status} />
                    {inv.verdict && (
                      <span className="rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                        {inv.verdict.replace("_"," ")}
                      </span>
                    )}
                  </div>
                  <h3 className="mt-1.5 text-base font-semibold text-white">{inv.title}</h3>
                  <p className="mt-1 text-sm text-slate-400">{inv.summary}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {inv.affected_assets.map(a => (
                      <span key={a} className="rounded border border-border bg-bg px-2 py-0.5 font-mono text-[10px] text-slate-300">{a}</span>
                    ))}
                  </div>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1 text-[11px] text-slate-500">
                  <span><span className="font-mono text-cyber-300">{inv.iocs}</span> IOCs</span>
                  <span><span className="font-mono text-cyber-300">{inv.notes}</span> notes</span>
                  <Link href={`/investigations/${inv.id}`} className="mt-2"><Button variant="secondary" size="sm"><FileSearch className="h-4 w-4" /> Open</Button></Link>
                </div>
              </div>
            </Card>
          ))}
        </div>

        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Promote alerts to investigation</h3>
            <p className="mt-1 text-xs text-slate-500">Recent unhandled alerts</p>
            <ul className="mt-3 space-y-2">
              {recentAlerts.map(a => (
                <li key={a.id} className="rounded border border-border bg-bg p-2.5">
                  <div className="flex items-center justify-between">
                    <SeverityBadge severity={a.severity} />
                    <span className="font-mono text-[10px] text-slate-500">{a.alert_uid}</span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-200 line-clamp-2">{a.title}</p>
                  <div className="mt-2 flex justify-end">
                    <Button variant="outline" size="sm">Promote</Button>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Verdict mix (30d)</h3>
            <ul className="mt-3 space-y-2 text-xs">
              {[
                ["True Positive", 64, "bg-severity-critical"],
                ["False Positive", 22, "bg-slate-500"],
                ["Benign", 11, "bg-neon-green"],
                ["Undetermined", 3, "bg-severity-medium"],
              ].map(([l, p, c]) => (
                <li key={l as string}>
                  <div className="flex items-center justify-between"><span className="text-slate-300">{l}</span><span className="font-mono text-slate-400">{p}%</span></div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded bg-bg"><div className={`h-full ${c}`} style={{ width: `${p}%` }} /></div>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
