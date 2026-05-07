import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { notFound } from "next/navigation";
import { formatTs } from "@/lib/utils";
import { Bot, Eye, FileSearch, Network } from "lucide-react";
import Link from "next/link";

export default function ScenarioPage({ params }: { params: { slug: string } }) {
  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) notFound();

  return (
    <div>
      <Topbar
        title={bundle.title}
        subtitle={`Threat actor ${bundle.threat_actor}`}
        actions={
          <>
            <Link href="/ai"><Button variant="outline" size="sm"><Bot className="h-4 w-4" /> AI Co-Analyst</Button></Link>
            <Link href={`/investigations/new?scenario=${bundle.scenario_id}`}><Button variant="primary" size="sm"><FileSearch className="h-4 w-4" /> Open Investigation</Button></Link>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <div className="flex items-center gap-2">
              <Badge>Scenario</Badge>
              <Badge variant="outline">{bundle.alerts.length} alerts</Badge>
              <Badge variant="outline">{bundle.events.length} events</Badge>
              <Badge variant="outline">{bundle.iocs.length} IOCs</Badge>
            </div>
            <h2 className="mt-3 text-lg font-bold text-white">Briefing</h2>
            <p className="mt-2 whitespace-pre-line text-sm leading-relaxed text-slate-300">{bundle.narrative}</p>
          </Card>

          {/* Killchain */}
          <Card>
            <h3 className="text-sm font-semibold text-white">Kill Chain</h3>
            <ol className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
              {bundle.killchain.map((k, i) => (
                <li key={i} className="rounded-md border border-border bg-bg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">{k.phase}</span>
                    <span className="font-mono text-[10px] text-slate-500">{formatTs(k.ts, "HH:mm:ss")}</span>
                  </div>
                  <p className="mt-1 text-sm text-slate-200">{k.action}</p>
                </li>
              ))}
            </ol>
          </Card>

          {/* Questions */}
          <Card>
            <h3 className="text-sm font-semibold text-white">Analyst Quiz</h3>
            <p className="mt-1 text-xs text-slate-500">Answer to earn XP. AI explains your mistakes.</p>
            <ol className="mt-4 space-y-5">
              {bundle.questions.map((q, idx) => (
                <li key={q.id} className="rounded-md border border-border bg-bg p-4">
                  <div className="flex items-start justify-between">
                    <p className="text-sm text-slate-100">
                      <span className="mr-2 font-mono text-cyber-300">Q{idx + 1}.</span>
                      {q.prompt}
                    </p>
                    <span className="rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 font-mono text-[10px] text-cyber-300">+{q.xp} XP</span>
                  </div>
                  {q.options && (
                    <ul className="mt-3 space-y-1.5">
                      {q.options.map(o => (
                        <li key={o.value}>
                          <label className="flex cursor-pointer items-center gap-2 rounded border border-border bg-bg-elevated px-2.5 py-1.5 text-xs text-slate-200 hover:border-cyber-500/40">
                            <input type={q.kind === "multi" ? "checkbox" : "radio"} name={q.id} className="accent-cyber-400" />
                            <span>{o.label}</span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ol>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="secondary">Save draft</Button>
              <Button variant="primary">Submit answers</Button>
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card className="border-severity-critical/30 bg-severity-critical/5">
            <h3 className="text-sm font-semibold text-white">Severity</h3>
            <div className="mt-2 flex items-center gap-2">
              <SeverityBadge severity="critical" />
              <span className="text-xs text-slate-300">Multi-stage compromise in progress</span>
            </div>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Pivot Tools</h3>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <Link href="/alerts"><Button className="w-full" variant="secondary" size="sm"><Eye className="h-4 w-4" /> Alerts</Button></Link>
              <Link href="/telemetry"><Button className="w-full" variant="secondary" size="sm"><Network className="h-4 w-4" /> Telemetry</Button></Link>
              <Link href="/hunts"><Button className="w-full" variant="secondary" size="sm">Hunts</Button></Link>
              <Link href="/mitre"><Button className="w-full" variant="secondary" size="sm">MITRE</Button></Link>
            </div>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Top IOCs</h3>
            <ul className="mt-3 space-y-1 text-xs">
              {bundle.iocs.slice(0, 12).map(i => (
                <li key={`${i.type}:${i.value}`} className="flex items-center justify-between gap-2 rounded border border-border bg-bg px-2 py-1.5">
                  <span className="rounded bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyber-300">{i.type}</span>
                  <span className="flex-1 truncate font-mono text-slate-200">{i.value}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
