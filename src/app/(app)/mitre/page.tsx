import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { TACTICS, TECHNIQUES, techniquesForTactic } from "@/lib/mitre/attack";
import { buildBecScenario, buildPhishingToExfil } from "@/lib/sim/scenarios";

export const metadata = { title: "MITRE ATT&CK" };

export default function MitrePage() {
  // Coverage from current scenarios
  const covered = new Map<string, number>();
  for (const b of [buildPhishingToExfil(), buildBecScenario()]) {
    for (const a of b.alerts) {
      if (!a.mitre_technique) continue;
      covered.set(a.mitre_technique, (covered.get(a.mitre_technique) ?? 0) + 1);
    }
  }
  const max = Math.max(1, ...covered.values());

  return (
    <div>
      <Topbar
        title="MITRE ATT&CK Heatmap"
        subtitle="Coverage across enterprise tactics & techniques"
      />
      <div className="container mx-auto max-w-[1600px] px-6 py-6">
        <Card padded={false}>
          <div className="overflow-x-auto">
            <div className="grid min-w-max grid-flow-col auto-cols-[180px] divide-x divide-border">
              {TACTICS.slice(2).map(tac => (
                <div key={tac.id} className="flex flex-col">
                  <div className="border-b border-border bg-bg-elevated px-3 py-2">
                    <p className="font-mono text-[10px] text-slate-500">{tac.id}</p>
                    <p className="text-xs font-semibold text-white">{tac.name}</p>
                  </div>
                  <ul className="flex-1 divide-y divide-border bg-bg">
                    {techniquesForTactic(tac.id).map(t => {
                      const c = covered.get(t.id) ?? 0;
                      const intensity = c === 0 ? 0 : 0.2 + (c / max) * 0.8;
                      return (
                        <li key={t.id}
                          className="px-3 py-2"
                          style={{ background: c ? `rgba(34,211,238,${intensity * 0.25})` : undefined }}>
                          <p className="font-mono text-[10px] text-cyber-300">{t.id}</p>
                          <p className="text-[11px] text-slate-200">{t.name}</p>
                          {c > 0 && (
                            <p className="mt-0.5 inline-block rounded bg-cyber-500/20 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-cyber-200">
                              {c} hit{c > 1 ? "s" : ""}
                            </p>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
          <Card>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Total techniques</p>
            <p className="mt-1 font-mono text-3xl font-bold text-white">{TECHNIQUES.length}</p>
          </Card>
          <Card>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Active coverage</p>
            <p className="mt-1 font-mono text-3xl font-bold text-cyber-300">{covered.size}</p>
          </Card>
          <Card>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Coverage %</p>
            <p className="mt-1 font-mono text-3xl font-bold text-neon-green">
              {Math.round((covered.size / TECHNIQUES.length) * 100)}%
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}
