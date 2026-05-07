import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { SCENARIOS } from "@/lib/sim/scenarios";
import Link from "next/link";
import { Sparkles, Zap, ShieldQuestion, Cloud, Mail, KeyRound, Cog } from "lucide-react";

export const metadata = { title: "Attack Scenarios" };

const ICON: Record<string, any> = {
  phishing_to_exfil: Mail,
  identity_bec: KeyRound,
};

function diffPill(d: string): string {
  switch (d) {
    case "expert":       return "rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-critical";
    case "advanced":     return "rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-high";
    case "intermediate": return "rounded border border-severity-medium/40 bg-severity-medium/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-medium";
    default:             return "rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 text-[10px] font-bold uppercase text-cyber-300";
  }
}

export default function ScenariosPage() {
  return (
    <div>
      <Topbar
        title="Attack Scenarios"
        subtitle="Run end-to-end simulations against the synthetic SOC"
        actions={<Button variant="primary" size="sm"><Zap className="h-4 w-4" /> Random Scenario</Button>}
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        <Card className="border-cyber-500/30 bg-gradient-to-br from-cyber-500/5 to-neon-purple/5">
          <div className="flex items-start gap-4">
            <div className="rounded-md border border-cyber-500/40 bg-cyber-500/10 p-3 text-cyber-300">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">How scenarios work</h3>
              <p className="mt-1 max-w-3xl text-sm text-slate-300">
                Each scenario spins up a deterministic, vendor-accurate attack chain — emails, EDR process trees,
                firewall sessions, AD authentications, cloud audit events. Triage the alerts, build a timeline,
                identify TTPs, and answer analyst questions to score XP and unlock badges.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
                <span>· No real customer data</span>
                <span>· MITRE-mapped</span>
                <span>· Replayable</span>
                <span>· AI-graded answers</span>
              </div>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {SCENARIOS.map(s => {
            const Icon = ICON[s.attack_kind] ?? ShieldQuestion;
            return (
              <Card key={s.slug} className="flex flex-col">
                <div className="flex items-start justify-between">
                  <div className="rounded-md border border-cyber-500/30 bg-cyber-500/10 p-2.5 text-cyber-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                </div>
                <h3 className="mt-3 text-base font-bold text-white">{s.title}</h3>
                <p className="mt-1 flex-1 text-sm text-slate-400">{s.summary}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge>{s.attack_kind.replaceAll("_"," ")}</Badge>
                  <Badge variant="outline">{s.threat_actor}</Badge>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <div className="text-[11px] text-slate-500">+250 XP · ~45 min</div>
                  <Link href={`/scenarios/${s.slug}`}><Button variant="primary" size="sm">Launch</Button></Link>
                </div>
              </Card>
            );
          })}

          {/* Coming soon placeholders */}
          {[
            { t: "Ransomware: Initial Foothold to Encryption", d: "VPN brute → AD enum → DPAPI → vssadmin delete shadows → encryption.", a: "LockBit-like", icon: Cog },
            { t: "Cloud Persistence via OAuth Consent Phishing", d: "Illicit consent grants on M365; mailbox forwarding rules added.", a: "TA-NIGHTAZURE", icon: Cloud },
            { t: "Insider Data Theft", d: "Privileged user copies customer DB to a personal cloud account.", a: "INSIDER", icon: ShieldQuestion },
          ].map(p => {
            const Icon = p.icon;
            return (
              <Card key={p.t} className="opacity-60 flex flex-col">
                <div className="flex items-start justify-between">
                  <div className="rounded-md border border-border bg-bg p-2.5 text-slate-400"><Icon className="h-5 w-5" /></div>
                  <span className="rounded border border-border bg-bg px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest text-slate-500">Coming soon</span>
                </div>
                <h3 className="mt-3 text-base font-bold text-white">{p.t}</h3>
                <p className="mt-1 flex-1 text-sm text-slate-400">{p.d}</p>
                <div className="mt-3"><Badge variant="outline">{p.a}</Badge></div>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
