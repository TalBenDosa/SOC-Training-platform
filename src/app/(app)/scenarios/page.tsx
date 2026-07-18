"use client";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { SCENARIOS } from "@/lib/sim/scenarios";
import Link from "next/link";
import {
  Sparkles, Zap, ShieldQuestion, Cloud, Mail, KeyRound, Lock, UserX,
  BotIcon, EyeOff,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface PublishedScenario {
  id: string;
  title: string;
  threat_actor: string;
  attack_kind: string;
  difficulty: string;
  narrative: string;
  events: unknown[];
  published_at: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ICON: Record<string, React.ElementType> = {
  phishing_to_exfil: Mail,
  identity_bec:      KeyRound,
  ransomware:        Lock,
  oauth_persistence: Cloud,
  insider_threat:    UserX,
};

function diffPill(d: string): string {
  switch (d) {
    case "expert":       return "rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-critical";
    case "advanced":     return "rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-high";
    case "intermediate": return "rounded border border-severity-medium/40 bg-severity-medium/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-medium";
    default:             return "rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 text-[10px] font-bold uppercase text-cyber-300";
  }
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function ScenariosPage() {
  const router = useRouter();
  const [hidden, setHidden]       = useState<string[]>([]);
  const [published, setPublished] = useState<PublishedScenario[]>([]);

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_scenarios") ?? "[]"));
      setPublished(JSON.parse(localStorage.getItem("published_scenarios") ?? "[]"));
    } catch { /* storage blocked */ }
  }, []);

  const visibleBuiltIn = SCENARIOS.filter(s => !hidden.includes(s.slug));

  function launchGenerated(scenario: PublishedScenario) {
    try {
      localStorage.setItem("session_scenario", JSON.stringify(scenario));
    } catch { /* ignore */ }
    router.push("/scenarios/preview");
  }

  return (
    <div>
      <Topbar
        title="Attack Scenarios"
        subtitle="Run end-to-end simulations against the synthetic SOC"
        actions={undefined}
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

        {/* Hidden-items notice */}
        {hidden.length > 0 && (
          <div className="flex items-center gap-2 rounded border border-border/40 bg-bg-elevated px-4 py-2 text-[11px] text-slate-500">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            {hidden.length} scenario{hidden.length > 1 ? "s" : ""} hidden by admin — manage in Admin → Content Library
          </div>
        )}

        {/* Built-in scenarios */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {visibleBuiltIn.map(s => {
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
                  <Badge>{s.attack_kind.replaceAll("_", " ")}</Badge>
                  <Badge variant="outline">{s.threat_actor}</Badge>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <div className="text-[11px] text-slate-500">+250 XP · ~45 min</div>
                  <Link href={`/scenarios/${s.slug}`}>
                    <Button variant="primary" size="sm">Launch</Button>
                  </Link>
                </div>
              </Card>
            );
          })}

          {/* AI-generated / published scenarios */}
          {published.map(s => {
            const Icon = ICON[s.attack_kind] ?? BotIcon;
            return (
              <Card key={s.id} className="flex flex-col border-neon-green/20">
                <div className="flex items-start justify-between">
                  <div className="rounded-md border border-neon-green/30 bg-neon-green/10 p-2.5 text-neon-green">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="rounded border border-neon-green/30 bg-neon-green/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-green">
                      AI Generated
                    </span>
                    <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                  </div>
                </div>
                <h3 className="mt-3 text-base font-bold text-white">{s.title}</h3>
                <p className="mt-1 flex-1 text-sm text-slate-400 line-clamp-2">{s.narrative}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge>{s.attack_kind.replaceAll("_", " ")}</Badge>
                  <Badge variant="outline">{s.threat_actor}</Badge>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <div className="text-[11px] text-slate-500">
                    {new Date(s.published_at).toLocaleDateString()}
                  </div>
                  <Button variant="secondary" size="sm" onClick={() => launchGenerated(s)}>
                    Launch
                  </Button>
                </div>
              </Card>
            );
          })}
        </div>

        {visibleBuiltIn.length === 0 && published.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <ShieldQuestion className="h-12 w-12 text-slate-600 mb-4" />
            <p className="text-sm text-slate-400">All scenarios are hidden.</p>
            <p className="text-xs text-slate-600 mt-1">Restore them in Admin → Content Library.</p>
          </div>
        )}
      </div>
    </div>
  );
}
