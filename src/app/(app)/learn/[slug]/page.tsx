import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import Link from "next/link";
import { CheckCircle2, Circle, PlayCircle } from "lucide-react";
import { notFound } from "next/navigation";

const PATHS: Record<string, { title: string; modules: { title: string; lessons: { title: string; kind: string; min: number; xp: number }[] }[] }> = {
  "soc-analyst": {
    title: "SOC Analyst Fundamentals",
    modules: [
      { title: "SOC Foundations", lessons: [
        { title: "What is a SOC?",            kind: "lesson", min: 8,  xp: 50 },
        { title: "The Tier model & SLAs",     kind: "lesson", min: 10, xp: 50 },
        { title: "Mental models for triage",  kind: "lesson", min: 12, xp: 50 },
        { title: "Quiz: foundations",         kind: "quiz",   min: 5,  xp: 100 },
      ]},
      { title: "Alert Triage", lessons: [
        { title: "Reading EDR alerts",        kind: "lesson",     min: 12, xp: 75 },
        { title: "Process trees in depth",    kind: "lab",        min: 18, xp: 150 },
        { title: "Severity vs. risk score",   kind: "lesson",     min: 8,  xp: 50 },
        { title: "Containment basics",        kind: "lesson",     min: 10, xp: 75 },
        { title: "Lab: triage 10 alerts",     kind: "simulation", min: 25, xp: 250 },
      ]},
      { title: "MITRE ATT&CK", lessons: [
        { title: "Tactics & techniques",      kind: "lesson", min: 10, xp: 75 },
        { title: "Mapping alerts to ATT&CK",  kind: "lab",    min: 20, xp: 150 },
        { title: "Coverage thinking",         kind: "lesson", min: 10, xp: 75 },
      ]},
      { title: "Investigation Workflow", lessons: [
        { title: "Building timelines",        kind: "lesson", min: 12, xp: 75 },
        { title: "Pivoting on entities",      kind: "lab",    min: 22, xp: 200 },
        { title: "Verdict workflows",         kind: "lesson", min: 10, xp: 75 },
        { title: "Capstone scenario",         kind: "simulation", min: 45, xp: 500 },
      ]},
    ],
  },
};

export default function PathDetail({ params }: { params: { slug: string } }) {
  const path = PATHS[params.slug];
  if (!path) notFound();
  const totalLessons = path.modules.reduce((n, m) => n + m.lessons.length, 0);
  const totalXp = path.modules.reduce((n, m) => n + m.lessons.reduce((x, l) => x + l.xp, 0), 0);

  return (
    <div>
      <Topbar title={path.title} subtitle={`${totalLessons} lessons · ${totalXp.toLocaleString()} XP`} />
      <div className="container mx-auto max-w-4xl px-6 py-6 space-y-4">
        {path.modules.map((m, i) => (
          <Card key={m.title}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Module {i + 1}</p>
                <h3 className="text-base font-semibold text-white">{m.title}</h3>
              </div>
              <Badge variant="outline">{m.lessons.length} lessons</Badge>
            </div>
            <ul className="mt-3 divide-y divide-border">
              {m.lessons.map((l, j) => (
                <li key={l.title} className="flex items-center justify-between py-2.5 text-sm">
                  <div className="flex items-center gap-3 min-w-0">
                    {j === 0 && i === 0 ? <PlayCircle className="h-4 w-4 text-cyber-300" /> :
                     j < 2 ? <CheckCircle2 className="h-4 w-4 text-neon-green" /> :
                             <Circle className="h-4 w-4 text-slate-600" />}
                    <span className="truncate text-slate-200">{l.title}</span>
                    <span className="rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-slate-400">{l.kind}</span>
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-slate-500">
                    <span>{l.min} min</span>
                    <span className="font-mono text-cyber-300">+{l.xp} XP</span>
                    <Link href="#"><Button size="sm" variant="ghost">Open</Button></Link>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
    </div>
  );
}
