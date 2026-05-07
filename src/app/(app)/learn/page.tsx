import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import Link from "next/link";
import { GraduationCap, Crosshair, ShieldAlert, ShieldCheck, Wrench } from "lucide-react";

export const metadata = { title: "Learning Paths" };

const PATHS = [
  {
    slug: "soc-analyst",     icon: GraduationCap, title: "SOC Analyst",
    blurb: "Triage, contain, escalate. The Tier-1 → Tier-2 backbone.",
    diff: "beginner", hours: 18, color: "from-cyber-500/30",
    modules: [
      { t: "SOC Foundations", l: ["What is a SOC?","Tier model","SLAs and queues","Mental models for triage"] },
      { t: "Alert Triage",    l: ["Reading EDR alerts","Process trees","Severity vs risk","Containment basics"] },
      { t: "MITRE ATT&CK",    l: ["Tactics & techniques","Mapping alerts","Coverage thinking"] },
      { t: "Investigation",   l: ["Timeline building","Pivoting on entities","Verdict workflows"] },
    ],
  },
  {
    slug: "threat-hunter",   icon: Crosshair, title: "Threat Hunter",
    blurb: "Hypothesize, query, find what your SIEM missed.",
    diff: "intermediate", hours: 22, color: "from-neon-purple/30",
    modules: [
      { t: "Hunt Methodology", l: ["TTP-based hunting","Hypothesis framework","Coverage gaps"] },
      { t: "KQL & SPL",        l: ["Joins","Aggregations","Time series","Entity baselining"] },
      { t: "Sigma & Detection", l: ["Sigma syntax","Backend conversion","Test data"] },
    ],
  },
  {
    slug: "incident-responder", icon: ShieldAlert, title: "Incident Responder",
    blurb: "Contain, eradicate, recover. Lead the war room.",
    diff: "advanced", hours: 26, color: "from-severity-high/30",
    modules: [
      { t: "IR Lifecycle (NIST)", l: ["Prepare","Detect","Contain","Eradicate","Recover","Lessons learned"] },
      { t: "Forensics 101",      l: ["Triage acquisition","Timeline analysis","Memory snippets"] },
      { t: "Comms & Reporting",  l: ["Exec briefings","Customer notifications","Postmortems"] },
    ],
  },
  {
    slug: "detection-engineer", icon: ShieldCheck, title: "Detection Engineer",
    blurb: "Author, validate, tune, and ship detections.",
    diff: "advanced", hours: 24, color: "from-neon-green/30",
    modules: [
      { t: "Sigma Mastery", l: ["Selection patterns","Modifiers","Coverage testing"] },
      { t: "Telemetry Sources", l: ["EDR vs Sysmon","O365 UAL","CloudTrail"] },
      { t: "Tuning",        l: ["FP analysis","Allowlists","Tiered severities"] },
    ],
  },
  {
    slug: "purple-team", icon: Wrench, title: "Purple Team",
    blurb: "Emulate adversaries. Detect. Improve. Repeat.",
    diff: "expert", hours: 28, color: "from-severity-critical/30",
    modules: [
      { t: "Adversary Emulation", l: ["Atomic Red Team","CALDERA","Custom TTPs"] },
      { t: "Detection Validation", l: ["Replay frameworks","KPI tracking"] },
      { t: "Reporting & ROI",      l: ["Heatmap delta","Investment justification"] },
    ],
  },
];

const diffColor: Record<string, string> = {
  beginner:     "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
  intermediate: "border-severity-medium/40 bg-severity-medium/10 text-severity-medium",
  advanced:     "border-severity-high/40 bg-severity-high/10 text-severity-high",
  expert:       "border-severity-critical/40 bg-severity-critical/10 text-severity-critical",
};

export default function LearnPage() {
  return (
    <div>
      <Topbar title="Learning Paths" subtitle="Structured tracks from Recruit to SOC Architect" />
      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {PATHS.map(p => {
          const Icon = p.icon;
          return (
            <Card key={p.slug} className={`relative overflow-hidden`}>
              <div className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${p.color} to-transparent opacity-40`} />
              <div className="relative">
                <div className="flex items-start justify-between">
                  <div className="rounded-md border border-cyber-500/30 bg-cyber-500/10 p-2.5 text-cyber-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase ${diffColor[p.diff]}`}>{p.diff}</span>
                </div>
                <h3 className="mt-3 text-lg font-bold text-white">{p.title}</h3>
                <p className="mt-1 text-sm text-slate-400">{p.blurb}</p>
                <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-500">
                  <span>{p.hours}h</span>
                  <span>·</span>
                  <span>{p.modules.length} modules</span>
                  <span>·</span>
                  <span>{p.modules.reduce((n, m) => n + m.l.length, 0)} lessons</span>
                </div>
                <ul className="mt-4 space-y-1.5">
                  {p.modules.map((m, i) => (
                    <li key={m.t} className="rounded border border-border bg-bg p-2.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Module {i + 1}</span>
                        <span className="text-[10px] text-slate-500">{m.l.length} lessons</span>
                      </div>
                      <p className="mt-1 text-xs font-semibold text-slate-100">{m.t}</p>
                      <p className="mt-0.5 text-[10px] text-slate-400">{m.l.join(" · ")}</p>
                    </li>
                  ))}
                </ul>
                <div className="mt-4 flex items-center justify-between">
                  <Badge variant="outline">{p.modules.reduce((n, m) => n + m.l.length, 0) * 50} XP</Badge>
                  <Link href={`/learn/${p.slug}`}><Button size="sm" variant="primary">Start path</Button></Link>
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
