import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Textarea } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { CheckCircle2, FlaskConical, Plus, Rocket, ShieldCheck } from "lucide-react";

export const metadata = { title: "Detection Lab" };

const RULES = [
  {
    id: "det-001", name: "Office spawns encoded PowerShell",
    lang: "sigma", status: "validated", severity: "high",
    tp: 12, fp: 1, tested: "2026-05-06",
    yaml: `title: Office Application Spawns Encoded PowerShell
id: 5b1f8c3a-9e3a-4f9c-9b7d-1a8b2c3d4e5f
status: stable
description: Detects MS Office spawning powershell.exe with -EncodedCommand
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.initial_access
  - attack.t1566.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\POWERPNT.EXE'
      - '\\OUTLOOK.EXE'
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-Enc '
      - '-EncodedCommand'
      - '-e '
  condition: selection
falsepositives:
  - Legitimate macros at large enterprises (rare, validate per app)
level: high`,
  },
  {
    id: "det-002", name: "LSASS MiniDump via comsvcs.dll",
    lang: "sigma", status: "deployed", severity: "critical",
    tp: 4, fp: 0, tested: "2026-05-04",
    yaml: `title: LSASS Memory Dump via comsvcs.dll MiniDump
id: 7c8e0fa3-4a9e-4f7e-9b1c-2c8d4e1a3b9c
description: Detects rundll32.exe invoking comsvcs.dll MiniDump against LSASS
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  condition: selection
level: critical`,
  },
  {
    id: "det-003", name: "DNS tunneling — high-entropy subdomain",
    lang: "sigma", status: "testing", severity: "medium",
    tp: 9, fp: 14, tested: "2026-05-07",
    yaml: `title: DNS Query With High Entropy Subdomain
description: Long base32-like subdomains correlated with DNS tunneling C2
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource: { product: dns, category: query }
detection:
  selection:
    QueryName|re: '^[a-z2-7]{40,}\\.'
  condition: selection
level: medium`,
  },
];

export default function DetectionsPage() {
  return (
    <div>
      <Topbar
        title="Detection Engineering Lab"
        subtitle="Author, validate, and ship Sigma / KQL / SPL detections"
        actions={
          <>
            <Button variant="secondary" size="sm"><FlaskConical className="h-4 w-4" /> Validate All</Button>
            <Button variant="primary" size="sm"><Plus className="h-4 w-4" /> New Rule</Button>
          </>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {RULES.map(r => (
            <Card key={r.id}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-cyber-300">{r.id}</span>
                    <Badge variant="outline">{r.lang.toUpperCase()}</Badge>
                    <Badge>{r.status}</Badge>
                    <span className={
                      r.severity === "critical" ? "rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-critical" :
                      r.severity === "high"     ? "rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-high" :
                                                  "rounded border border-severity-medium/40 bg-severity-medium/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-medium"}>
                      {r.severity}
                    </span>
                  </div>
                  <h3 className="mt-2 text-base font-semibold text-white">{r.name}</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-right text-[11px]">
                  <div className="rounded border border-border bg-bg px-2 py-1">
                    <p className="text-[9px] uppercase tracking-widest text-slate-500">TP</p>
                    <p className="font-mono text-neon-green">{r.tp}</p>
                  </div>
                  <div className="rounded border border-border bg-bg px-2 py-1">
                    <p className="text-[9px] uppercase tracking-widest text-slate-500">FP</p>
                    <p className="font-mono text-severity-medium">{r.fp}</p>
                  </div>
                </div>
              </div>
              <pre className="mt-4 max-h-[300px] overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-[11px] leading-relaxed text-slate-200">
{r.yaml}
              </pre>
              <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500">
                <span>Last tested {r.tested}</span>
                <div className="flex gap-2">
                  <Button variant="secondary" size="sm"><FlaskConical className="h-4 w-4" /> Validate</Button>
                  <Button variant="primary" size="sm"><Rocket className="h-4 w-4" /> Deploy</Button>
                </div>
              </div>
            </Card>
          ))}
        </div>

        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Validation Bench</h3>
            <p className="mt-1 text-xs text-slate-500">Replay synthetic attack telemetry against your rule.</p>
            <Textarea defaultValue={`title: My New Detection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains: 'AppData\\\\Local\\\\Temp'
  condition: selection
level: high`} />
            <div className="mt-2 grid grid-cols-2 gap-2">
              <Button size="sm" variant="secondary">Convert to KQL</Button>
              <Button size="sm" variant="primary"><FlaskConical className="h-4 w-4" /> Run</Button>
            </div>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Coverage</h3>
            <ul className="mt-3 space-y-2 text-xs">
              {[
                ["Execution",      82],
                ["Persistence",    64],
                ["Defense Evasion",58],
                ["Credential Access",71],
                ["Lateral Movement",46],
                ["Exfiltration",    39],
              ].map(([k, v]) => (
                <li key={k as string}>
                  <div className="flex items-center justify-between"><span className="text-slate-300">{k}</span><span className="font-mono text-slate-400">{v}%</span></div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded bg-bg"><div className="h-full bg-gradient-to-r from-cyber-500 to-neon-green" style={{ width: `${v}%` }} /></div>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
              <CheckCircle2 className="h-4 w-4 text-neon-green" />
              <span>All deployed rules passing replay tests</span>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
