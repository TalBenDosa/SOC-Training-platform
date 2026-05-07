import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Textarea } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { Crosshair, Play, Save } from "lucide-react";

export const metadata = { title: "Threat Hunting" };

const HUNTS = [
  {
    id: "hunt-001", title: "Office spawning script interpreters",
    hypothesis: "Macro-enabled Office docs spawn powershell.exe, cmd.exe, wscript, mshta, rundll32 — a high-fidelity TTP for malicious documents.",
    lang: "kql", tech: ["T1566.001","T1059.001","T1059.005"],
    query: `// Sentinel KQL
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc`,
    findings: 3,
  },
  {
    id: "hunt-002", title: "LSASS access from non-system processes",
    hypothesis: "Mimikatz-style credential theft generates ProcessAccess events targeting lsass.exe with GrantedAccess 0x1010 / 0x1410.",
    lang: "kql", tech: ["T1003.001"],
    query: `DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","wininit.exe","services.exe")
| extend Target = tostring(parse_json(AdditionalFields).TargetImageFileName)
| where Target endswith "lsass.exe"
| extend Granted = tostring(parse_json(AdditionalFields).GrantedAccess)
| where Granted in ("0x1010","0x1410","0x143A")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Granted`,
    findings: 1,
  },
  {
    id: "hunt-003", title: "Anomalous SSO geography",
    hypothesis: "A user authenticating successfully from a country never previously seen for that account is high-signal for credential abuse.",
    lang: "kql", tech: ["T1078"],
    query: `let baseline =
    SigninLogs
    | where TimeGenerated > ago(60d)
    | summarize Countries = make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| join kind=leftouter baseline on UserPrincipalName
| where Countries !contains Location
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName`,
    findings: 7,
  },
];

export default function HuntsPage() {
  return (
    <div>
      <Topbar
        title="Threat Hunting"
        subtitle="Hypothesis-driven hunts across enterprise telemetry"
        actions={<Button variant="primary" size="sm"><Crosshair className="h-4 w-4" /> New Hunt</Button>}
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {HUNTS.map(h => (
            <Card key={h.id}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyber-300">{h.id}</span>
                    <Badge variant="outline">{h.lang.toUpperCase()}</Badge>
                    {h.tech.map(t => <Badge key={t}>{t}</Badge>)}
                  </div>
                  <h3 className="mt-2 text-base font-semibold text-white">{h.title}</h3>
                  <p className="mt-1 text-sm text-slate-400">{h.hypothesis}</p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] uppercase tracking-widest text-slate-500">Findings</p>
                  <p className="font-mono text-2xl font-bold text-severity-high">{h.findings}</p>
                </div>
              </div>
              <pre className="mt-4 max-h-[260px] overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-[11px] leading-relaxed text-slate-200">
{h.query}
              </pre>
              <div className="mt-3 flex items-center justify-end gap-2">
                <Button variant="secondary" size="sm"><Save className="h-4 w-4" /> Save</Button>
                <Button variant="primary" size="sm"><Play className="h-4 w-4" /> Run on synthetic data</Button>
              </div>
            </Card>
          ))}
        </div>

        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Hunt Builder</h3>
            <p className="mt-1 text-xs text-slate-500">Compose KQL / SPL / Sigma against ingested telemetry</p>
            <Textarea defaultValue={`DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("EncodedCommand","FromBase64String","DownloadString")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`} />
            <Button className="mt-2 w-full" size="sm" variant="primary"><Play className="h-4 w-4" /> Execute</Button>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Hunt Library</h3>
            <ul className="mt-3 space-y-2 text-xs">
              {[
                "Encoded PowerShell over the last 7 days",
                "rundll32 calling user-writable DLLs",
                "Schtasks creating tasks pointing to %TEMP%",
                "DNS subdomains > 40 chars (tunneling)",
                "Outbound to newly registered domains",
                "Service creation events in business hours",
              ].map(t => (
                <li key={t} className="rounded border border-border bg-bg px-2 py-1.5 text-slate-300 hover:border-cyber-500/40">{t}</li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
