"use client";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Bot, Send, Sparkles, User, Workflow } from "lucide-react";
import { useState } from "react";

type Msg = { role: "user" | "assistant"; content: string };

const SEED_MESSAGES: Msg[] = [
  {
    role: "assistant",
    content:
`I'm your SOC Co-Analyst. Drop an alert UID, a SHA256, a username, or just describe what you're seeing.

Some things I can do right now:
• Explain why a detection fired and what to look at next
• Map an alert to MITRE ATT&CK and recommend hunts
• Build a triage timeline from raw EDR events
• Draft an investigation note in NIST IR format
• Convert Sigma → KQL → SPL`,
  },
];

const SUGGESTIONS = [
  "Explain alert CRWD-9F3A7C12",
  "What is T1003.001 and how do I detect it?",
  "Build a hunt for Office spawning script interpreters",
  "Draft an investigation summary for the WS-FIN-3041 incident",
  "Convert this Sigma rule to KQL",
];

export default function AiAssistantPage() {
  const [messages, setMessages] = useState<Msg[]>(SEED_MESSAGES);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);

  function send(text?: string) {
    const q = (text ?? input).trim();
    if (!q) return;
    setMessages(m => [...m, { role: "user", content: q }]);
    setInput("");
    setStreaming(true);

    // Simulated assistant response. Replace with /api/ai stream call.
    setTimeout(() => {
      setMessages(m => [...m, { role: "assistant", content: respondTo(q) }]);
      setStreaming(false);
    }, 700);
  }

  return (
    <div>
      <Topbar title="AI Co-Analyst" subtitle="Powered by Claude · grounded in your SOC telemetry" />
      <div className="container mx-auto max-w-[1400px] px-6 py-6 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <Card padded={false} className="flex flex-col h-[calc(100vh-180px)]">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-md border border-cyber-500/40 bg-cyber-500/10 text-cyber-300">
                <Bot className="h-4 w-4" />
              </span>
              <div>
                <p className="text-sm font-semibold text-white">SOC Co-Analyst</p>
                <p className="text-[11px] text-slate-500">Context: WS-FIN-3041 · phishing-to-cloud-exfil</p>
              </div>
            </div>
            <Button size="sm" variant="outline"><Workflow className="h-4 w-4" /> Inject IR Context</Button>
          </div>

          <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
                {m.role === "assistant" && (
                  <span className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-cyber-500/40 bg-cyber-500/10 text-cyber-300">
                    <Bot className="h-4 w-4" />
                  </span>
                )}
                <div className={`max-w-[80%] rounded-lg border px-3.5 py-2.5 text-sm ${
                  m.role === "user"
                    ? "border-cyber-500/40 bg-cyber-500/10 text-slate-100"
                    : "border-border bg-bg text-slate-200"}`}>
                  <pre className="whitespace-pre-wrap font-sans">{m.content}</pre>
                </div>
                {m.role === "user" && (
                  <span className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-bg text-slate-300">
                    <User className="h-4 w-4" />
                  </span>
                )}
              </div>
            ))}
            {streaming && (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyber-400" />
                <span>Co-Analyst is thinking…</span>
              </div>
            )}
          </div>

          <div className="border-t border-border px-5 py-3">
            <div className="flex flex-wrap gap-1.5 pb-2">
              {SUGGESTIONS.map(s => (
                <button key={s} onClick={() => send(s)}
                  className="rounded-full border border-border bg-bg px-3 py-1 text-[11px] text-slate-300 hover:border-cyber-500/40 hover:text-cyber-200">
                  {s}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") send(); }}
                placeholder="Ask about an alert, a host, an IOC, a technique…"
                className="h-10 flex-1 rounded-md border border-border bg-bg-elevated px-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
              />
              <Button onClick={() => send()} disabled={streaming}><Send className="h-4 w-4" /> Send</Button>
            </div>
          </div>
        </Card>

        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Capabilities</h3>
            <ul className="mt-3 space-y-2 text-xs text-slate-300">
              {[
                "Explain alerts in human language",
                "Map to MITRE & recommend pivots",
                "Generate triage timelines",
                "Author Sigma / KQL / SPL",
                "Grade your investigation",
                "Reduce context to executive summary",
              ].map(c => (
                <li key={c} className="flex items-start gap-2">
                  <Sparkles className="mt-0.5 h-3.5 w-3.5 text-cyber-300" />
                  <span>{c}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Grounding</h3>
            <p className="mt-2 text-xs text-slate-400">
              The assistant has read-only access to your active scenario, alerts, telemetry, IOCs, and your investigation notes.
              It cannot take actions on production systems.
            </p>
            <ul className="mt-3 space-y-1.5 text-[11px]">
              {["alerts","telemetry","investigations","mitre","detections"].map(t => (
                <li key={t} className="rounded border border-border bg-bg px-2 py-1.5 font-mono text-slate-300">tool: {t}</li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}

function respondTo(q: string): string {
  const lower = q.toLowerCase();
  if (lower.includes("crwd-")) {
    return `Alert CRWD-9F3A7C12 fired because WINWORD.EXE spawned powershell.exe with -EncodedCommand and -W Hidden — a canonical T1059.001 pattern initiated by a macro-enabled document (T1566.001). Immediate next pivots:

1) Decode the EncodedCommand to confirm intent (likely an IEX downloader).
2) Pull the network connection telemetry for the same PID — look for outbound 443 to a recently-registered domain.
3) Search EDR for the WINWORD attachment SHA256 fleet-wide.
4) Check whether a Run key or scheduled task was added in the next 5 minutes (T1547.001 / T1053.005).

Containment: network-isolate the host, reset the user's creds, revoke active SSO sessions.`;
  }
  if (lower.includes("t1003.001") || lower.includes("lsass")) {
    return `T1003.001 = OS Credential Dumping: LSASS Memory.

How attackers do it: read LSASS process memory (Mimikatz, comsvcs.dll MiniDump, procdump, custom tools) to extract NTLM hashes, Kerberos tickets, and plaintext passwords cached by SSPs.

How to detect:
• Sysmon Event 10 ProcessAccess with Target=lsass.exe and GrantedAccess in (0x1010, 0x1410, 0x143A) from a non-system process
• rundll32.exe with cmdline containing 'comsvcs.dll' and 'MiniDump'
• Microsoft Defender ASR rule "Block credential stealing from LSASS" for prevention

Hunt seed:
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| extend Target = tostring(parse_json(AdditionalFields).TargetImageFileName)
| where Target endswith "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","wininit.exe","services.exe","WUDFHost.exe")`;
  }
  if (lower.includes("hunt") || lower.includes("kql")) {
    return `Here's a KQL hunt for Office spawning script interpreters:

DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| extend EncodedCmd = ProcessCommandLine matches regex @"-(Enc|EncodedCommand|e)\\s"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, EncodedCmd
| sort by Timestamp desc

Tune by allowlisting any internal apps that legitimately spawn cmd.exe from Excel (very rare).`;
  }
  return `I can help with that. Share the alert UID, host, or query you have in mind and I'll walk through it step-by-step.`;
}
