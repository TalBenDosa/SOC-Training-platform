"use client";
/**
 * Standalone EDR console — investigate a host the way an analyst does on
 * CrowdStrike Falcon / Defender for Endpoint: walk the process ANCESTRY tree,
 * read command lines, look up hashes, then decide (isolate the payload, or
 * resolve as benign). Data is self-contained (src/lib/edr/investigations.ts);
 * hash lookups hit the real hashDatabase so "Look up hash" returns a genuine
 * verdict.
 */
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  Cpu, ShieldAlert, ShieldCheck, ChevronRight, ChevronDown, FileSearch, Ban, CheckCircle2,
  XCircle, Clock, Network, FileWarning, Fingerprint, MonitorX, Terminal, AlertTriangle,
} from "lucide-react";
import { EDR_INVESTIGATIONS, buildProcessTree, type EdrInvestigation, type EdrProcess } from "@/lib/edr/investigations";
import { lookupHash, vtLabel, vtColor } from "@/lib/sim/hashDatabase";
import { isContained, setContained } from "@/lib/edr/containment";
import { isTrainingActive } from "@/lib/sim/trainingSession";

const SEV_STYLE: Record<string, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  medium: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  low: "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
};

export default function EdrConsolePage() {
  usePageTitle("EDR Console");
  const router = useRouter();
  // A plain client component (no useSearchParams / Suspense) so the page hydrates
  // normally on a hard load or refresh — an earlier Suspense-wrapped
  // useSearchParams left the console rendered but NON-interactive after a direct
  // navigation. The deep-link (?case=…) is read post-mount instead, which also
  // avoids any server/client hydration mismatch.
  const [allowed, setAllowed] = useState<boolean | null>(null); // null = still checking
  const [liveInv, setLiveInv] = useState<EdrInvestigation | null>(null);
  const [invId, setInvId] = useState(EDR_INVESTIGATIONS[0].id);

  useEffect(() => {
    // The EDR console is ONLY reachable from an active shift — the student must
    // have pressed Start Training on the Dashboard. No shift → bounce back to
    // the Dashboard (there's nothing to investigate on the endpoint yet).
    if (!isTrainingActive()) { router.replace("/dashboard"); return; }
    setAllowed(true);
    // Deep-link from the SOC Dashboard: /edr?case=<id> opens that host, the
    // "Investigate in EDR" pivot. case=live loads the EdrInvestigation the
    // Dashboard generated from the attack running in the feed (sessionStorage).
    const requested = new URLSearchParams(window.location.search).get("case");
    if (requested === "live") {
      try {
        // localStorage (shared across tabs) — the Dashboard stashed it here so
        // this EDR tab can read the live attack it generated.
        const stashed = JSON.parse(localStorage.getItem("edr_live_investigation") || "null");
        if (stashed?.id) { setLiveInv(stashed); setInvId(stashed.id); return; }
      } catch { /* fall through to a static case */ }
    }
    if (requested && EDR_INVESTIGATIONS.some(i => i.id === requested)) setInvId(requested);
  }, [router]);

  const investigations = useMemo(
    () => (liveInv ? [liveInv, ...EDR_INVESTIGATIONS] : EDR_INVESTIGATIONS),
    [liveInv],
  );
  const inv = investigations.find(i => i.id === invId) ?? investigations[0];
  if (!allowed) return null; // checking access / redirecting to the Dashboard
  return <Console key={inv.id} inv={inv} investigations={investigations} onSwitch={setInvId} invId={inv.id} />;
}

function Console({ inv, investigations, invId, onSwitch }: { inv: EdrInvestigation; investigations: EdrInvestigation[]; invId: string; onSwitch: (id: string) => void }) {
  const { roots, childrenOf } = useMemo(() => buildProcessTree(inv.processes), [inv]);
  const detByPid = useMemo(() => {
    const m = new Map<number, typeof inv.detections>();
    for (const d of inv.detections) { const l = m.get(d.pid) ?? []; l.push(d); m.set(d.pid, l); }
    return m;
  }, [inv]);

  const [selPid, setSelPid] = useState<number | null>(inv.detections[0]?.pid ?? roots[0]?.pid ?? null);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set(inv.processes.map(p => p.pid))); // all open
  // Isolation is shared with the SOC Dashboard: containing here marks the host
  // "Contained" there too. Seed from the store so a host isolated on either
  // surface stays isolated on both.
  const [isolated, setIsolated] = useState(() => isContained(inv.host.name));
  const isolate = (next: boolean) => { setIsolated(next); setContained(inv.host.name, next); };
  const [hashResult, setHashResult] = useState<Record<number, string>>({});
  const [decided, setDecided] = useState<null | { correct: boolean }>(null);
  const [tab, setTab] = useState<"overview" | "network" | "files">("overview");
  const [rtr, setRtr] = useState<{ cmd: string; out: string }[]>([]);
  const [rtrIn, setRtrIn] = useState("");

  const sel = inv.processes.find(p => p.pid === selPid) ?? null;
  const toggle = (pid: number) => setExpanded(s => { const n = new Set(s); n.has(pid) ? n.delete(pid) : n.add(pid); return n; });

  // Incident Workbench roll-up — the "full picture" a Falcon incident gives:
  // one score, the ATT&CK techniques seen on this host, and the affected
  // entities, all derived from the detections already on the investigation.
  const workbench = useMemo(() => {
    const SEV_WEIGHT: Record<string, number> = { critical: 40, high: 25, medium: 12, low: 4 };
    const score = Math.min(100, inv.detections.reduce((s, d) => s + (SEV_WEIGHT[d.severity] ?? 0), 0));
    const techniques = Array.from(new Set(inv.detections.map(d => d.technique)));
    const band = score >= 70 ? "Critical" : score >= 40 ? "High" : score >= 15 ? "Medium" : "Low";
    return { score, techniques, band };
  }, [inv]);
  const bandStyle = workbench.band === "Critical" ? "text-severity-critical" : workbench.band === "High" ? "text-severity-high" : workbench.band === "Medium" ? "text-neon-amber" : "text-neon-green";

  // RTR-lite: a simulated Real Time Response shell answering from the host's data.
  function runRtr(raw: string) {
    const cmd = raw.trim();
    if (!cmd) return;
    const [verb, ...args] = cmd.split(/\s+/);
    let out = "";
    switch (verb.toLowerCase()) {
      case "help":
        out = "Commands: ps · netstat · kill <pid> · get <path> · reg query <key> · cat <path> · contain · clear"; break;
      case "ps":
        out = ["PID    PPID   USER                 IMAGE", ...inv.processes
          .slice().sort((a, b) => a.pid - b.pid)
          .map(p => `${String(p.pid).padEnd(6)} ${String(p.ppid).padEnd(6)} ${p.user.padEnd(20)} ${p.name}`)].join("\n"); break;
      case "netstat": {
        const rows = inv.processes.flatMap(p => (p.network ?? []).map(c => `${c.proto ?? "TCP"}  ${p.name}(${p.pid}) -> ${c.remote_ip}:${c.remote_port}${c.domain ? ` (${c.domain})` : ""}  ${c.direction}`));
        out = rows.length ? rows.join("\n") : "No active connections."; break;
      }
      case "kill": {
        const pid = Number(args[0]);
        const p = inv.processes.find(x => x.pid === pid);
        out = p ? `Process ${pid} (${p.name}) terminated.` : `No process with pid ${args[0] ?? "?"}.`; break;
      }
      case "get": {
        const path = args.join(" ");
        const hit = inv.processes.some(p => (p.files ?? []).some(f => f.path.toLowerCase() === path.toLowerCase()));
        out = path ? `Queued "${path}" for upload to the cloud (password: infected).${hit ? " File captured." : " (path not seen on host — check spelling)"}` : "usage: get <full path>"; break;
      }
      case "reg":
        out = args[0] === "query"
          ? `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    Updater   REG_SZ   rundll32.exe C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll,Start`
          : "usage: reg query <key>"; break;
      case "cat": {
        const path = args.join(" ");
        out = path ? `(binary content) ${path} — use 'get' to pull it to the cloud for analysis.` : "usage: cat <path>"; break;
      }
      case "contain": isolate(true); out = "Host network-contained. Only sensor traffic allowed."; break;
      case "clear": setRtr([]); return;
      default: out = `rtr: unknown command '${verb}'. Type 'help'.`;
    }
    setRtr(r => [...r, { cmd, out }]);
  }

  function decide(choice: number /* pid, or -1 for benign */) {
    // A student who flags ANY process the console itself confirms malicious — its
    // hash resolves malicious under "Look up hash" (lookupHash) — has correctly
    // identified a malicious process, so accept it, even when a *different*
    // process is the designated "impact" the debrief highlights (e.g. flagging the
    // Cobalt Strike beacon instead of the LockBit encryptor in the ransomware
    // case). Penalizing a flag the tooling itself calls malicious teaches students
    // to distrust the hash lookup — the exact negative-learning we're removing.
    // Benign resolution (-1) stays correct only when the case truly has no payload;
    // in a benign case, flagging any process is still wrong.
    const correct = (() => {
      if (choice === -1) return inv.answer.pid === -1;
      if (inv.answer.pid < 0) return false;
      if (choice === inv.answer.pid) return true;
      const p = inv.processes.find(x => x.pid === choice);
      return !!(p?.sha256 && lookupHash(p.sha256)?.malicious);
    })();
    setDecided({ correct });
    // Flag that the student investigated on the endpoint, so the Dashboard can
    // remind them to actually FILE the incident report — investigating without
    // writing it up is the classic half-finished ticket. localStorage so the
    // write fires a `storage` event in the Dashboard tab.
    try {
      localStorage.setItem("soc_edr_investigated", "1");
      window.dispatchEvent(new CustomEvent("soc:edr-investigated"));
    } catch { /* ignore */ }
  }

  return (
    <div>
      <Topbar title="EDR Console" subtitle="Investigate the endpoint — walk the tree, decide" />
      <div className="container mx-auto max-w-[1200px] px-6 py-6 space-y-4">
        {/* case switch + host header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-2">
            {investigations.map(i => (
              <button key={i.id} onClick={() => onSwitch(i.id)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${i.id === invId ? "border-cyber-500/60 bg-cyber-500/10 text-cyber-200" : "border-border bg-bg-elevated text-slate-400 hover:text-white"}`}>
                {i.id === "live" && <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-neon-green align-middle" />}
                {i.host.name}
              </button>
            ))}
          </div>
          <Button variant={isolated ? "outline" : "primary"} size="sm" onClick={() => isolate(!isolated)}>
            <MonitorX className="mr-1.5 h-4 w-4" /> {isolated ? "Host isolated ✓ — release" : "Isolate host"}
          </Button>
        </div>

        <Card className="border-cyber-500/20">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-bg"><Cpu className="h-5 w-5 text-cyber-300" /></span>
              <div>
                <p className="text-sm font-bold text-white">{inv.host.name} <span className="ml-1 font-mono text-[11px] font-normal text-slate-400">{inv.host.ip}</span></p>
                <p className="text-[11px] text-slate-400">{inv.host.os} · signed-in: <span className="font-mono">{inv.host.user}</span></p>
              </div>
            </div>
            <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${isolated ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : "border-neon-green/30 bg-neon-green/10 text-neon-green"}`}>
              {isolated ? "Contained — network isolated" : "Online"}
            </span>
          </div>
          <p className="mt-3 text-[13px] text-slate-300">{inv.summary}</p>
        </Card>

        {/* Incident Workbench — one incident, scored, with the ATT&CK picture */}
        <Card className="border-border">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <div className="flex items-center gap-3">
              <div className="text-center">
                <p className={`font-mono text-2xl font-bold leading-none ${bandStyle}`}>{workbench.score}</p>
                <p className="text-[9px] uppercase tracking-wider text-slate-500">score</p>
              </div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Incident severity</p>
                <p className={`text-sm font-bold ${bandStyle}`}>{workbench.band}</p>
              </div>
            </div>
            <div className="h-8 w-px bg-border" />
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Detections</p>
              <p className="text-sm font-bold text-white">{inv.detections.length}</p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Affected</p>
              <p className="text-sm font-mono text-slate-200">{inv.host.name} · {inv.host.user}</p>
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">ATT&amp;CK techniques</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {workbench.techniques.length ? workbench.techniques.map(t => (
                  <span key={t} className="rounded border border-neon-purple/30 bg-neon-purple/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-neon-purple">{t}</span>
                )) : <span className="text-[11px] text-slate-500">none</span>}
              </div>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.15fr_1fr]">
          {/* process tree */}
          <Card className="p-0">
            <h2 className="border-b border-border px-4 py-3 text-sm font-bold text-white">Process tree</h2>
            <div className="max-h-[460px] overflow-auto p-2 font-mono text-[12px]">
              {roots.map(r => (
                <TreeNode key={r.pid} p={r} depth={0} childrenOf={childrenOf} expanded={expanded} toggle={toggle}
                  selPid={selPid} setSel={setSelPid} detByPid={detByPid} reveal={decided !== null} />
              ))}
            </div>
          </Card>

          {/* detail + timeline */}
          <div className="space-y-4">
            {sel && (
              <Card className="p-0">
                <div className="flex items-center justify-between border-b border-border px-4 py-3">
                  <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Terminal className="h-4 w-4 text-cyber-300" /> {sel.name} <span className="font-mono text-[11px] font-normal text-slate-400">pid {sel.pid}</span></h2>
                  {!sel.signed && <span className="rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-bold text-severity-high">UNSIGNED</span>}
                </div>
                {/* tabs: Overview / Network / Files (Falcon execution-details style) */}
                <div className="flex gap-1 border-b border-border px-3 pt-2 text-[11px]">
                  {(["overview", "network", "files"] as const).map(t => (
                    <button key={t} onClick={() => setTab(t)}
                      className={`rounded-t px-2.5 py-1.5 font-medium capitalize transition ${tab === t ? "bg-bg text-cyber-300" : "text-slate-400 hover:text-white"}`}>
                      {t}{t === "network" && sel.network?.length ? ` (${sel.network.length})` : ""}{t === "files" && sel.files?.length ? ` (${sel.files.length})` : ""}
                    </button>
                  ))}
                </div>

                {tab === "overview" && (
                  <div className="space-y-2 px-4 py-3 text-[12px]">
                    <Field label="Command line"><code className="break-all text-slate-200">{sel.cmdline}</code></Field>
                    <Field label="Image path"><code className="break-all text-slate-400">{sel.path}</code></Field>
                    <Field label="User"><span className="font-mono text-slate-300">{sel.user}</span></Field>
                    <Field label="Started"><span className="font-mono text-slate-300">{sel.startedAt}</span></Field>
                    <Field label="Signed"><span className={sel.signed ? "text-neon-green" : "text-severity-high"}>{sel.signed ? "Yes" : "No — not signed"}</span></Field>
                    {sel.sha256 && (
                      <div className="pt-1">
                        <div className="flex items-center gap-2">
                          <Fingerprint className="h-3.5 w-3.5 text-slate-500" />
                          <code className="break-all text-[11px] text-slate-400">{sel.sha256}</code>
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                          <Button variant="outline" size="sm" onClick={() => {
                            const e = lookupHash(sel.sha256!);
                            setHashResult(r => ({ ...r, [sel.pid]: e ? vtLabel(e) : "Unknown — no reputation on record" }));
                          }}><FileSearch className="mr-1.5 h-3.5 w-3.5" /> Look up hash</Button>
                          {hashResult[sel.pid] && (
                            <span className={`text-[12px] font-bold ${lookupHash(sel.sha256!)?.malicious ? vtColor(lookupHash(sel.sha256!)!) : "text-slate-400"}`}>
                              {hashResult[sel.pid]}
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                    {(() => { const ioa = detByPid.get(sel.pid)?.[0] as { ioa?: string } | undefined; return ioa?.ioa ? (
                      <p className="mt-2 rounded-lg border border-severity-high/25 bg-severity-high/5 px-3 py-2 text-[12px] text-slate-300"><span className="font-bold text-severity-high">IOA</span> · {ioa.ioa}</p>
                    ) : null; })()}
                    {decided && sel.note && (
                      <p className="mt-1 rounded-lg border border-border bg-bg px-3 py-2 text-[12px] text-slate-300"><span className="text-slate-500">why:</span> {sel.note}</p>
                    )}
                  </div>
                )}

                {tab === "network" && (
                  <div className="px-4 py-3 text-[12px]">
                    {sel.network?.length ? (
                      <table className="w-full text-left"><tbody className="divide-y divide-border/50">
                        {sel.network.map((c, i) => (
                          <tr key={i}>
                            <td className="py-1.5 pr-2 font-mono text-slate-500">{c.ts}</td>
                            <td className="py-1.5 pr-2 text-slate-400">{c.proto ?? "TCP"}</td>
                            <td className="py-1.5 pr-2 font-mono text-slate-200">{c.remote_ip}:{c.remote_port}</td>
                            <td className="py-1.5 font-mono text-cyber-300">{c.domain ?? ""}</td>
                          </tr>
                        ))}
                      </tbody></table>
                    ) : <p className="text-slate-500">No network activity recorded for this process.</p>}
                  </div>
                )}

                {tab === "files" && (
                  <div className="px-4 py-3 text-[12px]">
                    {sel.files?.length ? (
                      <div className="space-y-1.5">
                        {sel.files.map((f, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className="font-mono text-slate-500">{f.ts}</span>
                            <span className={`rounded px-1 text-[10px] font-bold uppercase ${f.action === "write" ? "bg-neon-amber/15 text-neon-amber" : "bg-slate-700 text-slate-300"}`}>{f.action}</span>
                            <code className="break-all text-slate-300">{f.path}</code>
                          </div>
                        ))}
                      </div>
                    ) : <p className="text-slate-500">No file activity recorded for this process.</p>}
                  </div>
                )}
              </Card>
            )}

            <Card className="p-0">
              <h2 className="border-b border-border px-4 py-3 text-sm font-bold text-white">Timeline</h2>
              <div className="max-h-[220px] space-y-1.5 overflow-auto px-4 py-3">
                {inv.timeline.map((t, i) => (
                  <div key={i} className="flex items-start gap-2 text-[12px]">
                    <span className="font-mono text-[11px] text-slate-500">{t.at}</span>
                    <TimelineIcon kind={t.kind} />
                    <span className="text-slate-300">{t.text}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        {/* RTR-lite — simulated Real Time Response shell */}
        <Card className="p-0">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
            <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Terminal className="h-4 w-4 text-neon-green" /> Real Time Response — {inv.host.name}</h2>
            <div className="flex flex-wrap gap-1">
              {["ps", "netstat", "reg query Run", "help"].map(c => (
                <button key={c} onClick={() => runRtr(c)} className="rounded border border-border bg-bg px-2 py-0.5 font-mono text-[10px] text-slate-400 transition hover:text-white">{c}</button>
              ))}
            </div>
          </div>
          <div className="max-h-[240px] overflow-auto bg-black/40 px-4 py-3 font-mono text-[11.5px] leading-relaxed">
            {rtr.length === 0 && <p className="text-slate-500">Connected to {inv.host.name}. Type <span className="text-slate-300">help</span>, or use the quick commands above. RTR runs on the endpoint — <span className="text-neon-amber">kill</span>, <span className="text-neon-amber">get</span> and <span className="text-neon-amber">contain</span> take real action.</p>}
            {rtr.map((l, i) => (
              <div key={i} className="mb-2">
                <p className="text-neon-green">{inv.host.name}&gt; <span className="text-slate-200">{l.cmd}</span></p>
                <pre className="whitespace-pre-wrap text-slate-400">{l.out}</pre>
              </div>
            ))}
          </div>
          <form onSubmit={e => { e.preventDefault(); runRtr(rtrIn); setRtrIn(""); }} className="flex items-center gap-2 border-t border-border px-4 py-2.5">
            <span className="font-mono text-[12px] text-neon-green">&gt;</span>
            <input value={rtrIn} onChange={e => setRtrIn(e.target.value)} placeholder="ps · netstat · kill 6388 · get <path> · reg query Run"
              className="flex-1 bg-transparent font-mono text-[12px] text-white placeholder-slate-600 focus:outline-none" aria-label="RTR command" />
            <Button type="submit" variant="outline" size="sm">Run</Button>
          </form>
        </Card>

        {/* decision */}
        <Card className={decided ? (decided.correct ? "border-neon-green/40" : "border-severity-high/40") : "border-cyber-500/30"}>
          {!decided ? (
            <>
              <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Your call</h2>
              <p className="mt-1 text-[13px] text-slate-400">Select the process that is the malicious <strong>payload</strong> and flag it — or, if this is benign activity, resolve it as a false positive.</p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button variant="primary" size="sm" disabled={selPid === null} onClick={() => decide(selPid!)}>
                  <Ban className="mr-1.5 h-4 w-4" /> Flag {sel ? `${sel.name} (pid ${sel.pid})` : "selected"} as payload
                </Button>
                <span className="text-[11px] text-slate-500">or</span>
                <Button variant="outline" size="sm" onClick={() => decide(-1)}>
                  <ShieldCheck className="mr-1.5 h-4 w-4" /> Resolve as benign / false positive
                </Button>
              </div>
            </>
          ) : (
            <>
              <h2 className={`flex items-center gap-2 text-sm font-bold ${decided.correct ? "text-neon-green" : "text-severity-high"}`}>
                {decided.correct ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                {decided.correct ? "Correct" : "Not quite"}
              </h2>
              <p className="mt-2 text-[13px] text-slate-200">{inv.answer.explanation}</p>
              <p className="mt-2 text-[11px] text-slate-500">The process tree is now colour-coded by verdict, and each node&apos;s reasoning is shown in its detail panel.</p>
              {/* The investigation isn't done until it's written up. This runs in
                  its own tab, so send them BACK to the Dashboard tab to file the
                  report — the one place they're actually graded. */}
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  onClick={() => window.close()}
                  className="inline-flex items-center gap-1.5 rounded-md bg-neon-purple px-3.5 py-2 text-xs font-bold text-white shadow transition hover:brightness-110"
                >
                  <FileWarning className="h-4 w-4" /> Done — return to the Dashboard and file your report
                </button>
                <Button variant="outline" size="sm" onClick={() => { setDecided(null); }}>Investigate again</Button>
              </div>
              <p className="mt-2 text-[11px] text-neon-amber">Switch back to your SOC Dashboard tab to write the incident report — your findings only count once it&apos;s submitted.</p>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

function TreeNode({ p, depth, childrenOf, expanded, toggle, selPid, setSel, detByPid, reveal }: {
  p: EdrProcess; depth: number; childrenOf: Map<number, EdrProcess[]>; expanded: Set<number>;
  toggle: (pid: number) => void; selPid: number | null; setSel: (pid: number) => void;
  detByPid: Map<number, { technique: string; name: string; severity: string }[]>; reveal: boolean;
}) {
  const kids = childrenOf.get(p.pid) ?? [];
  const open = expanded.has(p.pid);
  const dets = detByPid.get(p.pid) ?? [];
  const verdictColor = reveal
    ? p.verdict === "malicious" ? "text-severity-critical" : p.verdict === "suspicious" ? "text-neon-amber" : "text-slate-300"
    : "text-slate-200";
  return (
    <div>
      <div
        onClick={() => setSel(p.pid)}
        style={{ paddingLeft: depth * 16 + 4 }}
        className={`flex cursor-pointer items-center gap-1.5 rounded px-1.5 py-1 transition ${selPid === p.pid ? "bg-cyber-500/15" : "hover:bg-white/[0.03]"}`}
      >
        {kids.length > 0 ? (
          <button onClick={e => { e.stopPropagation(); toggle(p.pid); }} className="shrink-0 text-slate-500">
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        ) : <span className="w-3.5 shrink-0" />}
        <span className={`truncate font-medium ${verdictColor}`}>{p.name}</span>
        <span className="shrink-0 text-[10px] text-slate-500">{p.pid}</span>
        {!p.signed && <span className="shrink-0 rounded bg-severity-high/15 px-1 text-[9px] font-bold text-severity-high">unsigned</span>}
        {dets.length > 0 && (
          <span className={`shrink-0 rounded border px-1 text-[9px] font-bold ${SEV_STYLE[dets[0].severity]}`}>
            ⚠ {dets[0].technique}
          </span>
        )}
      </div>
      {open && kids.map(k => (
        <TreeNode key={k.pid} p={k} depth={depth + 1} childrenOf={childrenOf} expanded={expanded} toggle={toggle}
          selPid={selPid} setSel={setSel} detByPid={detByPid} reveal={reveal} />
      ))}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-2">
      <span className="w-24 shrink-0 text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  );
}

function TimelineIcon({ kind }: { kind: string }) {
  const cls = "h-3.5 w-3.5 shrink-0 mt-0.5";
  if (kind === "network") return <Network className={`${cls} text-cyber-300`} />;
  if (kind === "file") return <FileWarning className={`${cls} text-neon-amber`} />;
  if (kind === "detection") return <AlertTriangle className={`${cls} text-severity-high`} />;
  return <Clock className={`${cls} text-slate-500`} />;
}
