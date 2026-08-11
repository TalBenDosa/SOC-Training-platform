"use client";
/**
 * Standalone EDR console — investigate a host the way an analyst does on
 * CrowdStrike Falcon / Defender for Endpoint: walk the process ANCESTRY tree,
 * read command lines, look up hashes, then decide (isolate the payload, or
 * resolve as benign). Data is self-contained (src/lib/edr/investigations.ts);
 * hash lookups hit the real hashDatabase so "Look up hash" returns a genuine
 * verdict.
 */
import { useMemo, useState } from "react";
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

const SEV_STYLE: Record<string, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  medium: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  low: "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
};

export default function EdrConsolePage() {
  usePageTitle("EDR Console");
  const [invId, setInvId] = useState(EDR_INVESTIGATIONS[0].id);
  const inv = useMemo(() => EDR_INVESTIGATIONS.find(i => i.id === invId)!, [invId]);
  return <Console key={inv.id} inv={inv} onSwitch={setInvId} invId={invId} />;
}

function Console({ inv, invId, onSwitch }: { inv: EdrInvestigation; invId: string; onSwitch: (id: string) => void }) {
  const { roots, childrenOf } = useMemo(() => buildProcessTree(inv.processes), [inv]);
  const detByPid = useMemo(() => {
    const m = new Map<number, typeof inv.detections>();
    for (const d of inv.detections) { const l = m.get(d.pid) ?? []; l.push(d); m.set(d.pid, l); }
    return m;
  }, [inv]);

  const [selPid, setSelPid] = useState<number | null>(inv.detections[0]?.pid ?? roots[0]?.pid ?? null);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set(inv.processes.map(p => p.pid))); // all open
  const [isolated, setIsolated] = useState(false);
  const [hashResult, setHashResult] = useState<Record<number, string>>({});
  const [decided, setDecided] = useState<null | { correct: boolean }>(null);

  const sel = inv.processes.find(p => p.pid === selPid) ?? null;
  const toggle = (pid: number) => setExpanded(s => { const n = new Set(s); n.has(pid) ? n.delete(pid) : n.add(pid); return n; });

  function decide(choice: number /* pid, or -1 for benign */) {
    setDecided({ correct: choice === inv.answer.pid });
  }

  return (
    <div>
      <Topbar title="EDR Console" subtitle="Investigate the endpoint — walk the tree, decide" />
      <div className="container mx-auto max-w-[1200px] px-6 py-6 space-y-4">
        {/* case switch + host header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-2">
            {EDR_INVESTIGATIONS.map(i => (
              <button key={i.id} onClick={() => onSwitch(i.id)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${i.id === invId ? "border-cyber-500/60 bg-cyber-500/10 text-cyber-200" : "border-border bg-bg-elevated text-slate-400 hover:text-white"}`}>
                {i.host.name}
              </button>
            ))}
          </div>
          <Button variant={isolated ? "outline" : "primary"} size="sm" onClick={() => setIsolated(v => !v)}>
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
                  {decided && sel.note && (
                    <p className="mt-2 rounded-lg border border-border bg-bg px-3 py-2 text-[12px] text-slate-300"><span className="text-slate-500">why:</span> {sel.note}</p>
                  )}
                </div>
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
              <div className="mt-3">
                <Button variant="outline" size="sm" onClick={() => { setDecided(null); }}>Investigate again</Button>
              </div>
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
