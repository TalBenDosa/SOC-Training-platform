"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DetailPanelBody } from "@/app/(app)/dashboard/EventFeed";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { ArrowUpRight, Check, ShieldAlert, ChevronDown, Search } from "lucide-react";
import type { Ev, ScopeState } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { enrichSnapshot } from "./shared";
import { ScopeConsole } from "./ScopeConsole";

// ── T3 threat-hunt console ───────────────────────────────────────────────────
export function HuntConsole({ scope, elevations, elevAcked, nameOf, act, onEdr, onPivot }: {
  scope: ScopeState; elevations: Ev[]; elevAcked: Set<string>; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onEdr?: (description?: string) => void;
  onPivot?: (field: "user" | "host" | "ip", value: string) => void;
}) {
  const [f, setF] = useState({ hypothesis: "", finding: "", technique: "", conclusion: "confirmed" });
  const [busy, setBusy] = useState(false);
  const [busyElev, setBusyElev] = useState<string | null>(null);
  const [openElev, setOpenElev] = useState<number | null>(null);
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null); // A3: live threat-intel enrichment
  async function log() {
    if (f.hypothesis.trim().length < 8) return;
    setBusy(true); const ok = await act("hunt.logged", { ...f }); setBusy(false);
    if (ok) setF({ hypothesis: "", finding: "", technique: "", conclusion: "confirmed" });
  }
  return (
    <div className="space-y-4">
      {/* Routed work handed down from Tier-2 — deep-hunt these specifically */}
      {elevations.length > 0 && (
        <Card className="border-neon-amber/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-neon-amber" /> Elevations for you ({elevations.length})</h3>
          <p className="mt-1 text-[11px] text-slate-400">Tier-2 handed these down for a deep hunt.</p>
          <div className="mt-2 space-y-2">
            {elevations.slice().reverse().map(e => {
              const p = e.payload as { event_id?: string; summary?: string; severity?: string; hostname?: string; entity?: string; snapshot?: Record<string, unknown>; hunt_ask?: string; t2_verdict?: string; t2_findings?: string; t2_recommendation?: string };
              const eid = String(p.event_id); const b = busyElev === e.seq + ""; const snap = enrichSnapshot(p.snapshot); const isOpen = openElev === e.seq;
              const done = elevAcked.has(eid);
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <p className="text-sm text-slate-200">{asStr(p.summary) || "elevated case"}</p>
                  <p className="mt-0.5 font-mono text-[10px] text-slate-500">from {nameOf(e.actor_id)} · sev {asStr(p.severity) || "—"}{asStr(p.hostname) ? ` · ${asStr(p.hostname)}` : ""}</p>
                  {/* A2: the T2 hunt-ask + filed findings so the hunter starts from context, not the raw alert */}
                  {asStr(p.hunt_ask) && (
                    <div className="mt-1.5 rounded border border-neon-purple/30 bg-neon-purple/[0.06] px-2 py-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-neon-purple">Tier-2 asks you to hunt</p>
                      <p className="mt-0.5 text-[11px] text-slate-200">{asStr(p.hunt_ask)}</p>
                    </div>
                  )}
                  {(asStr(p.t2_findings) || asStr(p.t2_verdict) || asStr(p.t2_recommendation)) && (
                    <div className="mt-1 rounded border border-border/50 bg-bg-elevated/30 px-2 py-1 text-[11px]">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Tier-2 investigation</p>
                      {asStr(p.t2_verdict) && <p className="mt-0.5 text-slate-400">verdict: {asStr(p.t2_verdict).replace("_", " ")}</p>}
                      {asStr(p.t2_findings) && <p className="mt-0.5 text-slate-300">{asStr(p.t2_findings)}</p>}
                      {asStr(p.t2_recommendation) && <p className="mt-0.5 text-cyber-200">▶ recommended: {asStr(p.t2_recommendation)}</p>}
                    </div>
                  )}
                  {snap && (
                    <button onClick={() => setOpenElev(isOpen ? null : e.seq)} className="mt-1 flex items-center gap-1 text-[11px] text-cyber-300 underline-offset-2 hover:underline">
                      <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? "" : "-rotate-90"}`} /> {isOpen ? "Hide the log" : "View the full log (raw event + JSON)"}
                    </button>
                  )}
                  {snap && isOpen && <div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40"><DetailPanelBody event={snap} onThreatQuery={setThreatQuery} onPivot={onPivot} /></div>}
                  {!done && <Button variant="outline" size="sm" className="mt-2" disabled={b} onClick={async () => { setBusyElev(e.seq + ""); await act("elevation.acknowledged", { event_id: eid }); setBusyElev(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Take the hunt</Button>}
                  {done && <p className="mt-1 text-[11px] text-neon-green">✓ taken — record findings below</p>}
                </div>
              );
            })}
          </div>
        </Card>
      )}
      <Card>
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Threat hunt (Tier-3)</h3>
          {onEdr && <Button variant="outline" size="sm" onClick={() => onEdr()}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>}
        </div>
        <p className="mt-1 text-[11px] text-slate-400">Beyond the queue: form a hypothesis, hunt the feed, record what you found.</p>
        <div className="mt-2 space-y-2">
          <input value={f.hypothesis} onChange={e => setF(s => ({ ...s, hypothesis: e.target.value }))} placeholder="Hypothesis — name the entities (e.g. 'lateral movement from FIN-WS-07 to DC01 via SMB')" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <textarea value={f.finding} onChange={e => setF(s => ({ ...s, finding: e.target.value }))} placeholder="Finding / evidence — cite the hosts, users, IPs, hashes or techniques you verified it against" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <div className="flex gap-1.5">
            <input value={f.technique} onChange={e => setF(s => ({ ...s, technique: e.target.value }))} placeholder="MITRE technique (e.g. T1021.002)" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <select value={f.conclusion} onChange={e => setF(s => ({ ...s, conclusion: e.target.value }))} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 focus:outline-none">
              <option value="confirmed">confirmed</option>
              <option value="refuted">refuted</option>
              <option value="inconclusive">inconclusive</option>
            </select>
          </div>
          <p className="text-[10px] text-slate-500">Scored on substance: a hypothesis that names real entities, a finding that cites the evidence, a valid in-case technique, and a clear conclusion — a disproved (refuted) hypothesis with evidence counts fully.</p>
          <Button variant="primary" size="sm" disabled={busy || f.hypothesis.trim().length < 8} onClick={log}>Log hunt finding</Button>
        </div>
      </Card>
      {/* G-10: Tier-3 owns the FINAL scope — confirm or amend what Tier-2 proposed */}
      <ScopeConsole scope={scope} mode="confirm" act={act} />
      {/* A3: live threat-intel enrichment when a hash/IP/domain is checked in a log */}
      {threatQuery && <ThreatIntelDrawer key="t3-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}
