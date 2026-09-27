"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { Siren, FolderOpen, Search } from "lucide-react";
import type { Ev, Ioc } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { asStr, detectIocType, isValidIoc } from "@/lib/team/format";

// ── Threat Intel console — G-17: relevance + corroboration ────────────────────
// TI playtest: the seat only received `act` — no escalations, no analyst IOCs, and a
// hard-coded advisory repo (PuTTY / mega.nz / 8.8.8.8) unrelated to any session.
// Now the pick-list is THIS shift's own evidence: every indicator an analyst attached
// (escalation / elevation / pinned evidence / report), each with its corroboration in
// the live feed — vetting "does the feed back this up?" is still the teaching point.
type Lead = { value: string; type: string; refs: { kind: string; label: string; eid: string; by: string | null }[] };
const EMPTY = { actor: "", technique: "", confidence: "0.7", relevance: "medium", recommendation: "", next_expected: "", ioc: "", event_id: "" };

export function TIConsole({ events, feed, nameOf, act }: { events: Ev[]; feed: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState(EMPTY);
  const [busy, setBusy] = useState(false);
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null);
  // Escalated cases (current round per log) — what the team is actually working.
  const cases = useMemo(() => {
    const m = new Map<string, Ev>();
    for (const e of events) if (e.type === "escalation.requested") m.set(String((e.payload as { event_id?: string }).event_id), e);
    return [...m.values()].reverse();
  }, [events]);
  const caseLabel = (eid: string) => { const c = cases.find(e => String((e.payload as { event_id?: string }).event_id) === eid); const p = c?.payload as { summary?: string; what?: string } | undefined; return asStr(p?.summary) || asStr(p?.what) || ""; };
  // Every indicator the analysts attached, de-duplicated, with where it came from.
  const leads = useMemo(() => {
    const m = new Map<string, Lead>();
    const kindOf: Record<string, string> = { "escalation.requested": "escalation", "elevation.requested": "elevation", "evidence.pinned": "pinned", "report.submitted": "report" };
    for (const e of events) {
      const kind = kindOf[e.type]; if (!kind) continue;
      const p = e.payload as { iocs?: unknown; event_id?: string; summary?: string; what?: string; label?: string };
      if (!Array.isArray(p.iocs)) continue;
      for (const raw of p.iocs as Partial<Ioc>[]) {
        const value = asStr(raw?.value).trim(); if (!value) continue;
        const key = value.toLowerCase();
        const lead = m.get(key) ?? { value, type: asStr(raw?.type) || detectIocType(value), refs: [] };
        lead.refs.push({ kind, label: asStr(p.summary) || asStr(p.what) || asStr(p.label) || "case", eid: String(p.event_id ?? ""), by: e.actor_id });
        m.set(key, lead);
      }
    }
    return [...m.values()];
  }, [events]);
  // Corroboration: which feed logs mention the indicator (lower-cased JSON, built once per feed change).
  const feedText = useMemo(() => feed.map(e => ({ e, text: JSON.stringify(e.payload ?? {}).toLowerCase() })), [feed]);
  const hitsFor = (v: string) => {
    const needle = v.toLowerCase();
    const hits = feedText.filter(x => x.text.includes(needle)).map(x => x.e);
    const sources = [...new Set(hits.map(h => asStr((h.payload as { source?: string }).source)).filter(Boolean))];
    const hosts = [...new Set(hits.map(h => asStr((h.payload as { hostname?: string }).hostname)).filter(Boolean))];
    return { n: hits.length, sources, hosts, first: hits[0] };
  };
  const iocOk = !f.ioc.trim() || isValidIoc(f.ioc);
  const canPublish = !busy && (!!f.actor.trim() || !!f.technique.trim()) && !!f.recommendation.trim() && iocOk;
  async function publish() {
    if (!canPublish) return;
    const ioc = f.ioc.trim();
    setBusy(true);
    const ok = await act("intel.published", { ...f, ioc, ioc_type: ioc ? detectIocType(ioc) : undefined, event_id: f.event_id || undefined, case_label: f.event_id ? caseLabel(f.event_id) || undefined : undefined, confidence: Number(f.confidence) });
    setBusy(false);
    if (ok) setF(EMPTY);
  }
  function lookup(value: string, type: string, ev?: Ev) {
    const t = type === "sha256" || type === "sha1" || type === "md5" ? "hash" : type === "ip" ? "ip" : type === "domain" ? "domain" : null;
    if (!t) return;
    const event = (ev?.payload ?? { id: "ti", ts: new Date().toISOString(), source: "siem", event_type: "informational", severity: "informational" }) as unknown as TelemetryEvent;
    setThreatQuery({ type: t, value, event } as ThreatQuery);
  }
  return (
    <div className="space-y-4">
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Threat intel</h3>
        <p className="mt-1 text-[11px] text-slate-400">Turn the team&apos;s indicators into context — rate its relevance to THIS incident and say what to do. It lands on every seat&apos;s Team intel card.</p>
        <div className="mt-2 space-y-2">
          <select value={f.event_id} onChange={e => setF(s => ({ ...s, event_id: e.target.value }))} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
            <option value="">enriching: — general / no specific case —</option>
            {cases.map(e => { const eid = String((e.payload as { event_id?: string }).event_id); return <option key={e.seq} value={eid}>enriching: {caseLabel(eid).slice(0, 70) || `case #${e.seq}`}</option>; })}
          </select>
          <input value={f.ioc} onChange={e => setF(s => ({ ...s, ioc: e.target.value }))} placeholder="IOC (domain / IP / hash — verified against the feed)" className={`w-full rounded-lg border bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none ${iocOk ? "border-border" : "border-severity-high/60"}`} />
          {!iocOk && <p className="text-[10px] text-severity-high">That isn&apos;t an indicator shape (hash / IP / domain / email / hostname).</p>}
          <input value={f.actor} onChange={e => setF(s => ({ ...s, actor: e.target.value }))} placeholder="Actor / campaign / malware family (if known — don't over-attribute)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.technique} onChange={e => setF(s => ({ ...s, technique: e.target.value }))} placeholder="Technique / TTP (e.g. T1189 drive-by)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.next_expected} onChange={e => setF(s => ({ ...s, next_expected: e.target.value }))} placeholder="Next expected step (predict)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.recommendation} onChange={e => setF(s => ({ ...s, recommendation: e.target.value }))} placeholder="Recommended action (required) — block / hunt / watch / no action" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <div className="flex gap-2">
            <select value={f.relevance} onChange={e => setF(s => ({ ...s, relevance: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="high">relevance: high</option><option value="medium">relevance: med</option><option value="low">relevance: low</option></select>
            <select value={f.confidence} onChange={e => setF(s => ({ ...s, confidence: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="0.5">conf: low</option><option value="0.7">conf: med</option><option value="0.9">conf: high</option></select>
          </div>
          <Button variant="primary" size="sm" disabled={!canPublish} onClick={publish}>Publish intel</Button>
          {!canPublish && !busy && <p className="text-[10px] text-slate-500">Needs an actor or technique and a recommended action.</p>}
        </div>
      </Card>
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Indicators from the team ({leads.length})</h3>
        <p className="mt-1 text-[11px] text-slate-400">Everything analysts attached to escalations, elevations, pinned evidence and reports. Vet each against the feed before you relay it — an indicator seen only in one escalation isn&apos;t corroborated yet.</p>
        {leads.length === 0 ? <p className="mt-2 text-xs text-slate-500">No indicators yet — they appear here as soon as Tier-1 escalates with IOCs.</p> : (
          <div className="mt-2 max-h-[420px] space-y-1.5 overflow-y-auto">
            {leads.slice().reverse().map(l => {
              const h = hitsFor(l.value);
              const canLookup = ["sha256", "sha1", "md5", "ip", "domain"].includes(l.type);
              return (
                <div key={l.value} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-xs">
                  <p className="break-all font-mono text-[11px] text-slate-200"><span className="text-slate-500">{l.type}:</span>{l.value}</p>
                  <p className="mt-0.5 text-[10px] text-slate-500">{l.refs.slice(0, 3).map(r => `${r.kind} by ${nameOf(r.by)} — ${r.label.slice(0, 50)}`).join(" · ")}{l.refs.length > 3 ? ` · +${l.refs.length - 3}` : ""}</p>
                  <p className={`mt-0.5 text-[10px] ${h.n > 1 ? "text-neon-green" : "text-neon-amber"}`}>
                    {h.n === 0 ? "not seen in the feed — analyst-supplied only; corroborate before publishing" : `seen in ${h.n} feed log${h.n > 1 ? "s" : ""}`}{h.sources.length ? ` · ${h.sources.slice(0, 4).join(", ")}` : ""}{h.hosts.length ? ` · hosts: ${h.hosts.slice(0, 3).join(", ")}` : ""}
                  </p>
                  <div className="mt-1 flex gap-3">
                    <button onClick={() => setF(s => ({ ...s, ioc: l.value, event_id: s.event_id || l.refs.find(r => r.eid)?.eid || "" }))} className="text-[10px] text-cyber-300 underline-offset-2 hover:underline">enrich this IOC →</button>
                    {canLookup && <button onClick={() => lookup(l.value, l.type, h.first)} className="inline-flex items-center gap-0.5 text-[10px] text-cyber-300 underline-offset-2 hover:underline"><Search className="h-3 w-3" /> reputation lookup</button>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
      {threatQuery && <ThreatIntelDrawer key="ti-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}
