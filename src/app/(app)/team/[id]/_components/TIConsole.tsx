"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Siren, FolderOpen } from "lucide-react";

// ── Threat Intel console — G-17: relevance + intel repository ─────────────────
// A tiny advisory repo the TI analyst must VET against the live evidence. One IOC
// is deliberately WRONG (a decoy) — publishing it as-is is the teaching mistake
// ("verify against the source, don't relay blindly").
const INTEL_REPO: Array<{ id: string; source: string; title: string; ioc: string; note?: string; decoy?: boolean }> = [
  { id: "a1", source: "CISA AA24-109A", title: "Trojanized SSH/PuTTY installers drop Cobalt Strike", ioc: "puttysoftware-download.com", note: "Matches the download domain in the feed." },
  { id: "a2", source: "Vendor blog", title: "FIN-actor exfil to mega.nz", ioc: "mega.nz", note: "Corroborate against DLP/proxy logs before acting." },
  { id: "a3", source: "OSINT (unverified)", title: "Reported C2 IP for this cluster", ioc: "8.8.8.8", note: "Single-source OSINT post; no corroboration listed. Verify against the feed before publishing.", decoy: true },
];
export function TIConsole({ act }: { act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ actor: "", technique: "", confidence: "0.7", relevance: "medium", recommendation: "", next_expected: "", ioc: "" });
  const [busy, setBusy] = useState(false);
  async function publish() {
    if (!f.actor.trim() && !f.technique.trim()) return;
    setBusy(true); const ok = await act("intel.published", { ...f, confidence: Number(f.confidence) }); setBusy(false);
    if (ok) setF({ actor: "", technique: "", confidence: "0.7", relevance: "medium", recommendation: "", next_expected: "", ioc: "" });
  }
  return (
    <div className="space-y-4">
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Threat intel</h3>
        <p className="mt-1 text-[11px] text-slate-400">Turn indicators into context for the team — rate its relevance to THIS incident.</p>
        <div className="mt-2 space-y-2">
          <input value={f.actor} onChange={e => setF(s => ({ ...s, actor: e.target.value }))} placeholder="Actor / campaign" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.technique} onChange={e => setF(s => ({ ...s, technique: e.target.value }))} placeholder="Technique / TTP" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.ioc} onChange={e => setF(s => ({ ...s, ioc: e.target.value }))} placeholder="IOC (domain / IP / hash — verified)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.next_expected} onChange={e => setF(s => ({ ...s, next_expected: e.target.value }))} placeholder="Next expected step (predict)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <div className="flex gap-2">
            <input value={f.recommendation} onChange={e => setF(s => ({ ...s, recommendation: e.target.value }))} placeholder="Recommended action" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          </div>
          <div className="flex gap-2">
            <select value={f.relevance} onChange={e => setF(s => ({ ...s, relevance: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="high">relevance: high</option><option value="medium">relevance: med</option><option value="low">relevance: low</option></select>
            <select value={f.confidence} onChange={e => setF(s => ({ ...s, confidence: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="0.5">conf: low</option><option value="0.7">conf: med</option><option value="0.9">conf: high</option></select>
          </div>
          <Button variant="primary" size="sm" disabled={busy || (!f.actor.trim() && !f.technique.trim())} onClick={publish}>Publish intel</Button>
        </div>
      </Card>
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Intel repository</h3>
        <p className="mt-1 text-[11px] text-slate-400">Vet each advisory against the feed before you relay it — not all IOCs are good.</p>
        <div className="mt-2 space-y-1.5">
          {INTEL_REPO.map(a => (
            <div key={a.id} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-xs">
              <p className="text-slate-200">{a.title}</p>
              <p className="mt-0.5 font-mono text-[10px] text-slate-400">{a.ioc} · <span className="text-slate-500">{a.source}</span></p>
              {a.note && <p className="mt-0.5 text-[10px] text-slate-500">{a.note}</p>}
              <button onClick={() => setF(s => ({ ...s, ioc: a.ioc, actor: s.actor || a.title }))} className="mt-1 text-[10px] text-cyber-300 underline-offset-2 hover:underline">use this IOC →</button>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
