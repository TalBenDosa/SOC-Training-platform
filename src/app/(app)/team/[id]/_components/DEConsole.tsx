"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import type { LiveEvent } from "@/app/(app)/dashboard/useLiveEvents";
import { eventMatchesSearch } from "@/app/(app)/dashboard/eventSearch";
import { ShieldAlert } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── Detection Engineer console — G-06: predicate / KQL-lite back-test ─────────
export function DEConsole({ liveFeed, events, act }: { liveFeed: LiveEvent[]; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ name: "", keyword: "", technique: "" });
  const [busy, setBusy] = useState(false);
  // Field-based back-test: `field:value` tokens AND-ed (source:edr mitre:T1059 …),
  // reusing the real feed search engine — not a naive substring. Falls back to
  // substring for bare terms, so simple queries still work.
  const matched = useMemo(() => {
    const q = f.keyword.trim();
    if (!q) return [] as LiveEvent[];
    return liveFeed.filter(e => eventMatchesSearch(e, q));
  }, [liveFeed, f.keyword]);
  const published = events.filter(e => e.type === "rule.published");
  const tuned = events.filter(e => e.type === "rule.tuned");
  const [tuneText, setTuneText] = useState("");
  const [busyTune, setBusyTune] = useState(false);
  async function publish() {
    if (!f.name.trim() || !f.keyword.trim()) return;
    setBusy(true); const ok = await act("rule.published", { ...f, matched: matched.length }); setBusy(false);
    if (ok) setF({ name: "", keyword: "", technique: "" });
  }
  async function tune() {
    const ex = tuneText.trim(); if (!ex) return;
    const last = published[published.length - 1]?.payload as { name?: string } | undefined;
    setBusyTune(true); const ok = await act("rule.tuned", { rule: asStr(last?.name) || "last rule", exclusion: ex }); setBusyTune(false);
    if (ok) setTuneText("");
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Detection engineering</h3>
      <p className="mt-1 text-[11px] text-slate-400">Write a field-based rule mid-incident — it back-tests live against the feed.</p>
      <div className="mt-2 space-y-2">
        <input value={f.name} onChange={e => setF(s => ({ ...s, name: e.target.value }))} placeholder="Rule name" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={f.keyword} onChange={e => setF(s => ({ ...s, keyword: e.target.value }))} placeholder="Predicate (e.g. source:edr mitre:T1059, host:FIN-WS-07, PuTTY)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <p className="text-[10px] text-slate-500">fields: source · host · user · ip · mitre · rule · vendor · event · severity — AND-ed</p>
        {f.keyword.trim() && (
          <div className={`rounded border px-2 py-1 text-[11px] ${matched.length > 0 ? "border-neon-green/30 bg-neon-green/[0.05] text-neon-green" : "border-border text-slate-500"}`}>
            back-test: {matched.length} match{matched.length === 1 ? "" : "es"}
            {matched.length > 0 && <div className="mt-1 space-y-0.5">{matched.slice(0, 3).map(e => <p key={e.id} className="truncate font-mono text-[10px] text-slate-400">{e.source} · {asStr(e.displayDescription) || asStr(e.description) || e.event_type}</p>)}</div>}
          </div>
        )}
        <Button variant="primary" size="sm" disabled={busy || !f.name.trim() || !f.keyword.trim()} onClick={publish}>Publish rule</Button>
      </div>
      {published.length > 0 && <div className="mt-3 border-t border-border/50 pt-2 space-y-1">{published.map(r => { const p = r.payload as { name?: string; matched?: number; keyword?: string }; return <p key={r.seq} className="truncate text-[11px] text-slate-400"><span className="text-slate-200">{asStr(p.name)}</span> <span className="font-mono text-[10px]">{asStr(p.keyword)}</span> · {p.matched ?? 0} matched</p>; })}</div>}
      {/* Tune a rule — add an exclusion to cut false positives (rule.tuned) */}
      {published.length > 0 && (
        <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Tune a rule ({tuned.length})</p>
          <div className="flex gap-1.5">
            <input value={tuneText} onChange={e => setTuneText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") tune(); }} placeholder="Exclusion to cut FPs (e.g. user:svc-backup)" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <Button variant="outline" size="sm" disabled={busyTune || !tuneText.trim()} onClick={tune}>Tune</Button>
          </div>
        </div>
      )}
    </Card>
  );
}
