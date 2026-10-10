"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Pin, PinOff, Search, ScrollText, Send, X, BookOpen, Radar } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { IocTruth, IocType } from "@/lib/edr/iocIntel";
import { extractIocs, normalizeIoc, iocDigest } from "@/lib/edr/iocIntel";
import { asStr, hostKey } from "@/lib/team/format";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { useServerNow } from "@/lib/team/clock";
import { TECHNIQUES, tacticById } from "@/lib/mitre/attack";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { useForensicPins } from "./forensicPins";
import { forensicHosts } from "./ForensicWorkbench";
import { ChoiceGroup } from "./ChoiceGroup";

/**
 * Tier-3's toolkit, beside the forensic workbench in the Tier-3 navigation:
 * - Timeline explorer: every log of the hosts in play, merged in time order (a super-timeline
 *   in the spirit of plaso), filtered and pinned to the same working timeline as the workbench.
 * - Intel lookup: reputation of an IP, domain or hash seen in this shift (the same threat-intel
 *   view the feed and the EDR console use; values not seen in the shift are refused).
 * - ATT&CK: the technique library, to name what you found.
 * - The report to the SOC Manager (status, escalation, containment readiness).
 */

const hhmmss = (ms: number) => new Date(ms).toLocaleTimeString("en-GB", { hour12: false });
const field = "rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60";

// ── Timeline explorer ────────────────────────────────────────────────────────
export function TimelineExplorer({ sessionId, meId, feed, events }: { sessionId: string; meId: string; feed: Ev[]; events: Ev[] }) {
  const hosts = useMemo(() => forensicHosts(events, feed), [events, feed]);
  const keys = useMemo(() => new Set(hosts.map(hostKey)), [hosts]);
  const rows = useMemo(() => feed.filter(e => e.occurred_at && keys.has(hostKey(asStr((e.payload as { hostname?: unknown }).hostname)))).map(e => {
    const t = withRebasedTime(e.payload as unknown as TelemetryEvent, e.occurred_at!);
    return { id: asStr((e.payload as { id?: unknown }).id) || String(e.seq), at: Date.parse(e.occurred_at!), host: asStr(t.hostname), source: asStr(t.source), type: asStr(t.event_type), sev: asStr(t.severity), text: asStr(t.description) || asStr(t.event_type) };
  }).sort((a, b) => a.at - b.at), [feed, keys]);
  const [host, setHost] = useState("all");
  const [source, setSource] = useState("all");
  const [q, setQ] = useState("");
  const sources = [...new Set(rows.map(r => r.source))].sort();
  const shown = rows.filter(r => (host === "all" || hostKey(r.host) === hostKey(host)) && (source === "all" || r.source === source) && (!q.trim() || `${r.text} ${r.type} ${r.host}`.toLowerCase().includes(q.trim().toLowerCase()))).slice(0, 500);
  const { pins, toggle } = useForensicPins(sessionId, meId);
  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ScrollText className="h-4 w-4 text-cyber-300" aria-hidden /> Timeline explorer</h2>
      <p className="mt-0.5 text-[11px] text-slate-400">Every log of the hosts in play, in time order across sources. Pin the rows that tell the story; they join your timeline in the workbench.</p>
      {hosts.length === 0 ? <p className="mt-2 text-[11px] text-slate-400">No host in play yet.</p> : (
        <>
          <div className="mt-2 flex flex-wrap gap-2">
            <label className="text-[11px] text-slate-300">Host <select value={host} onChange={e => setHost(e.target.value)} className={`${field} ml-1`}><option value="all">All hosts ({hosts.length})</option>{hosts.map(h => <option key={h} value={h}>{h}</option>)}</select></label>
            <label className="text-[11px] text-slate-300">Source <select value={source} onChange={e => setSource(e.target.value)} className={`${field} ml-1`}><option value="all">All</option>{sources.map(s => <option key={s} value={s}>{s}</option>)}</select></label>
            <label className="flex-1 text-[11px] text-slate-300">Search <input value={q} onChange={e => setQ(e.target.value)} placeholder="process, IP, user, file..." className={`${field} ml-1 w-full max-w-xs`} /></label>
            <span className="self-center font-mono text-[11px] text-slate-400">{shown.length} rows</span>
          </div>
          <div className="mt-2 max-h-[30rem] overflow-auto rounded border border-border">
            <table className="w-full border-collapse font-mono text-[11px]">
              <thead className="sticky top-0 bg-bg-elevated text-left text-slate-400"><tr><th className="w-7" aria-label="Pin" /><th className="px-2 py-1">Time</th><th className="px-2 py-1">Host</th><th className="px-2 py-1">Source</th><th className="px-2 py-1">Event</th><th className="px-2 py-1">Level</th><th className="px-2 py-1">Details</th></tr></thead>
              <tbody>
                {shown.map(r => {
                  const ref = `TL/${r.id}`; const pinned = pins.some(p => p.ref === ref);
                  return (
                    <tr key={r.id} className={`border-t border-border/50 ${pinned ? "bg-neon-purple/10" : "hover:bg-white/[0.03]"}`}>
                      <td className="px-1"><button type="button" aria-label={pinned ? "Unpin row" : "Pin row to my timeline"} onClick={() => toggle({ ref, host: r.host, evidence: "SIEM", plugin: r.source, text: r.text.slice(0, 180), atMs: r.at })} className={pinned ? "text-neon-purple" : "text-slate-500 hover:text-slate-200"}>{pinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}</button></td>
                      <td className="whitespace-nowrap px-2 py-1 text-slate-400">{hhmmss(r.at)}</td>
                      <td className="whitespace-nowrap px-2 py-1 text-slate-200">{r.host}</td>
                      <td className="whitespace-nowrap px-2 py-1 text-slate-300">{r.source}</td>
                      <td className="whitespace-nowrap px-2 py-1 text-slate-300">{r.type}</td>
                      <td className="whitespace-nowrap px-2 py-1 text-slate-400">{r.sev}</td>
                      <td className="px-2 py-1 text-slate-200">{r.text}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  );
}

// ── Intel lookup ─────────────────────────────────────────────────────────────
const typeOf = (v: string): IocType | null => {
  const s = v.trim();
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(s)) return "hash";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return "domain";
  return null;
};
export function IntelLookup({ feed, events, truth, onSeen }: { feed: Ev[]; events: Ev[]; truth: IocTruth | null; onSeen: (eventId: string) => void }) {
  const hosts = useMemo(() => new Set(forensicHosts(events, feed).map(hostKey)), [events, feed]);
  const index = useMemo(() => {
    const m = new Map<string, { type: IocType; value: string; ev: TelemetryEvent; id: string; inPlay: boolean }>();
    for (const e of feed) {
      const t = e.payload as unknown as TelemetryEvent;
      const id = asStr((e.payload as { id?: unknown }).id) || String(e.seq);
      for (const i of extractIocs(t)) {
        const k = `${i.type}:${normalizeIoc(i.type, i.value)}`;
        const inPlay = hosts.has(hostKey(asStr(t.hostname)));
        if (!m.has(k) || (inPlay && !m.get(k)!.inPlay)) m.set(k, { ...i, ev: t, id, inPlay });
      }
    }
    return m;
  }, [feed, hosts]);
  const suggestions = [...index.values()].filter(x => x.inPlay && x.type !== "ip" || (x.inPlay && x.type === "ip" && !/^(10\.|192\.168\.|172\.)/.test(x.value))).slice(0, 14);
  const [q, setQ] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [query, setQuery] = useState<ThreatQuery | null>(null);
  // The reputation comes from the server once the log is "opened" (the same rule as the feed:
  // only indicators from logs in your hands). Wait for it, never show a premature "clean".
  const [pending, setPending] = useState<{ q: ThreatQuery; digest: string; since: number } | null>(null);
  useEffect(() => {
    if (!pending) return;
    if (truth?.entries?.[pending.digest]) { setQuery(pending.q); setPending(null); return; }
    const t = setTimeout(() => { setQuery(pending.q); setPending(null); }, Math.max(0, 6000 - (Date.now() - pending.since)));
    return () => clearTimeout(t);
  }, [pending, truth]);
  function look(v = q) {
    const type = typeOf(v);
    if (!type) { setMsg("Enter an IP address, a domain or a hash (MD5, SHA-1 or SHA-256)."); return; }
    const hit = index.get(`${type}:${normalizeIoc(type, v.trim())}`);
    if (!hit) { setMsg("Not seen in this shift's telemetry. Look up indicators that appear in the logs."); return; }
    setMsg(null); onSeen(hit.id);
    const digest = iocDigest(type, hit.value);
    const qq = { type, value: hit.value, event: hit.ev } as ThreatQuery;
    if (truth?.entries?.[digest]) setQuery(qq); else setPending({ q: qq, digest, since: Date.now() });
  }
  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Radar className="h-4 w-4 text-cyber-300" aria-hidden /> Intel lookup</h2>
      <p className="mt-0.5 text-[11px] text-slate-400">Reputation of an IP, a domain or a file hash from this shift: detections, first seen, related infrastructure. Reputation is a lead, not a verdict.</p>
      <form className="mt-2 flex gap-2" onSubmit={e => { e.preventDefault(); look(); }}>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="198.51.100.23 · update-cdn.example · sha256..." className={`${field} flex-1 font-mono`} aria-label="Indicator to look up" />
        <Button variant="primary" size="sm" type="submit"><Search className="mr-1 h-3.5 w-3.5" aria-hidden /> Look up</Button>
      </form>
      {msg && <p className="mt-1 text-[11px] text-neon-amber" role="alert">{msg}</p>}
      {pending && <p className="mt-1 text-[11px] text-slate-400" role="status">Looking up {pending.q.value}...</p>}
      {suggestions.length > 0 && (
        <div className="mt-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Indicators on the hosts in play</p>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {suggestions.map(x => <button key={`${x.type}:${x.value}`} type="button" onClick={() => { setQ(x.value); look(x.value); }} className="rounded border border-border px-2 py-0.5 font-mono text-[11px] text-slate-300 hover:border-cyber-500/60 hover:text-white"><span className="text-slate-500">{x.type}</span> {x.value.length > 28 ? `${x.value.slice(0, 26)}…` : x.value}</button>)}
          </div>
        </div>
      )}
      {query && <ThreatIntelDrawer key={`${query.type}:${query.value}`} query={query} truth={truth} onClose={() => setQuery(null)} />}
    </Card>
  );
}

// ── ATT&CK lookup ────────────────────────────────────────────────────────────
export function AttackLookup() {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return TECHNIQUES.slice(0, 0);
    return TECHNIQUES.filter(t => t.id.toLowerCase().startsWith(s) || t.name.toLowerCase().includes(s) || (t.description ?? "").toLowerCase().includes(s)).slice(0, 25);
  }, [q]);
  const t = TECHNIQUES.find(x => x.id === sel) ?? null;
  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><BookOpen className="h-4 w-4 text-cyber-300" aria-hidden /> ATT&amp;CK library</h2>
      <p className="mt-0.5 text-[11px] text-slate-400">Name what you found: search by ID (T1059.001) or by words (scheduled task, rundll32, credential dumping).</p>
      <input value={q} onChange={e => { setQ(e.target.value); setSel(null); }} placeholder="T1218 · rundll32 · persistence..." className={`${field} mt-2 w-full`} aria-label="Search techniques" />
      <div className="mt-2 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <ul className="max-h-80 space-y-0.5 overflow-y-auto">
          {q.trim() && list.length === 0 && <li className="text-[11px] text-slate-400">No technique matches.</li>}
          {list.map(x => <li key={x.id}><button type="button" onClick={() => setSel(x.id)} className={`w-full rounded px-2 py-1 text-left text-[11px] ${sel === x.id ? "bg-cyber-500/15 text-white" : "text-slate-300 hover:bg-white/5"}`}><span className="font-mono text-cyber-300">{x.id}</span> {x.name}</button></li>)}
        </ul>
        {t && (
          <div className="space-y-1.5 rounded-lg border border-border bg-bg p-2.5 text-[11px]">
            <p className="text-sm font-semibold text-white"><span className="font-mono text-cyber-300">{t.id}</span> {t.name}</p>
            <p className="text-slate-400">Tactic: {tacticById(t.tactic)?.name ?? t.tactic}</p>
            {t.description && <p className="text-slate-300">{t.description}</p>}
            {"whatAttackerDoes" in t && t.whatAttackerDoes && <p className="text-slate-300"><span className="text-slate-400">What the attacker does: </span>{String(t.whatAttackerDoes)}</p>}
            {"logIndicators" in t && Array.isArray(t.logIndicators) && t.logIndicators.length > 0 && (
              <div><p className="text-slate-400">What it looks like in the logs:</p><ul className="list-disc pl-4 text-slate-300">{(t.logIndicators as string[]).map((l, i) => <li key={i}>{l}</li>)}</ul></div>
            )}
            {Array.isArray(t.data_sources) && t.data_sources.length > 0 && <p className="text-slate-400">Data sources: {t.data_sources.join(", ")}</p>}
          </div>
        )}
      </div>
    </Card>
  );
}

// ── Report to the SOC Manager ────────────────────────────────────────────────
export const REPORT_KINDS = [
  { v: "status", label: "Status update" }, { v: "scope_grew", label: "Escalation: the scope grew" },
  { v: "data_at_risk", label: "Escalation: data at risk" }, { v: "containment_ready", label: "Containment readiness" },
  { v: "need_decision", label: "I need a decision" },
] as const;
const KIND_LABEL: Record<string, string> = Object.fromEntries(REPORT_KINDS.map(k => [k.v, k.label]));

export function ForensicReportModal({ events, act, onClose, onSent }: { events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onClose: () => void; onSent: (msg: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(true, ref, { onEscape: onClose });
  const now = useServerNow(15_000);
  const findings = events.filter(e => e.type === "forensic.finding");
  const status = new Map<string, string>();
  for (const f of findings) { const p = f.payload as Record<string, unknown>; if (p.kind === "host_status") status.set(asStr(p.host), asStr(p.status)); }
  const [kind, setKind] = useState<string>("status");
  const [summary, setSummary] = useState("");
  const [ready, setReady] = useState<"ready" | "not_ready" | "unknown" | null>(null);
  const [why, setWhy] = useState("");
  const [asks, setAsks] = useState("");
  const [next, setNext] = useState<"15" | "30" | "60" | null>(null);
  const [attach, setAttach] = useState<Set<number>>(() => new Set(findings.map(f => f.seq)));
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const missing = [!summary.trim() && "what you established", !ready && "containment readiness", !next && "the next update time"].filter(Boolean) as string[];
  async function send() {
    setTried(true);
    if (missing.length || busy) return;
    setBusy(true);
    const att = findings.filter(f => attach.has(f.seq)).map(f => { const p = f.payload as Record<string, unknown>; return { seq: f.seq, kind: asStr(p.kind), host: asStr(p.host), summary: asStr(p.summary).slice(0, 300), confidence: asStr(p.confidence) }; });
    const ok = await act("forensic.report", { kind, summary: summary.trim().slice(0, 1500), readiness: ready, readiness_reason: why.trim().slice(0, 400), asks: asks.trim().slice(0, 400), next_update_min: Number(next),
      hosts: [...status.entries()].map(([host, s]) => ({ host, status: s })), findings: att });
    setBusy(false);
    if (ok) { onSent(`Report sent to the SOC Manager. Next update promised by ${new Date(now + Number(next) * 60000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`); onClose(); }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-8">
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="t3-report-title" className="w-full max-w-xl space-y-3 rounded-xl border border-border bg-bg-elevated p-4 shadow-2xl">
        <div className="flex items-center justify-between">
          <h2 id="t3-report-title" className="flex items-center gap-2 text-base font-semibold text-white"><Send className="h-4 w-4 text-cyber-300" aria-hidden /> Report to the SOC Manager</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <p className="text-[11px] text-slate-400">The manager decides containment and reports upward from what you send. Say what is confirmed, what is not, and whether it is safe to contain now.</p>
        <label className="block text-[11px] font-semibold text-slate-300">Type
          <select value={kind} onChange={e => setKind(e.target.value)} className={`${field} mt-1 w-full`}>{REPORT_KINDS.map(k => <option key={k.v} value={k.v}>{k.label}</option>)}</select>
        </label>
        {status.size > 0 && (
          <div className="text-[11px]"><p className="font-semibold text-slate-300">Host status (from your published findings)</p>
            <div className="mt-1 flex flex-wrap gap-1.5">{[...status.entries()].map(([h, s]) => <span key={h} className={`rounded border px-2 py-0.5 font-mono ${s === "compromised" ? "border-severity-critical/50 text-severity-critical" : s === "not_compromised" ? "border-neon-green/40 text-neon-green" : "border-border text-slate-300"}`}>{h}: {s.replace("_", " ")}</span>)}</div>
          </div>
        )}
        <label className="block text-[11px] font-semibold text-slate-300">What you established <span className="text-neon-amber" aria-hidden>*</span>
          <textarea value={summary} onChange={e => setSummary(e.target.value)} rows={3} maxLength={1500} placeholder="e.g. Entry: ISO from a phishing link on WS-FIN-2847. A hidden PowerShell beacons to 193.106.191.42. No persistence found yet; no other host seen talking to that IP." className={`${field} mt-1 w-full`} aria-invalid={tried && !summary.trim()} />
        </label>
        <ChoiceGroup legend="Is it safe to contain now?" hideLegend={false} size="xs" value={ready} onChange={setReady}
          options={[{ value: "ready", label: "Ready to contain" }, { value: "not_ready", label: "Not yet" }, { value: "unknown", label: "Cannot tell yet" }]} />
        <label className="block text-[11px] font-semibold text-slate-300">Why
          <input value={why} onChange={e => setWhy(e.target.value)} maxLength={400} placeholder="e.g. memory captured; scope confirmed to one host" className={`${field} mt-1 w-full`} />
        </label>
        <label className="block text-[11px] font-semibold text-slate-300">What you need from the manager
          <input value={asks} onChange={e => setAsks(e.target.value)} maxLength={400} placeholder="e.g. approve isolating WS-FIN-2847; ask IT not to reimage it yet" className={`${field} mt-1 w-full`} />
        </label>
        <ChoiceGroup legend="Next update in" hideLegend={false} size="xs" tone="cyan" value={next} onChange={setNext} options={[{ value: "15", label: "15 min" }, { value: "30", label: "30 min" }, { value: "60", label: "60 min" }]} />
        {findings.length > 0 && (
          <div className="text-[11px]"><p className="font-semibold text-slate-300">Attach findings</p>
            <div className="mt-1 max-h-32 space-y-0.5 overflow-y-auto">
              {findings.map(f => { const p = f.payload as Record<string, unknown>; return (
                <label key={f.seq} className="flex items-start gap-1.5"><input type="checkbox" checked={attach.has(f.seq)} onChange={() => setAttach(s => { const n = new Set(s); if (n.has(f.seq)) n.delete(f.seq); else n.add(f.seq); return n; })} className="mt-0.5" />
                  <span className="text-slate-300"><span className="font-mono text-slate-400">{asStr(p.host)}</span> {asStr(p.summary).slice(0, 140)}</span></label>
              ); })}
            </div>
          </div>
        )}
        {tried && missing.length > 0 && <p className="text-[11px] text-neon-amber" role="alert">Still needed: {missing.join(", ")}.</p>}
        <div className="flex gap-2 border-t border-border/60 pt-3">
          <Button variant="primary" size="sm" disabled={busy} onClick={send}><Send className="mr-1 h-3.5 w-3.5" aria-hidden /> Send to the SOC Manager</Button>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  );
}

/** The SOC Manager's view of Tier-3 reports (Situation board). */
export function ForensicReportsCard({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  const reports = events.filter(e => e.type === "forensic.report");
  if (!reports.length) return null;
  const tone = (r: string) => (r === "ready" ? "border-neon-green/40 text-neon-green" : r === "not_ready" ? "border-neon-amber/50 text-neon-amber" : "border-border text-slate-300");
  return (
    <Card className="border-cyber-500/40">
      <p className="flex items-center gap-1.5 text-sm font-bold text-white"><Send className="h-4 w-4 text-cyber-300" aria-hidden /> Reports from Tier-3 ({reports.length})</p>
      <ul className="mt-2 space-y-2">
        {reports.slice().reverse().slice(0, 5).map(r => {
          const p = r.payload as Record<string, unknown>;
          const hosts = (Array.isArray(p.hosts) ? p.hosts : [])
            .map(h => (typeof h === "string" ? { host: h, status: "" } : { host: asStr((h as { host?: unknown })?.host), status: asStr((h as { status?: unknown })?.status) }))
            .filter(h => h.host);
          const nextMin = Number(p.next_update_min);
          const att = Array.isArray(p.findings) ? p.findings.length : 0;
          return (
            <li key={r.seq} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded border border-cyber-500/40 px-1.5 font-mono text-[10px] uppercase text-cyber-200">{KIND_LABEL[asStr(p.kind)] ?? asStr(p.kind)}</span>
                <span className={`rounded border px-1.5 text-[10px] ${tone(asStr(p.readiness))}`}>{p.readiness === "ready" ? "ready to contain" : p.readiness === "not_ready" ? "not ready to contain" : "readiness unknown"}</span>
                <span className="ml-auto text-[10px] text-slate-400"><bdi>{nameOf(r.actor_id)}</bdi>{r.occurred_at ? ` · ${new Date(r.occurred_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : ""}</span>
              </div>
              <p className="mt-1 text-slate-100"><bdi>{asStr(p.summary)}</bdi></p>
              {asStr(p.readiness_reason) && <p className="text-[11px] text-slate-400">Why: <bdi>{asStr(p.readiness_reason)}</bdi></p>}
              {asStr(p.asks) && <p className="text-[11px] text-neon-purple">Needs from you: <bdi>{asStr(p.asks)}</bdi></p>}
              {hosts.length > 0 && <p className="mt-1 flex flex-wrap gap-1">{hosts.map(h => <span key={h.host} className="rounded border border-border px-1.5 font-mono text-[10px] text-slate-300">{h.host}{h.status ? `: ${h.status.replace("_", " ")}` : ""}</span>)}</p>}
              <p className="text-[10px] text-slate-500">{att} finding{att === 1 ? "" : "s"} attached{nextMin > 0 ? ` · next update in ${nextMin} min` : ""}</p>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
