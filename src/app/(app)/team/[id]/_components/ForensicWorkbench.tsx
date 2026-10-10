"use client";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { HardDrive, Cpu, Pin, PinOff, FileSearch, ShieldQuestion, Lock, Microscope } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { asStr, hostKey } from "@/lib/team/format";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { useServerNow } from "@/lib/team/clock";
import { buildEvidenceView, COLLECT_DELAY_S, EVIDENCE_PREFIX, type EvidenceKind, type FeedRow, type HostState } from "@/lib/forensics/workbench";
import { ChoiceGroup } from "./ChoiceGroup";

/**
 * Tier-3 Forensic Workbench (MVP). Pick a host the team is working, collect evidence (a memory
 * capture or a triage package: it takes simulated time and freezes what the host held at that
 * moment), read it in tool views (Volatility, autoruns, Prefetch, an event-log timeline), pin
 * rows to your timeline, and publish structured findings with the rows as evidence. Findings are
 * shared with the team and shown to the SOC Manager. Nothing here shows a verdict.
 */

const FINDING_KINDS = [
  { v: "host_status", label: "Host status" }, { v: "persistence", label: "Persistence" }, { v: "c2", label: "C2 channel" },
  { v: "lateral", label: "Lateral movement" }, { v: "patient_zero", label: "Patient zero / entry point" },
  { v: "exfiltration", label: "Data staged or exfiltrated" }, { v: "note", label: "Other finding" },
] as const;
const KIND_LABEL: Record<string, string> = Object.fromEntries(FINDING_KINDS.map(k => [k.v, k.label]));
interface PinRow { ref: string; host: string; evidence: string; plugin: string; text: string; atMs: number | null }

const hhmm = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/** Hosts the team has put in play: escalations, elevations, scope, containment, isolation. */
export function forensicHosts(events: Ev[], feed: Ev[]): string[] {
  const hostOfEid = new Map(feed.map(f => [asStr((f.payload as { id?: unknown }).id), asStr((f.payload as { hostname?: unknown }).hostname)]));
  const out = new Map<string, string>();
  const add = (h: string) => { const k = hostKey(h); if (k && !out.has(k)) out.set(k, h); };
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    if (e.type === "escalation.requested") add(asStr(p.hostname) || asStr((p.snapshot as { hostname?: unknown } | undefined)?.hostname) || hostOfEid.get(asStr(p.event_id)) || "");
    else if (e.type === "elevation.requested") add(hostOfEid.get(asStr(p.event_id)) || "");
    else if (e.type === "containment.requested") add(asStr(p.target));
    else if (e.type === "edr.host_isolated" || e.type === "forensic.collected" || e.type === "forensic.finding") add(asStr(p.host));
    else if (e.type === "scope.set" || e.type === "scope.confirmed") for (const h of (Array.isArray(p.hosts) ? p.hosts : [])) add(asStr(h));
  }
  return [...out.values()].filter(h => !h.includes("@") && !/^\d+\.\d+\.\d+\.\d+$/.test(h));
}

export function ForensicWorkbench({ sessionId, feed, events, meId, nameOf, act, onEdr }: {
  sessionId: string; feed: Ev[]; events: Ev[]; meId: string; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onEdr?: (host: string) => void;
}) {
  // A fast clock only while something is being collected (progress bars); otherwise a slow one.
  const collectingSoon = events.some(e => e.type === "forensic.collected" && e.occurred_at && Date.now() - Date.parse(e.occurred_at) < 75_000);
  const now = useServerNow(collectingSoon ? 1_000 : 15_000);
  const hosts = useMemo(() => forensicHosts(events, feed), [events, feed]);
  const [host, setHost] = useState<string | null>(null);
  const cur = host && hosts.some(h => hostKey(h) === hostKey(host)) ? host : hosts[0] ?? null;
  const rows: FeedRow[] = useMemo(() => feed.filter(e => e.occurred_at).map(e => {
    const t = e.payload as unknown as TelemetryEvent;
    return { ev: withRebasedTime(t, e.occurred_at!), atMs: Date.parse(e.occurred_at!) };
  }), [feed]);

  // Evidence items (everyone's), with readiness after the simulated collection time.
  const evidence = useMemo(() => events.filter(e => e.type === "forensic.collected").map(e => {
    const p = e.payload as { host?: string; kind?: EvidenceKind; evidence_id?: string };
    const at = e.occurred_at ? Date.parse(e.occurred_at) : Date.now();
    const kind = (p.kind === "triage" ? "triage" : "memory") as EvidenceKind;
    return { id: asStr(p.evidence_id), host: asStr(p.host), kind, at, readyAt: at + COLLECT_DELAY_S[kind] * 1000, by: e.actor_id };
  }), [events]);
  const stateOf = (h: string): HostState => {
    const k = hostKey(h);
    let isolatedAtMs: number | null = null;
    for (const e of events) {
      if ((e.type === "edr.host_isolated" || e.type === "edr.host_released") && hostKey(asStr((e.payload as { host?: unknown }).host)) === k)
        isolatedAtMs = e.type === "edr.host_isolated" ? (e.occurred_at ? Date.parse(e.occurred_at) : null) : null;
    }
    const kills = events.filter(e => e.type === "rtr.action" && (e.payload as { action?: unknown }).action === "kill" && hostKey(asStr((e.payload as { host?: unknown }).host)) === k)
      .map(e => ({ pid: Number((e.payload as { pid?: unknown }).pid) || undefined, name: asStr((e.payload as { name?: unknown }).name) || undefined, atMs: e.occurred_at ? Date.parse(e.occurred_at) : 0 }));
    return { isolatedAtMs, kills };
  };
  const hostEvidence = cur ? evidence.filter(x => hostKey(x.host) === hostKey(cur)) : [];
  const [selEv, setSelEv] = useState<string | null>(null);
  const shownEv = hostEvidence.find(x => x.id === selEv && now >= x.readyAt) ?? [...hostEvidence].reverse().find(x => now >= x.readyAt) ?? null;
  const view = useMemo(() => (shownEv && cur ? buildEvidenceView({ feed: rows, host: shownEv.host, evidenceId: shownEv.id, kind: shownEv.kind, snapshotMs: shownEv.at, state: stateOf(shownEv.host), sessionId }) : null),
    [shownEv?.id, rows.length, cur]); // eslint-disable-line react-hooks/exhaustive-deps
  const [plugin, setPlugin] = useState<string>("windows.pslist");
  const table = view?.tables.find(t => t.plugin === plugin) ?? view?.tables[0] ?? null;

  // Pins: my working timeline (kept in this browser), cited by findings.
  const pinKey = `fw-pins-${sessionId}-${meId}`;
  const [pins, setPins] = useState<PinRow[]>([]);
  useEffect(() => { try { setPins(JSON.parse(localStorage.getItem(pinKey) ?? "[]")); } catch { /* storage blocked */ } }, [pinKey]);
  const savePins = (next: PinRow[]) => { setPins(next); try { localStorage.setItem(pinKey, JSON.stringify(next)); } catch { /* storage blocked */ } };
  const togglePin = (r: PinRow) => savePins(pins.some(p => p.ref === r.ref) ? pins.filter(p => p.ref !== r.ref) : [...pins, r]);

  const [busy, setBusy] = useState<EvidenceKind | null>(null);
  async function collect(kind: EvidenceKind) {
    if (!cur) return;
    setBusy(kind);
    const n = evidence.filter(x => x.kind === kind).length;
    for (let k = 1; k <= 3; k++) {
      const id = `${EVIDENCE_PREFIX[kind]}-${String(n + k).padStart(3, "0")}`;
      if (await act("forensic.collected", { host: cur, kind, evidence_id: id })) { setSelEv(id); break; }
    }
    setBusy(null);
  }

  // Finding form
  const [fk, setFk] = useState<string>("host_status");
  const [status, setStatus] = useState<"compromised" | "not_compromised" | "undetermined" | null>(null);
  const [summary, setSummary] = useState("");
  const [conf, setConf] = useState<"low" | "moderate" | "high" | null>(null);
  const hostPins = cur ? pins.filter(p => hostKey(p.host) === hostKey(cur)) : [];
  const [cite, setCite] = useState<Set<string>>(new Set());
  const findings = events.filter(e => e.type === "forensic.finding");
  async function publish() {
    if (!cur || !summary.trim() || !conf || (fk === "host_status" && !status)) return;
    const evs = hostPins.filter(p => cite.has(p.ref));
    const ok = await act("forensic.finding", { kind: fk, host: cur, status: fk === "host_status" ? status : undefined, summary: summary.trim().slice(0, 800), confidence: conf,
      evidence: evs.map(p => p.ref), evidence_text: evs.map(p => `${p.evidence} ${p.plugin}: ${p.text}`.slice(0, 200)) });
    if (ok) { setSummary(""); setConf(null); setStatus(null); setCite(new Set()); }
  }

  const happened = cur ? events.filter(e => {
    const p = e.payload as Record<string, unknown>; const k = hostKey(cur);
    const h = asStr(p.host) || asStr(p.target) || asStr(p.hostname) || asStr((p.snapshot as { hostname?: unknown } | undefined)?.hostname);
    return ["escalation.requested", "containment.requested", "containment.approved", "containment.denied", "edr.host_isolated", "edr.host_released", "rtr.action", "forensic.collected", "forensic.finding"].includes(e.type) && hostKey(h) === k;
  }) : [];
  const describe = (e: Ev) => {
    const p = e.payload as Record<string, unknown>;
    switch (e.type) {
      case "escalation.requested": return `escalated: ${asStr(p.summary) || "alert"}`;
      case "containment.requested": return `requested ${asStr(p.containment_type) || "isolation"}`;
      case "containment.approved": return "containment approved by the manager";
      case "containment.denied": return "containment denied by the manager";
      case "edr.host_isolated": return "host isolated in EDR";
      case "edr.host_released": return "host released from isolation";
      case "rtr.action": return p.action === "kill" ? `RTR kill: ${asStr(p.name) || `PID ${asStr(p.pid)}`} (process terminated)` : `RTR ${asStr(p.action)} ${asStr(p.path)}`;
      case "forensic.collected": return `${p.kind === "triage" ? "triage package" : "memory capture"} ${asStr(p.evidence_id)} taken`;
      case "forensic.finding": return `finding: ${KIND_LABEL[asStr(p.kind)] ?? asStr(p.kind)}`;
      default: return e.type;
    }
  };
  const st = cur ? stateOf(cur) : null;
  const hasEdr = cur ? rows.some(r => r.ev.hostname && hostKey(r.ev.hostname) === hostKey(cur) && (r.ev.source === "edr" || r.ev.source === "sysmon")) : false;

  if (!hosts.length) return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Microscope className="h-4 w-4 text-cyber-300" aria-hidden /> Forensic workbench</h2>
      <p className="mt-1 text-[11px] text-slate-400">No host is in play yet. Hosts appear here as the team escalates, scopes, isolates or asks to contain them. Meanwhile, hunt in the live feed.</p>
    </Card>
  );

  return (
    <div className="space-y-3">
      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Microscope className="h-4 w-4 text-cyber-300" aria-hidden /> Forensic workbench</h2>
          <span className="text-[11px] text-slate-400">Collect evidence, read it in the tools, cite it in findings.</span>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5" role="tablist" aria-label="Hosts in play">
          {hosts.map(h => {
            const s = stateOf(h); const n = evidence.filter(x => hostKey(x.host) === hostKey(h)).length;
            const by = [...new Set(evidence.filter(x => hostKey(x.host) === hostKey(h)).map(x => nameOf(x.by)))];
            return (
              <button key={h} type="button" role="tab" aria-selected={cur === h} onClick={() => { setHost(h); setSelEv(null); }}
                className={`rounded-lg border px-2.5 py-1.5 text-left text-xs transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400 ${cur === h ? "border-cyber-500/60 bg-cyber-500/10 text-white" : "border-border text-slate-300 hover:border-slate-500"}`}>
                <span className="block font-mono font-semibold">{h}</span>
                <span className="block text-[10px] text-slate-400">{s.isolatedAtMs ? "isolated" : "online"} · {n} evidence{by.length ? ` · ${by.join(", ")}` : ""}</span>
              </button>
            );
          })}
        </div>
      </Card>

      {cur && st && (
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_16rem]">
          <Card>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-bold text-white">{cur}</span>
              <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${st.isolatedAtMs ? "border-neon-amber/50 text-neon-amber" : "border-neon-green/40 text-neon-green"}`}>{st.isolatedAtMs ? `ISOLATED since ${hhmm(st.isolatedAtMs)}` : "ONLINE"}</span>
              <span className="text-[10px] text-slate-400">{hasEdr ? "EDR telemetry: yes" : "EDR telemetry: none (event logs only)"}</span>
              {onEdr && hasEdr && <button type="button" onClick={() => onEdr(cur)} className="ml-auto text-[11px] text-cyber-300 underline-offset-2 hover:underline">Open in EDR (RTR shell)</button>}
            </div>
            <p className="mt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Collect</p>
            <div className="mt-1 flex flex-wrap gap-2">
              <Button variant="outline" size="sm" disabled={!!busy || !hasEdr} onClick={() => collect("memory")}><Cpu className="mr-1 h-3.5 w-3.5" aria-hidden /> Memory capture (~{COLLECT_DELAY_S.memory}s)</Button>
              <Button variant="outline" size="sm" disabled={!!busy} onClick={() => collect("triage")}><HardDrive className="mr-1 h-3.5 w-3.5" aria-hidden /> Triage package (~{COLLECT_DELAY_S.triage}s)</Button>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">A capture freezes what the host holds at that moment: later attacker activity needs a new capture. Capture memory before anyone kills a process or reboots the host.</p>
            <p className="mt-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">What happened to this host</p>
            <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto text-[11px]">
              {happened.length === 0 && <li className="text-slate-400">Nothing recorded yet.</li>}
              {happened.map(e => <li key={e.seq} className={e.type === "rtr.action" && (e.payload as { action?: unknown }).action === "kill" ? "text-neon-amber" : "text-slate-300"}>
                <span className="font-mono text-slate-400">{e.occurred_at ? hhmm(Date.parse(e.occurred_at)) : ""}</span> <bdi>{nameOf(e.actor_id)}</bdi>: {describe(e)}</li>)}
            </ul>
          </Card>
          <Card>
            <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><Lock className="h-3.5 w-3.5" aria-hidden /> Evidence locker</p>
            <ul className="mt-1.5 space-y-1.5">
              {hostEvidence.length === 0 && <li className="text-[11px] text-slate-400">No evidence from this host yet.</li>}
              {hostEvidence.map(x => {
                const ready = now >= x.readyAt; const pct = Math.min(100, Math.round(((now - x.at) / (x.readyAt - x.at)) * 100));
                return (
                  <li key={x.id}>
                    <button type="button" disabled={!ready} onClick={() => setSelEv(x.id)} className={`w-full rounded border px-2 py-1 text-left text-[11px] ${shownEv?.id === x.id ? "border-cyber-500/60 bg-cyber-500/10" : "border-border"} disabled:cursor-wait`}>
                      <span className="font-mono font-semibold text-slate-100">{x.id}</span> <span className="text-slate-400">{x.kind === "memory" ? "memory" : "triage"} · snapshot {hhmm(x.at)}</span>
                      <span className="block text-[10px] text-slate-400">by <bdi>{nameOf(x.by)}</bdi>{ready ? " · ready" : ` · collecting ${pct}%`}</span>
                      {!ready && <span className="mt-1 block h-1 rounded bg-slate-700"><span className="block h-1 rounded bg-cyber-400" style={{ width: `${pct}%` }} /></span>}
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>
        </div>
      )}

      {view && (
        <Card>
          <div className="flex flex-wrap items-center gap-2">
            <FileSearch className="h-4 w-4 text-cyber-300" aria-hidden />
            <span className="font-mono text-xs font-semibold text-white">{view.evidenceId}</span>
            <span className="text-[11px] text-slate-400">{view.host} · snapshot {hhmm(view.snapshotMs)}</span>
            <div className="ml-auto flex flex-wrap gap-1" role="tablist" aria-label="Tool views">
              {view.tables.map(t => (
                <button key={t.plugin} type="button" role="tab" aria-selected={table?.plugin === t.plugin} onClick={() => setPlugin(t.plugin)}
                  className={`rounded px-2 py-1 font-mono text-[11px] ${table?.plugin === t.plugin ? "bg-cyber-500/15 text-cyber-100" : "text-slate-400 hover:text-slate-200"}`}>{t.label}</button>
              ))}
            </div>
          </div>
          {view.empty && <p className="mt-2 text-[11px] text-slate-400">{view.empty}</p>}
          {table && (
            <>
              {table.command && <p className="mt-2 overflow-x-auto rounded bg-black/40 px-2 py-1 font-mono text-[11px] text-neon-green">$ {table.command}</p>}
              {table.notes.map((n, i) => <p key={i} className="mt-1 text-[11px] text-neon-amber">{n}</p>)}
              <div className="mt-2 max-h-80 overflow-auto rounded border border-border">
                <table className="w-full border-collapse font-mono text-[11px]">
                  <thead className="sticky top-0 bg-bg-elevated text-left text-slate-400">
                    <tr><th className="w-7 px-1" aria-label="Pin" />{table.columns.map(c => <th key={c} className="whitespace-nowrap px-2 py-1 font-semibold">{c}</th>)}</tr>
                  </thead>
                  <tbody>
                    {table.rows.map((r, i) => {
                      const ref = table.refs[i]; const pinned = pins.some(p => p.ref === ref);
                      const text = r.map(String).filter(Boolean).slice(0, 6).join(" · ").slice(0, 180);
                      return (
                        <tr key={ref} className={`border-t border-border/50 ${pinned ? "bg-neon-purple/10" : "hover:bg-white/[0.03]"}`}>
                          <td className="px-1"><button type="button" aria-label={pinned ? "Unpin row" : "Pin row to my timeline"} onClick={() => togglePin({ ref, host: view.host, evidence: view.evidenceId, plugin: table.label, text, atMs: table.times[i] })}
                            className={pinned ? "text-neon-purple" : "text-slate-500 hover:text-slate-200"}>{pinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}</button></td>
                          {r.map((c, j) => <td key={j} className="whitespace-nowrap px-2 py-1 text-slate-200">{String(c)}</td>)}
                        </tr>
                      );
                    })}
                    {table.rows.length === 0 && <tr><td colSpan={table.columns.length + 1} className="px-2 py-2 text-slate-400">No rows.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Card>
      )}

      {cur && (
        <div className="grid gap-3 xl:grid-cols-2">
          <Card>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">My timeline ({pins.length})</p>
            <ol className="mt-1.5 max-h-56 space-y-1 overflow-y-auto text-[11px]">
              {pins.length === 0 && <li className="text-slate-400">Pin rows from the tool views to build the sequence of events.</li>}
              {[...pins].sort((a, b) => (a.atMs ?? Infinity) - (b.atMs ?? Infinity)).map(p => (
                <li key={p.ref} className="flex gap-2"><span className="w-16 shrink-0 font-mono text-slate-400">{p.atMs ? hhmm(p.atMs) : "--:--"}</span>
                  <span className="min-w-0 flex-1 text-slate-200"><span className="font-mono text-slate-400">{p.host} {p.plugin}</span> {p.text}</span>
                  <button type="button" onClick={() => togglePin(p)} aria-label="Remove from timeline" className="text-slate-500 hover:text-slate-200"><PinOff className="h-3 w-3" /></button></li>
              ))}
            </ol>
          </Card>
          <Card>
            <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><ShieldQuestion className="h-3.5 w-3.5" aria-hidden /> Publish a finding on {cur}</p>
            <div className="mt-1.5 space-y-2">
              <label className="block text-[11px] text-slate-300">What did you find?
                <select value={fk} onChange={e => setFk(e.target.value)} className="mt-1 w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200">{FINDING_KINDS.map(k => <option key={k.v} value={k.v}>{k.label}</option>)}</select>
              </label>
              {fk === "host_status" && <ChoiceGroup legend="Host status" hideLegend={false} size="xs" value={status} onChange={setStatus}
                options={[{ value: "compromised", label: "Compromised" }, { value: "not_compromised", label: "Not compromised" }, { value: "undetermined", label: "Undetermined" }]} />}
              <label className="block text-[11px] text-slate-300">The finding (what, where, when)
                <textarea value={summary} onChange={e => setSummary(e.target.value)} rows={2} maxLength={800} placeholder="e.g. powershell.exe PID 6512 (parent WINWORD.EXE) holds an outbound session to 198.51.100.23:443" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
              </label>
              <div className="text-[11px] text-slate-300">Evidence (your pinned rows on this host)
                <div className="mt-1 max-h-24 space-y-0.5 overflow-y-auto">
                  {hostPins.length === 0 && <p className="text-slate-400">Pin rows first: a finding without evidence is a guess.</p>}
                  {hostPins.map(p => (
                    <label key={p.ref} className="flex cursor-pointer items-start gap-1.5"><input type="checkbox" checked={cite.has(p.ref)} onChange={() => setCite(s => { const n = new Set(s); if (n.has(p.ref)) n.delete(p.ref); else n.add(p.ref); return n; })} className="mt-0.5" />
                      <span className="text-slate-300"><span className="font-mono text-slate-400">{p.evidence} {p.plugin}</span> {p.text}</span></label>
                  ))}
                </div>
              </div>
              <ChoiceGroup legend="Confidence" hideLegend={false} size="xs" tone="cyan" value={conf} onChange={setConf}
                options={[{ value: "low", label: "Low" }, { value: "moderate", label: "Moderate" }, { value: "high", label: "High" }]} />
              <Button variant="primary" size="sm" disabled={!summary.trim() || !conf || (fk === "host_status" && !status)} onClick={publish}>Publish finding</Button>
              <p className="text-[10px] text-slate-400">Shared with the team and shown to the SOC Manager.</p>
            </div>
          </Card>
        </div>
      )}

      {findings.length > 0 && <FindingsBoard events={events} nameOf={nameOf} />}
    </div>
  );
}

/** All forensic findings of the shift, newest first (Tier-3 workbench and the manager's board). */
export function FindingsBoard({ events, nameOf, compact = false }: { events: Ev[]; nameOf: (u: string | null) => string; compact?: boolean }) {
  const findings = events.filter(e => e.type === "forensic.finding");
  const statusBy = new Map<string, { status: string; by: string | null; conf: string }>();
  for (const f of findings) { const p = f.payload as Record<string, unknown>; if (p.kind === "host_status") statusBy.set(asStr(p.host), { status: asStr(p.status), by: f.actor_id, conf: asStr(p.confidence) }); }
  const tone = (s: string) => (s === "compromised" ? "border-severity-critical/50 text-severity-critical" : s === "not_compromised" ? "border-neon-green/40 text-neon-green" : "border-border text-slate-300");
  return (
    <Card>
      <p className="flex items-center gap-1.5 text-sm font-bold text-white"><Microscope className="h-4 w-4 text-cyber-300" aria-hidden /> Forensic findings ({findings.length})</p>
      {statusBy.size > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {[...statusBy.entries()].map(([h, s]) => <span key={h} className={`rounded border px-2 py-0.5 font-mono text-[11px] ${tone(s.status)}`}>{h}: {s.status.replace("_", " ")} ({s.conf})</span>)}
        </div>
      )}
      <ul className="mt-2 space-y-1.5">
        {findings.slice().reverse().slice(0, compact ? 4 : 50).map(f => {
          const p = f.payload as Record<string, unknown>;
          const ev = Array.isArray(p.evidence_text) ? (p.evidence_text as unknown[]).map(asStr) : [];
          return (
            <li key={f.seq} className="rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs">
              <p className="text-slate-100"><span className="mr-1 rounded border border-border px-1 font-mono text-[10px] uppercase text-slate-400">{KIND_LABEL[asStr(p.kind)] ?? asStr(p.kind)}</span><span className="font-mono text-slate-300">{asStr(p.host)}</span> <bdi>{asStr(p.summary)}</bdi></p>
              <p className="text-[11px] text-slate-400">{asStr(p.confidence)} confidence · {ev.length ? `${ev.length} evidence row${ev.length > 1 ? "s" : ""}` : "no evidence cited"} · <bdi>{nameOf(f.actor_id)}</bdi>{f.occurred_at ? ` · ${hhmm(Date.parse(f.occurred_at))}` : ""}</p>
              {!compact && ev.length > 0 && <ul className="mt-1 space-y-0.5 font-mono text-[10px] text-slate-400">{ev.map((t, i) => <li key={i}>{t}</li>)}</ul>}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
