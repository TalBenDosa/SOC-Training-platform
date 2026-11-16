"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Radar, ListChecks, Monitor, User, Plus, Microscope, X } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr, hostKey } from "@/lib/team/format";
import {
  buildRegister, entityKey, indicatorKind, scansOf, stateChangeProblem, sweepFeed, STATE_LABEL,
  type Confidence, type EntityKind, type EntityState, type RegisterEntry,
} from "@/lib/team/t3Case";
import { ChoiceGroup } from "./ChoiceGroup";

/**
 * Tier-3 "Case" tab (T3 interface spec, stage B): sweep an indicator across every host the team
 * can see, and keep the shared scope register: each host or account suspected, confirmed,
 * cleared or "cannot check", always backed by a citation (a finding or a sweep).
 */

const STATE_TONE: Record<EntityState, string> = {
  suspected: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  confirmed: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  cleared: "border-neon-green/40 bg-neon-green/10 text-neon-green",
  cannot_check: "border-slate-500/40 bg-slate-500/10 text-slate-300",
};
const hhmm = (ms: number | null) => (ms == null ? "" : new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));

export function T3CaseTab({ events, feed, nameOf, act, onOpenEvidence }: {
  events: Ev[]; feed: Ev[]; meId?: string; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  /** Open the Evidence tab on this host. */
  onOpenEvidence: (host: string) => void;
}) {
  const register = useMemo(() => buildRegister(events), [events]);
  const scans = useMemo(() => scansOf(events), [events]);
  const inRegister = useMemo(() => new Set(register.map(r => r.key)), [register]);
  const findings = useMemo(() => events.filter(e => e.type === "forensic.finding"), [events]);

  // ── sweep ──
  const [ind, setInd] = useState("");
  const [sweeping, setSweeping] = useState(false);
  const [sweepErr, setSweepErr] = useState<string | null>(null);
  const kind = indicatorKind(ind);
  async function sweep() {
    const q = ind.trim();
    if (q.length < 3) { setSweepErr("Type at least 3 characters: an IP, domain, hash, process or account."); return; }
    setSweepErr(null); setSweeping(true);
    const r = sweepFeed(feed, q);
    const ok = await act("t3.scan", { indicator: q.slice(0, 200), kind, hosts: r.hosts.slice(0, 60), rows: r.rows });
    setSweeping(false);
    if (ok) setInd("");
  }
  const lastScan = scans[scans.length - 1] ?? null;

  async function addEntity(entity: string, k: EntityKind, cites: number[] = []) {
    return act("t3.scope.entity", { entity: entity.slice(0, 120), entity_kind: k, state: "suspected", cites });
  }
  async function addAllFrom(scanSeq: number, hosts: string[]) {
    for (const h of hosts) await addEntity(h, "host", [scanSeq]);
  }

  // ── Tier-2's scope proposal, offered as suspects ──
  const proposal = useMemo(() => {
    const last = [...events].reverse().find(e => e.type === "scope.set");
    if (!last) return [] as { entity: string; kind: EntityKind }[];
    const p = last.payload as { hosts?: unknown; users?: unknown };
    const hosts = (Array.isArray(p.hosts) ? p.hosts : []).map(asStr).filter(Boolean).map(h => ({ entity: h, kind: "host" as EntityKind }));
    const users = (Array.isArray(p.users) ? p.users : []).map(asStr).filter(Boolean).map(u => ({ entity: u, kind: "account" as EntityKind }));
    return [...hosts, ...users].filter(x => !inRegister.has(entityKey(x.entity, x.kind)));
  }, [events, inRegister]);

  // ── manual add ──
  const [manual, setManual] = useState("");
  const [manualKind, setManualKind] = useState<EntityKind>("host");

  // ── state editor ──
  const [edit, setEdit] = useState<string | null>(null);
  const [next, setNext] = useState<EntityState | null>(null);
  const [cites, setCites] = useState<Set<number>>(new Set());
  const [conf, setConf] = useState<Confidence | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [editErr, setEditErr] = useState<string | null>(null);
  function openEdit(r: RegisterEntry, to: EntityState) {
    // Carry the citations forward only when confirming: a sweep that hit the host is no proof it is clean.
    setEdit(r.key); setNext(to); setCites(new Set(to === "confirmed" ? r.cites : [])); setConf(r.confidence); setReason(""); setEditErr(null);
  }
  /** What can back a state for this entity: findings on the host, and sweeps that hit it. */
  function citeOptions(r: RegisterEntry) {
    const opts: { seq: number; label: string }[] = [];
    if (r.kind === "host") for (const f of findings) {
      const p = f.payload as Record<string, unknown>;
      if (hostKey(asStr(p.host)) !== r.key) continue;
      const st = p.kind === "host_status" ? ` (${asStr(p.status).replace("_", " ")})` : "";
      opts.push({ seq: f.seq, label: `Finding: ${asStr(p.kind).replace("_", " ")}${st}, ${asStr(p.confidence) || "?"} confidence` });
    }
    for (const s of scans) {
      const hit = r.kind === "host" ? s.hosts.find(h => hostKey(h.host) === r.key) : null;
      if (hit) opts.push({ seq: s.seq, label: `Sweep "${s.indicator}": ${hit.count} log${hit.count === 1 ? "" : "s"} on this host` });
      else if (r.kind === "account" && s.indicator.toLowerCase().includes(r.key)) opts.push({ seq: s.seq, label: `Sweep "${s.indicator}"` });
      else if (r.kind === "host" && next === "cleared") opts.push({ seq: s.seq, label: `Sweep "${s.indicator}": not seen on this host` });
    }
    return opts;
  }
  async function save(r: RegisterEntry) {
    if (!next) return;
    const c = [...cites];
    const problem = stateChangeProblem(next, c, reason);
    if (problem) { setEditErr(problem); return; }
    setBusy(true);
    const ok = await act("t3.scope.entity", { entity: r.entity, entity_kind: r.kind, state: next, cites: c, confidence: conf ?? undefined, reason: reason.trim().slice(0, 400) || undefined });
    setBusy(false);
    if (ok) setEdit(null);
  }

  const counts = (s: EntityState) => register.filter(r => r.state === s).length;
  const field = "rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none";

  return (
    <div className="space-y-3" data-tour="t3-case">
      {/* Sweep */}
      <Card>
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Radar className="h-4 w-4 text-cyber-300" aria-hidden /> Sweep an indicator across all hosts</h2>
        <p className="mt-1 text-[11px] text-slate-400">Take an indicator from your evidence (an IP, domain, hash, process or account) and find every host whose logs mention it. Each sweep is recorded, and an empty sweep is evidence too.</p>
        <form className="mt-2 flex flex-wrap items-center gap-2" onSubmit={e => { e.preventDefault(); void sweep(); }}>
          <label htmlFor="t3-sweep" className="sr-only">Indicator to sweep</label>
          <input id="t3-sweep" value={ind} onChange={e => setInd(e.target.value)} placeholder="e.g. 193.106.191.42 or svchost-update.exe" className={`${field} min-w-0 flex-1 font-mono`} />
          {ind.trim().length >= 3 && <span className="rounded border border-border px-1.5 py-0.5 text-[11px] text-slate-300">{kind}</span>}
          <Button type="submit" variant="primary" size="sm" disabled={sweeping}><Radar className="mr-1 h-3.5 w-3.5" aria-hidden /> Sweep</Button>
        </form>
        {sweepErr && <p role="alert" className="mt-1 text-[11px] text-neon-amber">{sweepErr}</p>}
        {lastScan && (
          <div className="mt-3 rounded-lg border border-border bg-bg px-3 py-2" aria-live="polite">
            <p className="text-xs text-slate-200">
              <span className="font-mono">{lastScan.indicator}</span> <span className="text-slate-400">({lastScan.kind}, by {nameOf(lastScan.by)} at {hhmm(lastScan.atMs)}):</span>{" "}
              {lastScan.hosts.length ? <>seen on <strong>{lastScan.hosts.length}</strong> host{lastScan.hosts.length === 1 ? "" : "s"}{lastScan.rows > lastScan.hosts.reduce((n, h) => n + h.count, 0) ? <span className="text-slate-400">, plus logs with no host name</span> : null}</> : <span className="text-neon-green">0 hosts (clean)</span>}
            </p>
            {lastScan.hosts.length > 0 && (
              <ul className="mt-2 space-y-1">
                {lastScan.hosts.map(h => {
                  const there = inRegister.has(hostKey(h.host));
                  return (
                    <li key={h.host} className="flex flex-wrap items-center gap-2 text-xs">
                      <Monitor className="h-3.5 w-3.5 text-slate-400" aria-hidden />
                      <span className="font-mono text-slate-100">{h.host}</span>
                      <span className="text-slate-400">{h.count} log{h.count === 1 ? "" : "s"}{h.first_ms ? `, first ${hhmm(h.first_ms)}` : ""}</span>
                      {there ? <span className="ml-auto text-[11px] text-slate-400">in the register</span>
                        : <Button variant="outline" size="sm" className="ml-auto h-6 px-2 text-[11px]" onClick={() => void addEntity(h.host, "host", [lastScan.seq])}><Plus className="h-3 w-3" aria-hidden /> Add as suspected</Button>}
                    </li>
                  );
                })}
              </ul>
            )}
            {lastScan.hosts.filter(h => !inRegister.has(hostKey(h.host))).length > 1 && (
              <Button variant="secondary" size="sm" className="mt-2" onClick={() => void addAllFrom(lastScan.seq, lastScan.hosts.filter(h => !inRegister.has(hostKey(h.host))).map(h => h.host))}>Add all new hosts as suspected</Button>
            )}
          </div>
        )}
      </Card>

      {/* Register */}
      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ListChecks className="h-4 w-4 text-cyber-300" aria-hidden /> Scope register</h2>
          <span className="text-[11px] text-slate-400">{counts("confirmed")} confirmed · {counts("suspected")} suspected · {counts("cleared")} cleared{counts("cannot_check") ? ` · ${counts("cannot_check")} cannot check` : ""}</span>
        </div>
        <p className="mt-1 text-[11px] text-slate-400">The team&apos;s one answer to &quot;how far did it get&quot;. Confirm or clear only with evidence: a finding from the Evidence tab, or a sweep. Shared with every Tier-3 and shown to the SOC Manager.</p>

        {proposal.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5 rounded-lg border border-cyber-500/30 bg-cyber-500/5 px-2 py-1.5 text-[11px]">
            <span className="text-cyber-200">Tier-2 proposed:</span>
            {proposal.map(x => (
              <button key={`${x.kind}:${x.entity}`} type="button" onClick={() => void addEntity(x.entity, x.kind)} className="rounded border border-border px-1.5 py-0.5 font-mono text-slate-200 hover:border-cyber-500/50" title="Add as suspected">+ {x.entity}</button>
            ))}
          </div>
        )}

        {register.length === 0 ? (
          <p className="mt-3 text-xs text-slate-400">No entities yet. Take a hand-off from your inbox, add the host you are working, or sweep an indicator.</p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400">
                <tr><th className="py-1 pr-2 font-semibold">Entity</th><th className="py-1 pr-2 font-semibold">State</th><th className="py-1 pr-2 font-semibold">Backed by</th><th className="py-1 pr-2 font-semibold">Confidence</th><th className="py-1 font-semibold">By</th></tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {register.map(r => (
                  <RegisterRow key={r.key} r={r} nameOf={nameOf} editing={edit === r.key}
                    onEdit={to => openEdit(r, to)} onRemove={() => void act("t3.scope.entity", { entity: r.entity, entity_kind: r.kind, state: "removed" })}
                    onEvidence={r.kind === "host" ? () => onOpenEvidence(r.entity) : undefined}>
                    {edit === r.key && next && (
                      <div className="mt-2 space-y-2 rounded-lg border border-border bg-bg-elevated/60 p-2">
                        <p className="text-[11px] font-semibold text-slate-200">Mark <bdi className="font-mono">{r.entity}</bdi> as {STATE_LABEL[next].toLowerCase()}</p>
                        <fieldset>
                          <legend className="text-[11px] text-slate-400">Backed by</legend>
                          {citeOptions(r).length ? citeOptions(r).map(o => (
                            <label key={o.seq} className="mt-1 flex items-start gap-2 text-[11px] text-slate-200">
                              <input type="checkbox" checked={cites.has(o.seq)} onChange={e => setCites(s => { const n = new Set(s); if (e.target.checked) n.add(o.seq); else n.delete(o.seq); return n; })} className="mt-0.5 h-3 w-3" />
                              {o.label}
                            </label>
                          )) : <p className="mt-1 text-[11px] text-slate-400">Nothing to cite yet. Write a finding in the Evidence tab, or sweep an indicator.</p>}
                        </fieldset>
                        {next !== "cannot_check" && <ChoiceGroup legend="Confidence" options={[{ value: "low", label: "Low" }, { value: "moderate", label: "Moderate" }, { value: "high", label: "High" }]} value={conf} onChange={setConf} size="xs" />}
                        <label className="block text-[11px] text-slate-400">Reason
                          <input value={reason} onChange={e => setReason(e.target.value)} maxLength={400} placeholder={next === "cleared" ? "e.g. admin change, ticket CHG-1042" : next === "cannot_check" ? "e.g. no EDR on this host" : "optional"} className={`${field} mt-1 w-full text-xs`} />
                        </label>
                        {editErr && <p role="alert" className="text-[11px] text-neon-amber">{editErr}</p>}
                        <div className="flex gap-2">
                          <Button variant="primary" size="sm" disabled={busy} onClick={() => void save(r)}>Save</Button>
                          <Button variant="ghost" size="sm" onClick={() => setEdit(null)}>Cancel</Button>
                        </div>
                      </div>
                    )}
                  </RegisterRow>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <form className="mt-3 flex flex-wrap items-center gap-2" onSubmit={e => { e.preventDefault(); const v = manual.trim(); if (v.length >= 2) void addEntity(v, manualKind).then(ok => { if (ok) setManual(""); }); }}>
          <label htmlFor="t3-add-entity" className="sr-only">Host or account to add</label>
          <input id="t3-add-entity" value={manual} onChange={e => setManual(e.target.value)} placeholder="Add a host or account" className={`${field} min-w-0 flex-1 font-mono text-xs`} />
          <select aria-label="Entity type" value={manualKind} onChange={e => setManualKind(e.target.value as EntityKind)} className={`${field} text-xs`}>
            <option value="host">Host</option><option value="account">Account</option>
          </select>
          <Button type="submit" variant="outline" size="sm"><Plus className="h-3.5 w-3.5" aria-hidden /> Add as suspected</Button>
        </form>
      </Card>

      {/* Sweep log */}
      {scans.length > 0 && (
        <Card>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Sweeps ({scans.length})</h3>
          <ul className="mt-2 space-y-1 text-xs">
            {[...scans].reverse().map(s => (
              <li key={s.seq} className="flex flex-wrap gap-2">
                <span className="font-mono text-slate-100">{s.indicator}</span>
                <span className="text-slate-400">{s.kind}</span>
                <span className={s.hosts.length ? "text-slate-200" : "text-neon-green"}>{s.hosts.length ? `${s.hosts.length} host${s.hosts.length === 1 ? "" : "s"}` : "0 hosts (clean)"}</span>
                <span className="ml-auto text-slate-400">{nameOf(s.by)} · {hhmm(s.atMs)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function RegisterRow({ r, nameOf, editing, onEdit, onRemove, onEvidence, children }: {
  r: RegisterEntry; nameOf: (u: string | null) => string; editing: boolean;
  onEdit: (to: EntityState) => void; onRemove: () => void; onEvidence?: () => void; children?: React.ReactNode;
}) {
  const moves: EntityState[] = (["suspected", "confirmed", "cleared", "cannot_check"] as EntityState[]).filter(s => s !== r.state);
  return (
    <tr className="align-top">
      <td className="py-2 pr-2">
        <span className="flex items-center gap-1.5 font-mono text-slate-100">
          {r.kind === "host" ? <Monitor className="h-3.5 w-3.5 text-slate-400" aria-label="host" /> : <User className="h-3.5 w-3.5 text-slate-400" aria-label="account" />}
          {r.entity}
        </span>
        {r.reason && <span className="mt-0.5 block max-w-[16rem] text-[11px] text-slate-400">{r.reason}</span>}
        {children}
      </td>
      <td className="py-2 pr-2">
        <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-semibold ${STATE_TONE[r.state]}`}>{STATE_LABEL[r.state]}</span>
        {!editing && (
          <div className="mt-1 flex flex-wrap gap-1">
            {moves.map(s => <button key={s} type="button" onClick={() => onEdit(s)} className="rounded border border-border px-1 text-[10px] text-slate-300 hover:border-cyber-500/50 hover:text-white">{STATE_LABEL[s]}</button>)}
          </div>
        )}
      </td>
      <td className="py-2 pr-2 text-[11px] text-slate-300">
        {r.cites.length ? `${r.cites.length} citation${r.cites.length === 1 ? "" : "s"}${r.source === "finding" ? " (finding)" : ""}` : <span className="text-slate-500">none</span>}
        {onEvidence && <button type="button" onClick={onEvidence} className="mt-1 flex items-center gap-1 text-cyber-300 hover:underline"><Microscope className="h-3 w-3" aria-hidden /> Evidence</button>}
      </td>
      <td className="py-2 pr-2 text-[11px] text-slate-300">{r.confidence ?? "-"}</td>
      <td className="py-2 text-[11px] text-slate-400">
        {nameOf(r.by)}
        <button type="button" onClick={onRemove} aria-label={`Remove ${r.entity} from the register`} className="ml-1 rounded p-0.5 text-slate-500 hover:text-white"><X className="h-3 w-3" aria-hidden /></button>
      </td>
    </tr>
  );
}
