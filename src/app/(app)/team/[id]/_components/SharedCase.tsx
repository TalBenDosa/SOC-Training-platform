"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ShieldCheck, FolderOpen, ChevronDown, Crosshair } from "lucide-react";
import type { RosterMember, Me, Ev } from "@/lib/team/types";
import { sevColor, asStr } from "@/lib/team/format";
import { containmentRequests, escalationStates, incidentByEvent, scopeByIncident, type ScopeSnapshot } from "@/lib/team/projections";
import { ROLE_LABEL } from "./shared";
import { containmentVerb } from "./T2Console";

// ── Shared Case panel (§5.1) — the one artifact the whole team works ──────────
const CASE_STATUSES = ["new", "triaged", "investigating", "contained", "eradicated", "closed"];
function sevRank(s?: string) { return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1; }
// Per-incident grouping (T3 / Manager playtest: three incidents were forced into one
// scope + one status). Each escalated log belongs to the incident its latest labelled
// action names (report / containment / hunt / scope `incident`); an unlabelled log is
// its own incident (the escalation's root event) — old sessions still render.
interface IncidentGroup { key: string; name: string; labelled: boolean; escs: Ev[]; reports: Ev[]; hunts: Ev[]; scope: ScopeSnapshot | null; maxSev: string }
export function SharedCase({ events, feed, roster, me, act, nameOf }: { events: Ev[]; feed: Ev[]; roster: RosterMember[]; me: Me; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; nameOf: (u: string | null) => string }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false); // G-02: collapsed to a summary bar by default
  const feedById = useMemo(() => new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.payload as Record<string, unknown>])), [feed]);
  const escStates = useMemo(() => escalationStates(events), [events]);
  const escs = useMemo(() => [...escStates.values()].filter(s => s.rounds > 0).map(s => s.request).sort((a, b) => a.seq - b.seq), [escStates]);
  const notes = useMemo(() => events.filter(e => e.type === "note.added"), [events]);
  const hunts = useMemo(() => events.filter(e => e.type === "hunt.logged"), [events]);
  const statusEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.status_set"), [events]);
  const ownerEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.assigned"), [events]);
  const contByEid = useMemo(() => { const m = new Map<string, ReturnType<typeof containmentRequests>>(); for (const r of containmentRequests(events)) m.set(r.eid, [...(m.get(r.eid) ?? []), r]); return m; }, [events]);

  const autoStatus = escs.length > 0 ? "investigating" : "new";
  const status = (statusEvt?.payload as { status?: string })?.status ?? autoStatus;
  const ownerId = (ownerEvt?.payload as { owner?: string })?.owner ?? null;

  // Scope builds itself from what Tier-1 escalated — resolve each escalated event
  // back to its feed log and union the hosts/users/techniques it touched.
  const hosts = new Set<string>(), users = new Set<string>(), techs = new Set<string>();
  let maxSev = "low";
  for (const esc of escs) {
    const pp = esc.payload as { event_id?: string };
    const fe = feedById.get(String(pp.event_id)) as { hostname?: string; severity?: string; mitre_technique?: string; user?: { email?: string; full_name?: string }; user_email?: string } | undefined;
    if (typeof fe?.hostname === "string" && fe.hostname) hosts.add(fe.hostname);
    if (typeof fe?.mitre_technique === "string" && fe.mitre_technique) techs.add(fe.mitre_technique);
    const u = fe?.user?.email || fe?.user?.full_name || fe?.user_email; if (typeof u === "string" && u) users.add(u);
    if (typeof fe?.severity === "string" && sevRank(fe.severity) > sevRank(maxSev)) maxSev = fe.severity;
  }
  const severity = (statusEvt?.payload as { severity?: string })?.severity ?? maxSev;
  // G-10: an explicit scope (T2 set / T3 confirmed) overrides the auto-derived union.
  // "confirmed" only while the LATEST scope event is Tier-3's confirmation (it used to
  // stay "confirmed by Tier-3" after Tier-2 changed the scope).
  const scopes = useMemo(() => scopeByIncident(events), [events]);
  const explicitScope = scopes.get("") ?? null;   // labelled scopes render inside their incident
  const scopeConfirmed = !!explicitScope?.confirmed;
  const dispHosts = explicitScope ? explicitScope.hosts : [...hosts];
  const dispUsers = explicitScope ? explicitScope.users : [...users];
  const dispTechs = explicitScope ? explicitScope.techniques : [...techs];
  const scopeLabel = explicitScope ? (scopeConfirmed ? "confirmed by Tier-3" : "proposed") : "auto-derived";
  // G-09: executed containments (shared containment state / real MTTC).
  const executed = useMemo(() => events.filter(e => e.type === "containment.executed"), [events]);

  // ── incidents ──
  const groups = useMemo(() => {
    const incOf = incidentByEvent(events);
    const byKey = new Map<string, IncidentGroup>();
    const get = (key: string, name: string, labelled: boolean) => { let g = byKey.get(key); if (!g) { g = { key, name, labelled, escs: [], reports: [], hunts: [], scope: labelled ? scopes.get(name) ?? null : null, maxSev: "low" }; byKey.set(key, g); } return g; };
    for (const e of escs) {
      const eid = String((e.payload as { event_id?: string }).event_id);
      const lab = incOf.get(eid);
      const p = e.payload as { summary?: string; what?: string };
      const g = lab ? get(`L:${lab}`, lab, true) : get(`E:${eid}`, asStr(p.summary) || asStr(p.what) || `case #${e.seq}`, false);
      g.escs.push(e);
      const sev = asStr((feedById.get(eid) as { severity?: string } | undefined)?.severity);
      if (sevRank(sev) > sevRank(g.maxSev)) g.maxSev = sev;
    }
    const keyForEid = new Map<string, string>();
    for (const g of byKey.values()) for (const e of g.escs) keyForEid.set(String((e.payload as { event_id?: string }).event_id), g.key);
    const latestReport = new Map<string, Ev>();
    for (const e of events) if (e.type === "report.submitted") latestReport.set(String((e.payload as { event_id?: string }).event_id), e);
    for (const [eid, r] of latestReport) { const k = keyForEid.get(eid); if (k) byKey.get(k)!.reports.push(r); }
    const loose: Ev[] = [];
    for (const h of hunts) {
      const p = h.payload as { event_id?: string; incident?: string };
      const lab = asStr(p.incident).trim();
      const k = lab ? `L:${lab}` : keyForEid.get(String(p.event_id ?? ""));
      if (k && byKey.has(k)) byKey.get(k)!.hunts.push(h);
      else if (lab) get(`L:${lab}`, lab, true).hunts.push(h);
      else loose.push(h);
    }
    // labelled scopes with no escalation yet still show as an incident
    for (const [lab] of scopes) if (lab) get(`L:${lab}`, lab, true);
    return { list: [...byKey.values()], loose };
  }, [events, escs, hunts, scopes, feedById]);

  const canStatus = ["t2", "t3", "lead", "mgr"].includes(me.role ?? "");
  const canAssign = ["lead", "mgr"].includes(me.role ?? "");
  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");

  async function addNote() { if (!note.trim()) return; setBusy(true); const ok = await act("note.added", { text: note }); setBusy(false); if (ok) setNote(""); }

  const huntRow = (h: Ev) => { const p = h.payload as { hypothesis?: string; finding?: string; technique?: string; conclusion?: string }; const c = asStr(p.conclusion); return (
    <div key={h.seq} className="rounded border border-neon-purple/25 bg-neon-purple/[0.05] px-2 py-1 text-[11px]">
      <p className="text-slate-200"><Crosshair className="mr-1 inline h-3 w-3 text-neon-purple" />{asStr(p.hypothesis)} <span className={`ml-1 rounded border px-1 py-px text-[9px] font-bold uppercase ${c === "confirmed" ? "border-severity-high/40 text-severity-high" : c === "refuted" ? "border-neon-green/40 text-neon-green" : "border-border text-slate-400"}`}>{c || "logged"}</span>{asStr(p.technique) && <span className="ml-1 font-mono text-[10px] text-cyber-300">{asStr(p.technique)}</span>}</p>
      {asStr(p.finding) && <p className="mt-0.5 text-slate-400">{asStr(p.finding)}</p>}
      <p className="font-mono text-[10px] text-slate-500">{nameOf(h.actor_id)}</p>
    </div>
  ); };

  return (
    <Card>
      {/* G-02: thin collapsible summary bar — status·sev·owner·scope·evidence — the
          feed stays the team's primary truth; the case opens to full detail on click */}
      <button onClick={() => setOpen(o => !o)} className="flex w-full flex-wrap items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Shared case</h2>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${status === "closed" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : status === "contained" || status === "eradicated" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"}`}>{status}</span>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevRank(severity) >= 3 ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>sev {severity}</span>
        <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">{groups.list.length} incident{groups.list.length === 1 ? "" : "s"} · {dispHosts.length}h · {dispUsers.length}u · {dispTechs.length}t · {escs.length} ev{hunts.length ? ` · ${hunts.length} hunt` : ""}{executed.length ? ` · ${executed.length} contained` : ""}</span>
        <span className="ml-auto text-[11px] text-slate-400">owner: <span className="text-slate-200">{ownerId ? nameOf(ownerId) : "unassigned"}</span></span>
      </button>

      {open && (<>
      {/* Plain explanation — the case was opaque to new players (feedback) */}
      <p className="mt-2 text-[11px] leading-relaxed text-slate-400">
        The team&apos;s <b className="text-slate-300">single source of truth</b> — it builds itself from what Tier-1 escalates. Related cases group into <b className="text-slate-300">incidents</b> by the incident label on a report, scope, containment or hunt. Move the <b className="text-slate-300">status</b> as the shift progresses (new → investigating → contained → closed); the SOC Manager assigns an <b className="text-slate-300">owner</b>.
      </p>
      {/* lifecycle stepper */}
      <div className="mt-3 flex flex-wrap items-center gap-1">
        {CASE_STATUSES.map(s => (
          <button key={s} disabled={!canStatus || busy || s === status}
            onClick={async () => { setBusy(true); await act("case.status_set", { status: s, severity }); setBusy(false); }}
            className={`rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition ${s === status ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : canStatus ? "border-border text-slate-400 hover:text-white" : "border-border/50 text-slate-600"}`}>{s}</button>
        ))}
      </div>
      {canAssign && (
        <div className="mt-2">
          <select value={ownerId ?? ""} onChange={async e => { setBusy(true); await act("case.assigned", { owner: e.target.value }); setBusy(false); }}
            className="rounded-lg border border-border bg-bg px-2 py-1 text-xs text-slate-200 focus:outline-none">
            <option value="">assign owner…</option>
            {players.map(p => <option key={p.user_id} value={p.user_id}>{p.name} · {ROLE_LABEL[p.role] ?? p.role}</option>)}
          </select>
        </div>
      )}

      {/* scope — explicit shift-wide T2/T3 scope when set (G-10), else auto-derived from escalations */}
      <div className="mt-3 flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Scope{scopes.size > 1 || (scopes.size === 1 && !scopes.has("")) ? " (shift-wide)" : ""}</p>
        <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${scopeConfirmed ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : explicitScope ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-500"}`}>{scopeLabel}</span>
      </div>
      <div className="mt-1 grid gap-2 sm:grid-cols-3">
        <ScopeBox label="Hosts" items={dispHosts} />
        <ScopeBox label="Users" items={dispUsers} />
        <ScopeBox label="Techniques" items={dispTechs} accent />
      </div>
      {executed.length > 0 && (
        <div className="mt-2 flex items-center gap-2 rounded border border-neon-green/30 bg-neon-green/[0.06] px-2 py-1 text-[11px] text-neon-green">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" /> Contained: {executed.map(e => asStr((e.payload as { target?: string }).target)).filter(Boolean).join(", ") || `${executed.length} target(s)`}
        </div>
      )}

      {/* incidents — evidence (escalations), determinations, hunt findings and containment per incident */}
      <div className="mt-3">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Incidents ({groups.list.length})</p>
        {groups.list.length === 0 ? <p className="text-xs text-slate-500">No escalations yet — when Tier-1 escalates a log, it lands here as case evidence, and the scope above fills in.</p> : (
          <div className="space-y-2">
            {groups.list.map(g => (
              <div key={g.key} className="rounded-lg border border-border bg-bg px-2.5 py-2">
                <div className="flex items-center gap-2">
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevColor(g.maxSev)}`} />
                  <span className="min-w-0 flex-1 truncate text-xs font-semibold text-slate-200">{g.labelled ? g.name : `Case: ${g.name}`}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{g.escs.length} ev{g.reports.length ? ` · ${g.reports.length} report` : ""}{g.hunts.length ? ` · ${g.hunts.length} hunt` : ""}</span>
                </div>
                {g.scope && <p className="mt-0.5 font-mono text-[10px] text-slate-500">scope {g.scope.confirmed ? "✓ confirmed" : "proposed"}: {[...g.scope.hosts, ...g.scope.users, ...g.scope.techniques].join(", ") || "—"}</p>}
                {g.escs.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {g.escs.map(e => { const p = e.payload as { what?: string; summary?: string; event_id?: string }; const eid = String(p.event_id); const st = escStates.get(eid); const fe = feedById.get(eid) as { severity?: string } | undefined; const cont = contByEid.get(eid) ?? []; return (
                      <div key={e.seq} className="text-[11px]">
                        <div className="flex items-center gap-2">
                          <span className={`h-1 w-1 shrink-0 rounded-full ${sevColor(fe?.severity)}`} />
                          <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.summary) || asStr(p.what) || "escalation"}</span>
                          <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}{st?.owner ? ` → ${nameOf(st.owner)}` : ""}</span>
                          <span className="shrink-0 font-mono text-[9px] uppercase text-slate-500">{st?.resolved ? "resolved" : st?.bounced ? "bounced" : st?.acked ? "taken" : "open"}</span>
                        </div>
                        {cont.map(r => <p key={r.seq} className={`ml-3 text-[10px] ${r.status === "denied" ? "text-severity-high" : r.status === "executed" ? "text-neon-green" : "text-cyber-300"}`}>{containmentVerb(asStr((r.request.payload as { containment_type?: string }).containment_type))} {asStr((r.request.payload as { target?: string }).target)} — {r.status}</p>)}
                      </div>
                    ); })}
                  </div>
                )}
                {/* A1: Tier-2/3 determinations & handover reports — read live by T3 and the Manager */}
                {g.reports.map(e => { const p = e.payload as { verdict?: string; summary?: string; recommendation?: string }; const v = asStr(p.verdict); return (
                  <div key={e.seq} className="mt-1 rounded border border-cyber-500/25 bg-cyber-500/[0.05] px-2 py-1 text-[11px]">
                    <div className="flex items-center gap-2">
                      {v && <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${v === "true_positive" || v === "escalate" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>{v.replace("_", " ")}</span>}
                      <span className="min-w-0 flex-1 truncate text-slate-200">{asStr(p.summary) || "incident report"}</span>
                      <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
                    </div>
                    {asStr(p.recommendation) && <p className="mt-0.5 text-cyber-200"><span className="text-slate-500">▶ recommends:</span> {asStr(p.recommendation)}</p>}
                  </div>
                ); })}
                {/* T3 playtest: hunt findings now reach the team, per incident */}
                {g.hunts.length > 0 && <div className="mt-1 space-y-1">{g.hunts.map(huntRow)}</div>}
              </div>
            ))}
          </div>
        )}
      </div>
      {groups.loose.length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Hunt findings — not linked to a case ({groups.loose.length})</p>
          <div className="space-y-1">{groups.loose.slice().reverse().map(huntRow)}</div>
        </div>
      )}

      {/* case notes */}
      <div className="mt-3 border-t border-border/50 pt-2">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Case notes ({notes.length})</p>
        {notes.length > 0 && (
          <div className="mb-2 max-h-40 space-y-1 overflow-y-auto">
            {notes.slice().reverse().map(e => <p key={e.seq} className="whitespace-pre-wrap break-words text-xs text-slate-300"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}:</span> {String((e.payload as { text?: string }).text ?? "")}</p>)}
          </div>
        )}
        <div className="flex gap-2">
          <input value={note} onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter") addNote(); }} placeholder="Add a case note…" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <Button variant="outline" size="sm" disabled={busy || !note.trim()} onClick={addNote}>Add</Button>
        </div>
      </div>
      </>)}
    </Card>
  );
}
function ScopeBox({ label, items, accent }: { label: string; items: string[]; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
      <p className="text-[10px] uppercase tracking-wider text-slate-400">{label}</p>
      {items.length === 0 ? <p className="text-[11px] text-slate-600">—</p> : (
        <div className="mt-1 flex flex-wrap gap-1">{items.slice(0, 8).map(i => <span key={i} className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${accent ? "bg-cyber-500/10 text-cyber-300" : "bg-white/5 text-slate-300"}`}>{i}</span>)}{items.length > 8 && <span className="text-[10px] text-slate-500">+{items.length - 8}</span>}</div>
      )}
    </div>
  );
}
