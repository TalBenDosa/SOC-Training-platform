"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ShieldCheck, FolderOpen, ChevronDown } from "lucide-react";
import type { RosterMember, Me, Ev } from "@/lib/team/types";
import { sevColor, asStr } from "@/lib/team/format";
import { ROLE_LABEL } from "./shared";

// ── Shared Case panel (§5.1) — the one artifact the whole team works ──────────
const CASE_STATUSES = ["new", "triaged", "investigating", "contained", "eradicated", "closed"];
function sevRank(s?: string) { return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1; }
export function SharedCase({ events, feed, roster, me, act, nameOf }: { events: Ev[]; feed: Ev[]; roster: RosterMember[]; me: Me; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; nameOf: (u: string | null) => string }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false); // G-02: collapsed to a summary bar by default
  const feedById = useMemo(() => new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.payload as Record<string, unknown>])), [feed]);
  const escs = useMemo(() => events.filter(e => e.type === "escalation.requested"), [events]);
  const notes = useMemo(() => events.filter(e => e.type === "note.added"), [events]);
  // A1: the latest Tier-2 incident report per case — the live handover the team reads.
  const reportsByEid = useMemo(() => {
    const m = new Map<string, Ev>();
    for (const e of events) if (e.type === "report.submitted") m.set(String((e.payload as { event_id?: string }).event_id), e);
    return m;
  }, [events]);
  const reports = useMemo(() => [...reportsByEid.values()], [reportsByEid]);
  const statusEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.status_set"), [events]);
  const ownerEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.assigned"), [events]);

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
  const scopeEvt = useMemo(() => [...events].reverse().find(e => e.type === "scope.set" || e.type === "scope.confirmed"), [events]);
  const scopeConfirmed = useMemo(() => events.some(e => e.type === "scope.confirmed"), [events]);
  const explicitScope = scopeEvt ? (scopeEvt.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }) : null;
  const dispHosts = explicitScope ? (explicitScope.hosts ?? []) : [...hosts];
  const dispUsers = explicitScope ? (explicitScope.users ?? []) : [...users];
  const dispTechs = explicitScope ? (explicitScope.techniques ?? []) : [...techs];
  const scopeLabel = explicitScope ? (scopeConfirmed ? "confirmed by Tier-3" : "proposed by Tier-2") : "auto-derived";
  // G-09: executed isolations (shared containment state / real MTTC).
  const executed = useMemo(() => events.filter(e => e.type === "containment.executed"), [events]);
  const canStatus = ["t2", "t3", "lead", "mgr"].includes(me.role ?? "");
  const canAssign = ["lead", "mgr"].includes(me.role ?? "");
  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");

  async function addNote() { if (note.trim().length < 3) return; setBusy(true); const ok = await act("note.added", { text: note }); setBusy(false); if (ok) setNote(""); }

  return (
    <Card>
      {/* G-02: thin collapsible summary bar — status·sev·owner·scope·evidence — the
          feed stays the team's primary truth; the case opens to full detail on click */}
      <button onClick={() => setOpen(o => !o)} className="flex w-full flex-wrap items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Shared case</h2>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${status === "closed" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : status === "contained" || status === "eradicated" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"}`}>{status}</span>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevRank(severity) >= 3 ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>sev {severity}</span>
        <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">{dispHosts.length}h · {dispUsers.length}u · {dispTechs.length}t · {escs.length} ev{executed.length ? ` · ${executed.length} isolated` : ""}</span>
        <span className="ml-auto text-[11px] text-slate-400">owner: <span className="text-slate-200">{ownerId ? nameOf(ownerId) : "unassigned"}</span></span>
      </button>

      {open && (<>
      {/* Plain explanation — the case was opaque to new players (feedback) */}
      <p className="mt-2 text-[11px] leading-relaxed text-slate-400">
        The team&apos;s <b className="text-slate-300">single source of truth</b> for this incident — it builds itself from what Tier-1 escalates. Move the <b className="text-slate-300">status</b> as the incident progresses (new → investigating → contained → closed); the SOC Manager assigns an <b className="text-slate-300">owner</b>; scope, evidence and isolations roll up here so everyone shares one picture.
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

      {/* scope — explicit T2/T3 scope when set (G-10), else auto-derived from escalations */}
      <div className="mt-3 flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Scope</p>
        <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${scopeConfirmed ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : explicitScope ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-500"}`}>{scopeLabel}</span>
      </div>
      <div className="mt-1 grid gap-2 sm:grid-cols-3">
        <ScopeBox label="Hosts" items={dispHosts} />
        <ScopeBox label="Users" items={dispUsers} />
        <ScopeBox label="Techniques" items={dispTechs} accent />
      </div>
      {executed.length > 0 && (
        <div className="mt-2 flex items-center gap-2 rounded border border-neon-green/30 bg-neon-green/[0.06] px-2 py-1 text-[11px] text-neon-green">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" /> Isolation executed: {executed.map(e => asStr((e.payload as { target?: string }).target)).filter(Boolean).join(", ") || `${executed.length} host(s)`}
        </div>
      )}

      {/* evidence = the escalations — the case builds itself as tickets rise */}
      <div className="mt-3">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Evidence ({escs.length})</p>
        {escs.length === 0 ? <p className="text-xs text-slate-500">No escalations yet — when Tier-1 escalates a log, it lands here as case evidence, and the scope above fills in.</p> : (
          <div className="space-y-1">
            {escs.map(e => { const p = e.payload as { what?: string; event_id?: string }; const fe = feedById.get(String(p.event_id)) as { severity?: string } | undefined; return (
              <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-xs">
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevColor(fe?.severity)}`} />
                <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.what) || "escalation"}</span>
                <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
              </div>
            ); })}
          </div>
        )}
      </div>

      {/* A1: Tier-2 determinations & handover reports — read live by T3 and the Manager */}
      {reports.length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Determinations &amp; handover ({reports.length})</p>
          <div className="space-y-1.5">
            {reports.map(e => { const p = e.payload as { verdict?: string; summary?: string; recommendation?: string; findings?: string }; const v = asStr(p.verdict); return (
              <div key={e.seq} className="rounded-lg border border-cyber-500/25 bg-cyber-500/[0.05] px-2.5 py-1.5 text-xs">
                <div className="flex items-center gap-2">
                  {v && <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${v === "true_positive" || v === "escalate" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>{v.replace("_", " ")}</span>}
                  <span className="min-w-0 flex-1 truncate text-slate-200">{asStr(p.summary) || "incident report"}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
                </div>
                {asStr(p.recommendation) && <p className="mt-0.5 text-[11px] text-cyber-200"><span className="text-slate-500">▶ recommends:</span> {asStr(p.recommendation)}</p>}
              </div>
            ); })}
          </div>
        </div>
      )}

      {/* case notes */}
      <div className="mt-3 border-t border-border/50 pt-2">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Case notes ({notes.length})</p>
        {notes.length > 0 && (
          <div className="mb-2 max-h-40 space-y-1 overflow-y-auto">
            {notes.slice().reverse().map(e => <p key={e.seq} className="whitespace-pre-wrap break-words text-xs text-slate-300"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}:</span> {String((e.payload as { text?: string }).text ?? "").slice(0, 2000)}</p>)}
          </div>
        )}
        <div className="flex gap-2">
          <input value={note} onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter") addNote(); }} placeholder="Add a case note…" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <Button variant="outline" size="sm" disabled={busy || note.trim().length < 3} onClick={addNote}>Add</Button>
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
        <div className="mt-1 flex flex-wrap gap-1">{items.slice(0, 8).map(i => <span key={i} className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${accent ? "bg-cyber-500/10 text-cyber-300" : "bg-white/5 text-slate-300"}`}>{i}</span>)}</div>
      )}
    </div>
  );
}
