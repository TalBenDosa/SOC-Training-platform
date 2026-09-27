"use client";
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CheckCircle2, FolderOpen } from "lucide-react";
import type { ScopeState } from "@/lib/team/types";
import type { ScopeSnapshot } from "@/lib/team/projections";

// ── Scope console (G-10): T2 proposes scope, T3 confirms/amends ───────────────
// Per-incident (T3 / Manager playtest: one scope for three incidents): an optional
// incident label picks WHICH scope you're editing; blank = the shift-wide scope, so
// sessions without labels behave exactly as before.
export function ScopeConsole({ scope, scopes, incidents = [], mode, act }: { scope: ScopeState; scopes?: Map<string, ScopeSnapshot>; incidents?: string[]; mode: "set" | "confirm"; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [incident, setIncident] = useState("");
  const inc = incident.trim();
  // The scope being edited: the selected incident's latest, else the legacy single scope.
  const cur: ScopeSnapshot | ScopeState = scopes ? (scopes.get(inc) ?? null) : scope;
  const [hosts, setHosts] = useState(cur?.hosts.join(", ") ?? "");
  const [users, setUsers] = useState(cur?.users.join(", ") ?? "");
  const [techs, setTechs] = useState(cur?.techniques.join(", ") ?? "");
  const [busy, setBusy] = useState(false);
  // Re-sync the fields when the shared scope actually changes (e.g. T2 amends it
  // after T3's console already mounted) or another incident is picked, so T3
  // confirms the LATEST proposal. Keyed on a content signature so typing isn't clobbered.
  const scopeSig = `${inc}§${cur ? `${cur.hosts.join()}|${cur.users.join()}|${cur.techniques.join()}|${cur.confirmed}` : ""}`;
  useEffect(() => {
    setHosts(cur?.hosts.join(", ") ?? "");
    setUsers(cur?.users.join(", ") ?? "");
    setTechs(cur?.techniques.join(", ") ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeSig]);
  const parse = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  async function submit(type: "scope.set" | "scope.confirmed") {
    setBusy(true);
    await act(type, { hosts: parse(hosts), users: parse(users), techniques: parse(techs), incident: inc || undefined });
    setBusy(false);
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Incident scope</h3>
      <p className="mt-0.5 text-[11px] text-slate-400">{mode === "set" ? "Define what's in play — hosts, users, techniques. Tier-3 confirms it." : "Review Tier-2's scope, amend if needed, then confirm the final scope."} Several incidents at once? Give each its own label.</p>
      <div className="mt-2 flex items-center gap-1.5">
        <input value={incident} onChange={e => setIncident(e.target.value)} list="scope-incidents" placeholder="Incident label (optional — blank = shift-wide scope)" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <datalist id="scope-incidents">{incidents.map(i => <option key={i} value={i} />)}</datalist>
      </div>
      {incidents.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          {["", ...incidents].map(i => <button key={i || "_all"} onClick={() => setIncident(i)} className={`rounded border px-1.5 py-0.5 font-mono text-[9px] ${inc === i ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400 hover:text-white"}`}>{i || "shift-wide"}</button>)}
        </div>
      )}
      {cur && <p className="mt-1 text-[10px] font-mono text-slate-500">current{inc ? ` (${inc})` : ""}: {cur.hosts.length}h · {cur.users.length}u · {cur.techniques.length}t {cur.confirmed ? "· ✓ confirmed" : "· proposed"}</p>}
      <div className="mt-2 space-y-1.5">
        <input value={hosts} onChange={e => setHosts(e.target.value)} placeholder="hosts (comma-separated)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={users} onChange={e => setUsers(e.target.value)} placeholder="users" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={techs} onChange={e => setTechs(e.target.value)} placeholder="techniques (T1234…)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
      </div>
      <div className="mt-2 flex gap-1.5">
        <Button variant="outline" size="sm" disabled={busy} onClick={() => submit("scope.set")}>{mode === "set" ? "Set scope" : "Amend"}</Button>
        {mode === "confirm" && <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("scope.confirmed")}><CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Confirm scope</Button>}
      </div>
    </Card>
  );
}
