"use client";
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CheckCircle2, FolderOpen } from "lucide-react";
import type { ScopeState } from "@/lib/team/types";

// ── Scope console (G-10): T2 proposes scope, T3 confirms/amends ───────────────
export function ScopeConsole({ scope, mode, act }: { scope: ScopeState; mode: "set" | "confirm"; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [hosts, setHosts] = useState(scope?.hosts.join(", ") ?? "");
  const [users, setUsers] = useState(scope?.users.join(", ") ?? "");
  const [techs, setTechs] = useState(scope?.techniques.join(", ") ?? "");
  const [busy, setBusy] = useState(false);
  // Re-sync the fields when the shared scope actually changes (e.g. T2 amends it
  // after T3's console already mounted) so T3 confirms the LATEST proposal, not a
  // stale one. Keyed on the scope's content signature so typing isn't clobbered.
  const scopeSig = scope ? `${scope.hosts.join()}|${scope.users.join()}|${scope.techniques.join()}|${scope.confirmed}` : "";
  useEffect(() => {
    setHosts(scope?.hosts.join(", ") ?? "");
    setUsers(scope?.users.join(", ") ?? "");
    setTechs(scope?.techniques.join(", ") ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeSig]);
  const parse = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  async function submit(type: "scope.set" | "scope.confirmed") {
    setBusy(true);
    const ok = await act(type, { hosts: parse(hosts), users: parse(users), techniques: parse(techs) });
    setBusy(false);
    if (ok && type === "scope.confirmed") { /* confirmed — leave fields as the locked value */ }
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Incident scope</h3>
      <p className="mt-0.5 text-[11px] text-slate-400">{mode === "set" ? "Define what's in play — hosts, users, techniques. Tier-3 confirms it." : "Review Tier-2's scope, amend if needed, then confirm the final scope."}</p>
      {scope && <p className="mt-1 text-[10px] font-mono text-slate-500">current: {scope.hosts.length}h · {scope.users.length}u · {scope.techniques.length}t {scope.confirmed ? "· ✓ confirmed" : "· proposed"}</p>}
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
