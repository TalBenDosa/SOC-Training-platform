"use client";
import { useEffect, useState } from "react";
import { displayError } from "@/lib/http/apiError";
import { Button } from "@/components/ui/Button";
import { UserPlus } from "lucide-react";
import type { RosterMember } from "@/lib/team/types";
import { ROLE_LABEL } from "./shared";

// Add a member to a live/lobby session (staff) — grow the team or backfill a
// role. Calls the /members route; the invitee then sees it under Team training.
export function AddMemberPanel({ sessionId, roster }: { sessionId: string; roster: RosterMember[] }) {
  const [members, setMembers] = useState<{ user_id: string; display_name: string | null; handle: string | null }[] | null>(null);   // null = not loaded
  const [pick, setPick] = useState({ user_id: "", role: "t1" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || members !== null) return;
    (async () => {
      // Same org-scoped, active-only candidate list as the Session Builder (#18).
      const res = await fetch("/api/team/candidates").catch(() => null);
      if (!res || !res.ok) { setMembers([]); setMsg({ ok: false, text: "Couldn't load your organisation's members." }); return; }
      const data = await res.json();
      setMembers(data.members ?? []);
    })();
  }, [open, members]);
  const inSession = new Set(roster.filter(r => r.status !== "left").map(r => r.user_id));
  const available = (members ?? []).filter(m => !inSession.has(m.user_id));
  async function add() {
    if (!pick.user_id) return;
    setBusy(true); setMsg(null);
    try {
      const res = await fetch(`/api/team/sessions/${sessionId}/members`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(pick) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "Could not add the member.");
      const who = (members ?? []).find(m => m.user_id === pick.user_id);
      setMsg({ ok: true, text: `${who?.display_name || who?.handle || "Member"} added as ${ROLE_LABEL[pick.role] ?? pick.role}. They'll see it under Team training.` });
      setPick({ user_id: "", role: "t1" });
    } catch (e) { setMsg({ ok: false, text: displayError(e, "Could not add the member.") }); }
    finally { setBusy(false); }
  }
  return (
    <div className="mt-3 border-t border-border/50 pt-3">
      {!open ? (
        <button onClick={() => setOpen(true)} className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyber-300 hover:underline"><UserPlus className="h-3.5 w-3.5" /> Add a member</button>
      ) : (
        <div className="space-y-1.5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Add a member</p>
          <div className="flex gap-1.5">
            <select value={pick.user_id} onChange={e => setPick(s => ({ ...s, user_id: e.target.value }))} className="min-w-0 flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
              <option value="">{members === null ? "Loading members…" : "— member —"}</option>
              {available.map(m => <option key={m.user_id} value={m.user_id}>{m.display_name || m.handle || m.user_id.slice(0, 8)}</option>)}
            </select>
            <select value={pick.role} onChange={e => setPick(s => ({ ...s, role: e.target.value }))} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
              {["t1", "t2", "t3", "mgr", "observer"].map(r => <option key={r} value={r}>{ROLE_LABEL[r] ?? r}</option>)}
            </select>
            <Button variant="outline" size="sm" disabled={busy || !pick.user_id} onClick={add}>Add</Button>
          </div>
          {members !== null && available.length === 0 && members.length > 0 && <p className="text-[11px] text-slate-500">Everyone active is already on the roster.</p>}
          {msg && <p className={`text-[11px] ${msg.ok ? "text-neon-green" : "text-severity-high"}`}>{msg.text}</p>}
        </div>
      )}
    </div>
  );
}
