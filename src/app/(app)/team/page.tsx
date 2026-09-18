"use client";
/**
 * Team-SOC training — index (Phase 0.3). Staff see the Session Builder (pick a
 * company + difficulty, invite org members with roles); everyone sees the
 * sessions they belong to and can enter the lobby. The exercise itself lives at
 * /team/[id].
 */
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { Users, Plus, Loader2, AlertTriangle, ChevronRight, Radio } from "lucide-react";

type Diff = "easy" | "medium" | "hard";
// Team role set: T1 & T2 take MANY players; T3 and the SOC Manager are single-seat.
const PLAY_ROLES = [
  { id: "t1", label: "Tier-1 Triage" }, { id: "t2", label: "Tier-2 Investigator" },
  { id: "t3", label: "Tier-3 / Threat Hunter" }, { id: "mgr", label: "SOC Manager" },
];
const SINGLE_SEAT = new Set(["t3", "mgr"]); // at most one participant each

interface SessionRow {
  id: string; company_id: string; difficulty: string; status: string; created_at: string;
  my_role: string | null; player_count: number; ready_count: number;
}
interface Member { user_id: string; display_name: string | null; handle: string | null; status: string }

const STATUS_STYLE: Record<string, string> = {
  lobby: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  running: "border-neon-green/40 bg-neon-green/10 text-neon-green",
  paused: "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
  ended: "border-slate-600 bg-slate-800/60 text-slate-400",
  debriefed: "border-slate-600 bg-slate-800/60 text-slate-400",
};

export default function TeamIndexPage() {
  usePageTitle("Team training");
  const router = useRouter();
  const { isPlatformAdmin, orgRole } = useOrgContext();
  const isStaff = isPlatformAdmin || orgRole === "org_admin" || orgRole === "instructor";

  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // builder state
  const [company, setCompany] = useState(COMPANY_PROFILES[0]?.id ?? "nexacorp");
  const [difficulty, setDifficulty] = useState<Diff>("medium");
  const [roster, setRoster] = useState<Member[]>([]);
  const [picked, setPicked] = useState<Record<string, string>>({}); // user_id -> role
  const [creating, setCreating] = useState(false);

  async function load() {
    setError(null);
    const res = await fetch("/api/team/sessions");
    setLoading(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    setSessions((await res.json()).sessions ?? []);
  }
  async function loadRoster() {
    const res = await fetch("/api/org/members");
    if (!res.ok) return;
    const data = await res.json();
    setRoster((data.members ?? []).filter((m: Member) => m.status === "active"));
  }
  useEffect(() => { load(); if (isStaff) loadRoster(); }, [isStaff]);

  function togglePick(userId: string) {
    setPicked(p => {
      const c = { ...p };
      if (c[userId]) delete c[userId]; else c[userId] = "t1";
      return c;
    });
  }

  // Enforce single-seat roles (T3, Manager): block a second assignment.
  function setRole(userId: string, role: string) {
    if (SINGLE_SEAT.has(role) && Object.entries(picked).some(([u, r]) => u !== userId && r === role)) {
      const lbl = PLAY_ROLES.find(r => r.id === role)?.label ?? role;
      setError(`${lbl} takes a single participant — it's already assigned.`);
      return;
    }
    setError(null);
    setPicked(p => ({ ...p, [userId]: role }));
  }

  async function createSession() {
    const invites = Object.entries(picked).map(([user_id, role]) => ({ user_id, role }));
    if (invites.length === 0) { setError("Invite at least one member to the exercise."); return; }
    setCreating(true); setError(null);
    const res = await fetch("/api/team/sessions", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ company_id: company, difficulty, invites }),
    });
    setCreating(false);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not create the session."); return; }
    router.push(`/team/${data.id}`);
  }

  const companyName = (id: string) => COMPANY_PROFILES.find(c => c.id === id)?.name ?? id;

  return (
    <div>
      <Topbar title="Team training" subtitle="Run a shared SOC incident with your team" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
            <AlertTriangle className="h-4 w-4" />{error}
          </div>
        )}

        {isStaff && (
          <Card>
            <h2 className="flex items-center gap-2 text-sm font-bold text-white">
              <Plus className="h-4 w-4 text-cyber-300" /> New team exercise
            </h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block text-xs uppercase tracking-wider text-slate-400">Company</span>
                <select value={company} onChange={e => setCompany(e.target.value)}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                  {COMPANY_PROFILES.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block text-xs uppercase tracking-wider text-slate-400">Difficulty</span>
                <select value={difficulty} onChange={e => setDifficulty(e.target.value as Diff)}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                  <option value="easy">Easy</option><option value="medium">Medium</option><option value="hard">Hard</option>
                </select>
              </label>
            </div>

            <div className="mt-4">
              <p className="mb-1 text-xs uppercase tracking-wider text-slate-400">Invite &amp; assign roles</p>
              <p className="mb-2 text-[11px] text-slate-500">Tier-1 &amp; Tier-2 can hold several analysts each · Tier-3 and SOC Manager are single-seat.</p>
              {roster.length === 0 ? (
                <p className="text-sm text-slate-400">No active members to invite. Add students to your class first.</p>
              ) : (
                <div className="space-y-1.5">
                  {roster.map(m => {
                    const on = !!picked[m.user_id];
                    return (
                      <div key={m.user_id} className={`flex items-center gap-3 rounded-lg border px-3 py-2 transition ${on ? "border-cyber-500/40 bg-cyber-500/[0.06]" : "border-border"}`}>
                        <input type="checkbox" checked={on} onChange={() => togglePick(m.user_id)} className="h-4 w-4 accent-cyber-500" />
                        <span className="min-w-0 flex-1 truncate text-sm text-slate-200">
                          {m.display_name || m.handle || m.user_id.slice(0, 8)}
                          {m.handle && <span className="ml-1 font-mono text-[11px] text-slate-500">@{m.handle}</span>}
                        </span>
                        <select value={picked[m.user_id] ?? "t1"} disabled={!on}
                          onChange={e => setRole(m.user_id, e.target.value)}
                          className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-slate-200 disabled:opacity-40 focus:border-cyber-500/50 focus:outline-none">
                          {PLAY_ROLES.map(r => <option key={r.id} value={r.id}>{r.label}{SINGLE_SEAT.has(r.id) ? " · 1 seat" : " · multi"}</option>)}
                        </select>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {Object.keys(picked).length > 0 && !Object.values(picked).includes("t1") && (
              <p className="mt-3 rounded-lg border border-neon-amber/30 bg-neon-amber/[0.06] px-3 py-2 text-[11px] text-neon-amber">
                ⚠ No Tier-1 assigned — with no analyst triaging the feed, nothing will get escalated. Add at least one Tier-1.
              </p>
            )}
            <div className="mt-4 flex items-center gap-3">
              <Button variant="primary" size="sm" disabled={creating || Object.keys(picked).length === 0} onClick={createSession}>
                {creating ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Plus className="mr-1.5 h-4 w-4" />}
                Create &amp; open lobby
              </Button>
              <span className="text-xs text-slate-500">You&apos;ll run it as instructor; invitees ready-up in the lobby.</span>
            </div>
          </Card>
        )}

        <Card className="overflow-hidden p-0">
          <div className="px-4 py-3">
            <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Your sessions</h2>
          </div>
          {loading ? (
            <div className="flex items-center gap-2 px-4 pb-4 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
          ) : sessions.length === 0 ? (
            <p className="px-4 pb-4 text-sm text-slate-400">No team sessions yet.{isStaff ? " Create one above." : " You'll see exercises here once your instructor invites you."}</p>
          ) : (
            <div className="divide-y divide-border/60">
              {sessions.map(s => {
                // Closed sessions (ended/debriefed) can't be entered — they're a
                // record only. Live/lobby/paused stay enterable.
                const closed = s.status === "ended" || s.status === "debriefed";
                const inner = (
                  <>
                    <span className={`rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${STATUS_STYLE[s.status] ?? STATUS_STYLE.ended}`}>
                      {s.status === "running" ? <span className="inline-flex items-center gap-1"><Radio className="h-2.5 w-2.5" />live</span> : closed ? "closed" : s.status}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className={`truncate text-sm font-medium ${closed ? "text-slate-400" : "text-white"}`}>{companyName(s.company_id)}</p>
                      <p className="font-mono text-[11px] text-slate-500">
                        {s.difficulty} · {s.ready_count}/{s.player_count} ready
                        {s.my_role && s.my_role !== "instructor" && <span className="ml-1 text-cyber-300">· you: {s.my_role}</span>}
                        {s.my_role === "instructor" && <span className="ml-1 text-neon-amber">· you: instructor</span>}
                      </p>
                    </div>
                    {closed
                      ? <Link href={`/team/${s.id}`} className="shrink-0 rounded-md border border-border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-cyber-300 hover:border-cyber-500/40 hover:bg-cyber-500/[0.06]">View report</Link>
                      : <ChevronRight className="h-4 w-4 text-slate-600" />}
                  </>
                );
                // Closed sessions aren't re-enterable as a live room, but the read-only
                // after-action report stays reachable via the explicit "View report" link.
                return closed ? (
                  <div key={s.id} title="This session is closed — open its report to review the debrief." className="flex items-center gap-3 px-4 py-3">{inner}</div>
                ) : (
                  <Link key={s.id} href={`/team/${s.id}`} className="flex items-center gap-3 px-4 py-3 transition hover:bg-white/[0.02]">{inner}</Link>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
