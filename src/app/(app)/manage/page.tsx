"use client";
/**
 * Org-admin console — a college's own dashboard. Scoped entirely to the admin's
 * org by the /api/org/* routes (org id comes from their JWT, never the client),
 * so a college admin sees and touches only their own students.
 */
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  Users, Trophy, Activity, Target, DoorOpen, UserPlus, X, Link2, Copy, Check, AlertTriangle, Loader2,
} from "lucide-react";
import type { OrgMember, OrgUsage } from "@/lib/org/types";

interface OrgLite { id: string; name: string; slug: string; seat_limit: number; status: string; expires_at: string | null }
type Member = OrgMember & { xp?: number };

export default function ManagePage() {
  usePageTitle("Manage class");
  const [org, setOrg] = useState<OrgLite | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [usage, setUsage] = useState<OrgUsage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [email, setEmail] = useState("");
  const [adding, setAdding] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    setError(null);
    const res = await fetch("/api/org/members");
    setLoading(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    const data = await res.json();
    setOrg(data.org); setMembers(data.members); setUsage(data.usage);
    // Surface the standing class invite link (created with the org) so it's
    // ready to share without pressing "Generate".
    const invRes = await fetch("/api/org/invites");
    if (invRes.ok) {
      const { invites } = await invRes.json();
      const primary = (invites ?? []).find(
        (i: { email: string | null; role: string; accepted_at: string | null; expires_at: string; link: string }) =>
          !i.email && i.role === "student" && !i.accepted_at && new Date(i.expires_at) > new Date(),
      );
      if (primary) setInviteLink(primary.link);
    }
  }
  useEffect(() => { load(); }, []);

  async function addMember(e: React.FormEvent) {
    e.preventDefault(); setAdding(true); setError(null); setNotice(null);
    const res = await fetch("/api/org/members", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, role: "student" }),
    });
    setAdding(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to add."); return; }
    setEmail(""); setNotice(`Added ${email}.`); await load();
  }

  async function removeMember(userId: string) {
    const res = await fetch("/api/org/members", {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to remove."); return; }
    await load();
  }

  async function makeInvite() {
    setError(null); setInviteLink(null);
    const res = await fetch("/api/org/invites", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: "student" }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to create invite."); return; }
    setInviteLink((await res.json()).invites?.[0]?.link ?? null);
  }
  async function copyInvite() {
    if (!inviteLink) return;
    try { await navigator.clipboard.writeText(inviteLink); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* blocked */ }
  }

  const field = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";
  const active = members.filter(m => m.status === "active");
  const roster = [...members].sort((a, b) => (b.xp ?? 0) - (a.xp ?? 0));

  return (
    <div>
      <Topbar title={org ? `Manage — ${org.name}` : "Manage class"} subtitle="Your students and their progress" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {notice && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{notice}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat icon={<Users className="h-4 w-4" />} label="Students" value={`${active.length}${org && org.seat_limit > 0 ? `/${org.seat_limit}` : ""}`} />
              <Stat icon={<Trophy className="h-4 w-4" />} label="Total XP" value={(usage?.total_xp ?? 0).toLocaleString()} />
              <Stat icon={<Activity className="h-4 w-4" />} label="Sessions" value={String(usage?.sessions ?? 0)} />
              <Stat icon={<Target className="h-4 w-4" />} label="Scenarios" value={String(usage?.scenarios_completed ?? 0)} />
              <Stat icon={<DoorOpen className="h-4 w-4" />} label="Rooms" value={String(usage?.rooms_completed ?? 0)} />
            </div>

            <Card>
              <h2 className="mb-3 text-sm font-bold text-white">Invite students</h2>
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="outline" size="sm" onClick={makeInvite}><Link2 className="mr-1.5 h-4 w-4" /> Generate class link</Button>
                {inviteLink && (
                  <>
                    <input readOnly value={inviteLink} className={`${field} max-w-sm font-mono text-[11px]`} aria-label="Invite link" onFocus={e => e.currentTarget.select()} />
                    <Button variant="outline" size="sm" onClick={copyInvite}>{copied ? <Check className="h-4 w-4 text-neon-green" /> : <Copy className="h-4 w-4" />}</Button>
                  </>
                )}
              </div>
              <form onSubmit={addMember} className="mt-4 flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[220px]">
                  <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="mg-email">Or attach an existing account by email</label>
                  <input id="mg-email" type="email" className={field} value={email} onChange={e => setEmail(e.target.value)} placeholder="student@college.ac.il" required />
                </div>
                <Button type="submit" variant="primary" size="sm" disabled={adding}><UserPlus className="mr-1.5 h-4 w-4" />{adding ? "Adding…" : "Add"}</Button>
              </form>
            </Card>

            <Card>
              <h2 className="mb-3 text-sm font-bold text-white">Roster ({active.length})</h2>
              {roster.length === 0 ? (
                <p className="text-sm text-slate-400">No students yet. Share your class link to get started.</p>
              ) : (
                <div className="divide-y divide-border/60">
                  {roster.map((m, i) => (
                    <div key={m.user_id} className="flex items-center justify-between gap-3 py-2.5">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="w-5 shrink-0 text-center font-mono text-[11px] text-slate-500">{i + 1}</span>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-white">{m.display_name || m.handle || m.user_id.slice(0, 8)}</p>
                          <p className="truncate font-mono text-[11px] text-slate-400">{m.handle ? `@${m.handle}` : ""} · {m.role}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs font-bold text-cyber-300">{(m.xp ?? 0).toLocaleString()} XP</span>
                        <button onClick={() => removeMember(m.user_id)} aria-label={`Remove ${m.handle ?? "student"}`}
                          className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high"><X className="h-4 w-4" /></button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <Card className="py-3">
      <div className="flex items-center gap-1.5 text-slate-400">{icon}<span className="text-[10px] uppercase tracking-wider">{label}</span></div>
      <p className="mt-1 font-mono text-lg font-bold text-white">{value}</p>
    </Card>
  );
}
