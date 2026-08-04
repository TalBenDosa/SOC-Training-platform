"use client";
/**
 * Super-admin — single organization: licence controls (seats, dates, status),
 * cohort usage, member management, and a guarded delete. Every mutation goes to
 * a requireSuperAdmin-gated API route.
 */
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  ArrowLeft, Loader2, Users, Trophy, Activity, Target, DoorOpen, Trash2, UserPlus, X, AlertTriangle,
} from "lucide-react";
import type { Organization, OrgMember, OrgUsage, OrgStatus, OrgRole } from "@/lib/org/types";

function toDateInput(iso: string | null): string {
  return iso ? new Date(iso).toISOString().slice(0, 10) : "";
}

export default function OrgDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  usePageTitle("Organization");

  const [org, setOrg] = useState<Organization | null>(null);
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [usage, setUsage] = useState<OrgUsage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // license form
  const [seatLimit, setSeatLimit] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [status, setStatus] = useState<OrgStatus>("active");
  const [saving, setSaving] = useState(false);

  // add member
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<OrgRole>("student");
  const [adding, setAdding] = useState(false);

  const [confirmName, setConfirmName] = useState("");

  async function load() {
    setError(null);
    const res = await fetch(`/api/superadmin/orgs/${id}`);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    const data = await res.json();
    setOrg(data.org); setMembers(data.members); setUsage(data.usage);
    setSeatLimit(String(data.org.seat_limit)); setExpiresAt(toDateInput(data.org.expires_at)); setStatus(data.org.status);
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  async function patch(body: Record<string, unknown>, msg: string) {
    setSaving(true); setError(null); setNotice(null);
    const res = await fetch(`/api/superadmin/orgs/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    setSaving(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Update failed."); return; }
    setNotice(msg); await load();
  }

  async function addMember(e: React.FormEvent) {
    e.preventDefault();
    setAdding(true); setError(null); setNotice(null);
    const res = await fetch(`/api/superadmin/orgs/${id}/members`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, role }),
    });
    setAdding(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to add member."); return; }
    setEmail(""); setNotice(`Added ${email}.`); await load();
  }

  async function removeMember(userId: string) {
    const res = await fetch(`/api/superadmin/orgs/${id}/members`, {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to remove."); return; }
    await load();
  }

  async function deleteOrg() {
    const res = await fetch(`/api/superadmin/orgs/${id}`, { method: "DELETE" });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Delete failed."); return; }
    router.push("/superadmin");
  }

  const field = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";
  const label = "mb-1.5 block text-xs font-semibold text-slate-400";
  const activeMembers = members.filter(m => m.status === "active");

  return (
    <div>
      <Topbar title={org?.name ?? "Organization"} subtitle={org ? `/${org.slug}` : ""} />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        <Link href="/superadmin" className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
          <ArrowLeft className="h-3.5 w-3.5" /> All organizations
        </Link>

        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {notice && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{notice}</div>}

        {!org ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {/* Usage */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat icon={<Users className="h-4 w-4" />} label="Members" value={`${activeMembers.length}${org.seat_limit > 0 ? `/${org.seat_limit}` : ""}`} />
              <Stat icon={<Trophy className="h-4 w-4" />} label="Total XP" value={(usage?.total_xp ?? 0).toLocaleString()} />
              <Stat icon={<Activity className="h-4 w-4" />} label="Sessions" value={String(usage?.sessions ?? 0)} />
              <Stat icon={<Target className="h-4 w-4" />} label="Scenarios" value={String(usage?.scenarios_completed ?? 0)} />
              <Stat icon={<DoorOpen className="h-4 w-4" />} label="Rooms" value={String(usage?.rooms_completed ?? 0)} />
            </div>

            {/* License */}
            <Card>
              <h2 className="mb-4 text-sm font-bold text-white">Licence</h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label className={label} htmlFor="l-seats">Seat limit (0 = ∞)</label>
                  <input id="l-seats" type="number" min={0} className={field} value={seatLimit} onChange={e => setSeatLimit(e.target.value)} />
                </div>
                <div>
                  <label className={label} htmlFor="l-exp">Expires</label>
                  <input id="l-exp" type="date" className={field} value={expiresAt} onChange={e => setExpiresAt(e.target.value)} />
                </div>
                <div>
                  <label className={label} htmlFor="l-status">Status</label>
                  <select id="l-status" className={field} value={status} onChange={e => setStatus(e.target.value as OrgStatus)}>
                    <option value="active">active</option>
                    <option value="trial">trial</option>
                    <option value="suspended">suspended</option>
                    <option value="expired">expired</option>
                  </select>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="primary" size="sm" disabled={saving}
                  onClick={() => patch({ seat_limit: Number(seatLimit), expires_at: expiresAt || null, status }, "Licence updated.")}>
                  {saving ? "Saving…" : "Save licence"}
                </Button>
                {org.status !== "suspended"
                  ? <Button variant="outline" size="sm" onClick={() => patch({ status: "suspended" }, "Suspended.")}>Suspend</Button>
                  : <Button variant="outline" size="sm" onClick={() => patch({ status: "active" }, "Reactivated.")}>Reactivate</Button>}
              </div>
            </Card>

            {/* Members */}
            <Card>
              <h2 className="mb-3 text-sm font-bold text-white">Members ({activeMembers.length})</h2>
              <form onSubmit={addMember} className="mb-4 flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[200px]">
                  <label className={label} htmlFor="m-email">Attach existing account by email</label>
                  <input id="m-email" type="email" className={field} value={email} onChange={e => setEmail(e.target.value)} placeholder="student@college.ac.il" required />
                </div>
                <select className={`${field} w-auto`} value={role} onChange={e => setRole(e.target.value as OrgRole)} aria-label="Role">
                  <option value="student">student</option>
                  <option value="instructor">instructor</option>
                  <option value="org_admin">org_admin</option>
                </select>
                <Button type="submit" variant="primary" size="sm" disabled={adding}>
                  <UserPlus className="mr-1.5 h-4 w-4" /> {adding ? "Adding…" : "Add"}
                </Button>
              </form>
              {members.length === 0 ? (
                <p className="text-sm text-slate-400">No members yet.</p>
              ) : (
                <div className="divide-y divide-border/60">
                  {members.map(m => (
                    <div key={m.user_id} className="flex items-center justify-between py-2.5">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-white">{m.display_name || m.handle || m.user_id.slice(0, 8)}</p>
                        <p className="truncate font-mono text-[11px] text-slate-400">{m.handle ? `@${m.handle}` : ""} · {m.role}{m.status !== "active" ? ` · ${m.status}` : ""}</p>
                      </div>
                      <button onClick={() => removeMember(m.user_id)} aria-label={`Remove ${m.handle ?? "member"}`}
                        className="shrink-0 rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high">
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Danger */}
            <Card className="border-severity-high/30">
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-severity-high"><Trash2 className="h-4 w-4" /> Delete organization</h2>
              <p className="mb-3 text-xs text-slate-400">Permanently removes the org and its memberships. Type <span className="font-mono text-white">{org.name}</span> to confirm.</p>
              <div className="flex flex-wrap items-center gap-2">
                <input className={`${field} max-w-xs`} value={confirmName} onChange={e => setConfirmName(e.target.value)} placeholder={org.name} aria-label="Confirm org name" />
                <Button variant="outline" size="sm" disabled={confirmName !== org.name} onClick={deleteOrg}
                  className="border-severity-high/40 text-severity-high hover:bg-severity-high/10">
                  Delete permanently
                </Button>
              </div>
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
