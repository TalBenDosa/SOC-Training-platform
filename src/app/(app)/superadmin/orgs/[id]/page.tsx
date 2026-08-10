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
  Copy, Check, Download, KeyRound, LogIn, ShieldCheck, Mail,
} from "lucide-react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
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

  // entering the environment (super-admin context switch)
  const [entering, setEntering] = useState(false);

  // invite a new org admin by email
  const [adminEmail, setAdminEmail] = useState("");
  const [invitingAdmin, setInvitingAdmin] = useState(false);
  const [adminInvite, setAdminInvite] = useState<{ email: string; link: string; emailed: boolean } | null>(null);
  const [adminCopied, setAdminCopied] = useState(false);

  async function enterEnvironment() {
    setError(null); setNotice(null); setEntering(true);
    const res = await fetch("/api/superadmin/enter-org", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org_id: id }),
    });
    if (!res.ok) {
      setEntering(false);
      setError((await res.json().catch(() => ({})))?.error ?? "Could not enter the environment.");
      return;
    }
    // The org claims live in the JWT — refresh the session so the access-token
    // hook restamps them for the NEW active org, then reload so every consumer
    // (nav, /manage, leaderboards) picks the new context up at once.
    const supabase = getSupabaseBrowserClient();
    await supabase?.auth.refreshSession();
    window.location.href = "/manage";
  }

  // enrollment — the org's affiliation code (0028/0029). Domains auto-join and
  // class links are gone: this code is the ONLY way a student enters this org.
  const [orgCode, setOrgCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [codeBusy, setCodeBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // branding
  const [brandColor, setBrandColor] = useState("#22d3ee");
  const [brandLogo, setBrandLogo] = useState("");

  // contract (commercial record — see migration 0020)
  const [cPlan, setCPlan] = useState("");
  const [cSeats, setCSeats] = useState("");
  const [cPrice, setCPrice] = useState("");
  const [cCurrency, setCCurrency] = useState("ILS");
  const [cPo, setCPo] = useState("");
  const [cSigned, setCSigned] = useState("");
  const [cNotes, setCNotes] = useState("");

  const [confirmName, setConfirmName] = useState("");

  async function load() {
    setError(null);
    const res = await fetch(`/api/superadmin/orgs/${id}`);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    const data = await res.json();
    setOrg(data.org); setMembers(data.members); setUsage(data.usage);
    setSeatLimit(String(data.org.seat_limit)); setExpiresAt(toDateInput(data.org.expires_at)); setStatus(data.org.status);
    const br = (data.org.branding ?? {}) as { color?: string; logo_url?: string };
    setBrandColor(br.color ?? "#22d3ee"); setBrandLogo(br.logo_url ?? "");
    const ct = (data.org.contract ?? {}) as {
      plan?: string; seats_purchased?: number; price?: number; currency?: string;
      po_number?: string; signed_at?: string; notes?: string;
    };
    setCPlan(ct.plan ?? "");
    setCSeats(ct.seats_purchased === undefined ? "" : String(ct.seats_purchased));
    setCPrice(ct.price === undefined ? "" : String(ct.price));
    setCCurrency(ct.currency ?? "ILS");
    setCPo(ct.po_number ?? "");
    setCSigned(toDateInput(ct.signed_at ?? null));
    setCNotes(ct.notes ?? "");
    // This org's live affiliation code (from the all-orgs endpoint).
    const codesRes = await fetch("/api/superadmin/org-codes");
    if (codesRes.ok) {
      const { orgs } = await codesRes.json();
      const mine = (orgs ?? []).find((o: { id: string }) => o.id === id);
      setOrgCode(mine?.active_code ?? null);
    }
  }

  async function generateOrgCode() {
    setError(null); setNotice(null); setCodeBusy(true);
    const res = await fetch("/api/superadmin/org-codes", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org_id: id }),
    });
    setCodeBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to generate a code."); return; }
    const data = await res.json();
    setOrgCode(data.active ?? null);
    setNotice("New affiliation code generated — valid for 24 hours.");
  }

  async function copyCode() {
    if (!orgCode) return;
    try { await navigator.clipboard.writeText(orgCode.code); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* clipboard blocked */ }
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

  async function inviteAdmin(e: React.FormEvent) {
    e.preventDefault();
    setInvitingAdmin(true); setError(null); setNotice(null); setAdminInvite(null);
    const res = await fetch(`/api/superadmin/orgs/${id}/invite-admin`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: adminEmail }),
    });
    setInvitingAdmin(false);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Failed to invite admin."); return; }
    // Surface the link (and whether the email actually went out) so it can be
    // sent by hand if Resend isn't configured yet.
    setAdminInvite({ email: adminEmail, link: data.adminLink, emailed: data.emailed });
    setAdminEmail("");
    setNotice(data.emailed ? `Invitation emailed to ${adminEmail}.` : `Invite created — email delivery is off, share the link below.`);
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
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link href="/superadmin" className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
            <ArrowLeft className="h-3.5 w-3.5" /> All organizations
          </Link>
          {/* Super-admin enters ANY environment: joins as org_admin (no seat
              cap, no affiliation clock — see /api/superadmin/enter-org) and
              switches active context to it. Entering B keeps membership in A,
              so environments accumulate rather than replace. */}
          <Button variant="outline" size="sm" disabled={entering} onClick={enterEnvironment}>
            <LogIn className="mr-1.5 h-4 w-4" />
            {entering ? "Entering…" : "Enter this environment"}
          </Button>
        </div>

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

            {/* Enrollment — the org's affiliation code, and ONLY that. The
                domain auto-join editor and the anonymous class link that used
                to live here described doors 0028/0029 removed: showing them
                would promise enrolment paths that no longer exist. */}
            <Card className="border-neon-cyan/30">
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-white">
                <KeyRound className="h-4 w-4 text-neon-cyan" /> Affiliation code
              </h2>
              <p className="mb-4 text-[11px] text-slate-400">
                This environment&apos;s own code — the only way a student joins it. The org admin
                shares it with their class; students register with email + code. Valid 24 hours;
                each enrolment lasts 100 days.
              </p>
              <div className="flex flex-wrap items-center gap-3">
                {orgCode ? (
                  <>
                    <span className="rounded-lg border border-neon-cyan/40 bg-neon-cyan/5 px-4 py-2 font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">
                      {orgCode.code}
                    </span>
                    <span className="text-xs text-slate-400">expires {new Date(orgCode.expires_at).toLocaleString()}</span>
                    <Button variant="outline" size="sm" onClick={copyCode} aria-label="Copy code">
                      {copied ? <Check className="h-4 w-4 text-neon-green" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </>
                ) : (
                  <span className="text-sm text-slate-400">No live code.</span>
                )}
                <Button variant="primary" size="sm" disabled={codeBusy} onClick={generateOrgCode}>
                  {codeBusy ? "Generating…" : "Generate code"}
                </Button>
              </div>
            </Card>

            {/* Branding */}
            <Card>
              <h2 className="mb-3 text-sm font-bold text-white">Branding</h2>
              <div className="flex flex-wrap items-end gap-3">
                <div>
                  <label className={label} htmlFor="b-color">Accent colour</label>
                  <input id="b-color" type="color" className="h-10 w-16 cursor-pointer rounded-md border border-border bg-bg" value={brandColor} onChange={e => setBrandColor(e.target.value)} />
                </div>
                <div className="flex-1 min-w-[220px]">
                  <label className={label} htmlFor="b-logo">Logo URL <span className="font-normal">(https)</span></label>
                  <input id="b-logo" className={field} value={brandLogo} onChange={e => setBrandLogo(e.target.value)} placeholder="https://college.ac.il/logo.png" />
                </div>
                <Button variant="outline" size="sm" disabled={saving}
                  onClick={() => patch({ branding: { color: brandColor, logo_url: brandLogo || undefined } }, "Branding updated.")}>
                  Save branding
                </Button>
              </div>
              <p className="mt-2 text-[11px] text-slate-400">Shown as a badge in the students&apos; top bar and on their certificates.</p>
            </Card>

            {/* Contract — what this college actually bought. A record, not a
                billing engine: it doesn't charge anyone or gate access (the
                licence fields above do that), it just stops the commercial
                terms living only in someone's memory. */}
            <Card>
              <h2 className="mb-1 text-sm font-bold text-white">Contract</h2>
              <p className="mb-3 text-[11px] text-slate-400">
                What was sold, for how much, under which PO. Does not affect access — seats and expiry are set in Licence above.
              </p>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div>
                  <label className={label} htmlFor="c-plan">Plan</label>
                  <input id="c-plan" className={field} value={cPlan} onChange={e => setCPlan(e.target.value)} placeholder="Pilot / Annual" />
                </div>
                <div>
                  <label className={label} htmlFor="c-seats">Seats purchased</label>
                  <input id="c-seats" type="number" min={0} className={field} value={cSeats} onChange={e => setCSeats(e.target.value)} placeholder="30" />
                </div>
                <div>
                  <label className={label} htmlFor="c-price">Price</label>
                  <div className="flex gap-1.5">
                    <input id="c-price" type="number" min={0} step="0.01" className={field} value={cPrice} onChange={e => setCPrice(e.target.value)} placeholder="12000" />
                    <input aria-label="Currency" className={`${field} w-20`} value={cCurrency} onChange={e => setCCurrency(e.target.value)} placeholder="ILS" />
                  </div>
                </div>
                <div>
                  <label className={label} htmlFor="c-po">PO / invoice no.</label>
                  <input id="c-po" className={field} value={cPo} onChange={e => setCPo(e.target.value)} placeholder="PO-2026-014" />
                </div>
                <div>
                  <label className={label} htmlFor="c-signed">Signed on</label>
                  <input id="c-signed" type="date" className={field} value={cSigned} onChange={e => setCSigned(e.target.value)} />
                </div>
              </div>
              <div className="mt-3">
                <label className={label} htmlFor="c-notes">Notes</label>
                <textarea id="c-notes" rows={2} value={cNotes} onChange={e => setCNotes(e.target.value)}
                  className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
                  placeholder="Renewal contact, agreed terms, anything the next conversation needs." />
              </div>
              <div className="mt-3 flex items-center gap-2">
                <Button variant="outline" size="sm" disabled={saving}
                  onClick={() => patch({ contract: {
                    plan: cPlan, seats_purchased: cSeats, price: cPrice, currency: cCurrency,
                    po_number: cPo, signed_at: cSigned, notes: cNotes,
                  } }, "Contract saved.")}>
                  Save contract
                </Button>
                <span className="text-[11px] text-slate-500">Visible to this college — keep internal-only notes elsewhere.</span>
              </div>
            </Card>

            {/* Invite a NEW org admin by email — the person who will run this
                college. They get a join link to their org's registration form,
                then the /manage dashboard. Distinct from "attach existing
                account" below, which only works once someone already signed up. */}
            <Card className="border-neon-purple/30">
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-white">
                <ShieldCheck className="h-4 w-4 text-neon-purple" /> Invite an org admin
              </h2>
              <p className="mb-3 text-[11px] text-slate-400">
                Sends an email invitation to run this college. The link opens their org&apos;s
                registration form; once registered they get the management dashboard and can
                generate the class code for students.
              </p>
              <form onSubmit={inviteAdmin} className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[220px]">
                  <label className={label} htmlFor="a-email">Admin email</label>
                  <input id="a-email" type="email" className={field} value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder="head.of.dept@college.ac.il" required />
                </div>
                <Button type="submit" variant="primary" size="sm" disabled={invitingAdmin}>
                  <Mail className="mr-1.5 h-4 w-4" /> {invitingAdmin ? "Sending…" : "Send invitation"}
                </Button>
              </form>
              {adminInvite && (
                <div className="mt-3 rounded-lg border border-border bg-bg-elevated px-3 py-2.5">
                  <p className="text-[11px] text-slate-400">
                    {adminInvite.emailed
                      ? <>Emailed to <span className="text-slate-200">{adminInvite.email}</span>. The link is also here:</>
                      : <>Email delivery is off on this deployment — <span className="text-neon-amber">send this link to {adminInvite.email} yourself</span>:</>}
                  </p>
                  <div className="mt-2 flex items-center gap-2">
                    <input readOnly value={adminInvite.link} onFocus={e => e.currentTarget.select()}
                      className={`${field} flex-1 font-mono text-[11px]`} aria-label="Admin invite link" />
                    <Button variant="outline" size="sm" onClick={() => { navigator.clipboard.writeText(adminInvite.link); setAdminCopied(true); setTimeout(() => setAdminCopied(false), 2000); }}>
                      {adminCopied ? <Check className="h-4 w-4 text-neon-green" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              )}
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

            {/* Offboard / danger */}
            <Card className="border-severity-high/30">
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-white">Offboarding</h2>
              <p className="mb-3 text-xs text-slate-400">Export the college&apos;s data before removing it, then hand them the file.</p>
              <a href={`/api/superadmin/orgs/${id}/export`} download
                className="mb-5 inline-flex items-center gap-2 rounded-lg border border-border bg-bg px-3.5 py-2 text-xs font-bold text-slate-200 transition hover:text-white">
                <Download className="h-4 w-4" /> Export data (JSON)
              </a>
              <h3 className="mb-1 flex items-center gap-2 text-sm font-bold text-severity-high"><Trash2 className="h-4 w-4" /> Delete organization</h3>
              <p className="mb-3 text-xs text-slate-400">Deletes the org and its learner data; accounts are re-homed as unaffiliated. Type <span className="font-mono text-white">{org.name}</span> to confirm.</p>
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
