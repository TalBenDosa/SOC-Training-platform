"use client";
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { KeyRound, Mail, Copy, Check, AlertTriangle, RefreshCw } from "lucide-react";
import { safeFetch, NETWORK_ERROR } from "@/lib/http/safeFetch";

interface PendingInvite { id: string; email: string | null; role: string; created_at: string; expires_at: string; expired: boolean }
interface StaffAccount { user_id: string; role: string; name: string; email: string | null; last_sign_in_at: string | null; joined_at: string | null }
type SendState = { busy?: boolean; ok?: boolean; status?: string; message?: string; link?: string };

const DAY = 86_400_000;
function ago(iso: string | null): string {
  if (!iso) return "never";
  const d = Math.floor((Date.now() - Date.parse(iso)) / DAY);
  return d <= 0 ? "today" : d === 1 ? "yesterday" : `${d} days ago`;
}
function untilLabel(iso: string): string {
  const d = Math.ceil((Date.parse(iso) - Date.now()) / DAY);
  return d <= 0 ? `expired ${ago(iso)}` : d === 1 ? "expires tomorrow" : `expires in ${d} days`;
}
const ROLE: Record<string, string> = { org_admin: "Org admin", instructor: "Instructor" };

/**
 * Has this college's admin actually got in? Unused staff invitations (resend —
 * an expired one is renewed) and registered admins with their last sign-in
 * (send a sign-in email). Built for the environment whose admin never signed in.
 */
export function AdminAccessCard({ orgId, refreshKey }: { orgId: string; refreshKey: number }) {
  const [invites, setInvites] = useState<PendingInvite[] | null>(null);
  const [admins, setAdmins] = useState<StaffAccount[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [send, setSend] = useState<Record<string, SendState>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let alive = true;
    setError(null);
    safeFetch(`/api/superadmin/orgs/${orgId}/admin-access`).then(async res => {
      if (!alive) return;
      if (!res) { setError(NETWORK_ERROR); return; }
      const d = await res.json().catch(() => ({}));
      if (!res.ok) { setError(d?.error ?? "Couldn't load admin access."); return; }
      setInvites(d.invites ?? []); setAdmins(d.admins ?? []);
    });
    return () => { alive = false; };
  }, [orgId, refreshKey, reload]);

  async function post(key: string, url: string) {
    setSend(s => ({ ...s, [key]: { busy: true } }));
    const res = await safeFetch(url, { method: "POST" });
    if (!res) { setSend(s => ({ ...s, [key]: { ok: false, message: NETWORK_ERROR } })); return; }
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { setSend(s => ({ ...s, [key]: { ok: false, message: d?.error ?? "Couldn't send." } })); return; }
    const message = d.email_status === "sent"
      ? `Sent to ${d.email ?? "the invitee"}${d.renewed ? " — the expired link was renewed for 14 days" : ""}.`
      : d.email_status === "rejected"
        ? "The email provider rejected this recipient — share the link yourself."
        : "Email isn't configured on this deployment — share the link yourself.";
    setSend(s => ({ ...s, [key]: { ok: d.email_status === "sent", status: d.email_status, message, link: d.link } }));
    if (d.renewed) setReload(r => r + 1);   // show the new expiry
  }

  const loading = invites === null || admins === null;
  const signedIn = (admins ?? []).filter(a => a.role === "org_admin" && a.last_sign_in_at);
  const nobodyIn = !loading && signedIn.length === 0;

  const Result = ({ k }: { k: string }) => {
    const st = send[k];
    if (!st || st.busy) return null;
    return (
      <div className={`mt-1.5 rounded border px-2 py-1.5 text-[11px] ${st.ok ? "border-neon-green/30 bg-neon-green/[0.06] text-neon-green" : "border-neon-amber/30 bg-neon-amber/[0.06] text-neon-amber"}`} role="status">
        {st.message}
        {!st.ok && st.link && (
          <div className="mt-1.5 flex items-center gap-2">
            <input readOnly value={st.link} onFocus={e => e.currentTarget.select()} aria-label="Invitation link"
              className="min-w-0 flex-1 rounded border border-border bg-bg px-2 py-1 font-mono text-[10px] text-slate-300" />
            <button type="button" aria-label="Copy invitation link"
              onClick={() => { navigator.clipboard?.writeText(st.link!).then(() => { setCopied(k); setTimeout(() => setCopied(null), 2000); }).catch(() => {}); }}
              className="rounded p-1 text-slate-300 hover:bg-white/5">
              {copied === k ? <Check className="h-3.5 w-3.5 text-neon-green" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        )}
      </div>
    );
  };

  return (
    <Card className={nobodyIn ? "border-neon-amber/40" : undefined}>
      <div className="mb-1 flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><KeyRound className="h-4 w-4 text-neon-purple" /> Admin access</h2>
        <button type="button" onClick={() => setReload(r => r + 1)} aria-label="Refresh admin access" className="rounded p-1 text-slate-400 hover:bg-white/5 hover:text-slate-200"><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>
      <p className="mb-3 text-[11px] text-slate-400">Has the person running this college actually got in? Resend an invitation that was never used, or email a sign-in link to an admin who has an account.</p>

      {error && <p className="text-[12px] text-severity-high">{error}</p>}
      {loading && !error && <p className="text-[12px] text-slate-400">Loading…</p>}

      {nobodyIn && !error && (
        <p className="mb-3 flex items-center gap-1.5 rounded border border-neon-amber/40 bg-neon-amber/10 px-2.5 py-1.5 text-[12px] text-neon-amber">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> No org admin has signed in to this environment yet.
        </p>
      )}

      {!loading && (invites ?? []).length > 0 && (
        <div className="mb-3">
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Invitations not used yet</p>
          <div className="space-y-2">
            {invites!.map(inv => (
              <div key={inv.id} className="rounded-lg border border-border/60 bg-bg px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[12px] text-slate-200">{inv.email ?? "generic link (no recipient)"}</p>
                    <p className="text-[10px] text-slate-500">
                      {ROLE[inv.role] ?? inv.role} · sent {ago(inv.created_at)} ·{" "}
                      <span className={inv.expired ? "text-severity-high" : "text-slate-400"}>{untilLabel(inv.expires_at)}</span>
                    </p>
                  </div>
                  {inv.email && (
                    <Button variant="outline" size="sm" disabled={!!send[inv.id]?.busy}
                      onClick={() => post(inv.id, `/api/superadmin/orgs/${orgId}/invites/${inv.id}/resend`)}>
                      <Mail className="mr-1.5 h-3.5 w-3.5" /> {send[inv.id]?.busy ? "Sending…" : inv.expired ? "Renew & resend" : "Resend invitation"}
                    </Button>
                  )}
                </div>
                <Result k={inv.id} />
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && (admins ?? []).length > 0 && (
        <div>
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Registered admins &amp; instructors</p>
          <div className="space-y-2">
            {admins!.map(a => (
              <div key={a.user_id} className="rounded-lg border border-border/60 bg-bg px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[12px] font-medium text-white">{a.name} <span className="font-mono text-[11px] font-normal text-slate-400">{a.email ?? ""}</span></p>
                    <p className="text-[10px] text-slate-500">
                      {ROLE[a.role] ?? a.role} · last sign-in:{" "}
                      <span className={!a.last_sign_in_at ? "text-neon-amber" : Date.now() - Date.parse(a.last_sign_in_at) > 14 * DAY ? "text-neon-amber" : "text-slate-400"}>{ago(a.last_sign_in_at)}</span>
                    </p>
                  </div>
                  <Button variant="outline" size="sm" disabled={!!send[a.user_id]?.busy}
                    onClick={() => post(a.user_id, `/api/superadmin/orgs/${orgId}/members/${a.user_id}/sign-in-email`)}>
                    <Mail className="mr-1.5 h-3.5 w-3.5" /> {send[a.user_id]?.busy ? "Sending…" : "Send sign-in email"}
                  </Button>
                </div>
                <Result k={a.user_id} />
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && !error && (invites ?? []).length === 0 && (admins ?? []).length === 0 && (
        <p className="text-[12px] text-slate-400">No admin invited yet — use “Invite an org admin” below.</p>
      )}
    </Card>
  );
}
