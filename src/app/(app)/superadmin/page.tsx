"use client";
/**
 * Platform super-admin console — the organizations index. Lists every college
 * with seat usage and licence window, and provisions new environments. Gated by
 * middleware (platform-admin only) and by every API route's requireSuperAdmin;
 * this page renders nothing sensitive until those pass.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Building2, Plus, Users, CalendarClock, Loader2, AlertTriangle, ShieldCheck, Link2, Copy, Check, CheckCircle2, DollarSign } from "lucide-react";
import type { OrgSummary, OrgStatus } from "@/lib/org/types";

const STATUS_STYLE: Record<OrgStatus, string> = {
  active: "border-neon-green/30 bg-neon-green/10 text-neon-green",
  trial: "border-cyber-500/30 bg-cyber-500/10 text-cyber-300",
  suspended: "border-neon-amber/30 bg-neon-amber/10 text-neon-amber",
  expired: "border-severity-high/30 bg-severity-high/10 text-severity-high",
};

interface AiSpend { usd_30d: number; usd_7d: number; cap_30d: number }

function fmtUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

export default function SuperAdminPage() {
  usePageTitle("Super Admin");
  const [orgs, setOrgs] = useState<OrgSummary[] | null>(null);
  const [spend, setSpend] = useState<AiSpend | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function load() {
    setError(null);
    const res = await fetch("/api/superadmin/orgs");
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); setOrgs([]); return; }
    const body = await res.json();
    setOrgs(body.orgs);
    setSpend(body.ai_spend ?? null);
  }
  useEffect(() => { load(); }, []);

  return (
    <div>
      <Topbar title="Organizations" subtitle="Provision and manage college environments" />
      <div className="container mx-auto max-w-[1100px] px-6 py-6 space-y-6">
        <div className="flex items-center justify-between">
          <p className="flex items-center gap-2 text-sm text-slate-400">
            <ShieldCheck className="h-4 w-4 text-cyber-300" /> Platform super-admin
          </p>
          <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
            <Plus className="mr-1.5 h-4 w-4" /> New organization
          </Button>
        </div>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        {spend && (
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2.5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg">
                  <DollarSign className="h-4.5 w-4.5 text-cyber-300" />
                </span>
                <div>
                  <p className="text-sm font-bold text-white">AI spend</p>
                  <p className="text-[11px] text-slate-400">All tenants · estimated from token usage</p>
                </div>
              </div>
              <div className="flex items-center gap-6 tabular-nums">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Last 7 days</p>
                  <p className="text-lg font-bold text-white">{fmtUsd(spend.usd_7d)}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Last 30 days</p>
                  <p className={`text-lg font-bold ${spend.usd_30d >= spend.cap_30d ? "text-severity-high" : spend.usd_30d >= spend.cap_30d * 0.8 ? "text-neon-amber" : "text-white"}`}>
                    {fmtUsd(spend.usd_30d)}
                    <span className="ml-1 text-[11px] font-normal text-slate-400">/ {fmtUsd(spend.cap_30d)} cap</span>
                  </p>
                </div>
              </div>
            </div>
            {spend.usd_30d >= spend.cap_30d && (
              <p className="mt-3 flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-[12px] text-severity-high">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                Monthly cap reached — AI generation is serving deterministic fallbacks. Raise <code className="font-mono">AI_MONTHLY_CAP_USD</code> to resume.
              </p>
            )}
          </Card>
        )}

        {orgs === null ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : orgs.length === 0 && !error ? (
          <Card className="text-center text-sm text-slate-400">
            No organizations yet. Create the first college environment to get started.
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {orgs.map(o => (
              <Link key={o.id} href={`/superadmin/orgs/${o.id}`}>
                <Card className="h-full transition hover:border-cyber-500/50">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg">
                        <Building2 className="h-4.5 w-4.5 text-cyber-300" />
                      </span>
                      <div className="min-w-0">
                        <p className="truncate text-sm font-bold text-white">{o.name}</p>
                        <p className="truncate font-mono text-[11px] text-slate-400">/{o.slug}</p>
                      </div>
                    </div>
                    <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${STATUS_STYLE[o.status]}`}>
                      {o.status}
                    </span>
                  </div>
                  <div className="mt-4 flex items-center gap-4 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1">
                      <Users className="h-3.5 w-3.5" /> {o.seats_used}{o.seat_limit > 0 ? ` / ${o.seat_limit}` : " / ∞"} seats
                    </span>
                    <span className="flex items-center gap-1">
                      <CalendarClock className="h-3.5 w-3.5" /> {fmtDate(o.expires_at)}
                    </span>
                    {!o.active && <span className="font-bold text-severity-high">LOCKED</span>}
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </div>

      {creating && <CreateOrgModal onClose={() => setCreating(false)} onCreated={() => { setCreating(false); load(); }} />}
    </div>
  );
}

function CreateOrgModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [seatLimit, setSeatLimit] = useState("50");
  const [expiresAt, setExpiresAt] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // After creation we show the standing class invite link so it can be handed
  // to the college immediately.
  const [createdLink, setCreatedLink] = useState<string | null>(null);
  const [createdName, setCreatedName] = useState("");
  const [emailed, setEmailed] = useState(false);
  const [copied, setCopied] = useState(false);

  const autoSlug = (v: string) => v.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    const res = await fetch("/api/superadmin/orgs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, slug: slug || autoSlug(name), seat_limit: Number(seatLimit),
        expires_at: expiresAt || null, admin_email: adminEmail || undefined,
      }),
    });
    setSubmitting(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to create."); return; }
    const data = await res.json();
    setCreatedName(name);
    setCreatedLink(data.inviteLink ?? null);
    setEmailed(!!data.emailed);
    // don't close yet — surface the invite link first (onCreated on "Done").
  }

  async function copyLink() {
    if (!createdLink) return;
    try { await navigator.clipboard.writeText(createdLink); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* blocked */ }
  }

  const field = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";
  const label = "mb-1.5 block text-xs font-semibold text-slate-400";

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onClick={onClose}>
      <Card className="w-full max-w-md" >
        <div onClick={e => e.stopPropagation()}>
          {createdLink ? (
            <div>
              <div className="mb-3 flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-neon-green" />
                <h2 className="text-lg font-bold text-white">{createdName} is ready</h2>
              </div>
              <p className="mb-3 text-sm text-slate-400">
                Share this class invite link with the college — anyone who opens it creates an account inside their environment.
              </p>
              <div className="flex items-center gap-2">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-cyber-500/30 bg-cyber-500/10">
                  <Link2 className="h-4 w-4 text-cyber-300" />
                </span>
                <input readOnly value={createdLink} onFocus={e => e.currentTarget.select()}
                  className="h-10 flex-1 rounded-md border border-border bg-bg px-3 font-mono text-[11px] text-white focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30" aria-label="Class invite link" />
                <Button type="button" variant="outline" size="sm" onClick={copyLink}>
                  {copied ? <Check className="h-4 w-4 text-neon-green" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
              {emailed && (
                <p className="mt-2 flex items-center gap-1.5 text-[11px] text-neon-green">
                  <Check className="h-3.5 w-3.5" /> We emailed these links to {adminEmail}.
                </p>
              )}
              <p className="mt-2 text-[11px] text-slate-400">The link is also always available on the organization page. The regular signup form still works for everyone else.</p>
              <div className="mt-5 flex justify-end">
                <Button type="button" variant="primary" size="sm" onClick={onCreated}>Done</Button>
              </div>
            </div>
          ) : (
          <>
          <h2 className="mb-4 text-lg font-bold text-white">New organization</h2>
          <form onSubmit={submit} className="space-y-3">
            <div>
              <label className={label} htmlFor="org-name">College name</label>
              <input id="org-name" className={field} value={name} required
                onChange={e => { setName(e.target.value); if (!slug) setSlug(autoSlug(e.target.value)); }}
                placeholder="e.g. Sapir College" />
            </div>
            <div>
              <label className={label} htmlFor="org-slug">Slug</label>
              <input id="org-slug" className={field} value={slug} onChange={e => setSlug(autoSlug(e.target.value))} placeholder="sapir-college" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={label} htmlFor="org-seats">Seat limit</label>
                <input id="org-seats" type="number" min={0} className={field} value={seatLimit} onChange={e => setSeatLimit(e.target.value)} />
              </div>
              <div>
                <label className={label} htmlFor="org-expiry">Expires</label>
                <input id="org-expiry" type="date" className={field} value={expiresAt} onChange={e => setExpiresAt(e.target.value)} />
              </div>
            </div>
            <div>
              <label className={label} htmlFor="org-admin">Org-admin email <span className="font-normal">(optional — invited)</span></label>
              <input id="org-admin" type="email" className={field} value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder="admin@college.ac.il" />
            </div>
            {error && <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
              <Button type="submit" variant="primary" size="sm" disabled={submitting}>
                {submitting ? "Creating…" : "Create"}
              </Button>
            </div>
          </form>
          </>
          )}
        </div>
      </Card>
    </div>
  );
}
