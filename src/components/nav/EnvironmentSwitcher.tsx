"use client";
/**
 * Super-admin environment switcher (sidebar). The platform owner is present in
 * every environment and moves between them freely; before this, switching meant
 * going to /superadmin/orgs/[id] and clicking "Enter this environment" for each
 * one. This shows the ACTIVE environment and a one-click list of the others the
 * super-admin has entered.
 *
 * Only rendered for platform admins (claim-gated); the real cross-tenant
 * authority is enforced server-side by requireSuperAdmin on the routes it calls.
 */
import { useEffect, useState } from "react";
import { Check, ChevronsUpDown, Loader2, Layers } from "lucide-react";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

interface Env { id: string; name: string; slug: string }

export function EnvironmentSwitcher({ onNavigate }: { onNavigate?: () => void }) {
  const { isPlatformAdmin, orgId, orgName, loading: claimLoading } = useOrgContext();
  const [open, setOpen] = useState(false);
  const [envs, setEnvs] = useState<Env[] | null>(null);
  const [switching, setSwitching] = useState<string | null>(null);

  useEffect(() => {
    if (!isPlatformAdmin || !open || envs !== null) return;
    fetch("/api/superadmin/my-environments")
      .then(r => (r.ok ? r.json() : { environments: [] }))
      .then(d => setEnvs(d.environments ?? []))
      .catch(() => setEnvs([]));
  }, [isPlatformAdmin, open, envs]);

  if (claimLoading || !isPlatformAdmin) return null;

  async function switchTo(id: string) {
    if (id === orgId) { setOpen(false); return; }
    setSwitching(id);
    const res = await fetch("/api/superadmin/enter-org", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org_id: id }),
    });
    if (!res.ok) { setSwitching(null); return; }
    // Org claims live in the JWT — refresh so the access-token hook restamps the
    // new active org, then hard-reload so every consumer picks it up at once.
    const supabase = getSupabaseBrowserClient();
    await supabase?.auth.refreshSession();
    onNavigate?.();
    window.location.href = "/manage";
  }

  return (
    <div className="mt-2 px-1">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-2 rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-left text-xs text-slate-200 transition hover:border-cyber-500/50"
        aria-expanded={open}
        aria-label="Switch environment"
      >
        <Layers className="h-3.5 w-3.5 shrink-0 text-cyber-300" />
        <span className="min-w-0 flex-1">
          <span className="block text-[9px] uppercase tracking-wider text-slate-500">Environment</span>
          <span className="block truncate font-medium">{orgName ?? "—"}</span>
        </span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-slate-500" />
      </button>

      {open && (
        <div className="mt-1 overflow-hidden rounded-md border border-border bg-bg">
          {envs === null ? (
            <div className="flex items-center gap-2 px-2.5 py-2 text-[11px] text-slate-400">
              <Loader2 className="h-3 w-3 animate-spin" /> Loading…
            </div>
          ) : envs.length === 0 ? (
            <div className="px-2.5 py-2 text-[11px] text-slate-500">No environments yet.</div>
          ) : (
            envs.map(e => (
              <button
                key={e.id}
                onClick={() => switchTo(e.id)}
                disabled={switching !== null}
                className={`flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[11px] transition hover:bg-white/5 ${e.id === orgId ? "text-cyber-300" : "text-slate-300"}`}
              >
                <span className="w-3.5 shrink-0">
                  {switching === e.id ? <Loader2 className="h-3 w-3 animate-spin" /> : e.id === orgId ? <Check className="h-3 w-3" /> : null}
                </span>
                <span className="truncate">{e.name}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}
