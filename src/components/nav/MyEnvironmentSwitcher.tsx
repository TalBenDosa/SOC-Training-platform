"use client";
/**
 * Multi-environment controls for a REGULAR user, next to "Team Training".
 *
 * The model (Tal): one access code per environment — a user who redeemed TWO codes
 * belongs to two environments. So:
 *   - "Join another environment" (→ /join, which redeems a code onto the signed-in
 *     account) is offered to every member, so a single-environment user can add one.
 *   - "Switch environment" appears ONLY once the user actually belongs to ≥2
 *     environments (redeemed ≥2 codes) — a single-environment student never sees it.
 *
 * The platform super-admin has their own cross-tenant switcher (EnvironmentSwitcher),
 * so this renders nothing for them.
 */
import { useEffect, useState } from "react";
import { ChevronsUpDown, Check, Loader2, Layers, Plus } from "lucide-react";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

interface Env { org_id: string; name: string; role: string; is_current: boolean }

export function MyEnvironmentSwitcher({ onNavigate }: { onNavigate?: () => void }) {
  const { isPlatformAdmin, orgRole, loading } = useOrgContext();
  const [envs, setEnvs] = useState<Env[] | null>(null);
  const [open, setOpen] = useState(false);
  const [switching, setSwitching] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Only org members (not guests / no-org) and not the super-admin.
  const eligible = !loading && !isPlatformAdmin && !!orgRole;
  useEffect(() => {
    if (!eligible || envs !== null) return;
    fetch("/api/account/environments")
      .then(r => (r.ok ? r.json() : null))
      .then(d => setEnvs(Array.isArray(d?.environments) ? d.environments : []))
      .catch(() => setEnvs([]));
  }, [eligible, envs]);

  if (!eligible || !envs || envs.length === 0) return null;

  const goJoin = () => { onNavigate?.(); window.location.href = "/join"; };

  // Single environment → just the way to add a second (enter another access code).
  if (envs.length < 2) {
    return (
      <button
        onClick={goJoin}
        className="mt-0.5 flex w-full items-center gap-2.5 rounded-md px-3 py-1.5 text-xs text-slate-400 transition-colors hover:bg-white/5 hover:text-white"
      >
        <Plus className="h-3.5 w-3.5 shrink-0" />
        <span>Join another environment</span>
      </button>
    );
  }

  const current = envs.find(e => e.is_current);
  async function switchTo(orgId: string) {
    if (switching) return;
    setSwitching(orgId);
    setError(null);
    try {
      const res = await fetch("/api/account/environments", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org_id: orgId }),
      });
      if (!res.ok) {
        setError((await res.json().catch(() => ({})))?.error ?? "Couldn't switch environment.");
        setSwitching(null);
        return;
      }
      // Org context lives in the JWT — refresh so the hook restamps the new active org,
      // then hard-reload so every consumer (content, progress, team) picks it up at once.
      await getSupabaseBrowserClient()?.auth.refreshSession();
      onNavigate?.();
      window.location.href = "/rooms";
    } catch {
      setError("Network error — couldn't switch environment.");
      setSwitching(null);
    }
  }

  return (
    <div className="mt-0.5">
      <button
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 rounded-md px-3 py-1.5 text-xs text-slate-400 transition-colors hover:bg-white/5 hover:text-white"
      >
        <Layers className="h-3.5 w-3.5 shrink-0" />
        <span className="min-w-0 flex-1 truncate text-left">Switch environment</span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 opacity-60" />
      </button>
      {open && (
        <div className="mt-1 space-y-0.5 rounded-md border border-border bg-bg-elevated p-1">
          {current && <p className="px-2 py-1 text-[10px] uppercase tracking-wide text-slate-500">You&apos;re in: {current.name}</p>}
          {envs.map(e => (
            <button
              key={e.org_id}
              onClick={() => (e.is_current ? setOpen(false) : switchTo(e.org_id))}
              disabled={!!switching}
              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs text-slate-200 transition hover:bg-white/5 disabled:opacity-60"
            >
              {switching === e.org_id
                ? <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                : e.is_current
                  ? <Check className="h-3.5 w-3.5 shrink-0 text-neon-green" />
                  : <span className="h-3.5 w-3.5 shrink-0" />}
              <span className="min-w-0 flex-1 truncate">{e.name}</span>
            </button>
          ))}
          {error && <p className="px-2 py-1 text-[10px] text-severity-high">{error}</p>}
          <button
            onClick={goJoin}
            className="flex w-full items-center gap-2 rounded border-t border-border/60 px-2 py-1.5 text-left text-xs text-cyber-300 transition hover:bg-white/5"
          >
            <Plus className="h-3.5 w-3.5 shrink-0" />
            <span>Join another environment</span>
          </button>
        </div>
      )}
    </div>
  );
}
