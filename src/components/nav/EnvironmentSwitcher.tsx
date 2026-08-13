"use client";
/**
 * Super-admin environment switcher (sidebar) — a TWO-LEVEL TREE, not a flat list.
 *
 *   Main environment (root)  — the super-admin's home / control tower. Pinned at
 *                              the top; selecting it is "return to Main".
 *   Client environments      — every college the super-admin has entered, listed
 *                              beneath the root, each one click to enter.
 *
 * The header shows where you are standing right now (Main, or a specific
 * college). Only rendered for platform admins (claim-gated); the real
 * cross-tenant authority is enforced server-side by requireSuperAdmin on the
 * routes it calls.
 */
import { useEffect, useState } from "react";
import { Check, ChevronsUpDown, Loader2, Home, Layers } from "lucide-react";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { ROOT_ORG_ID, ROOT_ENVIRONMENT_LABEL } from "@/lib/org/rootEnvironment";

interface Env { id: string; name: string; slug: string }
interface Root { id: string; name: string; org_name: string; slug: string }
interface Tree { root: Root; children: Env[]; current_org_id: string | null; at_root: boolean }

export function EnvironmentSwitcher({ onNavigate }: { onNavigate?: () => void }) {
  const { isPlatformAdmin, orgId, orgName, loading: claimLoading } = useOrgContext();
  const [open, setOpen] = useState(false);
  const [tree, setTree] = useState<Tree | null>(null);
  const [switching, setSwitching] = useState<string | null>(null);

  useEffect(() => {
    if (!isPlatformAdmin || !open || tree !== null) return;
    fetch("/api/superadmin/my-environments")
      .then(r => (r.ok ? r.json() : null))
      .then(d => setTree(d))
      .catch(() => setTree(null));
  }, [isPlatformAdmin, open, tree]);

  if (claimLoading || !isPlatformAdmin) return null;

  const atRoot = orgId === ROOT_ORG_ID;
  const headerLabel = atRoot ? ROOT_ENVIRONMENT_LABEL : (orgName ?? "—");

  async function switchTo(id: string, isRoot: boolean) {
    if (id === orgId) { setOpen(false); return; }
    setSwitching(id);
    const res = await fetch("/api/superadmin/enter-org", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org_id: id }),
    });
    if (!res.ok) { setSwitching(null); return; }
    // Org claims live in the JWT — refresh so the access-token hook restamps the
    // new active org, then hard-reload so every consumer picks it up at once.
    // Entering the root lands on the control tower (/superadmin); entering a
    // client lands on that college's console (/manage).
    const supabase = getSupabaseBrowserClient();
    await supabase?.auth.refreshSession();
    onNavigate?.();
    window.location.href = isRoot ? "/superadmin" : "/manage";
  }

  return (
    <div className="mt-2 px-1">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-2 rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-left text-xs text-slate-200 transition hover:border-cyber-500/50"
        aria-expanded={open}
        aria-label="Switch environment"
      >
        {atRoot ? <Home className="h-3.5 w-3.5 shrink-0 text-amber-300" /> : <Layers className="h-3.5 w-3.5 shrink-0 text-cyber-300" />}
        <span className="min-w-0 flex-1">
          <span className="block text-[9px] uppercase tracking-wider text-slate-500">
            {atRoot ? "You are at the root" : "Inside environment"}
          </span>
          <span className="block truncate font-medium">{headerLabel}</span>
        </span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-slate-500" />
      </button>

      {open && (
        <div className="mt-1 overflow-hidden rounded-md border border-border bg-bg">
          {tree === null ? (
            <div className="flex items-center gap-2 px-2.5 py-2 text-[11px] text-slate-400">
              <Loader2 className="h-3 w-3 animate-spin" /> Loading…
            </div>
          ) : (
            <>
              {/* Root — the Main environment, always pinned at the top. */}
              <button
                onClick={() => switchTo(tree.root.id, true)}
                disabled={switching !== null}
                className={`flex w-full items-center gap-2 border-b border-border px-2.5 py-2 text-left text-[11px] transition hover:bg-white/5 ${atRoot ? "text-amber-300" : "text-slate-200"}`}
              >
                <span className="w-3.5 shrink-0">
                  {switching === tree.root.id ? <Loader2 className="h-3 w-3 animate-spin" /> : atRoot ? <Check className="h-3 w-3" /> : <Home className="h-3 w-3 text-amber-300/80" />}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block font-medium">{ROOT_ENVIRONMENT_LABEL}</span>
                  <span className="block text-[9px] text-slate-500">{atRoot ? "you are here" : "return to the root"}</span>
                </span>
              </button>

              {/* Children — the client environments. */}
              {tree.children.length === 0 ? (
                <div className="px-2.5 py-2 text-[11px] text-slate-500">No client environments yet.</div>
              ) : (
                <>
                  <div className="px-2.5 pt-1.5 pb-0.5 text-[9px] uppercase tracking-wider text-slate-600">Client environments</div>
                  {tree.children.map(e => (
                    <button
                      key={e.id}
                      onClick={() => switchTo(e.id, false)}
                      disabled={switching !== null}
                      className={`flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[11px] transition hover:bg-white/5 ${e.id === orgId ? "text-cyber-300" : "text-slate-300"}`}
                    >
                      <span className="w-3.5 shrink-0">
                        {switching === e.id ? <Loader2 className="h-3 w-3 animate-spin" /> : e.id === orgId ? <Check className="h-3 w-3" /> : null}
                      </span>
                      <span className="truncate">{e.name}</span>
                    </button>
                  ))}
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
