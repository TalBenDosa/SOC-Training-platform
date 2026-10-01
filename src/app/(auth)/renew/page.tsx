"use client";
/**
 * The renewal screen an org student lands on when their 100-day affiliation
 * lapses (redirected here by the (app) layout gate — see 0028_org_codes.sql).
 * They enter the class's CURRENT code (their instructor generates one, valid
 * 24h) and go straight back to work.
 *
 * Lives in the (auth) group ON PURPOSE: the (app) layout redirects expired
 * students away from every app page, so this page must not be one of them.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useAuth } from "@/lib/auth/AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { KeyRound, LogOut } from "lucide-react";

export default function RenewPage() {
  usePageTitle("Renew enrolment");
  const router = useRouter();
  const { signOut } = useAuth();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const post = (url: string) => fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: code.trim() }),
      });
      let res = await post("/api/account/renew-affiliation");
      let data = await res.json().catch(() => ({}));
      // P5-09: a code from ANOTHER institution is a way out, not a dead end —
      // join that environment with it (it becomes the active one).
      if (!res.ok && data?.code === "wrong_org") {
        res = await post("/api/account/join-environment");
        data = await res.json().catch(() => ({}));
      }
      if (!res.ok) throw new Error(data.error ?? "Could not renew.");
      // The active environment lives in the session token — refresh it, then a
      // full load so the layout gate re-evaluates against the new expiry/context.
      await getSupabaseBrowserClient()?.auth.refreshSession();
      window.location.href = "/dashboard";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not renew.");
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <Card className="w-full max-w-md text-center">
        <KeyRound className="mx-auto h-8 w-8 text-neon-cyan" />
        <h1 className="mt-4 text-lg font-bold text-white">Renew your enrolment</h1>
        <p className="mt-2 text-sm text-slate-400">
          Your 100-day course enrolment has ended. Enter your class&apos;s current
          code — your instructor can generate today&apos;s — and you&apos;re back in,
          with all your progress exactly where you left it.
        </p>
        <form onSubmit={submit} className="mt-6 text-left">
          <label htmlFor="renew-code" className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Class code
          </label>
          <input
            id="renew-code"
            type="text"
            autoComplete="off"
            autoFocus
            value={code}
            onChange={e => setCode(e.target.value.toUpperCase())}
            placeholder="e.g. K7MRW3TQ"
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 font-mono text-sm tracking-widest text-white placeholder:text-slate-500 focus:border-neon-cyan focus:outline-none focus:ring-1 focus:ring-neon-cyan"
          />
          <Button type="submit" className="mt-4 w-full" disabled={!code.trim() || busy}>
            {busy ? "Checking…" : "Renew enrolment"}
          </Button>
        </form>
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
        <p className="mt-5 text-xs text-slate-500">
          In another course too? Enter that course&apos;s code above to continue there.
        </p>
        <button
          type="button"
          onClick={async () => { await signOut(); router.push("/login"); }}
          className="mt-3 inline-flex items-center gap-1.5 text-xs text-slate-400 underline-offset-2 hover:text-slate-200 hover:underline"
        >
          <LogOut className="h-3.5 w-3.5" /> Sign out
        </button>
      </Card>
    </main>
  );
}
