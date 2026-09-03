"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { KeyRound } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

/**
 * Landed on after clicking the reset-password email link. Supabase's client
 * SDK auto-exchanges the recovery token in the URL for a temporary session
 * (detectSessionInUrl, on by default) — this page captures the new password.
 *
 * We verify a session actually got established before showing the form: a link
 * that has expired, was already used, or was opened in a different browser than
 * the one that requested it (PKCE has no code-verifier there) yields NO session,
 * and a bare form would then fail on submit with a cryptic "Auth session
 * missing". Instead we show a clear "request a new link" state.
 */
export default function UpdatePasswordPage() {
  usePageTitle("Set new password");
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  // null = still checking; true = a (recovery or normal) session exists; false = no session.
  const [linkValid, setLinkValid] = useState<boolean | null>(null);

  useEffect(() => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setLinkValid(false); return; }
    let settled = false;
    const finish = (ok: boolean) => { if (!settled) { settled = true; setLinkValid(ok); } };
    // The SDK exchanges the token on load and fires PASSWORD_RECOVERY / SIGNED_IN.
    const { data: sub } = supabase.auth.onAuthStateChange((_e, session) => { if (session) finish(true); });
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) finish(true);
      // Give detectSessionInUrl a moment to exchange a `?code=` before giving up.
      else setTimeout(() => finish(Boolean(data.session)), 2500);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) { setError("Password must be at least 8 characters."); return; }
    if (password !== confirm) { setError("Passwords don't match."); return; }

    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setError("Not configured on this deployment yet."); return; }

    setSubmitting(true);
    const { error: updateError } = await supabase.auth.updateUser({ password });
    setSubmitting(false);
    if (updateError) { setError(updateError.message); return; }
    setDone(true);
    setTimeout(() => { router.push("/rooms"); router.refresh(); }, 1500);
  }

  if (!isSupabaseConfigured) {
    return <Card className="w-full max-w-md text-center"><p className="text-sm text-slate-400">Not configured on this deployment yet.</p></Card>;
  }

  if (done) {
    return (
      <Card className="w-full max-w-md text-center">
        <h1 className="text-lg font-bold text-neon-green">Password updated</h1>
        <p className="mt-2 text-sm text-slate-400">Taking you back in…</p>
      </Card>
    );
  }

  if (linkValid === null) {
    return (
      <Card className="w-full max-w-md text-center">
        <p className="text-sm text-slate-400">Verifying your reset link…</p>
      </Card>
    );
  }

  if (linkValid === false) {
    return (
      <Card className="w-full max-w-md text-center">
        <span className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
          <KeyRound className="h-5 w-5 text-cyber-300" />
        </span>
        <h1 className="mt-4 text-lg font-bold text-white">This reset link isn&apos;t active</h1>
        <p className="mt-2 text-sm text-slate-400">
          It may have expired, already been used, or been opened in a different browser than the
          one you requested it from. Request a fresh link and open it in the same browser.
        </p>
        <Link href="/reset-password" className="mt-6 inline-block">
          <Button variant="primary">Request a new link</Button>
        </Link>
        <p className="mt-4 text-xs text-slate-500">
          Already know your password? <Link href="/login" className="text-cyber-300 hover:underline">Sign in</Link>
        </p>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <div className="mb-6 flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
          <KeyRound className="h-5 w-5 text-cyber-300" />
        </span>
        <h1 className="text-lg font-bold text-white">Set a new password</h1>
      </div>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="update-password" className="mb-1.5 block text-xs font-semibold text-slate-400">New password</label>
          <input
            id="update-password"
            type="password" required minLength={8} autoComplete="new-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>
        <div>
          <label htmlFor="update-confirm" className="mb-1.5 block text-xs font-semibold text-slate-400">Confirm new password</label>
          <input
            id="update-confirm"
            type="password" required autoComplete="new-password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>
        {error && (
          <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>
        )}
        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting}>
          {submitting ? "Updating…" : "Update password"}
        </Button>
      </form>
    </Card>
  );
}
