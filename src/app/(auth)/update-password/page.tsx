"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { KeyRound } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

/**
 * Landed on after clicking the reset-password email link. Supabase's client
 * SDK auto-exchanges the recovery token in the URL for a temporary session
 * (detectSessionInUrl, on by default) — this page just captures the new password.
 */
export default function UpdatePasswordPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

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
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">New password</label>
          <input
            type="password" required minLength={8} autoComplete="new-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">Confirm new password</label>
          <input
            type="password" required autoComplete="new-password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
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
