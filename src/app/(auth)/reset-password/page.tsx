"use client";
import { useState } from "react";
import Link from "next/link";
import { KeyRound, Mail } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

export default function ResetPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setError("Not configured on this deployment yet."); return; }

    setSubmitting(true);
    const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/update-password`,
    });
    setSubmitting(false);
    if (resetError) { setError(resetError.message); return; }
    setSent(true);
  }

  if (!isSupabaseConfigured) {
    return (
      <Card className="w-full max-w-md text-center">
        <p className="text-sm text-slate-400">Accounts aren&apos;t set up on this deployment yet.</p>
        <Link href="/rooms" className="mt-4 inline-block"><Button variant="outline">Back to app</Button></Link>
      </Card>
    );
  }

  if (sent) {
    return (
      <Card className="w-full max-w-md text-center">
        <Mail className="mx-auto h-8 w-8 text-cyber-300" />
        <h1 className="mt-4 text-lg font-bold text-white">Check your email</h1>
        <p className="mt-2 text-sm text-slate-400">
          If an account exists for <span className="text-slate-200">{email}</span>, we sent a link to reset your password.
        </p>
        <Link href="/login" className="mt-6 inline-block"><Button variant="outline">Back to sign in</Button></Link>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <div className="mb-6 flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
          <KeyRound className="h-5 w-5 text-cyber-300" />
        </span>
        <div>
          <h1 className="text-lg font-bold text-white">Reset your password</h1>
          <p className="text-xs text-slate-500">We&apos;ll email you a reset link.</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">Email</label>
          <input
            type="email" required autoComplete="email" value={email}
            onChange={e => setEmail(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="you@company.com"
          />
        </div>
        {error && (
          <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>
        )}
        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting}>
          {submitting ? "Sending…" : "Send reset link"}
        </Button>
      </form>
      <p className="mt-5 text-center text-xs text-slate-500">
        <Link href="/login" className="text-cyber-300 hover:underline">Back to sign in</Link>
      </p>
    </Card>
  );
}
