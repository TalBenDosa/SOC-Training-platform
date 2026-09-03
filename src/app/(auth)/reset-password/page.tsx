"use client";
import { useState } from "react";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { KeyRound, Mail } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { isSupabaseConfigured } from "@/lib/supabase/config";

export default function ResetPasswordPage() {
  usePageTitle("Reset password");
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    // Route through our own endpoint (Resend + a stateless recovery token) rather
    // than Supabase's built-in email, so the reset link is immune to the project's
    // Site-URL / redirect-allowlist config and works cross-device. See
    // src/app/api/auth/request-reset/route.ts.
    try {
      const res = await fetch("/api/auth/request-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      setSubmitting(false);
      if (res.status === 429) {
        const b = await res.json().catch(() => ({}));
        setError(b.error ?? "Too many reset requests. Please wait a few minutes and try again.");
        return;
      }
      if (!res.ok && res.status !== 200) {
        const b = await res.json().catch(() => ({}));
        setError(b.error ?? "Something went wrong. Please try again.");
        return;
      }
      setSent(true);
    } catch {
      setSubmitting(false);
      setError("Network error. Please try again.");
    }
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
          <p className="text-xs text-slate-400">We&apos;ll email you a reset link.</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="reset-email" className="mb-1.5 block text-xs font-semibold text-slate-400">Email</label>
          <input
            id="reset-email"
            type="email" required autoComplete="email" value={email}
            onChange={e => setEmail(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
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
      <p className="mt-5 text-center text-xs text-slate-400">
        <Link href="/login" className="text-cyber-300 hover:underline">Back to sign in</Link>
      </p>
    </Card>
  );
}
