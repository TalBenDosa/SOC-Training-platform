"use client";
import { useState } from "react";
import Link from "next/link";
import { Suspense } from "react";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useRouter, useSearchParams } from "next/navigation";
import { LogIn, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

function LoginForm() {
  usePageTitle("Sign in");
  const router = useRouter();
  const searchParams = useSearchParams();
  // refreshSupabaseSession sets ?next= when it redirects an unauthenticated
  // visitor. Honour it so signing in returns them to what they asked for.
  // Same-origin paths only — an open redirect here would let a crafted link
  // bounce a freshly-authenticated user to an attacker-controlled page.
  // Set by the signup flow so a new account gets an explicit confirmation
  // here rather than landing on a bare form wondering whether it worked.
  const justRegistered = searchParams.get("registered") === "1";
  const rawNext = searchParams.get("next");
  // Same-origin relative paths only. Must start with a single "/" and NOT with
  // "//" (protocol-relative) or "/\" — browsers normalise backslashes to
  // forward slashes, so "/\evil.com" would otherwise resolve to an external
  // host. The negative lookahead rejects both.
  const nextPath = rawNext && /^\/(?![/\\])/.test(rawNext) ? rawNext : "/welcome";
  // ?code= — an access code carried over from signup's "this email already has
  // an account" path. Applied AFTER authentication: the code joins its
  // environment to the signed-in account (multi-environment), then we land on
  // the dashboard of the newly joined environment.
  const rawCode = searchParams.get("code");
  const joinCode = rawCode && /^[A-Z0-9]{6,12}$/i.test(rawCode.trim()) ? rawCode.trim().toUpperCase() : null;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const supabase = getSupabaseBrowserClient();
    if (!supabase) {
      setError("Sign-in isn't configured on this deployment yet.");
      return;
    }

    setSubmitting(true);
    const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    setSubmitting(false);

    if (signInError) {
      setError(
        signInError.message === "Invalid login credentials"
          ? "Incorrect email or password."
          : signInError.message,
      );
      return;
    }

    // Carried access code → join its environment onto this account before
    // navigating. On failure we STOP with the reason (seat cap, expired code)
    // rather than silently landing the user somewhere they didn't join.
    if (joinCode) {
      setSubmitting(true);
      const res = await fetch("/api/account/join-environment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: joinCode }),
      });
      setSubmitting(false);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error ?? "Signed in, but couldn't join with this code.");
        return;
      }
      await supabase.auth.refreshSession(); // restamp org claims for the new context
      window.location.href = "/dashboard";
      return;
    }

    router.push(nextPath);
    router.refresh();
  }

  if (!isSupabaseConfigured) {
    return (
      <Card className="w-full max-w-md text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-neon-amber" />
        <h1 className="mt-4 text-lg font-bold text-white">Accounts aren&apos;t set up yet</h1>
        <p className="mt-2 text-sm text-slate-400">
          This deployment hasn&apos;t been connected to a database. You can still use the platform —
          your progress is saved on this device.
        </p>
        <Link href="/rooms" className="mt-6 inline-block">
          <Button variant="primary">Continue as guest</Button>
        </Link>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <div className="mb-6 flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
          <LogIn className="h-5 w-5 text-cyber-300" />
        </span>
        <div>
          <h1 className="text-lg font-bold text-white">Sign in</h1>
          <p className="text-xs text-slate-400">Welcome back to your SOC shift.</p>
        </div>
      </div>

      {joinCode && (
        <div className="mb-4 flex items-start gap-2 rounded border border-cyber-500/30 bg-cyber-500/5 px-3 py-2.5">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyber-300" />
          <p className="text-xs text-slate-300">
            Sign in and the code <span className="font-mono font-bold text-cyber-300">{joinCode}</span>{" "}
            will add its environment to your account.
          </p>
        </div>
      )}
      {justRegistered && (
        <div className="mb-4 flex items-start gap-2 rounded border border-neon-green/30 bg-neon-green/5 px-3 py-2.5">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-neon-green" />
          <p className="text-xs text-slate-300">
            Your account is ready. Sign in to start training.
          </p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="login-email" className="mb-1.5 block text-xs font-semibold text-slate-400">Email</label>
          <input
            id="login-email"
            type="email" required autoComplete="email" value={email}
            onChange={e => setEmail(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="you@company.com"
          />
        </div>
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <label htmlFor="login-password" className="text-xs font-semibold text-slate-400">Password</label>
            <Link href="/reset-password" className="text-[11px] text-cyber-300 hover:underline">Forgot password?</Link>
          </div>
          <input
            id="login-password"
            type="password" required autoComplete="current-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>

        {error && (
          <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">
            {error}
          </div>
        )}

        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </Button>
      </form>

      <p className="mt-5 text-center text-xs text-slate-400">
        New here? <Link href="/signup" className="text-cyber-300 hover:underline">Create an account</Link>
      </p>
    </Card>
  );
}

/**
 * useSearchParams() puts this page into client-side rendering, and Next
 * requires a Suspense boundary around that during static export — without one
 * the build fails on /login. The fallback is deliberately the same card shell
 * so the boundary is invisible rather than flashing an empty page.
 */
export default function LoginPage() {
  return (
    <Suspense fallback={<Card className="w-full max-w-md p-6 text-center text-sm text-slate-400">Loading…</Card>}>
      <LoginForm />
    </Suspense>
  );
}
