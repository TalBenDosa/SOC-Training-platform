"use client";
import { useState } from "react";
import Link from "next/link";
import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { LogIn, AlertTriangle } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  // refreshSupabaseSession sets ?next= when it redirects an unauthenticated
  // visitor. Honour it so signing in returns them to what they asked for.
  // Same-origin paths only — an open redirect here would let a crafted link
  // bounce a freshly-authenticated user to an attacker-controlled page.
  const rawNext = searchParams.get("next");
  const nextPath = rawNext && rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/home";
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
          <p className="text-xs text-slate-500">Welcome back to your SOC shift.</p>
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
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-400">Password</label>
            <Link href="/reset-password" className="text-[11px] text-cyber-300 hover:underline">Forgot password?</Link>
          </div>
          <input
            type="password" required autoComplete="current-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
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

      <p className="mt-5 text-center text-xs text-slate-500">
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
