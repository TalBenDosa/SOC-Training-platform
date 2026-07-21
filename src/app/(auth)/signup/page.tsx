"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { UserPlus, Mail, CheckCircle2, AlertTriangle, Loader2, Check, X } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [handle, setHandle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [checkEmail, setCheckEmail] = useState(false);
  const [signedUp, setSignedUp] = useState(false);
  /** null = not checked yet (blank, or too short to be worth asking about). */
  const [handleFree, setHandleFree] = useState<boolean | null>(null);
  const [checkingHandle, setCheckingHandle] = useState(false);

  const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
  const normalisedHandle = handle.trim().toLowerCase();
  const handleWellFormed = normalisedHandle === "" || HANDLE_RE.test(normalisedHandle);

  // Availability is asked of the database, debounced, because profiles SELECT
  // is owner-only — the browser cannot query the table directly. The RPC
  // returns a single boolean and nothing else.
  useEffect(() => {
    if (normalisedHandle === "" || !HANDLE_RE.test(normalisedHandle)) {
      setHandleFree(null);
      return;
    }
    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    let cancelled = false;
    setCheckingHandle(true);
    const t = setTimeout(async () => {
      const { data, error: rpcError } = await supabase.rpc("handle_available", { candidate: normalisedHandle });
      if (cancelled) return;
      setCheckingHandle(false);
      // A failed lookup must not read as "available" — that would let someone
      // submit a taken name and only discover it after the account exists.
      setHandleFree(rpcError ? null : Boolean(data));
    }, 400);

    return () => { cancelled = true; clearTimeout(t); setCheckingHandle(false); };
  }, [normalisedHandle]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    if (normalisedHandle !== "" && !HANDLE_RE.test(normalisedHandle)) {
      setError("A nickname must be 3-20 characters, using only letters, numbers and underscores.");
      return;
    }
    if (normalisedHandle !== "" && handleFree === false) {
      setError(`The nickname "${normalisedHandle}" is already taken. Pick another one.`);
      return;
    }

    const supabase = getSupabaseBrowserClient();
    if (!supabase) {
      setError("Sign-up isn't configured on this deployment yet.");
      return;
    }

    setSubmitting(true);
    const { data, error: signUpError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback`,
        // Read by the handle_new_user() trigger, which RE-VALIDATES it before
        // use — this value is user-supplied and arrives unverified.
        data: normalisedHandle ? { handle: normalisedHandle } : undefined,
      },
    });
    setSubmitting(false);

    if (signUpError) {
      setError(signUpError.message);
      return;
    }
    // If email confirmation is disabled in the Supabase project, signUp already
    // returns an active session — go straight in. Otherwise show "check your email".
    if (data.session) {
      // Confirmation is disabled on this project, so the account is already
      // active. Sign the fresh session out and hand them to the login form:
      // the request was to land on sign-in, and arriving there already
      // authenticated would be confusing.
      await supabase.auth.signOut();
      setSignedUp(true);
      setTimeout(() => router.push("/login?registered=1"), 1600);
    } else {
      setCheckEmail(true);
    }
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

  if (signedUp) {
    return (
      <Card className="w-full max-w-md text-center">
        <CheckCircle2 className="mx-auto h-8 w-8 text-neon-green" />
        <h1 className="mt-4 text-lg font-bold text-white">Account created</h1>
        <p className="mt-2 text-sm text-slate-400">
          {normalisedHandle
            ? <>You&apos;ll be known as <span className="font-semibold text-white">{normalisedHandle}</span>. </>
            : null}
          Taking you to sign in…
        </p>
        <Loader2 className="mx-auto mt-5 h-4 w-4 animate-spin text-slate-500" />
        {/* A manual way through, in case the redirect does not fire — the
            previous flow left the user with no feedback and no next step. */}
        <Link href="/login?registered=1" className="mt-5 inline-block">
          <Button variant="outline" size="sm">Go to sign in</Button>
        </Link>
      </Card>
    );
  }

  if (checkEmail) {
    return (
      <Card className="w-full max-w-md text-center">
        <Mail className="mx-auto h-8 w-8 text-cyber-300" />
        <h1 className="mt-4 text-lg font-bold text-white">Check your email</h1>
        <p className="mt-2 text-sm text-slate-400">
          We sent a confirmation link to <span className="text-slate-200">{email}</span>.
          Click it to activate your account, then sign in.
        </p>
        <Link href="/login" className="mt-6 inline-block">
          <Button variant="outline">Back to sign in</Button>
        </Link>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <div className="mb-6 flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
          <UserPlus className="h-5 w-5 text-cyber-300" />
        </span>
        <div>
          <h1 className="text-lg font-bold text-white">Create your account</h1>
          <p className="text-xs text-slate-500">Free — your progress follows you across devices.</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <label className="text-xs font-semibold text-slate-400">
              Nickname <span className="font-normal text-slate-600">(optional)</span>
            </label>
            {/* Only speak once there is something worth saying. */}
            {normalisedHandle !== "" && (
              checkingHandle ? (
                <span className="flex items-center gap-1 text-[11px] text-slate-500">
                  <Loader2 className="h-3 w-3 animate-spin" /> checking
                </span>
              ) : !handleWellFormed ? (
                <span className="text-[11px] text-severity-high">3-20 chars: a-z, 0-9, _</span>
              ) : handleFree === true ? (
                <span className="flex items-center gap-1 text-[11px] text-neon-green">
                  <Check className="h-3 w-3" /> available
                </span>
              ) : handleFree === false ? (
                <span className="flex items-center gap-1 text-[11px] text-severity-high">
                  <X className="h-3 w-3" /> taken
                </span>
              ) : null
            )}
          </div>
          <input
            type="text" autoComplete="username" value={handle} maxLength={20}
            onChange={e => setHandle(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="How you'll appear on the platform"
          />
          <p className="mt-1 text-[11px] text-slate-600">
            Leave blank and we&apos;ll use the first part of your email.
          </p>
        </div>
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
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">Password</label>
          <input
            type="password" required minLength={8} autoComplete="new-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="At least 8 characters"
          />
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">Confirm password</label>
          <input
            type="password" required autoComplete="new-password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-600 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>

        {error && (
          <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">
            {error}
          </div>
        )}

        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting || checkingHandle || handleFree === false || !handleWellFormed}>
          {submitting ? "Creating account…" : "Create account"}
        </Button>
      </form>

      <p className="mt-5 text-center text-xs text-slate-500">
        Already have an account? <Link href="/login" className="text-cyber-300 hover:underline">Sign in</Link>
        {" · "}
        <Link href="/reset-password" className="text-cyber-300 hover:underline">Forgot password?</Link>
      </p>
      <p className="mt-3 flex items-center justify-center gap-1.5 text-center text-[11px] text-slate-600">
        {/* This used to read "progress you've made on this device carries over".
            That stopped being true for new visitors once the routes were gated:
            you can no longer reach a room without an account, so there is no
            guest progress left to carry. It still holds for anyone who used the
            platform BEFORE the gate, hence the conditional wording. */}
        <CheckCircle2 className="h-3 w-3" /> Any progress from before you signed up carries over automatically.
      </p>
    </Card>
  );
}
