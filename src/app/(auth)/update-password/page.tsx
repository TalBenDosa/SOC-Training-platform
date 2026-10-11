"use client";
import { PASSWORD_MAX_BYTES } from "@/app/(app)/account/accountValidation";
import { authErrorMessage } from "@/lib/http/apiError";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { KeyRound } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button, buttonClasses } from "@/components/ui/Button";
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
  /** Which input the current error is about (aria-invalid + aria-describedby). */
  const [errorField, setErrorField] = useState<"password" | "confirm" | null>(null);
  // The "Password updated" view replaces the form: move focus to its heading.
  const doneHeadingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (done) doneHeadingRef.current?.focus(); }, [done]);
  // null = still checking; true = a (recovery or normal) session exists; false = no session.
  const [linkValid, setLinkValid] = useState<boolean | null>(null);

  useEffect(() => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setLinkValid(false); return; }
    let settled = false;
    const finish = (ok: boolean) => { if (!settled) { settled = true; setLinkValid(ok); } };
    const sub = supabase.auth.onAuthStateChange((_e, session) => { if (session) finish(true); });

    (async () => {
      // Preferred path: our own reset email carries a stateless recovery
      // `token_hash`. verifyOtp needs no PKCE code-verifier, so it works even
      // when the link is opened on a different device than it was requested from.
      const url = new URL(window.location.href);
      const tokenHash = url.searchParams.get("token_hash");
      const type = url.searchParams.get("type");
      if (tokenHash && type === "recovery") {
        const { error } = await supabase.auth.verifyOtp({ type: "recovery", token_hash: tokenHash });
        if (!error) {
          // Drop the token from the address bar so a refresh / back doesn't re-verify.
          window.history.replaceState(null, "", "/update-password");
          finish(true);
          return;
        }
      }
      // Fallback: a legacy Supabase PKCE `?code=` (detectSessionInUrl auto-exchanges
      // it), or an already-active session (a signed-in user changing their password).
      const { data } = await supabase.auth.getSession();
      if (data.session) { finish(true); return; }
      setTimeout(async () => {
        const { data: d2 } = await supabase.auth.getSession();
        finish(Boolean(d2.session));
      }, 2500);
    })();

    return () => sub.data.subscription.unsubscribe();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setErrorField(null);
    // P5-16: same bound the server/bcrypt enforce (72 BYTES — a Hebrew letter is 2).
    if (new TextEncoder().encode(password).length > PASSWORD_MAX_BYTES) {
      setError("That password is too long — keep it under 72 bytes (about 36 Hebrew or 72 English characters).");
      setErrorField("password");
      return;
    }
    if (password.length < 8) { setError("Password must be at least 8 characters."); setErrorField("password"); return; }
    if (password !== confirm) { setError("Passwords don't match."); setErrorField("confirm"); return; }

    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setError("Not configured on this deployment yet."); return; }

    setSubmitting(true);
    const { error: updateError } = await supabase.auth.updateUser({ password });
    setSubmitting(false);
    if (updateError) { setError(authErrorMessage(updateError)); return; }   // E-07
    setDone(true);
    setTimeout(() => { router.push("/rooms"); router.refresh(); }, 1500);
  }

  if (!isSupabaseConfigured) {
    return <Card className="w-full max-w-md text-center"><p className="text-sm text-slate-400">Not configured on this deployment yet.</p></Card>;
  }

  if (done) {
    return (
      <Card className="w-full max-w-md text-center">
        <div role="status">
          <h1 ref={doneHeadingRef} tabIndex={-1} className="text-lg font-bold text-neon-green outline-none">Password updated</h1>
          <p className="mt-2 text-sm text-slate-400">Taking you back in…</p>
        </div>
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
        <Link href="/reset-password" className={buttonClasses("primary", "md", "mt-6")}>
          Request a new link
        </Link>
        <p className="mt-4 text-xs text-slate-500">
          Already know your password? <Link href="/login" className="text-cyber-300 underline underline-offset-2 hover:text-cyber-200">Sign in</Link>
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
            aria-invalid={errorField === "password" || undefined}
            aria-describedby={errorField === "password" ? "update-password-hint update-password-error" : "update-password-hint"}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
          {/* Visible rule, linked to the field (WCAG 3.3.2). */}
          <p id="update-password-hint" className="mt-1 text-[11px] text-slate-400">
            At least 8 characters.
          </p>
        </div>
        <div>
          <label htmlFor="update-confirm" className="mb-1.5 block text-xs font-semibold text-slate-400">Confirm new password</label>
          <input
            id="update-confirm"
            type="password" required autoComplete="new-password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            aria-invalid={errorField === "confirm" || undefined}
            aria-describedby={errorField === "confirm" ? "update-password-error" : undefined}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          />
        </div>
        {error && (
          <div id="update-password-error" role="alert" className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>
        )}
        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting}>
          {submitting ? "Updating…" : "Update password"}
        </Button>
      </form>
    </Card>
  );
}
