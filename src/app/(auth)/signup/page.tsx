"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useRouter } from "next/navigation";
import { UserPlus, Mail, CheckCircle2, AlertTriangle, Loader2, Check, X, Building2, Lock } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { cn } from "@/lib/utils";

export default function SignupPage() {
  usePageTitle("Create account");
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [handle, setHandle] = useState("");
  const [fullName, setFullName] = useState("");
  // Enrollment: an invite token in the URL (?invite=…) drops the new account
  // into the inviting institution via the signup trigger. Read from the URL
  // rather than useSearchParams to avoid a Suspense boundary on this client page.
  const [inviteToken, setInviteToken] = useState("");
  const [inviteOrg, setInviteOrg] = useState<string | null>(null);
  const [inviteRole, setInviteRole] = useState<string>("student");
  /** The address the invite was issued TO, when it names one. A roster invite is
   *  bound to it server-side (migration 0026), so the field is locked to match —
   *  letting someone type a different address here would only produce a failed
   *  signup after the fact. Null for a shareable class-wide link. */
  const [inviteEmail, setInviteEmail] = useState<string | null>(null);
  /** "checking" until the token resolves, so we never render a form that looks
   *  like a normal signup while an invitation is still being validated. */
  const [inviteState, setInviteState] = useState<"none" | "checking" | "valid" | "invalid">("none");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [checkEmail, setCheckEmail] = useState(false);
  const [signedUp, setSignedUp] = useState(false);
  /** null = not checked yet (blank, or too short to be worth asking about). */
  const [handleFree, setHandleFree] = useState<boolean | null>(null);
  const [checkingHandle, setCheckingHandle] = useState(false);

  // Pick up ?invite=<token> and resolve which institution it belongs to.
  //
  // A failed resolve used to be swallowed (`if (d?.valid)` and an empty catch),
  // which meant an expired or wrong token rendered an ordinary signup form: the
  // student created an account believing they had joined their college, and
  // silently landed in the default org instead. Nothing told them, and nothing
  // told the admin why their student never appeared on the roster. An invitation
  // that cannot be honoured is now a blocking state.
  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("invite");
    if (!token) return;
    setInviteToken(token);
    setInviteState("checking");
    fetch(`/api/invitations/${encodeURIComponent(token)}`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (d?.valid) {
          setInviteOrg(d.orgName ?? null);
          setInviteRole(typeof d.role === "string" ? d.role : "student");
          const invited = typeof d.email === "string" && d.email.trim() ? d.email.trim().toLowerCase() : null;
          setInviteEmail(invited);
          if (invited) setEmail(invited);
          setInviteState("valid");
        } else {
          setInviteState("invalid");
        }
      })
      .catch(() => setInviteState("invalid"));
  }, []);

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

    // Metadata read by the handle_new_user() trigger, which RE-VALIDATES it
    // before use — these values are user-supplied and arrive unverified. The
    // full name becomes profiles.display_name and is what a certificate prints;
    // both fields are optional, so an empty object degrades to today's behaviour.
    const metadata: Record<string, string> = {};
    if (normalisedHandle) metadata.handle = normalisedHandle;
    const trimmedName = fullName.trim();
    if (trimmedName) metadata.full_name = trimmedName;
    // Carries the enrollment: the trigger re-validates the token and assigns the org.
    if (inviteToken) metadata.invitation_token = inviteToken;

    setSubmitting(true);
    const { data, error: signUpError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback`,
        data: Object.keys(metadata).length ? metadata : undefined,
      },
    });
    setSubmitting(false);

    if (signUpError) {
      // The enrollment trigger raises named exceptions (migration 0026) that
      // surface here as opaque database errors. Translate the ones a student
      // can actually act on — anything else passes through unchanged.
      const raw = signUpError.message ?? "";
      if (raw.includes("invitation_email_mismatch")) {
        setError(
          inviteEmail
            ? `This invitation was issued to ${inviteEmail}. Sign up with that address, or ask your course administrator for an invite for the address you want to use.`
            : "This invitation was issued to a different email address. Ask your course administrator for a new invite link.",
        );
      } else if (raw.includes("invitation_invalid")) {
        setError("This invitation has expired or has already been used. Ask your course administrator for a fresh link.");
      } else if (raw.includes("seat_limit_reached")) {
        setError(`${inviteOrg ?? "This course"} has no seats left. Ask your course administrator to free one up, then try again.`);
      } else {
        setError(raw);
      }
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
        <Loader2 className="mx-auto mt-5 h-4 w-4 animate-spin text-slate-400" />
        {/* A manual way through, in case the redirect does not fire — the
            previous flow left the user with no feedback and no next step. */}
        <Link href="/login?registered=1" className="mt-5 inline-block">
          <Button variant="outline" size="sm">Go to sign in</Button>
        </Link>
      </Card>
    );
  }

  // A token was supplied but can't be honoured. Stop here rather than render a
  // form that would quietly enrol them in the wrong place (see the resolve
  // effect above). Signing up WITHOUT an invitation stays available below.
  if (inviteState === "invalid") {
    return (
      <Card className="w-full max-w-md text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-neon-amber" />
        <h1 className="mt-4 text-lg font-bold text-white">This invitation isn&apos;t valid</h1>
        <p className="mt-2 text-sm text-slate-400">
          The link has expired or has already been used, so we can&apos;t add you to the course it
          belongs to. Ask your course administrator to send you a fresh invite link.
        </p>
        <Link href="/login" className="mt-6 inline-block">
          <Button variant="outline">Back to sign in</Button>
        </Link>
      </Card>
    );
  }

  if (inviteState === "checking") {
    return (
      <Card className="w-full max-w-md text-center">
        <Loader2 className="mx-auto h-6 w-6 animate-spin text-slate-400" />
        <p className="mt-4 text-sm text-slate-400">Checking your invitation…</p>
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
          <h1 className="text-lg font-bold text-white">
            {inviteState === "valid" ? "Complete your enrolment" : "Create your account"}
          </h1>
          <p className="text-xs text-slate-400">
            {inviteState === "valid"
              ? "One step left — set a password and you're in."
              : "Your progress follows you across every device."}
          </p>
        </div>
      </div>

      {/* Institution card. The student arrived from their college's invite link,
          so lead with WHOSE course this is — it's the one thing they need to
          confirm before handing over a password. */}
      {inviteState === "valid" && (
        <div className="mb-5 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.07] p-4">
          <div className="flex items-start gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10">
              <Building2 className="h-4 w-4 text-cyber-300" />
            </span>
            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyber-400">
                You&apos;ve been invited by
              </p>
              <p className="mt-0.5 truncate text-base font-bold text-white">
                {inviteOrg ?? "your course"}
              </p>
              <p className="mt-1 text-xs text-slate-400">
                Your account will be created inside their course as{" "}
                <span className="font-semibold text-slate-200">{inviteRole.replace("_", " ")}</span>
                {" "}— progress, assignments and the class leaderboard are all theirs.
              </p>
            </div>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="signup-fullname" className="mb-1.5 block text-xs font-semibold text-slate-400">
            Full name <span className="font-normal text-slate-400">(optional)</span>
          </label>
          <input
            id="signup-fullname"
            type="text" autoComplete="name" value={fullName} maxLength={60}
            onChange={e => setFullName(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="e.g. Tal Ben Dosa"
          />
          <p className="mt-1 text-[11px] text-slate-400">
            Printed on the rank certificates you earn. Your nickname stays your public handle.
          </p>
        </div>
        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <label htmlFor="signup-handle" className="text-xs font-semibold text-slate-400">
              Nickname <span className="font-normal text-slate-400">(optional)</span>
            </label>
            {/* Only speak once there is something worth saying. */}
            {normalisedHandle !== "" && (
              checkingHandle ? (
                <span className="flex items-center gap-1 text-[11px] text-slate-400">
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
            id="signup-handle"
            type="text" autoComplete="username" value={handle} maxLength={20}
            onChange={e => setHandle(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="How you'll appear on the platform"
          />
          <p className="mt-1 text-[11px] text-slate-400">
            Leave blank and we&apos;ll use the first part of your email.
          </p>
        </div>
        <div>
          <label htmlFor="signup-email" className="mb-1.5 flex items-baseline justify-between text-xs font-semibold text-slate-400">
            <span>Email</span>
            {inviteEmail && (
              <span className="flex items-center gap-1 font-normal text-[11px] text-cyber-300">
                <Lock className="h-3 w-3" /> set by your invitation
              </span>
            )}
          </label>
          <input
            id="signup-email"
            type="email" required autoComplete="email" value={email}
            onChange={e => setEmail(e.target.value)}
            // A roster invite is bound to its recipient server-side, so an
            // editable box here would just invite a signup that fails on submit.
            readOnly={!!inviteEmail}
            aria-readonly={!!inviteEmail}
            className={cn(
              "h-10 w-full rounded-md border px-3 text-sm placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30",
              inviteEmail
                ? "cursor-not-allowed border-cyber-500/25 bg-cyber-500/[0.06] text-slate-200"
                : "border-border bg-bg text-white focus:border-cyber-500/50",
            )}
            placeholder="you@company.com"
          />
          {inviteEmail && (
            <p className="mt-1 text-[11px] text-slate-400">
              Your course administrator issued this invitation to this address. Need a different
              one? Ask them to send a new invite.
            </p>
          )}
        </div>
        <div>
          <label htmlFor="signup-password" className="mb-1.5 block text-xs font-semibold text-slate-400">Password</label>
          <input
            id="signup-password"
            type="password" required minLength={8} autoComplete="new-password" value={password}
            onChange={e => setPassword(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="At least 8 characters"
          />
        </div>
        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <label htmlFor="signup-confirm" className="text-xs font-semibold text-slate-400">Confirm password</label>
            {/* Live match feedback — mirrors the nickname field, so a mismatch is
                caught while typing instead of only on submit. */}
            {confirm !== "" && (
              password === confirm ? (
                <span className="flex items-center gap-1 text-[11px] text-neon-green"><Check className="h-3 w-3" /> match</span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] text-severity-high"><X className="h-3 w-3" /> no match yet</span>
              )
            )}
          </div>
          <input
            id="signup-confirm"
            type="password" required autoComplete="new-password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            className="h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
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

      <p className="mt-5 text-center text-xs text-slate-400">
        Already have an account? <Link href="/login" className="text-cyber-300 hover:underline">Sign in</Link>
        {" · "}
        <Link href="/reset-password" className="text-cyber-300 hover:underline">Forgot password?</Link>
      </p>
      <p className="mt-3 flex items-center justify-center gap-1.5 text-center text-[11px] text-slate-400">
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
