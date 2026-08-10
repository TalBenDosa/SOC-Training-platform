"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useRouter } from "next/navigation";
import { UserPlus, Mail, CheckCircle2, AlertTriangle, Loader2, Check, X, Building2, Lock, ArrowRight } from "lucide-react";
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
  /** The access code (0028) — the ONLY student door. Arrives via ?code= from
      the /join gate, which already validated it; re-resolved here so the form
      can show WHICH college it joins, and so a stale deep link blocks cleanly. */
  const [orgCode, setOrgCode] = useState("");
  const [codeState, setCodeState] = useState<"none" | "checking" | "valid" | "invalid">("none");
  const [codeOrg, setCodeOrg] = useState<string | null>(null);
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
    const params = new URLSearchParams(window.location.search);
    const codeParam = params.get("code");
    const token = params.get("invite");

    // CODE-FIRST: the registration form only exists behind a credential. A
    // bare /signup (no code, no invite) goes back to the access gate.
    if (!token && !codeParam) {
      router.replace("/join");
      return;
    }

    // Code handed off from the /join gate — re-resolve to display the college
    // and to block a stale bookmark with a clear message rather than a
    // surprise failure on submit.
    if (!token && codeParam) {
      const cleaned = codeParam.toUpperCase();
      setOrgCode(cleaned);
      setCodeState("checking");
      fetch(`/api/access-codes/${encodeURIComponent(cleaned)}`)
        .then(r => (r.ok ? r.json() : null))
        .then(d => {
          if (d?.valid) { setCodeOrg(d.orgName ?? null); setCodeState("valid"); }
          else setCodeState("invalid");
        })
        .catch(() => setCodeState("invalid"));
    }
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
    // The student path (0028): no invite link → a class code is REQUIRED. The
    // trigger enforces this server-side (signup_requires_code); this check just
    // saves a round-trip for the obvious case.
    if (!inviteToken) {
      const trimmedCode = orgCode.trim();
      if (!trimmedCode) {
        setError("Enter your class code — you'll find it with your instructor. Without it, registration isn't possible.");
        return;
      }
      metadata.org_code = trimmedCode;
    }

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
      } else if (raw.toLowerCase().includes("already registered")) {
        // The multi-environment case: this email HAS an account and is holding
        // a code for a (possibly additional) environment. Registration is the
        // wrong door — sign in and the code joins the environment to the
        // existing account, keeping every environment they're already in.
        setError(
          orgCode
            ? "This email already has an account — and that's fine: sign in and this code will add the environment to it, alongside any you're already in."
            : "This email already has an account. Sign in instead.",
        );
      } else if (raw.includes("student_invite_requires_code")) {
        setError("Class-wide invite links were retired — students now join with a class code. Ask your instructor for today's code.");
      } else if (raw.includes("org_code_invalid")) {
        setError("That class code isn't valid or has expired — codes are refreshed daily. Ask your instructor for today's code.");
      } else if (raw.includes("signup_requires_code")) {
        setError("Registration requires a class code or an invitation link. Ask your instructor for today's code.");
      } else if (raw.includes("seat_limit_reached")) {
        setError(`${inviteOrg ?? "This course"} has no seats left. Ask your course administrator to free one up, then try again.`);
      } else {
        setError(raw);
      }
      return;
    }
    // If email confirmation is disabled in the Supabase project (it is, on this
    // deployment: mailer_autoconfirm), signUp returns an active session — the
    // account is ready NOW. Otherwise show "check your email".
    if (data.session) {
      // Render the success confirmation FIRST, so it can't be skipped by the
      // sign-out below re-rendering the tree. Then sign the fresh session out
      // in the background (the request is to land on sign-in, and arriving
      // there already authenticated would be confusing), and auto-advance
      // after a beat long enough to actually read the confirmation.
      setSignedUp(true);
      void supabase.auth.signOut();
      setTimeout(() => router.push("/login?registered=1"), 2600);
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
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-neon-green/40 bg-neon-green/10">
          <CheckCircle2 className="h-8 w-8 text-neon-green" />
        </div>
        <h1 className="mt-5 text-xl font-bold text-white">You&apos;re registered!</h1>
        <p className="mt-2 text-sm text-slate-300">
          Your account is ready
          {codeOrg ? <> in <span className="font-semibold text-white">{codeOrg}</span></> : null}
          {normalisedHandle ? <>, as <span className="font-semibold text-white">{normalisedHandle}</span></> : null}.
        </p>
        <p className="mt-1 text-sm text-slate-400">Sign in to start training.</p>
        {/* The confirmation is the point, so the button is the primary path.
            An auto-redirect follows a couple of seconds later as a fallback. */}
        <Link href="/login?registered=1" className="mt-6 block">
          <Button variant="primary" size="lg" className="w-full">
            Continue to sign in <ArrowRight className="h-4 w-4" />
          </Button>
        </Link>
        <p className="mt-3 flex items-center justify-center gap-1.5 text-[11px] text-slate-500">
          <Loader2 className="h-3 w-3 animate-spin" /> Taking you there automatically…
        </p>
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

  // A dead code from a stale bookmark blocks HERE, before any typing — with
  // the fix in hand (get today's code), not a dead end.
  if (codeState === "invalid") {
    return (
      <Card className="w-full max-w-md text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-neon-amber" />
        <h1 className="mt-4 text-lg font-bold text-white">This access code isn&apos;t valid</h1>
        <p className="mt-2 text-sm text-slate-400">
          Codes are refreshed daily and each one lasts 24 hours. Ask your instructor for
          today&apos;s code, then try again.
        </p>
        <Link href="/join" className="mt-6 inline-block">
          <Button variant="outline">Enter a different code</Button>
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
        {/* The credential that admitted them — LOCKED, not editable. The code
            was entered and validated at the /join gate (code-first flow); here
            it only shows what it unlocked and offers a way back. */}
        {!inviteToken && codeState === "valid" && (
          <div className="rounded-lg border border-neon-cyan/30 bg-neon-cyan/[0.05] p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyber-400">
                  Joining
                </p>
                <p className="truncate text-base font-bold text-white">{codeOrg ?? "your course"}</p>
              </div>
              <span className="flex items-center gap-1.5 rounded border border-neon-cyan/40 bg-bg px-2.5 py-1 font-mono text-sm font-bold tracking-[0.2em] text-neon-cyan">
                <Lock className="h-3 w-3" /> {orgCode}
              </span>
            </div>
            <Link href="/join" className="mt-2 inline-block text-[11px] text-slate-400 underline-offset-2 hover:text-cyber-300 hover:underline">
              Use a different code
            </Link>
          </div>
        )}
        {!inviteToken && codeState === "checking" && (
          <p className="flex items-center gap-2 text-sm text-slate-400">
            <Loader2 className="h-4 w-4 animate-spin" /> Checking your access code…
          </p>
        )}
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
            {/* The one error whose FIX is a different door: an existing account
                holding a code signs in, and the code joins the environment to
                that account (/login applies ?code= after authentication). */}
            {error.toLowerCase().includes("already has an account") && orgCode && (
              <Link
                href={`/login?code=${encodeURIComponent(orgCode)}`}
                className="mt-2 block rounded border border-cyber-500/40 bg-cyber-500/10 px-3 py-2 text-center text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20"
              >
                Sign in &amp; join with this code →
              </Link>
            )}
          </div>
        )}

        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={submitting || checkingHandle || handleFree === false || !handleWellFormed}>
          {submitting ? "Creating account…" : "Create account"}
        </Button>

        {/* Notice at the point of collection, not only in a footer link on the
            marketing page. The transparency duty toward the data subject
            (יידוע נושא המידע) attaches when the data is COLLECTED — a student
            arriving straight from an invite link never sees the landing page,
            so that footer link reached nobody on the invited path. */}
        <p className="mt-4 text-center text-[11px] leading-relaxed text-slate-500">
          By creating an account you agree we may store your email, display name and
          learning progress to run the course.{" "}
          <Link href="/privacy" className="text-slate-400 underline underline-offset-2 hover:text-cyber-300">
            What we store and why
          </Link>
        </p>
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
