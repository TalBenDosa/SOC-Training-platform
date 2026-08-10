/**
 * Invitation entry point. An org-admin (or the super-admin) hands a student a
 * link like /join?token=… — this resolves it and sends them STRAIGHT INTO
 * REGISTRATION, carrying the token, so the signup trigger enrols them in the
 * inviting institution (see supabase/migrations/0026_invitation_binding.sql).
 *
 * This used to be an interstitial card ("You're invited to X" → click "Accept
 * & create account" → signup). The click bought nothing: the student already
 * decided to join by opening the link, and the institution is shown far more
 * prominently on the signup form itself now. It is a Server Component so the
 * redirect happens before anything renders — no spinner, no flash of a card
 * the student is about to be moved off.
 *
 * An invalid or expired token still stops here with a real explanation, rather
 * than dumping them on a signup form that would silently enrol them nowhere.
 *
 * Reached with NO token, this renders a code-entry form rather than an error:
 * the landing page's "I have an invite code" CTA points here on purpose, for
 * students handed a code instead of a link.
 */
import Link from "next/link";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { AlertTriangle, KeyRound, CheckCircle2 } from "lucide-react";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { EnterInviteCode } from "./EnterInviteCode";

export const metadata = { title: "Join" };

interface PageProps {
  searchParams: Promise<{ token?: string }>;
}

function InvalidInvite({ reason }: { reason: string }) {
  return (
    <Card className="w-full max-w-md text-center">
      <AlertTriangle className="mx-auto h-8 w-8 text-neon-amber" />
      <h1 className="mt-4 text-lg font-bold text-white">This invitation isn&apos;t valid</h1>
      <p className="mt-2 text-sm text-slate-400">{reason}</p>
      <p className="mt-4 text-xs text-slate-400">
        Ask your course administrator to send you a fresh invite link.
      </p>
      {/* Mistyped codes are the common case here, so offer another go before
          sending them to a sign-in page they have no account for yet. */}
      <Link href="/join" className="mt-6 inline-block">
        <Button variant="outline">Try another code</Button>
      </Link>
      <Link href="/login" className="mt-4 block text-xs text-slate-400 hover:text-white">
        Already have an account? Sign in
      </Link>
    </Card>
  );
}

/**
 * A CONSUMED invite (accepted_at set) is not a failure — the person already
 * registered with it. Re-opening the same one-time link is the single most
 * common way to hit "not valid", and the generic error read as a breakage to
 * someone who had, in fact, just succeeded. Send them to sign in instead.
 */
function AlreadyRegistered({ orgName }: { orgName: string | null }) {
  return (
    <Card className="w-full max-w-md text-center">
      <CheckCircle2 className="mx-auto h-8 w-8 text-neon-green" />
      <h1 className="mt-4 text-lg font-bold text-white">You&apos;re already registered</h1>
      <p className="mt-2 text-sm text-slate-400">
        This invitation has already been used to create your account
        {orgName ? <> for <span className="font-semibold text-white">{orgName}</span></> : null}.
        An invite link works once — there&apos;s nothing more to do here. Just sign in.
      </p>
      <Link href="/login" className="mt-6 inline-block">
        <Button>Continue to sign in</Button>
      </Link>
    </Card>
  );
}

export default async function JoinPage({ searchParams }: PageProps) {
  const { token } = await searchParams;

  // No token: this is the ACCESS GATE — step 1 of the code-first entry flow.
  // Every "Get access" button on the landing page leads here; the registration
  // form only exists on the other side of a validated code.
  if (!token) {
    return (
      <Card className="w-full max-w-md text-center">
        <KeyRound className="mx-auto h-8 w-8 text-neon-cyan" />
        <h1 className="mt-4 text-lg font-bold text-white">Get access</h1>
        <p className="mt-2 text-sm text-slate-400">
          Entry is by access code only. Your instructor shares today&apos;s code with the
          class — enter it and you&apos;ll move straight to registration.
        </p>
        <EnterInviteCode />
        <Link href="/login" className="mt-6 inline-block text-xs text-slate-400 hover:text-white">
          Already have an account? Sign in
        </Link>
      </Card>
    );
  }

  const admin = getSupabaseAdminClient();
  if (!admin) {
    return <InvalidInvite reason="Accounts aren't configured on this deployment yet." />;
  }

  const { data, error } = await admin.rpc("resolve_invitation", { p_token: token });
  if (error) {
    return <InvalidInvite reason="We couldn't check this invitation just now. Please try again shortly." />;
  }

  const row = Array.isArray(data) ? data[0] : data;
  if (!row) {
    return <InvalidInvite reason="We don't recognise this invitation code." />;
  }
  if (row.valid !== true) {
    // valid=false conflates two very different states. Look up the invitation
    // itself to tell them apart: accepted_at set → the person already
    // registered with this link (success, not failure); otherwise it genuinely
    // lapsed. resolve_invitation doesn't surface accepted_at, so read it here.
    const { data: inv } = await admin
      .from("invitations")
      .select("accepted_at")
      .eq("token", token)
      .maybeSingle();
    if (inv?.accepted_at) {
      return <AlreadyRegistered orgName={row.org_name ?? null} />;
    }
    return <InvalidInvite reason="This invitation has expired. Ask your course administrator for a fresh link." />;
  }

  // Valid → straight to registration, carrying the token.
  redirect(`/signup?invite=${encodeURIComponent(token)}`);
}
