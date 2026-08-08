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
 */
import Link from "next/link";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { AlertTriangle } from "lucide-react";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

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
      <Link href="/login" className="mt-6 inline-block">
        <Button variant="outline">Back to sign in</Button>
      </Link>
    </Card>
  );
}

export default async function JoinPage({ searchParams }: PageProps) {
  const { token } = await searchParams;

  if (!token) {
    return <InvalidInvite reason="This link is missing its invitation code." />;
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
    return <InvalidInvite reason="This invitation has expired or has already been used." />;
  }

  // Valid → straight to registration, carrying the token.
  redirect(`/signup?invite=${encodeURIComponent(token)}`);
}
