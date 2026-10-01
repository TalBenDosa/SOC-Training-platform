"use client";
import { useState } from "react";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { MailCheck, AlertTriangle } from "lucide-react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { safeFetch, NETWORK_ERROR } from "@/lib/http/safeFetch";

const ROLE_LABEL: Record<string, string> = { org_admin: "an administrator", instructor: "an instructor", student: "a student" };

/**
 * /join for someone who is ALREADY signed in (SEC-02): accept the invitation into
 * this account with an explicit click. The server checks the invitation is
 * addressed to this account's email and signs out the account's other sessions.
 */
export function AcceptInvite({ token, orgName, role, invitedEmail, signedInAs }: {
  token: string; orgName: string | null; role: string; invitedEmail: string | null; signedInAs: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = !!invitedEmail && invitedEmail.toLowerCase() !== signedInAs.toLowerCase();

  async function accept() {
    setBusy(true); setError(null);
    const res = await safeFetch(`/api/invitations/${encodeURIComponent(token)}/accept`, { method: "POST" });
    if (!res) { setBusy(false); setError(NETWORK_ERROR); return; }
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { setBusy(false); setError(d?.error ?? "Couldn't accept the invitation."); return; }
    // New org / role → mint a token carrying it before entering the app.
    await getSupabaseBrowserClient()?.auth.refreshSession().catch(() => undefined);
    window.location.assign(d.role === "student" ? "/dashboard" : "/manage");
  }

  async function signOut() {
    await getSupabaseBrowserClient()?.auth.signOut().catch(() => undefined);
    window.location.assign(`/login?next=${encodeURIComponent(`/join?token=${token}`)}`);
  }

  return (
    <Card className="w-full max-w-md text-center">
      <MailCheck className="mx-auto h-8 w-8 text-neon-cyan" />
      <h1 className="mt-4 text-lg font-bold text-white">
        Join {orgName ?? "the organisation"} as {ROLE_LABEL[role] ?? role}
      </h1>
      <p className="mt-2 text-sm text-slate-400">You&apos;re signed in as <span className="font-mono text-slate-200">{signedInAs}</span>.</p>
      {mismatch ? (
        <>
          <p className="mt-4 flex items-start gap-2 rounded border border-neon-amber/40 bg-neon-amber/10 px-3 py-2 text-left text-sm text-neon-amber">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            This invitation was sent to {invitedEmail}. Sign in with that account to accept it.
          </p>
          <Button className="mt-5" variant="outline" onClick={signOut}>Sign out and switch account</Button>
        </>
      ) : (
        <>
          <p className="mt-3 text-xs text-slate-500">Accepting signs this account out on your other devices, as a precaution.</p>
          <Button className="mt-5" disabled={busy} onClick={accept}>{busy ? "Accepting…" : "Accept invitation"}</Button>
        </>
      )}
      {error && <p role="alert" className="mt-3 text-sm text-severity-high">{error}</p>}
      <Link href="/dashboard" className="mt-5 block text-xs text-slate-400 hover:text-white">Not now</Link>
    </Card>
  );
}
