"use client";
/**
 * Accept an invitation. The org-admin (or super-admin) hands out a link like
 * /join?token=… ; this shows who's inviting and sends the invitee into signup
 * carrying the token, so the signup trigger drops them into the right org.
 */
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Building2, Loader2, AlertTriangle } from "lucide-react";

interface Resolved {
  valid: boolean;
  orgName: string | null;
  role: string;
  email: string | null;
}

function JoinInner() {
  usePageTitle("Join");
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<Resolved | null | "loading">("loading");

  useEffect(() => {
    if (!token) { setState(null); return; }
    fetch(`/api/invitations/${encodeURIComponent(token)}`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => setState(d ?? { valid: false, orgName: null, role: "student", email: null }))
      .catch(() => setState({ valid: false, orgName: null, role: "student", email: null }));
  }, [token]);

  if (state === "loading") {
    return <Card className="w-full max-w-md text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-slate-400" /></Card>;
  }

  if (!state || !state.valid) {
    return (
      <Card className="w-full max-w-md text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-neon-amber" />
        <h1 className="mt-4 text-lg font-bold text-white">This invitation isn&apos;t valid</h1>
        <p className="mt-2 text-sm text-slate-400">
          The link may have expired or already been used. Please ask your course administrator for a new one.
        </p>
        <Link href="/login" className="mt-6 inline-block"><Button variant="outline">Back to sign in</Button></Link>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md text-center">
      <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-cyber-500/30 bg-cyber-500/10">
        <Building2 className="h-6 w-6 text-cyber-300" />
      </span>
      <h1 className="mt-4 text-lg font-bold text-white">You&apos;re invited to {state.orgName ?? "a course"}</h1>
      <p className="mt-2 text-sm text-slate-400">
        Join as <span className="font-semibold text-white">{state.role.replace("_", " ")}</span> and start training on HACK THE SOC.
      </p>
      <Link href={`/signup?invite=${encodeURIComponent(token)}`} className="mt-6 inline-block">
        <Button variant="primary" size="lg">Accept &amp; create account</Button>
      </Link>
      <p className="mt-4 text-xs text-slate-400">
        Already have an account? <Link href="/login" className="text-cyber-300 hover:underline">Sign in</Link> and ask your admin to add you.
      </p>
    </Card>
  );
}

export default function JoinPage() {
  return (
    <Suspense fallback={<Card className="w-full max-w-md text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-slate-400" /></Card>}>
      <JoinInner />
    </Suspense>
  );
}
