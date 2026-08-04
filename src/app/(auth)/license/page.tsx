"use client";
/**
 * Shown when a college's license has expired or been suspended. Middleware
 * redirects every app route here for members of a locked org, so it must stand
 * on its own — the only actions are "contact your admin" and sign out.
 */
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useAuth } from "@/lib/auth/AuthContext";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Lock } from "lucide-react";

export default function LicensePage() {
  usePageTitle("Access paused");
  const { signOut } = useAuth();

  return (
    <Card className="w-full max-w-md text-center">
      <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-neon-amber/40 bg-neon-amber/10">
        <Lock className="h-6 w-6 text-neon-amber" />
      </span>
      <h1 className="mt-4 text-lg font-bold text-white">Your access is paused</h1>
      <p className="mt-2 text-sm text-slate-400">
        Your organisation&apos;s access to HACK THE SOC is currently inactive — the
        licence has expired or been suspended. Your progress is safe and will be
        restored the moment access is renewed.
      </p>
      <p className="mt-3 text-sm text-slate-400">
        Please contact your course administrator to renew it.
      </p>
      <Button variant="outline" className="mt-6" onClick={() => signOut()}>
        Sign out
      </Button>
    </Card>
  );
}
