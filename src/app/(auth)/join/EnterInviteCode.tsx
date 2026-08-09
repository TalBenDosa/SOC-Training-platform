"use client";
/**
 * Code-entry form for students who arrive at /join WITHOUT a token — i.e. they
 * clicked "I have an invite code" on the landing page rather than opening the
 * emailed link.
 *
 * Before this existed, that button led to /join, which treated a missing token
 * as a hard error ("This link is missing its invitation code") — the CTA
 * promised somewhere to type the code and then gave the student nowhere to
 * type it.
 *
 * Accepts either the bare token or a pasted invite URL, because a student told
 * to "use your invite code" will copy whichever of the two they were sent. The
 * token is never validated here: submitting just re-enters /join?token=…, and
 * the Server Component resolves it exactly as it does for an emailed link. So
 * this form widens the entrance without adding a second trust path.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";

/**
 * Pull the token out of whatever the student pasted. A full invite URL carries
 * it as ?token=…; anything else is treated as the bare code. Falls back to the
 * raw string when URL parsing fails, so a mistyped URL still reaches the
 * resolver and gets the resolver's own "we don't recognise this" message
 * rather than a client-side one that would be guessing.
 */
function extractToken(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  if (!/^https?:\/\//i.test(trimmed)) return trimmed;
  try {
    return new URL(trimmed).searchParams.get("token")?.trim() || trimmed;
  } catch {
    return trimmed;
  }
}

export function EnterInviteCode() {
  const [value, setValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();

  const token = extractToken(value);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    setSubmitting(true);
    router.push(`/join?token=${encodeURIComponent(token)}`);
  }

  return (
    <form onSubmit={onSubmit} className="mt-6 text-left">
      <label htmlFor="invite-code" className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
        Invitation code
      </label>
      <input
        id="invite-code"
        name="invite-code"
        type="text"
        autoComplete="off"
        autoFocus
        value={value}
        onChange={e => setValue(e.target.value)}
        placeholder="Paste your code or invite link"
        className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-neon-cyan focus:outline-none focus:ring-1 focus:ring-neon-cyan"
      />
      <Button type="submit" className="mt-4 w-full" disabled={!token || submitting}>
        {submitting ? "Checking…" : "Continue"}
      </Button>
    </form>
  );
}
