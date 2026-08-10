"use client";
/**
 * The access gate's input — step 1 of the code-first entry flow:
 *
 *   Get access → THIS (enter code) → validated → /signup?code=… (the form)
 *
 * The code is checked against /api/access-codes/[code] BEFORE the student
 * moves on, so a typo fails here with "ask for today's code" instead of after
 * they've filled a whole registration form. The trigger re-validates at
 * signup regardless — this check is UX, not enforcement.
 *
 * Also accepts a pasted invite LINK (admins get those by email): a UUID token
 * routes to /join?token=… and resolves through the invitation path unchanged.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/lib/auth/AuthContext";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

/**
 * Pull the credential out of whatever was pasted. A full invite URL carries
 * ?token=…; anything else is treated as an access code. Falls back to the raw
 * string when URL parsing fails, so a mangled paste still reaches validation
 * and gets a real answer.
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
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  // A SIGNED-IN user entering a code isn't registering — they're joining an
  // additional environment with the account they already have.
  const { user } = useAuth();

  const token = extractToken(value);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!token || submitting) return;
    setError(null);

    // Invite links are UUIDs (36 chars, dashed) → the invitation resolver.
    if (!/^[A-Z0-9]{6,12}$/i.test(token)) {
      setSubmitting(true);
      router.push(`/join?token=${encodeURIComponent(token)}`);
      return;
    }

    const code = token.toUpperCase();
    setSubmitting(true);
    try {
      // Signed in → redeem the code onto THIS account: join the environment,
      // switch into it, done. No signup form, no "User already registered".
      if (user) {
        const res = await fetch("/api/account/join-environment", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          // Org claims live in the JWT — restamp them for the new context.
          await getSupabaseBrowserClient()?.auth.refreshSession();
          window.location.href = "/dashboard";
          return;
        }
        setError(data.error ?? "Couldn't join with this code.");
        setSubmitting(false);
        return;
      }

      // Not signed in → validate, then on to registration.
      const res = await fetch(`/api/access-codes/${encodeURIComponent(code)}`);
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.valid) {
        router.push(`/signup?code=${encodeURIComponent(code)}`);
        return;
      }
      setError("That access code isn't valid or has expired — codes are refreshed daily. Ask your instructor for today's code.");
    } catch {
      setError("Couldn't check the code just now. Try again in a moment.");
    }
    setSubmitting(false);
  }

  return (
    <form onSubmit={onSubmit} className="mt-6 text-left">
      <label htmlFor="invite-code" className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
        Access code
      </label>
      <input
        id="invite-code"
        name="invite-code"
        type="text"
        autoComplete="off"
        autoFocus
        value={value}
        onChange={e => { setValue(e.target.value); setError(null); }}
        placeholder="e.g. K7MRW3TQ — or paste an invite link"
        className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 font-mono text-sm tracking-widest text-white placeholder:text-slate-500 focus:border-neon-cyan focus:outline-none focus:ring-1 focus:ring-neon-cyan"
      />
      <Button type="submit" className="mt-4 w-full" disabled={!token || submitting}>
        {submitting ? "Checking…" : "Continue"}
      </Button>
      {user && (
        <p className="mt-3 text-center text-[11px] text-slate-500">
          Signed in as <span className="text-slate-300">{user.email}</span> — this environment
          will be added to your account, alongside any you&apos;re already in.
        </p>
      )}
      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
    </form>
  );
}
