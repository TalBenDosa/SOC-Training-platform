"use client";
import { useState } from "react";
import { UserMinus } from "lucide-react";

/**
 * Staff: take a member off the roster (DELETE /api/team/sessions/[id]/members) —
 * QA M1. A no-show, or an invitee whose access to the organisation expired (they can
 * never mark ready), otherwise wedged Start forever; mid-shift it frees a seat. The
 * member becomes `left`: no more reads, writes or seat; their actions so far still
 * count in the shift review. Irreversible from here (re-add them to bring them back),
 * so it asks first. Every screen refreshes from the member.removed event.
 */
export async function removeMember(sessionId: string, userId: string): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch(`/api/team/sessions/${sessionId}/members?user_id=${encodeURIComponent(userId)}`, { method: "DELETE" }).catch(() => null);
  if (!res) return { ok: false, error: "Couldn't reach the server — check your connection and try again." };
  if (res.ok) return { ok: true };
  const data = await res.json().catch(() => ({}));
  return { ok: false, error: (data as { error?: string })?.error ?? "Couldn't remove the member." };
}

export function RemoveMemberButton({ sessionId, userId, name, onError }: { sessionId: string; userId: string; name: string; onError?: (msg: string) => void }) {
  const [busy, setBusy] = useState(false);
  async function run() {
    if (!confirm(`Remove ${name} from this session? They lose access right away; anything they already did still counts in the review.`)) return;
    setBusy(true);
    const r = await removeMember(sessionId, userId);
    setBusy(false);
    if (!r.ok) onError?.(r.error ?? "Couldn't remove the member.");
  }
  return (
    <button type="button" onClick={run} disabled={busy} aria-label={`Remove ${name} from the session`} title="Remove from the session"
      className="inline-flex shrink-0 items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[10px] text-slate-400 transition hover:border-severity-high/50 hover:text-severity-high disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">
      <UserMinus className="h-3 w-3" /> {busy ? "Removing…" : "Remove"}
    </button>
  );
}
