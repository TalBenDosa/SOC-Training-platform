"use client";
/**
 * "Report an issue" — one click from wherever the student hit the problem.
 *
 * Deliberately tiny and low-ceremony: a quiet text link, a two-field modal, no
 * category taxonomy to navigate. Every extra step here costs reports, and the
 * whole value of this feature is volume — each report is a content defect found
 * by someone other than us.
 *
 * `context` should carry whatever pins the report down (room id, task index,
 * the question as displayed) so a report is actionable without a reply.
 */
import { useState } from "react";
import { Flag, X, Check, Loader2 } from "lucide-react";

interface Props {
  targetKind: "room_task" | "scenario" | "quiz" | "dashboard" | "other";
  targetId: string;
  context?: Record<string, string | number | undefined>;
  className?: string;
}

export function ReportIssue({ targetKind, targetId, context, className }: Props) {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!message.trim()) return;
    setBusy(true); setError(null);
    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_kind: targetKind, target_id: targetId, context, message }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d?.error ?? "Could not send. Please try again.");
      }
      setSent(true);
      setTimeout(() => { setOpen(false); setSent(false); setMessage(""); }, 1400);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={className ?? "inline-flex items-center gap-1.5 text-[11px] text-slate-500 transition hover:text-slate-300"}
        title="Report a problem with this content"
      >
        <Flag className="h-3 w-3" /> Report an issue
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Report an issue">
          <div className="w-full max-w-md rounded-xl border border-border bg-bg-elevated p-5 shadow-2xl">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                <Flag className="h-4 w-4 text-neon-amber" /> Report an issue
              </h2>
              <button onClick={() => setOpen(false)} aria-label="Close" className="rounded p-1 text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            {sent ? (
              <p className="flex items-center gap-2 py-6 text-sm text-neon-green">
                <Check className="h-4 w-4" /> Thanks — that helps. We&apos;ll take a look.
              </p>
            ) : (
              <form onSubmit={submit}>
                <label className="mb-1.5 block text-xs text-slate-400" htmlFor="ri-msg">
                  What&apos;s wrong? A wrong answer, a confusing question, a broken task — anything.
                </label>
                <textarea
                  id="ri-msg" rows={4} value={message} onChange={e => setMessage(e.target.value)} autoFocus
                  className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
                  placeholder="The marked answer looks wrong — 4625 is a failed logon, not a successful one."
                />
                {error && <p className="mt-2 text-[11px] text-severity-high">{error}</p>}
                <div className="mt-3 flex items-center justify-end gap-2">
                  <button type="button" onClick={() => setOpen(false)}
                    className="rounded-lg border border-border px-3 py-1.5 text-xs text-slate-300 hover:text-white">Cancel</button>
                  <button type="submit" disabled={busy || !message.trim()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-bold text-cyber-300 transition hover:bg-cyber-500/20 disabled:opacity-40">
                    {busy ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Sending…</> : "Send report"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </>
  );
}
